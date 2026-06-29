import argparse
import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import random
import re
import string
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx
from curl_cffi.requests import AsyncSession as CurlAsyncSession
from dotenv import load_dotenv

try:
    from fake_useragent import UserAgent
except ImportError:
    UserAgent = None


SIMILARWEB_API_BASE = "https://data.similarweb.com/api/v1/data"
TRAFFIC_SOURCE = "similarweb"
ASSET_SOURCE = "site_scraper"
ASSET_DB_STORAGE_BUCKET = "sitesimgs"
DEFAULT_R2_BUCKET = "siteimgs"
D1_API_BASE = "https://api.cloudflare.com/client/v4"
DOMAIN_STATE_SOURCE = "ahrefs"
AHREFS_DOMAIN_RATING_URL = "https://api.ahrefs.com/v3/public/domain-rating-free"
IANA_RDAP_DNS = "https://data.iana.org/rdap/dns.json"
RDAP_USER_AGENT = "traffic-runner-domain-whois/0.1"
PRICING_EXTRACTOR_VERSION = "python-rule-pricing-v1"
OPENAI_PRICING_EXTRACTOR_VERSION = "openai-structured-pricing-v1"
OPENAI_API_BASE = "https://api.openai.com/v1"
DEFAULT_OPENAI_PRICING_MODEL = "gpt-5.4-mini"
DEFAULT_OPENAI_PRICING_FALLBACK_MODEL = ""
OPENAI_PRICING_MIN_CONFIDENCE = 60
DEFAULT_OPENAI_PRICING_TEXT_CHARS = 24000
BROWSER_RENDERING_TEXT_SCORE_THRESHOLD = 8
PRICING_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
_PRICING_UA_GENERATOR: Any | None = None
MAX_PRICING_HTML_BYTES = 1_200_000
MAX_PRICING_TEXT_CHARS = 180_000
COMMON_PRICING_PATHS = (
    "/pricing",
    "/pricing/",
    "/plans",
    "/plans/",
    "/pricing-page",
    "/pricing-plans",
    "/plans-pricing",
    "/billing",
)
COMMON_CONTACT_SALES_PATHS = (
    "/contact-sales",
    "/book-a-demo",
    "/book-a-demo-call",
    "/request-demo",
    "/demo",
    "/contact",
    "/contact-us",
    "/enterprise",
)
BAD_PRICING_PATH_PARTS = {
    "article",
    "articles",
    "blog",
    "buy",
    "cart",
    "careers",
    "case-study",
    "case-studies",
    "community",
    "docs",
    "guide",
    "help",
    "help-center",
    "issues",
    "legal",
    "news",
    "policy",
    "privacy",
    "privacy-policy",
    "resources",
    "release-note",
    "release-notes",
    "refund",
    "search",
    "shop",
    "store",
    "support",
    "terms",
    "terms-of-use",
}
PRICING_PATH_PARTS = {"pricing", "prices", "plans", "pricing-plans", "plans-pricing", "billing"}
CONTACT_SALES_PATH_PARTS = {
    "book-a-demo",
    "book-a-demo-call",
    "contact-sales",
    "request-demo",
    "schedule-demo",
    "demo",
    "contact",
    "contact-us",
    "enterprise",
    "sales",
}
PRICING_PLAN_NAMES = (
    "Free",
    "Basic",
    "Starter",
    "Lite",
    "Plus",
    "Pro",
    "Professional",
    "Premium",
    "Creator",
    "Team",
    "Business",
    "Growth",
    "Scale",
    "Enterprise",
)
PRICE_RE = re.compile(
    r"(?:(?P<currency1>US\$|\$|₹|USD|EUR|GBP|INR)\s*(?P<amount1>\d{1,7}(?:,\d{2,3})*(?:\.\d{1,4})?)|"
    r"(?P<amount2>\d{1,7}(?:,\d{2,3})*(?:\.\d{1,4})?)\s*(?P<currency2>USD|EUR|GBP|INR))",
    re.I,
)
COMMON_THREE_LABEL_SUFFIXES = {
    "co.uk",
    "com.au",
    "co.jp",
    "co.in",
    "co.nz",
    "co.kr",
    "com.br",
    "com.cn",
    "com.sg",
    "com.hk",
    "co.za",
    "com.mx",
}


@dataclass(frozen=True)
class Config:
    cloudflare_account_id: str
    cloudflare_d1_database_id: str
    cloudflare_api_token: str
    brightdata_proxy_host: str
    brightdata_proxy_port: int
    brightdata_proxy_user: str
    brightdata_proxy_password: str
    limit: int
    concurrency: int
    max_retries: int
    poll_interval_seconds: int
    asset_limit: int
    domain_state_limit: int
    domain_state_max_age_days: int
    pricing_limit: int
    pricing_timeout_seconds: int
    openai_api_key: str
    openai_pricing_model: str
    openai_pricing_fallback_model: str
    openai_pricing_timeout_seconds: int
    openai_pricing_text_chars: int
    browser_rendering_api_token: str
    browser_rendering_enabled: bool
    browser_rendering_timeout_seconds: int
    r2_access_key_id: str
    r2_secret_access_key: str
    r2_bucket: str
    r2_public_base_url: str


@dataclass(frozen=True)
class TrafficTask:
    normalized_domain: str
    traffic_month: str
    attempts: int


@dataclass(frozen=True)
class AssetTask:
    tool_id: int
    canonical_slug: str
    normalized_domain: str
    official_url: str
    attempts: int


@dataclass(frozen=True)
class DomainStateCandidate:
    normalized_domain: str


@dataclass(frozen=True)
class PricingTask:
    task_id: int
    pricing_source_id: int
    tool_id: int
    canonical_slug: str
    source_url: str
    official_url: str
    attempts: int
    max_attempts: int


@dataclass(frozen=True)
class FetchResult:
    status: str
    monthly_rows: list[dict[str, Any]]
    error: str | None = None


@dataclass(frozen=True)
class DomainStateResult:
    status: str
    domain_rating: float | None
    domain_created_at: str | None
    error: str | None = None


@dataclass(frozen=True)
class AssetFetchResult:
    final_url: str
    screenshot: bytes
    html: str = ""


@dataclass(frozen=True)
class FaviconAsset:
    body: bytes
    key: str
    mime_type: str


@dataclass(frozen=True)
class PricingFetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    html: str
    error: str = ""
    page_status: str = "found"
    discovery_method: str = "source_url"


def read_int_env(name: str, fallback: int) -> int:
    value = os.getenv(name)
    if not value:
        return fallback
    try:
        return int(value)
    except ValueError:
        return fallback


def read_bool_env(name: str, fallback: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return fallback
    return value.strip().lower() not in {"0", "false", "no", "off"}


def log_info(message: str, **fields: Any) -> None:
    print(json.dumps({"level": "info", "message": message, **fields}, ensure_ascii=False), flush=True)


def log_error(message: str, **fields: Any) -> None:
    print(json.dumps({"level": "error", "message": message, **fields}, ensure_ascii=False), file=sys.stderr, flush=True)


def mask_value(value: str, prefix: int = 18, suffix: int = 8) -> str:
    if not value:
        return ""
    if len(value) <= prefix + suffix + 3:
        return value
    return f"{value[:prefix]}...{value[-suffix:]}"


def extract_brightdata_zone(username: str) -> str | None:
    match = re.search(r"(?:^|-)zone-([A-Za-z0-9_]+)", username or "")
    return match.group(1) if match else None


def response_header_summary(response: httpx.Response) -> dict[str, str]:
    keys = [
        "content-type",
        "content-length",
        "server",
        "cf-ray",
        "x-cache",
        "via",
        "x-brd-error",
        "x-brd-ip",
    ]
    return {key.replace("-", "_"): response.headers[key] for key in keys if key in response.headers}


def response_body_sample(response: httpx.Response, limit: int = 500) -> str:
    try:
        text = response.text
    except Exception as error:
        return f"<unable_to_read_response_text:{type(error).__name__}>"
    return re.sub(r"\s+", " ", text).strip()[:limit]



def load_config(require_brightdata: bool = True) -> Config:
    load_dotenv()
    return Config(
        cloudflare_account_id=os.environ["CLOUDFLARE_ACCOUNT_ID"],
        cloudflare_d1_database_id=os.environ["CLOUDFLARE_D1_DATABASE_ID"],
        cloudflare_api_token=os.environ["CLOUDFLARE_API_TOKEN"],
        brightdata_proxy_host=os.getenv("BRIGHTDATA_PROXY_HOST", "brd.superproxy.io"),
        brightdata_proxy_port=read_int_env("BRIGHTDATA_PROXY_PORT", 33335),
        brightdata_proxy_user=os.environ["BRIGHTDATA_PROXY_USER"] if require_brightdata else os.getenv("BRIGHTDATA_PROXY_USER", ""),
        brightdata_proxy_password=os.environ["BRIGHTDATA_PROXY_PASSWORD"] if require_brightdata else os.getenv("BRIGHTDATA_PROXY_PASSWORD", ""),
        limit=read_int_env("RUNNER_LIMIT", 20),
        concurrency=read_int_env("RUNNER_CONCURRENCY", 5),
        max_retries=read_int_env("RUNNER_MAX_RETRIES", 2),
        poll_interval_seconds=read_int_env("RUNNER_POLL_INTERVAL_SECONDS", 300),
        asset_limit=read_int_env("RUNNER_ASSET_LIMIT", 50),
        domain_state_limit=read_int_env("RUNNER_DOMAIN_STATE_LIMIT", 50),
        domain_state_max_age_days=read_int_env("RUNNER_DOMAIN_STATE_MAX_AGE_DAYS", 30),
        pricing_limit=read_int_env("RUNNER_PRICING_LIMIT", 20),
        pricing_timeout_seconds=read_int_env("RUNNER_PRICING_TIMEOUT_SECONDS", 20),
        openai_api_key=os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API", ""),
        openai_pricing_model=os.getenv("OPENAI_PRICING_MODEL", DEFAULT_OPENAI_PRICING_MODEL),
        openai_pricing_fallback_model=os.getenv("OPENAI_PRICING_FALLBACK_MODEL", DEFAULT_OPENAI_PRICING_FALLBACK_MODEL),
        openai_pricing_timeout_seconds=read_int_env("OPENAI_PRICING_TIMEOUT_SECONDS", 45),
        openai_pricing_text_chars=read_int_env("OPENAI_PRICING_TEXT_CHARS", DEFAULT_OPENAI_PRICING_TEXT_CHARS),
        browser_rendering_api_token=os.getenv("CLOUDFLARE_BROWSER_RENDERING_API_TOKEN") or os.environ["CLOUDFLARE_API_TOKEN"],
        browser_rendering_enabled=read_bool_env("CLOUDFLARE_BROWSER_RENDERING_ENABLED", False),
        browser_rendering_timeout_seconds=read_int_env("CLOUDFLARE_BROWSER_RENDERING_TIMEOUT_SECONDS", 45),
        r2_access_key_id=os.getenv("CLOUDFLARE_R2_ACCESS_KEY_ID", ""),
        r2_secret_access_key=os.getenv("CLOUDFLARE_R2_SECRET_ACCESS_KEY", ""),
        r2_bucket=os.getenv("CLOUDFLARE_R2_BUCKET", DEFAULT_R2_BUCKET),
        r2_public_base_url=os.getenv("R2_PUBLIC_BASE_URL", "").rstrip("/"),
    )


def normalize_domain(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    host = (parsed.netloc or parsed.path).split("@")[-1].split(":")[0].strip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", host):
        return ""
    return host


def get_registrable_domain(domain: str) -> str:
    labels = [part.strip() for part in (domain or "").split(".") if part.strip()]
    if len(labels) >= 3 and ".".join(labels[-2:]) in COMMON_THREE_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)


def normalize_rdap_domain(value: str) -> str:
    domain = normalize_domain(value)
    if not domain:
        return ""
    return get_registrable_domain(domain)


def parse_iso_timestamp(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generate_session_id(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_delta(**kwargs: Any) -> str:
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class PricingHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.jsonld_scripts: list[str] = []
        self._ignore_depth = 0
        self._jsonld_depth = 0
        self._jsonld_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr = {name.lower(): value or "" for name, value in attrs}
        if tag == "script":
            if attr.get("type", "").lower() == "application/ld+json":
                self._jsonld_depth += 1
                self._jsonld_parts = []
            else:
                self._ignore_depth += 1
            return
        if tag in {"style", "noscript", "svg"}:
            self._ignore_depth += 1
            return
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])
        if tag in {"br", "p", "div", "li", "tr", "td", "th", "section", "article", "h1", "h2", "h3", "h4"}:
            self.text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script" and self._jsonld_depth:
            self._jsonld_depth -= 1
            script = "".join(self._jsonld_parts).strip()
            if script:
                self.jsonld_scripts.append(script)
            self._jsonld_parts = []
            return
        if tag in {"script", "style", "noscript", "svg"} and self._ignore_depth:
            self._ignore_depth -= 1
            return
        if tag in {"p", "div", "li", "tr", "section", "article", "h1", "h2", "h3", "h4"}:
            self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._jsonld_depth:
            self._jsonld_parts.append(data)
        elif not self._ignore_depth:
            self.text_parts.append(data)

    @property
    def text(self) -> str:
        lines = []
        for line in html.unescape("".join(self.text_parts)).splitlines():
            cleaned = re.sub(r"\s+", " ", line).strip()
            if cleaned:
                lines.append(cleaned)
        return "\n".join(lines)[:MAX_PRICING_TEXT_CHARS]


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def normalize_pricing_url(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid URL: {value}")
    return parsed.geturl()


def pricing_url_origin(value: str) -> str:
    parsed = urlsplit(normalize_pricing_url(value))
    return f"{parsed.scheme}://{parsed.netloc}"


def is_bad_pricing_url(value: str) -> bool:
    parsed = urlsplit(value)
    parts = {part.lower() for part in parsed.path.split("/") if part}
    if parts & BAD_PRICING_PATH_PARTS:
        return True
    if any(part.endswith("-policy") or part.endswith("-terms") for part in parts):
        return True
    return any(part.startswith("api-") or part.endswith("-api") for part in parts)


def is_pricing_path_part(part: str) -> bool:
    normalized = part.lower()
    return (
        normalized in PRICING_PATH_PARTS
        or "pricing" in normalized
        or normalized in {"price", "plans", "billing", "upgrade"}
    )


def is_pricing_fragment(fragment: str) -> bool:
    normalized = fragment.lower().strip()
    return normalized in {"pricing", "plans", "price", "billing"} or "pricing" in normalized


def is_strict_pricing_url(value: str) -> bool:
    parsed = urlsplit(value)
    parts = {part.lower() for part in parsed.path.split("/") if part}
    if is_bad_pricing_url(value):
        return False
    if is_pricing_fragment(parsed.fragment):
        return True
    if not parts:
        return False
    return any(is_pricing_path_part(part) for part in parts)


def is_contact_sales_url(value: str) -> bool:
    parsed = urlsplit(value)
    parts = {part.lower() for part in parsed.path.split("/") if part}
    if not parts or is_bad_pricing_url(value):
        return False
    return bool(parts & CONTACT_SALES_PATH_PARTS)


def pricing_url_score(value: str) -> int:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return -1000
    parts = [part.lower() for part in parsed.path.split("/") if part]
    if not parts:
        return 75 if is_pricing_fragment(parsed.fragment) else -50
    if is_bad_pricing_url(value):
        return -200

    score = 0
    depth = len(parts)
    if depth == 1:
        score += 35
    elif depth == 2:
        score += 20
    elif depth >= 4:
        score -= 25

    for part in parts:
        if part in {"pricing", "pricing-page", "pricing-plans", "plans-pricing"}:
            score += 100
        elif "pricing" in part:
            score += 85
        elif part in {"plans", "billing", "upgrade"}:
            score += 55
        elif part in {"enterprise", "contact-sales", "contact"}:
            score -= 20

    if is_pricing_fragment(parsed.fragment):
        score += 75
    if parsed.query:
        score -= 5
    return score


def contact_sales_url_score(value: str) -> int:
    if not is_contact_sales_url(value):
        return -1000
    parsed = urlsplit(value)
    parts = [part.lower() for part in parsed.path.split("/") if part]
    score = 0
    for part in parts:
        if part in {"contact-sales", "book-a-demo", "book-a-demo-call", "request-demo", "schedule-demo"}:
            score += 90
        elif part == "demo":
            score += 70
        elif part in {"enterprise", "sales"}:
            score += 55
        elif part in {"contact", "contact-us"}:
            score += 35
    score -= max(0, len(parts) - 2) * 10
    return score


def source_context_parts(source_url: str) -> set[str]:
    generic = PRICING_PATH_PARTS | {"feature", "features", "product", "products", "en", "us", "www"}
    return {
        part
        for part in (segment.lower() for segment in urlsplit(source_url).path.split("/") if segment)
        if part not in generic and len(part) > 2
    }


def final_url_matches_source_context(source_url: str, final_url: str) -> bool:
    required_parts = source_context_parts(source_url)
    if not required_parts:
        return True
    final_parts = {part.lower() for part in urlsplit(final_url).path.split("/") if part}
    return required_parts.issubset(final_parts)


def random_pricing_user_agent() -> str:
    global _PRICING_UA_GENERATOR
    if UserAgent is not None:
        try:
            if _PRICING_UA_GENERATOR is None:
                _PRICING_UA_GENERATOR = UserAgent(
                    browsers=["Chrome", "Edge"],
                    platforms=["desktop"],
                    fallback=PRICING_USER_AGENT,
                )
            user_agent = _PRICING_UA_GENERATOR.random
            if user_agent:
                return str(user_agent)
        except Exception:
            pass
    return PRICING_USER_AGENT


def pricing_request_headers(url: str) -> dict[str, str]:
    origin = pricing_url_origin(url)
    return {
        "User-Agent": random_pricing_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": f"{origin}/",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }


def asset_page_url(task: AssetTask) -> str:
    for raw in (task.official_url, f"https://{task.normalized_domain}", f"http://{task.normalized_domain}"):
        if not raw:
            continue
        candidate = raw if "://" in raw else f"https://{raw}"
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return candidate
    return f"https://{task.normalized_domain}"


def read_html_attribute(tag: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", tag, re.I)
    if not match or not match.group(1):
        return ""
    return match.group(1).strip().strip("\"'").strip()


def extract_favicon_href(html_body: str, page_url: str) -> str | None:
    links = re.findall(r"<link\b[^>]*>", html_body or "", re.I)
    icon_links = []
    for tag in links:
        rel = read_html_attribute(tag, "rel").lower()
        href = read_html_attribute(tag, "href")
        if href and ("icon" in rel or "apple-touch-icon" in rel):
            icon_links.append((rel, href))
    preferred = next((href for rel, href in icon_links if "apple-touch-icon" in rel), None)
    preferred = preferred or next((href for _rel, href in icon_links), None)
    return urljoin(page_url, preferred) if preferred else None


def find_favicon_href(html_body: str, page_url: str) -> str:
    return extract_favicon_href(html_body, page_url) or urljoin(page_url, "/favicon.ico")


def asset_extension(asset_url: str, content_type: str) -> str:
    normalized = (content_type or "").lower()
    if "image/png" in normalized:
        return ".png"
    if "image/svg" in normalized:
        return ".svg"
    if "image/webp" in normalized:
        return ".webp"
    if "image/jpeg" in normalized or "image/jpg" in normalized:
        return ".jpg"
    if "image/x-icon" in normalized or "image/vnd.microsoft.icon" in normalized:
        return ".ico"
    try:
        match = re.search(r"\.(ico|png|svg|jpg|jpeg|webp)$", urlsplit(asset_url).path, re.I)
    except ValueError:
        match = None
    return f".{match.group(1).lower().replace('jpeg', 'jpg')}" if match else ".ico"


def asset_mime_type(asset_url: str, content_type: str) -> str:
    normalized = (content_type or "").split(";")[0].strip().lower()
    if normalized.startswith("image/"):
        return normalized
    extension = asset_extension(asset_url, "")
    if extension == ".png":
        return "image/png"
    if extension == ".svg":
        return "image/svg+xml"
    if extension == ".webp":
        return "image/webp"
    if extension == ".jpg":
        return "image/jpeg"
    return "image/x-icon"


def asset_public_url(base_url: str, object_key: str) -> str | None:
    if not base_url:
        return None
    normalized_base = base_url.rstrip("/")
    if not normalized_base.startswith(("http://", "https://")):
        normalized_base = f"https://{normalized_base}"
    encoded_path = "/".join(quote(part, safe="") for part in object_key.split("/"))
    return f"{normalized_base}/{encoded_path}"


def parse_pricing_html(value: str) -> PricingHtmlParser:
    parser = PricingHtmlParser()
    parser.feed(value or "")
    return parser


def pricing_text_quality(text: str) -> int:
    lower = text.lower()
    score = 0
    score += len(re.findall(r"\$\s?\d|usd\s?\d", lower)) * 3
    score += len(re.findall(r"\bpricing|plans?|monthly|yearly|per month|per user|contact sales|enterprise\b", lower))
    score -= len(re.findall(r"\bblog|privacy|terms|careers|cookie|shopping|purchase|cart\b", lower)) * 2
    return score


def extract_sitemap_locs(sitemap_body: str) -> list[str]:
    body = sitemap_body.strip()
    if not body:
        return []
    locs: list[str] = []
    try:
        root = ET.fromstring(body)
        for element in root.iter():
            if element.tag.endswith("loc") and element.text:
                locs.append(element.text.strip())
    except ET.ParseError:
        locs.extend(match.group(1).strip() for match in re.finditer(r"<loc>\s*([^<]+?)\s*</loc>", body, re.I))
    return [loc for loc in locs if loc.startswith(("http://", "https://"))]


def add_pricing_candidate(urls: list[str], seen: set[str], candidate: str, origin: str) -> None:
    try:
        normalized = normalize_pricing_url(candidate)
    except ValueError:
        return
    if urlsplit(normalized).netloc != urlsplit(origin).netloc:
        return
    if not is_pricing_fragment(urlsplit(normalized).fragment):
        normalized = normalized.split("#", 1)[0]
    key = normalized.rstrip("/")
    if key in seen:
        return
    if not is_strict_pricing_url(normalized):
        return
    seen.add(key)
    urls.append(normalized)


def add_contact_sales_candidate(urls: list[str], seen: set[str], candidate: str, origin: str) -> None:
    try:
        normalized = normalize_pricing_url(candidate).split("#", 1)[0]
    except ValueError:
        return
    if urlsplit(normalized).netloc != urlsplit(origin).netloc:
        return
    key = normalized.rstrip("/")
    if key in seen or not is_contact_sales_url(normalized):
        return
    seen.add(key)
    urls.append(normalized)


def discover_pricing_urls(base_url: str, html_body: str, sitemap_body: str = "") -> list[str]:
    origin = pricing_url_origin(base_url)
    parser = parse_pricing_html(html_body)
    urls: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        add_pricing_candidate(urls, seen, urljoin(base_url, href), origin)
    if re.search(r"\bpricing|plans?\b", parser.text, re.I):
        add_pricing_candidate(urls, seen, urljoin(origin, "/#pricing"), origin)
    for loc in extract_sitemap_locs(sitemap_body):
        add_pricing_candidate(urls, seen, loc, origin)
    for path in COMMON_PRICING_PATHS:
        add_pricing_candidate(urls, seen, urljoin(origin, path), origin)
    urls.sort(key=pricing_url_score, reverse=True)
    return urls[:12]


def discover_contact_sales_urls(base_url: str, html_body: str, sitemap_body: str = "") -> list[str]:
    origin = pricing_url_origin(base_url)
    parser = parse_pricing_html(html_body)
    urls: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        add_contact_sales_candidate(urls, seen, urljoin(base_url, href), origin)
    for loc in extract_sitemap_locs(sitemap_body):
        add_contact_sales_candidate(urls, seen, loc, origin)
    for path in COMMON_CONTACT_SALES_PATHS:
        add_contact_sales_candidate(urls, seen, urljoin(origin, path), origin)
    urls.sort(key=contact_sales_url_score, reverse=True)
    return urls[:8]


def read_decimal(value: Any) -> str | None:
    try:
        amount = Decimal(str(value).replace(",", "").strip())
    except (InvalidOperation, ValueError):
        return None
    if amount < 0:
        return None
    return format(amount.normalize(), "f")


def decimal_value(value: Any) -> Decimal:
    try:
        return Decimal(str(value or "0").replace(",", "").strip())
    except (InvalidOperation, ValueError):
        return Decimal("0")


def normalize_currency(value: str | None) -> str:
    raw = (value or "$").upper().replace("US$", "USD").replace("$", "USD").replace("₹", "INR")
    if raw in {"USD", "EUR", "GBP", "INR"}:
        return raw
    return "USD"


def clean_snippet(value: str, limit: int = 180) -> str:
    cleaned = re.sub(r"\s+", " ", html.unescape(value or "")).strip()
    return cleaned[:limit].strip()


def infer_interval(context: str) -> str | None:
    lower = context.lower()
    if re.search(r"/\s*yr\b|per year|yearly|annually|annual|/year|\byr\b", lower):
        return "yearly"
    if re.search(r"/\s*mo\b|per month|monthly|/month|\bmo\b", lower):
        return "monthly"
    return None


def infer_unit(context: str) -> str | None:
    lower = context.lower()
    if "per user" in lower or "/user" in lower:
        return "user"
    if "per seat" in lower or "/seat" in lower:
        return "seat"
    return None


def is_polluted_context(context: str) -> bool:
    lower = context.lower()
    return bool(
        re.search(
            r"\b(under|shopping|purchase|cart|invoice|discount|save|coupon|refund|tax|blog|privacy|terms|"
            r"per image|token|credit|api call|api pricing|model price)\b",
            lower,
        )
    )


def choose_plan_name(context_before_price: str, fallback_index: int) -> str:
    before = clean_snippet(context_before_price, 220)
    lower = before.lower()
    last_name = ""
    last_pos = -1
    for name in PRICING_PLAN_NAMES:
        pos = lower.rfind(name.lower())
        if pos > last_pos:
            last_name = name
            last_pos = pos
    if last_name:
        return last_name

    lines = [clean_snippet(line, 80) for line in before.split("\n") if clean_snippet(line, 80)]
    for line in reversed(lines[-4:]):
        words = line.split()
        if 1 <= len(words) <= 4 and not is_polluted_context(line):
            return line
    return f"Plan {fallback_index}"


def price_sort_key(plan: dict[str, Any]) -> tuple[int, Decimal]:
    price = (plan.get("prices") or [{}])[0]
    amount = decimal_value(price.get("amount"))
    if amount == 0:
        return (0, amount)
    if price.get("billing_interval") == "monthly":
        return (1, amount)
    if price.get("billing_interval") == "yearly":
        return (2, amount)
    return (3, amount)


def display_text_has_explicit_price(value: str) -> bool:
    return bool(PRICE_RE.search(value or ""))


def validate_plan_price_integrity(plans: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for plan in plans:
        name = clean_snippet(str(plan.get("name") or plan.get("source_plan_key") or "Unknown"), 80)
        prices = list(plan.get("prices") or [])
        if not prices:
            errors.append(f"Plan has no price row: {name}")
            continue
        for price in prices:
            display_text = str(price.get("display_text") or "")
            has_display_price = display_text_has_explicit_price(display_text)
            amount = price.get("amount")
            currency = price.get("currency")
            is_custom_quote = bool(price.get("custom_quote")) or price.get("kind") == "custom_quote"
            if has_display_price and (amount in (None, "") or not currency):
                errors.append(f"Explicit price text missing structured amount/currency: {name}")
            if has_display_price and is_custom_quote:
                errors.append(f"Explicit price text marked as custom quote: {name}")
            if not is_custom_quote and amount not in (None, "") and not currency:
                errors.append(f"Structured price missing currency: {name}")
    return sorted(set(errors))


def comparable_plan_name(value: str) -> str:
    name = re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()
    name = re.sub(r"\bplan\b", "", name).strip()
    return re.sub(r"\s+", " ", name)


def public_price_map(plans: list[dict[str, Any]]) -> dict[str, tuple[str, str, str]]:
    prices: dict[str, tuple[str, str, str]] = {}
    for plan in plans:
        name = comparable_plan_name(str(plan.get("name") or plan.get("source_plan_key") or ""))
        if not name:
            continue
        for price in list(plan.get("prices") or [])[:1]:
            if price.get("custom_quote"):
                continue
            amount = read_decimal(price.get("amount"))
            currency = str(price.get("currency") or "").upper()
            if amount is not None and currency:
                prices[name] = (amount, currency, str(plan.get("name") or name))
    return prices


def validate_jsonld_visible_price_conflicts(
    jsonld_plans: list[dict[str, Any]],
    visible_plans: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    jsonld_prices = public_price_map(jsonld_plans)
    visible_prices = public_price_map(visible_plans)
    for key, (jsonld_amount, jsonld_currency, display_name) in jsonld_prices.items():
        visible = visible_prices.get(key)
        if not visible:
            continue
        visible_amount, visible_currency, _ = visible
        if (jsonld_amount, jsonld_currency) != (visible_amount, visible_currency):
            errors.append(
                f"JSON-LD price conflicts with visible text for {display_name}: "
                f"{jsonld_amount} {jsonld_currency} vs {visible_amount} {visible_currency}"
            )
    return errors


def should_verify_rule_pricing_with_openai(
    payload: dict[str, Any],
    text_score: int,
    page_status: str,
) -> tuple[bool, list[str]]:
    if page_status != "found":
        return False, []
    plans = list(payload.get("plans") or [])
    reasons: list[str] = []
    if not plans:
        return True, ["rules_found_no_plans"]
    names = [str(plan.get("name") or "") for plan in plans]
    name_counts: dict[str, int] = {}
    for name in names:
        key = name.lower().strip()
        name_counts[key] = name_counts.get(key, 0) + 1
        if re.fullmatch(r"plan\s+\d+", key):
            reasons.append("generic_plan_name")
    if any(count > 1 and name not in {"free", "enterprise"} for name, count in name_counts.items()):
        reasons.append("duplicate_plan_names")
    if text_score < 18:
        reasons.append("low_text_quality")

    currencies = set()
    for plan in plans:
        for price in plan.get("prices", []):
            if price.get("currency"):
                currencies.add(str(price.get("currency")))
            display_text = str(price.get("display_text") or "")
            lower = display_text.lower()
            if len(display_text) > 140:
                reasons.append("long_price_context")
            if re.search(r"\b(raise[sd]?|funding|students?|graduates?|academy|this month only|additional cost|traditional)\b", lower):
                reasons.append("polluted_price_context")
            if "₹" in display_text and price.get("currency") != "INR":
                reasons.append("currency_mismatch")
    if len(currencies) > 1:
        reasons.append("mixed_currencies")
    return bool(reasons), sorted(set(reasons))


def validate_extracted_plan_consistency(plans: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen_names: dict[str, int] = {}
    currencies = set()
    for plan in plans:
        name = str(plan.get("name") or "").strip().lower()
        if name:
            seen_names[name] = seen_names.get(name, 0) + 1
        for price in plan.get("prices", []):
            if price.get("currency"):
                currencies.add(str(price.get("currency")))
    duplicated_names = {name for name, count in seen_names.items() if count > 1 and name not in {"free", "enterprise", "custom"}}
    if duplicated_names:
        errors.append("Duplicate plan names in extracted pricing")
    if len(currencies) > 1:
        errors.append("Multiple currencies in extracted pricing")
    return errors


def normalize_pricing_plan(
    name: str,
    amount: str | None,
    currency: str = "USD",
    context: str = "",
    index: int = 0,
) -> dict[str, Any]:
    kind = "one_time" if re.search(r"one[- ]?time|lifetime", context, re.I) else "recurring"
    if amount is None:
        kind = "custom_quote"
    price = {
        "kind": kind,
        "amount": amount,
        "currency": currency if amount is not None else None,
        "billing_interval": infer_interval(context) if kind == "recurring" else None,
        "commitment_interval": None,
        "unit": infer_unit(context),
        "custom_quote": amount is None,
        "starting_at": bool(re.search(r"from|starting", context, re.I)),
        "display_text": clean_snippet(context, 180),
    }
    clean_name = clean_snippet(name, 80) or ("Enterprise" if amount is None else f"Plan {index}")
    return {
        "source_plan_key": re.sub(r"[^a-z0-9]+", "_", clean_name.lower()).strip("_")[:80],
        "name": clean_name,
        "audience": None,
        "description": None,
        "is_enterprise": 1 if re.search(r"enterprise|contact", clean_name, re.I) else 0,
        "prices": [price],
        "features": [],
        "display_order": index,
    }


def collect_jsonld_nodes(value: Any) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            nodes.extend(collect_jsonld_nodes(item))
    elif isinstance(value, dict):
        nodes.append(value)
        if "@graph" in value:
            nodes.extend(collect_jsonld_nodes(value["@graph"]))
        if "offers" in value:
            nodes.extend(collect_jsonld_nodes(value["offers"]))
    return nodes


def extract_jsonld_plans(scripts: list[str]) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    for script in scripts:
        try:
            data = json.loads(html.unescape(script))
        except json.JSONDecodeError:
            continue
        for node in collect_jsonld_nodes(data):
            raw_price = node.get("price") or node.get("lowPrice")
            if raw_price is None and isinstance(node.get("priceSpecification"), dict):
                raw_price = node["priceSpecification"].get("price")
            amount = read_decimal(raw_price)
            if amount is None:
                continue
            name = clean_snippet(str(node.get("name") or node.get("description") or ""), 80) or "Listed plan"
            currency = normalize_currency(str(node.get("priceCurrency") or "USD"))
            plans.append(normalize_pricing_plan(name, amount, currency, json.dumps(node, ensure_ascii=False), len(plans)))
            if len(plans) >= 6:
                return plans
    return plans


def has_free_plan_signal(text: str) -> bool:
    lower = re.sub(r"\s+", " ", (text or "").lower())
    if re.search(r"\bfree\s+(trial|demo|consultation|call|account|signup|sign up|start|download)\b", lower):
        return False
    return bool(
        re.search(r"\bfree\s+(plan|tier|forever)\b|\b(plan|tier)\s+free\b", lower)
        or re.search(r"\bfree\b.{0,80}\$(?:\s*)0(?:\b|/)", lower)
        or re.search(r"\$(?:\s*)0(?:\b|/).{0,80}\bfree\b", lower)
    )


def extract_text_plans(text: str) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for match in PRICE_RE.finditer(text):
        amount = read_decimal(match.group("amount1") or match.group("amount2"))
        if amount is None:
            continue
        start = max(0, match.start() - 260)
        end = min(len(text), match.end() + 220)
        context = text[start:end]
        if is_polluted_context(context):
            continue
        currency = normalize_currency(match.group("currency1") or match.group("currency2"))
        name = choose_plan_name(text[start:match.start()], len(plans) + 1)
        plan = normalize_pricing_plan(name, amount, currency, context, len(plans))
        price = plan["prices"][0]
        key = (plan["name"].lower(), price["amount"], price["billing_interval"])
        if key in seen:
            continue
        seen.add(key)
        plans.append(plan)
        if len(plans) >= 6:
            break

    lower = text.lower()
    if has_free_plan_signal(text) and not any(plan["name"].lower() == "free" for plan in plans):
        plans.insert(0, normalize_pricing_plan("Free", "0", "USD", "Free", 0))
    if re.search(r"contact sales|custom pricing|talk to sales", lower) and not any(plan["prices"][0]["custom_quote"] for plan in plans):
        custom_plan = normalize_pricing_plan("Custom", None, "USD", "Contact sales", len(plans))
        custom_plan["is_enterprise"] = 1
        custom_plan["description"] = "No public prices; contact sales or book a demo."
        custom_plan["prices"][0]["billing_interval"] = "custom"
        plans.append(custom_plan)

    normalized = sorted(plans[:6], key=price_sort_key)
    for index, plan in enumerate(normalized):
        plan["display_order"] = index
    return normalized


def extract_pricing_payload(
    html_body: str,
    source_url: str,
    final_url: str,
    http_status: int,
    error: str,
    page_status: str = "found",
    discovery_method: str = "source_url",
) -> tuple[dict[str, Any], str, int, list[str]]:
    if page_status == "contact_sales":
        plan = normalize_pricing_plan("Custom", None, "USD", "Book a demo / contact sales", 0)
        plan["is_enterprise"] = 1
        plan["description"] = "No public prices; contact sales or book a demo."
        plan["prices"][0]["billing_interval"] = "custom"
        plan["prices"][0]["display_text"] = "Book a demo / contact sales"
        payload = {
            "plans": [plan],
            "plan_count": 1,
            "quality": {
                "ok": True,
                "reason": None,
                "text_score": pricing_text_quality(parse_pricing_html(html_body).text if html_body else ""),
                "final_url": final_url,
                "page_status": page_status,
                "discovery_method": discovery_method,
            },
            "extraction_method": "python_rule",
        }
        return payload, "approved", 78, []

    if page_status == "not_found":
        payload = {
            "plans": [],
            "plan_count": 0,
            "quality": {
                "ok": False,
                "reason": error or "no credible pricing page found",
                "text_score": 0,
                "final_url": final_url,
                "page_status": page_status,
                "discovery_method": discovery_method,
            },
            "extraction_method": "python_rule",
        }
        return payload, "manual_review", 10, [error or "No credible pricing page found"]

    parser = parse_pricing_html(html_body)
    text = parser.text
    jsonld_plans = extract_jsonld_plans(parser.jsonld_scripts)
    text_plans = extract_text_plans(text)
    plans = jsonld_plans or text_plans
    validation_errors: list[str] = []
    if http_status < 200 or http_status >= 400:
        validation_errors.append(error or f"HTTP {http_status}")
    if http_status == 200 and not is_strict_pricing_url(final_url):
        validation_errors.append(f"Final URL is not a strict pricing page: {final_url}")
    if http_status == 200 and not final_url_matches_source_context(source_url, final_url):
        validation_errors.append(f"Final URL lost source context: {final_url}")
    if not plans:
        validation_errors.append("No public pricing plans found")
    validation_errors.extend(validate_plan_price_integrity(plans))
    if jsonld_plans and text_plans:
        validation_errors.extend(validate_jsonld_visible_price_conflicts(jsonld_plans, text_plans))

    has_paid_or_quote = any(
        price.get("custom_quote") or decimal_value(price.get("amount")) > 0
        for plan in plans
        for price in plan.get("prices", [])
    )
    if plans and not has_paid_or_quote and not any(plan["name"].lower() == "free" for plan in plans):
        validation_errors.append("No paid, free, or custom-quote plan found")

    approved = not validation_errors and bool(plans)
    confidence = 82 if approved else 45 if plans else 25
    payload = {
        "plans": plans,
        "plan_count": len(plans),
        "quality": {
            "ok": approved,
            "reason": validation_errors[0] if validation_errors else None,
            "text_score": pricing_text_quality(text),
            "final_url": final_url,
            "page_status": page_status,
            "discovery_method": discovery_method,
        },
        "extraction_method": "python_rule",
    }
    return payload, "approved" if approved else "manual_review", confidence, validation_errors


def derive_final_pipeline_stage(
    payload: dict[str, Any],
    review_status: str,
    extractor_version: str,
    model_name: str | None,
    discovery_method: str,
) -> str:
    used_browser = "browser_run" in (discovery_method or "")
    if review_status != "approved":
        return "browser_run_manual_review" if used_browser else "manual_review"
    if model_name or extractor_version == OPENAI_PRICING_EXTRACTOR_VERSION or payload.get("extraction_method") == "openai_structured":
        return "browser_run_openai" if used_browser else "openai"
    page_status = ((payload.get("quality") or {}).get("page_status") or "").strip()
    if page_status == "contact_sales":
        return "contact_sales"
    return "browser_run_rule" if used_browser else "rule"


def openai_pricing_schema() -> dict[str, Any]:
    price_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "kind": {"type": "string", "enum": ["recurring", "one_time", "usage", "custom_quote"]},
            "amount": {"type": ["string", "null"]},
            "currency": {"type": ["string", "null"]},
            "billing_interval": {"type": ["string", "null"], "enum": ["monthly", "yearly", "one_time", "usage", "custom", None]},
            "commitment_interval": {"type": ["string", "null"], "enum": ["monthly", "yearly", "none", None]},
            "unit": {"type": ["string", "null"]},
            "custom_quote": {"type": "boolean"},
            "starting_at": {"type": "boolean"},
            "display_text": {"type": "string"},
        },
        "required": [
            "kind",
            "amount",
            "currency",
            "billing_interval",
            "commitment_interval",
            "unit",
            "custom_quote",
            "starting_at",
            "display_text",
        ],
    }
    plan_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "source_plan_key": {"type": "string"},
            "name": {"type": "string"},
            "audience": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "is_enterprise": {"type": "boolean"},
            "display_order": {"type": "integer"},
            "prices": {"type": "array", "items": price_schema},
            "features": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "source_plan_key",
            "name",
            "audience",
            "description",
            "is_enterprise",
            "display_order",
            "prices",
            "features",
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "plans": {"type": "array", "items": plan_schema},
            "confidence": {"type": "integer"},
            "notes": {"type": "string"},
        },
        "required": ["plans", "confidence", "notes"],
    }


def normalize_openai_plan(plan: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(plan, dict):
        return None
    raw_prices = plan.get("prices") if isinstance(plan.get("prices"), list) else []
    raw_price = raw_prices[0] if raw_prices and isinstance(raw_prices[0], dict) else {}
    raw_amount = raw_price.get("amount")
    amount = read_decimal(raw_amount) if raw_amount not in (None, "") else None
    custom_quote = bool(raw_price.get("custom_quote")) or amount is None or raw_price.get("kind") == "custom_quote"
    kind = str(raw_price.get("kind") or ("custom_quote" if custom_quote else "recurring"))
    if kind not in {"recurring", "one_time", "usage", "custom_quote"}:
        kind = "custom_quote" if custom_quote else "recurring"

    billing_interval = raw_price.get("billing_interval")
    if billing_interval not in {"monthly", "yearly", "one_time", "usage", "custom", None}:
        billing_interval = None
    commitment_interval = raw_price.get("commitment_interval")
    if commitment_interval not in {"monthly", "yearly", "none", None}:
        commitment_interval = None

    name = clean_snippet(str(plan.get("name") or ""), 80)
    if not name:
        name = "Enterprise" if custom_quote else f"Plan {index + 1}"
    price = {
        "kind": kind,
        "amount": None if custom_quote else amount,
        "currency": normalize_currency(str(raw_price.get("currency") or "USD")) if not custom_quote else None,
        "billing_interval": billing_interval,
        "commitment_interval": None if commitment_interval == "none" else commitment_interval,
        "unit": clean_snippet(str(raw_price.get("unit") or ""), 40) or None,
        "custom_quote": custom_quote,
        "starting_at": bool(raw_price.get("starting_at")),
        "display_text": clean_snippet(str(raw_price.get("display_text") or ""), 180),
    }
    features = [
        clean_snippet(str(feature), 120)
        for feature in (plan.get("features") if isinstance(plan.get("features"), list) else [])
        if clean_snippet(str(feature), 120)
    ][:12]
    source_key = clean_snippet(str(plan.get("source_plan_key") or ""), 80)
    if not source_key:
        source_key = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:80]
    return {
        "source_plan_key": source_key,
        "name": name,
        "audience": clean_snippet(str(plan.get("audience") or ""), 80) or None,
        "description": clean_snippet(str(plan.get("description") or ""), 220) or None,
        "is_enterprise": 1 if bool(plan.get("is_enterprise")) or re.search(r"enterprise|contact", name, re.I) else 0,
        "prices": [price],
        "features": features,
        "display_order": index,
    }


def validate_pricing_plans(
    plans: list[dict[str, Any]],
    source_url: str,
    final_url: str,
    http_status: int,
    error: str,
) -> list[str]:
    validation_errors: list[str] = []
    if http_status < 200 or http_status >= 400:
        validation_errors.append(error or f"HTTP {http_status}")
    if http_status == 200 and not is_strict_pricing_url(final_url):
        validation_errors.append(f"Final URL is not a strict pricing page: {final_url}")
    if http_status == 200 and not final_url_matches_source_context(source_url, final_url):
        validation_errors.append(f"Final URL lost source context: {final_url}")
    if not plans:
        validation_errors.append("No public pricing plans found")
    validation_errors.extend(validate_plan_price_integrity(plans))

    has_paid_or_quote = any(
        price.get("custom_quote") or decimal_value(price.get("amount")) > 0
        for plan in plans
        for price in plan.get("prices", [])
    )
    if plans and not has_paid_or_quote and not any(plan["name"].lower() == "free" for plan in plans):
        validation_errors.append("No paid, free, or custom-quote plan found")
    return validation_errors


class OpenAIPricingExtractor:
    def __init__(self, api_key: str, model: str, timeout_seconds: int, text_chars: int):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.text_chars = text_chars

    async def extract(
        self,
        html_body: str,
        source_url: str,
        final_url: str,
        http_status: int,
        error: str,
    ) -> tuple[dict[str, Any], str, int, list[str]] | None:
        if not self.api_key or http_status != 200 or not html_body:
            return None
        text = parse_pricing_html(html_body).text[: self.text_chars]
        if not text.strip():
            return None

        request_payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Extract public SaaS pricing plans from the provided pricing page text. "
                        "Return only primary public package prices. Ignore discounts, trials, FAQ examples, add-ons, "
                        "API credit tables, and unrelated comparison text unless they are the main package price. "
                        "Use at most six plans. Each plan must keep at most one primary price."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "source_url": source_url,
                            "final_url": final_url,
                            "pricing_text": text,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "pricing_extraction",
                    "strict": True,
                    "schema": openai_pricing_schema(),
                },
            },
            "max_completion_tokens": 3000,
        }

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout_seconds)) as client:
                response = await client.post(
                    f"{OPENAI_API_BASE}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=request_payload,
                )
            response.raise_for_status()
            data = response.json()
            message = ((data.get("choices") or [{}])[0].get("message") or {})
            content = message.get("content")
            if not content:
                log_info("pricing.openai.empty_response", model=self.model, final_url=final_url)
                return None
            parsed = json.loads(content)
        except Exception as error_value:
            log_info("pricing.openai.failed", model=self.model, final_url=final_url, error=str(error_value)[:300])
            return None

        raw_plans = parsed.get("plans") if isinstance(parsed, dict) else []
        plans = [
            normalized
            for index, raw_plan in enumerate(raw_plans if isinstance(raw_plans, list) else [])
            if (normalized := normalize_openai_plan(raw_plan, index)) is not None
        ][:6]
        validation_errors = validate_pricing_plans(plans, source_url, final_url, http_status, error)
        validation_errors.extend(validate_extracted_plan_consistency(plans))
        try:
            model_confidence = int(parsed.get("confidence") or 70) if isinstance(parsed, dict) else 70
        except (TypeError, ValueError):
            model_confidence = 70
        if model_confidence < OPENAI_PRICING_MIN_CONFIDENCE:
            validation_errors.append(f"OpenAI confidence below {OPENAI_PRICING_MIN_CONFIDENCE}: {model_confidence}")
        approved = not validation_errors and bool(plans)
        confidence = min(90, max(0, model_confidence)) if approved else min(65, max(20, model_confidence))
        payload = {
            "plans": plans,
            "plan_count": len(plans),
            "quality": {
                "ok": approved,
                "reason": validation_errors[0] if validation_errors else None,
                "text_score": pricing_text_quality(text),
                "final_url": final_url,
                "notes": clean_snippet(str(parsed.get("notes") or ""), 300) if isinstance(parsed, dict) else "",
            },
            "extraction_method": "openai_structured",
        }
        return payload, "approved" if approved else "manual_review", confidence, validation_errors


class CloudflareBrowserRunRenderer:
    def __init__(self, config: Config):
        self.endpoint = (
            f"{D1_API_BASE}/accounts/{config.cloudflare_account_id}"
            "/browser-rendering/content"
        )
        self.headers = {
            "Authorization": f"Bearer {config.browser_rendering_api_token}",
            "Content-Type": "application/json",
        }
        self.timeout_seconds = config.browser_rendering_timeout_seconds

    async def render(self, result: PricingFetchResult) -> PricingFetchResult | None:
        target_url = result.final_url or result.url
        request_payload = {
            "url": target_url,
            "userAgent": random_pricing_user_agent(),
            "setExtraHTTPHeaders": {
                "Accept-Language": "en-US,en;q=0.9",
            },
            "rejectResourceTypes": ["image", "media", "font"],
            "gotoOptions": {
                "waitUntil": "networkidle0",
            },
        }
        try:
            async with httpx.AsyncClient(timeout=float(self.timeout_seconds)) as client:
                response = await client.post(self.endpoint, headers=self.headers, json=request_payload)
        except Exception as error:
            log_info("pricing.browser_render.failed", url=target_url, error=str(error)[:300])
            return None

        if response.status_code < 200 or response.status_code >= 300:
            log_info(
                "pricing.browser_render.http_error",
                url=target_url,
                status=response.status_code,
                body=response_body_sample(response, 300),
            )
            return None

        rendered_html = ""
        try:
            data = response.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            if data.get("success") is False:
                log_info("pricing.browser_render.api_error", url=target_url, response=str(data)[:300])
                return None
            rendered = data.get("result")
            if isinstance(rendered, dict):
                rendered = rendered.get("content") or rendered.get("html")
            if isinstance(rendered, str):
                rendered_html = rendered
        if not rendered_html and "html" in response.headers.get("content-type", "").lower():
            rendered_html = response.text
        if not rendered_html.strip():
            log_info("pricing.browser_render.empty", url=target_url)
            return None

        log_info(
            "pricing.browser_render.done",
            url=target_url,
            text_score=pricing_text_quality(parse_pricing_html(rendered_html).text),
        )
        return PricingFetchResult(
            url=result.url,
            final_url=target_url,
            status=200,
            content_type="text/html; rendered=cloudflare-browser-run",
            html=rendered_html,
            error="",
            page_status="found",
            discovery_method=f"{result.discovery_method}+browser_run",
        )


class CloudflareBrowserRunAssetClient:
    def __init__(self, config: Config):
        self.endpoint_base = f"{D1_API_BASE}/accounts/{config.cloudflare_account_id}/browser-rendering"
        self.headers = {
            "Authorization": f"Bearer {config.browser_rendering_api_token}",
            "Content-Type": "application/json",
        }
        self.timeout_seconds = config.browser_rendering_timeout_seconds

    async def call_quick_action(self, endpoint: str, body: dict[str, Any]) -> Any:
        async with httpx.AsyncClient(timeout=float(self.timeout_seconds)) as client:
            response = await client.post(f"{self.endpoint_base}/{endpoint}", headers=self.headers, json=body)
        text = response.text
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = None
        if response.status_code < 200 or response.status_code >= 300 or (isinstance(parsed, dict) and parsed.get("success") is False):
            message = ""
            if isinstance(parsed, dict):
                errors = parsed.get("errors")
                if isinstance(errors, list):
                    message = "; ".join(str(error.get("message") or "") for error in errors if isinstance(error, dict))
            raise RuntimeError(message or text[:300] or f"HTTP {response.status_code}")
        return parsed.get("result") if isinstance(parsed, dict) and "result" in parsed else parsed

    async def fetch_homepage_asset(self, task: AssetTask) -> AssetFetchResult:
        primary_url = asset_page_url(task)
        parsed = urlsplit(primary_url)
        candidates = [primary_url]
        if parsed.scheme == "https":
            candidates.append(f"http://{parsed.netloc}{parsed.path or '/'}")

        errors: list[str] = []
        for target_url in candidates:
            payload = {
                "url": target_url,
                "userAgent": random_pricing_user_agent(),
                "setExtraHTTPHeaders": {
                    "Accept-Language": "en-US,en;q=0.9",
                },
                "gotoOptions": {
                    "waitUntil": "domcontentloaded",
                    "timeout": self.timeout_seconds * 1000,
                },
            }
            try:
                snapshot = await self.call_quick_action("snapshot", payload)
                screenshot_raw = snapshot.get("screenshot") if isinstance(snapshot, dict) else None
                if not screenshot_raw:
                    raise RuntimeError("snapshot returned no screenshot")
                if isinstance(screenshot_raw, str) and "," in screenshot_raw[:40]:
                    screenshot_raw = screenshot_raw.split(",", 1)[1]
                screenshot = base64.b64decode(str(screenshot_raw), validate=False)
                html_body = ""
                try:
                    content = await self.call_quick_action(
                        "content",
                        {
                            **payload,
                            "rejectResourceTypes": ["image", "media", "font"],
                        },
                    )
                    if isinstance(content, dict):
                        html_body = str(content.get("content") or content.get("html") or "")
                    elif isinstance(content, str):
                        html_body = content
                except Exception as content_error:
                    log_info("assets.browser_content.failed", url=target_url, error=str(content_error)[:300])
                return AssetFetchResult(final_url=target_url, screenshot=screenshot, html=html_body)
            except Exception as error:
                errors.append(f"{target_url}: {str(error)[:220]}")

        raise RuntimeError("Browser Run asset capture failed. " + " | ".join(errors))


class R2AssetUploader:
    def __init__(self, config: Config):
        if not config.r2_access_key_id or not config.r2_secret_access_key:
            raise RuntimeError("Missing CLOUDFLARE_R2_ACCESS_KEY_ID or CLOUDFLARE_R2_SECRET_ACCESS_KEY.")
        if not config.r2_bucket:
            raise RuntimeError("Missing CLOUDFLARE_R2_BUCKET.")
        self.account_id = config.cloudflare_account_id
        self.access_key_id = config.r2_access_key_id
        self.secret_access_key = config.r2_secret_access_key
        self.bucket = config.r2_bucket

    def signing_key(self, date_stamp: str) -> bytes:
        key = ("AWS4" + self.secret_access_key).encode("utf-8")
        for value in (date_stamp, "auto", "s3", "aws4_request"):
            key = hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()
        return key

    async def put_object(self, key: str, body: bytes, content_type: str) -> None:
        host = f"{self.account_id}.r2.cloudflarestorage.com"
        canonical_uri = f"/{quote(self.bucket, safe='')}/{quote(key, safe='/-_.~')}"
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "content-type": content_type,
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
        canonical_request = "\n".join(["PUT", canonical_uri, "", canonical_headers, signed_headers, payload_hash])
        credential_scope = f"{date_stamp}/auto/s3/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signature = hmac.new(self.signing_key(date_stamp), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self.access_key_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.put(f"https://{host}{canonical_uri}", headers=headers, content=body)
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"R2 upload failed: HTTP {response.status_code} {response.text[:300]}")


def amount_minor(value: str | None) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int((Decimal(str(value)) * 100).to_integral_value())
    except InvalidOperation:
        return None


def derive_tool_pricing_summary(plans: list[dict[str, Any]]) -> dict[str, Any]:
    prices = [price for plan in plans for price in plan.get("prices", [])]
    has_free = any(
        (price.get("amount") == "0") or plan.get("name", "").lower() == "free"
        for plan in plans
        for price in plan.get("prices", [])
    )
    custom_only = bool(prices) and all(price.get("custom_quote") for price in prices)
    paid_prices = [
        price
        for price in prices
        if not price.get("custom_quote") and decimal_value(price.get("amount")) > 0
    ]
    usage_only = bool(paid_prices) and all(price.get("kind") == "usage" for price in paid_prices)

    if paid_prices and has_free:
        pricing_model = "freemium"
    elif paid_prices and usage_only:
        pricing_model = "usage_based"
    elif paid_prices:
        pricing_model = "paid"
    elif custom_only:
        pricing_model = "contact"
    elif has_free:
        pricing_model = "free"
    else:
        pricing_model = "unknown"

    def candidate_rank(price: dict[str, Any]) -> tuple[int, Decimal]:
        interval = price.get("billing_interval")
        amount = decimal_value(price.get("amount"))
        if interval == "monthly":
            return (0, amount)
        if interval == "yearly":
            return (1, amount)
        return (2, amount)

    chosen = sorted(paid_prices, key=candidate_rank)[0] if paid_prices else None
    if chosen and chosen.get("billing_interval") in {"monthly", "yearly"}:
        pricing_interval = chosen.get("billing_interval")
    elif usage_only:
        pricing_interval = "usage"
    elif custom_only:
        pricing_interval = "custom"
    else:
        pricing_interval = "none"

    starting_minor = amount_minor(chosen.get("amount")) if chosen else None
    currency = normalize_currency(chosen.get("currency") if chosen else None) if chosen else None
    return {
        "pricing_model": pricing_model,
        "has_free_plan": 1 if has_free else 0,
        "pricing_interval": pricing_interval,
        "pricing_currency_code": None if currency == "USD" else currency,
        "starting_price_minor": None if currency == "USD" else starting_minor,
        "starting_price_usd_minor": starting_minor if currency == "USD" else None,
    }


def previous_traffic_month() -> str:
    now = datetime.now(timezone.utc)
    first_this_month = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    previous = first_this_month - timedelta(days=1)
    return f"{previous.year}-{previous.month:02d}-01"


def to_number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed == parsed else None


def to_integer(value: Any) -> int | None:
    parsed = to_number(value)
    if parsed is None:
        return None
    return max(0, int(parsed))


def to_month_start(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    match = re.match(r"^(\d{4})-(\d{2})", text)
    if not match:
        return None
    return f"{match.group(1)}-{match.group(2)}-01"


def country_name(country_code: Any) -> str | None:
    if not country_code:
        return None
    return str(country_code).upper()


def parse_country_rank(payload: dict[str, Any]) -> dict[str, Any]:
    country_rank = payload.get("CountryRank") or {}
    country_code = country_rank.get("CountryCode")
    rank = to_integer(country_rank.get("Rank"))
    return {
        "country_rank_country": country_code,
        "country_rank": rank,
        "country_rank_text": f"{country_code} #{rank}" if country_code and rank is not None else None,
    }


def parse_traffic_sources(payload: dict[str, Any]) -> dict[str, Any]:
    sources = payload.get("TrafficSources") or {}
    return {
        "social_traffic_share": to_number(sources.get("Social")),
        "paid_referrals_traffic_share": to_number(sources.get("Paid Referrals")),
        "mail_traffic_share": to_number(sources.get("Mail")),
        "search_traffic_share": to_number(sources.get("Search")),
        "direct_traffic_share": to_number(sources.get("Direct")),
        "referrals_traffic_share": to_number(sources.get("Referrals")),
    }


def parse_top_countries(payload: dict[str, Any]) -> dict[str, Any]:
    countries = payload.get("TopCountryShares") or []
    result: dict[str, Any] = {}
    for index in range(1, 6):
        country = countries[index - 1] if index - 1 < len(countries) else {}
        result[f"top_country_{index}"] = country_name(country.get("CountryCode"))
        result[f"top_country_{index}_traffic_share"] = to_number(country.get("Value"))
    return result


def parse_monthly_rows(payload: dict[str, Any], domain: str, requested_month: str) -> list[dict[str, Any]]:
    engagements = payload.get("Engagments") or {}
    estimated_visits = payload.get("EstimatedMonthlyVisits") or {}
    snapshot_month = to_month_start(payload.get("SnapshotDate"))
    query_date = None
    if to_integer(engagements.get("Year")) and to_integer(engagements.get("Month")):
        query_date = f"{to_integer(engagements.get('Year'))}-{to_integer(engagements.get('Month')):02d}-01"

    base_fields = {
        "website": payload.get("SiteName") or domain,
        "query_date": query_date,
        "engagement_visits": to_integer(engagements.get("Visits")),
        "global_rank": to_integer((payload.get("GlobalRank") or {}).get("Rank")),
        **parse_country_rank(payload),
        "bounce_rate": to_number(engagements.get("BounceRate")),
        "pages_per_visit": to_number(engagements.get("PagePerVisit")),
        "avg_visit_duration_seconds": to_integer(engagements.get("TimeOnSite")),
        **parse_traffic_sources(payload),
        **parse_top_countries(payload),
    }

    monthly_rows: list[dict[str, Any]] = []
    if isinstance(estimated_visits, dict):
        for month, visits in estimated_visits.items():
            traffic_month = to_month_start(month)
            if traffic_month:
                monthly_rows.append({"traffic_month": traffic_month, "visits": to_integer(visits)})

    if not monthly_rows:
        traffic_month = snapshot_month or requested_month
        monthly_rows.append({"traffic_month": traffic_month, "visits": to_integer(engagements.get("Visits"))})

    monthly_rows.sort(key=lambda row: row["traffic_month"])
    latest_month = monthly_rows[-1]["traffic_month"]
    for row in monthly_rows:
        if row["traffic_month"] == latest_month:
            row.update(base_fields)
        else:
            row.update({"website": domain, "query_date": None})
    return monthly_rows


class SimilarWebClient:
    def __init__(self, config: Config):
        self.proxy_host = config.brightdata_proxy_host
        self.proxy_port = config.brightdata_proxy_port
        self.proxy_user = config.brightdata_proxy_user
        self.proxy_password = config.brightdata_proxy_password
        self.proxy_user_summary = mask_value(config.brightdata_proxy_user)
        log_info(
            "similarweb.client.config",
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            proxy_user=self.proxy_user_summary,
            proxy_zone=extract_brightdata_zone(config.brightdata_proxy_user),
            proxy_user_has_session="-session-" in config.brightdata_proxy_user,
            proxy_session_per_fetch=True,
        )

    def build_proxy_url(self) -> str:
        session_id = generate_session_id()
        username = f"{self.proxy_user}-session-{session_id}"
        return f"http://{username}:{self.proxy_password}@{self.proxy_host}:{self.proxy_port}"

    async def fetch(self, domain: str, requested_month: str) -> FetchResult:
        clean_domain = normalize_domain(domain)
        if not clean_domain:
            log_info("similarweb.invalid_domain", domain=domain, requested_month=requested_month)
            return FetchResult(status="failed", monthly_rows=[], error="invalid_domain")

        headers = {
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
        }
        url = f"{SIMILARWEB_API_BASE}?domain={clean_domain}"
        log_info("similarweb.fetch.start", domain=clean_domain, requested_month=requested_month)

        try:
            started_at = time.perf_counter()
            async with CurlAsyncSession() as client:
                response = await client.get(
                    url,
                    proxy=self.build_proxy_url(),
                    headers=headers,
                    timeout=25.0,
                    verify=False,
                    impersonate="chrome",
                    default_headers=True,
                )
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        except Exception as error:
            log_error(
                "similarweb.fetch.request_error",
                domain=clean_domain,
                error_type=type(error).__name__,
                error=str(error)[:500],
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                proxy_user=self.proxy_user_summary,
            )
            return FetchResult(status="failed", monthly_rows=[], error=f"request_error:{str(error)[:300]}")

        is_success = 200 <= response.status_code < 300
        response_history = getattr(response, "history", []) or []
        log_info(
            "similarweb.fetch.response",
            domain=clean_domain,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            final_host=urlsplit(str(response.url)).netloc,
            http_version=str(getattr(response, "http_version", "")),
            history_statuses=[item.status_code for item in response_history],
            **response_header_summary(response),
        )
        if not is_success:
            log_info(
                "similarweb.fetch.response_body",
                domain=clean_domain,
                status_code=response.status_code,
                body_sample=response_body_sample(response),
            )

        if response.status_code == 404:
            return FetchResult(status="no_data", monthly_rows=[], error="similarweb_no_data")
        if response.status_code == 403:
            return FetchResult(status="forbidden", monthly_rows=[], error="similarweb_forbidden")
        if response.status_code in (407, 429) or response.status_code >= 500:
            return FetchResult(
                status="failed",
                monthly_rows=[],
                error=f"similarweb_http_{response.status_code}:{response.text[:300]}",
            )
        if not is_success:
            return FetchResult(
                status="failed",
                monthly_rows=[],
                error=f"similarweb_http_{response.status_code}:{response.text[:300]}",
            )

        try:
            payload = response.json()
        except json.JSONDecodeError:
            log_error("similarweb.fetch.invalid_json", domain=clean_domain)
            return FetchResult(status="failed", monthly_rows=[], error="similarweb_invalid_json")

        monthly_rows = parse_monthly_rows(payload, clean_domain, requested_month)
        has_data = any(row.get("visits") is not None for row in monthly_rows) or any(
            row.get("global_rank") is not None for row in monthly_rows
        )
        status = "done" if has_data else "no_data"
        log_info("similarweb.fetch.parsed", domain=clean_domain, status=status, monthly_rows=len(monthly_rows))
        return FetchResult(status=status, monthly_rows=monthly_rows)


def extract_rdap_created_at(payload: dict[str, Any]) -> str | None:
    events = payload.get("events")
    if not isinstance(events, list):
        return None

    action_groups = [
        {"registration"},
        {"created", "creation", "registered"},
    ]
    for actions in action_groups:
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction") or "").lower()
            event_date = parse_iso_timestamp(event.get("eventDate"))
            if action in actions and event_date:
                return event_date
    return None


def find_rdap_base_urls(domain: str, bootstrap: dict[str, Any]) -> list[str]:
    labels = [part for part in domain.split(".") if part]
    suffixes = [".".join(labels[index:]) for index in range(len(labels))]
    best_match = ""
    best_urls: list[str] = []

    services = bootstrap.get("services")
    if not isinstance(services, list):
        return []

    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, urls = service
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        tld_set = {str(tld).lower().lstrip(".") for tld in tlds}
        for suffix in suffixes:
            if suffix in tld_set and len(suffix) > len(best_match):
                best_match = suffix
                best_urls = [str(url).strip() for url in urls if str(url).strip()]

    return best_urls


class DomainStateClient:
    async def fetch(self, domain: str) -> DomainStateResult:
        ahrefs_result, whois_result = await asyncio.gather(
            self.fetch_ahrefs_domain_rating(domain),
            self.fetch_domain_created_at(domain),
        )
        return DomainStateResult(
            status=ahrefs_result.status,
            domain_rating=ahrefs_result.domain_rating,
            domain_created_at=ahrefs_result.domain_created_at or whois_result.domain_created_at,
            error=ahrefs_result.error,
        )

    async def fetch_ahrefs_domain_rating(self, domain: str) -> DomainStateResult:
        clean_domain = normalize_domain(domain)
        if not clean_domain:
            return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error="invalid_domain")

        endpoint = httpx.URL(AHREFS_DOMAIN_RATING_URL).copy_add_param("target", clean_domain)
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.get(endpoint, headers={"Accept": "application/json,text/plain,*/*"})
        except Exception as error:
            return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error=str(error)[:300])

        if response.status_code == 404:
            return DomainStateResult(status="no_data", domain_rating=None, domain_created_at=None, error="ahrefs_not_found")
        if not response.is_success:
            raise RuntimeError(f"Ahrefs HTTP {response.status_code}: {response.text[:300]}")

        try:
            payload = response.json()
        except json.JSONDecodeError:
            raise RuntimeError("Ahrefs returned invalid JSON")

        raw_rating = (payload.get("domain_rating") or {}).get("domain_rating") if isinstance(payload.get("domain_rating"), dict) else payload.get("domain_rating")
        rating = to_number(raw_rating)
        created_at = parse_iso_timestamp(
            payload.get("domain_created_at")
            or payload.get("created_at")
            or ((payload.get("domain_rating") or {}).get("domain_created_at") if isinstance(payload.get("domain_rating"), dict) else None)
        )
        if rating is None:
            return DomainStateResult(status="no_data", domain_rating=None, domain_created_at=created_at, error="ahrefs_domain_rating_not_found")

        return DomainStateResult(
            status="done",
            domain_rating=min(max(rating, 0), 100),
            domain_created_at=created_at,
        )

    async def fetch_rdap_json(self, url: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=25.0) as client:
            response = await client.get(
                url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": RDAP_USER_AGENT,
                },
            )
        if response.status_code == 404:
            raise FileNotFoundError("rdap_http_404")
        if not response.is_success:
            raise RuntimeError(f"RDAP HTTP {response.status_code}: {response.text[:300]}")
        try:
            payload = response.json()
        except json.JSONDecodeError:
            raise RuntimeError("RDAP returned invalid JSON")
        return payload if isinstance(payload, dict) else {}

    async def fetch_domain_created_at(self, domain: str) -> DomainStateResult:
        clean_domain = normalize_rdap_domain(domain)
        if not clean_domain:
            return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error="invalid_domain")

        try:
            bootstrap = await self.fetch_rdap_json(IANA_RDAP_DNS)
            base_urls = find_rdap_base_urls(clean_domain, bootstrap)
        except Exception as error:
            return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error=str(error)[:300])

        if not base_urls:
            return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error=f"rdap_service_not_found:{clean_domain}")

        last_error = ""
        for base_url in base_urls:
            url = f"{base_url.rstrip('/')}/domain/{clean_domain}"
            try:
                payload = await self.fetch_rdap_json(url)
            except FileNotFoundError:
                return DomainStateResult(status="no_data", domain_rating=None, domain_created_at=None, error="rdap_http_404")
            except Exception as error:
                last_error = str(error)[:300]
                continue

            created_at = extract_rdap_created_at(payload)
            return DomainStateResult(
                status="done" if created_at else "no_data",
                domain_rating=None,
                domain_created_at=created_at,
                error=None if created_at else "created_at_not_found",
            )

        return DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error=f"rdap_query_failed:{last_error}")


class PricingClient:
    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds

    async def fetch_url(self, url: str) -> PricingFetchResult:
        try:
            normalized = normalize_pricing_url(url)
            headers = pricing_request_headers(normalized)
        except ValueError as error:
            return PricingFetchResult(url=url, final_url=url, status=0, content_type="", html="", error=str(error))

        try:
            started_at = time.perf_counter()
            async with httpx.AsyncClient(
                timeout=float(self.timeout_seconds),
                follow_redirects=True,
                headers=headers,
            ) as client:
                response = await client.get(normalized)
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        except Exception as error:
            log_info("pricing.fetch.request_error", url=normalized, error=str(error)[:300])
            return PricingFetchResult(url=normalized, final_url=normalized, status=0, content_type="", html="", error=str(error)[:300])

        content_type = response.headers.get("content-type", "")
        html_body = ""
        if any(kind in content_type.lower() for kind in ("html", "xml", "text")):
            body = response.content[:MAX_PRICING_HTML_BYTES]
            html_body = body.decode(response.encoding or "utf-8", errors="replace")
        log_info(
            "pricing.fetch.response",
            url=normalized,
            final_url=str(response.url),
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            content_type=content_type[:120],
        )
        return PricingFetchResult(
            url=normalized,
            final_url=str(response.url),
            status=response.status_code,
            content_type=content_type,
            html=html_body,
            error="" if response.is_success else f"HTTP {response.status_code}",
        )

    async def fetch_sitemap_body(self, origin_url: str) -> str:
        try:
            origin = pricing_url_origin(origin_url)
        except ValueError:
            return ""
        root = await self.fetch_url(urljoin(origin, "/sitemap.xml"))
        if root.status != 200 or not root.html:
            return ""

        bodies = [root.html]
        nested_sitemaps = []
        for loc in extract_sitemap_locs(root.html):
            try:
                parsed = urlsplit(loc)
            except ValueError:
                continue
            if parsed.netloc == urlsplit(origin).netloc and parsed.path.lower().endswith(".xml"):
                nested_sitemaps.append(loc)
        for sitemap_url in nested_sitemaps[:4]:
            nested = await self.fetch_url(sitemap_url)
            if nested.status == 200 and nested.html:
                bodies.append(nested.html)
        return "\n".join(bodies)

    async def choose_pricing_page(self, task: PricingTask) -> PricingFetchResult:
        first = await self.fetch_url(task.source_url)
        first_text = parse_pricing_html(first.html).text if first.html else ""
        if first.status == 200 and is_strict_pricing_url(first.final_url) and pricing_text_quality(first_text) >= 12:
            return PricingFetchResult(
                first.url,
                first.final_url,
                first.status,
                first.content_type,
                first.html,
                first.error,
                "found",
                "source_url",
            )

        try:
            home_url = pricing_url_origin(task.official_url or task.source_url)
        except ValueError:
            home_url = task.source_url
        home = await self.fetch_url(home_url)
        sitemap_body = await self.fetch_sitemap_body(home.final_url or home_url)
        candidates = discover_pricing_urls(home.final_url or home_url, home.html, sitemap_body) if home.html else []
        best_result = first
        best_score = (
            pricing_url_score(first.final_url) + pricing_text_quality(first_text)
            if first.status == 200
            else -1000
        )
        for candidate in candidates:
            if candidate.rstrip("/") == first.final_url.rstrip("/"):
                continue
            result = await self.fetch_url(candidate)
            text = parse_pricing_html(result.html).text if result.html else ""
            if result.status != 200 or not is_strict_pricing_url(result.final_url):
                continue
            score = pricing_url_score(result.final_url) + pricing_text_quality(text)
            if score > best_score:
                best_result = result
                best_score = score
        best_text = parse_pricing_html(best_result.html).text if best_result.html else ""
        if (
            best_result.status == 200
            and is_strict_pricing_url(best_result.final_url)
            and pricing_text_quality(best_text) > 0
        ):
            return PricingFetchResult(
                best_result.url,
                best_result.final_url,
                best_result.status,
                best_result.content_type,
                best_result.html,
                best_result.error,
                "found",
                "candidate_scored",
            )

        contact_candidates = discover_contact_sales_urls(home.final_url or home_url, home.html, sitemap_body) if home.html else []
        for candidate in contact_candidates:
            result = await self.fetch_url(candidate)
            text = parse_pricing_html(result.html).text if result.html else ""
            if result.status == 200 and len(text) >= 80:
                return PricingFetchResult(
                    result.url,
                    result.final_url,
                    result.status,
                    result.content_type,
                    result.html,
                    result.error,
                    "contact_sales",
                    "contact_or_demo",
                )

        return PricingFetchResult(
            best_result.url,
            best_result.final_url,
            best_result.status,
            best_result.content_type,
            best_result.html,
            best_result.error or "No credible pricing page found",
            "not_found",
            "none",
        )


class D1Client:
    def __init__(self, config: Config):
        self.url = (
            f"{D1_API_BASE}/accounts/{config.cloudflare_account_id}"
            f"/d1/database/{config.cloudflare_d1_database_id}/query"
        )
        self.headers = {
            "Authorization": f"Bearer {config.cloudflare_api_token}",
            "Content-Type": "application/json",
        }

    async def execute(self, sql: str, params: list[Any] | None = None) -> Any:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(self.url, headers=self.headers, json={"sql": sql, "params": params or []})
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success", False):
            raise RuntimeError(f"D1 query failed: {payload}")
        result = payload.get("result")
        if isinstance(result, list):
            first_result = result[0] if result else {}
            if isinstance(first_result, dict) and not first_result.get("success", True):
                raise RuntimeError(f"D1 query failed: {payload}")
            return first_result
        return result or {}

    async def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        result = await self.execute(sql, params)
        if isinstance(result, dict) and isinstance(result.get("results"), list):
            return result["results"]
        return []

    async def run(self, sql: str, params: list[Any] | None = None) -> dict[str, Any]:
        result = await self.execute(sql, params)
        if isinstance(result, dict) and isinstance(result.get("meta"), dict):
            return result["meta"]
        return {}

    async def insert_snapshot(self, domain: str, task_month: str, status: str, row: dict[str, Any], error: str | None) -> None:
        await self.execute(
            """
            INSERT INTO domain_traffic_snapshots (
              normalized_domain, source, website, query_date, traffic_month, status,
              visits, engagement_visits, global_rank, country_rank_country, country_rank,
              country_rank_text, bounce_rate, pages_per_visit, avg_visit_duration_seconds,
              social_traffic_share, paid_referrals_traffic_share, mail_traffic_share,
              search_traffic_share, direct_traffic_share, referrals_traffic_share,
              top_country_1, top_country_1_traffic_share, top_country_2, top_country_2_traffic_share,
              top_country_3, top_country_3_traffic_share, top_country_4, top_country_4_traffic_share,
              top_country_5, top_country_5_traffic_share, fetched_at, last_error
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              CURRENT_TIMESTAMP, ?
            )
            """,
            [
                domain,
                TRAFFIC_SOURCE,
                row.get("website") or domain,
                row.get("query_date"),
                row.get("traffic_month") or task_month,
                status,
                row.get("visits"),
                row.get("engagement_visits"),
                row.get("global_rank"),
                row.get("country_rank_country"),
                row.get("country_rank"),
                row.get("country_rank_text"),
                row.get("bounce_rate"),
                row.get("pages_per_visit"),
                row.get("avg_visit_duration_seconds"),
                row.get("social_traffic_share"),
                row.get("paid_referrals_traffic_share"),
                row.get("mail_traffic_share"),
                row.get("search_traffic_share"),
                row.get("direct_traffic_share"),
                row.get("referrals_traffic_share"),
                row.get("top_country_1"),
                row.get("top_country_1_traffic_share"),
                row.get("top_country_2"),
                row.get("top_country_2_traffic_share"),
                row.get("top_country_3"),
                row.get("top_country_3_traffic_share"),
                row.get("top_country_4"),
                row.get("top_country_4_traffic_share"),
                row.get("top_country_5"),
                row.get("top_country_5_traffic_share"),
                error,
            ],
        )

    async def insert_result(self, task: TrafficTask, result: FetchResult) -> None:
        rows = result.monthly_rows or [{"traffic_month": task.traffic_month}]
        log_info(
            "d1.insert_result.start",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            status=result.status,
            rows=len(rows),
        )
        for row in rows:
            await self.insert_snapshot(task.normalized_domain, task.traffic_month, result.status, row, result.error)
        if result.monthly_rows:
            await self.upsert_tool_traffic_monthly(task.normalized_domain, result.monthly_rows)
        log_info(
            "d1.insert_result.done",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            status=result.status,
            rows=len(rows),
        )

    async def upsert_tool_traffic_monthly(self, domain: str, rows: list[dict[str, Any]]) -> None:
        tools = await self.query(
            """
            SELECT id
            FROM tools
            WHERE normalized_domain = ?
              AND status = 'published'
              AND duplicate_of_tool_id IS NULL
            """,
            [domain],
        )
        if not tools:
            log_info("d1.tool_traffic_monthly.no_matching_tools", domain=domain)
            return

        captured_at = utc_now_iso()
        for tool in tools:
            tool_id = int(tool.get("id") or 0)
            if tool_id <= 0:
                continue
            for row in rows:
                traffic_month = row.get("traffic_month")
                if not traffic_month:
                    continue
                await self.run(
                    """
                    INSERT INTO tool_traffic_monthly (
                      tool_id, normalized_domain, source, traffic_month, visits,
                      global_rank, country_rank_country, country_rank, bounce_rate,
                      pages_per_visit, avg_visit_duration_seconds, captured_at, raw_payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tool_id, source, traffic_month) DO UPDATE
                    SET normalized_domain = excluded.normalized_domain,
                        visits = excluded.visits,
                        global_rank = excluded.global_rank,
                        country_rank_country = excluded.country_rank_country,
                        country_rank = excluded.country_rank,
                        bounce_rate = excluded.bounce_rate,
                        pages_per_visit = excluded.pages_per_visit,
                        avg_visit_duration_seconds = excluded.avg_visit_duration_seconds,
                        captured_at = excluded.captured_at,
                        raw_payload = excluded.raw_payload,
                        updated_at = ?
                    """,
                    [
                        tool_id,
                        domain,
                        TRAFFIC_SOURCE,
                        traffic_month,
                        row.get("visits"),
                        row.get("global_rank") or None,
                        row.get("country_rank_country"),
                        row.get("country_rank") or None,
                        row.get("bounce_rate"),
                        row.get("pages_per_visit"),
                        row.get("avg_visit_duration_seconds"),
                        captured_at,
                        json.dumps(row, ensure_ascii=False),
                        captured_at,
                    ],
                )


class D1AssetStore:
    def __init__(self, d1: D1Client):
        self.d1 = d1

    async def queue_missing_asset_tasks(self, limit: int) -> int:
        now = utc_now_iso()
        stale_queued_before = iso_delta(hours=-1)
        stale_done_before = iso_delta(hours=-24)
        rows = await self.d1.query(
            """
            SELECT
              t.id AS tool_id,
              t.canonical_slug,
              t.normalized_domain,
              t.official_url
            FROM tools t
            LEFT JOIN asset_tasks task
              ON task.tool_id = t.id
             AND task.source = ?
            WHERE t.status = 'published'
              AND t.duplicate_of_tool_id IS NULL
              AND trim(t.normalized_domain) <> ''
              AND (
                NOT EXISTS (
                  SELECT 1
                  FROM tool_assets ta
                  WHERE ta.tool_id = t.id
                    AND ta.asset_kind = 'screenshot'
                    AND ta.storage_bucket = ?
                    AND ta.is_current = 1
                )
                OR NOT EXISTS (
                  SELECT 1
                  FROM tool_assets ta
                  WHERE ta.tool_id = t.id
                    AND ta.asset_kind = 'favicon'
                    AND ta.is_current = 1
                )
              )
              AND (
                task.tool_id IS NULL
                OR (
                  task.status IN ('failed', 'sync_failed')
                  AND (task.next_retry_at IS NULL OR task.next_retry_at <= ?)
                )
                OR (
                  task.status IN ('queued', 'processing')
                  AND task.updated_at < ?
                )
                OR (
                  task.status = 'done'
                  AND task.updated_at < ?
                )
              )
            ORDER BY t.id ASC
            LIMIT ?
            """,
            [ASSET_SOURCE, ASSET_DB_STORAGE_BUCKET, now, stale_queued_before, stale_done_before, limit],
        )
        queued = 0
        for row in rows:
            tool_id = int(row.get("tool_id") or 0)
            domain = str(row.get("normalized_domain") or "")
            if tool_id <= 0 or not domain:
                continue
            await self.d1.run(
                """
                INSERT INTO asset_tasks (
                  tool_id, normalized_domain, source, status, last_queued_at, next_retry_at, last_error
                )
                VALUES (?, ?, ?, 'queued', ?, NULL, NULL)
                ON CONFLICT (tool_id, source) DO UPDATE
                SET normalized_domain = excluded.normalized_domain,
                    status = excluded.status,
                    last_queued_at = excluded.last_queued_at,
                    next_retry_at = NULL,
                    last_error = NULL,
                    updated_at = excluded.last_queued_at
                """,
                [tool_id, domain, ASSET_SOURCE, now],
            )
            queued += 1
        return queued

    async def claim_due_tasks(self, limit: int) -> list[AssetTask]:
        now = utc_now_iso()
        stale_processing_before = iso_delta(hours=-1)
        next_retry_at = iso_delta(hours=1)
        rows = await self.d1.query(
            """
            SELECT
              task.tool_id,
              task.normalized_domain,
              task.attempts,
              t.canonical_slug,
              t.official_url
            FROM asset_tasks task
            JOIN tools t ON t.id = task.tool_id
            WHERE task.source = ?
              AND (
                (
                  task.status IN ('queued', 'failed', 'sync_failed')
                  AND (task.next_retry_at IS NULL OR task.next_retry_at <= ?)
                )
                OR (
                  task.status = 'processing'
                  AND task.updated_at < ?
                )
              )
            ORDER BY coalesce(task.next_retry_at, ''), task.updated_at
            LIMIT ?
            """,
            [ASSET_SOURCE, now, stale_processing_before, limit],
        )

        claimed: list[AssetTask] = []
        for row in rows:
            tool_id = int(row.get("tool_id") or 0)
            domain = str(row.get("normalized_domain") or "")
            if tool_id <= 0 or not domain:
                continue
            meta = await self.d1.run(
                """
                UPDATE asset_tasks
                SET status = 'processing',
                    attempts = attempts + 1,
                    last_started_at = ?,
                    next_retry_at = ?,
                    last_error = NULL,
                    updated_at = ?
                WHERE tool_id = ?
                  AND source = ?
                  AND (
                    (
                      status IN ('queued', 'failed', 'sync_failed')
                      AND (next_retry_at IS NULL OR next_retry_at <= ?)
                    )
                    OR (
                      status = 'processing'
                      AND updated_at < ?
                    )
                  )
                """,
                [now, next_retry_at, now, tool_id, ASSET_SOURCE, now, stale_processing_before],
            )
            if int(meta.get("changes") or 0) > 0:
                claimed.append(
                    AssetTask(
                        tool_id=tool_id,
                        canonical_slug=str(row.get("canonical_slug") or ""),
                        normalized_domain=domain,
                        official_url=str(row.get("official_url") or ""),
                        attempts=int(row.get("attempts") or 0) + 1,
                    )
                )
        return claimed

    async def upsert_tool_asset(
        self,
        task: AssetTask,
        asset_kind: str,
        storage_object_path: str,
        public_url: str | None,
        mime_type: str,
        width: int | None,
        height: int | None,
    ) -> None:
        rows = await self.d1.query(
            """
            SELECT id
            FROM tool_assets
            WHERE tool_id = ?
              AND asset_kind = ?
              AND coalesce(locale_code, '') = ''
              AND is_current = 1
            LIMIT 1
            """,
            [task.tool_id, asset_kind],
        )
        if rows:
            await self.d1.run(
                """
                UPDATE tool_assets
                SET storage_bucket = ?,
                    storage_object_path = ?,
                    public_url = ?,
                    mime_type = ?,
                    width = ?,
                    height = ?,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ?
                """,
                [ASSET_DB_STORAGE_BUCKET, storage_object_path, public_url, mime_type, width, height, rows[0]["id"]],
            )
            return

        await self.d1.run(
            """
            INSERT INTO tool_assets (
              tool_id,
              locale_code,
              asset_kind,
              storage_bucket,
              storage_object_path,
              public_url,
              mime_type,
              width,
              height,
              is_current
            )
            VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            [task.tool_id, asset_kind, ASSET_DB_STORAGE_BUCKET, storage_object_path, public_url, mime_type, width, height],
        )

    async def complete_task(self, task: AssetTask, status: str, error: str | None = None) -> None:
        now = utc_now_iso()
        await self.d1.run(
            """
            UPDATE asset_tasks
            SET status = ?,
                last_fetched_at = ?,
                next_retry_at = ?,
                last_error = ?,
                updated_at = ?
            WHERE tool_id = ?
              AND source = ?
            """,
            [
                status,
                now,
                None if status == "done" else iso_delta(days=1),
                (error or "")[:2000] or None,
                now,
                task.tool_id,
                ASSET_SOURCE,
            ],
        )


class D1TaskStore:
    def __init__(self, d1: D1Client):
        self.d1 = d1

    async def queue_missing_traffic_tasks(self, limit: int, traffic_month: str) -> int:
        now = utc_now_iso()
        stale_queued_before = iso_delta(hours=-1)
        candidates = await self.d1.query(
            """
            SELECT t.normalized_domain
            FROM tools t
            LEFT JOIN tool_traffic_monthly tm
              ON tm.normalized_domain = t.normalized_domain
             AND tm.source = ?
             AND tm.traffic_month = ?
            LEFT JOIN traffic_tasks task
              ON task.normalized_domain = t.normalized_domain
             AND task.source = ?
             AND task.traffic_month = ?
            WHERE t.status = 'published'
              AND t.duplicate_of_tool_id IS NULL
              AND trim(t.normalized_domain) <> ''
              AND tm.traffic_month IS NULL
              AND (
                task.normalized_domain IS NULL
                OR (
                  task.status IN ('failed', 'sync_failed')
                  AND (task.next_retry_at IS NULL OR task.next_retry_at <= ?)
                )
                OR (
                  task.status IN ('queued', 'processing')
                  AND task.updated_at < ?
                )
              )
            GROUP BY t.normalized_domain
            ORDER BY min(coalesce(task.updated_at, '')) ASC, min(t.id) ASC
            LIMIT ?
            """,
            [TRAFFIC_SOURCE, traffic_month, TRAFFIC_SOURCE, traffic_month, now, stale_queued_before, limit],
        )

        queued = 0
        for candidate in candidates:
            domain = str(candidate.get("normalized_domain") or "")
            if not domain:
                continue
            await self.d1.run(
                """
                INSERT INTO traffic_tasks (
                  normalized_domain, source, traffic_month, status, last_queued_at, next_retry_at, last_error
                )
                VALUES (?, ?, ?, 'queued', ?, NULL, NULL)
                ON CONFLICT (normalized_domain, source, traffic_month) DO UPDATE
                SET status = excluded.status,
                    last_queued_at = excluded.last_queued_at,
                    next_retry_at = excluded.next_retry_at,
                    last_error = NULL,
                    updated_at = excluded.last_queued_at
                """,
                [domain, TRAFFIC_SOURCE, traffic_month, now],
            )
            queued += 1

        return queued

    async def claim_due_tasks(self, limit: int) -> list[TrafficTask]:
        now = utc_now_iso()
        stale_processing_before = iso_delta(hours=-1)
        next_retry_at = iso_delta(hours=1)
        rows = await self.d1.query(
            """
            SELECT normalized_domain, source, traffic_month, attempts
            FROM traffic_tasks
            WHERE source = ?
              AND (
                (
                  status IN ('queued', 'failed', 'sync_failed')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                )
                OR (
                  status = 'processing'
                  AND updated_at < ?
                )
              )
            ORDER BY coalesce(next_retry_at, ''), updated_at
            LIMIT ?
            """,
            [TRAFFIC_SOURCE, now, stale_processing_before, limit],
        )

        claimed: list[TrafficTask] = []
        for row in rows:
            domain = str(row.get("normalized_domain") or "")
            traffic_month = str(row.get("traffic_month") or "")
            if not domain or not traffic_month:
                continue

            meta = await self.d1.run(
                """
                UPDATE traffic_tasks
                SET status = 'processing',
                    attempts = attempts + 1,
                    last_started_at = ?,
                    next_retry_at = ?,
                    last_error = NULL,
                    updated_at = ?
                WHERE normalized_domain = ?
                  AND source = ?
                  AND traffic_month = ?
                  AND (
                    (
                      status IN ('queued', 'failed', 'sync_failed')
                      AND (next_retry_at IS NULL OR next_retry_at <= ?)
                    )
                    OR (
                      status = 'processing'
                      AND updated_at < ?
                    )
                  )
                """,
                [
                    now,
                    next_retry_at,
                    now,
                    domain,
                    TRAFFIC_SOURCE,
                    traffic_month,
                    now,
                    stale_processing_before,
                ],
            )
            if int(meta.get("changes") or 0) > 0:
                claimed.append(
                    TrafficTask(
                        normalized_domain=domain,
                        traffic_month=traffic_month,
                        attempts=int(row.get("attempts") or 0) + 1,
                    )
                )

        return claimed

    async def complete_task(self, task: TrafficTask, result: FetchResult) -> None:
        retry_days = 1 if result.status == "failed" else None
        now = utc_now_iso()
        log_info(
            "d1.complete_task.start",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            status=result.status,
        )
        await self.d1.run(
            """
            UPDATE traffic_tasks
            SET status = ?,
                last_fetched_at = ?,
                next_retry_at = ?,
                last_error = ?,
                updated_at = ?
            WHERE normalized_domain = ?
              AND source = ?
              AND traffic_month = ?
            """,
            [
                result.status,
                now,
                iso_delta(days=retry_days) if retry_days is not None else None,
                (result.error or "")[:2000] or None,
                now,
                task.normalized_domain,
                TRAFFIC_SOURCE,
                task.traffic_month,
            ],
        )
        await self.update_tool_status(task.normalized_domain, result)
        log_info(
            "d1.complete_task.done",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            status=result.status,
        )

    async def update_tool_status(self, domain: str, result: FetchResult) -> None:
        retry_days = 30
        if result.status in ("no_data", "forbidden"):
            retry_days = 7
        if result.status == "failed":
            retry_days = 1

        now = utc_now_iso()
        await self.d1.run(
            """
            INSERT INTO tool_traffic_fetch_status (
              tool_id, normalized_domain, source, last_checked_at, last_status, last_error, next_retry_at
            )
            SELECT
              id,
              normalized_domain,
              ?,
              ?,
              ?,
              ?,
              ?
            FROM tools
            WHERE normalized_domain = ?
              AND status = 'published'
              AND duplicate_of_tool_id IS NULL
            ON CONFLICT (tool_id, source) DO UPDATE
            SET normalized_domain = excluded.normalized_domain,
                last_checked_at = excluded.last_checked_at,
                last_status = excluded.last_status,
                last_error = excluded.last_error,
                next_retry_at = excluded.next_retry_at,
                updated_at = ?
            """,
            [
                TRAFFIC_SOURCE,
                now,
                result.status,
                (result.error or "")[:2000] or None,
                iso_delta(days=retry_days),
                domain,
                now,
            ],
        )


class D1DomainStateStore:
    def __init__(self, d1: D1Client):
        self.d1 = d1

    async def get_due_candidates(self, limit: int, max_age_days: int) -> list[DomainStateCandidate]:
        stale_before = iso_delta(days=-max_age_days)
        missing_created_at_before = iso_delta(days=-1)
        rows = await self.d1.query(
            """
            SELECT t.normalized_domain
            FROM tools t
            LEFT JOIN domain_states ds
              ON ds.normalized_domain = t.normalized_domain
             AND ds.source = ?
            WHERE t.status = 'published'
              AND t.duplicate_of_tool_id IS NULL
              AND trim(t.normalized_domain) <> ''
              AND (
                ds.last_crawled_at IS NULL
                OR ds.last_crawled_at < ?
                OR (
                  ds.domain_created_at IS NULL
                  AND ds.last_crawled_at < ?
                )
              )
            GROUP BY t.normalized_domain
            ORDER BY CASE WHEN min(ds.last_crawled_at) IS NULL THEN 0 ELSE 1 END,
                     min(ds.last_crawled_at) ASC,
                     t.normalized_domain ASC
            LIMIT ?
            """,
            [DOMAIN_STATE_SOURCE, stale_before, missing_created_at_before, limit],
        )
        return [
            DomainStateCandidate(normalized_domain=str(row.get("normalized_domain") or ""))
            for row in rows
            if row.get("normalized_domain")
        ]

    async def update_domain_state(self, domain: str, result: DomainStateResult) -> None:
        now = utc_now_iso()
        await self.d1.run(
            """
            INSERT INTO domain_states (
              normalized_domain, source, domain_rating, last_crawled_at, domain_created_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (normalized_domain, source) DO UPDATE
            SET domain_rating = excluded.domain_rating,
                last_crawled_at = excluded.last_crawled_at,
                domain_created_at = coalesce(excluded.domain_created_at, domain_states.domain_created_at),
                updated_at = ?
            """,
            [
                domain,
                DOMAIN_STATE_SOURCE,
                result.domain_rating,
                now,
                result.domain_created_at,
                now,
            ],
        )


class D1PricingStore:
    def __init__(self, d1: D1Client):
        self.d1 = d1

    async def queue_due_tasks(self, limit: int) -> int:
        now = utc_now_iso()
        rows = await self.d1.query(
            """
            WITH latest_task AS (
              SELECT pricing_source_id, max(id) AS task_id
              FROM pricing_tasks
              GROUP BY pricing_source_id
            )
            SELECT
              ps.id AS pricing_source_id,
              ps.tool_id
            FROM pricing_sources ps
            JOIN tools t ON t.id = ps.tool_id
            LEFT JOIN latest_task lt ON lt.pricing_source_id = ps.id
            LEFT JOIN pricing_tasks task ON task.id = lt.task_id
            WHERE ps.is_active = 1
              AND t.status = 'published'
              AND t.duplicate_of_tool_id IS NULL
              AND (
                ps.next_run_at IS NULL
                OR ps.next_run_at <= ?
                OR t.pricing_model = 'unknown'
              )
              AND (
                task.id IS NULL
                OR task.status IN ('succeeded', 'failed')
              )
            ORDER BY coalesce(ps.next_run_at, ''), ps.id
            LIMIT ?
            """,
            [now, limit],
        )

        queued = 0
        for row in rows:
            source_id = int(row.get("pricing_source_id") or 0)
            tool_id = int(row.get("tool_id") or 0)
            if source_id <= 0 or tool_id <= 0:
                continue
            await self.d1.run(
                """
                INSERT INTO pricing_tasks (
                  pricing_source_id,
                  tool_id,
                  status,
                  priority,
                  run_after,
                  attempts,
                  max_attempts,
                  last_error
                )
                VALUES (?, ?, 'queued', 0, ?, 0, 3, NULL)
                """,
                [source_id, tool_id, now],
            )
            queued += 1
        return queued

    async def claim_due_tasks(
        self,
        limit: int,
        task_ids: list[int] | None = None,
        claim: bool = True,
    ) -> list[PricingTask]:
        now = utc_now_iso()
        task_ids = task_ids or []
        params: list[Any]
        if task_ids:
            placeholders = ", ".join("?" for _ in task_ids)
            where = f"task.id IN ({placeholders}) AND task.status IN ('queued', 'manual_review', 'failed')"
            params = [*task_ids, limit]
        else:
            where = "task.status = 'queued' AND task.run_after <= ? AND task.attempts < task.max_attempts"
            params = [now, limit]

        rows = await self.d1.query(
            f"""
            SELECT
              task.id AS task_id,
              task.pricing_source_id,
              task.tool_id,
              task.attempts,
              task.max_attempts,
              t.canonical_slug,
              t.official_url,
              ps.url AS source_url
            FROM pricing_tasks task
            JOIN pricing_sources ps ON ps.id = task.pricing_source_id
            JOIN tools t ON t.id = task.tool_id
            WHERE {where}
            ORDER BY task.priority DESC, task.id ASC
            LIMIT ?
            """,
            params,
        )

        tasks: list[PricingTask] = []
        for row in rows:
            task = PricingTask(
                task_id=int(row["task_id"]),
                pricing_source_id=int(row["pricing_source_id"]),
                tool_id=int(row["tool_id"]),
                canonical_slug=str(row.get("canonical_slug") or ""),
                source_url=str(row.get("source_url") or ""),
                official_url=str(row.get("official_url") or ""),
                attempts=int(row.get("attempts") or 0) + (1 if claim else 0),
                max_attempts=int(row.get("max_attempts") or 3),
            )
            if not claim:
                tasks.append(task)
                continue

            meta = await self.d1.run(
                """
                UPDATE pricing_tasks
                SET status = 'running',
                    attempts = attempts + 1,
                    started_at = ?,
                    finished_at = NULL,
                    last_error = NULL,
                    updated_at = ?
                WHERE id = ?
                  AND status IN ('queued', 'manual_review', 'failed')
                """,
                [now, now, task.task_id],
            )
            if int(meta.get("changes") or 0) > 0:
                tasks.append(task)
        return tasks

    async def insert_snapshot(self, task: PricingTask, result: PricingFetchResult) -> int:
        text = parse_pricing_html(result.html).text if result.html else ""
        raw_hash = sha256_text(result.html or f"{result.status}:{result.final_url}")
        text_hash = sha256_text(text)
        meta = await self.d1.run(
            """
            INSERT INTO pricing_snapshots (
              pricing_source_id,
              pricing_task_id,
              final_url,
              http_status,
              content_type,
              raw_hash,
              semantic_hash,
              fetch_mode,
              error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'static', ?)
            """,
            [
                task.pricing_source_id,
                task.task_id,
                result.final_url or result.url,
                result.status or None,
                result.content_type or None,
                raw_hash,
                text_hash,
                result.error or None,
            ],
        )
        return int(meta.get("last_row_id") or 0)

    async def insert_extraction(
        self,
        snapshot_id: int,
        payload: dict[str, Any],
        review_status: str,
        confidence: int,
        validation_errors: list[str],
        extractor_version: str = PRICING_EXTRACTOR_VERSION,
        model_name: str | None = None,
    ) -> int:
        meta = await self.d1.run(
            """
            INSERT INTO pricing_extractions (
              snapshot_id,
              schema_version,
              extractor_version,
              model_name,
              raw_extraction_json,
              confidence_score,
              validation_errors,
              review_status
            )
            VALUES (?, 'v1', ?, ?, ?, ?, ?, ?)
            """,
            [
                snapshot_id,
                extractor_version,
                model_name,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                confidence,
                json.dumps(validation_errors, ensure_ascii=False, separators=(",", ":")),
                review_status,
            ],
        )
        return int(meta.get("last_row_id") or 0)

    async def save_catalog(self, task: PricingTask, result: PricingFetchResult, plans: list[dict[str, Any]]) -> int:
        now = utc_now_iso()
        context_hash = sha256_text(f"{task.pricing_source_id}:{result.final_url or result.url}")
        version_hash = sha256_text(json.dumps(plans, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        await self.d1.run(
            """
            INSERT INTO pricing_catalog_versions (
              tool_id,
              pricing_source_id,
              context_hash,
              version_hash,
              first_observed_at,
              last_observed_at,
              status
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT (pricing_source_id, context_hash, version_hash) DO UPDATE SET
              last_observed_at = excluded.last_observed_at,
              superseded_at = NULL,
              status = 'active'
            """,
            [task.tool_id, task.pricing_source_id, context_hash, version_hash, now, now],
        )
        rows = await self.d1.query(
            """
            SELECT id
            FROM pricing_catalog_versions
            WHERE pricing_source_id = ?
              AND context_hash = ?
              AND version_hash = ?
            LIMIT 1
            """,
            [task.pricing_source_id, context_hash, version_hash],
        )
        if not rows:
            raise RuntimeError("Unable to resolve pricing catalog version.")
        version_id = int(rows[0]["id"])

        await self.d1.run(
            """
            UPDATE pricing_catalog_versions
            SET status = 'superseded',
                superseded_at = ?
            WHERE pricing_source_id = ?
              AND status = 'active'
              AND id <> ?
            """,
            [now, task.pricing_source_id, version_id],
        )
        await self.d1.run(
            """
            DELETE FROM plan_features
            WHERE pricing_plan_id IN (
              SELECT id FROM pricing_plans WHERE pricing_version_id = ?
            )
            """,
            [version_id],
        )
        await self.d1.run(
            """
            DELETE FROM plan_prices
            WHERE pricing_plan_id IN (
              SELECT id FROM pricing_plans WHERE pricing_version_id = ?
            )
            """,
            [version_id],
        )
        await self.d1.run("DELETE FROM pricing_plans WHERE pricing_version_id = ?", [version_id])

        for index, plan in enumerate(plans):
            plan_meta = await self.d1.run(
                """
                INSERT INTO pricing_plans (
                  pricing_version_id,
                  source_plan_key,
                  name,
                  description,
                  audience,
                  is_enterprise,
                  display_order
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    version_id,
                    plan.get("source_plan_key"),
                    plan.get("name"),
                    plan.get("description"),
                    plan.get("audience"),
                    1 if plan.get("is_enterprise") else 0,
                    index,
                ],
            )
            plan_id = int(plan_meta.get("last_row_id") or 0)
            for price in list(plan.get("prices") or [])[:1]:
                await self.d1.run(
                    """
                    INSERT INTO plan_prices (
                      pricing_plan_id,
                      kind,
                      amount,
                      currency,
                      billing_interval,
                      commitment_interval,
                      unit,
                      starting_at,
                      custom_quote,
                      display_text,
                      derived
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    [
                        plan_id,
                        price.get("kind") or "recurring",
                        price.get("amount"),
                        price.get("currency"),
                        price.get("billing_interval"),
                        price.get("commitment_interval"),
                        price.get("unit"),
                        1 if price.get("starting_at") else 0,
                        1 if price.get("custom_quote") else 0,
                        price.get("display_text"),
                    ],
                )
        return version_id

    async def update_summary(self, task: PricingTask, plans: list[dict[str, Any]]) -> None:
        summary = derive_tool_pricing_summary(plans)
        await self.d1.run(
            """
            UPDATE tools
            SET pricing_model = ?,
                has_free_plan = ?,
                pricing_interval = ?,
                pricing_currency_code = ?,
                starting_price_minor = ?,
                starting_price_usd_minor = ?,
                updated_at = ?
            WHERE id = ?
            """,
            [
                summary["pricing_model"],
                summary["has_free_plan"],
                summary["pricing_interval"],
                summary["pricing_currency_code"],
                summary["starting_price_minor"],
                summary["starting_price_usd_minor"],
                utc_now_iso(),
                task.tool_id,
            ],
        )

    async def finish_task(
        self,
        task: PricingTask,
        status: str,
        error: str | None,
        result: PricingFetchResult | None,
    ) -> None:
        now = utc_now_iso()
        await self.d1.run(
            """
            UPDATE pricing_tasks
            SET status = ?,
                last_error = ?,
                finished_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            [status, (error or "")[:2000] or None, now, now, task.task_id],
        )
        if status == "succeeded":
            await self.d1.run(
                """
                UPDATE pricing_sources
                SET last_success_at = ?,
                    last_content_hash = ?,
                    unchanged_runs = 0,
                    next_run_at = ?,
                    last_error = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                [
                    now,
                    sha256_text(result.html) if result else None,
                    iso_delta(days=30),
                    now,
                    task.pricing_source_id,
                ],
            )
            return

        await self.d1.run(
            """
            UPDATE pricing_sources
            SET last_error = ?,
                updated_at = ?
            WHERE id = ?
            """,
            [(error or "")[:2000] or None, now, task.pricing_source_id],
        )


async def process_task(
    task: TrafficTask,
    similarweb: SimilarWebClient,
    d1: D1Client,
    store: D1TaskStore,
    max_retries: int,
) -> str:
    result = FetchResult(status="failed", monthly_rows=[], error="not_started")
    for attempt in range(max_retries + 1):
        log_info(
            "task.fetch_attempt.start",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            attempt=attempt + 1,
            max_attempts=max_retries + 1,
        )
        result = await similarweb.fetch(task.normalized_domain, task.traffic_month)
        log_info(
            "task.fetch_attempt.done",
            domain=task.normalized_domain,
            traffic_month=task.traffic_month,
            attempt=attempt + 1,
            status=result.status,
        )
        if result.status != "failed":
            break
        if attempt < max_retries:
            await asyncio.sleep(random.uniform(1.0, 3.0))

    await d1.insert_result(task, result)
    await store.complete_task(task, result)
    return result.status


async def process_domain_state(
    candidate: DomainStateCandidate,
    client: DomainStateClient,
    store: D1DomainStateStore,
    max_retries: int,
) -> str:
    result = DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error="not_started")
    for attempt in range(max_retries + 1):
        log_info(
            "domain_state.fetch_attempt.start",
            domain=candidate.normalized_domain,
            attempt=attempt + 1,
            max_attempts=max_retries + 1,
        )
        try:
            result = await client.fetch(candidate.normalized_domain)
        except Exception as error:
            result = DomainStateResult(status="failed", domain_rating=None, domain_created_at=None, error=str(error)[:300])
        log_info(
            "domain_state.fetch_attempt.done",
            domain=candidate.normalized_domain,
            attempt=attempt + 1,
            status=result.status,
        )
        if result.status != "failed":
            break
        if attempt < max_retries:
            await asyncio.sleep(random.uniform(1.0, 3.0))

    if result.status in ("done", "no_data"):
        await store.update_domain_state(candidate.normalized_domain, result)
    return result.status


async def fetch_favicon_asset(page_url: str, domain: str, html_body: str) -> FaviconAsset | None:
    favicon_url = extract_favicon_href(html_body, page_url)
    if not favicon_url:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                page_response = await client.get(
                    page_url,
                    headers={
                        "User-Agent": random_pricing_user_agent(),
                        "Accept": "text/html,application/xhtml+xml",
                    },
                )
            if 200 <= page_response.status_code < 300:
                favicon_url = extract_favicon_href(page_response.text[:200000], str(page_response.url))
        except Exception as error:
            log_info("assets.favicon.discover_failed", domain=domain, url=page_url, error=str(error)[:300])
    favicon_url = favicon_url or urljoin(page_url, "/favicon.ico")
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.get(
                favicon_url,
                headers={
                    "User-Agent": random_pricing_user_agent(),
                    "Accept": "image/avif,image/webp,image/png,image/svg+xml,image/*,*/*;q=0.8",
                    "Referer": page_url,
                },
            )
    except Exception as error:
        log_info("assets.favicon.fetch_failed", domain=domain, url=favicon_url, error=str(error)[:300])
        return None
    if response.status_code < 200 or response.status_code >= 300:
        log_info("assets.favicon.http_error", domain=domain, url=favicon_url, status=response.status_code)
        return None
    try:
        content_length = int(response.headers.get("content-length") or 0)
    except ValueError:
        content_length = 0
    if content_length > 1024 * 1024:
        return None
    body = response.content
    if not body or len(body) > 1024 * 1024:
        return None
    mime_type = asset_mime_type(favicon_url, response.headers.get("content-type", ""))
    extension = asset_extension(favicon_url, mime_type)
    return FaviconAsset(
        body=body,
        key=f"{domain}/favicon-{int(time.time() * 1000)}{extension}",
        mime_type=mime_type,
    )


async def process_asset_task(
    task: AssetTask,
    browser_client: CloudflareBrowserRunAssetClient,
    uploader: R2AssetUploader,
    store: D1AssetStore,
    public_base_url: str,
    max_retries: int,
) -> str:
    last_error = "not_started"
    for attempt in range(max_retries + 1):
        try:
            log_info(
                "asset_task.fetch_attempt.start",
                tool_id=task.tool_id,
                slug=task.canonical_slug,
                domain=task.normalized_domain,
                attempt=attempt + 1,
                max_attempts=max_retries + 1,
            )
            result = await browser_client.fetch_homepage_asset(task)
            screenshot_key = f"{task.normalized_domain}/{int(time.time() * 1000)}.png"
            await uploader.put_object(screenshot_key, result.screenshot, "image/png")
            await store.upsert_tool_asset(
                task,
                "screenshot",
                screenshot_key,
                asset_public_url(public_base_url, screenshot_key),
                "image/png",
                1280,
                720,
            )

            favicon = await fetch_favicon_asset(result.final_url, task.normalized_domain, result.html)
            if favicon is not None:
                await uploader.put_object(favicon.key, favicon.body, favicon.mime_type)
                await store.upsert_tool_asset(
                    task,
                    "favicon",
                    favicon.key,
                    asset_public_url(public_base_url, favicon.key),
                    favicon.mime_type,
                    None,
                    None,
                )

            await store.complete_task(task, "done")
            log_info(
                "asset_task.fetch_attempt.done",
                tool_id=task.tool_id,
                slug=task.canonical_slug,
                domain=task.normalized_domain,
                status="done",
                favicon=bool(favicon),
            )
            return "done"
        except Exception as error:
            last_error = str(error)[:900]
            log_error(
                "asset_task.fetch_attempt.failed",
                tool_id=task.tool_id,
                slug=task.canonical_slug,
                domain=task.normalized_domain,
                attempt=attempt + 1,
                error=last_error,
            )
            if attempt < max_retries:
                await asyncio.sleep(random.uniform(1.0, 3.0))

    await store.complete_task(task, "failed", last_error)
    return "failed"


async def run_openai_pricing_extraction(
    task: PricingTask,
    result: PricingFetchResult,
    payload: dict[str, Any],
    review_status: str,
    confidence: int,
    validation_errors: list[str],
    openai_extractors: list[OpenAIPricingExtractor],
    needs_model_check: bool,
    model_check_reasons: list[str],
) -> tuple[dict[str, Any], str, int, list[str], str | None]:
    if not ((review_status != "approved" or needs_model_check) and openai_extractors and result.page_status == "found"):
        return payload, review_status, confidence, validation_errors, None

    model_name = None
    model_verified = False
    for index, openai_extractor in enumerate(openai_extractors):
        openai_extraction = await openai_extractor.extract(
            result.html,
            task.source_url,
            result.final_url,
            result.status,
            result.error,
        )
        if openai_extraction is None:
            if index + 1 < len(openai_extractors):
                log_info(
                    "pricing.openai.escalate",
                    from_model=openai_extractor.model,
                    to_model=openai_extractors[index + 1].model,
                    reason="empty_response",
                )
            continue

        payload, review_status, confidence, validation_errors = openai_extraction
        model_name = openai_extractor.model
        model_verified = True
        if (review_status != "approved" or confidence < OPENAI_PRICING_MIN_CONFIDENCE) and index + 1 < len(openai_extractors):
            log_info(
                "pricing.openai.escalate",
                from_model=openai_extractor.model,
                to_model=openai_extractors[index + 1].model,
                review_status=review_status,
                confidence=confidence,
                validation_errors=validation_errors[:3],
            )
            continue
        break

    if not model_verified and needs_model_check:
        review_status = "manual_review"
        validation_errors = [*validation_errors, f"Rule extraction requires model verification: {', '.join(model_check_reasons)}"]
        confidence = min(confidence, 55)
    return payload, review_status, confidence, validation_errors, model_name


def should_render_pricing_with_browser(
    result: PricingFetchResult,
    review_status: str,
    text_score: int,
    validation_errors: list[str],
) -> bool:
    if review_status == "approved":
        return False
    if result.status != 200 or not result.html:
        return False
    if result.page_status not in {"found", "not_found"}:
        return False
    if not is_strict_pricing_url(result.final_url):
        return False
    if text_score < BROWSER_RENDERING_TEXT_SCORE_THRESHOLD:
        return True
    return any("No public pricing plans found" in error for error in validation_errors)


async def process_pricing_task(
    task: PricingTask,
    client: PricingClient,
    openai_extractors: list[OpenAIPricingExtractor],
    browser_renderer: CloudflareBrowserRunRenderer | None,
    store: D1PricingStore,
    max_retries: int,
    approve_pricing: bool,
    dry_run: bool,
) -> str:
    result = PricingFetchResult(task.source_url, task.source_url, 0, "", "", "not_started")
    for attempt in range(max_retries + 1):
        log_info(
            "pricing_task.fetch_attempt.start",
            task_id=task.task_id,
            slug=task.canonical_slug,
            attempt=attempt + 1,
            max_attempts=max_retries + 1,
        )
        result = await client.choose_pricing_page(task)
        log_info(
            "pricing_task.fetch_attempt.done",
            task_id=task.task_id,
            slug=task.canonical_slug,
            attempt=attempt + 1,
            status=result.status,
            final_url=result.final_url,
        )
        if result.status and result.status < 500:
            break
        if attempt < max_retries:
            await asyncio.sleep(random.uniform(1.0, 3.0))

    payload, review_status, confidence, validation_errors = extract_pricing_payload(
        result.html,
        task.source_url,
        result.final_url,
        result.status,
        result.error,
        result.page_status,
        result.discovery_method,
    )
    extractor_version = PRICING_EXTRACTOR_VERSION
    model_name = None
    text_score = pricing_text_quality(parse_pricing_html(result.html).text if result.html else "")
    needs_model_check, model_check_reasons = should_verify_rule_pricing_with_openai(
        payload,
        text_score,
        result.page_status,
    )
    payload, review_status, confidence, validation_errors, model_name = await run_openai_pricing_extraction(
        task,
        result,
        payload,
        review_status,
        confidence,
        validation_errors,
        openai_extractors,
        needs_model_check,
        model_check_reasons,
    )
    if model_name:
        extractor_version = OPENAI_PRICING_EXTRACTOR_VERSION

    if browser_renderer is not None and should_render_pricing_with_browser(result, review_status, text_score, validation_errors):
        rendered_result = await browser_renderer.render(result)
        if rendered_result is not None:
            result = rendered_result
            payload, review_status, confidence, validation_errors = extract_pricing_payload(
                result.html,
                task.source_url,
                result.final_url,
                result.status,
                result.error,
                result.page_status,
                result.discovery_method,
            )
            extractor_version = PRICING_EXTRACTOR_VERSION
            model_name = None
            text_score = pricing_text_quality(parse_pricing_html(result.html).text if result.html else "")
            needs_model_check, model_check_reasons = should_verify_rule_pricing_with_openai(
                payload,
                text_score,
                result.page_status,
            )
            payload, review_status, confidence, validation_errors, model_name = await run_openai_pricing_extraction(
                task,
                result,
                payload,
                review_status,
                confidence,
                validation_errors,
                openai_extractors,
                needs_model_check,
                model_check_reasons,
            )
            if model_name:
                extractor_version = OPENAI_PRICING_EXTRACTOR_VERSION

    final_pipeline_stage = derive_final_pipeline_stage(
        payload,
        review_status,
        extractor_version,
        model_name,
        result.discovery_method,
    )
    payload["final_pipeline_stage"] = final_pipeline_stage

    if review_status == "approved" and not approve_pricing:
        review_status = "manual_review"
        validation_errors = ["Python extraction pending manual approval"]
        confidence = min(confidence, 70)

    if dry_run:
        log_info(
            "pricing_task.dry_run",
            task_id=task.task_id,
            slug=task.canonical_slug,
            review_status=review_status,
            final_pipeline_stage=final_pipeline_stage,
            plans=len(payload.get("plans") or []),
            final_url=result.final_url,
            validation_errors=validation_errors,
        )
        return "dry_run"

    snapshot_id = await store.insert_snapshot(task, result)
    await store.insert_extraction(
        snapshot_id,
        payload,
        review_status,
        confidence,
        validation_errors,
        extractor_version=extractor_version,
        model_name=model_name,
    )

    if review_status == "approved":
        plans = list(payload.get("plans") or [])
        await store.save_catalog(task, result, plans)
        await store.update_summary(task, plans)
        await store.finish_task(task, "succeeded", None, result)
        return "succeeded"

    error = "; ".join(validation_errors)[:900] or result.error or "manual review"
    await store.finish_task(task, "manual_review", error, result)
    return "manual_review"


async def run_assets_once(config: Config, limit: int | None = None) -> dict[str, int]:
    effective_limit = limit or config.asset_limit
    log_info("assets_runner.batch.start", limit=effective_limit, concurrency=config.concurrency)
    browser_client = CloudflareBrowserRunAssetClient(config)
    uploader = R2AssetUploader(config)
    d1 = D1Client(config)
    store = D1AssetStore(d1)
    queued = await store.queue_missing_asset_tasks(effective_limit)
    log_info("assets_runner.queue_missing_asset_tasks.done", queued=queued)
    tasks = await store.claim_due_tasks(effective_limit)
    log_info("assets_runner.claim_due_tasks.done", claimed=len(tasks))

    semaphore = asyncio.Semaphore(config.concurrency)
    counts = {
        "asset_queued": queued,
        "claimed": len(tasks),
        "done": 0,
        "failed": 0,
    }

    async def guarded(task: AssetTask) -> None:
        async with semaphore:
            try:
                status = await process_asset_task(
                    task,
                    browser_client,
                    uploader,
                    store,
                    config.r2_public_base_url,
                    config.max_retries,
                )
            except Exception as error:
                status = "failed"
                log_error(
                    "asset_task.failed_with_exception",
                    tool_id=task.tool_id,
                    slug=task.canonical_slug,
                    domain=task.normalized_domain,
                    error=str(error)[:300],
                )
                await store.complete_task(task, "failed", str(error)[:900])
            counts[status] = counts.get(status, 0) + 1
            log_info("asset_task.done", tool_id=task.tool_id, slug=task.canonical_slug, status=status)

    if tasks:
        await asyncio.gather(*(guarded(task) for task in tasks))

    return counts


async def run_once(config: Config, limit: int | None = None) -> dict[str, int]:
    effective_limit = limit or config.limit
    log_info("runner.batch.start", limit=effective_limit, concurrency=config.concurrency)
    d1 = D1Client(config)
    store = D1TaskStore(d1)
    similarweb = SimilarWebClient(config)
    traffic_month = previous_traffic_month()
    queued = await store.queue_missing_traffic_tasks(effective_limit, traffic_month)
    log_info("runner.queue_missing_traffic_tasks.done", queued=queued, traffic_month=traffic_month)
    tasks = await store.claim_due_tasks(effective_limit)
    log_info("runner.claim_due_tasks.done", claimed=len(tasks))

    semaphore = asyncio.Semaphore(config.concurrency)
    counts = {
        "traffic_queued": queued,
        "claimed": len(tasks),
        "done": 0,
        "no_data": 0,
        "forbidden": 0,
        "failed": 0,
    }

    async def guarded(task: TrafficTask) -> None:
        async with semaphore:
            try:
                log_info("task.start", domain=task.normalized_domain, traffic_month=task.traffic_month)
                status = await process_task(task, similarweb, d1, store, config.max_retries)
            except Exception as error:
                status = "failed"
                log_error(
                    "task.failed_with_exception",
                    domain=task.normalized_domain,
                    traffic_month=task.traffic_month,
                    error=str(error)[:300],
                )
                await store.complete_task(task, FetchResult(status="failed", monthly_rows=[], error=str(error)[:300]))
            counts[status] = counts.get(status, 0) + 1
            log_info("task.done", domain=task.normalized_domain, traffic_month=task.traffic_month, status=status)

    if tasks:
        await asyncio.gather(*(guarded(task) for task in tasks))

    return counts


async def run_pricing_once(
    config: Config,
    limit: int | None = None,
    task_ids: list[int] | None = None,
    approve_pricing: bool = False,
    dry_run: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, int]:
    effective_limit = limit or config.pricing_limit
    log_info(
        "pricing_runner.batch.start",
        limit=effective_limit,
        concurrency=config.concurrency,
        dry_run=dry_run,
        approve_pricing=approve_pricing,
    )
    d1 = D1Client(config)
    store = D1PricingStore(d1)
    client = PricingClient(timeout_seconds or config.pricing_timeout_seconds)
    openai_models: list[str] = []
    if config.openai_api_key:
        for model in (config.openai_pricing_model, config.openai_pricing_fallback_model):
            clean_model = (model or "").strip()
            if clean_model and clean_model not in openai_models:
                openai_models.append(clean_model)
    openai_extractors = [
        OpenAIPricingExtractor(
            config.openai_api_key,
            model,
            config.openai_pricing_timeout_seconds,
            config.openai_pricing_text_chars,
        )
        for model in openai_models
    ]
    log_info(
        "pricing_runner.openai_config",
        enabled=bool(openai_extractors),
        models=openai_models,
    )
    browser_renderer = CloudflareBrowserRunRenderer(config) if config.browser_rendering_enabled else None
    log_info(
        "pricing_runner.browser_rendering_config",
        enabled=browser_renderer is not None,
        timeout_seconds=config.browser_rendering_timeout_seconds if browser_renderer is not None else None,
    )
    queued = 0
    if not task_ids and not dry_run:
        queued = await store.queue_due_tasks(effective_limit)
        log_info("pricing_runner.queue_due_tasks.done", queued=queued)
    tasks = await store.claim_due_tasks(effective_limit, task_ids=task_ids, claim=not dry_run)
    log_info("pricing_runner.claim_due_tasks.done", claimed=len(tasks), dry_run=dry_run)

    semaphore = asyncio.Semaphore(config.concurrency)
    counts = {
        "queued": queued,
        "claimed": len(tasks),
        "succeeded": 0,
        "manual_review": 0,
        "failed": 0,
        "dry_run": 0,
    }

    async def guarded(task: PricingTask) -> None:
        async with semaphore:
            try:
                log_info("pricing_task.start", task_id=task.task_id, slug=task.canonical_slug)
                status = await process_pricing_task(
                    task,
                    client,
                    openai_extractors,
                    browser_renderer,
                    store,
                    config.max_retries,
                    approve_pricing=approve_pricing,
                    dry_run=dry_run,
                )
            except Exception as error:
                status = "failed" if dry_run else "manual_review"
                log_error(
                    "pricing_task.failed_with_exception",
                    task_id=task.task_id,
                    slug=task.canonical_slug,
                    error=str(error)[:300],
                )
                if not dry_run:
                    await store.finish_task(task, "manual_review", str(error)[:900], None)
            counts[status] = counts.get(status, 0) + 1
            log_info("pricing_task.done", task_id=task.task_id, slug=task.canonical_slug, status=status)

    if tasks:
        await asyncio.gather(*(guarded(task) for task in tasks))

    return counts


async def run_assets_loop(config: Config, limit: int | None, interval_seconds: int) -> None:
    log_info("assets_runner.loop.start", interval_seconds=interval_seconds)
    while True:
        counts = await run_assets_once(config, limit)
        log_info("assets_runner.batch.summary", **counts)
        await asyncio.sleep(interval_seconds)


async def run_loop(config: Config, limit: int | None, interval_seconds: int) -> None:
    log_info("runner.loop.start", interval_seconds=interval_seconds)
    while True:
        counts = await run_once(config, limit)
        log_info("runner.batch.summary", **counts)
        await asyncio.sleep(interval_seconds)


async def run_pricing_loop(
    config: Config,
    limit: int | None,
    interval_seconds: int,
    task_ids: list[int] | None,
    approve_pricing: bool,
    dry_run: bool,
    timeout_seconds: int | None,
) -> None:
    log_info("pricing_runner.loop.start", interval_seconds=interval_seconds)
    while True:
        counts = await run_pricing_once(
            config,
            limit,
            task_ids=task_ids,
            approve_pricing=approve_pricing,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
        )
        log_info("pricing_runner.batch.summary", **counts)
        await asyncio.sleep(interval_seconds)


async def run_all_loop(config: Config, limit: int | None, interval_seconds: int, timeout_seconds: int | None) -> None:
    shared_interval = interval_seconds or 300
    traffic_interval = 1800
    log_info(
        "all_runner.loop.start",
        traffic_interval_seconds=traffic_interval,
        pricing_interval_seconds=shared_interval,
        assets_interval_seconds=shared_interval,
    )
    await asyncio.gather(
        run_loop(config, limit or config.limit, traffic_interval),
        run_pricing_loop(config, config.pricing_limit, shared_interval, None, True, False, timeout_seconds),
        run_assets_loop(config, config.asset_limit, shared_interval),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scheduled traffic, assets, and pricing runner")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="process one batch and exit")
    mode.add_argument("--loop", action="store_true", help="poll tasks forever")
    parser.add_argument("--pricing", action="store_true", help="process pricing_tasks instead of traffic_tasks")
    parser.add_argument("--assets", action="store_true", help="process asset_tasks instead of traffic_tasks")
    parser.add_argument("--all", action="store_true", help="run traffic, pricing, and assets loops in one process")
    parser.add_argument("--approve-pricing", action="store_true", help="write approved pricing extractions into active catalogs")
    parser.add_argument("--dry-run", action="store_true", help="for pricing mode, fetch and extract without D1 writes")
    parser.add_argument("--task-id", type=int, action="append", default=[], help="pricing task id to run; can be repeated")
    parser.add_argument("--timeout", type=int, default=None, help="pricing HTTP timeout in seconds")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--interval-seconds", type=int, default=None)
    args = parser.parse_args()
    selected = [args.pricing, args.assets, args.all]
    if sum(1 for value in selected if value) > 1:
        parser.error("--pricing, --assets, and --all are mutually exclusive")
    if args.all and not args.loop:
        parser.error("--all requires --loop")
    return args


def main() -> None:
    args = parse_args()
    config = load_config(require_brightdata=not (args.pricing or args.assets))
    interval_seconds = args.interval_seconds or config.poll_interval_seconds
    if args.all:
        asyncio.run(run_all_loop(config, args.limit, args.interval_seconds, args.timeout))
        return

    if args.assets:
        if args.loop:
            asyncio.run(run_assets_loop(config, args.limit, interval_seconds))
            return

        counts = asyncio.run(run_assets_once(config, args.limit))
        log_info("assets_runner.batch.summary", **counts)
        return

    if args.pricing:
        if args.loop:
            asyncio.run(
                run_pricing_loop(
                    config,
                    args.limit,
                    interval_seconds,
                    args.task_id,
                    args.approve_pricing,
                    args.dry_run,
                    args.timeout,
                )
            )
            return

        counts = asyncio.run(
            run_pricing_once(
                config,
                args.limit,
                task_ids=args.task_id,
                approve_pricing=args.approve_pricing,
                dry_run=args.dry_run,
                timeout_seconds=args.timeout,
            )
        )
        log_info("pricing_runner.batch.summary", **counts)
        return

    if args.loop:
        asyncio.run(run_loop(config, args.limit, interval_seconds))
        return

    counts = asyncio.run(run_once(config, args.limit))
    log_info("runner.batch.summary", **counts)


if __name__ == "__main__":
    main()
