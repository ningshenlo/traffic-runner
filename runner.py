import argparse
import asyncio
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
from curl_cffi.requests import AsyncSession as CurlAsyncSession
from dotenv import load_dotenv


SIMILARWEB_API_BASE = "https://data.similarweb.com/api/v1/data"
TRAFFIC_SOURCE = "similarweb"
D1_API_BASE = "https://api.cloudflare.com/client/v4"
DOMAIN_STATE_SOURCE = "ahrefs"
AHREFS_DOMAIN_RATING_URL = "https://api.ahrefs.com/v3/public/domain-rating-free"
IANA_RDAP_DNS = "https://data.iana.org/rdap/dns.json"
RDAP_USER_AGENT = "traffic-runner-domain-whois/0.1"
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
    domain_state_limit: int
    domain_state_max_age_days: int


@dataclass(frozen=True)
class TrafficTask:
    normalized_domain: str
    traffic_month: str
    attempts: int


@dataclass(frozen=True)
class DomainStateCandidate:
    normalized_domain: str


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


def read_int_env(name: str, fallback: int) -> int:
    value = os.getenv(name)
    if not value:
        return fallback
    try:
        return int(value)
    except ValueError:
        return fallback

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



def load_config() -> Config:
    load_dotenv()
    return Config(
        cloudflare_account_id=os.environ["CLOUDFLARE_ACCOUNT_ID"],
        cloudflare_d1_database_id=os.environ["CLOUDFLARE_D1_DATABASE_ID"],
        cloudflare_api_token=os.environ["CLOUDFLARE_API_TOKEN"],
        brightdata_proxy_host=os.getenv("BRIGHTDATA_PROXY_HOST", "brd.superproxy.io"),
        brightdata_proxy_port=read_int_env("BRIGHTDATA_PROXY_PORT", 33335),
        brightdata_proxy_user=os.environ["BRIGHTDATA_PROXY_USER"],
        brightdata_proxy_password=os.environ["BRIGHTDATA_PROXY_PASSWORD"],
        limit=read_int_env("RUNNER_LIMIT", 20),
        concurrency=read_int_env("RUNNER_CONCURRENCY", 5),
        max_retries=read_int_env("RUNNER_MAX_RETRIES", 2),
        poll_interval_seconds=read_int_env("RUNNER_POLL_INTERVAL_SECONDS", 300),
        domain_state_limit=read_int_env("RUNNER_DOMAIN_STATE_LIMIT", 50),
        domain_state_max_age_days=read_int_env("RUNNER_DOMAIN_STATE_MAX_AGE_DAYS", 30),
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
            "Origin": "https://www.similarweb.com",
            "Referer": f"https://www.similarweb.com/website/{clean_domain}/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
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


async def run_loop(config: Config, limit: int | None, interval_seconds: int) -> None:
    log_info("runner.loop.start", interval_seconds=interval_seconds)
    while True:
        counts = await run_once(config, limit)
        log_info("runner.batch.summary", **counts)
        await asyncio.sleep(interval_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scheduled SimilarWeb traffic runner")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="process one batch and exit")
    mode.add_argument("--loop", action="store_true", help="poll traffic_tasks forever")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--interval-seconds", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config()
    interval_seconds = args.interval_seconds or config.poll_interval_seconds
    if args.loop:
        asyncio.run(run_loop(config, args.limit, interval_seconds))
        return

    counts = asyncio.run(run_once(config, args.limit))
    log_info("runner.batch.summary", **counts)


if __name__ == "__main__":
    main()
