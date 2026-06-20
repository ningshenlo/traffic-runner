import argparse
import asyncio
import json
import os
import random
import re
import string
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import asyncpg
import httpx
from dotenv import load_dotenv
from fake_useragent import UserAgent


SIMILARWEB_API_BASE = "https://data.similarweb.com/api/v1/data"
TRAFFIC_SOURCE = "similarweb"
D1_API_BASE = "https://api.cloudflare.com/client/v4"


@dataclass(frozen=True)
class Config:
    database_url: str
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


@dataclass(frozen=True)
class TrafficTask:
    normalized_domain: str
    traffic_month: str
    attempts: int


@dataclass(frozen=True)
class FetchResult:
    status: str
    monthly_rows: list[dict[str, Any]]
    error: str | None = None


def read_int_env(name: str, fallback: int) -> int:
    value = os.getenv(name)
    if not value:
        return fallback
    try:
        return int(value)
    except ValueError:
        return fallback


def load_config() -> Config:
    load_dotenv()
    return Config(
        database_url=os.environ["DATABASE_URL"],
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


def generate_session_id(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


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
        session_id = generate_session_id()
        username = f"{config.brightdata_proxy_user}-session-{session_id}"
        self.proxy_url = (
            f"http://{username}:{config.brightdata_proxy_password}"
            f"@{config.brightdata_proxy_host}:{config.brightdata_proxy_port}"
        )
        self.user_agent = UserAgent()

    async def fetch(self, domain: str, requested_month: str) -> FetchResult:
        clean_domain = normalize_domain(domain)
        if not clean_domain:
            return FetchResult(status="failed", monthly_rows=[], error="invalid_domain")

        headers = {
            "User-Agent": self.user_agent.random,
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.8",
        }
        url = f"{SIMILARWEB_API_BASE}?domain={clean_domain}"

        try:
            async with httpx.AsyncClient(proxy=self.proxy_url, headers=headers, timeout=25.0, verify=False) as client:
                response = await client.get(url)
        except Exception as error:
            return FetchResult(status="failed", monthly_rows=[], error=f"request_error:{str(error)[:300]}")

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
        if not response.is_success:
            return FetchResult(
                status="failed",
                monthly_rows=[],
                error=f"similarweb_http_{response.status_code}:{response.text[:300]}",
            )

        try:
            payload = response.json()
        except json.JSONDecodeError:
            return FetchResult(status="failed", monthly_rows=[], error="similarweb_invalid_json")

        monthly_rows = parse_monthly_rows(payload, clean_domain, requested_month)
        has_data = any(row.get("visits") is not None for row in monthly_rows) or any(
            row.get("global_rank") is not None for row in monthly_rows
        )
        return FetchResult(status="done" if has_data else "no_data", monthly_rows=monthly_rows)


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
        return payload.get("result")

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
        for row in rows:
            await self.insert_snapshot(task.normalized_domain, task.traffic_month, result.status, row, result.error)


class NeonTaskStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def claim_due_tasks(self, limit: int) -> list[TrafficTask]:
        rows = await self.pool.fetch(
            """
            WITH due AS (
              SELECT normalized_domain, source, traffic_month
              FROM public.traffic_tasks
              WHERE source = $1
                AND (
                  (
                    status IN ('queued', 'failed', 'sync_failed')
                    AND (next_retry_at IS NULL OR next_retry_at <= now())
                  )
                  OR (
                    status = 'processing'
                    AND updated_at < now() - interval '1 hour'
                  )
                )
              ORDER BY coalesce(next_retry_at, '-infinity'::timestamptz), updated_at
              LIMIT $2
              FOR UPDATE SKIP LOCKED
            )
            UPDATE public.traffic_tasks task
            SET status = 'processing',
                attempts = task.attempts + 1,
                last_started_at = now(),
                next_retry_at = now() + interval '1 hour',
                last_error = NULL,
                updated_at = now()
            FROM due
            WHERE task.normalized_domain = due.normalized_domain
              AND task.source = due.source
              AND task.traffic_month = due.traffic_month
            RETURNING task.normalized_domain, task.traffic_month::text, task.attempts
            """,
            TRAFFIC_SOURCE,
            limit,
        )
        return [
            TrafficTask(
                normalized_domain=row["normalized_domain"],
                traffic_month=row["traffic_month"],
                attempts=row["attempts"],
            )
            for row in rows
        ]

    async def complete_task(self, task: TrafficTask, result: FetchResult) -> None:
        retry_days = 1 if result.status == "failed" else None
        await self.pool.execute(
            """
            UPDATE public.traffic_tasks
            SET status = $2,
                last_fetched_at = now(),
                next_retry_at = CASE
                  WHEN $3::integer IS NULL THEN NULL
                  ELSE now() + ($3::integer * interval '1 day')
                END,
                last_error = $4,
                updated_at = now()
            WHERE normalized_domain = $1
              AND source = $5
              AND traffic_month = $6::date
            """,
            task.normalized_domain,
            result.status,
            retry_days,
            (result.error or "")[:2000] or None,
            TRAFFIC_SOURCE,
            task.traffic_month,
        )
        await self.update_tool_status(task.normalized_domain, result)

    async def update_tool_status(self, domain: str, result: FetchResult) -> None:
        retry_days = 30
        if result.status in ("no_data", "forbidden"):
            retry_days = 7
        if result.status == "failed":
            retry_days = 1

        await self.pool.execute(
            """
            INSERT INTO public.tool_traffic_fetch_status (
              tool_id, normalized_domain, source, last_checked_at, last_status, last_error, next_retry_at
            )
            SELECT
              id,
              normalized_domain,
              $2,
              now(),
              $3,
              $4,
              now() + ($5::integer * interval '1 day')
            FROM public.tools
            WHERE normalized_domain = $1
              AND status = 'published'
              AND duplicate_of_tool_id IS NULL
            ON CONFLICT (tool_id, source) DO UPDATE
            SET normalized_domain = excluded.normalized_domain,
                last_checked_at = excluded.last_checked_at,
                last_status = excluded.last_status,
                last_error = excluded.last_error,
                next_retry_at = excluded.next_retry_at,
                updated_at = now()
            """,
            domain,
            TRAFFIC_SOURCE,
            result.status,
            (result.error or "")[:2000] or None,
            retry_days,
        )


async def process_task(
    task: TrafficTask,
    similarweb: SimilarWebClient,
    d1: D1Client,
    store: NeonTaskStore,
    max_retries: int,
) -> str:
    result = FetchResult(status="failed", monthly_rows=[], error="not_started")
    for attempt in range(max_retries + 1):
        result = await similarweb.fetch(task.normalized_domain, task.traffic_month)
        if result.status != "failed":
            break
        if attempt < max_retries:
            await asyncio.sleep(random.uniform(1.0, 3.0))

    await d1.insert_result(task, result)
    await store.complete_task(task, result)
    return result.status


async def run_once(config: Config, limit: int | None = None) -> dict[str, int]:
    pool = await asyncpg.create_pool(config.database_url, min_size=1, max_size=2)
    store = NeonTaskStore(pool)
    d1 = D1Client(config)
    similarweb = SimilarWebClient(config)
    tasks = await store.claim_due_tasks(limit or config.limit)
    if not tasks:
        await pool.close()
        return {"claimed": 0, "done": 0, "no_data": 0, "forbidden": 0, "failed": 0}

    semaphore = asyncio.Semaphore(config.concurrency)
    counts = {"claimed": len(tasks), "done": 0, "no_data": 0, "forbidden": 0, "failed": 0}

    async def guarded(task: TrafficTask) -> None:
        async with semaphore:
            try:
                status = await process_task(task, similarweb, d1, store, config.max_retries)
            except Exception as error:
                status = "failed"
                await store.complete_task(task, FetchResult(status="failed", monthly_rows=[], error=str(error)[:300]))
            counts[status] = counts.get(status, 0) + 1
            print(f"[{status}] {task.normalized_domain} {task.traffic_month}")

    await asyncio.gather(*(guarded(task) for task in tasks))
    await pool.close()
    return counts


async def run_loop(config: Config, limit: int | None, interval_seconds: int) -> None:
    while True:
        counts = await run_once(config, limit)
        print(json.dumps(counts, ensure_ascii=False))
        await asyncio.sleep(interval_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SimilarWeb traffic runner")
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
    print(json.dumps(counts, ensure_ascii=False))


if __name__ == "__main__":
    main()
