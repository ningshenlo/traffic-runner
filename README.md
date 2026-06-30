# Traffic Runner

Python runner for scheduled SimilarWeb traffic backfill, homepage asset capture, and pricing task execution.

It uses the Cloudflare D1 `ainav` database as the task source and system of record. Each run automatically queues missing previous-month SimilarWeb traffic tasks, fetches due traffic through the Bright Data proxy zone, stores rows in `domain_traffic_snapshots` and `tool_traffic_monthly`, then updates `traffic_tasks` and `tool_traffic_fetch_status`.

Pricing mode consumes existing `pricing_tasks`, fetches public pricing pages with normal browser-like request headers, stores `pricing_snapshots` and `pricing_extractions`, and leaves results in `manual_review` by default. It writes active pricing catalogs only when `--approve-pricing` is passed.

Pricing extraction runs deterministic rules first. If rules cannot produce a trusted structure and `OPENAI_API_KEY` or `OPENAI_API` is set, it falls back to OpenAI structured JSON extraction. The default model is `gpt-5.4-mini`; set `OPENAI_PRICING_FALLBACK_MODEL` only when a second model should be tried after invalid or low-confidence output.

If static fetching and OpenAI still cannot produce trusted pricing from a likely pricing URL, pricing mode can use Cloudflare Browser Run to fetch rendered HTML, then rerun the same rule and OpenAI extraction path. Enable it with `CLOUDFLARE_BROWSER_RENDERING_ENABLED=1`. The Cloudflare token must include Browser Rendering edit access; set `CLOUDFLARE_BROWSER_RENDERING_API_TOKEN` if the normal D1 token does not have that permission.

Pricing extraction payloads include `final_pipeline_stage` for tracking the final path: `rule`, `openai`, `browser_run_rule`, `browser_run_openai`, `contact_sales`, `manual_review`, or `browser_run_manual_review`.

Assets mode scans published tools missing a current screenshot or favicon, claims `asset_tasks`, captures homepage screenshots with Cloudflare Browser Run, uploads screenshots/favicons to R2, and writes `tool_assets` directly.

## Setup

```bash
cd traffic-runner
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
```

Fill `.env` with:

- `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID`, `CLOUDFLARE_API_TOKEN`: D1 REST API access.
- `BRIGHTDATA_PROXY_USER`, `BRIGHTDATA_PROXY_PASSWORD`: Bright Data proxy credentials for traffic mode.
- Optional runner tuning: `RUNNER_LIMIT`, `RUNNER_PRICING_LIMIT`, `RUNNER_PRICING_TIMEOUT_SECONDS`.
- Optional pricing AI fallback: `OPENAI_API_KEY` or `OPENAI_API`, plus `OPENAI_PRICING_MODEL` and `OPENAI_PRICING_FALLBACK_MODEL`.
- Optional rendered-page fallback: `CLOUDFLARE_BROWSER_RENDERING_ENABLED`, `CLOUDFLARE_BROWSER_RENDERING_API_TOKEN`, `CLOUDFLARE_BROWSER_RENDERING_TIMEOUT_SECONDS`.
- Assets mode: `RUNNER_ASSET_LIMIT`, `CLOUDFLARE_BROWSER_RENDERING_API_TOKEN`, `CLOUDFLARE_R2_ACCESS_KEY_ID`, `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, `CLOUDFLARE_R2_BUCKET`, and optional `R2_PUBLIC_BASE_URL`.
  Use the real R2 bucket name for `CLOUDFLARE_R2_BUCKET` (for example `sitesimgs`) and the public/custom domain for `R2_PUBLIC_BASE_URL` (for example `https://img.sigpik.com`). The D1 `tool_assets.storage_bucket` value remains `sitesimgs` for compatibility with the existing frontend.

`wrangler.toml` points at the same `ainav` D1 database used by the frontend. Keep `CLOUDFLARE_D1_DATABASE_ID` in `.env` aligned with that file.

## Run

Docker default command runs all loops in one process:

```bash
python runner.py --all --loop --interval-seconds 300
```

Process one batch:

```bash
python runner.py --once --limit 20
```

Run as a polling worker:

```bash
python runner.py --loop --interval-seconds 300
```

The runner claims due D1 traffic tasks where `traffic_tasks.status` is `queued`, `failed`, `sync_failed`, or stale `processing`.

Capture missing homepage screenshots and favicons:

```bash
python runner.py --assets --once --limit 10
```

Run assets as a polling worker:

```bash
python runner.py --assets --loop --interval-seconds 300
```

Process queued pricing tasks:

```bash
python runner.py --pricing --once --limit 10
```

Dry-run a specific pricing task without D1 writes:

```bash
python runner.py --pricing --once --task-id 126 --dry-run
```
