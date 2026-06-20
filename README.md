# Traffic Runner

Python runner for SimilarWeb traffic snapshots.

It uses the existing Neon `traffic_tasks` table as the task source, fetches SimilarWeb data through the Bright Data proxy zone, stores every fetched monthly row in Cloudflare D1 `domain_traffic_snapshots`, then updates Neon task/status tables.

## Setup

```bash
cd traffic-runner
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
```

Fill `.env` with:

- `DATABASE_URL`: Neon Postgres connection string.
- `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID`, `CLOUDFLARE_API_TOKEN`: D1 REST API access.
- `BRIGHTDATA_PROXY_USER`, `BRIGHTDATA_PROXY_PASSWORD`: Bright Data proxy credentials.

## Run

Process one batch:

```bash
python runner.py --once --limit 20
```

Run as a polling worker:

```bash
python runner.py --loop --interval-seconds 300
```

The runner only claims due tasks where `traffic_tasks.status` is `queued`, `failed`, `sync_failed`, or stale `processing`.
