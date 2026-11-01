# Counterstrike Lite — sample solution

A five-agent fleet that reads a vulnerability feed, works out which of your assets are affected, ranks them by real exposure, and writes an owner-ready alert for each one. Scaled-down POC of *Project Counterstrike: Agent Fleet*.

```
feed + KEV + inventory
        │
  1 Feed Watcher ──► 2 Extractor (LLM, grounded) ──► 3 Correlator ──► 4 Risk Scorer ──► 5 Remediation Writer ──► Dispatcher
                            │                              │                                                  │
                            └── needs_human.json           └── no matches ──────────────────────────────────► outbox/
```

## Run it

Create and activate a project environment first. In Git Bash on Windows:

```bash
python -m venv .venv
source .venv/Scripts/activate
```

On Linux/macOS, activate with `source .venv/bin/activate`. In Windows PowerShell,
use `.\.venv\Scripts\Activate.ps1`.

```bash
python -m pip install -e ".[dev]"
python -m counterstrike run  --data data --out out          # offline, deterministic FakeLLM
python -m counterstrike eval --out out                       # gate: exits 1 on any regression
python -m pytest --cov=counterstrike --cov-report=term-missing --cov-fail-under=80
```

Use `python -m pytest` so tests run with the same Python used to install dependencies.
If collection fails with `No module named 'apscheduler'`, the selected environment is
missing a declared project dependency; activate `.venv` and repeat the install command.
With an already provisioned environment, Git Bash can run the tests directly without
activation:

```bash
.venv/Scripts/python.exe -m pytest --cov=counterstrike --cov-report=term-missing --cov-fail-under=80
```

## Local API and dashboard

The API serves the dashboard from the same origin. For a database-backed local workspace, use the Docker Compose stack below. A bare API process can serve liveness/readiness and the temporary fixture compatibility route without a database, but database-backed dashboard, run, review, and usage routes require PostgreSQL and Alembic migrations.

### Docker Compose stack

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Open `http://127.0.0.1:8000`. Compose starts PostgreSQL, applies migrations, then starts the API and worker. The database has no host-published port; the API is published on host loopback only. The default LLM provider remains `fake`, and live calls remain off. To inspect service logs or stop the stack:

```bash
docker compose logs -f api worker
docker compose down
```

`POSTGRES_PASSWORD` and `COUNTERSTRIKE_DB_RUNTIME_PASSWORD` in `.env.example` are local-demo values; replace both for local use and supply secrets through a deployment secret store outside the demo. Compose applies migrations as the database owner and runs the API and worker under the restricted `counterstrike_app` role; that role cannot update or delete audit events, LLM content-access records, or review decisions. The default Compose subnet is `172.16.240.0/24`; if it conflicts with an existing network, set `COMPOSE_SUBNET` to a free private CIDR. `API_TRUSTED_LOCAL_CLIENT_CIDRS` is configured for that private bridge only by Compose, while the host port remains bound to `127.0.0.1`; production settings reject this development exception. Track runtime acceptance in `planning/BACKEND_IMPLEMENTATION_TRACKER.md`.

The OpenAI-compatible adapter now requires a persisted run ID and commits the encrypted request and pending attempt before network dispatch. Live calls remain off by default. Enabling them requires provider configuration, `DATABASE_URL`, encrypted artifact capture and retention settings, and explicit `LLM_DATA_BOUNDARY_APPROVED=true` and `LLM_ARTIFACT_RETENTION_APPROVED=true`. Provider/data policy, access roles, spend enforcement, migration, and runtime acceptance are still pending. Keep `LLM_PROVIDER=fake` for offline runs.

## Outputs (`out/`)

| File | What it is |
|---|---|
| `alerts.json` | One alert per (CVE, asset): priority, SLA, risk score + breakdown, fix, evidence |
| `outbox/<owner>.md` | The same alerts grouped per engineering owner, ready to forward |
| `needs_human.json` | Advisories the fleet refused to guess about, with the reason |
| `run_report.json` | Counts and a per-agent trace (timings, LLM calls, prompt version, injection flags) |
| `scorecard.md` | Written by `eval` |

Expected result on the fixtures: 5 alerts — P1 log4j on payments-api, P2 openssl on client-portal, P2 pillow on doc-scanner (KEV), P3 jinja2 on reporting-ui, P4 requests on kyc-service (the injection fixture) — and CVE-2099-0008 routed to a human.

## Layout

```
src/counterstrike/
  models.py        typed contracts + LangGraph state
  agents/          ingest, extract, correlate, score, remediate
  dispatch.py      outbox writer
  graph.py         LangGraph wiring (conditional edges)
  llm.py           LLMPort, FakeLLM, audited gateway adapter
  llm_metering.py  Per-attempt request/response capture and token/cost records
  guards.py        injection detection, grounding checks
  versions.py      tolerant version parsing, PEP 440 ranges
  evaluate.py      metrics + release gate
data/              synthetic feed, inventory, KEV list, aliases, gold labels
grading/           trainer-only hidden fixture set (do not share with students)
tests/             unit, guard, end-to-end and public contract tests
.github/workflows/ci.yml
DECISION_LOG.md
```

All CVE IDs are synthetic (`CVE-2099-xxxx`); none describe real vulnerabilities.
