# Backend API and LLM Integration Strategy

**Decision status: Accepted as the implementation planning baseline on 31 October 2026.**
**Purpose:** Freeze a practical backend, API, persistence, and LLM design for the Counterstrike agent fleet, then implement against the approved contract.

The user authorized phased implementation planning and execution against this baseline. Provider-specific data boundary, prompt/response retention, identity, pricing, and platform decisions remain explicit gates in [the implementation tracker](BACKEND_IMPLEMENTATION_TRACKER.md); live LLM calls remain disabled until those gates are resolved.

## 1. Recommendation

Build a Python API and worker around the existing LangGraph pipeline. Use FastAPI for the HTTP boundary, PostgreSQL for durable run and audit state, SQLAlchemy 2.x with Alembic for persistence and schema changes, and a separate worker process for scheduled ingestion and user-triggered runs. Keep the existing `LLMPort` seam: deterministic code retains control of matching, scoring, priority, remediation facts, and dispatch decisions; a configured model may extract candidate facts from bulletins and draft grounded prose only.

The API will serve the current frontend from the same origin and provide versioned read and action endpoints. The existing JSON fixtures and CLI remain available for offline development and evaluation. The API will not connect to or modify managed assets. External feed and notification adapters are independent integrations with explicit enablement and audit records.

This proposal covers the Must gaps summarized in [the updated requirement gap plan](UPDATED_REQUIREMENT_GAP_PLAN.md) and preserves the boundaries recorded in [the current decision log](../DECISION_LOG.md). The [Counterstrike Agents Fleet Requirements](../requirement/Counterstrike_Agents_Fleet_Requirements.docx) remains the authority if it conflicts with this strategy.

## 2. Goals and boundaries

### In scope for the backend foundation

- Serve the dashboard and provide stable, documented APIs for dashboard data, alerts, human review, run history, and service health.
- Start a fleet run on demand and on a configured polling schedule; track its status, inputs, timing, trace, and outcome durably.
- Make source ingestion idempotent, independently observable, and resilient to an individual source outage.
- Persist normalized advisory, inventory, correlation, alert, review, source checkpoint, and audit records.
- Make user/system actions, pipeline decisions, failures, and outbound deliveries traceable through structured operational logs and a durable append-only audit trail.
- Record per-attempt LLM usage, latency, outcomes, and cost (or explicitly mark cost unavailable) and expose aggregate usage views with budget controls.
- Support the approved LLM through configuration without changing the `LLMPort` contract or allowing model output to make security decisions.
- Use `.env` for local configuration, `.env.example` for safe documented placeholders, and deployment secrets for hosted environments.
- Keep fixture-based runs deterministic and offline in CI.

### Explicit boundaries

- The fleet remains advisory and read-only with respect to target assets. No patching, configuration changes, or shell/SSH execution is introduced.
- Model keys, prompts containing sensitive values, and raw authorization headers are never returned by an API or written to run/audit logs.
- The initial API is an internal/demo service. Public internet exposure and multi-tenant authorization are out of scope until identity, role, and network requirements are approved.
- Teams/email delivery can be implemented behind a durable outbox and disabled by default. Actual external sends require configured destinations and explicit deployment enablement.
- Ticket creation, vendor scraping, and feedback-based model training remain outside the initial backend slice unless the requirement owner re-scopes them.

## 3. Proposed technology decisions

| Concern | Proposed choice | Why it fits this repository | Consequence / alternative rejected |
|---|---|---|---|
| API framework | **FastAPI + Uvicorn** | Python service matches the existing agent code and Pydantic contracts; typed request/response models and generated OpenAPI make the API easy to inspect. | Adds an ASGI runtime and API dependencies. A handwritten `http.server` implementation is smaller but would make validation, API documentation, and middleware less maintainable. |
| API schemas | **Pydantic v2** | Already used for advisory, asset, alert, and match validation. Reuse the domain models and add explicit API DTOs. | Avoid exposing internal LangGraph state directly; API DTOs form a stable boundary. |
| Durable storage | **PostgreSQL** | Supports durable run history, source checkpoints, human decisions, audit events, and a database-backed work queue. Fits the required containerized deployment direction. | Requires a database service. JSON files remain the fixture/import/export format, not the authoritative live store. SQLite is limited to fast isolated tests only. |
| Persistence and migrations | **SQLAlchemy 2.x + Alembic + psycopg 3** | Familiar Python persistence stack, explicit schema evolution, and a PostgreSQL driver. Start with synchronous sessions because LangGraph and current agents are synchronous. | Async ORM is deferred until measurements show a need; it would add coordination across the API, graph, and DB code. |
| Run queue | **PostgreSQL-backed jobs table, claimed with row locks** | Durable manual and scheduled jobs without adding Redis/Celery for the current throughput. A dedicated worker claims jobs and records attempts/status. | Start with one active worker for deterministic output and safe shared state. Add Redis/Celery only if measured queue throughput or isolation needs justify another service. |
| Scheduler | **APScheduler in the dedicated worker process** | Direct fit for the 15-minute polling interpretation in the gap plan; keeps scheduling out of API web workers. | Run exactly one scheduler instance in the deployment. Job table uniqueness/leases prevent duplicate schedules. For multi-replica scheduling, replace with a platform scheduler or distributed scheduler after approval. |
| External HTTP | **HTTPX with explicit connect/read/write/pool timeouts and bounded retries** | Shared client for feed and model adapters; enables explicit timeout policy. | Retries are limited to safe transient failures and honor rate limits; no unbounded retries. |
| Operational logging | **Python standard `logging` with JSON formatter, UTC timestamps, and request/run/source correlation IDs** | Avoids a new vendor dependency and emits records that local runs and hosted log collectors can index. | Logs describe operations and diagnostics; they are not the authoritative audit ledger. No raw secrets, prompt bodies, or full inventory rows. |
| Audit trail | **Append-only `audit_event` rows in PostgreSQL, with a DB role that cannot update/delete them** | A database-backed trail survives process restarts and can reconstruct who/what caused a change and the pipeline facts behind it. | Include event schema/version and integrity checks; export periodic signed/hash manifests to immutable storage when a production retention platform is selected. |
| LLM audit and metering | **One `llm_call` record per provider attempt, plus encrypted full request/response artifacts; compute cost from observed token usage and an explicit versioned pricing table** | Makes exact model inputs, outputs, retries, task usage, and run-level spend inspectable and reportable. | Prompt/response artifacts can contain sensitive source text. Store them separately with encryption, strict access, retention controls, and access auditing; never copy their contents into ordinary logs. |
| LLM integration | **Keep `LLMPort`; retain `FakeLLM`; harden the OpenAI-compatible gateway adapter** | Existing agents already depend on a provider-neutral port and CI uses `FakeLLM`. It is the lowest-risk route to live calls. | Azure OpenAI endpoint details must be confirmed. Use the OpenAI-compatible API shape only if the approved Azure deployment supports it; otherwise add a separate Azure adapter behind the same port. |
| Frontend delivery | **FastAPI serves `frontend/` and `/api/v1/*` from one origin** | No browser CORS setup or second server is needed; the current static UI remains build-free. | Replace the Node preview data server after the Python API is ready. Keep local Node preview only until migration is complete. |
| Packaging/local run | **Existing `pyproject.toml`; Docker Compose for API, worker, and PostgreSQL** | Keeps dependencies and commands in the Python project and supports a repeatable demo. | CI and Compose secrets must be injected from environment; `.env` is local-only and excluded from version control. |

FastAPI’s dependency model and generated API schema support the proposed typed HTTP boundary ([FastAPI dependencies](https://fastapi.tiangolo.com/tutorial/dependencies/), [FastAPI security](https://fastapi.tiangolo.com/tutorial/security/)). SQLAlchemy’s 2.x ORM provides the persistence layer ([SQLAlchemy ORM](https://docs.sqlalchemy.org/en/20/orm/)). HTTPX supports explicit operation timeouts ([HTTPX timeouts](https://www.python-httpx.org/advanced/timeouts/)). APScheduler’s user guide documents scheduled jobs and job behavior ([APScheduler 3.x guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html)). These links are technical references, not a commitment to specific dependency patch versions.

## 4. Target runtime layout

```text
Browser
  └── FastAPI / Uvicorn
        ├── serves frontend static files
        ├── validates /api/v1 requests and returns DTOs
        ├── reads PostgreSQL for alerts, review, run, and dashboard views
        └── enqueues manual work in PostgreSQL

Worker process
  ├── APScheduler enqueues periodic source-poll jobs
  ├── claims queued jobs from PostgreSQL
  ├── invokes source adapters and existing LangGraph fleet
  ├── stores normalized results, audit events, and outbox records
  └── makes LLM calls only through LLMPort

PostgreSQL
  ├── advisory and enrichment records
  ├── inventory snapshots
  ├── runs, jobs, and source checkpoints
  ├── matches, alerts, and analyst review decisions
  └── append-only audit events and delivery outbox
```

The API process must not execute a full model-backed graph synchronously inside a request. `POST /runs` validates and queues work, then returns `202 Accepted` with a run identifier. The worker runs the graph and updates durable state. This keeps HTTP responsive when a source or model is slow.

## 5. Proposed API contract

All paths below are under `/api/v1`. JSON timestamps use UTC ISO 8601. Collection endpoints use bounded `limit` and `offset` pagination. Responses contain stable IDs and never include credentials or internal filesystem paths.

| Method and path | Purpose | Response / behavior |
|---|---|---|
| `GET /health/live` | Process liveness | `200` if the API process is running. No DB dependency. |
| `GET /health/ready` | Service readiness | `200` when the configured database is reachable and at the repository's current Alembic head. Without a database, only non-production fixture mode is ready when all required fixtures exist; otherwise return `503` with safe dependency status. |
| `GET /auth/context` | UI capability context | Return the configured local development identity and capability names; this endpoint is informational and does not authenticate callers. |
| `GET /dashboard` | Overview page aggregate | Latest run, priority counts, affected asset count, review count, and selected latest findings. |
| `GET /alerts` | Alert list | Filter by `priority`, `owner`, `service`, `search`, `since`, and bounded pagination; sorted by priority/risk/time. |
| `GET /alerts/{alert_id}` | Alert detail | Alert facts, bounded advisory context, associated inventory security posture, score breakdown/policy version, source references, evidence, and latest run association. |
| `GET /reviews` | Analyst queue | Open, resolved, and filtered human-review cases with reason, bounded source-bulletin text, source references, and decision history. |
| `POST /reviews/{review_id}/decision` | Record analyst disposition | Validated disposition and note; appends an audit event. It does not suppress an existing alert without an explicit, separately audited action. |
| `GET /runs` | Run history | Paginated status, trigger, timestamps, and summary counts. |
| `POST /runs` | Queue a manual run | `202` plus `run_id`, status URL, and accepted timestamp. Accepts an approved trigger/input scope only; no arbitrary filesystem paths. |
| `GET /runs/{run_id}` | Run status and trace | Pending/running/succeeded/partial/failed, stage trace, source fetch results, safe error codes, and counts. |
| `GET /sources` | Feed status | Source enabled state, last attempt/success, checkpoint, and latest safe error category. |
| `GET /audit/events` | Filtered audit history | Bounded, paginated event metadata filtered by UTC time, event type, outcome, actor, run, or request; excludes free-form reasons and event details. Requires `audit_reader` or `admin`; access itself is audited. |
| `GET /audit/integrity` | Verify audit-chain integrity | Valid/invalid result, checked event count, and a failure reference when invalid. Requires `audit_reader` or `admin`; access itself is audited. |
| `GET /llm/usage` | Aggregate and inspect model usage | Filter by time window, run, provider, model, task, and outcome; show known cost and unknown-cost counts separately. |
| `GET /llm/usage/{call_id}` | Inspect a single model attempt | Return safe call and artifact metadata only. Exact content is available through the purpose-required privileged content-read operation below. |
| `POST /llm/usage/{call_id}/content` | Privileged LLM audit read | Require `llm_audit_reader` and a validated purpose plus artifact kind; decrypt and return one retained request/response/parsed-output/error artifact, and persist every access outcome in the audit chain. |
| `GET /llm/usage/report` | Produce detailed or aggregate usage report | Filter by time, run, task, provider/model, actor, prompt version, advisory, and outcome; group by day/run/task/model/prompt version or return individual attempts. |
| `GET /llm/budgets` | Inspect spend limits and current totals | Configured limits, usage to date, remaining amount, and threshold status; unknown costs remain separate. |
| `GET /openapi.json` | Machine-readable API contract | Generated from API DTOs. Interactive docs are enabled only for local/dev unless explicitly approved for deployment. |

### API rules

- `404` for unknown IDs; `409` for conflicting run/review transitions; `422` for invalid filters, payloads, and schema validation; `429` for configured rate limiting; `503` for temporary service dependency failures.
- Validate all IDs, enum values, string lengths, pagination bounds, and request body size.
- Do not accept arbitrary data/output directories or caller-supplied model/provider URLs through the API.
- Require an `Idempotency-Key` for manual run creation; return `run_id`, `status_url`, and `accepted_at`, including the existing job response for a duplicate key. The worker also de-duplicates scheduled run windows and source advisory keys.
- Human-review decisions carry reviewer identity from authenticated context, never a caller-provided identity field. Local demo may use an explicitly labelled development identity until real SSO is agreed.
- Local development role capabilities are explicit: `viewer` (read), `analyst` (read/review), `operator` (read/review/run/usage), `audit_reader` (read/audit events and chain status), `llm_audit_reader` (read/usage/LLM content), and `admin` (all listed capabilities). The role is loaded from trusted configuration and is never accepted from a request.
- API authentication is a deployment gate. Local role gates operate only in development/test with loopback access, or with an explicitly allowlisted private Docker bridge while the host port is published to loopback only. Production rejects trusted-local CIDR configuration; protected routes remain denied until approved OIDC/SSO role checks are implemented. `/auth/context` is informational only.
- Persist a correlated audit event for every protected API request, including method, route template, outcome, status, and bounded non-secret query filters. Never put raw request bodies, credentials, prompts, or model responses in operational logs; prompts and responses use encrypted LLM artifacts.

## 6. Persistence model and ownership

| Record | Minimum fields | Reason |
|---|---|---|
| `source` / `source_checkpoint` | name, enabled, last attempt/success, cursor/modified time, failure count | Independent feed polling and restart-safe checkpoints. |
| `advisory` | canonical ID, vendor/source IDs, title, publication/modified times, CVSS, affected ranges, references, raw-source hash | De-duplication and source provenance. Store raw source payload only if retention/security policy permits. |
| `enrichment` | advisory ID, EPSS score/percentile, KEV status, source, observed time | Make each enrichment value auditable and freshness-aware. |
| `inventory_asset` / `inventory_snapshot` | asset/service, vendor/product/component, version, owner/contact, criticality, exposure, data classification, effective time | Version inventory input and preserve the basis for past decisions. Keep sensitive inventory data local. |
| `run` | ID, trigger, status, start/end, config/policy/prompt versions, counts, safe failure summary | User-visible run history and reconstructable analysis. |
| `job` | ID, type, run ID, queued/claimed/completed timestamps, attempt, lease, idempotency key | Durable queue for API and scheduler work. |
| `match` | advisory/asset IDs, outcome, confidence, evidence, comparator | Distinguish affected, possible, and not affected results. |
| `alert` | current `Alert` fields plus match/run IDs, references, score breakdown, policy version, status timestamps | Dashboard and notification payload. |
| `review_case` / `review_decision` | case, reason, stage, state, reviewer, disposition, note, timestamps | Durable human queue and accountable decisions. Decisions are append-only. |
| `audit_event` | event ID/time, actor/system, run/advisory/asset IDs, event type, before/after hashes or safe summary, source/evidence refs | Reconstruct the pipeline without storing secrets or unnecessary bulletin text. Append-only at the application layer. |
| `llm_call` | call ID, run/job/request IDs, task, provider/model/deployment, prompt version, attempt, start/end, outcome, latency, input/output/total tokens, pricing key/version, estimated cost/currency, safe error class | Attribute every LLM attempt and its cost/usage to the task and run; retain failed calls and retries. No prompt or completion body is stored. |
| `llm_exchange_artifact` | artifact ID, call ID, kind (`request`, `response`, `provider_error`), encrypted canonical payload, plaintext SHA-256, key/version reference, capture time, retention deadline, purge time | Preserve the exact system prompt, user prompt/query, serialized context/messages and model parameters, plus raw response or sanitized provider error for audit/replay. Isolated from general logs and access-controlled; expiry erases ciphertext while retaining hash/tombstone metadata and a chained purge event. |
| `llm_audit_access` | access event ID/time, actor, call/artifact IDs, purpose/reason, request ID, outcome | Audit every view/export of prompt or response content and support review of sensitive audit access. |
| `outbox_message` | event key, channel, recipient reference, payload hash, status, attempts, next retry, provider response code | Future Teams/email delivery with idempotency and dead-letter visibility. |

Persist an inventory snapshot/version with each run. A later inventory change must not silently rewrite the facts behind an old alert. Keep `out/` JSON exports for CLI/eval compatibility and optionally produce a run export from persisted records.

## 7. LLM integration and safety contract

### Provider decision

Retain `LLMPort`, `FakeLLM`, and the existing `GatewayLLM` behavior as the compatibility baseline. Refactor provider creation into validated settings and adapters without putting provider-specific code into agents. Configure provider as `fake` or `openai_compatible` for the first implementation. Confirm the approved Azure endpoint shape before enabling production calls; add an `azure_openai` adapter if the endpoint is not OpenAI-compatible.

### Configuration shape

Local `.env` is read at process startup; real `.env` files remain ignored by Git. `.env.example` documents only names, safe defaults, and fake placeholder values:

```dotenv
# API and worker
COUNTERSTRIKE_ENV=development
API_HOST=127.0.0.1
API_PORT=8000
DATABASE_URL=postgresql+psycopg://counterstrike:change-me@localhost:5432/counterstrike
DATA_DIR=data
OUT_DIR=out
POLL_INTERVAL_MINUTES=15

# LLM: keep fake as the safe offline default
LLM_PROVIDER=fake
LLM_LIVE_CALLS_ENABLED=false
LLM_DATA_BOUNDARY_APPROVED=false
LLM_ARTIFACT_RETENTION_APPROVED=false
LLM_BASE_URL=https://gateway.example.invalid/v1
LLM_API_KEY=replace-with-secret
LLM_MODEL=replace-with-approved-model
LLM_TIMEOUT_SECONDS=30
LLM_MAX_RETRIES=2
LLM_MAX_OUTPUT_TOKENS=1200
LLM_EXTRACTION_ENABLED=true
LLM_SUMMARY_ENABLED=true
LLM_AUDIT_CONTENT_CAPTURE=false
LLM_AUDIT_ENCRYPTION_KEY=replace-with-secret-key
LLM_AUDIT_ARTIFACT_RETENTION_DAYS=configure-after-policy-approval
LLM_INPUT_PRICE_USD_PER_1M=
LLM_OUTPUT_PRICE_USD_PER_1M=
LLM_MAX_COST_PER_RUN_USD=
LLM_MAX_COST_PER_MONTH_USD=
```

The live adapter additionally requires explicit provider/data-boundary and artifact-retention approvals, a persisted run context, a migrated database, and durable encrypted request capture. `LLM_LIVE_CALLS_ENABLED` defaults to false; setting it true without those gates is invalid. Live use remains disabled until the provider decision and role/budget controls are accepted.

No committed `.env` contains a working API key. `.env.example` must not look like a usable secret. `LLM_AUDIT_CONTENT_CAPTURE` stays false by default; enabling the gateway requires changing it to true alongside the required encryption key and approved retention period. The worker checks for expired artifacts every five minutes while content capture and a retention period are configured. It clears ciphertext in a single audited transition, preserving the plaintext hash, capture metadata, and access history; reads are denied as soon as the retention deadline passes and return `410` after purge. Hosted environments inject `DATABASE_URL` and `LLM_API_KEY` from the platform secret store; logs and API responses expose only provider/model labels after redaction, never the key or full secret-bearing URL.

### Call behavior

- Extraction remains limited to untrusted bulletin text plus the approved product vocabulary. Do not send inventory owner, service, internal hostname, or contact data to the model for extraction.
- Summary generation receives only the minimum facts already used by `remediate_agent`; do not expand the prompt with asset contacts or unrelated inventory context.
- Preserve schema validation, literal/evidence grounding, version checks, injection detection, and deterministic fallback. A provider error, timeout, invalid JSON, or grounding failure must route to fallback/human review according to task type; it must not mark a case unaffected.
- Set temperature to zero and enforce an output-token cap. Apply explicit request timeout and at most the configured bounded retries for transient network/server errors. Do not retry authentication, invalid request, or schema failures.
- Record provider name, model/deployment label, prompt version, elapsed time, token usage if provided, retry count, and result category. Never record API key, authorization header, or full prompt payload in standard logs.
- Emit one durable `llm_call` usage record for each network attempt, including a retry or failed response. On a successful response, prefer provider-reported input/output token counts. If usage is absent, record token counts and cost as unknown unless a configured tokenizer/estimation policy is explicitly approved; label estimates separately from provider-reported values.
- Calculate cost using the deployment/model pricing key plus an effective-dated pricing configuration. Store the applied rate version and calculation basis with the row. Do not fetch or assume a public price at runtime; rates can differ by provider, region, deployment, and contract. If the rate is missing, retain tokens and report cost as unknown.
- Allow configured per-run and per-period spend ceilings. Before each model attempt, check the remaining budget; on ceiling breach, stop further calls and use the existing deterministic fallback or route the affected case to human review. Record the budget decision and do not silently switch providers.
- Default CI and local `.env.example` to `fake`. Live model smoke tests are opt-in and cannot be a requirement for offline evaluation.

### Usage and cost API

Add the following usage, reporting, and audited-content endpoints to the API contract:

| Method and path | Purpose | Response / behavior |
|---|---|---|
| `GET /llm/usage` | Aggregate and inspect model usage | Filter by time window, run, provider, model, task, actor, prompt version, advisory, and outcome. Return calls, retries, provider-reported tokens, known cost by currency, and unknown-cost counts; exclude prompt/response bodies. |
| `GET /llm/usage/{call_id}` | Inspect one metered attempt | Return safe call and artifact metadata only; message content is not included. |
| `POST /llm/usage/{call_id}/content` | Read an individual encrypted artifact | Require the `llm_audit_reader` role, artifact kind, and a specific purpose. Return only the selected artifact and append the access outcome to the durable audit chain. |
| `GET /llm/usage/report` | Produce detailed or aggregate usage report | Filter by time, run, task, provider/model, actor, prompt version, advisory, and outcome; group by day/run/task/model/prompt version or return individual attempts. |
| `GET /llm/budgets` | Read configured limits and current period totals | Return limits, spend/usage to date, remaining amount, and threshold state. Values with unknown cost remain separately visible. |

These endpoints require an operator/security role if hosted because model usage and spend can be commercially sensitive. Access to prompt/response contents requires a separate `llm_audit_reader` role and purpose/reason; content is excluded from aggregate responses. The API does not expose a key-management or pricing-edit operation; pricing and ceilings come from protected environment/configuration or a future controlled admin workflow. Empty price settings mean **cost unknown**; they do not disable token counting or silently set spend to zero. A hard spend ceiling requires a valid rate configuration and should fail startup if the ceiling is enabled without rates. Live-model startup also requires approved encryption-key and artifact-retention settings; if full content cannot be durably encrypted before a request, the call must not be sent.

Audit event listing and chain verification use a separate `audit_reader` capability (also granted to `admin`). Event views expose indexed metadata and hashes only; they omit arbitrary event details, reasons, prompts, and responses. Every audit-view request creates its own API access audit event.

Usage and aggregate reports never include message contents. The dedicated content-read endpoint returns one artifact only to a separate `llm_audit_reader` role, requires a purpose/reason, and appends an `llm_audit_access` event. Bulk content export requires separate explicit authorization and bounded date/run filters.

## 8. Observability and audit design

Operational logging, audit events, and LLM metering are separate records with a shared correlation spine. A log line is for operations; an audit event is the durable record of an action/decision; an LLM usage row is the cost/accounting ledger for one provider attempt.

### Correlation and structured logs

- Generate or validate a `request_id` at the API boundary and propagate it through queued `job_id`, `run_id`, `source_id`, `advisory_id`, and `llm_call_id` context. Return `request_id` in response headers and safe error bodies.
- Emit JSON logs with UTC timestamp, severity, event name, service/process, environment, request/run/job/source IDs, duration, outcome, retry number, and safe error code. Use stable event names such as `api.request.completed`, `run.started`, `source.fetch.failed`, `agent.stage.completed`, `llm.call.completed`, `review.decision.recorded`, and `outbox.delivery.attempted`.
- Log method, normalized route template, response status, and duration for API calls. Avoid raw query strings, request bodies, cookies, authorization headers, response bodies, and user-supplied bulletin text. Health/static requests may be sampled or excluded from audit actions but retain aggregate operational counters.
- Log transitions and failure categories at the component that owns them. Avoid duplicate stack traces at every layer; capture one sanitized exception event with `request_id`/`run_id` and keep detailed stack traces in restricted operational logs only.
- Never copy prompts, responses, user queries, serialized context, or raw provider error bodies into operational logs. Their full audited copies belong only in the protected LLM exchange artifact store.
- In production, write stdout/stderr for collection by the deployment platform. Local development writes readable structured output to console; optional rotating local files are not authoritative and are disabled by default.

### Audit event contract

Every state-changing or security-relevant action creates an append-only audit event in the same transaction as its state change where possible. Pipeline decisions and failed attempts are audited even when no user initiated them.

Required event fields:

- `event_id`, `occurred_at` (UTC), `schema_version`, `event_type`, `outcome`, and `actor_type` (`user`, `system`, `worker`, or `integration`).
- `actor_id` from authenticated identity when available; for a service actor, a stable service identity. Never accept an actor identity from an untrusted request body.
- `request_id`, `job_id`, `run_id`, and relevant `source_id`, `advisory_id`, `asset_id`, `alert_id`, `review_id`, `delivery_id`, or `llm_call_id`.
- `action`, `resource_type`, resource identifier, and an allowlisted change summary. Record before/after values only for non-sensitive, explicitly allowlisted fields; otherwise record canonical hashes and references.
- `reason` or decision rationale where applicable, source/evidence references, policy/prompt/schema versions, safe error category, and client/application version.

Audit events cover at least API run enqueue/cancel (if cancellation is supported), source poll/checkpoint, advisory upsert/deduplication, correlation outcome including possible/not-affected, score and policy version, recommendation creation/fallback, review decision, configuration/budget changes, LLM call outcome, and delivery enqueue/attempt/result. Read access to sensitive inventory/review/usage data is separately auditable by route/resource and actor, without copying returned records into the audit event.

Every user/system action that creates, changes, or reads security-sensitive or cost-sensitive data is auditable by actor, resource, outcome, and request ID. High-volume static assets and liveness probes remain operationally logged/aggregated rather than producing noisy per-file business audit rows.

### Integrity, retention, and access

- The API/worker database role may insert but not update/delete audit rows; use a separate migration/retention role for maintenance. Application code has no audit-delete endpoint.
- Add indexes for time, actor, event type, run, and resource IDs. Configure retention and access review with the requirement owner; do not set an arbitrary permanent retention period in code.
- Include the previous event hash and current canonical event hash per tenant/system stream, with deterministic serialization. A periodic verifier reports broken links. Hash chaining is tamper-evidence, not a substitute for restricted DB access or backups.
- For production, periodically export audit batches and their signed/hash manifest to the approved immutable/WORM log store once that destination is selected. Until then, report the PostgreSQL audit store as the source of record and its limitations.
- Restrict audit and usage views to authorized roles. Prompt/response content is an explicit audited-data exception: preserve it exactly in an encrypted artifact store with separate key management, no general DB/log access, access-reason capture, access audit, configurable retention/deletion, and tamper-evident hashes. API keys, authorization headers, cookies, and credentials are always removed before persistence. Provider error bodies are retained only after credential redaction and size limits.
- Exact prompts and responses may contain proprietary advisories, user-provided text, or personal data. Production enablement requires the data owner to approve the model data boundary, encryption key owner, access group, retention period, and permitted export destination. If content retention is not approved, the system must not claim full prompt/response auditability; live-model mode requires an explicit approved exception policy.

### LLM usage and cost accounting

- Meter the logical task and each provider attempt separately so retries and failures cannot disappear from accounting. A logical extraction/summary can point to multiple `llm_call` rows. For every attempt, capture the exact rendered system and user messages, user query/input, serialized context, model parameters, and raw response body or sanitized error body as encrypted, hash-verified artifacts. Preserve the model's raw response separately from the parsed/validated output used by the agent.
- Store the request before dispatch and append the response/error immediately after completion. A crash between these steps leaves an auditable request with a `response_missing` outcome rather than an unrecorded call. If the request artifact cannot be durably recorded, do not send the live model request.
- Keep full prompt/response content out of standard list, dashboard, and aggregate reports. A privileged individual-call view may reveal artifacts, with reason and actor recorded in `llm_audit_access`; bulk content export requires separate permission and bounded date/run filters.
- Retain both prompt template/system-prompt version and a content hash alongside the exact rendered prompt. This lets reviewers inspect the template version and the precise query/context used for the call.
- Preserve provider-reported token counts and usage source. Track input, output, cached input (when available), total tokens, latency, outcome, retry count, and safe provider error family. Do not infer zero use from a missing usage block.
- Compute per-call estimate as `input_tokens × input_rate + output_tokens × output_rate`, applying provider-specific cached-token rates only when reported and configured. Store native currency and normalized currency only if an approved exchange-rate source is introduced; initially report provider currency and avoid fabricated FX conversions.
- Attribute spend to run, task (`extract`/`summarise`), provider/model/deployment, environment, and time interval. The usage endpoint distinguishes provider-reported cost (if returned), locally estimated cost, and unknown cost.
- Record pricing as versioned configuration with effective date, model/deployment key, input/output (and optional cached input) rate per million tokens, currency, source/approver, and update timestamp. Rates are deployment configuration, not constants hidden in agent code.
- Add alerts/metrics at configurable spend thresholds and stop further LLM calls at hard ceilings. A ceiling breach becomes a visible run event and follows deterministic fallback/human-review policy. Do not automatically send content to a cheaper/unapproved model.
- Reconcile local estimates against a provider billing/usage export when available, but do not make provider billing APIs a runtime dependency. Store reconciliation period, source, difference, and status as a separate accounting record.

## 8. Feed and worker behavior

The source adapters normalize NVD, CISA KEV, OSV, and EPSS inputs into source-aware domain records; the exact first three production sources and access requirements must be confirmed. Keep fixture JSON as an adapter used by tests and offline evaluation.

1. Scheduler creates a unique poll job for each source/window; the DB uniqueness key prevents duplicate scheduled work.
2. Worker claims one job with a lease and records an attempt before calling a source.
3. Adapter makes bounded HTTP requests, honors rate limits/`Retry-After`, validates payloads, and records source-specific success/failure. A failing feed does not block other source jobs.
4. Normalize identifiers and upsert advisories/enrichment idempotently. Save checkpoint only after successfully processing the corresponding page/window.
5. A run is marked `partial` if a required source fails but the remaining work completes; status retains per-source evidence and safe failure categories.
6. After ingestion and enrichment, invoke the existing deterministic LangGraph stages. Persist results transactionally by run; write audit events for stage decisions and include the policy/prompt versions.
7. Worker commits an outbox record for each intended delivery; a separate delivery loop sends only when a channel is enabled. Repeated jobs reuse stable idempotency keys.

Initial scheduling follows the gap plan’s 15-minute interpretation. Make the interval configurable and record it in run metadata. Polling interval, feed API limits, and source-specific retention need operator approval before deployment.

## 9. Security, privacy, and operational controls

- Local API defaults to loopback. Production API must use TLS through the deployment ingress and approved OIDC/SSO roles: read-only dashboard, analyst review, and operator run/config permissions.
- Worker and API use separate least-privilege DB roles where practical. The worker may write run results; the API may read and enqueue. Audit storage denies update/delete to application paths.
- Validate model and feed URLs at startup from trusted configuration. Never let an HTTP request choose a URL, model deployment, filesystem path, or credential.
- Request limits, bounded pagination, timeouts, retry caps, and job leases prevent unbounded work. Health endpoints return dependency status without secrets or internal stack traces.
- Use structured logs and the audit/usage controls in Section 8 with correlation IDs (`request_id`, `run_id`, `source_id`), redaction filters, UTC timestamps, and no raw key/prompt/inventory dumps.
- Keep raw source retention configurable and documented. Do not log or expose personally identifying owner contacts beyond the role-authorized response.
- Use migrations as the only schema-change mechanism; backups and restore checks are deployment requirements before production data is used.
- Store generated recommendations with references and evidence. Unsupported advice is withheld or flagged for human review; the LLM cannot invent or replace references.

## 10. Frontend integration plan

The current `frontend/app.js` expects a single `/api/data` bundle and the Node server reads `out/` plus fixture files. During migration:

1. Implement `/api/v1/dashboard`, `/alerts`, `/reviews`, `/runs`, and `/health/*` with fixture-backed repository adapters first.
2. Change frontend calls to the versioned endpoints (or provide a temporary compatibility `/api/data` adapter) and render loading, empty, partial, error, and stale-run states.
3. Add a visible `Run analysis` action that submits an idempotent `POST /runs`, then polls the run status. Keep destructive asset actions absent.
4. Serve the static frontend through FastAPI in local and Compose runs; remove reliance on the Node static-data API after parity is verified.
5. Make review submission explicit with confirmation, disposition, note, and reviewer identity from the auth context.

## 11. Implementation phases and gates

| Phase | Deliverable | Gate before next phase |
|---|---|---|
| 0. Freeze this design | Confirm endpoints, provider, data boundary, auth mode, storage, and first-source list. | Requirement owner approves this decision document; unresolved choices are marked as deferred rather than silently assumed. |
| 1. Settings and API skeleton | Typed settings loader, `.env.example`, FastAPI app, error envelope, OpenAPI, health endpoints, same-origin static serving, JSON logging and correlation middleware. | Startup validation works without a key in fake mode; secret values never appear in errors; request IDs cross API/log boundaries. |
| 2. Database and run/job model | SQLAlchemy models, Alembic baseline, repositories, job lease/idempotency, append-only audit and LLM usage tables. | Migration creates clean DB; restart does not lose job/run history; duplicate request creates one run; application role cannot update/delete audit rows. |
| 3. Read APIs and frontend migration | Dashboard, alerts/detail, reviews, runs, source health; UI migrated to API. | API/UI counts match fixture CLI output; filters, empty, loading, failed, partial states are legible. |
| 4. Worker and LLM | Worker executes LangGraph; harden gateway client and keep FakeLLM. | Offline fixtures pass unchanged; provider timeout/schema/adversarial cases safely fall back; no model-owned priority or match. |
| 5. Feed adapters and schedule | Source adapters, checkpoints, deduplication, APScheduler in worker. | Mocked multi-feed cycle and isolated outage scenarios demonstrate idempotence and source-level errors. |
| 6. Analyst audit and outbox | Persist review decisions, audit trail, LLM usage/cost ledger, delivery outbox and disabled-by-default channel adapters. | Replay reconstructs decision chain and each model attempt; usage totals reconcile to call rows; missing price is shown as unknown; duplicate delivery retries do not duplicate messages; no target asset mutation exists. |
| 7. Compose and hardening | API/worker/PostgreSQL Compose, health checks, CI checks, deployment notes. | Clean setup works from `.env.example`; live secrets remain external; acceptance evidence is mapped to requirement ACs. |

No implementation phase begins until Phase 0 is approved. The acceptance matrix and test cases are derived from the updated requirement’s FR/AC list; exact metric thresholds, timing targets, and source credentials must be confirmed before claiming compliance.

## 12. Verification strategy

- **Unit:** settings validation and redaction; API DTOs; migrations/models; feed parsing; identifier normalization; idempotency; queue leases; retries/backoff; LLM output schema and grounding; correlation outcomes; risk boundaries; review transitions.
- **API contract:** OpenAPI snapshot/schema checks; status codes and safe error envelopes; pagination/filter bounds; no secret or internal path fields; auth role matrix.
- **Integration:** PostgreSQL-backed run queue; API enqueues one run; worker executes FakeLLM fleet; dashboard/alert/review/run views match persisted records; scheduler enqueue behavior.
- **Reliability/security:** source/LLM/database timeout and failure injection; one source outage isolation; repeat poll and repeated POST idempotence; untrusted bulletin injection; reviewer audit trail; no outbound target-system writes.
- **Observability/accounting:** every state-changing API action and pipeline decision maps to an audit event; request/run IDs connect logs, audit rows, and LLM attempts; audit tamper verification detects altered/deleted links; per-run/provider/task usage totals equal call-level rows; retry and failed-call usage is retained; cost unknown is distinct from zero; budget thresholds stop calls and produce an auditable fallback.
- **LLM exchange audit:** exact rendered system/user prompts, user query/context, model parameters, raw response, and parsed output are retrievable for an authorized individual call; artifact hashes verify; retries have distinct attempt records; artifact views/exports create access audit events; aggregate reports do not leak content; credentials are absent; filters and totals reconcile to call rows.
- **Evaluation:** preserve existing offline gold evaluation. Add requirement metrics for precision/recall, uncertain matches routed to review, source citation coverage, and run latency. Live provider/channel checks are manually enabled and never leak credentials to CI artifacts.
- **Manual acceptance:** clean Docker Compose startup, `.env.example` setup, browser dashboard, manual run progress, analyst queue, health/source status, and explicit disclosure of local fixture versus live feed/provider state.

## 13. Decisions requiring confirmation before freeze

The following cannot be safely inferred from the repository and are called out for approval:

1. Is the deployment provider **Azure OpenAI**, and if so does the approved endpoint support the OpenAI-compatible route? If not, confirm the required Azure API version/deployment semantics for a dedicated adapter.
2. Are FastAPI + PostgreSQL + a PostgreSQL-backed worker queue acceptable, or is an existing organization platform/database mandated?
3. Confirm whether the requirement’s first source set is NVD + CISA KEV + OSV and whether EPSS is a required fourth enrichment source.
4. Confirm local development identity behavior and the production identity provider/roles before shared deployment.
5. Confirm which Teams/email mechanisms and recipients are approved; until then, outbox delivery remains disabled.
6. Confirm inventory and advisory retention rules, raw bulletin storage, owner contact handling, and the model data boundary.
7. Confirm whether analyst decisions should change alert state or only annotate/reclassify a review case. This proposal defaults to append-only disposition and no silent suppression.
8. Confirm if the dashboard API is read-only to most users and which roles may enqueue runs or submit decisions.
9. Approve audit-log retention, immutable/WORM archive destination, access roles, and whether sensitive read access must be retained at field-level or route/resource-level granularity.
10. Confirm the provider billing/usage source, pricing owner and update workflow, currency policy, and per-run/monthly LLM budgets. Until approved, token usage is still recorded, but cost is reported as unknown without configured rates.
11. Approve full prompt/query/context and response retention: permitted data classes, encryption key ownership, LLM-audit readers, access-reason policy, retention/deletion period, and bulk export permissions. This is required before live-model calls are enabled because captured text can contain sensitive or licensed source content.

## 14. Freeze checklist

The design can be marked **Approved / Frozen** when the requirement owner accepts the proposed stack and either answers or explicitly defers each item in Section 13. Record changes to this document and the decision log before implementation. After freeze, implementation can proceed phase by phase against the API, persistence, audit, and metering contracts above; changes to a frozen contract require a decision-log entry.
