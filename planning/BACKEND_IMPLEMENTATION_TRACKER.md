# Counterstrike Backend Implementation Tracker

**Tracker status:** Active  
**Strategy status:** Accepted as the implementation planning baseline on 31 October 2026; production/security decisions remain gated.  
**Implementation status:** In progress (Phases 1–4 foundations started)  
**Source of design:** [Backend API and LLM Integration Strategy](BACKEND_API_LLM_STRATEGY.md)

This tracker turns the approved backend strategy into reviewable work. Update task and phase statuses here as work proceeds. A status of **Done** means the stated acceptance evidence exists; it does not mean only that code was written.

## Status legend

| Status | Meaning |
|---|---|
| Not started | No implementation work has begun. |
| In progress | Work is actively underway. |
| Blocked | Work cannot proceed until a named dependency or decision is resolved. |
| Done | Acceptance evidence has been checked and recorded. |
| Deferred | Explicitly moved out of the approved scope, with a reason. |

## Overall progress

| Phase | State | Tasks done | Tasks total | Exit condition |
|---|---|---:|---:|---|
| 0. Planning and gates | In progress | 1 | 4 | Strategy baseline and tracker accepted; operational decisions recorded before affected production features. |
| 1. Service foundation | In progress | 0 | 5 | Configured API starts safely, serves UI, and emits correlated structured logs. |
| 2. Database, audit, and migrations | In progress | 0 | 6 | Durable schema and append-only audit controls work on a clean PostgreSQL instance. |
| 3. LLM exchange, usage, and cost | In progress | 0 | 8 | Each model attempt has auditable request/response artifacts, usage and cost status; reports reconcile. |
| 4. API workflows and frontend integration | In progress | 0 | 8 | UI is served by the API and all views/actions use versioned API contracts. |
| 5. Worker, runs, and source polling | In progress | 0 | 7 | Manual and scheduled jobs are durable, isolated, idempotent, and observable. |
| 6. Analyst review and delivery outbox | In progress | 0 | 5 | Review decisions are attributable; delivery is durable and disabled until configured. |
| 7. Containerization and acceptance | In progress | 0 | 6 | Clean Compose setup and acceptance evidence cover applicable requirements. |
| **Total** | **Implementation active** | **1** | **49** | Phases 1–6 foundations are underway; runtime acceptance evidence is pending. |

The one completed item is `PLN-01`: strategy and technology baseline accepted for planning. Phase 1 items are in progress and do not count as done until their acceptance evidence has been checked. Progress counts are updated when task status changes; blocked and deferred items do not count as done.

## Phase 0 — Planning and decision gates

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| PLN-01 | Accept the backend strategy as the implementation planning baseline. | — | **Done** | User authorized creation of phased implementation items; strategy is the baseline. |
| PLN-02 | Confirm or explicitly defer provider details: Azure endpoint/API shape, deployment/model identifier, approved data boundary. | PLN-01 | Not started | Decision recorded in strategy and `DECISION_LOG.md`; no live LLM enablement until resolved. |
| PLN-03 | Approve full prompt/query/context/response artifact retention: data classes, encryption key owner, reader role, reason policy, retention/deletion, export rules. | PLN-01 | Not started | Written configuration/retention decision; gates live-model mode. |
| PLN-04 | Confirm database/platform, identity provider and roles, feed sources, audit archive/retention, pricing owner/rates, and spend ceilings. | PLN-01 | Not started | Each decision recorded or marked deferred with the phase it blocks. Local fixture implementation may proceed with safe defaults. |

## Phase 1 — Service foundation

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| FND-01 | Add validated application settings and local `.env` loading; document all settings in `.env.example`. | PLN-01 | In progress | Added typed settings, environment-over-dotenv precedence, safe defaults, and example placeholders. Runtime validation evidence is pending. |
| FND-02 | Add FastAPI/Uvicorn application, typed API DTOs, versioned router, consistent safe error envelope, and OpenAPI. | FND-01 | In progress | Added API shell, typed health/error schemas, safe error handlers, and development OpenAPI. Runtime/API contract evidence is pending. |
| FND-03 | Add `/health/live` and `/health/ready` with safe dependency status. | FND-02 | In progress | Liveness and readiness routes are implemented. Readiness distinguishes non-production fixture mode from DB mode and compares applied Alembic heads with repository heads; the migration-head read was repaired to run while its connection is open. Runtime status-code/clean-migration checks remain pending. |
| FND-04 | Add JSON operational logging, UTC timestamps, redaction, and request correlation middleware. | FND-02 | In progress | Added JSON formatter, request IDs, route-template access event, redaction, and Uvicorn logger wiring. Runtime/log redaction evidence is pending. |
| FND-05 | Serve the current frontend from FastAPI; retain a temporary compatibility path while the UI migrates. | FND-02 | In progress | Added same-origin static mount and temporary `/api/data`; browser/runtime smoke evidence is pending. |

## Phase 2 — Database, audit, and migrations

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| DB-01 | Add PostgreSQL, SQLAlchemy 2.x, psycopg 3, Alembic, connection lifecycle, and environment-specific DB configuration. | FND-01 | In progress | Added dependencies, secret-safe URL setting, engine/session helpers, and DB readiness check against current Alembic heads. Clean DB connection/migration evidence is pending. |
| DB-02 | Model source/checkpoint, advisory/enrichment, inventory snapshot, run/job, match, alert, review, audit, LLM usage/artifacts, and outbox records. | DB-01 | In progress | Added SQLAlchemy models for all planned records; metadata/migration consistency review and persistence evidence are pending. |
| DB-03 | Add initial migration and migration policy; prohibit schema changes outside Alembic. | DB-02 | In progress | Added Alembic configuration and explicit PostgreSQL baseline migration. Upgrade/downgrade evidence against a clean DB is pending. |
| DB-04 | Add repositories and transaction boundaries for run and result persistence. | DB-02, DB-03 | In progress | Added queued/started lifecycle operations and atomic graph-result persistence for advisory, inventory snapshot/assets, matches, alerts, review cases, run summary, and chained audit events. Persistence/restart evidence and transaction rollback verification remain pending. |
| DB-05 | Implement append-only audit writes, event schema/version, correlation fields, hashes, and verifier. | DB-02, DB-03 | In progress | Added serialized global sequence, SHA-256 chaining, append writer, verifier, and PostgreSQL update/delete guards. Concurrency/tamper evidence and DB-role hardening remain pending. |
| DB-06 | Add safe audit and LLM artifact access records, retention jobs, and local/hosted key-provider interfaces. | PLN-03, DB-02, DB-05 | In progress | Added AES-256-GCM artifact encryption/decryption, key-version AAD, SHA-256 integrity validation, retention expiry checks, and per-read access/audit records. Key rotation/provider abstraction, purge job, authorization integration, and operational approval remain pending. |

## Phase 3 — LLM exchange, usage, and cost

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| LLM-01 | Refactor settings/provider factory behind existing `LLMPort`; preserve `FakeLLM` as default. | FND-01 | In progress | Factory now resolves configured fake/OpenAI-compatible providers and passes run/request/actor context. Live-run factory wiring and offline contract evidence remain pending. |
| LLM-02 | Harden OpenAI-compatible client with explicit timeout, bounded retries, output cap, status/error handling, and usage extraction. | LLM-01, PLN-02 | In progress | Added timeout, capped output, bounded transient retries, redacted/safe failure categories, provider token extraction, and per-attempt writes. Extract failures route to review and summary failures use deterministic fallback. Provider contract evidence and approved endpoint details remain pending. |
| LLM-03 | Add optional provider-specific Azure adapter if the approved endpoint is not OpenAI-compatible. | PLN-02, LLM-01 | Not started | Adapter conforms to the same port and passes provider contract tests. Deferred if compatible route is approved. |
| LLM-04 | Capture exact rendered system/user messages, query/context, model parameters, and prompt template/version per attempt. | DB-06, LLM-01 | In progress | Gateway encrypts canonical provider request and task context, stores prompt version/advisory ID, and sends the same canonical request bytes. Provider payload parity evidence remains pending. |
| LLM-05 | Persist raw response, parsed/validated output, or sanitized error response; hash and encrypt each artifact before/at dispatch. | DB-06, LLM-02, LLM-04 | In progress | Gateway commits encrypted request before dispatch; writes raw response plus extracted output or sanitized failure after completion. Crash/recovery and response-missing acceptance evidence remain pending. |
| LLM-06 | Record per-attempt call metadata, retries, latency, token counts and source, prompt version, result/error category, and provider/model. | DB-02, LLM-02 | In progress | Gateway records each retry as a linked attempt with task/provider/model/actor/advisory/request/run, latency, provider token counts, and safe outcome. Runtime reconciliation remains pending. |
| LLM-07 | Add effective-dated pricing configuration, cost calculation, unknown-cost handling, and run/period spend ceilings. | LLM-06, PLN-04 | In progress | Added immutable provider/model pricing versions with UTC effective dates, audit events on rate registration, per-call captured version/date/rates, conservative USD attempt estimates, PostgreSQL transaction advisory locks for run/month scopes, auditable denial on breach/unpriced history, and budget reporting with enforced reservations. Estimate-vs-bill reconciliation, pricing schedule acceptance, and PostgreSQL concurrency/breach acceptance remain pending. |
| LLM-08 | Add usage query/report API, aggregate groupings, privileged individual-call artifact view, and content-access audit. | DB-06, LLM-06, LLM-07, FND-02 | In progress | Added filtered usage metadata, aggregate token/cost/retry reporting by selected dimension and currency, month/run budget status, and individual call/artifact metadata. Added `llm_audit_reader`-gated content read with required purpose and success/failure/missing-artifact access auditing; hosted role, reconciliation, and bounded export evidence remain pending. |

## Phase 4 — API workflows and frontend integration

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| API-01 | Add dashboard aggregate endpoint with latest run, priority counts, review count, and top findings. | DB-04, FND-02 | In progress | Added `/api/v1/dashboard` with latest-run aggregates and ordered findings from durable records. Aggregate reconciliation evidence remains pending. |
| API-02 | Add paginated/filterable alert list and alert detail with evidence, references, score breakdown, and policy version. | DB-04, FND-02 | In progress | Added bounded pagination, priority/owner/service/search/since filters, stable ordering, and detail DTOs. Alert details now include bounded advisory context and inventory security posture needed by the UI. Contract/filter and database evidence remains pending. |
| API-03 | Add review queue list and decision API with authenticated actor, disposition, reason, validation, and audit write. | DB-04, DB-05, PLN-04 | In progress | Added paginated/filterable queue with bounded source-bulletin evidence/references and decision history, plus final-decision submission at the strategy path. Validates disposition/note, locks open case, appends decision, resolves case, and writes audit in one transaction. Actor attribution uses the configured local development identity; hosted identity and runtime transition/audit checks remain pending. |
| API-04 | Add run history, run detail/trace, and feed/source status endpoints. | DB-04, DB-05 | In progress | Added paginated run history, safe filtered run trace detail, and source/checkpoint status endpoints. Failure-state contract evidence remains pending. |
| API-05 | Add role enforcement for read, review, run, usage, audit, and LLM-content access. | PLN-04, FND-02 | In progress | Added trusted configuration-backed local roles and capability gates for read, review, run, usage, audit, and LLM content. Protected API requests persist method, route, outcome, status, timing, and bounded non-secret query filters; denied requests also emit structured logs. Docker development access is limited to an explicit private bridge CIDR while the published host port is loopback-only; production rejects that exception. Hosted OIDC/SSO and role-matrix/runtime acceptance remain pending. API source was recovered from bytecode and decompilation defects in run summaries, reviews, and usage reports were repaired; a broader endpoint-contract review remains required. |
| API-06 | Migrate frontend from `/api/data` fixture bundle to versioned endpoints and handle loading/empty/error/partial states. | FND-05, API-01, API-02, API-03, API-04 | In progress | Frontend now loads dashboard, paginated alert/review collections, run detail, sources, readiness, and capability context from versioned APIs; maps API DTOs into the existing page model; supports retry and partial-data banners; and submits analyst decisions through the audited review route. Alert detail now loads associated advisory and inventory context from the API. Browser/API acceptance and large-collection pagination UX remain pending. |
| API-07 | Add manual run form/action and progress polling; use idempotency key and explain current data/provider mode. | WKR-02, API-04, API-05 | In progress | Overview exposes Start analysis only with the `run` capability, posts to `/api/v1/runs` with a fresh `Idempotency-Key`, distinguishes fixture input from database persistence, reports provider/live-call state, and polls run detail to a terminal state with a bounded timeout. Worker/browser acceptance remains pending. |
| API-08 | Add bounded audit event reporting and audit-chain integrity endpoint. | DB-05, API-05 | In progress | Added `audit_reader`/`admin` capability gates, filterable paginated event metadata, and chain verification status. Free-form event details are not exposed; access is captured by API request auditing. PostgreSQL, authorization, and tamper-detection acceptance remain pending. |

## Phase 5 — Worker, runs, and source polling

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| WKR-01 | Add durable PostgreSQL job claim/lease/heartbeat/retry logic and worker entry point. | DB-04 | In progress | Added `counterstrike-worker`, skip-locked claim, expired-lease recovery, heartbeat renewal, bounded retry/backoff, and lifecycle audit events. Must validate on PostgreSQL under concurrent claim and worker restart before acceptance. |
| WKR-02 | Queue manual runs via API, enforce idempotency and safe run scope, and track run lifecycle. | WKR-01, API-05 | In progress | Added local-only `POST /api/v1/runs`, required idempotency key, configured-data scope, atomic run/job queueing, deduplication, and audit events. API-05 role enforcement and database concurrency acceptance remain pending. |
| WKR-03 | Invoke existing LangGraph from worker, persist trace/results, and preserve offline CLI/eval behavior. | WKR-02, LLM-01, DB-04 | In progress | Worker passes persisted run/request/actor/job context to the graph and writes successful graph results with job completion atomically. Gold-fixture equivalence and failure/restart persistence acceptance remain pending. |
| WKR-04 | Define feed adapter contract and fixture adapter; normalize source provenance and identifiers. | DB-02 | In progress | Added a typed `FeedAdapter` contract, normalized `FeedBatch`, and deterministic fixture adapter. The ingest trace records source ID and UTC fetch time while preserving existing advisory normalization/deduplication. Public source adapters and database source/checkpoint persistence remain open. |
| WKR-05 | Implement and contract-test the first approved source adapters and enrichment adapters. | PLN-04, WKR-04 | Not started | Mocked source fixtures validate pagination, schema drift, rate limits, and provenance. |
| WKR-06 | Add isolated source jobs, checkpointing, deduplication, safe retry/backoff, and source health reporting. | WKR-01, WKR-05, DB-05 | Not started | Repeated polls are idempotent; one source outage does not stop others; checkpoint advances only after successful processing. |
| WKR-07 | Add APScheduler to the dedicated worker for the approved polling interval and unique schedule windows. | WKR-06, PLN-04 | Not started | Exactly one scheduler instance; duplicate schedule cannot enqueue duplicate poll work. |

## Phase 6 — Analyst review and delivery outbox

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| ACT-01 | Persist confirmed/possible/not-affected match outcomes and confidence/evidence; route uncertainty to review. | WKR-03, DB-02 | Not started | Low-confidence cases are reviewable and never silently treated as not affected. |
| ACT-02 | Persist analyst decision history and make status/rationale visible in API/UI. | API-03, DB-05 | In progress | Decisions are append-only in storage and returned with case state and rationale from the review API. The migrated review UI displays history and submits audited decisions; browser replay and database transition/audit acceptance remain pending. |
| ACT-03 | Create transactional delivery outbox rows with stable idempotency keys and delivery audit events. | DB-02, DB-05, WKR-03 | Not started | Run retry never creates duplicate logical delivery. |
| ACT-04 | Add Teams/email channel adapters behind explicit config, role, recipient allowlist, and disabled-by-default setting. | PLN-04, ACT-03 | Not started | Mocked channel tests verify routing, retries, dead-letter visibility, and disabled behavior. |
| ACT-05 | Add daily digest generation and scheduling if retained as a Must in confirmed requirement scope. | ACT-04, WKR-07 | Not started | Digest groups eligible alerts by recipient and is idempotent; schedule and recipients are approved. |

## Phase 7 — Containerization and acceptance

| ID | Work item | Depends on | Status | Acceptance evidence / notes |
|---|---|---|---|---|
| OPS-01 | Add Dockerfile and Compose services for API, worker, PostgreSQL, migrations, and health checks. | DB-03, FND-05, WKR-01 | In progress | Added non-root Python image, PostgreSQL, one-shot migration, API and worker services, persistent volumes, health dependencies, and loopback-only API publication. Compose config and image build pass; clean startup completed, migrations reached `0004_llm_call_pricing_date`, and `/health/ready` returned 200 with database and required data checks ready. `/api/v1/dashboard` returned the expected empty-state response. Startup uncovered and fixed log-secret redaction and installed-package project-root detection. Remaining: verify container health/network publication and exercise manual-run access; broader clean-volume/recovery acceptance remains open. |
| OPS-02 | Add deployment logging, metrics/export hooks, audit archive integration, backups, and restore procedure. | DB-05, FND-04, PLN-04 | Not started | Operator can find a run by request/run ID and demonstrate audit recovery and restore. |
| OPS-03 | Extend CI for formatting/lint, unit, API contract, PostgreSQL integration, security checks, and existing evaluation gate. | Phase 1–6 | Not started | CI remains offline by default; hidden fixtures stay protected; reports do not publish secrets/prompt content. |
| OPS-04 | Add reliability/security fault injection for API, DB, source, LLM, scheduler, and delivery failures. | Phase 1–6 | Not started | Failure isolation, retries, safe fallback, and audit coverage pass documented scenarios. |
| OPS-05 | Map requirement acceptance criteria to runbook/demo evidence and record measured metrics. | OPS-03, OPS-04 | Not started | Each applicable AC has linked evidence or a clear approved exception; measurements are distinguished from estimates. |
| OPS-06 | Complete production-readiness review: auth, key rotation, prompt retention, audit retention, pricing, budgets, source/channel approvals. | PLN-02, PLN-03, PLN-04, Phase 1–6 | Not started | Written sign-off; live-model and external delivery switches remain off until passed. |

## Cross-phase implementation rules

- Keep the existing offline `FakeLLM` and gold evaluation working throughout; live calls are never needed for ordinary CI.
- Do not expose or log `.env`, API keys, authorization headers, database URLs, raw prompt/response artifacts, or full sensitive inventory records.
- Store exact model requests before sending and responses immediately after receipt; preserve raw versus parsed output and every retry as separate linked attempts.
- Every state transition and security-sensitive action must include actor/service identity, UTC time, request/run correlation, outcome, and audit evidence.
- LLM cannot set match outcomes, priority, risk, SLA, owner, or remediation facts. Existing grounding and injection safeguards remain release gates.
- No phase may silently turn an unknown result into “not affected.” No code path may modify managed assets.
- Update this tracker in the same change that completes a task: status, date, evidence link/command, and any new blocker. Recalculate phase and total counts after each update.

## Progress update log

| Date | Items updated | Summary | Evidence / blocker |
|---|---|---|---|
| 2026-10-31 | PLN-01 | Strategy accepted as implementation planning baseline; backlog and status tracker initialized. | User requested phased implementation items and trackable progress. No implementation code started. |
| 2026-10-31 | FND-01–FND-05 | Started API foundation: settings/.env example, FastAPI/Uvicorn entry point, liveness/readiness, structured request logs, same-origin static serving, and CLI live-LLM safety gate. | Added `config.py`, `api.py`, `observability.py`, `server.py`, `.env.example`; runtime acceptance evidence still pending. |
| 2026-10-31 | DB-01–DB-03 | Started persistent data foundation with SQLAlchemy models and an explicit Alembic baseline. | Added `db.py`, `db_models.py`, `migrations/env.py`, and `migrations/versions/0001_initial_schema.py`; PostgreSQL upgrade/consistency checks remain pending. |
| 2026-10-31 | DB-05–DB-06 | Started append-only chained audit events and encrypted LLM exchange content with audited read attempts. | Added `audit.py`, `artifacts.py`, key-version configuration, stream sequence persistence, and Postgres immutability triggers; migration/runtime/concurrency/access-control evidence remains pending. |
| 2026-10-31 | DB-04 | Started the transaction-owned run repository and graph output persistence path. | Added `repositories.py` for run creation/start and atomic run result snapshots; database persistence and restart acceptance evidence remain pending. |
| 2026-10-31 | API-01, API-02, API-04 | Started durable read APIs for dashboard, alerts, runs, and sources. | Added versioned endpoints and bounded filters in `api.py`; database-backed contract and UI integration evidence remains pending. |
| 2026-10-31 | LLM-08 | Started filtered per-call metadata and grouped usage reporting endpoints. | Added `/api/v1/llm/usage`, `/report`, `/budgets`, and `/{call_id}` metadata views plus actor/advisory dimensions; role-protected artifact content access and report reconciliation remain pending. |
| 2026-10-31 | LLM-04–LLM-07 | Started durable call metering and encrypted request/response artifact write operations. | Added `llm_metering.py`, versioned rates, token-based known-cost calculation, unknown-cost handling, and attempt audit events; provider orchestration and budget enforcement were added in the next tracker update, with acceptance evidence pending. |
| 2026-10-31 | LLM-01, LLM-02, LLM-04–LLM-06 | Wired OpenAI-compatible attempts through the durable audit/metering service. | Added explicit live-call/data-retention gates, timeout and bounded retry behavior, request-before-send commit, response/error capture, agent prompt/advisory metadata, and provider usage extraction; provider/database acceptance evidence remains pending. |
| 2026-10-31 | LLM-02 | Added task-level failure handling for live provider errors. | Extraction provider failures now route to human review; summary failures fall back to deterministic grounded text; operational logs include safe task/advisory/error-category fields without prompt content. Acceptance evidence remains pending. |
| 2026-10-31 | WKR-01 | Started durable job lifecycle and dedicated worker process. | Added atomic PostgreSQL `SKIP LOCKED` job claims, lease recovery/heartbeat, retry backoff, safe terminal error codes, audit events, and `counterstrike-worker`; PostgreSQL concurrency/restart acceptance remains pending. |
| 2026-10-31 | WKR-02, WKR-03 | Connected local manual run requests to durable jobs and worker graph execution. | Added `POST /api/v1/runs` with required idempotency key and same-transaction run/job/audit writes; worker executes LangGraph and atomically persists successful run output plus job completion. Local-only access is enforced pending API-05; runtime/DB acceptance remains pending. `py_compile` and `git diff --check` pass; test suite not run. |
| 2026-10-31 | LLM-07 | Added pre-dispatch transactional spend reservations and auditable budget rejection. | Added per-attempt conservative USD estimates, PostgreSQL advisory transaction locks over run/month budget scopes, fail-closed handling for historical unpriced calls, persisted budget-denial audit events, and migration `0002_llm_budget`. PostgreSQL race/breach acceptance and effective-dated pricing remain pending. |
| 2026-10-31 | LLM-07 | Added append-only effective-dated pricing versions and linked each LLM attempt to the applied rate. | Added `LLM_PRICING_EFFECTIVE_AT`, immutable provider/model/version rows, effective-rate selection, rate-registration audit events, per-call rate/date capture, and migrations `0003_llm_pricing` and `0004_llm_call_pricing_date`. Historical schedule selection and spend-limit behavior still need PostgreSQL runtime acceptance. |
| 2026-10-31 | API-03, ACT-02 | Added local review queue reads and audited analyst decision persistence. | Added paginated review listing with append-only view audit, validated decision payloads, one-way open-to-resolved transition under row lock, immutable decision history, and linked decision audit event. Hosted identity and frontend display remain pending; syntax/import checks pass, and the test suite was not run. |
| 2026-10-31 | FND-03, DB-01, API-03, API-05, LLM-08 | Reconciled API contracts and tightened readiness/audit behavior. | Added bounded source-bulletin evidence/references to review cases, made manual-run responses include `run_id`, `status_url`, and `accepted_at`, and aligned the review decision path. Implemented local role capability gates, persisted API request/denial events, configured actor attribution, `/api/v1/auth/context`, and purpose-required encrypted artifact reads with access audit records. Readiness now requires the current Alembic head when a database is configured and limits fixture-only readiness to non-production. Static checks pass; database and role-matrix acceptance remain pending. |
| 2026-10-31 | API-02, API-03, API-06 | Connected the primary UI pages and analyst decisions to versioned APIs. | Extended alert list/detail responses with summary, SLA, bounded advisory bulletin context, KEV status, and inventory posture. Replaced the frontend `/api/data` fetch with versioned dashboard/alert/review/run/source/readiness/capability calls, added retry/partial states, and connected audited decision submission/history. Python/JavaScript syntax and focused Ruff checks pass; browser and database acceptance remain pending. |
| 2026-10-31 | API-07 | Connected the overview manual-run action to the durable run API. | Frontend sends an idempotency key, presents data/provider/live-call mode, polls run status for up to three minutes, and refreshes the workspace after a terminal result. `node --check frontend/app.js`, `python -m py_compile src/counterstrike/api.py`, `python -m ruff check src/counterstrike/api.py`, and `git diff --check` pass. Test suite was not run; worker/browser acceptance remains open. |
| 2026-10-31 | FND-03 | Repaired the configured-database migration readiness check. | Applied Alembic heads are now read on the open connection after confirming `alembic_version` exists; the previous code referenced a closed connection and left the comparison variable unassigned. `py_compile`, Ruff, and `git diff --check` pass; live PostgreSQL readiness acceptance remains open. |
| 2026-10-31 | WKR-04 | Started the normalized feed adapter layer with the deterministic fixture source. | Added `FeedAdapter`/`FeedBatch` and `FixtureFeedAdapter`, wired existing ingest through the adapter, and exposed source ID/fetch time in the persisted run trace. `py_compile`, Ruff, and `git diff --check` pass; public adapters, source checkpoint writes, and fixture equivalence acceptance remain open. |
| 2026-10-31 | API-07 | Corrected data-mode reporting to match actual worker inputs. | Capability context now reports fixture input separately from database persistence configuration; overview mode text distinguishes both. This avoids implying database-backed source ingestion before that adapter path exists. `node --check frontend/app.js`, Python compilation, Ruff, and `git diff --check` pass; browser acceptance remains open. |
| 2026-10-31 | API-08, DB-05 | Added operator-facing audit event reporting and chain verification. | Added filtered/paginated `/api/v1/audit/events`, `/api/v1/audit/integrity`, `audit_reader` role, and hash-only event fields. Updated the API strategy and decision log (DL-14). Python compilation, Ruff, `git diff --check`, and OpenAPI route registration pass; role-matrix, PostgreSQL, and tamper acceptance remain pending. |
| 2026-10-31 | OPS-01, API-05 | Started local container deployment with an explicit local-only network boundary. | Added Dockerfile, Compose services for PostgreSQL/migrations/API/worker, persistent volumes and health checks; API publishes only on host loopback and trusts only the bounded private bridge CIDR in development. Added setup instructions and decision DL-15. `docker compose --env-file .env.example config --quiet`, Python compilation, Ruff, and `git diff --check` pass; Docker image build and runtime acceptance remain pending. |
| 2026-10-31 | OPS-01, FND-03, FND-04 | Built and started the Compose stack; fixed two runtime defects found by readiness/log inspection. | PostgreSQL and Alembic startup completed and API/worker started. `/health/ready` returned 200 and `/api/v1/dashboard` returned a valid empty-state JSON response. Fixed redaction replacement for secret patterns without capture groups, and project-root resolution when the package is installed in the container. `git diff --check` passes. Container health state, host publication/network boundary, and manual-run route acceptance remain to verify. |

## Next work

1. Review each recovered API endpoint against the approved API strategy and current frontend DTO use; correct any remaining decompiler defects before relying on all API contracts.
2. Validate API-05 role combinations and denial auditing, artifact-access outcomes, and decision actor attribution on PostgreSQL. Keep production access denied until OIDC/SSO is implemented and approved.
3. Validate WKR-01 through WKR-03 on PostgreSQL: idempotent concurrent API requests, competing workers, heartbeat ownership, lease expiry/restart, retry exhaustion, and atomic result/job persistence.
4. Validate LLM-07 with historical/future rate versions and parallel PostgreSQL attempts near run/month ceilings; confirm rate selection, no provider dispatch after denial, and reconcile estimates with final token costs. Keep live calls gated until provider/data-retention decisions are approved.
5. Complete browser/API acceptance for the migrated dashboard, alert detail, review, manual-run, and audit-reporting flows; keep local development identity explicitly labelled until hosted OIDC/SSO is approved.
6. Resolve PLN-02 through PLN-04 or explicitly defer their production-only parts before their dependent phases.
7. Finish Phase 1/2 runtime acceptance: validate migrations, repository persistence/rollback, audit-chain behavior, retention/key-provider controls, and API contracts before marking them complete.
8. Finish OPS-01 runtime acceptance: inspect container health and port publication, exercise manual-run access through loopback, and verify PostgreSQL has no host-published port; retain the running stack for interactive review.
