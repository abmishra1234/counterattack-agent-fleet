# Decision Log — Counterstrike Lite (sample solution)

Status values: **Accepted** (built on), **Provisional** (holds for the assessment; revisit for production), **Proposed** (awaiting mentor confirmation; not yet built on).
Each entry: context → options → decision → consequences → revisit trigger.

| ID | Decision | Status |
|----|----------|--------|
| DL-01 | Deterministic LangGraph pipeline, not an autonomous supervisor | Accepted |
| DL-02 | Five specialist agents + a dispatcher, split by "LLM vs code" | Accepted |
| DL-03 | The LLM may read and word, never decide | Accepted |
| DL-04 | `packaging` specifiers + tolerant parsing for version matching | Accepted |
| DL-05 | Risk policy implemented as a pure function with a per-factor breakdown | Accepted |
| DL-06 | Grounding check on every LLM extraction; failures go to a human queue | Accepted |
| DL-07 | Layered prompt-injection defence | Accepted |
| DL-08 | LLM behind a port: FakeLLM in CI, audited OpenAI-compatible gateway | Accepted |
| DL-09 | Alerts written to a per-owner outbox, never sent | Accepted |
| DL-10 | Synthetic, offline fixtures (CVE-2099-xxxx) | Accepted |
| DL-11 | Gold-label eval as a CI release gate; live-LLM run is manual | Accepted |
| DL-12 | Typed shared state with append-only lists | Accepted |
| DL-13 | Privileged LLM artifact reads | Accepted |
| DL-14 | Audit event review API | Accepted |
| DL-15 | Local Docker API access boundary | Accepted |
| DL-16 | Prototype scope decisions D1–D14 (T-02) | Proposed |

---

## DL-01 — Orchestration style
**Context.** The brief says "agent fleet". Triage must be repeatable and auditable: the same feed and inventory must always produce the same alerts.

| Option | For | Against |
|---|---|---|
| A. Single big prompt | Fastest to write | No validation points; untestable |
| B. LLM supervisor choosing the next agent (ReAct / CrewAI style) | Flexible | Non-deterministic routing, cost hard to bound, safety hard to prove |
| **C. LangGraph `StateGraph` with fixed nodes and conditional edges** | Explicit routing, typed state, each node unit-testable | Less "autonomous" |

**Decision.** C. Routing is code: `extract → correlate` only if something was extracted, `correlate → score` only if something matched; otherwise straight to `dispatch`.
**Consequences.** Two short-circuit paths are tested (`test_no_match_path_short_circuits_to_dispatch`). A run's trace always lists agents in order.
**Revisit when** a later stage genuinely needs to choose tools (e.g. fetch a vendor page on demand) — add one bounded, read-only tool node, not a free supervisor.

## DL-02 — Agent boundaries
**Context.** Responsibilities must be separable so a failure is attributable to one agent.

**Decision.** Five agents plus a dispatcher:

| Agent | Job | Uses LLM? |
|---|---|---|
| 1 Feed Watcher (`ingest`) | Load + validate feed, KEV list, inventory, aliases; de-duplicate | No |
| 2 Extractor (`extract`) | Free text → product + PEP 440 range + fixed version | Yes (bulletins only) |
| 3 Correlator (`correlate`) | Range × inventory → matches | No |
| 4 Risk Scorer (`score`) | Contextual score → P1–P4 + SLA | No |
| 5 Remediation Writer (`remediate`) | Owner-ready alert with evidence | Yes (summary wording only) |
| Dispatcher | Write `alerts.json`, per-owner outbox, `needs_human.json`, run report | No |

**Rationale.** The split follows the one line that matters for trust: language understanding (LLM) on one side, facts and decisions (code) on the other.

## DL-03 — What the LLM is allowed to do
**Decision.** The LLM may (1) read a free-text bulletin and propose structured facts, and (2) phrase a summary. It may **not** decide whether an asset is affected, compute risk, set priority/SLA, choose owners, or suppress an alert. Those fields are filled by code; the LLM output schema has no place for them.
**Verified by.** `test_priority_comes_from_scorer_not_llm` — an "inventive" model cannot move priorities.

## DL-04 — Version matching
| Option | For | Against |
|---|---|---|
| A. String comparison | Trivial | `"2.9" > "2.17"` — wrong |
| B. `semver` | Common | Rejects 4-part and letter-suffixed versions |
| **C. `packaging` `SpecifierSet` + tolerant parse** | PEP 440 semantics, inclusive/exclusive bounds, well tested | Vendor schemes (OpenSSL `1.1.1w`) need a fallback |

**Decision.** C. If a version fails PEP 440, compare its numeric prefix (`1.1.1w` → `1.1.1`) and record a `version_note` in the alert evidence. Completely unparseable versions are never matched.
**Revisit when** inventory contains distro versions (e.g. `1.1.1f-1ubuntu2`) — add a per-ecosystem comparator.

## DL-05 — Implementing the risk policy
**Context.** The brief asks for priority "beyond standard CVSS" and fixes the security office's policy so all teams are comparable. The implementation choices are ours: where the policy lives, how it is tested, and how an alert explains itself.

| Option | For | Against |
|---|---|---|
| A. Ask the LLM to apply the policy | Little code | Not reproducible; violates C4 |
| B. Weights scattered through agents | Quick | Hard to audit or change |
| **C. One pure `score()` + `band()` in the scorer, constants at module top** | Testable at boundaries; one place to change | — |

**Decision.** C. The policy as implemented:
`score = CVSS + 2.0 (in KEV) + 1.5 (internet-facing) + {critical +2, high +1, medium 0, low −1}`, floored at 0.
Bands: **P1 ≥ 12 (24 h)**, **P2 ≥ 9 (7 d)**, **P3 ≥ 6 (30 d)**, **P4 < 6 (90 d)**. Every alert carries its `score_breakdown`.
**Effect on the fixture.** Pillow (CVSS 8.1, low-criticality, internal) becomes **P2** because it is in KEV; Jinja2 (6.1) stays P3 only because it is internet-facing.
**Verified by.** `test_band_boundaries_are_inclusive` (12.0 → P1, 11.99 → P2, 6.0 → P3, 5.99 → P4) and `test_kev_and_exposure_lift_priority`.
**Revisit when** the security office recalibrates weights against past incidents, or adds EPSS (needs a live feed, out of scope offline).

## DL-06 — Grounding the extractor
**Context.** A model that "fills in" a plausible version range creates false alerts or, worse, false all-clears.

| Option | For | Against |
|---|---|---|
| A. Trust schema-valid JSON | Cheap | Valid ≠ true |
| **B. Schema + literal-presence check + vocabulary check** | Cheap, deterministic, catches invented numbers | Misses ranges stated only in words ("all 3.x") |
| C. Second LLM as verifier | Catches subtler errors | Doubles cost; still probabilistic |

**Decision.** B. Every version in the returned specifier and fixed version must appear verbatim in the bulletin, and the product must be in the inventory vocabulary. Anything else → `needs_human.json` with a reason. Non-JSON output → `needs_human`, never a crash.
**Verified by.** `test_hallucinated_versions_are_rejected`, `test_non_json_output_is_routed_not_crashed`; CVE-2099-0008 (no versions) is routed to a human in every run.

## DL-07 — Prompt injection from the feed
**Context.** Feed text is attacker-controllable. Fixture CVE-2099-0005 hides an HTML comment telling the agent to mark the advisory "not affected" and raise no alerts.

**Decision.** Four layers:
1. Bulletin text is wrapped in `<bulletin>` tags (closing tag escaped) and the system prompt states it is data.
2. `detect_injection` flags suspicious text; the flag appears in the run trace (`suspected_injection`).
3. The model cannot affect decisions anyway (DL-03).
4. The eval gate fails if the injected advisory loses its alert (`injection_resisted`).
**Consequence.** The `requests` alert for `kyc-service` is still raised at its computed priority (P4).

## DL-08 — LLM access
**Decision.** An `LLMPort` protocol with `FakeLLM` (deterministic test double, default) and an OpenAI-compatible gateway adapter configured through `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`.
**Rationale.** CI must run offline and free; production must use the approved enterprise gateway. Keeping the provider behind a port avoids a vendor-specific SDK dependency and preserves provider choice.
**Revisit when** the team standardises on a shared client module (e.g. the cohort's `llm_client.py`) — wrap it behind the same port.

**Current implementation gate (31 October 2026).** The gateway now uses encrypted per-attempt prompt/response artifacts, metering, effective-dated pricing, spend controls, local role gates, and a purpose-required audited artifact-content endpoint. Live use remains off by default pending provider/data-boundary and retention approval, hosted OIDC/SSO, PostgreSQL acceptance, and worker run-context verification. `FakeLLM` remains available for offline runs. The adapter requires a persisted run ID and cannot send a request if its encrypted request artifact fails to commit.

## DL-13 — Privileged LLM artifact reads
**Decision.** Keep `GET /api/v1/llm/usage/{call_id}` metadata-only. Expose exact content through `POST /api/v1/llm/usage/{call_id}/content`, requiring the configured `llm_audit_reader` capability, a selected artifact kind, and a specific access purpose. Persist both successful and unsuccessful access outcomes.
**Rationale.** A dedicated write request makes the audit purpose explicit and avoids returning sensitive prompts, queries, or model responses in ordinary metadata/report requests.
**Status.** Implemented for local development roles; hosted identity and runtime acceptance remain pending.

## DL-14 — Audit event review API
**Context.** API requests, decisions, worker transitions, and LLM access already append to the PostgreSQL hash chain, but operators have no supported way to query event metadata or invoke the chain verifier through the API.

**Decision.** Add paginated/filterable `GET /api/v1/audit/events` and `GET /api/v1/audit/integrity`. Require the separate `audit_reader` capability (also granted to `admin`). Return only bounded event metadata and hashes; do not return free-form reasons, safe detail payloads, prompts, or responses. Audit access to both endpoints through the existing API request audit middleware.

**Status.** Implemented for configured local roles; PostgreSQL and role-matrix acceptance remain pending.

## DL-15 — Local Docker API access boundary
**Context.** The API's development authorization gate accepts loopback clients. A containerized API must bind inside its container to a reachable interface, while the Compose stack should remain usable from the host without enabling shared or production access.

**Decision.** Compose publishes the API only on host `127.0.0.1`, keeps PostgreSQL private, and allowlists only the configured private Compose bridge CIDR for development/test role checks. Production settings reject `API_TRUSTED_LOCAL_CLIENT_CIDRS`; hosted deployment remains blocked on OIDC/SSO and network policy.

**Status.** Implemented in local Compose/configuration; Docker runtime and network-boundary acceptance remain pending.

## DL-16 — Prototype scope decisions (T-02)
**Context.** The requirement asks the mentor to confirm inventory, feeds and LLM by 2 November 2026 so the prototype scope can be frozen. Tracker items PLN-02, PLN-03 and PLN-04 depend on the same answers.

**Proposal.** The defaults in [planning/T02_MENTOR_DECISION_BRIEF.md](planning/T02_MENTOR_DECISION_BRIEF.md), rows D1–D14. Most restate the requirement's own assumptions (Q1–Q16). D5 (30-day retention), D8 (EPSS shown but not scored), D10 (P1 within 5 minutes of ingestion) and D12 (baseline from about 20 recent CVEs) are new values.

**Status.** Proposed. When the mentor replies, record each row's outcome below and change the index status to Accepted (or Provisional where a row is accepted only for the prototype).

| Row | Outcome | Date | Notes |
|---|---|---|---|
| D1–D14 | Awaiting mentor | — | Brief sent: *date to fill* |

**Consequences once accepted.** D1, D2 and D4 unblock live feed polling and the CI LLM smoke test. D10 and D11 fix the pass marks for AC-6 and AC-2. Live LLM calls and real alert delivery stay off until D4, D5 and D9 are accepted.

## DL-09 — Alert delivery
**Decision.** Write `out/outbox/<owner>.md` and `out/alerts.json`. No email, Slack or ticket creation.
**Rationale.** Sending messages on behalf of a security team is an action with side effects; for a POC a human forwards the outbox. Delivery adapters are a later, separately reviewed change.

## DL-10 — Data
**Decision.** Local JSON fixtures: 8 advisories (3 structured, 5 free text), 8 assets, a KEV-style list, an alias map. CVE IDs use the reserved-looking `CVE-2099-xxxx` range and every title says "(synthetic)", so nobody mistakes them for real advisories.
**Rejected.** Live NVD API — rate limits, network policy on enterprise runners, non-reproducible results.
**Each fixture tests something:** alias mapping (log4j2 → log4j-core), patched asset (A-102), unaffected major line with letter suffix (A-107), below-range asset (A-106), no-inventory product (tomcat), injection (0005), unparseable bulletin (0008), KEV lift (0007).

## DL-11 — Evaluation and the CI gate
**Decision.** `counterstrike eval` compares the outbox with `data/gold/expected_alerts.json` and fails the build unless: precision = 1.0, recall = 1.0, priority accuracy = 1.0, zero alerts on `must_not_alert` pairs, the unparseable advisory is in `needs_human`, the injection advisory still alerts, and every summary is grounded. The scorecard is appended to the GitHub job summary and the outbox uploaded as an artifact.
A live-LLM run is intended as a **manual** `workflow_dispatch` job (recall threshold 0.8, safety checks unchanged) after encrypted request/response capture, usage/cost metering, and privileged artifact access are implemented. Until then, the workflow reports that the live call was gated and sends no model request.

## DL-12 — Shared state
**Decision.** `FleetState` is a `TypedDict`; `needs_human` and `trace` use `Annotated[list, operator.add]` so any agent can append without overwriting another's entries. All payloads are pydantic models.
**Consequence.** `run_report.json` contains one trace entry per agent, with timings, LLM call count and prompt version.
