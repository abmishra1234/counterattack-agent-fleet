# Counterstrike Requirement Gap Plan

## Purpose and recommendation

This plan translates the updated Counterstrike requirement into implementation work by comparing it with the current repository. The current code is a useful deterministic prototype: it validates local JSON, extracts advisory facts, correlates versions, scores matches, drafts alerts and writes local files. It does not yet operate as the scheduled, multi-source, owner-notifying service described in the updated requirement. The work below closes those gaps in priority order while preserving the prototype's strongest properties: code-owned decisions, human review for uncertainty, offline tests and read-only recommendations.

The target date in the requirement is **16 November 2026**. Scope should be confirmed with the mentor by **2 November**, especially feed access, inventory shape and the approved LLM. Build the Must requirements first; treat the dashboard and advanced integrations as Should or Could work after the end-to-end path is reliable.

## Scope and planning assumptions

- The requirement document is the source of scope: FR-1 through FR-9 are Must, FR-10 is Should, and vendor scraping, ticket integration, feedback learning and additional threat-intelligence feeds are Could/stretch.
- Prototype integrations use public/free sources and a synthetic or masked inventory. No enterprise CMDB access is assumed.
- Polling every 15 minutes is the working interpretation of near real time.
- The fleet may notify owners and security staff through the approved Teams/email path, but it must not patch systems, change configuration or open tickets in the Must scope.
- Azure OpenAI is the assumed approved LLM. Only minimal advisory facts and approved context should be sent to it; inventory details stay local unless explicitly approved.
- Existing P1-P4 thresholds are provisional. The requirement says a KEV item on an internet-facing asset should be P1; the policy owner must reconcile this with the current additive score before implementation is finalized.
- No measured current-process baseline is present in the repository. The proposal should report prototype measurements and label any current-state comparison as an estimate until stakeholders provide operational data.

## Current implementation baseline

| Area | Current state | Relevant code |
|---|---|---|
| Orchestration | Fixed LangGraph flow: ingest, extract, correlate, score, remediate, dispatch; no retry or node-level failure isolation | `src/counterstrike/graph.py` |
| Ingestion | Reads one local JSON directory; de-duplicates advisory IDs; no scheduler, source adapters, checkpoints or feed-specific logs | `src/counterstrike/agents/ingest.py` |
| Advisory model | CVSS, title, dates, optional structured data and text; no vendor/reference/provenance schema or EPSS value | `src/counterstrike/models.py` |
| Enrichment | KEV membership is loaded from a local list; no NVD/OSV/GitHub clients and no EPSS lookup | `src/counterstrike/agents/extract.py` |
| Inventory | Versioned `1.0` local contract now captures vendor, product, type (including SaaS/vendor product), classification, aliases, ownership, criticality, exposure, version and service. The sample remains eight assets; no organizational import path or lifecycle update exists yet. | `data/inventory.json`, `src/counterstrike/models.py`, `src/counterstrike/inventory.py` |
| Correlation | Exact normalized component plus version range; outputs matches or no match, without confidence or a possible-match state | `src/counterstrike/agents/correlate.py` |
| Risk | Deterministic CVSS + KEV + internet exposure + criticality; the FR-6 KEV + internet-facing P1 override is now versioned and persisted. EPSS is not yet a score factor; other weights and SLA bands remain provisional. Impact summary is now a separate LLM-generated dimension and does not affect scoring. | `src/counterstrike/agents/score.py`, `src/counterstrike/risk_policy.py` |
| Advice | Fixed-version upgrade text or generic workaround; summary can be LLM-written; citations/references are absent | `src/counterstrike/agents/remediate.py` |
| Human review | Unclear extraction and invalid model output can be queued; ambiguous correlation confidence is not modeled | `src/counterstrike/models.py`, `src/counterstrike/agents/extract.py` |
| Delivery | Writes JSON, owner-grouped Markdown and a run report; nothing is sent to Teams/email and there is no daily digest | `src/counterstrike/dispatch.py` |
| Audit/evaluation | Agent trace and gold-label precision/recall/priority checks exist; no per-source ingestion history, retry audit or operational latency measurements | `src/counterstrike/dispatch.py`, `src/counterstrike/evaluate.py` |
| Deployment | GitHub Actions lint, tests, local evaluation gate and optional live-LLM smoke exist; no Docker/Compose or deployed dashboard | `.github/workflows/ci.yml`, `pyproject.toml` |

## Gap register and planned response

| ID | Requirement and gap | Planned work | Priority / completion evidence |
|---|---|---|---|
| G-01 | **FR-1 / AC-1:** At least three public feeds polled on a schedule and deduplicated. Current ingestion is local-file only. | Add a common feed-adapter contract and adapters for NVD, CISA KEV and OSV (or GitHub Advisories if access/coverage requires it). Add a 15-minute scheduler/worker entry point, bounded timeouts, rate-limit-aware retries, per-source checkpoints, normalized IDs and idempotent upserts. Preserve local JSON as the fixture adapter. Record fetch time, source, result and failure per poll. | Must. Demonstrate all three adapters with recorded/mock responses; one-cycle arrival target; repeated poll creates no duplicate advisory or alert; one unavailable feed does not block the other two. |
| G-02 | **FR-2:** CVSS, EPSS, KEV, affected ranges and references. The source layer has bounded NVD references and opt-in FIRST EPSS enrichment. EPSS scoring is now implemented behind a separate approval gate requiring source approval, an explicit weight, and a maximum-age window; absent, stale, invalid, or not-scored values contribute zero and report a reason. It remains disabled by default, and operational evaluation is pending. | Obtain the approved EPSS weight and freshness window; evaluate fresh/missing/stale/not-scored observations and record source provenance. Keep source polling disabled until PLN-04 approval. | Must. Fixtures/evaluation cover each enrichment state; alert score breakdown records contribution, configured weight and status, while alert evidence preserves source URL/retrieval time. |
| G-03 | **FR-3:** Inventory contract and local run path now support version 1.0 with application/service/vendor-product/SaaS asset types, vendor, product/component, version, owner/contact, criticality, exposure, data classification and aliases. Unknown fields are rejected; legacy array input is temporarily normalized as version 1.0. Metadata is persisted in run snapshots and shown in alert context. A protected paginated inventory read API and workspace page expose the latest persisted snapshot. Owner contact stays out of LLM prompts. No organization import path or asset lifecycle update exists, and the sample has eight assets. | Confirm the approved import source/fields, expand representative sample toward ~50 assets, and add reviewed import/change lifecycle with actor/audit provenance if that operation is in approved scope. Keep inventory local to matching/alert context and prevent unnecessary LLM transmission. | Must. Valid/invalid import acceptance covers duplicate IDs, unsupported versions, conflicting aliases, missing fields and supported product types. Demonstrate representative software, services and vendor/SaaS products; runtime persistence and browser acceptance remain open. |
| G-04 | **FR-4 / AC-2 / AC-3 / AC-7:** Affected, possibly affected or not affected, with confidence. Current correlator gives a binary result and exact component match. | Add explicit correlation outcomes, confidence and explanation. Start with deterministic alias/vendor/product matching and ecosystem-aware version comparators. Use “possibly affected” for incomplete or ambiguous version/product evidence and route below-threshold cases to analyst review. Never convert “unknown” to “not affected.” | Must. Labeled evaluation reports precision ≥90% and recall ≥95% (confirm sample size/targets); tests prove patched/out-of-range versions are not alerted and low confidence goes to review. |
| G-05 | **FR-5:** Business, operational and security impact summary. Implemented `impact_summary_v1`: an audited LLM step now asks for three labeled dimensions using CVSS, KEV, affected component/version, service, business criticality and exposure. Output must contain those facts and consistent KEV/exposure wording; otherwise a deterministic summary is used. The summary remains separate from match, score, priority, SLA, owner and remediation. The detail UI shows it as an Impact assessment. This is fact-presence checking, not semantic/source citation proof. | Add labeled-set/adversarial evaluation for all three dimensions and contradictions; decide the minimum cited evidence needed per claim and connect summary claims to source records where applicable. Continue minimizing inventory context. | Must. Evaluation covers required dimensions, source-grounded claims and non-empty rationale; adversarial output cannot alter computed decisions. Runtime/provider and browser acceptance remain open. |
| G-06 | **FR-6 / AC-4:** Explainable risk, P1-P4 and SLA using severity, exploitability, exposure and criticality. Version `req-fr6-kev-internet-p1-v1` forces P1 for KEV-listed, internet-facing assets. EPSS contribution is available only when `EPSS_SCORING_APPROVED=true` and requires explicit weight and max age; these settings are also included in a derived policy version. Alert/run records carry the active version, and API/UI expose the factor breakdown and EPSS application status. Existing weights and SLA bands remain provisional; no EPSS score is active by default. | Obtain approval for EPSS source use, weight, freshness, remaining factor weights, thresholds, and SLAs; evaluate boundaries and observed/stale/missing behavior. | Must. Boundary/evaluation evidence per factor and band; KEV + internet-facing → P1; security/mentor approval before remaining thresholds are authoritative. Code is gated but complete approval/acceptance remains open. |
| G-07 | **FR-7 / AC-5:** Alert detail carries sanitized NVD reference URLs. It now identifies references tagged Patch, Vendor Advisory, Release Notes, or Mitigation as remediation support and exposes them separately as `remediation_sources`; citation status is based on these tagged references rather than any arbitrary URL. When no fixed version is recorded, advice explicitly says so and limits mitigation to analyst-approved guidance. | Preserve source tags and retrieval provenance, and validate tag-to-claim relevance against labeled source examples. A tag is only a relevance signal, not proof that the linked page confirms the exact fixed version or workaround. | Must. Every recommendation has a tagged supporting source or an explicit unverified warning; evaluation covers missing/invalid refs, unsupported versions and mitigation claims. Provider/feed, database and browser acceptance remain open. |
| G-08 | **FR-8 / AC-6:** Route owner alerts through Teams/email; daily digest; tickets optional. Current dispatcher only writes local files. | Retain a durable outbox as the delivery boundary. Add Teams and email adapters behind configuration, P1/P2 owner plus security routing, deduplication/idempotency keys, delivery status and retry/dead-letter handling. Add a scheduled daily digest. Keep ticket creation out of Must scope. | Must. Mock delivery tests verify recipient, payload, no duplicate sends on retry, failure visibility and P1 timing from ingestion; demo real channel only with approved credentials/endpoint. |
| G-09 | **FR-9 / AC-8 / AC-9:** Retries, human review, audit log, read-only behavior and resilience to feed/agent failure. Current graph has no retry boundaries; trace contains only aggregate per-agent entries. | Add bounded retries around external feed/LLM/channel calls, timeout and backoff policy, failure isolation, and an analyst queue for unclear data/correlation. Expand append-only audit events with run/advisory/source IDs, decisions, evidence, policy/prompt versions, retry/failure status and timestamps. Use least-privilege credentials and prohibit write access to target systems. | Must. Fault-injection tests show one feed/agent failure does not stop independent work; each advisory can be reconstructed from audit records; no code path performs remediation changes. |
| G-10 | **FR-10:** Exposure dashboard and containerized deployment with CI. GitHub Actions CI exists, but Docker and dashboard do not. | Add Dockerfile and Compose for API/worker/storage/dashboard with health checks and environment-based secrets. Build a small read-only exposure dashboard for alert count, priority, affected services, aging and review status. Extend CI to build container, run unit/contract tests, integration tests and gold evaluation. | Should. `docker compose up` yields a working local demo; CI builds and evaluates the image; dashboard totals match stored alerts. |
| G-11 | **AC-10:** Proposal compares as-is/to-be and measures awareness-time improvement. No baseline or proposal artifact exists in the repository. | Record current workflow assumptions and gather stakeholder timings. Capture prototype discovery-to-alert latency, polling delay, precision/recall, review queue rate and delivery success. Write rollout stages, assumptions, risks and a measured-versus-estimated comparison. | Must deliverable. Proposal identifies data source and sample size for every metric; no unsupported productivity claim. |

## Delivery sequence

The dates below are a proposed sequence to meet the requirement's 16 November 2026 target, not a commitment on behalf of the team.

| Phase | Window | Work and exit gate |
|---|---|---|
| 0. Confirm decisions | 31 Oct–2 Nov | Confirm inventory fields/sample, NVD/KEV/OSV access, polling target, Azure OpenAI approval/data boundary, KEV+internet P1 rule, alert recipients and evaluation set. Freeze Must scope and owners. |
| 1. Data contracts and adapters | 3–5 Nov | Version advisory, inventory and source-reference schemas; implement three feed adapters plus fixture adapter, scheduled polling, deduplication/checkpoints and isolated failure handling. Exit: repeatable mocked three-feed cycle. |
| 2. Correlation and risk | 6–8 Nov | Expand inventory, add vendor/product aliases and confidence outcomes, implement EPSS enrichment and approved risk policy. Exit: labelled-set report meets targets or exposes specific remaining misses; uncertain results enter human review. |
| 3. Advice, audit and delivery | 9–11 Nov | Add citation-backed remediation, impact rationale, richer audit events, retries and Teams/email outbox delivery plus digest. Exit: failure/retry and no-duplicate delivery scenarios pass with mocked channels. |
| 4. Container, dashboard and proposal | 12–14 Nov | Add Docker Compose, read-only dashboard and CI image/evaluation checks; gather baseline/demo metrics and draft as-is/to-be proposal. Exit: clean local Compose demo and proposal draft. |
| 5. Hardening and demo | 15–16 Nov | Run full integration/evaluation, review secrets/data boundaries and failure cases, fix blockers, prepare demo and final proposal. Exit: Must acceptance checklist signed off; Should gaps disclosed. |

## Work split for two participants

Use the split suggested in the requirement and agree shared interfaces before parallel implementation.

- **Participant A — feeds, risk and alerts:** G-01, G-02 feed enrichment coordination, G-06, G-08 and shared audit event contract. Own source adapters, polling/checkpoints, scoring policy and Teams/email/digest adapters.
- **Participant B — inventory, correlation and advice:** G-03, G-04, G-05, G-07 and G-10 dashboard. Own inventory contract/import, confidence-aware matching, human review data, sourced advice and dashboard.
- **Joint ownership:** G-09 fault handling/audit, G-11 proposal/metrics, Docker/Compose integration, schemas and end-to-end acceptance. Merge through agreed interfaces and review security/data handling together.

## Acceptance and verification plan

Map verification directly to the requirement's acceptance criteria:

1. **AC-1:** Three source adapters ingest within one scheduled cycle, record poll results and deduplicate across repeated polls.
2. **AC-2:** A versioned labeled set produces the agreed precision and recall targets; report false positives and false negatives, not only aggregate percentages.
3. **AC-3:** Fixed versions and unused products create no alert; ambiguous or incomplete evidence becomes “possibly affected”/human review.
4. **AC-4:** Every affected asset has a factor breakdown and policy version; KEV plus internet exposure follows the approved P1 rule.
5. **AC-5:** Every recommendation has traceable source links or is withheld and flagged.
6. **AC-6:** Timed P1 demo measures from feed ingestion timestamp to successful owner-channel delivery against the agreed threshold.
7. **AC-7:** Below-threshold correlation confidence is routed to analysts, never silently discarded or alerted as confirmed.
8. **AC-8:** Audit inspection reconstructs source data, match decision, score, recommendation and delivery; access and code remain read-only toward managed assets.
9. **AC-9:** Injected source, model and channel failures are isolated, retried within configured limits and visible in the run status.
10. **AC-10:** Proposal includes as-is/to-be process, measured prototype metrics, assumptions, rollout and improvement estimate with provenance.

Recommended test layers: unit tests for adapters/parsers/policy/matching, contract tests for normalized records and alert payloads, mocked integration tests for retries and delivery, fault-injection tests for independence, labeled evaluation for AC-2, and a timed end-to-end demo for AC-6. Keep offline fixtures and fake LLM runs deterministic in CI; make live credentials/channel smoke tests an explicit manual workflow.

## Decisions and dependencies to resolve by 2 November

1. Which exact three sources are approved and accessible? Proposed baseline: NVD, CISA KEV and OSV; EPSS is an enrichment service and should be separately confirmed.
2. What is the official inventory schema, including SaaS/vendor products, ownership contacts, criticality, exposure and data classification?
3. What confidence threshold separates confirmed from possible matches, and what labeled dataset defines AC-2?
4. Does KEV + internet exposure force P1 regardless of CVSS and criticality, or should it be a score contribution?
5. What are the approved SLA hours and latency target for P1 delivery? The present code's SLA values are prototype defaults.
6. Are Teams webhook and email endpoints available for the demo, and who may receive P1/P2 alerts? How should retries avoid duplicate notifications?
7. What Azure OpenAI deployment is approved, and may advisory text be sent? Confirm that inventory records stay local or identify the minimal allowed fields.
8. What data is available for current-process awareness-time baseline, and who validates the proposal's comparison?

## Risks and scope controls

- **External API variability:** schemas, rate limits and outages can affect polling. Use adapters, fixture replay, timeouts, bounded retries and source-level health reporting.
- **False confidence from incomplete data:** unknown products or versions must not become “not affected.” Preserve uncertainty and analyst review.
- **Citation quality:** do not let an LLM invent references or fixed versions. References and patch claims must originate in source data and be retained with provenance.
- **Sensitive inventory data:** minimize fields sent to an LLM, keep inventory local by default, avoid logging secrets and use synthetic data for CI/demo artifacts.
- **Schedule pressure:** dashboard polish and ticket integration must not delay the Must path. Ticket integration, vendor scraping and feedback learning remain outside the target unless explicitly re-scoped.
- **Unvalidated process baseline:** show measurements from the prototype separately from estimates of the current process.

## Definition of ready for the final demonstration

- The three-source polling path runs on schedule, records checkpoints and survives a single feed failure.
- Inventory records cover the agreed asset/vendor scope and are validated before matching.
- Confirmed, possible and not-affected outcomes are distinct; confidence and evidence are inspectable.
- EPSS/KEV/CVSS and asset factors feed an approved, versioned P1-P4 policy with tested boundaries.
- Recommendations cite source records; low-confidence or unsupported advice reaches a human.
- P1/P2 alerts route to the approved owner/security channels, and daily digest behavior is demonstrated or transparently stubbed if credentials are unavailable.
- Audit events show the end-to-end decision path; the implementation makes no changes to managed assets.
- Docker Compose and CI support repeatable setup, offline tests and evaluation.
- AC-1 through AC-10 have evidence or an explicitly documented dependency/exception; the proposal distinguishes measured values from assumptions.
