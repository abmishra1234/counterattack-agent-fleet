# Counterstrike Gap Remediation Tasks

**Status:** Accepted on 1 November 2026
**Baseline:** commit `58bb260` on `main`. All 112 tests pass locally, coverage is 82.27% and ruff is clean. CI status on this commit has not been verified.
**Sources compared:** `requirement/Counterstrike_Agents_Fleet_Requirements.docx`, [UPDATED_REQUIREMENT_GAP_PLAN.md](UPDATED_REQUIREMENT_GAP_PLAN.md), [BACKEND_IMPLEMENTATION_TRACKER.md](BACKEND_IMPLEMENTATION_TRACKER.md) and the code under `src/`.

This document records the gaps between the requirement, the plan and the code, and the tasks agreed to close them before the 16 November 2026 target. Update the status column in the same change that completes a task.

## Key gaps

| # | Requirement | What the plan says | What the code does | Severity |
|---|---|---|---|---|
| 1 | FR-1 / AC-1: at least 3 feeds, deduplicated | G-01: NVD, KEV and OSV adapters | Only NVD produces advisories. KEV is a list of IDs, OSV is only looked up for CVEs already on the KEV list, and EPSS is enrichment only. There are no GitHub advisories. Deduplication keeps the first copy and doesn't merge data from other sources (`agents/ingest.py`). Public feeds and the scheduler are off by default. | High |
| 2 | FR-2 / FR-4: affected products and version ranges | G-02 / G-04 | The NVD adapter discards CPE configurations, so `structured=None` (`sources.py`). OSV version ranges are not used. Real CVEs all go to LLM extraction, and with the default FakeLLM they end up in human review. Correlation only works on the fixture advisories. | Critical |
| 3 | FR-4: match by product and version | G-04: ecosystem-aware comparators | Only PEP 440 comparison exists (`versions.py`). OpenSSL, Maven, semver and deb versions are parsed loosely and become `possible_match`. The asset `vendor` field is not used in matching. | High |
| 4 | AC-2: precision ≥ 90%, recall ≥ 95% | Labelled-set report | The gold set has 8 advisories, 5 alerts and 3 must-not-alert cases, too small to support the targets. The trainer-only hidden set is not in the checkout. | High |
| 5 | FR-7 / AC-5: advice cites a source; uncited advice is flagged | G-07 | Citations are computed only in the API alert detail (`api.py`). `alerts.json`, the outbox Markdown and delivered messages have no links and no uncited flag. The eval gate doesn't check citations. | High |
| 6 | AC-6: a P1 alert reaches the owner within the agreed time | G-08 | Delivery adapters exist but are disabled. Ingestion-to-delivery latency is not recorded anywhere, and the agreed time is not defined. | High |
| 7 | FR-9 / AC-9: retries; one failure doesn't stop the fleet | G-09 | The LangGraph graph has no retry policy. An exception in any agent fails the whole run, and `public_feeds_unavailable` raises. Fault injection (OPS-04) has not started. | Medium-high |
| 8 | AC-10: process improvement proposal | G-11 | No proposal exists. It is the project's main expected outcome. | Critical |
| 9 | FR-6: EPSS in the risk score | G-06: code complete | No test calls `epss_adjustment` or uses the scoring approval flag. `risk_policy.py` coverage is 54%. | Medium |
| 10 | FR-10: CI | OPS-03 | CI doesn't build the Docker image or run PostgreSQL integration tests. `db_roles.py` and `server.py` have 0% coverage. | Medium |
| 11 | Plan health | Decisions due 2 November | Decision items PLN-02, PLN-03 and PLN-04 have not started. The tracker shows 11 of 52 items done with 15 days left. Much of the effort has gone to production hardening the requirement doesn't ask for (encrypted LLM artifacts, pricing and budgets, key rotation, hash-chained audit), while the Must acceptance criteria have no evidence. | High (schedule) |
| 12 | Documentation and repo hygiene | — | The gap plan's baseline table contradicts its own gap rows. The README still describes "Counterstrike Lite — sample solution". Temporary scripts are committed at the repo root. | Low |

## Tasks

### P0: Must acceptance criteria and demo

| ID | Task | Closes gap | Done when | Status |
|---|---|---|---|---|
| T-01 | Confirm CI passes on HEAD for Python 3.10 and 3.12. | — | A passing CI run is linked here. | **Done** (1 Nov 2026). The user confirmed CI passed after the T-03 changes were pushed. Add the run link here. |
| T-02 | Close the 2 November decisions: sources, inventory, LLM, P1 delivery target, SLAs, EPSS weight, alert recipients and AC-2 targets. Where the mentor is silent, adopt the defaults stated in the requirement doc. | 11 | Each decision is recorded in `DECISION_LOG.md`. | In progress. Brief for the mentor at `planning/T02_MENTOR_DECISION_BRIEF.md`; proposed defaults recorded as DL-16. Waiting for mentor answers. |
| T-03 | Map NVD CPE configurations to affected products (vendor, product, version start/end, inclusive or exclusive). Use OSV `affected[].ranges` for every CVE in the polling window, not only KEV ones. | 2 | Recorded NVD and OSV fixtures produce structured products without calling the LLM. | **Done** (1 Nov 2026). NVD CPE matches and OSV ECOSYSTEM/SEMVER events map to `structured.products`; disjoint ranges are a `\|\|` union and the fix comes from the matched range. OSV lookups now cover CVEs without NVD ranges (KEV first, 100 per poll, overflow reported as `lookups_deferred`). Tests in `test_sources.py`, `test_extract.py`, `test_correlate_score.py`, `test_versions.py`. Non-PEP 440 versions still go to review until T-05. |
| T-04 | Make OSV (or GitHub Advisories) a separate advisory source. Merge records from different sources by CVE ID, keeping per-source provenance. | 1 | An AC-1 test passes: 3 recorded sources with overlapping IDs, one poll cycle, no duplicates, and the remaining sources still ingest when one is down. | Not started |
| T-05 | Add version comparison for semver, Maven, OpenSSL letter suffixes and basic deb versions. Use the vendor field in matching. Anything unknown stays a possible match. | 3 | Tests cover each comparator; patched or out-of-range versions never produce an alert. | Not started |
| T-06 | Expand the labelled set to about 40 or more advisory–asset pairs, covering negatives, ambiguous cases and SaaS/vendor products. Report false positives and false negatives. | 4 | An evaluation report against the 90% precision and 95% recall targets. | Not started |
| T-07 | Attach remediation sources and a citation status in the remediate step, and carry them into `alerts.json`, the outbox and delivered messages. Add a citation check to the eval gate and add references to the fixtures. | 5 | The gate fails if any alert is uncited and not flagged. | Not started |
| T-08 | Add LangGraph retry policies, isolate failures per advisory in extract and remediate, and add fault-injection tests for feed, LLM and channel failures. | 7 | AC-9 tests pass. | Not started |
| T-09 | Record ingestion and delivery timestamps, report latency in the run report and metrics, and add an end-to-end P1 test with a mocked channel plus a timed demo script. | 6 | AC-6 evidence with a measured latency. | Not started |
| T-10 | Write the process improvement proposal: as-is vs to-be, measured prototype metrics, a clear split between measured values and estimates, and a rollout plan. | 8 | The AC-10 document exists. | In progress. Draft at `docs/PROCESS_IMPROVEMENT_PROPOSAL.md` with fixture measurements. Still needs the as-is baseline from stakeholders and the metrics from T-06 and T-09. |
| T-11 | Build an evidence matrix linking AC-1 to AC-10 to the test, report or demo step that proves each. | All | Every criterion has evidence or an approved exception. | Not started |

### P1: Quality and accuracy

| ID | Task | Closes gap | Done when | Status |
|---|---|---|---|---|
| T-12 | Test every EPSS state (not configured, no observation, not scored, invalid, stale, future-dated, applied), the policy version string, and unknown-KEV review routing. | 9 | `risk_policy.py` coverage is at least 90%. | Not started |
| T-13 | Extend CI to build the Docker image, run integration tests against a PostgreSQL service (migrations, repositories, DB roles), and run the eval inside the image. | 10 | The new CI jobs pass. | Not started |
| T-14 | Refresh the gap plan's baseline table, the README and the tracker counts and statuses. | 12 | The docs match the code. | Not started |
| T-15 | Remove the temporary root-level scripts or move them under `scripts/`, and add ignore rules. | 12 | The repo root is clean. | Not started |

### P2: Scope control

| ID | Task | Closes gap | Done when | Status |
|---|---|---|---|---|
| T-16 | Mark production-hardening work (LLM artifact retention, pricing and budgets, KMS and key rotation, hosted OIDC) as Deferred in the tracker until T-03 to T-11 are done. | 11 | The tracker is re-baselined. | Not started |

## Sequence

1. T-01 and T-02 by 2 November.
2. T-03, T-04, T-05 and T-06 together, since they share the source and correlation data.
3. T-07, T-08 and T-09.
4. T-10 and T-11, using the metrics from T-06 and T-09.
5. P1 and P2 tasks as capacity allows. T-16 can be done at any time.
