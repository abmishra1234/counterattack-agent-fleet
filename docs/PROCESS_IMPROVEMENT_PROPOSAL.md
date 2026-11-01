# Process Improvement Proposal: Vulnerability Awareness with the Counterstrike Agents Fleet

**Status:** Draft v0.1, 1 November 2026. The current-process (as-is) figures are not yet collected; they are marked *to collect* and must not be read as results.
**Team:** Team-AI Foundation, Project Counterstrike
**Requirement covered:** AC-10. The proposal shows the as-is and to-be process, with a measurable improvement in time to awareness.

## 1. Summary

New vulnerabilities are disclosed continuously across open-source components, vendor products and SaaS services. Finding out which of them affect our estate, how urgently, and who must act is today a manual task. This proposal replaces the manual discovery and triage steps with a fleet of focused agents. The fleet polls public feeds, matches advisories to the technology inventory, scores risk with an explainable policy, and routes owner-ready alerts. People stay in charge of uncertain cases and of every change to systems.

The improvement we will measure is **time to awareness**: the time from public disclosure of a vulnerability to the moment the accountable owner receives an actionable alert. Secondary measures are analyst effort per advisory, alert precision and recall, and the share of findings that need human review.

## 2. As-is process (assumed; to be confirmed with the security team)

| Step | How it is assumed to work today | Who |
|---|---|---|
| 1. Discover | Analysts read vendor bulletins, NVD, CISA KEV and mailing lists when time allows. | Security analyst |
| 2. Identify relevance | Analysts search the CMDB or ask application teams whether the product and version are in use. | Analyst and app teams |
| 3. Assess and prioritise | Severity is judged mainly from CVSS; exposure and business criticality are looked up by hand. | Analyst |
| 4. Recommend | Analysts read the advisory for fixed versions and workarounds. | Analyst |
| 5. Notify | An email or ticket is sent to the owning team. | Analyst |

**Pain points we expect to confirm:** discovery depends on analyst availability; relevance checks need several people; prioritisation is inconsistent between analysts; there is no single record of what was assessed and why.

### Baseline to collect before the final review

| Metric | Value | How it will be measured |
|---|---|---|
| Time to awareness (median and 90th percentile) | *to collect* | Sample of 20 recent high-severity CVEs that affected the estate: public disclosure date vs the first internal ticket or email to the owning team. |
| Analyst effort per advisory | *to collect* | Analyst estimate for the same sample, or time-tracking data if available. |
| Advisories reviewed per week | *to collect* | Ticket or tracker counts. |
| Missed or late findings | *to collect* | Post-incident or audit records, if available. |

If no data can be provided, the as-is column will stay labelled as an estimate from stakeholder interviews, with the source named.

## 3. To-be process

| Step | How it works with the fleet | Human role |
|---|---|---|
| 1. Discover | A scheduled worker polls NVD, CISA KEV and OSV every 15 minutes, with EPSS as enrichment. Each poll is checkpointed and deduplicated by CVE ID. | None |
| 2. Identify relevance | Product and version ranges come from NVD CPE data and OSV package ranges and are matched in code against the inventory. Unclear matches are marked *possible* and go to an analyst. | Analyst reviews only uncertain matches |
| 3. Assess and prioritise | A versioned, explainable score combines CVSS, KEV, EPSS (once approved), internet exposure and business criticality into P1–P4 with an SLA. KEV on an internet-facing asset is always P1. | Policy owner approves the weights |
| 4. Recommend | The fixed version comes from the source record, not from the LLM. The LLM writes only a short impact summary, which is checked against the facts. | Analyst approves mitigations when no fix is recorded |
| 5. Notify | Alerts are routed by owner, with P1/P2 also sent to security, by email or Teams, plus a daily digest. Delivery is durable and idempotent. | Owner acts; nothing is patched automatically |

Every step writes an audit event, so each alert can be traced back to its source records, match decision, score and delivery.

## 4. Prototype measurements so far

All values below were measured on the checked-in synthetic fixtures (8 advisories, 50 inventory assets) on 1 November 2026, with the offline FakeLLM. They show the prototype works end to end; they are not a production benchmark.

| Measure | Value | Source |
|---|---|---|
| Pipeline time, ingestion to alert files | 33–47 ms over 3 runs | `run_report.json` trace and wall clock |
| Alerts produced | 5 (P1: 1, P2: 2, P3: 1, P4: 1) | `run_report.json` |
| Precision / recall against the gold labels | 1.0 / 1.0 | `counterstrike eval` |
| Priority accuracy | 1.0 | `counterstrike eval` |
| Findings routed to human review | 2 of 8 advisories | `needs_human.json` |
| Prompt-injection advisory still alerted correctly | Yes | `counterstrike eval` |

**Limits of these numbers:** the gold set has only 5 alerts, so it cannot support the AC-2 targets (precision ≥ 90%, recall ≥ 95%). A larger labelled set is task T-06. Ingestion-to-delivery latency is not measured yet; that is task T-09. Live feeds and live LLM calls have not been run, so real-world timing is unknown.

## 5. Expected improvement in time to awareness

With the fleet, time to awareness is bounded by:

> feed publication lag (outside our control) + polling interval (15 min) + pipeline time + delivery time

On fixtures the pipeline takes well under a second. With a live LLM and real feed volume it will be longer, and delivery time is still to be measured (T-09). The design target is therefore that a P1 alert reaches its owner **within one polling cycle plus delivery time** of the advisory appearing in a feed. Whether that is an improvement, and by how much, will be stated only once the as-is baseline in section 2 is collected. Until then no percentage improvement is claimed.

Expected secondary effects, to be confirmed by measurement:
- Analyst effort moves from searching and matching to reviewing only uncertain cases (2 of 8 advisories in the fixture run).
- Prioritisation becomes consistent and explainable, because every alert carries its factor breakdown and policy version.
- Every decision has an audit record.

## 6. Rollout plan

| Stage | Scope | Exit criteria |
|---|---|---|
| 1. Prototype (by 16 Nov 2026) | Synthetic inventory, fixture and recorded feeds, offline LLM, Docker Compose, CI. | AC-1 to AC-10 evidence matrix complete (T-11); this proposal reviewed by the mentor. |
| 2. Shadow pilot | Live public feeds; masked inventory of one business unit; alerts go to the security team only and are compared with the current process. | Two to four weeks of side-by-side time-to-awareness data; agreed precision and recall on real matches. |
| 3. Limited production | Owner alerts for P1/P2 in the pilot unit; approved LLM deployment and data boundary. | Owners confirm alerts are actionable; review queue workload is sustainable. |
| 4. Scale-out | More business units, CMDB integration, ticketing (stretch). | Approved by security and platform owners. |

## 7. Risks and controls

| Risk | Control |
|---|---|
| Incomplete inventory hides affected assets | Inventory contract validation; unknown versions are never treated as *not affected*; coverage reported per unit. |
| Noisy or wrong matches erode trust | Deterministic matching with evidence; uncertain cases go to review; precision and recall tracked on a labelled set. |
| LLM invents facts | The LLM cannot set match, priority, SLA, owner or fix; summaries are checked against facts and fall back to a template. |
| Feed outages | Each source is polled and checkpointed independently; failures are visible in source health. |
| Sensitive data sent to the LLM | Only minimal advisory and asset fields are sent; owner contacts never are; live calls stay off until the data boundary is approved. |

## 8. Decisions needed

1. Approval of the public sources (NVD, CISA KEV, OSV, EPSS) and the 15-minute polling interval.
2. Access to baseline data for section 2, or agreement that interview estimates are acceptable.
3. The P1 delivery-time target for AC-6.
4. The approved LLM deployment and data boundary.
5. Recipients for P1/P2 alerts during the shadow pilot.
