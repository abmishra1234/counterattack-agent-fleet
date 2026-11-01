# Counterstrike: Decisions Needed by 2 November 2026

**For:** project mentor
**From:** Abinash Kumar Mishra, Project Counterstrike
**Purpose:** freeze the prototype scope for the 16 November 2026 target (task T-02)

Each row has a proposed default. Most come from the assumptions in the requirements document (Q1–Q16). A reply of **"yes"** to a row accepts it; otherwise please write the correction in the last column. Rows marked **new value** are proposals not stated in the requirements document. Unanswered rows will be treated as accepted for the prototype and recorded as such.

| # | Decision | Proposed default | What it unblocks | Mentor answer |
|---|---|---|---|---|
| D1 | Approved vulnerability sources | Public, free sources only: NVD, CISA KEV and OSV as advisory sources; FIRST EPSS as enrichment. No paid threat intelligence or GitHub Advisories. (Q4) | Turning on live feed polling; AC-1 | |
| D2 | Meaning of "near real time" | Poll every 15 minutes. (Q6) | Scheduler setting; AC-1, AC-6 | |
| D3 | Inventory | Synthetic inventory of 50 assets: applications, services, vendor products and SaaS, with product, version, owner, criticality, exposure and data classification. No CMDB access. (Q1–Q3) | Correlation and evaluation; AC-2, AC-3 | |
| D4 | LLM and data boundary | Azure OpenAI with LangGraph. The LLM may receive advisory text and minimal asset facts (component, version, service, criticality, exposure); owner contacts and other inventory fields stay local. (Q7, Q8) Deployment name and endpoint to be supplied. | Any live LLM run, including the CI smoke test | |
| D5 | Prompt and response retention | **New value:** keep encrypted prompts and responses for 30 days, readable only by the audit-reader role, then purge. | Live LLM runs (the code requires an approved retention period) | |
| D6 | Agent autonomy | Recommend and alert only. No system changes and no ticket creation. (Q9) | Delivery scope; AC-8 | |
| D7 | Risk policy and SLAs | Current additive score (CVSS + KEV + exposure + criticality). KEV on an internet-facing asset is always P1. SLAs are P1 24 h, P2 7 days, P3 30 days, P4 90 days. (Q10) | Final priorities; AC-4 | |
| D8 | EPSS in the score | **New value:** show EPSS on alerts but do not add it to the score in the prototype, because no approved weight exists. | Scoring policy version | |
| D9 | Alert channels and recipients | Teams webhook and email; P1/P2 go to the application owner and the security team. (Q11, Q12) For the demo, a test mailbox and test Teams channel to be supplied. | Sending real alerts; AC-6 | |
| D10 | P1 delivery-time target (AC-6) | **New value:** a P1 alert reaches the owner channel within 5 minutes of the advisory being ingested. | The AC-6 timed demo | |
| D11 | Accuracy targets (AC-2) | Precision ≥ 90% and recall ≥ 95%, measured on a labelled set of at least 40 advisory–asset pairs that the team builds and the mentor reviews. | The AC-2 evaluation (T-06) | |
| D12 | Baseline for the proposal (AC-10) | **New value:** the security team provides dates for about 20 recent high-severity CVEs (public disclosure vs first internal notice to the owner). If unavailable, interview estimates are accepted and labelled as estimates. | The as-is section of the proposal | |
| D13 | Platform and access | Docker Compose with PostgreSQL and GitHub Actions CI; local configured roles instead of single sign-on for the prototype. (Q16) | Deployment and demo setup | |
| D14 | Timeline and evaluation | Completion on 16 November 2026; evaluated by live demo plus proposal. (Q15) | Final schedule | |
