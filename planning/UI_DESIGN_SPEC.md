# Counterstrike — End-to-End UI Design Specification

| Item | Detail |
|---|---|
| Document | UI design specification (supports deliverable D3 Solution design and D7 Alerts + dashboard) |
| Version | Draft v0.1 for mentor review, 31 Oct 2026 |
| Sources | `requirement/Counterstrike_Agents_Fleet_Requirements.docx` (FR-1–FR-10, AC-1–AC-10, S1–S10, alert and dashboard mock-ups); `planning/UPDATED_REQUIREMENT_GAP_PLAN.md` (G-01–G-11, delivery phases); current contracts in `src/counterstrike/models.py` and outputs in `out/` |
| Status | Proposed. Items marked **[Decision]** depend on the 2 Nov scope confirmation |

---

## 1. Purpose and scope

This document specifies every surface through which people see and act on Counterstrike output, from the moment a vulnerability is disclosed to the moment an owner has acknowledged it and the proposal measures how long that took. It covers:

1. **Outbound messages** — Teams alert card, email alert and daily digest (FR-8, Must).
2. **Analyst workspace** — review queue for low-confidence and unparseable items (FR-4, FR-9, AC-7, Must).
3. **Exposure dashboard** — overview, alerts, advisories, assets, fleet health, audit, policy and evaluation views (FR-10, Should).

It does not cover automatic patching, ticket creation (Could), SIEM/SOAR integration or enterprise CMDB sync; these are out of scope per the requirement.

### 1.1 Priority of UI work

The gap plan puts the dashboard at Should priority and requires the Must path to be reliable first. The UI is phased to match:

| UI tier | Surfaces | Requirement priority | Build window (gap plan phase) |
|---|---|---|---|
| **Tier 1 — Must** | Teams/email alert, daily digest, analyst review queue + decision form, run status page | FR-4, FR-8, FR-9 / AC-6, AC-7, AC-9 | Phase 3 (9–11 Nov) |
| **Tier 2 — Should** | Exposure overview, alert worklist and detail, advisory detail, inventory view, fleet health, audit trail | FR-10 / AC-1, AC-4, AC-5, AC-8 evidence | Phase 4 (12–14 Nov) |
| **Tier 3 — Could** | Risk-policy simulator, evaluation and metrics page, inventory import UI, "Create ticket" action | FR-10, AC-2, AC-10, stretch | Phase 5 only if Tier 1–2 are done |

If time runs short, Tier 1 alone still satisfies the Must acceptance criteria; Tier 2 views can be replaced by the existing JSON/Markdown outputs for the demo.

---

## 2. Users and their jobs

| Persona | Who | Primary job in the UI | Main surfaces | Permissions |
|---|---|---|---|---|
| **Application owner** | Engineering team lead (e.g. `team-payments`) | Learn what is affected, why it matters, what to do and by when | Teams/email alert, alert detail | View own alerts; acknowledge; dispute ("Not affected — why?") |
| **Security analyst** | Vulnerability-management analyst | Resolve uncertainty the fleet would not guess about; check evidence | Review queue, advisory detail, alert worklist | View all; decide review items; reopen alerts |
| **Security lead** | Head of vuln management / CISO delegate | See estate exposure, P1/P2 SLA risk, trend | Daily digest, exposure overview | View all; read-only |
| **Platform / fleet operator** | Participant or SRE running the service | Confirm feeds are polling, agents healthy, deliveries succeeding | Fleet health, run detail, delivery log | View all; re-run delivery from dead-letter; trigger manual poll |
| **Inventory steward** | Owner of the asset/vendor list | Keep inventory complete enough to match | Inventory view, import validation | View all; upload inventory file (Tier 3) |
| **Mentor / evaluator** | Assessor of the prototype | Verify acceptance criteria and proposal metrics | Evaluation page, audit trail | Read-only |

**[Decision Q12]** Default assumption: P1/P2 go to application owner + security team; P3/P4 go to the owner and appear in the digest only.

---

## 3. Design principles

These come directly from the requirement's guardrails and the decision log; each one has a concrete UI consequence.

| Principle | Source | UI rule |
|---|---|---|
| **Read-only toward managed assets** | AC-8, DL-03, guardrail "Read-only" | No control anywhere triggers a patch, config change or deployment. The only write actions change Counterstrike's own records (acknowledgement, review decision, feedback). |
| **Explain every priority** | FR-6, AC-4 | Every priority badge links to its factor breakdown and the policy version that produced it. A priority is never shown without "Why P1/P2/…". |
| **Cite or flag** | FR-7, AC-5 | Every remediation step shows at least one source link. Advice without a source is shown with an **Unverified** badge and is never sent as a confirmed fix. |
| **Show uncertainty, never hide it** | FR-4, AC-3, AC-7 | "Possibly affected" and "Needs review" have their own colour, label and queue. "Unknown" is never rendered as "Not affected". |
| **Code decides, AI words** | DL-03, G-05 | AI-written text (impact summary, extracted ranges) carries an **AI summary** label and the prompt/model version. Decision fields (match, score, owner, SLA) never carry that label because they are computed. |
| **Low noise** | Guardrail "Noise control" | Not-affected results produce no message. P4 goes to the digest only **[Decision]**. Duplicates from multiple feeds collapse to one row with source chips. |
| **Freshness is visible** | FR-1, AC-1, AC-9 | Every screen header shows "Feeds checked N min ago" and turns amber if any feed missed its last cycle. |
| **Inventory stays inside** | Guardrail, Q8 | The UI never shows, exports or sends inventory data to the LLM; pages that display LLM output state which fields were sent. |

---

## 4. End-to-end flow and where the UI touches it

```
 Disclosure                Fleet (orchestrated)                                         People
 ──────────   ┌───────────────────────────────────────────────────────────────┐   ─────────────────────────────
 NVD ───┐     │ 1 Watcher → 2 Enricher → 3 Correlator → 4 Risk → 5 Remediation  │
 KEV ───┼───► │     │            │              │           │         │          │ ─► 6 Notifier ─► Teams / email (U-1, U-2)
 OSV ───┤     │     │            │        possibly / low     │         │ uncited  │              └► Daily digest (U-3)
 EPSS ──┘     │     ▼            ▼        confidence ▼       ▼         ▼  advice  │
              │  Fleet health   Advisory     Review queue ◄─────────────┘         │ ─► Analyst decision (S-05/S-06)
              │  (S-08)         detail (S-04)    │                                │        │ confirm → alert
              │                                  └────────────────────────────────┘        │ reject  → closed, audited
              │  Audit trail (S-09) records every step, decision and delivery              ▼
              └──────────────────────────────────────────────────────────────────►  Dashboard (S-01…S-12)
```

### 4.1 Primary journeys

Each journey is traced to the demo scenario (S1–S10) and acceptance criterion it proves.

**J1 — P1 alert reaches the owner (S1, S5 · AC-4, AC-5, AC-6)**
1. Watcher ingests CVE from NVD; the poll is recorded in Fleet health (S-08) with its ingestion timestamp.
2. Enricher adds CVSS 9.8, EPSS 0.71, KEV = yes; Correlator finds Tomcat 9.0.85 on Client Portal (affected, confidence 0.98).
3. Risk assessor computes P1 (KEV + internet-facing rule); Remediation advisor cites the vendor advisory and NVD.
4. Notifier posts the Teams card (U-1) to the owner channel and the security channel, and sends the email (U-2).
5. Owner clicks **Acknowledge** in Teams → alert status becomes *Acknowledged*; time-to-acknowledge is recorded.
6. Dashboard (S-01) shows the alert in "P1 open"; Evaluation page (S-12) shows ingestion → delivery latency for the AC-6 timed demo.

**J2 — Analyst resolves a possible match (S4 · AC-7)**
1. Correlator matches inventory name "MS SQL Svr 2019" to `microsoft:sql_server:2019` with confidence 0.72 (below threshold **[Decision Q3]**, proposed 0.85).
2. Item enters the Review queue (S-05) as *Possibly affected*; no owner message is sent.
3. Analyst opens the decision drawer (S-06), sees the CVE record and inventory record side by side, and chooses **Confirm affected**, **Not affected** or **Need more info** with a mandatory reason.
4. Confirm → the item flows through scoring and notification as in J1, marked "Confirmed by analyst". Not affected → closed, no message, decision audited.

**J3 — Unparseable advisory (current fixture CVE-2099-0008 · AC-7, AC-9)**
1. Extractor cannot find a product or version range; item is routed with reason "no known product/version range found in bulletin".
2. Review queue shows it as *Unparsed advisory* with the raw bulletin text (rendered as inert text, never HTML).
3. Analyst can enter product + range manually (validated against the inventory vocabulary) or close as *Not relevant*.

**J4 — Owner disputes an alert (requirement "Not affected – why?")**
1. Owner clicks **Not affected – why?** in the Teams card or alert detail.
2. Form asks for a reason category (version already upgraded · component not used · compensating control · inventory wrong · other) and free text.
3. Alert moves to *Disputed* and appears in the Review queue; the analyst accepts (alert closes, inventory correction task logged for the steward) or rejects (alert stays open). Automatic learning from this feedback is a stretch item and is not implied by the UI.

**J5 — Re-prioritisation when KEV changes (S5 · AC-4)**
1. A CVE already alerted at P3 is added to CISA KEV.
2. Risk assessor recomputes; the alert changes to P1 under a new score record.
3. Owner receives a new card titled "Priority raised P3 → P1" with the factor that changed highlighted; alert detail history shows both scores and policy versions.

**J6 — A feed is down (S9 · AC-9)**
1. OSV returns errors; retries reach the configured limit.
2. Fleet health (S-08) shows OSV as *Failing* with last success time and error; the header freshness indicator turns amber with "1 of 3 feeds degraded".
3. NVD and KEV continue; alerts from them are unaffected. The digest includes a "Feed health" line.

**J7 — Daily digest (FR-8)**
At 08:00 local **[Decision]** the security lead and each owner receive a digest (U-3): new alerts by priority, SLA breaches and near-breaches, items awaiting review, feed health.

**J8 — Assessment and proposal metrics (S10 · AC-2, AC-10)**
Evaluator opens Evaluation (S-12): precision/recall on the labelled set with false positives/negatives listed, P1 latency measurements, review-queue rate, delivery success; each metric shows its sample size and data source.

---

## 5. Information architecture

```
Counterstrike
├── Overview ................................. S-01  Exposure at a glance
├── Alerts ................................... S-02  Worklist (group by CVE / asset / owner)
│   └── Alert detail ......................... S-03
├── Advisories ............................... S-04  CVE detail (sources, enrichment, correlation results)
├── Review queue  (badge: open count) ........ S-05
│   └── Decision drawer ...................... S-06
├── Inventory ................................ S-07  Assets, vendors/SaaS, validation issues
├── Fleet health ............................. S-08  Feeds, agents, runs, deliveries
│   └── Run detail / audit trail ............. S-09
├── Notifications ............................ S-10  Delivery log, dead-letter, digest preview
├── Risk policy .............................. S-11  Read-only policy + simulator (Tier 3)
├── Evaluation ............................... S-12  Accuracy, latency, proposal metrics (Tier 3)
└── Settings ................................. S-13  Channels, recipients, thresholds (read-only display of config)
```

**Navigation:** left sidebar on desktop (≥ 1024 px), collapsible to icons; bottom tab bar with Overview, Alerts, Review, More on narrow screens. Owners land on **Alerts** filtered to their team; analysts land on **Review queue**; security lead and operators land on **Overview**.

**Global header (every page):** product name · environment tag (DEMO / LOCAL) · freshness indicator ("Feeds checked 2 min ago", amber when degraded, red when all feeds stale > 2 cycles) · global search (CVE ID, asset ID, service, product) · user menu.

**Deep links:** `/alerts/{alert_id}`, `/advisories/{cve_id}`, `/review/{item_id}`, `/assets/{asset_id}`, `/runs/{run_id}`. Every outbound message links to the matching page.

---

## 6. Outbound message designs (Tier 1, Must)

### U-1 Teams alert card (Adaptive Card)

Layout follows the requirement mock-up "Actionable alert — what an application owner receives".

```
┌───────────────────────────────────────────────────────────────────────┐
│ ■ P1 · CVE-2026-XXXXX · Apache Tomcat                 KNOWN EXPLOITED   │  ← header colour = priority
├───────────────────────────────────────────────────────────────────────┤
│ AFFECTS                                                                │
│ Client Portal (Tier 1, internet-facing) · Tomcat 9.0.85 ·              │
│ owner: Digital Channels · respond by 01 Nov 10:15 (SLA 24 h)           │
├───────────────────────────────────────────────────────────────────────┤
│ IMPACT  [AI summary]                                                   │
│ Remote attacker may run code on the portal server → possible           │
│ client-data exposure and service outage.                               │
├───────────────────────────────────────────────────────────────────────┤
│ RECOMMENDED ACTION                                                     │
│ Upgrade to Tomcat 9.0.98.  [Vendor advisory ↗] [NVD ↗]                 │
│ Interim mitigation: disable the affected connector. [Vendor advisory ↗]│
├───────────────────────────────────────────────────────────────────────┤
│ WHY P1                                                                 │
│ CVSS 9.8 · EPSS 0.71 · in CISA KEV · internet-facing · Tier 1          │
│ policy risk-v1.0 · rule: KEV + internet-facing → P1                    │
├───────────────────────────────────────────────────────────────────────┤
│ [ Acknowledge ]  [ Not affected – why? ]  [ Open in Counterstrike ↗ ]  │
└───────────────────────────────────────────────────────────────────────┘
  Counterstrike · ALR-0001 · read-only advice; no system was changed
```

| Element | Rule |
|---|---|
| Header | `{priority} · {cve_id} · {product display name}`; right side shows **KNOWN EXPLOITED** when `in_kev`, else EPSS when ≥ 0.1 |
| Affects | Service, criticality tier, exposure, component + installed version, owner, due time = delivery time + SLA |
| Impact | AI summary (FR-5) with label; falls back to a template sentence when the LLM fails (counted as `summary_fallbacks`) |
| Recommended action | Each sentence ends with ≥ 1 source link. If no source supports a fix: "No confirmed fix in sources yet — analyst notified" and a **Watch** note (S7) |
| Why | All factors from `score_breakdown`, policy version, and any override rule that fired |
| Actions | *Acknowledge* (records user + time); *Not affected – why?* opens the dispute form (J4); *Open* deep-links to S-03. **Create ticket** is hidden unless the stretch integration is enabled |
| Footer | Alert ID and the read-only statement |

**Variants:** priority raised (J5) adds a top line "Priority raised P3 → P1 — CVE added to CISA KEV"; confirmed-by-analyst adds "Match confirmed by {analyst}"; resent after retry carries the same idempotency key, so Teams shows one card (G-08).

**Fallback:** if Adaptive Card actions are not available on the demo tenant, the card renders the same content with a single "Open in Counterstrike" link and actions happen in S-03.

### U-2 Email alert

- **Subject:** `[P1] CVE-2026-XXXXX affects Client Portal (Tomcat 9.0.85) — act within 24 h`
- **Body:** same sections as U-1, in that order, as HTML with a plain-text alternative. Buttons become links to S-03 (`?action=ack`, `?action=dispute`), which require sign-in; email links never perform the action with a single GET.
- **Recipients:** owner contact from inventory; security distribution list for P1/P2 **[Decision Q11, Q12]**.

### U-3 Daily digest (email + optional Teams post)

```
Counterstrike daily digest · Sat 31 Oct 2026 · 08:00
──────────────────────────────────────────────────────
Since yesterday:  146 CVEs ingested · 9 affect our estate · 4 awaiting analyst review
Open by priority: P1 2 · P2 5 · P3 7 · P4 11
SLA:              1 breached (P2, team-digital, 2 h over) · 2 due in < 24 h

NEW ALERTS
P1  CVE-2026-XXXXX  Apache Tomcat  Client Portal, Fund API   Acknowledged
P2  CVE-2026-YYYYY  OpenSSL        3 services                Delivered
P4  …  (P4 items listed here only; no individual message)

AWAITING REVIEW (no owner alert sent yet)
CVE-2026-ZZZZZ  "Acme HR SaaS"  possibly affected  conf 0.64  waiting 5 h

FEED HEALTH   NVD ✓  ·  CISA KEV ✓  ·  OSV ⚠ failing since 06:40 (3 retries)
[Open dashboard ↗]
```

Owner digest is the same, filtered to the owner's assets. Numbers must equal the dashboard totals at the digest's snapshot time (G-10 completion evidence).

---

## 7. Screen specifications

Each screen lists purpose, requirement trace, layout, content, interactions and states. Field names refer to existing models (`Alert`, `NeedsHuman`, `Asset`, …) and to fields the gap plan adds (marked *new*, with the gap ID).

### S-01 Exposure overview (Tier 2)

**Purpose:** answer "How exposed are we right now, and is the fleet working?" in one screen.
**Trace:** FR-10, FR-1, AC-1, AC-9, AC-10. Mock-up: "Security dashboard — exposure at a glance".

```
┌ Counterstrike · Vulnerability exposure ───────────────── Feeds checked 2 min ago ●┐
│                                                                                    │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐           │
│ │   146    │ │    9     │ │    2     │ │      4       │ │   38 min     │           │
│ │ New CVEs │ │ Affect   │ │ P1 open  │ │ Needs analyst│ │ Median time  │           │
│ │ today    │ │ estate   │ │          │ │ check        │ │ to alert     │           │
│ └──────────┘ └──────────┘ └──────────┘ └──────────────┘ └──────────────┘           │
│                                                                                    │
│ Open alerts by priority & age          │ SLA status                                 │
│ P1 ██ 2      P2 █████ 5                │ Breached 1 · Due < 24 h 2 · On track 22    │
│ P3 ███████ 7 P4 ███████████ 11         │                                            │
│                                                                                    │
│ Top exposures                                              [View all alerts →]     │
│ CVE            Product         Affected apps         Signals          Pri Owner    Status
│ CVE-2026-XXXXX Apache Tomcat   Client Portal, Fund API [KEV][EPSS .71] P1 Digital  Acknowledged
│ CVE-2026-YYYYY OpenSSL         3 services            [EPSS .12]       P2 Platform  Delivered
│ CVE-2026-ZZZZZ "Acme HR SaaS"  Vendor (SaaS)          —               P3 Vendor mgmt POSSIBLY AFFECTED
│                                                                                    │
│ Feed health: NVD ✓ 2 min · CISA KEV ✓ 2 min · OSV ⚠ failing 1 h 35 m  [Details →]   │
└────────────────────────────────────────────────────────────────────────────────────┘
```

| Tile | Definition | Source |
|---|---|---|
| New CVEs today | Distinct advisories first ingested since 00:00 local, after de-duplication | ingestion records (G-01) |
| Affect our estate | Distinct CVEs with ≥ 1 *affected* or *confirmed* match, still open | correlation results (G-04) |
| P1 open | Alerts with priority P1 and status not Resolved/Closed | alerts |
| Needs analyst check | Open review items (possibly affected + unparsed + disputed + uncited advice) | review queue |
| Median time to alert | Median of (first delivery success − first ingestion) for alerts created in last 7 days; label shows sample size on hover | audit events (G-09, G-11) |

**Interactions:** each tile filters S-02 or S-05; rows open S-04 (CVE grouped). Auto-refresh every 60 s with a visible "Updated hh:mm" note; no layout jump on refresh.
**States:** *Empty* — "No affected assets. Last poll 2 min ago, 3 of 3 feeds healthy" (makes clear that quiet ≠ broken). *Degraded* — amber banner naming failing feeds. *No data yet* — onboarding message linking to Fleet health.

### S-02 Alert worklist (Tier 2)

**Purpose:** find and triage alerts. **Trace:** FR-6, FR-8, AC-3, AC-4.

**Toolbar:** search · Priority (P1–P4 multi) · Status · Owner · Correlation outcome · KEV only · Internet-facing only · SLA (breached / due < 24 h) · Group by (*CVE* | *Asset* | *Owner* | none) · Export CSV (current filter, excludes AI text by default).

**Columns (Group by = none):**

| Column | Field | Notes |
|---|---|---|
| Priority | `priority` | Coloured badge with text label (never colour only) |
| Alert | `alert_id` | Link to S-03 |
| CVE | `cve_id` | Link to S-04; source chips (NVD, OSV) *new G-01* |
| Service / asset | `service`, `asset_id` | |
| Component | `component` `installed_version` → `fixed_version` | "no fix yet" when `fixed_version` is null |
| Signals | `in_kev`, EPSS *new G-02*, internet-facing | Chips |
| Score | `risk_score` | Hover shows breakdown |
| Owner | `owner` | |
| Status | *new* alert status (§8.2) | |
| Due | delivery time + `sla_hours` | Red when breached, amber when < 25 % SLA left |

**Default sort:** priority, then due time ascending. **Grouping by CVE** shows one parent row per CVE with child rows per asset (matches the mock-up's "Client Portal, Fund API").
**Row actions:** Acknowledge (owner/analyst), Open. No bulk "close" — closing happens through review decisions so each is audited.
**States:** empty filter result shows active filters with "Clear filters"; owner with no alerts sees "No open alerts for team-payments".

### S-03 Alert detail (Tier 2; minimal version in Tier 1 as the target of Teams/email links)

**Purpose:** everything one owner needs to act, plus proof for the analyst. **Trace:** FR-5, FR-6, FR-7, AC-4, AC-5, AC-8.

```
← Alerts
P1  ALR-0001 · CVE-2099-0001 · log4j-core on payments-api            Status: Delivered ▾
Respond by 01 Nov 10:15 (SLA 24 h · 22 h 40 m left)   [Acknowledge] [Not affected – why?]
───────────────────────────────────────────────────────────────────────────────────────
┌ Affects ───────────────────────────┐ ┌ Why P1 ────────────────────────────────────┐
│ Service     payments-api (A-101)   │ │ CVSS                 10.0 ██████████ +10.0   │
│ Component   log4j-core 2.14.1      │ │ CISA KEV             yes  ██          +2.0   │
│ Fixed in    2.17.1                 │ │ EPSS                 —    (added by G-02)    │
│ Exposure    internet-facing        │ │ Internet-facing      yes  █▌          +1.5   │
│ Criticality high                   │ │ Criticality          high █           +1.0   │
│ Owner       team-payments          │ │ Total 14.5 → P1 (≥ 12) · policy risk-v1.0    │
│ Match       affected · conf 1.00   │ │ [How is this calculated? → S-11]             │
└────────────────────────────────────┘ └──────────────────────────────────────────────┘
┌ Impact  [AI summary · fake-llm/summarise_v1] ─────────────────────────────────────────┐
│ Business:    …  Operational: …  Security: …                    (three dimensions G-05) │
└───────────────────────────────────────────────────────────────────────────────────────┘
┌ Recommended action ───────────────────────────────────────────────────────────────────┐
│ 1. Upgrade log4j-core from 2.14.1 to 2.17.1 or later.            [NVD ↗] [Vendor ↗]    │
│ 2. Rebuild and redeploy payments-api; re-run the dependency scan.                     │
│ Fix type: CONFIRMED FIX   (alternatives: MITIGATION ONLY · NO FIX KNOWN · UNVERIFIED)  │
└───────────────────────────────────────────────────────────────────────────────────────┘
┌ Evidence ─────────────────────────────────────────────────────────────────────────────┐
│ ▸ structured feed record (nvd) — retrieved 31 Oct 09:58 [source ↗]                     │
│ ▸ inventory A-101: log4j-core==2.14.1                                                 │
│ ▸ affected range >=2.0.0,<2.17.1                                                      │
│ ▸ alias applied: log4j2 → log4j-core                                                   │
└───────────────────────────────────────────────────────────────────────────────────────┘
┌ Timeline ─────────────────────────────────────────────────────────────────────────────┐
│ 09:58 ingested (NVD) · 09:58 enriched · 09:58 matched · 09:58 scored P1 ·              │
│ 09:59 Teams delivered · 09:59 email delivered · 10:12 acknowledged by j.doe            │
│ [Full audit trail → S-09]                                                              │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Rules:
- The **Why** panel lists every key of `score_breakdown` with its contribution and the band threshold reached; override rules (KEV + internet-facing → P1, if approved under **[Decision Q4/G-06]**) appear as a separate line "Rule applied".
- **Recommended action** shows a fix-type badge. *Unverified* (no source) is shown only to analysts; owners see "Advice pending analyst review" instead (AC-5).
- **Evidence** lines come from `Alert.evidence` and are rendered as plain text. Quotes from bulletins are visually marked as quotations from the source.
- A `version_note` (tolerant version parsing, DL-04) appears as an info line: "Installed version 1.1.1w compared as 1.1.1".
- If `suspected_injection` was flagged for the advisory, analysts see a banner "Source text contained instructions aimed at the AI; they were ignored. Decisions are computed." Owners do not see it.
- **History**: when priority changes (J5), a "Score history" expander shows each score, factors and policy version.

### S-04 Advisory (CVE) detail (Tier 2)

**Purpose:** one record per CVE across all sources, with its effect on the estate. **Trace:** FR-1, FR-2, FR-4, AC-1, AC-3, S6.

Sections:
1. **Header** — CVE ID, title, published, last modified, source chips (NVD · OSV · KEV) showing that duplicates merged into one record (S6).
2. **Enrichment** — table of CVSS (vector on hover), EPSS score + percentile, KEV (date added), CWE; each value has *source* and *retrieved at*. Missing or stale values display "Not available from sources (checked hh:mm)" — never a default number (G-02).
3. **Affected products** — vendor, product, affected range, fixed version, extraction method (*structured* / *AI-extracted* with evidence quotes), references list.
4. **Correlation results** — every inventory candidate considered, with outcome:

| Asset | Inventory product / version | Outcome | Confidence | Reason |
|---|---|---|---|---|
| A-101 payments-api | log4j-core 2.14.1 | **Affected** | 1.00 | in range >=2.0.0,<2.17.1 |
| A-102 … | log4j-core 2.17.2 | **Not affected** | 1.00 | version already fixed (S2) |
| A-207 hr-portal | "MS SQL Svr 2019" | **Possibly affected** | 0.72 | AI name match only → review |

Not-affected rows are collapsed by default ("3 assets checked and not affected — show") to demonstrate AC-3 without adding noise. If no inventory product matches, the section says "No inventory component uses this product" (S3).

5. **Raw source** (analyst only) — collapsible, raw JSON/text from each source, rendered inert.

### S-05 Review queue (Tier 1, Must)

**Purpose:** the human-in-the-loop for everything the fleet refused to guess. **Trace:** FR-4, FR-7, FR-9, AC-5, AC-7.

**Item types:**

| Type | Created when | Current support |
|---|---|---|
| Unparsed advisory | Extractor finds no product/range, or LLM output fails grounding/JSON | `NeedsHuman` (stage `extract`) |
| Possibly affected | Correlation confidence < threshold, version unknown, or name-only match | *new G-04* |
| Uncited advice | Remediation has no supporting source | *new G-07* |
| Disputed alert | Owner says "Not affected" (J4) | *new* |
| Inventory issue | Asset missing owner/version, unknown fields on import | *new G-03* |

**Layout:** list on the left, decision drawer (S-06) on the right on desktop; full-screen drawer on narrow screens.

**Columns:** type badge · CVE / advisory ID · asset (if any) · reason (e.g. `no known product/version range found in bulletin`) · confidence · provisional priority ("would be P2 if confirmed") · waiting time · assignee.

**Sort:** provisional priority, then waiting time. Items with a provisional P1/P2 waiting > 1 h show an amber clock — uncertainty must not silently delay urgent alerts **[Decision: escalation threshold]**.
**Filters:** type, provisional priority, assignee (me / unassigned / all).
**Empty state:** "Nothing waiting for review. The fleet resolved all items automatically in the last run."

### S-06 Review decision drawer (Tier 1, Must)

```
┌ Possibly affected · CVE-2026-ZZZZZ ↔ A-207 hr-portal ────────────── conf 0.72 ┐
│ Why it is here: inventory name matched by AI only; version not stated          │
│ ┌ CVE says ─────────────────────┐   ┌ Inventory says ────────────────────────┐ │
│ │ microsoft : sql_server : 2019 │ ⇄ │ "MS SQL Svr 2019" · version — (missing)│ │
│ │ affected < 15.0.4335          │   │ owner team-hr · internal · high        │ │
│ │ [NVD ↗]                        │   └────────────────────────────────────────┘ │
│ └───────────────────────────────┘                                              │
│ Provisional priority if confirmed: P2 (score 9.6)                               │
│                                                                                │
│ Decision  ( ) Confirm affected   ( ) Not affected   ( ) Need more info         │
│ Version (optional) [ 15.0.4223      ]  ← re-runs version check before saving   │
│ Reason (required)  [ Confirmed with team-hr, CU16 installed …               ]  │
│                                                         [Cancel] [Save decision]│
└────────────────────────────────────────────────────────────────────────────────┘
```

Rules:
- Reason is mandatory for every decision; the decision, reviewer and time are written to the audit log (AC-8).
- **Confirm affected** sends the item through scoring → remediation → notification; the analyst cannot set priority, owner or SLA (DL-03 applies to humans in the UI as well — policy overrides are a separate, audited policy change).
- **Not affected** closes the item without any message and, when the reason is "inventory wrong", creates an inventory-issue item for the steward.
- **Need more info** keeps the item open and lets the analyst assign it.
- For *Unparsed advisory*, the drawer shows the bulletin text and fields for product (autocomplete from inventory vocabulary), affected range and fixed version; values are validated the same way the extractor's output is (syntax + vocabulary).
- For *Uncited advice*, actions are **Add source URL** (must be http/https) or **Withhold advice** (alert is sent with "No confirmed fix in sources yet").

### S-07 Inventory (Tier 2; import is Tier 3)

**Purpose:** show what the fleet matches against and where data quality limits matching. **Trace:** FR-3, G-03, S8.

**Tabs:** *Software assets* · *Vendors & SaaS* · *Validation issues*.

| Column | Current field | Planned field (G-03) |
|---|---|---|
| Asset ID / service | `asset_id`, `service` | asset type (app / service / SaaS / infrastructure) |
| Vendor / product | `component` | `vendor`, `product`, aliases |
| Version | `version` | |
| Owner | `owner` | owner contact (Teams channel / email) |
| Criticality | `criticality` | business tier mapping (Tier 1 = critical) |
| Exposure | `internet_facing` | |
| Data classification | — | `data_classification` |
| Open alerts | derived | |

Asset detail shows its open alerts, review items and the alias map entries that apply. **Validation issues** lists missing owner/version and unknown fields with the row they came from. **Import (Tier 3):** upload JSON/CSV → validation preview (valid / warnings / errors) → confirm; the previous version remains available and the import is audited. Inventory data is labelled "Local only — not sent to AI".

### S-08 Fleet health (Tier 1 minimal, Tier 2 full)

**Purpose:** prove the fleet is polling, isolate failures, support AC-1 and AC-9. **Trace:** FR-1, FR-9, AC-1, AC-9, S9.

**Feeds panel:**

| Source | Status | Last success | Last attempt | New / updated / duplicate (last cycle) | Checkpoint | Next poll |
|---|---|---|---|---|---|---|
| NVD | ✓ Healthy | 10:00 | 10:00 | 12 / 3 / 4 | `lastModified 2026-10-31T09:59Z` | 10:15 |
| CISA KEV | ✓ Healthy | 10:00 | 10:00 | 1 / 0 / 0 | catalog v2026.10.31 | 10:15 |
| OSV | ⚠ Failing | 08:25 | 10:00 (retry 3/3, HTTP 503) | — | unchanged | 10:15 |
| EPSS (enrichment) | ✓ Healthy | 06:00 | 06:00 | daily file | 2026-10-31 | tomorrow 06:00 |

Status values: Healthy · Degraded (succeeded after retry) · Failing (retries exhausted) · Disabled. Clicking a source shows the poll history (last 24 h sparkline of new items and failures) and the error log.

**Agents panel:** one row per agent (Watcher, Enricher/Extractor, Correlator, Risk, Remediation, Notifier) for the latest run: status, duration (`ms`), items in/out, LLM calls, prompt version, retries, fallbacks — directly from the run `trace` in `run_report.json`.

**Runs list:** run ID, start, duration, trigger (schedule / manual), advisories in, alerts out, review items, status → S-09.

**Operator action:** **Poll now** (re-runs the Watcher only; it reads feeds and never writes to managed systems).

### S-09 Run detail and audit trail (Tier 2)

**Purpose:** reconstruct any decision end to end (AC-8). **Trace:** FR-9, AC-8.

- **Run view:** pipeline diagram of agents with counts on each edge (8 ingested → 7 extracted + 1 to review → 5 matches → 5 scored → 5 alerts → 5 owners), conditional short-circuits shown when taken (e.g. "no matches → dispatch").
- **Audit view (per advisory or alert):** chronological, append-only events: `ingested`, `deduplicated`, `enriched`, `extracted`, `grounding_check`, `injection_flag`, `matched`/`not_matched`, `review_created`, `review_decided`, `scored`, `advice_generated`, `delivery_attempted`, `delivered`, `acknowledged`. Each event shows timestamp, actor (agent name + version, or user), inputs summary, output, policy/prompt version and retry count.
- **Export:** JSON of the event chain for one advisory (for the evaluator).
- No edit or delete controls exist on this page.

### S-10 Notifications (Tier 2)

**Purpose:** prove delivery and avoid duplicates. **Trace:** FR-8, AC-6, G-08.

**Tabs:** *Delivery log* · *Dead-letter* · *Digest preview* · *Outbox (local files)*.

| Column | Meaning |
|---|---|
| Alert / digest | Link |
| Channel | Teams / email / local outbox |
| Recipient | Owner channel, security channel or address |
| Idempotency key | `{alert_id}:{channel}:{recipient}:{priority}` (a priority change makes a new key so J5 sends a new message) |
| Status | Queued · Sent · Failed (retrying n/m) · Dead-letter · Suppressed (duplicate) |
| Latency | Ingestion → delivery success |

Dead-letter rows have **Retry delivery** (operator only, audited). *Digest preview* renders tomorrow's digest from current data. *Outbox* lists the per-owner Markdown files that the prototype writes today, keeping the current DL-09 behaviour visible until real channels are approved.

### S-11 Risk policy (Tier 3)

**Purpose:** make the priority rules inspectable and let reviewers test them. **Trace:** FR-6, AC-4, G-06.

- **Policy card:** version, approval status (*Provisional* until security/mentor approval — shown as a badge), factors and weights, bands with SLA, override rules. Current prototype values: score = CVSS + 2.0 (KEV) + 1.5 (internet-facing) + criticality (critical +2, high +1, medium 0, low −1); P1 ≥ 12 (24 h), P2 ≥ 9 (7 d), P3 ≥ 6 (30 d), P4 < 6 (90 d). EPSS weight and the KEV + internet-facing override are **[Decision Q4/Q10]**.
- **Simulator:** inputs for CVSS, EPSS, KEV, exposure, criticality → shows score, band and the factor bars. It calls the same scoring function as the fleet; it does not change policy.
- Policy edits are not made in the UI; they are code/config changes reviewed through CI.

### S-12 Evaluation and metrics (Tier 3)

**Purpose:** evidence for AC-2, AC-6 and AC-10 and the proposal. **Trace:** AC-2, AC-6, AC-10, G-11, S10.

- **Matching accuracy:** precision, recall, priority accuracy on the labelled set, with sample size and dataset version; tables of false positives and false negatives (not just percentages); safety checks from the current gate (`must_not_alert` respected, unparseable advisory routed, injection resisted, summaries grounded) shown as pass/fail.
- **Timeliness:** distribution of ingestion → delivery for P1 (target **[Decision Q5]**), polling delay, review-queue waiting time.
- **Noise:** review-queue rate, dispute rate (% of alerts marked "not affected"), duplicate suppressions.
- **As-is vs to-be:** side-by-side table; every as-is value labelled *Estimate — source: stakeholder interview on dd/mm* until measured; every to-be value labelled *Measured — n = …, period …*.
- Data comes from `scorecard.md`/eval output and audit events; nothing on this page is typed in by hand except as-is estimates with their source.

### S-13 Settings (Tier 2, read-only display)

Shows the active configuration so evaluators can see what the run used: polling interval, enabled sources, correlation confidence threshold, LLM backend (fake / gateway, model name — never the key), channels enabled, recipient routing per priority, digest time, retry limits. Secrets are shown as "configured / not configured". Changes are made through environment configuration, not the UI, in the prototype.

---

## 8. Status models

### 8.1 Correlation outcome

| Outcome | Meaning | UI treatment | Notification |
|---|---|---|---|
| Affected | Product matches and version in range, confidence ≥ threshold | Red label "Affected" | Alert per priority routing |
| Possibly affected | Name-only/AI match, version unknown, or confidence < threshold | Amber-brown label "Possibly affected" | None until analyst confirms |
| Not affected | Product not used, or version outside range / fixed | Green label, collapsed by default | None |
| Unknown | Data missing to decide (e.g. inventory version blank) | Treated as Possibly affected; never shown as Not affected | None until reviewed |

### 8.2 Alert lifecycle

```
           ┌────────── priority change (J5) creates new score + message ─────────┐
           ▼                                                                      │
 Created ──► Delivered ──► Acknowledged ──► Resolved (fixed version observed in inventory)
   │            │   │            │
   │            │   └──► Disputed ──► (analyst) accepted → Closed – not affected
   │            │                     (analyst) rejected → back to Delivered/Acknowledged
   │            └──► Delivery failed ──► (retry) Delivered | Dead-letter
   └──► Pending review (from S-05 confirm path starts at Created)
```

*Resolved* is set only when the next inventory snapshot shows a version outside the affected range, so the UI never claims a fix it cannot see (read-only principle). SLA clocks start at first successful delivery **[Decision]**.

### 8.3 Review item lifecycle

`Open → Assigned → Decided (Confirmed | Not affected | Withheld | Source added) → Closed`, or `Open → Need more info → Assigned`. Every transition is an audit event.

### 8.4 Delivery lifecycle

`Queued → Sent` · `Queued → Failed → Retrying (n/m) → Sent | Dead-letter` · `Queued → Suppressed (duplicate key)`.

---

## 9. Visual design system

### 9.1 Colour tokens

Taken from the requirement mock-ups so the documents and product match. All text/background pairs must meet WCAG 2.1 AA (4.5:1 for text).

| Token | Light | Use |
|---|---|---|
| `--brand-navy` | `#1E3A5F` | Header bar, primary buttons |
| `--p1` | `#B91C1C` | P1 badge, Affected, KEV chip |
| `--p2` | `#EA580C` | P2 badge, EPSS high chip |
| `--p3` | `#B45309` | P3 badge, Possibly affected |
| `--p4` | `#6B7280` | P4 badge |
| `--ok` | `#15803D` | Not affected, healthy feed |
| `--warn` | `#D97706` | Degraded feed, SLA near breach |
| `--info` | `#2563EB` | Links, AI-summary label outline |
| `--teal` | `#0F766E` | Inventory panels, secondary button |
| `--surface` / `--surface-2` | `#FFFFFF` / `#F8FAFC` | Page / card background |
| `--text` / `--text-muted` | `#0F172A` / `#64748B` | Body / labels |

A dark theme redefines the same tokens; priority colours keep their hue but adjust lightness to keep contrast.

### 9.2 Components

| Component | Spec |
|---|---|
| Priority badge | Filled pill, white bold text "P1"…"P4"; tooltip "P1 · Critical — act now · SLA 24 h" |
| Outcome label | Filled label in uppercase: AFFECTED / POSSIBLY AFFECTED / NOT AFFECTED |
| Signal chips | `KEV` (red), `EPSS 0.71` (orange when ≥ 0.5, amber 0.1–0.5, grey < 0.1 — thresholds **[Decision]**), `Internet-facing`, `Tier 1` |
| AI label | Outlined chip "AI summary · {model}/{prompt_version}" on any generated text |
| Fix-type badge | CONFIRMED FIX · MITIGATION ONLY · NO FIX KNOWN · UNVERIFIED |
| Source link | Text + ↗ icon, opens new tab, shows domain on hover; links only from source data |
| Factor bar | Horizontal bar per score factor with numeric contribution printed at the end |
| Freshness indicator | Dot + "Feeds checked N min ago"; green / amber / red per §5 |
| KPI tile | Large number, label below, optional delta vs yesterday; whole tile is a link |
| Empty state | One sentence saying what was checked and when, plus the next action |

### 9.3 Typography and layout

- Inter (or system UI) for text; monospace for CVE IDs, versions and ranges.
- 8 px spacing grid; content max width 1440 px; cards with 12 px radius as in the mock-ups.
- Responsive: KPI tiles wrap 5 → 2 → 1 columns; tables become stacked cards below 768 px with priority, CVE, service and due time kept visible.

### 9.4 Accessibility

- Priority and outcome are always written as text, never colour only.
- Keyboard: every action reachable by Tab; review drawer traps focus; `Esc` closes it; `j/k` moves between queue items.
- Tables use proper header cells; charts have a table alternative.
- Teams cards and emails have plain-text fallbacks; email images are not required to understand content.

---

## 10. Data and API contract for the UI

The UI reads from the same store the fleet writes (vulnerability store + audit log in the solution architecture). The API is read-only except for the UI-owned records listed below.

| Method & path | Returns / does | Backed by |
|---|---|---|
| `GET /api/overview` | KPI tiles, priority counts, SLA status, top exposures, feed health | alerts, review items, feed polls |
| `GET /api/alerts?priority=&status=&owner=&group_by=` | Alert list | `Alert` + status *new* |
| `GET /api/alerts/{id}` | Alert detail incl. breakdown, evidence, references, history | `Alert`, `ScoredMatch`, audit |
| `GET /api/advisories/{cve_id}` | Merged advisory, enrichment with provenance, correlation results | `ExtractedAdvisory` + G-01/G-02/G-04 |
| `GET /api/review?type=&assignee=` | Review items | `NeedsHuman` + G-04/G-07 |
| `GET /api/assets`, `/api/assets/{id}` | Inventory and validation issues | `Asset` + G-03 |
| `GET /api/feeds`, `/api/runs`, `/api/runs/{id}` | Poll history, run trace | `run_report.json` trace + G-01/G-09 |
| `GET /api/audit?advisory_id=&alert_id=` | Event chain | audit log (G-09) |
| `GET /api/deliveries` | Delivery log | outbox (G-08) |
| `GET /api/policy`, `POST /api/policy/simulate` | Policy and side-effect-free score preview | `score()` / `band()` |
| `GET /api/evaluation` | Metrics and scorecard | `evaluate.py` output |
| `POST /api/alerts/{id}/ack` | Record acknowledgement | UI-owned |
| `POST /api/alerts/{id}/dispute` | Create disputed review item | UI-owned |
| `POST /api/review/{id}/decision` | Record decision; confirmed items re-enter the pipeline | UI-owned |
| `POST /api/deliveries/{id}/retry` | Re-queue dead-letter delivery (operator) | UI-owned |
| `POST /api/feeds/poll` | Trigger a Watcher run (operator) | UI-owned |

**Fields the UI needs that today's `Alert` model lacks:** `status`, `correlation_outcome`, `confidence`, `epss`, `references[] {url, source, retrieved_at}`, `impact {business, operational, security}`, `fix_type`, `policy_version`, `created_at`, `delivered_at`, `acknowledged_at/by`, `due_at`, `source_ids[]`. These are covered by G-02, G-04, G-05, G-06, G-07, G-08 and G-09 and should be added to the schemas in phase 1 so both participants build against the same contract.

**Write actions** are authenticated, require a reason where noted, and emit an audit event. No endpoint calls any managed system.

---

## 11. Non-functional UI requirements

| Area | Requirement |
|---|---|
| Performance | Overview and worklist load in < 2 s with 500 open alerts and 50 assets (prototype scale); drawer opens in < 300 ms |
| Freshness | Dashboard data no older than 60 s; header always shows feed check time |
| Consistency | Dashboard totals equal stored alerts and digest totals at the same snapshot (G-10 evidence) |
| Security | Sign-in required (local accounts or Entra ID **[Decision]**); role-based access per §2; CSRF protection on POSTs; source text rendered as inert text (no HTML) because feed content is attacker-controllable (DL-07); secrets never displayed |
| Privacy | Inventory never sent to the LLM; CSV export excludes AI text by default and marks synthetic data as "SYNTHETIC" |
| Audit | Every UI write is an audit event with user, time, before/after |
| Reliability | UI stays usable when a feed or the LLM is down (shows degraded state, not an error page) |
| Deployment | Runs as its own container in Docker Compose with a health check, alongside API/worker/storage (G-10) |

---

## 12. Recommended implementation approach

For a two-person, two-week build in a Python codebase:

- **FastAPI** for the read API and UI-owned writes, sharing the pydantic models in `models.py`.
- **Server-rendered pages (Jinja2 templates + HTMX)** for the dashboard and review queue: no separate JavaScript build, easy to containerise, fast enough for prototype scale. Charts with a small client library (e.g. Chart.js) or plain HTML bars for factor breakdowns.
- **Teams** via incoming webhook with Adaptive Card JSON; **email** via SMTP to an approved relay or a local mail catcher (MailHog) for the demo if credentials are unavailable — the digest and alert are then shown as "transparently stubbed", as the gap plan allows.
- **Fallback if Tier 2 slips:** a Streamlit read-only view over the same API takes about a day and covers S-01/S-02/S-08.

Ownership follows the gap plan split: Participant A — U-1, U-2, U-3, S-08, S-10, S-11; Participant B — S-03, S-04, S-05/S-06, S-07, S-01; jointly — S-09, S-12, design tokens and API contract.

---

## 13. Traceability matrix

| Requirement | Surfaces | How the UI shows evidence |
|---|---|---|
| FR-1 / AC-1 | S-08, S-04 header, S-01 freshness | Per-source poll records, duplicate counts, source chips on merged CVE |
| FR-2 | S-04 enrichment, S-03 Why panel | CVSS/EPSS/KEV with source and retrieval time |
| FR-3 | S-07 | Inventory with owner, criticality, exposure, data class, validation issues |
| FR-4 / AC-2, AC-3, AC-7 | S-04 correlation table, S-05, S-06, S-12 | Three outcomes with confidence; not-affected rows; review before alert |
| FR-5 | U-1, S-03 impact | Three impact dimensions with AI label |
| FR-6 / AC-4 | U-1 "Why P1", S-03, S-11 | Factor breakdown, policy version, override rule |
| FR-7 / AC-5 | U-1, S-03 actions, S-05 uncited | Source link per step; Unverified withheld from owners |
| FR-8 / AC-6 | U-1, U-2, U-3, S-10 | Delivery log with latency; digest |
| FR-9 / AC-8, AC-9 | S-05, S-08, S-09 | Retries, degraded state, full event chain |
| FR-10 | S-01…S-13 | Dashboard; containerised UI |
| AC-10 | S-12 | Measured vs estimated as-is/to-be with sample sizes |

## 14. Demo script mapped to screens

| Scenario | Show in UI |
|---|---|
| S1 New CVE, vulnerable version | Teams card U-1 arrives → open S-03 → Acknowledge → S-01 tile updates |
| S2 Version already fixed | S-04 correlation table: "Not affected · version already fixed"; no message in S-10 |
| S3 Product not used | S-04: "No inventory component uses this product"; no alert |
| S4 Messy inventory name | S-05 item "Possibly affected · conf 0.72" → S-06 confirm → alert sent |
| S5 Added to KEV later | U-1 "Priority raised P3 → P1"; S-03 score history |
| S6 Same CVE from NVD and OSV | S-04 header with two source chips; S-08 duplicate count |
| S7 No fix yet | S-03 fix type "MITIGATION ONLY" with watch note |
| S8 SaaS vendor advisory | S-07 Vendors & SaaS tab → S-03 vendor alert |
| S9 One feed down | S-08 OSV Failing; header amber; other alerts keep arriving |
| S10 Labelled set | S-12 precision/recall with FP/FN tables |

---

## 15. Open UI decisions (to confirm with the 2 Nov scope decisions)

1. Correlation confidence threshold for "possibly affected" (proposed 0.85) and escalation time for provisional P1/P2 review items (proposed 1 h).
2. Whether KEV + internet-facing is a hard P1 override; how the Why panel labels it.
3. P4 routing: digest only, or individual message as well.
4. SLA clock start: first ingestion, first delivery, or analyst confirmation.
5. Digest time and recipients (security lead only, or per owner too).
6. Sign-in method for the demo (local accounts vs Entra ID) and whether owners use the web UI or only Teams/email.
7. Whether Teams Adaptive Card actions (Acknowledge/Dispute in-card) are permitted on the demo tenant, or link-out only.
8. EPSS chip colour thresholds.
9. Whether "Create ticket" appears as a disabled placeholder or is hidden until the stretch integration exists.
