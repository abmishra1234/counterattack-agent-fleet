# Counterstrike Practical UI Specification

| Item | Detail |
|---|---|
| Purpose | Define a small, buildable UI for demonstrating vulnerability triage and owner-ready alerts |
| Status | Proposed prototype scope; confirm unresolved policy and delivery choices with the mentor |
| Requirement source | `requirement/Counterstrike_Agents_Fleet_Requirements.docx`, FR-1–FR-10 and AC-1–AC-10 |
| Implementation baseline | `planning/UPDATED_REQUIREMENT_GAP_PLAN.md`, `src/counterstrike/models.py`, `src/counterstrike/dispatch.py`, `out/` |
| Target date | 16 November 2026, per requirement document |

## 1. Purpose and product boundary

The UI should help a security analyst answer three questions quickly: **what needs attention, why was it flagged, and what should happen next?** It should also let the demo team show whether feeds and alert delivery are working. The design is intentionally limited to the prototype; it does not assume an enterprise SOC console or a fully integrated CMDB.

The current implementation is a command-line pipeline that reads local JSON and writes `alerts.json`, `needs_human.json`, `run_report.json` and per-owner Markdown. It has no browser UI, persistent alert status, user identity, API, acknowledgement workflow or delivery service. Any interactive UI therefore depends on implementation work in the gap plan. The screens below make those dependencies visible instead of presenting them as already available.

### Scope priorities

| Priority | UI scope | Requirement mapping |
|---|---|---|
| **Must for the prototype** | Owner-ready alert content; analyst review of uncertain items; basic run/feed status; human-readable explanation, evidence and source links; clear delivery status | FR-4, FR-7, FR-8, FR-9; AC-5–AC-9 |
| **Should if time permits** | One exposure overview and a searchable alert list/detail; read-only inventory summary | FR-10; supports AC-1, AC-4, AC-10 |
| **Later / stretch** | Interactive policy simulator, evaluation portal, inventory editing/import, tickets, user administration, trend analytics | FR-10 stretch; mentor approval required |

The Must alert path can be demonstrated with a local dashboard plus a rendered Teams/email preview when credentials or approved endpoints are unavailable. A preview must be labeled **Preview** or **Not sent**; it must never imply successful delivery.

## 2. Users and primary tasks

| User | Main task | UI access for prototype |
|---|---|---|
| Security analyst | Review uncertain matches, inspect evidence and record a disposition | Review queue and item detail |
| Application owner | Understand affected service, urgency, evidence and remediation | Alert message or alert detail; acknowledgement is optional until identity and storage exist |
| Security lead / evaluator | See current exposure and whether the latest run completed | Overview, alert list and run status |
| Prototype operator | Run the CLI, inspect outputs and diagnose failed feeds/delivery | Run status and output links; no production operations console |

Do not imply role-based access control or user sign-in until an identity provider and authorization rules are implemented. For a local demo, use seeded sample users or a read-only shared dashboard and explain that access control is out of scope.

## 3. Navigation and screen set

Use four main destinations. They can be tabs in a lightweight dashboard or routes in a small web application; avoid a separate page for every data type.

1. **Overview** — key counts, latest run, feed freshness and priority distribution.
2. **Alerts** — searchable/filterable list with a focused detail panel.
3. **Needs review** — unresolved or low-confidence items with evidence and a disposition form.
4. **Run status** — feed results, pipeline counts, warnings and links to generated output files.

Inventory, policy, evaluation, notifications history and audit can begin as read-only sections within these pages or remain as downloadable artifacts. Add dedicated navigation only when a user task requires it.

### Global frame

Use a familiar security operations layout rather than a collection of unrelated cards:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Counterstrike   Vulnerability Operations             LOCAL DEMO   ● Updated  │  64 px top bar
├─────────────────┬────────────────────────────────────────────────────────────┤
│  Overview       │  Breadcrumb / page title                 [Run status]     │
│  Alerts      08 │  Main page content                                        │
│  Needs review 02│                                                            │
│  Run status     │                                                            │
│                 │                                                            │
│  Counterstrike  │                                                            │
│  Prototype      │                                                            │
└─────────────────┴────────────────────────────────────────────────────────────┘
   240 px sidebar                  Flexible content area
```

- **Top bar:** product mark/name at left; environment badge and last successful run at right. Keep global search out of the first release unless it can search all displayed fields reliably.
- **Sidebar:** four labeled destinations with simple line icons and open-item counts. Highlight the current page with a pale blue background and a 3 px blue left edge. Keep the sidebar fixed on desktop; collapse it behind a menu below 900 px.
- **Content area:** use a 12-column grid, 24 px gutters, 32 px page padding and a 1440 px maximum content width. Page title and one-sentence description come before filters, metrics or tables.
- **Freshness:** show `Last run 10:15 · Completed` in the top bar. A stale or partial run adds a full-width amber/red notice below the page title with a link to Run status.
- **Typography:** use system UI/Inter. Page titles 26 px/600; section titles 16–18 px/600; body 14–16 px; table labels 12–13 px. Use a monospace face for CVE IDs, versions and asset IDs.
- **Density:** prefer a compact, readable operations view. Avoid oversized hero graphics, gradients, decorative charts and multiple competing accent colors.
- **Responsive behavior:** desktop-first, usable at 768 px. At narrow widths, sidebar becomes a menu, metric cards become a 2-column grid, and tables collapse into rows with priority, advisory, service and status visible first.
- **Color is never the only signal:** every severity, health or outcome color is paired with a text label and, where useful, an icon.

## 4. Screen requirements

### 4.1 Overview

**Question answered:** Is the fleet working, and how many items need attention?

```text
Overview  /  Vulnerability exposure
Monitor new findings, review decisions and the latest fleet run.

┌ 3 Needs action ┐ ┌ 8 Open alerts ┐ ┌ 2 Needs review ┐ ┌ 2/3 Feeds healthy ┐
│ 1 priority P1  │ │ 1 priority P1 │ │ Oldest: 2 h    │ │ OSV last failed  │
└────────────────┘ └───────────────┘ └────────────────┘ └──────────────────┘

┌ Open alerts by priority ─────────────────┐ ┌ Latest run ───────────────────┐
│ P1  █ 1                                  │ │ Completed · 10:15             │
│ P2  ███ 3                               │ │ 8 ingested · 5 matched · 8     │
│ P3  ███ 3                               │ │ alerts · 2 items need review  │
│ P4  █ 1                                  │ │ [View run details]             │
│ [View all alerts]                        │ └───────────────────────────────┘
└──────────────────────────────────────────┘

┌ Highest priority alerts ────────────────────────────────────────────────────┐
│ P1  CVE-…  log4j-core  payments-api  team-payments  Affected  [Open →]       │
│ P2  CVE-…  openssl     client-portal team-digital   Affected  [Open →]       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Rules**

- Each count links to the matching filtered list.
- Show only counts that can be calculated from the current data. If acknowledgement, SLA aging or delivery status is not stored, omit those metrics instead of estimating them.
- Display “No run yet” and “No alerts in this run” as distinct empty states.
- For the file-based MVP, counts are derived from the latest `run_report.json`, `alerts.json` and `needs_human.json`.
- Layout: four equal metric cards across the top; below, a two-thirds/one-third split for priority distribution and latest run; a full-width priority alert table follows. Cards use white backgrounds, a thin cool-gray border and a small colored icon/accent, not a full saturated fill.
- Priority distribution uses labeled horizontal bars. It is a navigation aid, not a substitute for exact counts or the alert list.

### 4.2 Alerts list and detail

**Question answered:** Which assets are affected, what is the priority, and what evidence supports the action?

List columns: Priority · CVE/advisory ID · Product · Service/asset · Installed version · Owner · Status. Default sort is priority, then risk score descending. Filters: priority, owner, product, and status. Search matches advisory ID, product, asset ID and service. Keep filters in the URL or provide a visible **Clear filters** action.

Page layout: title and result count at top; one filter/search row beneath; priority summary chips; then a full-width table. Use a sticky table header and subtle row dividers. Selecting a row opens a 440 px right-side detail drawer on wide screens; on smaller screens the detail becomes its own page. Do not make an entire dense table row the only keyboard-accessible control.

```text
Alerts  /  8 findings
[Search CVE, product, service…] [Priority ▾] [Owner ▾] [Status ▾] [Clear]
[All 8] [P1 1] [P2 3] [P3 3] [P4 1]
┌────┬─────────────┬───────────┬───────────────┬───────────┬──────────────┐
│Pri │ Advisory    │ Product   │ Service       │ Version   │ Owner        │
├────┼─────────────┼───────────┼───────────────┼───────────┼──────────────┤
│ P1 │ CVE-…       │ log4j-core│ payments-api  │ 2.14.1    │ team-payments│
│ P2 │ CVE-…       │ openssl   │ client-portal │ 3.0.6     │ team-digital │
└────┴─────────────┴───────────┴───────────────┴───────────┴──────────────┘
```

Selecting a row opens an inline side panel (or a detail route) with sections in this order:

1. **Decision:** Affected / Possibly affected / Needs review; priority and SLA; clearly distinguish computed facts from unresolved uncertainty.
2. **Affected asset:** service, component, installed version, owner, exposure and criticality where available.
3. **Why this priority:** score and factor breakdown from the scorer. If a value is missing, label it “Unavailable”; do not display a guessed value.
4. **Recommended action:** fixed version or mitigation and its status (confirmed fix / mitigation / no fix known). Each recommendation must link to a source. If citations are not available, label the action **Unverified** and do not present it as a confirmed vendor instruction.
5. **Evidence and sources:** affected range, inventory evidence, advisory source/reference links, and any version parsing note.
6. **Activity:** show only events that are actually recorded. Do not invent an acknowledgement or delivery timeline.

Drawer visual hierarchy: top strip contains a compact priority badge, advisory ID and close button; the affected service and component form the main heading; an amber/blue “Affected” state sits beside it. Place the score and SLA in a light-blue summary panel. Use clear section headers and divider spacing rather than nested tabs. Source links appear as ordinary underlined links with a small external-link icon.

Available prototype actions: **Open source**, **Copy alert link** (when a stable route exists), and **Mark reviewed** only after a persisted review/status model is implemented. Do not expose “Acknowledge,” “Resolve,” “Retry delivery,” or “Create ticket” as working buttons until their backend behavior exists. A disabled button is less useful than a clear status note.

### 4.3 Needs review

**Question answered:** What did the system decline to decide, and what information does an analyst need?

Each row shows advisory ID, review reason, known product (if any), affected asset (if any), created/run time and review status. Group duplicate review reasons for the same advisory while retaining the underlying evidence. Default sort is oldest first, with any provisional high-risk case pinned only if a deterministic score exists.

Use a two-column workbench: a 35% review list on the left and the selected item's evidence on the right. The selected row has a pale blue background and a blue edge. Show review reason in amber text on a pale amber background, not as a red severity badge. With no selected item, show a short prompt to choose an item; with no open items, show “No advisories need review.”

The detail view shows the raw bulletin as inert text, model output if present, grounding/validation reason, possible inventory candidates and source references. It must not render advisory HTML. The UI must not present a raw model suggestion as a confirmed fact.

**Decision form (only when review persistence is implemented):**

- **Confirm affected** — requires analyst identity and rationale; sends the item through the normal code-owned scoring path.
- **Not affected** — requires a reason (version outside range, product not present, alias mismatch, other); stores the decision and suppresses an owner alert.
- **Need more information** — keeps the item open and requires a short note.
- **Withhold advice** — appropriate when evidence or citations are insufficient.

Until the review record and audit event are persisted, use a read-only review view and demonstrate dispositions with a clearly marked fixture. Never make a UI-only decision that disappears on refresh.

When decisions are enabled, show the rationale text area directly below the evidence and keep the decision buttons together at the bottom of the panel. **Confirm affected** is the primary blue action; **Not affected** and **Need more information** are secondary outline actions. Require confirmation before closing an item. Do not use a destructive red button for an ordinary “Not affected” decision.

### 4.4 Run status

**Question answered:** What ran, what failed, and can the operator trust this result?

Show one row per enabled feed when feed polling is implemented: source, status, last attempt, last success, new/updated/duplicate counts and concise error. Before that exists, label local input files as **Fixture inputs**; do not show scheduled poll times or pretend the local JSON files are live feeds.

Arrange the page in three stacked regions: (1) a run summary banner with status, start/end time and trigger; (2) source/feed cards or table; (3) a horizontal pipeline stepper with one segment per agent and expandable details. Failed/degraded components use an amber or red outline and include a short explanation plus the last successful time. Keep raw trace JSON behind a **View details** disclosure.

Show the latest pipeline trace using actual `run_report.json` entries: agent, counts and duration. Add warnings for missing output files, failed nodes or incomplete runs. Link to `alerts.json`, `needs_human.json`, `run_report.json` and `scorecard.md` when present.

**Freshness states**

| State | Display |
|---|---|
| Current | Latest run completed; show timestamp |
| Stale | No completed run within the configured interval; show last successful time |
| Partial | Some input/source/agent failed; show which parts completed and which did not |
| No data | No run artifacts exist yet; provide the documented CLI command |

Do not add a **Poll now** button until the scheduler/feed-adapter path exists. For the current app, the useful operator instruction is the exact CLI command to run the local pipeline.

## 5. Alert and digest content

The message format must remain useful in plain text and narrow Teams/email clients. It should state the decision first, then the next step and evidence.

```text
[P1] CVE-… affects payments-api

Status: Affected · Priority: P1 · SLA: 24 hours
Component: log4j-core 2.14.1
Owner: team-payments

Why it matters: CVSS …; KEV: Yes; Internet-facing: Yes; criticality: High.
Recommended action: Upgrade to … . [Vendor advisory] [NVD]
Evidence: installed version is within …

Open alert details: <link, when available>
Advice only. Counterstrike did not change the service.
```

- Never ship the sample CVE/product/score values above as live facts; render from the alert record.
- A source link must be a validated HTTP(S) URL from feed data. A missing citation produces **Source unavailable / needs review**, not an invented link.
- Add generated text only when the current grounding checks pass. Mark generated impact wording **AI summary** and keep it separate from the code-owned match, score and SLA.
- Include an owner acknowledgement action only after identity, persistence and audit behavior are implemented. Until then, the owner receives the information and uses the agreed human process.
- Daily digest is a later delivery capability. Its preview may be shown, but totals must be derived from the same alert snapshot and labeled with the snapshot time.

## 6. Shared status language

Use these labels consistently in the list, detail and messages:

| Label | Meaning | Owner notification |
|---|---|---|
| **Affected** | Product and version evidence meet the approved matching rule | Eligible for alert, subject to review/routing policy |
| **Possibly affected** | Evidence is incomplete or match confidence is below the approved threshold | No confirmed owner alert until reviewed |
| **Not affected** | Deterministic evidence excludes the installed product/version | No alert |
| **Needs review** | Extraction, source evidence or inventory is insufficient for a safe decision | Analyst queue |
| **Unverified advice** | A recommendation lacks sufficient source support | Do not display as a confirmed fix |
| **Delivery status unknown** | No delivery adapter/status record exists | Never say Sent or Delivered |

“Not affected” must not be used as a synonym for “no match found” when inventory or advisory data is incomplete.

Alert acknowledgement, dispute, resolution and delivery are separate states. Do not combine them into a single “status” field in the UI. For the first demo, alert records can be read-only; add lifecycle controls only alongside the persistence and audit changes in the gap plan.

## 7. Prototype data contract

### Available now

- `Alert`: advisory ID, asset/service/component/version, fixed version, risk score, priority, SLA hours, owner, summary, remediation, evidence.
- `NeedsHuman`: advisory ID, stage and reason.
- `run_report.json`: counts and per-agent trace.
- `needs_human.json`, `alerts.json`, `scorecard.md`: generated output files.
- `Asset`: service, component, version, internet exposure, criticality and owner.

### Required before richer UI behavior

| UI behavior | Backend data/persistence needed |
|---|---|
| Live feed freshness and history | Feed poll records, checkpoint, timestamps and per-source result/error |
| Multi-source advisory detail | Source identity, source references, retrieval timestamps and normalized enrichment |
| Confidence and three-way outcomes | Correlation outcome, confidence value, explanation and threshold/policy version |
| EPSS and richer risk rationale | EPSS value/percentile/source time and versioned score policy |
| Cited remediation | Recommendation evidence-to-reference mapping and fix type |
| Acknowledgement/dispute/review | Persistent user action records, actor identity, reason, timestamps and append-only audit events |
| Successful delivery status | Outbox records per channel/recipient, idempotency key, attempt history and delivery receipt |
| SLA age/history | Stable created/delivered timestamps and status transition history |

For an interactive prototype, use a small persistence layer (SQLite is sufficient for a single-user local demo) for review decisions, delivery attempts and audit events. Keep generated source/advisory content in a separate normalized store or file layer. Do not use `out/` JSON as the only mutable database once users can change statuses.

## 8. Practical implementation recommendation

Choose one UI implementation path and keep it small. For the current repository and target date, a **single local web app** is the preferred end state, with the existing CLI pipeline retained as the worker. Use simple server-rendered pages or a lightweight dashboard over a small read API; avoid introducing a separate frontend application unless the team already has one. The UI should read stable serialized output and a small SQLite table for human decisions and delivery status.

Suggested build sequence:

1. **Read-only shell:** Overview, Alerts/detail, Needs review, Run status reading current output files. This demonstrates the existing system without changing alert logic.
2. **Contract completion:** add source URLs, confidence/outcome, EPSS and policy version to models as the backend work lands; render missing fields honestly.
3. **Human review persistence:** add the decision form only after actions survive refresh and appear in the audit trail.
4. **Delivery:** render Teams/email previews first, then wire approved channels with idempotent status records; show sent status only from a delivery receipt.
5. **Polish:** responsive layout, keyboard access, empty/error states, and evaluator-facing links.

Do not block the backend work to create mock pages for all proposed future screens. A smaller working alert and review flow is more useful than a broad dashboard filled with unimplemented controls.

## 9. Visual and accessibility rules

### 9.1 Professional color palette

Use a cool, trustworthy enterprise palette: deep navy for the application frame, clear blue for primary actions and links, teal for supporting accents, and soft cool grays for page surfaces. Reserve red, orange and amber for priority or operational status. The overall page should remain mostly light and calm; saturated colors belong on small badges, icons and thin accents rather than large panels.

| Token | Hex | Use |
|---|---|---|
| `navy-900` | `#172B4D` | Sidebar and top-bar background; white text/icons |
| `blue-700` | `#1D4ED8` | Primary buttons, selected navigation edge, links, keyboard focus |
| `blue-050` | `#EFF6FF` | Selected row, selected navigation background, info panel |
| `teal-700` | `#0F766E` | Secondary accent, inventory/source icon; not used to signal severity |
| `page-bg` | `#F4F7FB` | Overall workspace background |
| `surface` | `#FFFFFF` | Cards, drawers and table surface |
| `border` | `#D9E2EC` | Card edges, separators and table rules |
| `text-primary` | `#172B4D` | Main text |
| `text-secondary` | `#52657A` | Supporting labels and metadata |
| `p1` | `#B42318` | P1 badge and urgent state; pair with pale red `#FEE4E2` |
| `p2` | `#C2410C` | P2 badge; pair with pale orange `#FFEDD5` |
| `p3` | `#A16207` | P3 badge; pair with pale amber `#FEF3C7` |
| `p4` | `#475569` | P4 badge; pair with pale slate `#E2E8F0` |
| `success` | `#15803D` | Healthy / completed state; pair with pale green `#DCFCE7` |
| `warning` | `#A16207` | Degraded / needs attention; pair with pale amber `#FEF3C7` |
| `error` | `#B42318` | Failed state; pair with pale red `#FEE4E2` |

**Usage rules:**

- Sidebar and top bar use navy with white text. Active navigation uses `blue-050`, `blue-700` text and a narrow `blue-700` edge.
- Primary buttons use `blue-700` with white text. Secondary buttons use a white background, `border` outline and navy text. Links use `blue-700` and remain underlined on hover/focus.
- P1–P4 badges use the matching dark foreground on a pale tinted background; use bold text such as `P1 · Critical`. Do not use white-on-saturated red/orange for small text.
- Affected uses a pale red/rose treatment only when it represents an actual confirmed finding. Possibly affected / Needs review uses amber. Not affected uses pale green. Informational metadata uses blue or slate.
- Healthy, degraded and failed feed states pair a colored dot with the word **Healthy**, **Degraded** or **Failed**. Keep the dot at least 8 px and never rely on it alone.
- Keep card backgrounds white, with 1 px borders and subtle shadows only on floating elements such as the detail drawer. Avoid gradients and color-filled metric cards.

### 9.2 Layout, typography and components

- Use an 8 px spacing scale: 8 px within compact controls, 16 px between related elements, 24 px between sections, and 32 px page padding.
- Cards have 8 px corner radius; the side drawer has a subtle shadow and a fixed width near 440 px. Buttons and inputs are at least 40 px high.
- KPI cards show a small label, a large count and one supporting fact. Use a thin 3 px top accent or colored icon rather than a large colored background.
- Tables use 48 px rows, 12–14 px text, a pale slate header row and light horizontal separators. Highlight hover with `#F8FAFC`; selected row uses `blue-050`.
- Priority badges, outcome labels and AI-summary labels have distinct shapes and text. Do not make the AI label look like severity.
- Keep CVE IDs, version numbers/ranges and asset IDs in monospace. Truncate long text with a visible title/expand action; never truncate the recommendation or source URL without a way to inspect it.

### 9.3 Accessibility and page states

- Target WCAG AA contrast for text and controls. Pair every color-coded state with text and use visible keyboard focus (`2 px` blue outline with offset).
- Use semantic headings, table headers, labeled form controls and keyboard-operable navigation. Dialog/drawer focus behavior is required only when those interactive patterns are implemented.
- Render feed text as plain text to prevent markup/script execution. Escape user-provided owner, service and product strings.
- Provide loading, empty, stale, partial-failure and error states. Errors explain what failed and what to do next without exposing tokens or raw internal exceptions.
- Avoid decorative charts when the sample is small; use labeled counts and a plain-language explanation instead.

## 10. Acceptance checks for the UI

| Check | Pass condition |
|---|---|
| Alert comprehension | Reviewer can identify affected asset, priority, due time, recommendation and evidence from the first detail view |
| Decision transparency | Every priority links to the actual factor values and policy version; missing data is explicit |
| Uncertainty handling | Possible/unknown cases are visibly separate from confirmed affected and not affected cases |
| Source support | Recommendation links resolve to source records; unsupported advice is labeled and routed for review |
| Honest delivery | UI distinguishes preview, queued, sent, failed and unknown based on recorded state |
| Operational honesty | Local fixture inputs are not represented as live polling; partial failures remain visible |
| Human review | If decision controls are enabled, a decision persists after reload with actor, rationale and audit event |
| Read-only boundary | No action changes a managed asset or triggers patch/configuration changes |
| Small-screen/accessibility | Core list and detail tasks work with keyboard and at the agreed demo viewport |
| Requirement traceability | Screens provide evidence for FR-4, FR-5, FR-6, FR-7, FR-8, FR-9 and AC-5–AC-9, with FR-10 dashboard elements identified as Should |

## 11. Decisions to confirm

1. Is the first demonstration strictly local, or must it send a real Teams/email message?
2. Which users and roles are in the prototype, and is authentication required for the demo?
3. Which alert status actions are in the delivery scope: acknowledge, dispute, or only review an uncertain advisory?
4. Should an analyst confirmation immediately create an alert, or require a second reviewer for high-risk items?
5. Which fields and sources are guaranteed in the first release? The UI can progressively reveal EPSS, references and confidence when they are available.
6. Should the dashboard be delivered if time is short, or should the team prioritize notifications and review persistence?

## 12. Requirement traceability

| Requirement | UI evidence |
|---|---|
| FR-1 / AC-1 | Run status shows per-source timestamps and poll outcome once live adapters exist; local fixture mode is labeled honestly |
| FR-2 | Alert/advisory detail shows CVSS, EPSS, KEV, affected range and reference provenance when available |
| FR-3 | Affected asset detail shows product, version, owner, criticality, exposure and data class when supplied |
| FR-4 / AC-2, AC-3, AC-7 | Alerts and Needs review distinguish affected, possible, not affected and unknown; confidence is shown when computed |
| FR-5 | Alert detail/message shows a clearly labeled, evidence-grounded impact summary |
| FR-6 / AC-4 | Priority explanation lists the actual risk factors, policy version and approved override |
| FR-7 / AC-5 | Remediation shows source links; unsupported advice is marked unverified and withheld from confirmed guidance |
| FR-8 / AC-6 | Alert/digest format is owner-ready; delivery state and latency appear only when recorded |
| FR-9 / AC-8, AC-9 | Review queue, run status and audit events show uncertainty, retries and partial failures |
| FR-10 | Overview and read-only alert worklist comprise the Should dashboard; Docker/CI is covered by the gap plan |
| AC-10 | Evaluation/proposal view is later scope; metrics must identify sample size and measured vs estimated values |
