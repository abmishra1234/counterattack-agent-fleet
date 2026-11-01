# Counterstrike Agents Fleet: Architecture

This document describes the system at three levels, following the C4 model:

1. **System context**: who uses the system and which external systems it talks to.
2. **Containers**: the separately running parts of the system.
3. **Components**: the main modules inside the worker and the API.

A sequence diagram follows one scheduled run from feed poll to owner alert, and the last section compares the manual process with the automated workflow.

**Legend.** Solid arrows are active in the default configuration. Dashed arrows are implemented but **off by default** and enabled only by explicit settings and approvals (see [DELIVERY.md](DELIVERY.md) and `.env.example`). The diagrams reflect the code on 1 November 2026.

**Images and sources.** Each diagram is shown as a PNG from [diagrams/](diagrams/), so it displays in any Markdown viewer. The Mermaid source sits under it in a collapsed "Mermaid source" section. After editing a source, regenerate its image, for example `npx -p @mermaid-js/mermaid-cli@11.4.2 mmdc -i diagram.mmd -o docs/diagrams/<name>.png -w 1800 -s 2 -b white`.

## 1. System context

![System context diagram](diagrams/01-system-context.png)

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TB
    analyst["Security analyst<br/>reviews uncertain findings"]
    owner["Application owner<br/>receives alerts and fixes"]
    secteam["Security team<br/>receives P1/P2 alerts and digests"]
    operator["Operator / auditor<br/>runs analyses, checks usage and audit"]

    fleet["<b>Counterstrike Agents Fleet</b><br/>Detects new vulnerabilities, matches them to the<br/>inventory, scores risk, recommends fixes, routes alerts"]

    inventory[("Technology inventory<br/>synthetic, 50 assets (JSON)")]
    nvd["NVD CVE API"]
    kev["CISA KEV catalog"]
    osv["OSV.dev"]
    epss["FIRST EPSS API"]
    llm["Azure OpenAI<br/>(OpenAI-compatible)"]
    email["SMTP email"]
    teams["Microsoft Teams<br/>Workflows webhook"]

    analyst -->|reviews, decides| fleet
    operator -->|starts runs, inspects| fleet
    inventory -->|assets, owners, criticality| fleet
    fleet -.->|polls every 15 min| nvd
    fleet -.->|catalog sync| kev
    fleet -.->|package ranges| osv
    fleet -.->|exploit probability| epss
    fleet -.->|extraction and summaries| llm
    fleet -.->|alerts and digests| email
    fleet -.->|alerts and digests| teams
    email -.-> owner
    teams -.-> owner
    email -.-> secteam
    teams -.-> secteam
```

</details>

| External system | Used for | Default state |
|---|---|---|
| NVD | New and modified CVEs, CVSS, CPE version ranges, references | Off (`PUBLIC_FEEDS_ENABLED`); local fixtures used instead |
| CISA KEV | Known-exploited flag | Off; fixture `kev.json` used instead |
| OSV.dev | Package version ranges and descriptions | Off, with the public feeds |
| FIRST EPSS | Exploit probability (enrichment) | Off (`EPSS_ENABLED`, `EPSS_APPROVED`) |
| Azure OpenAI | Free-text extraction and impact summary wording | Off; offline `FakeLLM` used instead |
| SMTP / Teams | Owner and security alerts, daily digest | Off (`OUTBOX_DELIVERY_ENABLED`) |

## 2. Containers

![Container diagram](diagrams/02-containers.png)

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TB
    user["Analyst / operator<br/>(browser)"]

    subgraph compose["Docker Compose stack"]
        direction TB
        ui["<b>Dashboard</b><br/>static HTML/JS<br/>served by the API"]
        api["<b>API</b><br/>FastAPI + Uvicorn<br/>counterstrike-api<br/>127.0.0.1:8000"]
        worker["<b>Worker</b><br/>counterstrike-worker<br/>job runner, schedulers,<br/>outbox delivery"]
        db[("<b>PostgreSQL 16</b><br/>runs, jobs, advisories,<br/>matches, alerts, reviews,<br/>audit chain, LLM calls, outbox")]
        roles["db-roles<br/>(one-shot)<br/>creates restricted<br/>runtime role"]
        migrate["migrate<br/>(one-shot)<br/>alembic upgrade head"]
        data[("data volume<br/>fixtures, inventory,<br/>aliases, gold labels")]
        out[("output volume<br/>alerts.json, outbox/*.md,<br/>run_report.json")]
    end

    cli["<b>CLI</b><br/>python -m counterstrike run / eval<br/>offline, no database"]
    ext["External feeds, LLM,<br/>email and Teams<br/>(see context diagram)"]

    user -->|HTTPS| ui
    ui -->|/api/v1/* JSON| api
    api -->|SQL, restricted role| db
    api -->|queues run job| db
    worker -->|claims jobs with leases,<br/>writes results + audit| db
    worker -->|reads| data
    worker -->|writes| out
    worker -.->|feeds, LLM, delivery| ext
    roles --> db
    migrate --> db
    cli -->|reads| data
    cli -->|writes| out
```

</details>

| Container | Responsibility | Code |
|---|---|---|
| Dashboard | Overview, alerts, review queue, inventory, runs, sources, LLM usage, audit | `frontend/` |
| API | Versioned REST API, role checks, request audit, manual run queueing, health and metrics | `api.py`, `server.py` |
| Worker | Claims queued jobs, runs the agent pipeline, persists results, delivers outbox messages; hosts the source-poll and daily-digest schedulers | `worker.py`, `source_scheduler.py`, `digest_scheduler.py`, `delivery.py` |
| PostgreSQL | System of record; audit events are hash-chained and cannot be updated or deleted by the runtime role | `db_models.py`, `migrations/` |
| db-roles, migrate | One-shot setup: least-privilege runtime role, then schema migrations as the owner | `db_roles.py`, `alembic.ini` |
| CLI | Offline run and evaluation gate used by CI; same pipeline, file output only | `cli.py` |

`frontend/server.js` is an older standalone preview server that reads the CLI's `out/` files. The API now serves the dashboard directly.

## 3. Components

### 3a. Agent pipeline (inside the worker and the CLI)

The pipeline is a fixed LangGraph state graph. Routing is code; the LLM is called only inside **Extract** (free-text bulletins) and **Remediate** (summary wording), and it can never set a match, score, priority, owner or fix.

![Agent pipeline component diagram](diagrams/03a-agent-pipeline.png)

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TB
    ingest["<b>1 Ingest</b> (Feed Watcher)<br/>load feeds, KEV, inventory, aliases; dedupe by CVE ID"]
    extract["<b>2 Extract</b><br/>structured ranges by code; free text by LLM, grounding-checked"]
    correlate["<b>3 Correlate</b><br/>product + version range vs inventory:<br/>affected / possible / not affected"]
    score["<b>4 Score</b><br/>CVSS + KEV + exposure + criticality (+EPSS) → P1–P4 + SLA"]
    remediate["<b>5 Remediate</b><br/>fix from source data; impact summary, fact-checked"]
    dispatch["<b>Dispatch</b><br/>alerts, owner outbox, needs-human list, run report"]
    human[["Human review queue<br/>(needs_human)"]]

    ingest --> extract
    extract -->|something extracted| correlate
    extract -->|nothing extracted| dispatch
    correlate -->|matches| score
    correlate -->|no matches| dispatch
    score --> remediate --> dispatch
    extract -.->|unclear bulletin| human
    correlate -.->|possible match| human
    score -.->|KEV status unknown| human
    human --> dispatch
```

</details>

Dotted arrows here show items routed to an analyst; they are not alerted.

| Stage | Supporting modules | What they provide |
|---|---|---|
| 1 Ingest | `sources.py`, `inventory.py` | Fixture, NVD, KEV, OSV and EPSS adapters with checkpoints; inventory contract 1.0 validation |
| 2 Extract | `guards.py`, `llm.py` | Injection detection and grounding checks; `LLMPort` (FakeLLM or audited gateway) |
| 3 Correlate | `versions.py` | PEP 440 ranges, `\|\|` range unions, tolerant parsing |
| 4 Score | `risk_policy.py` | Versioned policy, KEV + internet-facing → P1, EPSS gate |
| 5 Remediate | `guards.py`, `llm.py` | Summary fact checks with template fallback |
| Dispatch | `dispatch.py` | File outputs for the CLI and run trace |
| (LLM calls) | `llm_metering.py`, `artifacts.py` | Encrypted prompts and responses, tokens, cost, budgets |

After the graph finishes, the worker hands the final state to **repositories.py**, which saves everything in one transaction: advisories, inventory snapshot, matches, alerts, review cases, the run summary, audit events and outbox rows.

### 3b. API

![API component diagram](diagrams/03b-api-components.png)

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart LR
    client["Dashboard / API client"]

    subgraph apimod["API (api.py)"]
        direction TB
        mw["Request middleware<br/>request ID, JSON logs,<br/>secret redaction"]
        authz["Capability gate<br/>roles → read, review, run,<br/>usage, audit, delivery,<br/>LLM content; unmapped = deny"]
        reqaudit["Request audit<br/>start/finish events;<br/>fail closed if audit<br/>cannot be written"]
        subgraph routes["/api/v1 routes"]
            direction TB
            r1["dashboard, alerts,<br/>alert detail"]
            r2["reviews + decisions"]
            r3["runs (queue, history,<br/>trace), sources"]
            r4["inventory"]
            r5["LLM usage, report,<br/>budgets, content"]
            r6["audit events,<br/>integrity, deliveries"]
        end
        health["/health/live, /health/ready,<br/>/metrics"]
    end

    repo["repositories.py<br/>run lifecycle, results"]
    audit["audit.py<br/>append-only<br/>SHA-256 chain + verifier"]
    art["artifacts.py + key_providers.py<br/>AES-256-GCM artifact<br/>decrypt, access records"]
    db[("PostgreSQL")]

    client --> mw --> authz --> reqaudit --> routes
    client --> health
    r3 --> repo
    r2 --> audit
    r5 --> art
    r6 --> audit
    routes --> db
    repo --> db
    audit --> db
    art --> db
```

</details>

## 4. One scheduled run, end to end

![Sequence diagram of one scheduled run](diagrams/04-scheduled-run-sequence.png)

<details>
<summary>Mermaid source</summary>

```mermaid
sequenceDiagram
    autonumber
    participant S as Source scheduler (worker)
    participant DB as PostgreSQL
    participant W as Worker job runner
    participant F as Feeds (NVD, KEV, OSV, EPSS)
    participant G as Agent pipeline
    participant O as Outbox delivery (worker)
    participant C as Email / Teams
    participant A as Owner / security team

    S->>DB: Every 15 min: insert run + job (unique per window)
    W->>DB: Claim job with lease, heartbeat
    W->>DB: Load source checkpoints
    W->>G: Run graph with run context
    G->>F: Poll NVD window, sync KEV, look up OSV / EPSS
    F-->>G: Advisories, ranges, KEV IDs, scores
    G->>G: Extract → correlate → score → remediate
    G-->>W: Alerts, matches, review items, trace
    W->>DB: One transaction: results, checkpoints, audit events, outbox rows
    O->>DB: Lease next outbox message
    O->>C: Send alert (P1/P2 also to security)
    C-->>A: Alert with priority, SLA, fix, evidence
    O->>DB: Record delivery outcome + audit event
```

</details>

Steps 5 and 11 to 13 only happen when public feeds and outbox delivery are enabled. In the default configuration the pipeline reads the local fixtures and alerts stay in the outbox.

## 5. Manual process vs automated workflow

Orange steps are done by people today. Green steps are done by the agents. Blue is the only step left for an analyst, and only for uncertain matches. The manual lane is an assumption until the security team confirms it; see [PROCESS_IMPROVEMENT_PROPOSAL.md](PROCESS_IMPROVEMENT_PROPOSAL.md) for the baseline still to be collected.

![Manual process vs automated workflow](diagrams/05-manual-vs-automated.png)

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TB
    subgraph asis["AS-IS: manual process (assumed, to be confirmed with the security team)"]
        direction LR
        m1["<b>1 Discover</b><br/>Analyst reads NVD, KEV,<br/>vendor bulletins, mailing lists<br/><i>when time allows</i>"]
        m2["<b>2 Identify relevance</b><br/>Search CMDB, ask app<br/>teams which versions run"]
        m3["<b>3 Assess</b><br/>Mostly CVSS; exposure and<br/>criticality looked up by hand"]
        m4["<b>4 Recommend</b><br/>Read the advisory for<br/>fixed version, workaround"]
        m5["<b>5 Notify</b><br/>Email or ticket<br/>to the owning team"]
        m1 --> m2 --> m3 --> m4 --> m5
    end

    subgraph tobe["TO-BE: Counterstrike agents fleet"]
        direction LR
        a1["<b>1 Ingest agent</b><br/>Polls NVD, KEV, OSV<br/>every 15 min; dedupes<br/>by CVE ID"]
        a2["<b>2 Extract + Correlate</b><br/>Product and version ranges<br/>matched to inventory in code"]
        a3["<b>3 Score</b><br/>CVSS + KEV + exposure +<br/>criticality → P1–P4 + SLA"]
        a4["<b>4 Remediate</b><br/>Fix taken from source record;<br/>summary fact-checked"]
        a5["<b>5 Dispatch</b><br/>Alert to owner by email/Teams;<br/>P1/P2 also to security"]
        a1 --> a2 --> a3 --> a4 --> a5
        rev[["Analyst reviews<br/>uncertain matches only"]]
        a2 -.->|possible match| rev
        rev -.->|decision| a5
    end

    asis ~~~ tobe

    classDef manual fill:#fde7d9,stroke:#c2410c,color:#1f2937
    classDef auto fill:#dcfce7,stroke:#15803d,color:#1f2937
    classDef human fill:#dbeafe,stroke:#1d4ed8,color:#1f2937
    class m1,m2,m3,m4,m5 manual
    class a1,a2,a3,a4,a5 auto
    class rev human
```

</details>
