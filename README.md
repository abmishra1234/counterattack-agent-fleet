# Counterstrike Lite — sample solution

A five-agent fleet that reads a vulnerability feed, works out which of your assets are affected, ranks them by real exposure, and writes an owner-ready alert for each one. Scaled-down POC of *Project Counterstrike: Agent Fleet*.

```
feed + KEV + inventory
        │
  1 Feed Watcher ──► 2 Extractor (LLM, grounded) ──► 3 Correlator ──► 4 Risk Scorer ──► 5 Remediation Writer ──► Dispatcher
                            │                              │                                                  │
                            └── needs_human.json           └── no matches ──────────────────────────────────► outbox/
```

## Run it

```bash
pip install -e ".[dev]"
python -m counterstrike run  --data data --out out          # offline, deterministic FakeLLM
python -m counterstrike eval --out out                       # gate: exits 1 on any regression
pytest --cov=counterstrike
```

Live model (any OpenAI-compatible gateway):

```bash
export LLM_BASE_URL=https://<gateway>/v1 LLM_API_KEY=... LLM_MODEL=<model>
python -m counterstrike run --llm gateway --out out-llm
```

## Outputs (`out/`)

| File | What it is |
|---|---|
| `alerts.json` | One alert per (CVE, asset): priority, SLA, risk score + breakdown, fix, evidence |
| `outbox/<owner>.md` | The same alerts grouped per engineering owner, ready to forward |
| `needs_human.json` | Advisories the fleet refused to guess about, with the reason |
| `run_report.json` | Counts and a per-agent trace (timings, LLM calls, prompt version, injection flags) |
| `scorecard.md` | Written by `eval` |

Expected result on the fixtures: 5 alerts — P1 log4j on payments-api, P2 openssl on client-portal, P2 pillow on doc-scanner (KEV), P3 jinja2 on reporting-ui, P4 requests on kyc-service (the injection fixture) — and CVE-2099-0008 routed to a human.

## Layout

```
src/counterstrike/
  models.py        typed contracts + LangGraph state
  agents/          ingest, extract, correlate, score, remediate
  dispatch.py      outbox writer
  graph.py         LangGraph wiring (conditional edges)
  llm.py           LLMPort, FakeLLM, GatewayLLM
  guards.py        injection detection, grounding checks
  versions.py      tolerant version parsing, PEP 440 ranges
  evaluate.py      metrics + release gate
data/              synthetic feed, inventory, KEV list, aliases, gold labels
grading/           trainer-only hidden fixture set (do not share with students)
tests/             unit, guard, end-to-end and public contract tests
.github/workflows/ci.yml
DECISION_LOG.md
```

All CVE IDs are synthetic (`CVE-2099-xxxx`); none describe real vulnerabilities.
