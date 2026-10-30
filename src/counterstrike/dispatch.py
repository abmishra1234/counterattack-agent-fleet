"""Dispatcher: writes the outbox. It never sends email/chat - delivery is out of scope."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

from counterstrike.models import FleetState

PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def dispatch_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    out = Path(state["out_dir"])
    (out / "outbox").mkdir(parents=True, exist_ok=True)
    alerts = sorted(
        state.get("alerts", []),
        key=lambda a: (PRIORITY_ORDER[a.priority], -a.risk_score, a.alert_id),
    )
    _write(out / "alerts.json", [a.model_dump() for a in alerts])
    _write(out / "needs_human.json", [n.model_dump() for n in state.get("needs_human", [])])

    by_owner = defaultdict(list)
    for a in alerts:
        by_owner[a.owner].append(a)
    for owner, items in by_owner.items():
        lines = [f"# Security alerts for {owner}", ""]
        for a in items:
            lines += [
                f"## {a.priority} - {a.cve_id} on {a.service} ({a.asset_id})",
                f"- Risk score: {a.risk_score}  |  SLA: {a.sla_hours} h",
                f"- {a.summary}",
                f"- Action: {a.remediation}",
                "- Evidence: " + "; ".join(a.evidence),
                "",
            ]
        (out / "outbox" / f"{owner}.md").write_text("\n".join(lines), encoding="utf-8")

    trace = [
        *state.get("trace", []),
        {
            "agent": "dispatch",
            "owners": len(by_owner),
            "ms": round((time.perf_counter() - t0) * 1000, 1),
        },
    ]
    report = {
        "advisories_ingested": len(state.get("advisories", [])),
        "advisories_extracted": len(state.get("extracted", [])),
        "needs_human": len(state.get("needs_human", [])),
        "matches": len(state.get("matches", [])),
        "alerts": len(alerts),
        "by_priority": {p: sum(a.priority == p for a in alerts) for p in PRIORITY_ORDER},
        "trace": trace,
    }
    _write(out / "run_report.json", report)
    return {"trace": trace[-1:]}


def _write(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
