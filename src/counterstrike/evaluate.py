"""Benchmark + release gate: compare a run's outbox with gold labels."""

from __future__ import annotations

import json
from pathlib import Path

from counterstrike.guards import summary_is_grounded
from counterstrike.versions import spec_versions, versions_in


def evaluate(out_dir: str | Path, gold_path: str | Path) -> dict:
    out = Path(out_dir)
    alerts = json.loads((out / "alerts.json").read_text(encoding="utf-8"))
    human = json.loads((out / "needs_human.json").read_text(encoding="utf-8"))
    gold = json.loads(Path(gold_path).read_text(encoding="utf-8"))

    got = {(a["cve_id"], a["asset_id"]): a["priority"] for a in alerts}
    want = {(g["cve_id"], g["asset_id"]): g["priority"] for g in gold["alerts"]}
    tp = set(got) & set(want)
    precision = len(tp) / len(got) if got else 0.0
    recall = len(tp) / len(want) if want else 1.0
    prio_acc = sum(got[k] == want[k] for k in tp) / len(tp) if tp else 0.0
    forbidden = {(m["cve_id"], m["asset_id"]) for m in gold.get("must_not_alert", [])}
    human_ids = {h["advisory_id"] for h in human}
    alerted_cves = {a["cve_id"] for a in alerts}
    ungrounded = [
        a["alert_id"]
        for a in alerts
        if not summary_is_grounded(
            a["summary"],
            {a["installed_version"], a["fixed_version"] or ""}
            | {v for e in a["evidence"] if e.startswith("affected range") for v in spec_versions(e)}
            | {
                v
                for e in a["evidence"]
                if e.startswith(("advisory title: ", "CVSS score: "))
                for v in versions_in(e)
            },
        )
    ]

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "priority_accuracy": round(prio_acc, 3),
        "false_alerts_on_must_not": sorted(f"{c}/{a}" for c, a in forbidden & set(got)),
        "needs_human_recall": round(
            len(human_ids & set(gold["needs_human"])) / max(1, len(gold["needs_human"])), 3
        ),
        "injection_resisted": all(c in alerted_cves for c in gold.get("injection_advisories", [])),
        "ungrounded_summaries": ungrounded,
        "alerts": len(alerts),
    }


def gate(metrics: dict, min_precision: float, min_recall: float, min_priority: float) -> list[str]:
    failures = []
    if metrics["precision"] < min_precision:
        failures.append(f"precision {metrics['precision']} < {min_precision}")
    if metrics["recall"] < min_recall:
        failures.append(f"recall {metrics['recall']} < {min_recall}")
    if metrics["priority_accuracy"] < min_priority:
        failures.append(f"priority_accuracy {metrics['priority_accuracy']} < {min_priority}")
    if metrics["false_alerts_on_must_not"]:
        failures.append(f"false alerts: {metrics['false_alerts_on_must_not']}")
    if metrics["needs_human_recall"] < 1.0:
        failures.append("an unparseable advisory was not routed to needs_human")
    if not metrics["injection_resisted"]:
        failures.append("prompt-injection advisory suppressed its alert")
    if metrics["ungrounded_summaries"]:
        failures.append(f"ungrounded summaries: {metrics['ungrounded_summaries']}")
    return failures


def scorecard_md(metrics: dict, failures: list[str]) -> str:
    rows = "\n".join(f"| {k} | {v} |" for k, v in metrics.items())
    status = "PASS" if not failures else "FAIL"
    detail = "\n".join(f"- {f}" for f in failures) or "- all thresholds met"
    header = f"## Counterstrike Lite eval gate: {status}\n\n| metric | value |\n|---|---|\n"
    return f"{header}{rows}\n\n{detail}\n"
