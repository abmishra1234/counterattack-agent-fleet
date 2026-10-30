"""Agent 4 - Risk Scorer: contextual priority beyond CVSS. Deterministic and explainable."""

from __future__ import annotations

import time

from counterstrike.models import Asset, ExtractedAdvisory, FleetState, ScoredMatch

KEV_BONUS = 2.0
INTERNET_BONUS = 1.5
CRITICALITY = {"critical": 2.0, "high": 1.0, "medium": 0.0, "low": -1.0}
# (threshold, priority, SLA hours) - first threshold the score reaches wins
BANDS = [(12.0, "P1", 24), (9.0, "P2", 168), (6.0, "P3", 720), (0.0, "P4", 2160)]


def score(adv: ExtractedAdvisory, asset: Asset) -> tuple[float, str, int, dict[str, float]]:
    breakdown = {
        "cvss": adv.cvss,
        "kev": KEV_BONUS if adv.in_kev else 0.0,
        "internet_facing": INTERNET_BONUS if asset.internet_facing else 0.0,
        "criticality": CRITICALITY[asset.criticality],
    }
    total = round(max(0.0, sum(breakdown.values())), 2)
    prio, sla = band(total)
    return total, prio, sla, breakdown


def band(total: float) -> tuple[str, int]:
    for threshold, prio, sla in BANDS:
        if total >= threshold:
            return prio, sla
    return "P4", BANDS[-1][2]


def score_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    advs = {a.advisory_id: a for a in state["extracted"]}
    assets = {a.asset_id: a for a in state["inventory"]}
    scored = []
    for m in state["matches"]:
        total, prio, sla, breakdown = score(advs[m.advisory_id], assets[m.asset_id])
        scored.append(
            ScoredMatch(
                **m.model_dump(),
                risk_score=total,
                priority=prio,
                sla_hours=sla,
                score_breakdown=breakdown,
            )
        )
    scored.sort(key=lambda s: (-s.risk_score, s.advisory_id, s.asset_id))
    return {
        "scored": scored,
        "trace": [
            {
                "agent": "score",
                "scored": len(scored),
                "by_priority": {
                    p: sum(s.priority == p for s in scored) for p in ("P1", "P2", "P3", "P4")
                },
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
