"""Agent 4 - Risk Scorer: contextual priority beyond CVSS. Deterministic and explainable."""

from __future__ import annotations

import time

from counterstrike.models import Asset, ExtractedAdvisory, FleetState, ScoredMatch
from counterstrike.risk_policy import (
    CRITICALITY,
    INTERNET_BONUS,
    KEV_BONUS,
    POLICY_VERSION,
    priority_for,
)


def score(adv: ExtractedAdvisory, asset: Asset) -> tuple[float, str, int, dict[str, float]]:
    breakdown = {
        "cvss": adv.cvss,
        "kev": KEV_BONUS if adv.in_kev else 0.0,
        "internet_facing": INTERNET_BONUS if asset.internet_facing else 0.0,
        "criticality": CRITICALITY[asset.criticality],
        "kev_internet_p1_override": float(adv.in_kev and asset.internet_facing),
    }
    total = round(
        max(0.0, sum(value for key, value in breakdown.items() if key != "kev_internet_p1_override")),
        2,
    )
    prio, sla = priority_for(total, kev=adv.in_kev, internet_facing=asset.internet_facing)
    return total, prio, sla, breakdown


def band(total: float) -> tuple[str, int]:
    return priority_for(total, kev=False, internet_facing=False)


def score_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    advs = {a.advisory_id: a for a in state["extracted"]}
    assets = {a.asset_id: a for a in state["inventory"]}
    scored = []
    for m in state["matches"]:
        if m.outcome != "affected":
            continue
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
                "policy_version": POLICY_VERSION,
                "scored": len(scored),
                "by_priority": {
                    p: sum(s.priority == p for s in scored) for p in ("P1", "P2", "P3", "P4")
                },
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
