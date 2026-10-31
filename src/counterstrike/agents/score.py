"""Agent 4 - Risk Scorer: contextual priority beyond CVSS. Deterministic and explainable."""

from __future__ import annotations

import time
from decimal import Decimal
from typing import Any

from counterstrike.config import Settings, load_settings
from counterstrike.models import Asset, ExtractedAdvisory, FleetState, NeedsHuman, ScoredMatch
from counterstrike.risk_policy import (
    CRITICALITY,
    INTERNET_BONUS,
    KEV_BONUS,
    POLICY_VERSION,
    epss_adjustment,
    policy_version_for_epss,
    priority_for,
)


def score(
    adv: ExtractedAdvisory,
    asset: Asset,
    *,
    epss_observation: dict[str, Any] | None = None,
    epss_weight: Decimal | None = None,
    epss_max_age_days: int | None = None,
) -> tuple[float, str, int, dict[str, Any]]:
    epss_contribution, epss_status = epss_adjustment(
        epss_observation,
        weight=epss_weight,
        max_age_days=epss_max_age_days,
    )
    epss_probability = (
        epss_observation.get("score")
        if isinstance(epss_observation, dict)
        and not isinstance(epss_observation.get("score"), bool)
        and isinstance(epss_observation.get("score"), (int, float))
        and 0 <= epss_observation["score"] <= 1
        else None
    )
    breakdown = {
        "cvss": adv.cvss,
        "kev": KEV_BONUS if adv.in_kev is True else 0.0,
        "kev_status": (
            "listed" if adv.in_kev is True else "not_listed" if adv.in_kev is False else "unknown"
        ),
        "internet_facing": INTERNET_BONUS if asset.internet_facing else 0.0,
        "criticality": CRITICALITY[asset.criticality],
        "epss": epss_contribution,
        "epss_weight": float(epss_weight) if epss_weight is not None else 0.0,
        "epss_status": epss_status,
        "epss_probability": epss_probability,
        "epss_score_date": (
            epss_observation.get("score_date")
            if isinstance(epss_observation, dict)
            and isinstance(epss_observation.get("score_date"), str)
            else None
        ),
        "epss_observed_at": (
            epss_observation.get("_observed_at")
            if isinstance(epss_observation, dict)
            and isinstance(epss_observation.get("_observed_at"), str)
            else None
        ),
        "epss_source_url": (
            epss_observation.get("_source_url")
            if isinstance(epss_observation, dict)
            and isinstance(epss_observation.get("_source_url"), str)
            else None
        ),
        "kev_internet_p1_override": float(adv.in_kev is True and asset.internet_facing),
    }
    total = round(
        max(
            0.0,
            sum(
                breakdown[key] for key in ("cvss", "kev", "internet_facing", "criticality", "epss")
            ),
        ),
        2,
    )
    prio, sla = priority_for(total, kev=adv.in_kev is True, internet_facing=asset.internet_facing)
    return total, prio, sla, breakdown


def band(total: float) -> tuple[str, int]:
    return priority_for(total, kev=False, internet_facing=False)


def score_agent(state: FleetState, *, settings: Settings | None = None) -> dict:
    t0 = time.perf_counter()
    settings = settings or load_settings()
    epss_enabled_for_scoring = settings.epss_scoring_approved
    epss_weight = settings.epss_risk_weight if epss_enabled_for_scoring else None
    epss_max_age_days = settings.epss_max_age_days if epss_enabled_for_scoring else None
    active_policy_version = policy_version_for_epss(epss_weight, epss_max_age_days)
    epss_by_advisory: dict[str, dict[str, Any]] = {}
    epss_observed_at: dict[str, str] = {}
    for item in state.get("source_enrichments", []):
        if not isinstance(item, dict) or item.get("kind") != "epss":
            continue
        advisory_id = item.get("advisory_id")
        value = item.get("value")
        observed_at = item.get("observed_at")
        if not isinstance(advisory_id, str) or not isinstance(value, dict):
            continue
        if advisory_id not in epss_observed_at or (
            isinstance(observed_at, str) and observed_at > epss_observed_at[advisory_id]
        ):
            epss_by_advisory[advisory_id] = {
                **value,
                "_observed_at": observed_at,
                "_source_url": item.get("source_url"),
            }
            if isinstance(observed_at, str):
                epss_observed_at[advisory_id] = observed_at
    advs = {a.advisory_id: a for a in state["extracted"]}
    assets = {a.asset_id: a for a in state["inventory"]}
    scored = []
    needs_human: list[NeedsHuman] = []
    kev_unknown_advisories: set[str] = set()
    for m in state["matches"]:
        if m.outcome != "affected":
            continue
        total, prio, sla, breakdown = score(
            advs[m.advisory_id],
            assets[m.asset_id],
            epss_observation=epss_by_advisory.get(m.advisory_id),
            epss_weight=epss_weight,
            epss_max_age_days=epss_max_age_days,
        )
        scored.append(
            ScoredMatch(
                **m.model_dump(),
                risk_score=total,
                priority=prio,
                sla_hours=sla,
                score_breakdown=breakdown,
            )
        )
        if advs[m.advisory_id].in_kev is None and m.advisory_id not in kev_unknown_advisories:
            kev_unknown_advisories.add(m.advisory_id)
            needs_human.append(
                NeedsHuman(
                    advisory_id=m.advisory_id,
                    stage="score",
                    reason="CISA KEV status is unknown because the catalog was unavailable",
                )
            )
    scored.sort(key=lambda s: (-s.risk_score, s.advisory_id, s.asset_id))
    return {
        "scored": scored,
        "needs_human": needs_human,
        "trace": [
            {
                "agent": "score",
                "policy_version": active_policy_version or POLICY_VERSION,
                "scored": len(scored),
                "kev_status_unknown": len(kev_unknown_advisories),
                "by_priority": {
                    p: sum(s.priority == p for s in scored) for p in ("P1", "P2", "P3", "P4")
                },
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
