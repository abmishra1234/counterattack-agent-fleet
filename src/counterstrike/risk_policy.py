"""Versioned deterministic risk policy shared by scoring and persistence."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

POLICY_VERSION = "req-fr6-kev-internet-p1-v1"

KEV_BONUS = 2.0
INTERNET_BONUS = 1.5
CRITICALITY = {"critical": 2.0, "high": 1.0, "medium": 0.0, "low": -1.0}
PRIORITY_BANDS = ((12.0, "P1", 24), (9.0, "P2", 168), (6.0, "P3", 720), (0.0, "P4", 2160))


def priority_for(total: float, *, kev: bool, internet_facing: bool) -> tuple[str, int]:
    """Apply the explicit FR-6 KEV + internet-facing P1 rule, then score bands."""
    if kev and internet_facing:
        return "P1", PRIORITY_BANDS[0][2]
    for threshold, priority, sla_hours in PRIORITY_BANDS:
        if total >= threshold:
            return priority, sla_hours
    return "P4", PRIORITY_BANDS[-1][2]


def policy_version_for_epss(weight: Decimal | None, max_age_days: int | None) -> str:
    if weight is None or max_age_days is None:
        return POLICY_VERSION
    return f"{POLICY_VERSION}+epss-w{format(weight.normalize(), 'f')}-age{max_age_days}d"


def epss_adjustment(
    observation: dict[str, Any] | None,
    *,
    weight: Decimal | None,
    max_age_days: int | None,
    today: date | None = None,
) -> tuple[float, str]:
    """Return a bounded EPSS contribution only for an approved, fresh source score."""
    if weight is None or max_age_days is None:
        return 0.0, "not_configured"
    if not isinstance(observation, dict):
        return 0.0, "no_observation"
    if observation.get("status") != "available":
        return 0.0, "not_scored"
    score = observation.get("score")
    score_date_value = observation.get("score_date")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= score <= 1
        or not isinstance(score_date_value, str)
    ):
        return 0.0, "invalid_score"
    try:
        score_date = date.fromisoformat(score_date_value)
    except ValueError:
        return 0.0, "invalid_score_date"
    age_days = ((today or datetime.now(timezone.utc).date()) - score_date).days
    if age_days < 0 or age_days > max_age_days:
        return 0.0, "stale"
    return round(float(weight) * float(score), 3), "applied"
