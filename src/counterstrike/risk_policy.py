"""Versioned deterministic risk policy shared by scoring and persistence."""

from __future__ import annotations

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
