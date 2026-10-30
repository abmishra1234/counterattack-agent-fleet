"""Agent 3 - Correlator: matches extracted ranges against the asset inventory (pure code)."""

from __future__ import annotations

import time

from counterstrike.models import FleetState, Match
from counterstrike.versions import is_affected, parse_spec, tolerant_version


def correlate_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    matches: list[Match] = []
    for adv in state["extracted"]:
        for prod in adv.products:
            spec = parse_spec(prod.affected)
            if spec is None:
                continue
            for asset in state["inventory"]:
                if asset.component.lower() != prod.product:
                    continue
                version, note = tolerant_version(asset.version)
                if version is None or not is_affected(version, spec):
                    continue
                matches.append(
                    Match(
                        advisory_id=adv.advisory_id,
                        asset_id=asset.asset_id,
                        component=asset.component,
                        installed_version=asset.version,
                        affected=prod.affected,
                        fixed_version=prod.fixed_version,
                        version_note=note,
                    )
                )
    return {
        "matches": matches,
        "trace": [
            {
                "agent": "correlate",
                "matches": len(matches),
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
