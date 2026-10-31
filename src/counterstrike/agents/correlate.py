"""Agent 3 - Correlator: matches extracted ranges against the asset inventory (pure code)."""

from __future__ import annotations

import time

from counterstrike.models import FleetState, Match, NeedsHuman
from counterstrike.versions import is_affected, parse_spec, tolerant_version


def _merge_candidate(previous: Match | None, candidate: Match) -> Match:
    if previous is None:
        return candidate
    evidence = list(dict.fromkeys([*previous.evidence, *candidate.evidence]))
    if previous.outcome != candidate.outcome:
        ranges = sorted({previous.affected, candidate.affected})
        return previous.model_copy(
            update={
                "affected": " | ".join(ranges)[:300],
                "outcome": "possible_match",
                "confidence": None,
                "evidence": evidence,
                "comparator": None,
                "version_note": "conflicting affected ranges",
            }
        )
    return previous.model_copy(
        update={
            "confidence": previous.confidence
            if previous.confidence == candidate.confidence
            else None,
            "comparator": previous.comparator
            if previous.comparator == candidate.comparator
            else None,
            "evidence": evidence,
        }
    )


def correlate_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    candidates: dict[tuple[str, str], Match] = {}
    human: list[NeedsHuman] = []
    human_keys: set[tuple[str, str]] = set()

    def add_review(advisory_id: str, key: str, reason: str) -> None:
        review_key = (advisory_id, key)
        if review_key not in human_keys:
            human.append(NeedsHuman(advisory_id=advisory_id, stage="correlate", reason=reason))
            human_keys.add(review_key)

    def add_candidate(candidate: Match) -> None:
        pair = (candidate.advisory_id, candidate.asset_id)
        candidates[pair] = _merge_candidate(candidates.get(pair), candidate)
        if candidates[pair].outcome == "possible_match":
            add_review(
                candidate.advisory_id,
                f"asset:{candidate.asset_id}",
                (
                    f"possible match for asset {candidate.asset_id}: "
                    "version comparison is inconclusive"
                ),
            )

    for adv in state["extracted"]:
        for prod in adv.products:
            spec = parse_spec(prod.affected)
            if spec is None:
                matching_assets = [
                    asset
                    for asset in state["inventory"]
                    if asset.component.lower() == prod.product
                ]
                if not matching_assets:
                    add_review(
                        adv.advisory_id,
                        f"range:{prod.product}",
                        f"invalid affected range for {prod.product}: {prod.affected[:200]}",
                    )
                for asset in matching_assets:
                    add_candidate(
                        Match(
                            advisory_id=adv.advisory_id,
                            asset_id=asset.asset_id,
                            component=asset.component,
                            installed_version=asset.version,
                            affected=prod.affected,
                            fixed_version=prod.fixed_version,
                            outcome="possible_match",
                            confidence=None,
                            comparator=None,
                            evidence=[
                                (
                                    f"asset component '{asset.component}' matches product "
                                    f"'{prod.product}'"
                                ),
                                f"affected range '{prod.affected[:200]}' is invalid",
                                *(str(item)[:500] for item in adv.evidence[:5]),
                            ],
                            version_note="invalid affected range",
                        )
                    )
                continue
            for asset in state["inventory"]:
                if asset.component.lower() != prod.product:
                    continue
                version, note = tolerant_version(asset.version)
                if version is None:
                    add_candidate(
                        Match(
                            advisory_id=adv.advisory_id,
                            asset_id=asset.asset_id,
                            component=asset.component,
                            installed_version=asset.version,
                            affected=prod.affected,
                            fixed_version=prod.fixed_version,
                            outcome="possible_match",
                            confidence=None,
                            comparator=None,
                            evidence=[
                                (
                                    f"asset component '{asset.component}' matches product "
                                    f"'{prod.product}'"
                                ),
                                (
                                    f"installed version '{asset.version[:120]}' cannot be "
                                    "compared with "
                                    f"affected range '{prod.affected[:200]}'"
                                ),
                                *(str(item)[:500] for item in adv.evidence[:5]),
                            ],
                            version_note=note or "unparseable installed version",
                        )
                    )
                    continue
                affected = is_affected(version, spec)
                outcome = "possible_match" if note else "affected" if affected else "not_affected"
                evidence = [
                    (
                        f"asset component '{asset.component}' matches advisory product "
                        f"'{prod.product}'"
                    ),
                    (
                        f"installed version '{asset.version}' satisfies affected range "
                        f"'{prod.affected}'"
                        if affected
                        else (
                            f"installed version '{asset.version}' does not satisfy affected range "
                            f"'{prod.affected}'"
                        )
                    ),
                    *(str(item)[:500] for item in adv.evidence[:5]),
                ]
                if note:
                    evidence.extend(
                        [
                            note[:500],
                            "tolerant version parsing is inconclusive; analyst review is required",
                        ]
                    )
                candidate = Match(
                    advisory_id=adv.advisory_id,
                    asset_id=asset.asset_id,
                    component=asset.component,
                    installed_version=asset.version,
                    affected=prod.affected,
                    fixed_version=prod.fixed_version,
                    comparator="pep440_tolerant" if note else "pep440",
                    outcome=outcome,
                    confidence=None if note else 1.0,
                    evidence=evidence,
                    version_note=note,
                )
                add_candidate(candidate)
    matches = list(candidates.values())
    return {
        "matches": matches,
        "needs_human": human,
        "trace": [
            {
                "agent": "correlate",
                "matches": len(matches),
                "affected": sum(item.outcome == "affected" for item in matches),
                "not_affected": sum(item.outcome == "not_affected" for item in matches),
                "possible_match": sum(item.outcome == "possible_match" for item in matches),
                "needs_human": len(human),
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
