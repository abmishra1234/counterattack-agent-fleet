import pytest

from counterstrike.agents.correlate import correlate_agent
from counterstrike.agents.score import band, score, score_agent
from counterstrike.models import AffectedProduct, Asset, ExtractedAdvisory


def pairs(state):
    return {
        (m.advisory_id, m.asset_id)
        for m in correlate_agent(state)["matches"]
        if m.outcome == "affected"
    }


def test_patched_and_out_of_range_assets_are_not_confirmed_affected(extracted_state):
    got = pairs(extracted_state)
    assert ("CVE-2099-0001", "A-101") in got
    assert ("CVE-2099-0001", "A-102") not in got  # 2.17.2 already patched
    assert ("CVE-2099-0002", "A-107") not in got  # 1.1.1w line not affected
    assert ("CVE-2099-0004", "A-106") not in got  # nginx 1.24.0 below range


def test_negative_and_uncertain_results_are_retained_but_not_scored(extracted_state):
    state = dict(extracted_state)
    result = correlate_agent(state)
    state["matches"] = result["matches"]
    outcomes = {(m.advisory_id, m.asset_id): m.outcome for m in state["matches"]}
    assert outcomes[("CVE-2099-0001", "A-102")] == "not_affected"
    assert outcomes[("CVE-2099-0002", "A-107")] == "possible_match"
    assert outcomes[("CVE-2099-0004", "A-106")] == "not_affected"
    assert all(item.outcome == "affected" for item in score_agent(state)["scored"])
    assert any("A-107" in item.reason for item in result["needs_human"])


@pytest.mark.parametrize("version,affected", [("unknown", "<2"), ("1.0", "invalid")])
def test_uncomparable_versions_require_review(version, affected):
    advisory = _adv(8.0).model_copy(
        update={
            "products": [AffectedProduct(product="c", affected=affected)],
        }
    )
    result = correlate_agent({"extracted": [advisory], "inventory": [_asset(version=version)]})
    assert result["matches"][0].outcome == "possible_match"
    assert result["matches"][0].confidence is None
    assert len(result["needs_human"]) == 1


def test_conflicting_ranges_merge_to_one_reviewable_match():
    advisory = _adv(8.0).model_copy(
        update={
            "products": [
                AffectedProduct(product="c", affected="<2"),
                AffectedProduct(product="c", affected=">=2"),
            ]
        }
    )
    result = correlate_agent({"extracted": [advisory], "inventory": [_asset()]})
    assert len(result["matches"]) == 1
    assert result["matches"][0].outcome == "possible_match"
    assert result["matches"][0].version_note == "conflicting affected ranges"
    assert len(result["needs_human"]) == 1


def _asset(**kw):
    base = dict(
        asset_id="X",
        service="s",
        component="c",
        version="1.0",
        internet_facing=False,
        criticality="medium",
        owner="o",
    )
    return Asset(**{**base, **kw})


def _adv(cvss, kev=False):
    return ExtractedAdvisory(
        advisory_id="CVE-X", title="t", cvss=cvss, in_kev=kev, products=[], method="structured"
    )


def test_kev_and_exposure_lift_priority():
    total, prio, sla, breakdown = score(
        _adv(10.0, kev=True), _asset(internet_facing=True, criticality="high")
    )
    assert (total, prio, sla) == (14.5, "P1", 24)
    assert breakdown == {
        "cvss": 10.0,
        "kev": 2.0,
        "kev_status": "listed",
        "internet_facing": 1.5,
        "criticality": 1.0,
        "epss": 0.0,
        "epss_weight": 0.0,
        "epss_status": "not_configured",
        "epss_probability": None,
        "epss_score_date": None,
        "epss_observed_at": None,
        "epss_source_url": None,
        "kev_internet_p1_override": 1.0,
    }


def test_band_boundaries_are_inclusive():
    assert band(12.0) == ("P1", 24)
    assert band(11.99)[0] == "P2"
    assert band(9.0)[0] == "P2"
    assert band(6.0)[0] == "P3"
    assert band(5.99)[0] == "P4"


def test_score_never_negative():
    total, prio, _, _ = score(_adv(0.0), _asset(criticality="low"))
    assert total == 0.0 and prio == "P4"
