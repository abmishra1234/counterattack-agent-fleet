from counterstrike.agents.correlate import correlate_agent
from counterstrike.agents.score import band, score
from counterstrike.models import Asset, ExtractedAdvisory


def pairs(state):
    return {(m.advisory_id, m.asset_id) for m in correlate_agent(state)["matches"]}


def test_patched_and_out_of_range_assets_are_not_matched(extracted_state):
    got = pairs(extracted_state)
    assert ("CVE-2099-0001", "A-101") in got
    assert ("CVE-2099-0001", "A-102") not in got  # 2.17.2 already patched
    assert ("CVE-2099-0002", "A-107") not in got  # 1.1.1w line not affected
    assert ("CVE-2099-0004", "A-106") not in got  # nginx 1.24.0 below range


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
    assert breakdown == {"cvss": 10.0, "kev": 2.0, "internet_facing": 1.5, "criticality": 1.0}


def test_band_boundaries_are_inclusive():
    assert band(12.0) == ("P1", 24)
    assert band(11.99)[0] == "P2"
    assert band(9.0)[0] == "P2"
    assert band(6.0)[0] == "P3"
    assert band(5.99)[0] == "P4"


def test_score_never_negative():
    total, prio, _, _ = score(_adv(0.0), _asset(criticality="low"))
    assert total == 0.0 and prio == "P4"
