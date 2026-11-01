import json

from counterstrike.agents.extract import extract_agent


class LyingLLM:
    """Returns a plausible but hallucinated version range."""

    name = "lying-llm"

    def complete(self, task, system, user, context):
        return json.dumps(
            {
                "products": [
                    {"product": "openssl", "affected": "<9.9.9", "fixed_version": "9.9.9"}
                ],
                "evidence": [],
            }
        )


class BrokenLLM:
    name = "broken-llm"

    def complete(self, task, system, user, context):
        return "Sure! Here is the answer: openssl is affected."


def by_id(state):
    return {e.advisory_id: e for e in state["extracted"]}


def test_structured_record_uses_alias(extracted_state):
    log4j = by_id(extracted_state)["CVE-2099-0001"]
    assert log4j.method == "structured"
    assert log4j.products[0].product == "log4j-core"
    assert log4j.in_kev


def test_free_text_bulletin_is_extracted_with_evidence(extracted_state):
    ossl = by_id(extracted_state)["CVE-2099-0002"]
    assert ossl.method == "llm"
    assert ossl.products[0].affected == ">=3.0.0,<=3.0.7"
    assert ossl.products[0].fixed_version == "3.0.8"
    assert any("3.0.0 through 3.0.7" in e for e in ossl.evidence)


def test_vague_bulletin_goes_to_human_queue(extracted_state):
    assert "CVE-2099-0008" not in by_id(extracted_state)
    assert [h.advisory_id for h in extracted_state["needs_human"]] == ["CVE-2099-0008"]


def test_injection_is_flagged_but_not_obeyed(extracted_state):
    req = by_id(extracted_state)["CVE-2099-0005"]
    assert req.suspected_injection
    assert req.products[0].affected == "<2.32.0"


def test_hallucinated_versions_are_rejected(base_state):
    out = extract_agent(base_state, LyingLLM())
    llm_items = [e for e in out["extracted"] if e.method == "llm"]
    assert llm_items == []
    assert any("not found in source text" in h.reason for h in out["needs_human"])


def test_non_json_output_is_routed_not_crashed(base_state):
    out = extract_agent(base_state, BrokenLLM())
    assert all(e.method == "structured" for e in out["extracted"])
    assert any("schema" in h.reason for h in out["needs_human"])


def test_feed_products_are_mapped_without_the_llm(base_state):
    from counterstrike.models import Advisory

    state = dict(base_state)
    state["advisories"] = [
        Advisory(
            id="CVE-2099-1000",
            source="nvd",
            published="2099-01-01",
            title="t",
            cvss=7.0,
            structured={
                "products": [
                    {
                        "product": "requests",
                        "affected": "<2.32.0",
                        "fixed": "2.32.0",
                        "origin": "osv",
                    },
                    {"product": "not-in-inventory", "affected": "<1.0a-bad!", "origin": "nvd"},
                    {"product": "openssl", "affected": "<1.1.1w-bad!", "origin": "nvd"},
                ]
            },
        )
    ]

    class NoCallLLM:
        name = "no-call"

        def complete(self, *args, **kwargs):
            raise AssertionError("structured feed data must not reach the LLM")

    out = extract_agent(state, NoCallLLM())
    (advisory,) = out["extracted"]
    assert [(p.product, p.fixed_version) for p in advisory.products] == [("requests", "2.32.0")]
    assert advisory.evidence == ["structured feed record (nvd, osv)"]
    # Unparseable ranges reach an analyst only for products the inventory runs.
    assert [h.reason for h in out["needs_human"]] == ["invalid specifier '<1.1.1w-bad!'"]
