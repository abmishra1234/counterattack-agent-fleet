"""Public feed contracts use recorded-shaped responses and never access the network."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from counterstrike import sources

CVE = "CVE-2099-0001"


class FeedClient:
    def __init__(self, failure=None):
        self.failure = failure
        self.closed = False
        self.calls = []

    def close(self):
        self.closed = True

    def get_json(self, source_id, url, **kwargs):
        self.calls.append((source_id, kwargs))
        if source_id == self.failure:
            raise sources.FeedFetchError(source_id, "timeout")
        return {
            "nvd": {
                "totalResults": 1,
                "vulnerabilities": [
                    None,
                    {"cve": {"id": "invalid"}},
                    {
                        "cve": {
                            "id": CVE,
                            "published": "2099-01-01",
                            "descriptions": [
                                {"lang": "fr", "value": "non"},
                                {"lang": "en", "value": "Product 1.0 is affected"},
                            ],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                            "references": [
                                {"url": "https://vendor.example/advisory", "tags": ["Patch"]},
                                {"url": "javascript:alert(1)"},
                                None,
                            ],
                        }
                    },
                ],
            },
            "cisa_kev": {
                "catalogVersion": "2099.01.01",
                "vulnerabilities": [
                    None,
                    {"cveID": "invalid"},
                    {"cveID": CVE, "requiredAction": "Apply update"},
                ],
            },
            "osv": {"id": "GHSA-test", "aliases": [CVE], "summary": "Independent evidence"},
            "epss": {
                "data": [{"cve": CVE, "epss": "0.9", "percentile": "0.99", "date": "2099-01-01"}]
            },
        }[source_id]


def test_normalized_feed_bundle_and_provenance(monkeypatch):
    client = FeedClient()
    monkeypatch.setattr(sources, "PublicSourceHTTPClient", lambda **kwargs: client)
    result = sources.fetch_public_feed_bundle(epss_enabled=True)
    assert len(result.advisories) == 1
    advisory = result.advisories[0]
    assert advisory.cvss == 9.8
    assert "Independent evidence" in advisory.text
    assert advisory.source_references == [
        {"url": "https://vendor.example/advisory", "tags": ["Patch"]}
    ]
    assert result.kev_ids == (CVE,)
    assert {item["kind"] for item in result.enrichments} == {
        "references",
        "osv",
        "cisa_kev",
        "epss",
    }
    assert all(item["status"] == "success" for item in result.source_syncs)
    assert client.closed


@pytest.mark.parametrize("failure", ["nvd", "cisa_kev", "osv", "epss"])
def test_independent_feed_failures_keep_provenance_and_cursor(monkeypatch, failure):
    client = FeedClient(failure)
    monkeypatch.setattr(sources, "PublicSourceHTTPClient", lambda **kwargs: client)
    result = sources.fetch_public_feed_bundle(epss_enabled=True)
    failed = next(item for item in result.source_syncs if item["source_id"] == failure)
    assert failed["status"] == ("partial" if failure == "epss" else "failure")
    assert failed["error_code"] == "timeout"
    if failure == "epss":
        assert json.loads(failed["next_cursor"])["remaining"] == [CVE]
    assert client.closed


def test_nvd_pagination_and_invalid_cursor():
    client = FeedClient()
    original = client.get_json

    def paginated(*args, **kwargs):
        payload = original(*args, **kwargs)
        payload["totalResults"] = 10
        return payload

    client.get_json = paginated
    adapter = sources.NVDFeedAdapter(client=client, api_key="test", page_size=3)
    page = adapter.fetch()
    assert json.loads(page.next_cursor)["offset"] == 3
    adapter.fetch(page.next_cursor)
    assert client.calls[-1][1]["params"]["startIndex"] == 3
    for cursor in ("bad", "{}", '{"start":"2000-01-01","end":"2000-01-02","offset":0}'):
        with pytest.raises(ValueError, match="cursor"):
            adapter.fetch(cursor)
    with pytest.raises(ValueError):
        sources.NVDFeedAdapter(client=client, page_size=0)


@pytest.mark.parametrize(
    "adapter,ids",
    [
        (sources.OSVEnrichmentAdapter, ("invalid",)),
        (sources.OSVEnrichmentAdapter, tuple([CVE] * 101)),
        (sources.EPSSEnrichmentAdapter, ()),
        (sources.EPSSEnrichmentAdapter, ("invalid",)),
    ],
)
def test_enrichment_rejects_invalid_batches(adapter, ids):
    with pytest.raises(ValueError):
        adapter(client=FeedClient()).fetch(ids)


@pytest.mark.parametrize(
    "payload,category",
    [
        ({}, "unexpected_response_shape"),
        ({"data": [{"cve": "CVE-2099-9999"}]}, "identifier_mismatch"),
        ({"data": [{"cve": CVE, "epss": "bad"}]}, "invalid_score"),
        ({"data": [{"cve": CVE, "epss": 2, "percentile": 0.1}]}, "invalid_score"),
    ],
)
def test_epss_rejects_untrusted_payload(payload, category):
    client = FeedClient()
    client.get_json = lambda *args, **kwargs: payload
    with pytest.raises(sources.FeedFetchError) as error:
        sources.EPSSEnrichmentAdapter(client=client).fetch((CVE,))
    assert error.value.category == category


@pytest.mark.parametrize(
    "body,status,limit,category",
    [
        (b'{"ok":true}', 200, 100, None),
        (b"[]", 200, 100, "unexpected_json_shape"),
        (b"bad", 200, 100, "invalid_json"),
        (b"{}", 429, 100, "http_429"),
        (b'{"too":"large"}', 200, 5, "response_too_large"),
    ],
)
def test_bounded_http_client(body, status, limit, category):
    client = sources.PublicSourceHTTPClient(max_response_bytes=limit)
    client._client.close()
    client._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, content=body),
        )
    )
    try:
        if category:
            with pytest.raises(sources.FeedFetchError) as error:
                client.get_json("test", "https://source.example/feed")
            assert error.value.category == category
        else:
            assert client.get_json("test", "https://source.example/feed") == {"ok": True}
        with pytest.raises(ValueError, match="HTTPS"):
            client.get_json("test", "http://source.example")
    finally:
        client.close()


def test_epss_backlog_is_resumable(monkeypatch):
    client = FeedClient()
    monkeypatch.setattr(sources, "PublicSourceHTTPClient", lambda **kwargs: client)
    backlog = [f"CVE-2099-{number:04d}" for number in range(1, 202)]
    result = sources.fetch_public_feed_bundle(
        epss_enabled=True,
        epss_cursor=json.dumps({"remaining": backlog}),
        max_epss_requests=1,
    )
    sync = next(item for item in result.source_syncs if item["source_id"] == "epss")
    assert sync["status"] == "partial"
    remaining = json.loads(sync["next_cursor"])["remaining"]
    assert len(remaining) == 101
    with pytest.raises(ValueError, match="cursor"):
        sources.fetch_public_feed_bundle(epss_enabled=True, epss_cursor='{"remaining":["bad"]}')
    assert client.closed


def test_nvd_timestamps_require_timezone():
    with pytest.raises(ValueError, match="timezone"):
        sources._iso_millis(datetime(2020, 1, 1))
    assert sources._iso_millis(datetime(2020, 1, 1, tzinfo=timezone.utc)).endswith("Z")


def test_nvd_cpe_matches_become_version_ranges():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.0.0",
                                "versionEndExcluding": "2.12.2",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.13.0",
                                "versionEndExcluding": "2.17.1",
                            },
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:1.4:*"},
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:unpatched:*:*"},
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:na:-:*"},
                            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:kernel:*:*"},
                            {"vulnerable": True, "criteria": "cpe:2.3:h:acme:router:1.0:*"},
                            {"vulnerable": True, "criteria": r"cpe:2.3:a:node\.js:node\.js:*:*"},
                        ]
                    }
                ]
            }
        ]
    }
    products = {p["product"]: p for p in sources._nvd_affected_products(cve)}
    assert set(products) == {"log4j", "widget", "unpatched", "node.js"}
    assert products["log4j"]["affected"] == ">=2.0.0,<2.12.2 || >=2.13.0,<2.17.1"
    assert products["log4j"]["vendor"] == "apache"
    assert products["log4j"]["fixed"] is None  # the fix depends on the matched range
    assert products["widget"]["affected"] == "==1.4"
    assert products["unpatched"]["affected"] == ">=0"
    assert all(p["origin"] == "nvd" for p in products.values())
    assert sources._nvd_affected_products({"configurations": "bad"}) == []


def test_osv_events_become_version_ranges():
    record = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Jinja2"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]},
                ],
            },
            {
                "package": {"ecosystem": "Maven", "name": "org.example:core-lib"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0"},
                            {"last_affected": "1.4"},
                            {"introduced": "2.0"},
                        ],
                    }
                ],
            },
            {"package": {"name": "listed"}, "versions": ["1.0", "1.1"]},
            {"package": "bad"},
        ]
    }
    products = {p["product"]: p for p in sources._osv_affected_products(record)}
    assert products["jinja2"]["affected"] == "<3.1.3"
    assert products["jinja2"]["fixed"] == "3.1.3"
    assert products["core-lib"]["affected"] == ">=1.0,<=1.4 || >=2.0"
    assert products["listed"]["affected"] == "==1.0 || ==1.1"


def test_osv_ranges_fill_advisories_nvd_left_without_products(monkeypatch):
    client = FeedClient()
    original = client.get_json

    def payloads(source_id, url, **kwargs):
        payload = original(source_id, url, **kwargs)
        if source_id == "cisa_kev":
            payload["vulnerabilities"] = []  # OSV must not depend on KEV membership
        if source_id == "osv":
            payload["affected"] = [
                {
                    "package": {"name": "requests"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}
                    ],
                }
            ]
        return payload

    client.get_json = payloads
    monkeypatch.setattr(sources, "PublicSourceHTTPClient", lambda **kwargs: client)
    advisory = sources.fetch_public_feed_bundle().advisories[0]
    assert advisory.structured == {
        "products": [
            {
                "product": "requests",
                "vendor": None,
                "affected": "<2.32.0",
                "fixed": "2.32.0",
                "origin": "osv",
            }
        ]
    }
    osv_trace = next(
        item
        for item in sources.fetch_public_feed_bundle(max_osv_lookups=0).trace
        if item["agent"] == "source_osv"
    )
    assert osv_trace["lookups_deferred"] == 1


def test_first_source_keeps_authority_over_a_product():
    nvd = [{"product": "a", "affected": "<2", "fixed": "2", "origin": "nvd"}]
    osv = [
        {"product": "a", "affected": "<3", "fixed": "3", "origin": "osv"},
        {"product": "b", "affected": "<1", "fixed": "1", "origin": "osv"},
    ]
    merged = sources._merge_structured({"products": nvd}, osv)
    assert [(p["product"], p["origin"]) for p in merged["products"]] == [
        ("a", "nvd"),
        ("b", "osv"),
    ]
    assert sources._merge_structured(None, []) is None
