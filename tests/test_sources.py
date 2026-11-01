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
