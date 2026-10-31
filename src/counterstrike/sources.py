"""Feed adapter contracts for deterministic fixtures and approved public sources."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import httpx

from counterstrike.models import Advisory


@dataclass(frozen=True)
class FeedBatch:
    """One normalized fetch result with enough provenance for checkpointing."""

    source_id: str
    fetched_at: datetime
    advisories: tuple[Advisory, ...]
    next_cursor: str | None = None


class FeedAdapter(Protocol):
    """Contract for independent public or fixture-backed advisory sources."""

    source_id: str

    def fetch(self, cursor: str | None = None) -> FeedBatch:
        """Return the next batch, preserving each advisory's source provenance."""


@dataclass(frozen=True)
class KEVEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str | None
    known_ransomware_campaign_use: str | None
    notes: str | None


@dataclass(frozen=True)
class KEVCatalogBatch:
    source_id: str
    fetched_at: datetime
    catalog_version: str
    date_released: str | None
    entries: tuple[KEVEntry, ...]


@dataclass(frozen=True)
class OSVLookupBatch:
    source_id: str
    fetched_at: datetime
    advisories: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class EPSSScore:
    cve_id: str
    score: float
    percentile: float
    score_date: str | None


@dataclass(frozen=True)
class EPSSLookupBatch:
    source_id: str
    fetched_at: datetime
    requested_ids: tuple[str, ...]
    scores: tuple[EPSSScore, ...]


@dataclass(frozen=True)
class PublicFeedBundle:
    advisories: tuple[Advisory, ...]
    kev_ids: tuple[str, ...]
    source_syncs: tuple[dict[str, Any], ...]
    enrichments: tuple[dict[str, Any], ...]
    trace: tuple[dict[str, Any], ...]


class FeedFetchError(RuntimeError):
    """Safe source fetch failure; intentionally excludes URL and response body."""

    def __init__(self, source_id: str, category: str):
        super().__init__(f"{source_id} feed request failed ({category})")
        self.source_id = source_id
        self.category = category


MAX_EPSS_BACKLOG_IDS = 50_000
MAX_EPSS_CURSOR_CHARS = 2_000_000


class PublicSourceHTTPClient:
    """Small bounded JSON client shared by public-feed adapters."""

    def __init__(self, *, timeout_seconds: float = 20, max_response_bytes: int = 20_000_000):
        if timeout_seconds <= 0 or max_response_bytes <= 0:
            raise ValueError("Source HTTP limits must be positive")
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": "Counterstrike-Agent-Fleet/0.1"},
        )
        self._max_response_bytes = max_response_bytes

    def close(self) -> None:
        self._client.close()

    def get_json(
        self,
        source_id: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Public source URLs must use HTTPS")
        try:
            body = bytearray()
            with self._client.stream("GET", url, params=params, headers=headers) as response:
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self._max_response_bytes:
                    raise FeedFetchError(source_id, "response_too_large")
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise FeedFetchError(source_id, "response_too_large")
            payload = json.loads(body)
        except FeedFetchError:
            raise
        except httpx.HTTPStatusError as exc:
            raise FeedFetchError(source_id, f"http_{exc.response.status_code}") from None
        except httpx.TimeoutException:
            raise FeedFetchError(source_id, "timeout") from None
        except httpx.HTTPError:
            raise FeedFetchError(source_id, "transport_error") from None
        except ValueError:
            raise FeedFetchError(source_id, "invalid_json") from None
        if not isinstance(payload, dict):
            raise FeedFetchError(source_id, "unexpected_json_shape")
        return payload


def _first_text(items: Any) -> str | None:
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and item.get("lang") == "en" and isinstance(
            item.get("value"), str
        ):
            value = item["value"].strip()
            if value:
                return value
    return None


def _nvd_cvss(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            metric = entries[0]
            score = (
                (metric.get("cvssData") or {}).get("baseScore")
                if isinstance(metric, dict)
                else None
            )
            if isinstance(score, int | float) and 0 <= score <= 10:
                return float(score)
    return None


def _nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    references = cve.get("references")
    if not isinstance(references, list):
        return []
    normalized = []
    for item in references:
        if not isinstance(item, dict):
            continue
        raw_url = item.get("url")
        if not isinstance(raw_url, str) or len(raw_url) > 1500:
            continue
        try:
            parsed = urlsplit(raw_url.strip())
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            continue
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii") if hostname else ""
        except UnicodeError:
            continue
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not ascii_hostname
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", ascii_hostname)
            or parsed.username is not None
            or parsed.password is not None
            or (port is not None and not 1 <= port <= 65535)
        ):
            continue
        reference = {"url": raw_url.strip()}
        source = item.get("source")
        if isinstance(source, str) and source.strip():
            reference["source"] = source.strip()[:200]
        tags = item.get("tags")
        if isinstance(tags, list):
            reference["tags"] = [tag[:80] for tag in tags if isinstance(tag, str)][:10]
        normalized.append(reference)
        if len(normalized) == 30:
            break
    return normalized


def _iso_millis(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("NVD polling timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class NVDFeedAdapter:
    """Poll NVD CVE 2.0 by modification window with resumable pagination."""

    source_id = "nvd"
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: PublicSourceHTTPClient | None = None,
        timeout_seconds: float = 20,
        poll_window_minutes: int = 15,
        overlap_minutes: int = 2,
        page_size: int = 2000,
    ):
        if not 1 <= poll_window_minutes <= 60 or not 0 <= overlap_minutes <= 30:
            raise ValueError("NVD polling window is outside supported bounds")
        if not 1 <= page_size <= 2000:
            raise ValueError("NVD page size must be between 1 and 2000")
        self.api_key = api_key.strip() if api_key and api_key.strip() else None
        self.client = client or PublicSourceHTTPClient(timeout_seconds=timeout_seconds)
        self.poll_window_minutes = poll_window_minutes
        self.overlap_minutes = overlap_minutes
        self.page_size = page_size

    def fetch(self, cursor: str | None = None) -> FeedBatch:
        now = datetime.now(timezone.utc)
        if cursor is None:
            end = now
            start = end - timedelta(minutes=self.poll_window_minutes + self.overlap_minutes)
            offset = 0
        else:
            try:
                state = json.loads(cursor)
                start = datetime.fromisoformat(state["start"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(state["end"].replace("Z", "+00:00"))
                offset = int(state["offset"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                raise ValueError("Invalid NVD pagination cursor") from None
            if start.tzinfo is None or end.tzinfo is None or offset < 0:
                raise ValueError("Invalid NVD pagination cursor")
            if end - start > timedelta(days=120) or end > now + timedelta(minutes=1):
                raise ValueError("NVD cursor window is outside the supported range")

        headers = {"apiKey": self.api_key} if self.api_key else None
        payload = self.client.get_json(
            self.source_id,
            self.endpoint,
            params={
                "lastModStartDate": _iso_millis(start),
                "lastModEndDate": _iso_millis(end),
                "resultsPerPage": self.page_size,
                "startIndex": offset,
            },
            headers=headers,
        )
        records = payload.get("vulnerabilities")
        total = payload.get("totalResults")
        if not isinstance(records, list) or not isinstance(total, int) or total < 0:
            raise FeedFetchError(self.source_id, "unexpected_response_shape")

        advisories: list[Advisory] = []
        for wrapped in records:
            cve = wrapped.get("cve") if isinstance(wrapped, dict) else None
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("id")
            if (
                not isinstance(cve_id, str)
                or len(cve_id) > 32
                or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)
            ):
                continue
            description = _first_text(cve.get("descriptions")) or ""
            published = cve.get("published")
            if not isinstance(published, str):
                published = ""
            advisories.append(
                Advisory(
                    id=cve_id,
                    source="nvd",
                    source_url=self.endpoint,
                    source_retrieved_at=now.isoformat(),
                    source_references=_nvd_references(cve),
                    published=published,
                    title=f"{cve_id}: {description[:400]}" if description else cve_id,
                    cvss=_nvd_cvss(cve),
                    text=description[:20_000],
                )
            )

        next_offset = offset + len(records)
        next_cursor = (
            json.dumps(
                {"start": _iso_millis(start), "end": _iso_millis(end), "offset": next_offset}
            )
            if next_offset < total and records
            else None
        )
        return FeedBatch(
            source_id=self.source_id,
            fetched_at=now,
            advisories=tuple(advisories),
            next_cursor=next_cursor,
        )


class CISAKEVEnrichmentAdapter:
    """Fetch the authoritative CISA KEV JSON catalog as CVE enrichment."""

    source_id = "cisa_kev"
    endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        *,
        client: PublicSourceHTTPClient | None = None,
        timeout_seconds: float = 20,
    ):
        self.client = client or PublicSourceHTTPClient(timeout_seconds=timeout_seconds)

    def fetch(self) -> KEVCatalogBatch:
        payload = self.client.get_json(self.source_id, self.endpoint)
        records = payload.get("vulnerabilities")
        if not isinstance(records, list):
            raise FeedFetchError(self.source_id, "unexpected_response_shape")
        entries = []
        for record in records:
            if not isinstance(record, dict):
                continue
            cve_id = record.get("cveID")
            if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            entries.append(
                KEVEntry(
                    cve_id=cve_id,
                    vendor_project=str(record.get("vendorProject") or "")[:200],
                    product=str(record.get("product") or "")[:200],
                    vulnerability_name=str(record.get("vulnerabilityName") or "")[:500],
                    date_added=str(record.get("dateAdded") or "")[:40],
                    short_description=str(record.get("shortDescription") or "")[:20_000],
                    required_action=str(record.get("requiredAction") or "")[:20_000],
                    due_date=str(record.get("dueDate") or "")[:40] or None,
                    known_ransomware_campaign_use=str(
                        record.get("knownRansomwareCampaignUse") or ""
                    )[:24]
                    or None,
                    notes=str(record.get("notes") or "")[:4000] or None,
                )
            )
        version = payload.get("catalogVersion")
        if not isinstance(version, str) or not version.strip():
            raise FeedFetchError(self.source_id, "missing_catalog_version")
        released = payload.get("dateReleased")
        return KEVCatalogBatch(
            source_id=self.source_id,
            fetched_at=datetime.now(timezone.utc),
            catalog_version=version[:80],
            date_released=str(released)[:40] if released else None,
            entries=tuple(entries),
        )


class OSVEnrichmentAdapter:
    """Look up OSV vulnerability records by CVE ID without leaking query content."""

    source_id = "osv"
    endpoint = "https://api.osv.dev/v1/vulns/{}"

    def __init__(
        self,
        *,
        client: PublicSourceHTTPClient | None = None,
        timeout_seconds: float = 20,
    ):
        self.client = client or PublicSourceHTTPClient(timeout_seconds=timeout_seconds)

    def fetch(self, cve_ids: tuple[str, ...]) -> OSVLookupBatch:
        if len(cve_ids) > 100:
            raise ValueError("OSV enrichment batches are limited to 100 CVE IDs")
        records: list[dict[str, Any]] = []
        for cve_id in dict.fromkeys(cve_ids):
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                raise ValueError("OSV lookup accepts CVE IDs only")
            try:
                payload = self.client.get_json(
                    self.source_id, self.endpoint.format(quote(cve_id, safe=""))
                )
            except FeedFetchError as exc:
                if exc.category == "http_404":
                    continue
                raise
            if payload.get("id") != cve_id and cve_id not in payload.get("aliases", []):
                raise FeedFetchError(self.source_id, "identifier_mismatch")
            records.append(payload)
        return OSVLookupBatch(
            source_id=self.source_id,
            fetched_at=datetime.now(timezone.utc),
            advisories=tuple(records),
        )


class EPSSEnrichmentAdapter:
    """Look up current EPSS scores for a bounded batch of CVE identifiers."""

    source_id = "epss"
    endpoint = "https://api.first.org/data/v1/epss"
    max_cves_per_request = 100
    max_query_chars = 2000

    def __init__(
        self,
        *,
        client: PublicSourceHTTPClient | None = None,
        timeout_seconds: float = 20,
    ):
        self.client = client or PublicSourceHTTPClient(timeout_seconds=timeout_seconds)

    def fetch(self, cve_ids: tuple[str, ...]) -> EPSSLookupBatch:
        requested = tuple(dict.fromkeys(cve_ids))
        if not requested or len(requested) > self.max_cves_per_request:
            raise ValueError("EPSS lookups require 1 to 100 CVE IDs")
        if any(
            len(cve_id) > 32 or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)
            for cve_id in requested
        ):
            raise ValueError("EPSS lookup accepts CVE IDs only")
        joined_ids = ",".join(requested)
        if len(joined_ids) > self.max_query_chars:
            raise ValueError("EPSS CVE query exceeds the documented size limit")

        payload = self.client.get_json(self.source_id, self.endpoint, params={"cve": joined_ids})
        records = payload.get("data")
        if not isinstance(records, list):
            raise FeedFetchError(self.source_id, "unexpected_response_shape")
        requested_set = set(requested)
        scores: dict[str, EPSSScore] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            cve_id = record.get("cve")
            if not isinstance(cve_id, str) or cve_id not in requested_set:
                raise FeedFetchError(self.source_id, "identifier_mismatch")
            try:
                score = float(record["epss"])
                percentile = float(record["percentile"])
            except (KeyError, TypeError, ValueError):
                raise FeedFetchError(self.source_id, "invalid_score") from None
            if not (0 <= score <= 1 and 0 <= percentile <= 1):
                raise FeedFetchError(self.source_id, "invalid_score")
            score_date = record.get("date")
            scores[cve_id] = EPSSScore(
                cve_id=cve_id,
                score=score,
                percentile=percentile,
                score_date=score_date if isinstance(score_date, str) else None,
            )
        return EPSSLookupBatch(
            source_id=self.source_id,
            fetched_at=datetime.now(timezone.utc),
            requested_ids=requested,
            scores=tuple(scores[cve_id] for cve_id in requested if cve_id in scores),
        )


def fetch_public_feed_bundle(
    *,
    nvd_api_key: str | None = None,
    timeout_seconds: float = 20,
    nvd_cursor: str | None = None,
    epss_cursor: str | None = None,
    epss_enabled: bool = False,
    max_nvd_pages: int = 5,
    max_epss_requests: int = 34,
) -> PublicFeedBundle:
    """Fetch a bounded NVD page window and independent KEV/OSV enrichments."""
    if not 1 <= max_nvd_pages <= 20:
        raise ValueError("NVD page bound must be between 1 and 20")
    if not 1 <= max_epss_requests <= 50:
        raise ValueError("EPSS request bound must be between 1 and 50")
    client = PublicSourceHTTPClient(timeout_seconds=timeout_seconds)
    nvd = NVDFeedAdapter(api_key=nvd_api_key, client=client)
    kev_adapter = CISAKEVEnrichmentAdapter(client=client)
    osv = OSVEnrichmentAdapter(client=client)
    epss = EPSSEnrichmentAdapter(client=client)
    advisories: list[Advisory] = []
    syncs: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    enrichments: list[dict[str, Any]] = []
    kev_ids: tuple[str, ...] = ()
    try:
        cursor = nvd_cursor
        bounded_nvd_pages = max_nvd_pages
        if epss_enabled:
            worst_case_cves_per_request = epss.max_query_chars // 33
            epss_capacity = max_epss_requests * worst_case_cves_per_request
            bounded_nvd_pages = min(max_nvd_pages, max(1, epss_capacity // 2000))
        try:
            for _ in range(bounded_nvd_pages):
                page = nvd.fetch(cursor)
                advisories.extend(page.advisories)
                cursor = page.next_cursor
                if cursor is None:
                    break
            sync_status = "partial" if cursor is not None else "success"
            syncs.append(
                {
                    "source_id": nvd.source_id,
                    "status": sync_status,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "next_cursor": cursor,
                    "record_count": len(advisories),
                    "error_code": "page_limit_reached" if cursor is not None else None,
                }
            )
            trace.append(
                {
                    "agent": "source_nvd",
                    "source_id": nvd.source_id,
                    "source_status": sync_status,
                    "advisories": len(advisories),
                    **({"source_error_code": "page_limit_reached"} if cursor else {}),
                }
            )
        except FeedFetchError as exc:
            syncs.append(
                {
                    "source_id": nvd.source_id,
                    "status": "failure",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "next_cursor": cursor,
                    "record_count": len(advisories),
                    "error_code": exc.category,
                }
            )
            trace.append(
                {
                    "agent": "source_nvd",
                    "source_id": nvd.source_id,
                    "source_status": "failure",
                    "source_error_code": exc.category,
                    "advisories": len(advisories),
                }
            )

        enrichments.extend(
            {
                "advisory_id": advisory.id,
                "source_id": nvd.source_id,
                "kind": "references",
                "source_url": advisory.source_url,
                "observed_at": advisory.source_retrieved_at,
                "value": {
                    "status": "available" if advisory.source_references else "unavailable",
                    "references": advisory.source_references,
                },
            }
            for advisory in advisories
        )

        try:
            catalog = kev_adapter.fetch()
            kev_ids = tuple(entry.cve_id for entry in catalog.entries)
            enrichments.extend(
                {
                    "advisory_id": entry.cve_id,
                    "source_id": kev_adapter.source_id,
                    "kind": "cisa_kev",
                    "value": {
                        "vendor_project": entry.vendor_project,
                        "product": entry.product,
                        "vulnerability_name": entry.vulnerability_name,
                        "date_added": entry.date_added,
                        "short_description": entry.short_description,
                        "required_action": entry.required_action,
                        "due_date": entry.due_date,
                        "known_ransomware_campaign_use": entry.known_ransomware_campaign_use,
                        "notes": entry.notes,
                        "catalog_version": catalog.catalog_version,
                    },
                }
                for entry in catalog.entries
            )
            syncs.append(
                {
                    "source_id": kev_adapter.source_id,
                    "status": "success",
                    "fetched_at": catalog.fetched_at.isoformat(),
                    "next_cursor": None,
                    "record_count": len(catalog.entries),
                    "error_code": None,
                }
            )
            trace.append(
                {
                    "agent": "source_cisa_kev",
                    "source_id": kev_adapter.source_id,
                    "source_status": "success",
                    "advisories": len(catalog.entries),
                }
            )
        except FeedFetchError as exc:
            trace.append(
                {
                    "agent": "source_cisa_kev",
                    "source_id": kev_adapter.source_id,
                    "source_status": "failure",
                    "source_error_code": exc.category,
                    "advisories": 0,
                }
            )
            syncs.append(
                {
                    "source_id": kev_adapter.source_id,
                    "status": "failure",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "next_cursor": None,
                    "record_count": 0,
                    "error_code": exc.category,
                }
            )

        # OSV adds independent descriptions for KEV CVEs in the current NVD window.
        osv_ids = tuple(dict.fromkeys(a.id for a in advisories if a.id in set(kev_ids)))
        osv_records: list[dict[str, Any]] = []
        osv_error = None
        if osv_ids:
            for start in range(0, len(osv_ids), 100):
                try:
                    batch = osv.fetch(osv_ids[start : start + 100])
                    osv_records.extend(batch.advisories)
                except FeedFetchError as exc:
                    osv_error = exc.category
                    break
        osv_count = len(osv_records)
        osv_status = (
            "failure"
            if osv_error and not osv_records
            else "partial"
            if osv_error
            else "skipped"
            if not osv_ids
            else "success"
        )
        osv_by_id = {
            identifier: record
            for record in osv_records
            for identifier in (record.get("id"), *(record.get("aliases") or []))
            if isinstance(identifier, str)
        }
        for record in osv_records:
            cve_aliases = [
                identifier
                for identifier in (record.get("id"), *(record.get("aliases") or []))
                if isinstance(identifier, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier)
            ]
            for advisory_id in cve_aliases:
                enrichments.append(
                    {
                        "advisory_id": advisory_id,
                        "source_id": osv.source_id,
                        "kind": "osv",
                        "value": {
                            key: record.get(key)
                            for key in (
                                "id",
                                "aliases",
                                "summary",
                                "details",
                                "affected",
                                "references",
                                "modified",
                                "published",
                            )
                            if key in record
                        },
                    }
                )
        enriched = []
        for advisory in advisories:
            record = osv_by_id.get(advisory.id)
            if record is None:
                enriched.append(advisory)
                continue
            extra = "\n\n".join(
                str(record.get(key) or "")[:10_000]
                for key in ("summary", "details")
                if record.get(key)
            )
            enriched.append(
                advisory.model_copy(
                    update={"text": f"{advisory.text}\n\nOSV enrichment:\n{extra}"[:20_000]}
                )
            )
        advisories = enriched
        syncs.append(
            {
                "source_id": osv.source_id,
                "status": osv_status,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "next_cursor": None,
                "record_count": osv_count,
                "error_code": osv_error,
            }
        )
        trace.append(
            {
                "agent": "source_osv",
                "source_id": osv.source_id,
                "source_status": osv_status,
                "source_error_code": osv_error,
                "advisories": osv_count,
            }
        )

        if epss_enabled:
            pending_ids: list[str] = []
            if epss_cursor is not None:
                try:
                    cursor_state = json.loads(epss_cursor)
                    pending_ids = cursor_state["remaining"]
                    invalid_pending = not isinstance(pending_ids, list)
                    if not invalid_pending:
                        invalid_pending = len(pending_ids) > MAX_EPSS_BACKLOG_IDS or any(
                            not isinstance(cve_id, str)
                            or len(cve_id) > 32
                            or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)
                            for cve_id in pending_ids
                        )
                    if invalid_pending:
                        raise ValueError
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    raise ValueError("Invalid EPSS enrichment cursor") from None
            candidate_ids = dict.fromkeys(
                [*pending_ids, *(advisory.id for advisory in advisories)]
            )
            epss_ids = list(candidate_ids)
            if len(epss_ids) > MAX_EPSS_BACKLOG_IDS:
                raise ValueError("EPSS enrichment backlog exceeds the supported bound")

            epss_batches: list[tuple[str, ...]] = []
            current_batch: list[str] = []
            current_query_chars = 0
            for cve_id in epss_ids:
                next_chars = current_query_chars + len(cve_id) + bool(current_batch)
                if current_batch and (
                    len(current_batch) >= epss.max_cves_per_request
                    or next_chars > epss.max_query_chars
                ):
                    epss_batches.append(tuple(current_batch))
                    current_batch = []
                    current_query_chars = 0
                    next_chars = len(cve_id)
                if next_chars > epss.max_query_chars:
                    raise ValueError("EPSS CVE identifier exceeds the documented query limit")
                current_batch.append(cve_id)
                current_query_chars = next_chars
            if current_batch:
                epss_batches.append(tuple(current_batch))

            processed_ids: list[str] = []
            epss_scores: dict[str, EPSSScore] = {}
            epss_retrieved_at: dict[str, datetime] = {}
            epss_error: str | None = None
            for batch_ids in epss_batches[:max_epss_requests]:
                try:
                    batch = epss.fetch(batch_ids)
                except FeedFetchError as exc:
                    epss_error = exc.category
                    break
                processed_ids.extend(batch.requested_ids)
                epss_scores.update({score.cve_id: score for score in batch.scores})
                epss_retrieved_at.update(
                    {cve_id: batch.fetched_at for cve_id in batch.requested_ids}
                )

            epss_remaining = epss_ids[len(processed_ids) :]
            epss_next_cursor = (
                json.dumps({"remaining": epss_remaining}, separators=(",", ":"))
                if epss_remaining
                else None
            )
            if epss_next_cursor is not None and len(epss_next_cursor) > MAX_EPSS_CURSOR_CHARS:
                raise ValueError("EPSS enrichment cursor exceeds the supported bound")
            epss_status = (
                "skipped"
                if not epss_ids
                else "partial"
                if epss_error or epss_next_cursor
                else "success"
            )
            epss_enrichments = [
                {
                    "advisory_id": cve_id,
                    "source_id": epss.source_id,
                    "kind": "epss",
                    "source_url": epss.endpoint,
                    "observed_at": epss_retrieved_at[cve_id].isoformat(),
                    "value": {
                        "status": "available" if cve_id in epss_scores else "not_scored",
                        "score": epss_scores[cve_id].score if cve_id in epss_scores else None,
                        "percentile": (
                            epss_scores[cve_id].percentile if cve_id in epss_scores else None
                        ),
                        "score_date": (
                            epss_scores[cve_id].score_date if cve_id in epss_scores else None
                        ),
                    },
                }
                for cve_id in processed_ids
            ]
            enrichments.extend(epss_enrichments)
            syncs.append(
                {
                    "source_id": epss.source_id,
                    "status": epss_status,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "next_cursor": epss_next_cursor,
                    "record_count": len(processed_ids),
                    "error_code": epss_error,
                }
            )
            trace.append(
                {
                    "agent": "source_epss",
                    "source_id": epss.source_id,
                    "source_status": epss_status,
                    "source_error_code": epss_error,
                    "advisories": len(processed_ids),
                    "scores_available": len(epss_scores),
                    "backlog_remaining": len(epss_remaining),
                }
            )
    finally:
        client.close()

    return PublicFeedBundle(
        advisories=tuple(advisories),
        kev_ids=kev_ids,
        source_syncs=tuple(syncs),
        enrichments=tuple(enrichments),
        trace=tuple(trace),
    )


@dataclass(frozen=True)
class FixtureFeedAdapter:
    """Load the repository's deterministic advisory fixture as a feed batch."""

    data_dir: Path
    source_id: str = "fixture-json"

    def fetch(self, cursor: str | None = None) -> FeedBatch:
        if cursor is not None:
            raise ValueError("Fixture feed does not support pagination cursors")
        path = self.data_dir / "advisories.json"
        with path.open(encoding="utf-8") as source_file:
            payload = json.load(source_file)
        if not isinstance(payload, list):
            raise ValueError("Fixture advisories must be a JSON array")
        advisories = tuple(Advisory.model_validate(item) for item in payload)
        return FeedBatch(
            source_id=self.source_id,
            fetched_at=datetime.now(timezone.utc),
            advisories=advisories,
        )
