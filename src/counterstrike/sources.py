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


class FeedFetchError(RuntimeError):
    """Safe source fetch failure; intentionally excludes URL and response body."""

    def __init__(self, source_id: str, category: str):
        super().__init__(f"{source_id} feed request failed ({category})")
        self.source_id = source_id
        self.category = category


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
            response = self._client.get(url, params=params, headers=headers)
            response.raise_for_status()
            if len(response.content) > self._max_response_bytes:
                raise FeedFetchError(source_id, "response_too_large")
            payload = response.json()
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


def _nvd_cvss(cve: dict[str, Any]) -> float:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return 0.0
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            metric = entries[0]
            score = (metric.get("cvssData") or {}).get("baseScore") if isinstance(metric, dict) else None
            if isinstance(score, int | float) and 0 <= score <= 10:
                return float(score)
    return 0.0


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
        poll_window_minutes: int = 15,
        overlap_minutes: int = 2,
        page_size: int = 2000,
    ):
        if not 1 <= poll_window_minutes <= 60 or not 0 <= overlap_minutes <= 30:
            raise ValueError("NVD polling window is outside supported bounds")
        if not 1 <= page_size <= 2000:
            raise ValueError("NVD page size must be between 1 and 2000")
        self.api_key = api_key.strip() if api_key and api_key.strip() else None
        self.client = client or PublicSourceHTTPClient()
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
            if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            description = _first_text(cve.get("descriptions")) or ""
            published = cve.get("published")
            if not isinstance(published, str):
                published = ""
            advisories.append(
                Advisory(
                    id=cve_id,
                    source="nvd",
                    published=published,
                    title=f"{cve_id}: {description[:400]}" if description else cve_id,
                    cvss=_nvd_cvss(cve),
                    text=description[:20_000],
                )
            )

        next_offset = offset + len(records)
        next_cursor = (
            json.dumps({"start": _iso_millis(start), "end": _iso_millis(end), "offset": next_offset})
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

    def __init__(self, *, client: PublicSourceHTTPClient | None = None):
        self.client = client or PublicSourceHTTPClient()

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

    def __init__(self, *, client: PublicSourceHTTPClient | None = None):
        self.client = client or PublicSourceHTTPClient()

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
