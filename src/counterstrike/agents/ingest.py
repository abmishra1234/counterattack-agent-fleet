"""Agent 1 - Feed Watcher: loads and validates the feed, KEV list, inventory and aliases."""

from __future__ import annotations

import json
import time
from pathlib import Path

from counterstrike.config import Settings, load_settings
from counterstrike.inventory import load_inventory_document
from counterstrike.models import Advisory, FleetState
from counterstrike.sources import FixtureFeedAdapter, fetch_public_feed_bundle


def _load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def ingest_agent(
    state: FleetState,
    *,
    settings: Settings | None = None,
    source_cursors: dict[str, str | None] | None = None,
) -> dict:
    t0 = time.perf_counter()
    data = Path(state["data_dir"])
    settings = settings or load_settings()
    source_trace: list[dict] = []
    source_syncs: list[dict] = []
    source_enrichments: list[dict] = []
    if settings.public_feeds_enabled:
        bundle = fetch_public_feed_bundle(
            nvd_api_key=(settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None),
            timeout_seconds=settings.public_feed_timeout_seconds,
            nvd_cursor=(source_cursors or {}).get("nvd"),
            epss_cursor=(source_cursors or {}).get("epss"),
            epss_enabled=settings.epss_enabled and settings.epss_approved,
        )
        advisories = list(bundle.advisories)
        kev = list(bundle.kev_ids)
        source_trace.extend(bundle.trace)
        source_syncs.extend(bundle.source_syncs)
        source_enrichments.extend(bundle.enrichments)
        kev_complete = any(
            item.get("source_id") == "cisa_kev" and item.get("status") == "success"
            for item in source_syncs
        )
        if not any(item.get("status") in {"success", "partial"} for item in source_syncs):
            raise RuntimeError("public_feeds_unavailable")
    else:
        feed_batch = FixtureFeedAdapter(data).fetch()
        advisories = list(feed_batch.advisories)
        kev = list(_load(data / "kev.json")["cve_ids"])
        kev_complete = True
        source_trace.append(
            {
                # Fixture loading is a source activity, not a second execution of
                # the ingest agent. Keep it distinct in persisted run traces.
                "agent": "fixture_feed",
                "source_id": feed_batch.source_id,
                "source_status": "success",
                "fetched_at": feed_batch.fetched_at.isoformat(),
                "advisories": len(advisories),
            }
        )
    inventory = load_inventory_document(data / "inventory.json").assets
    aliases = {k.lower(): v.lower() for k, v in _load(data / "aliases.json").items()}
    for asset in inventory:
        canonical_product = asset.inventory_product.casefold()
        for alias in asset.aliases:
            normalized_alias = alias.casefold()
            existing = aliases.get(normalized_alias)
            if existing is not None and existing != canonical_product:
                raise ValueError("inventory alias conflicts with configured product aliases")
            aliases[normalized_alias] = canonical_product
    unique: list[Advisory] = []
    seen: set[str] = set()
    for adv in advisories:  # feeds repeat items; keep the first copy of each CVE id
        if adv.id not in seen:
            seen.add(adv.id)
            unique.append(adv)
    return {
        "advisories": unique,
        "inventory": inventory,
        "kev": kev,
        "kev_complete": kev_complete,
        "aliases": aliases,
        "source_syncs": source_syncs,
        "source_enrichments": source_enrichments,
        "trace": [
            *source_trace,
            {
                "agent": "ingest",
                "advisories": len(unique),
                "assets": len(inventory),
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            },
        ],
    }
