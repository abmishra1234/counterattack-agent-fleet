"""Agent 1 - Feed Watcher: loads and validates the feed, KEV list, inventory and aliases."""

from __future__ import annotations

import json
import time
from pathlib import Path

from counterstrike.models import Advisory, Asset, FleetState
from counterstrike.sources import FixtureFeedAdapter


def _load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def ingest_agent(state: FleetState) -> dict:
    t0 = time.perf_counter()
    data = Path(state["data_dir"])
    feed_batch = FixtureFeedAdapter(data).fetch()
    advisories = list(feed_batch.advisories)
    inventory = [Asset.model_validate(a) for a in _load(data / "inventory.json")]
    kev = list(_load(data / "kev.json")["cve_ids"])
    aliases = {k.lower(): v.lower() for k, v in _load(data / "aliases.json").items()}
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
        "aliases": aliases,
        "trace": [
            {
                "agent": "ingest",
                "source_id": feed_batch.source_id,
                "fetched_at": feed_batch.fetched_at.isoformat(),
                "advisories": len(unique),
                "assets": len(inventory),
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
