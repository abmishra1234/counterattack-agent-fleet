"""Feed adapter contracts and the deterministic local-fixture adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

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
