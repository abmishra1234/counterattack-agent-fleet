"""Load and validate versioned inventory documents for API and worker use."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from counterstrike.models import InventoryDocument


def parse_inventory_document(payload: Any) -> InventoryDocument:
    # Continue accepting the pre-contract list format for older user inventories.
    if isinstance(payload, list):
        payload = {"schema_version": "1.0", "assets": payload}
    return InventoryDocument.model_validate(payload)


def load_inventory_document(path: Path) -> InventoryDocument:
    with path.open(encoding="utf-8") as inventory_file:
        return parse_inventory_document(json.load(inventory_file))
