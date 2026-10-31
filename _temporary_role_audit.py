import json
import urllib.error
import urllib.parse
import urllib.request

base = "http://127.0.0.1:8002/api/v1"


def get(path):
    with urllib.request.urlopen(base + path, timeout=5) as response:
        return response.status, json.loads(response.read())


status, context = get("/auth/context")
print("auth", status, context.get("role"))
status, inventory = get(
    "/inventory?limit=2&asset_type=application&data_classification=confidential"
)
print("inventory", status, inventory.get("total"), inventory.get("snapshot_id"))
status, _ = get("/inventory?limit=1&search=SYNTHETIC_PRIVATE_PROBE")
print("free_text_inventory", status)
status, audit = get("/audit/events?limit=200&event_type=api.request.started")
matching = [
    item for item in audit.get("items", []) if item.get("resource_id") == "/api/v1/inventory"
]
print("audited_inventory_requests", status, json.dumps(matching[:2], ensure_ascii=True))
