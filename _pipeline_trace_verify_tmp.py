import json
import urllib.request

base = "http://127.0.0.1:8000/api/v1/runs"
with urllib.request.urlopen(base + "?limit=1", timeout=5) as response:
    listing = json.loads(response.read())
print("runs_status", response.status, "total", listing.get("total"))
if listing.get("items"):
    run_id = listing["items"][0]["id"]
    with urllib.request.urlopen(base + "/" + run_id, timeout=5) as response:
        detail = json.loads(response.read())
    print("run_id", run_id, "status", detail.get("status"))
    print("trace", json.dumps(detail.get("trace", []), ensure_ascii=True))
