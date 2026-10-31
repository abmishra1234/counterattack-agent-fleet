import json
import urllib.error
import urllib.parse
import urllib.request

base = "http://127.0.0.1:8000/api/v1/inventory"

def get(params):
    url = base + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())

status, page = get({"limit": 2})
print("base", status, json.dumps(page, default=str)[:1600])
if status == 200:
    items = page.get("items", [])
    candidates = []
    for item in items:
        for field in ("asset_type", "data_classification"):
            value = item.get(field)
            if value:
                candidates.append((field, value))
    for field, value in candidates[:4]:
        status, filtered = get({"limit": 2, field: value})
        print("filter", field, value, status, filtered.get("total"), len(filtered.get("items", [])))
    for params in ({"asset_type": "__invalid__"}, {"data_classification": "__invalid__"}):
        status, body = get(params)
        print("invalid", params, status, body.get("error", {}).get("code"))
