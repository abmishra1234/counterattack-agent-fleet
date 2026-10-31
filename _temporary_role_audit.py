import json
import urllib.error
import urllib.parse
import urllib.request

for url in (
    "http://127.0.0.1:8002/api/v1/auth/context",
    "http://127.0.0.1:8002/api/v1/inventory?limit=2&asset_type=application&data_classification=confidential",
    "http://127.0.0.1:8002/api/v1/audit/events?limit=100&event_type=api.request.started",
):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = json.loads(response.read())
            if url.endswith("event_type=api.request.started"):
                matching = [item for item in body.get("items", []) if item.get("resource_id") == "/api/v1/inventory"]
                print(response.status, url, json.dumps(matching, ensure_ascii=True))
            else:
                print(response.status, url, json.dumps(body, ensure_ascii=True)[:1500])
    except urllib.error.HTTPError as error:
        print(error.code, url, error.read(1000).decode())
    except Exception as error:
        print(type(error).__name__, url, str(error))
