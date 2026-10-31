import json
import re
from urllib.request import urlopen

from sqlalchemy import select

from counterstrike.audit import verify_chain
from counterstrike.db import session_scope
from counterstrike.db_models import AuditEvent

with urlopen("http://127.0.0.1:8000/metrics", timeout=10) as response:
    assert response.status == 200, response.status
    metrics = response.read().decode("utf-8")

for required in (
    "counterstrike_http_requests_total",
    "counterstrike_http_request_duration_seconds",
    "counterstrike_jobs",
    "counterstrike_llm_calls",
    "counterstrike_database_up 1",
):
    assert required in metrics, required
assert not re.search(
    r"CVE-[0-9]{4}-[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
    r"prompt_hash|actor_id|advisory_id|asset_id|model=",
    metrics,
)
allowed_labels = {"method", "route", "status", "le", "direction", "outcome"}
for line in metrics.splitlines():
    if not line.startswith("counterstrike_http_") or "{" not in line:
        continue
    labels = re.findall(r'([a-z_]+)="([^"]*)"', line)
    assert labels and all(name in allowed_labels for name, _ in labels), line
    assert all(
        name != "route" or value == "unmatched" or value.startswith("/") for name, value in labels
    ), line

with session_scope() as session:
    events = session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.resource_type == "api_route",
            AuditEvent.resource_id == "/metrics",
            AuditEvent.event_type.in_(
                ("api.request.started", "api.request.completed", "api.request.failed")
            ),
        )
        .order_by(AuditEvent.sequence_number.desc())
        .limit(2)
    ).all()
    valid, failure = verify_chain(session)
    types = [event.event_type for event in reversed(events)]
    assert types == ["api.request.started", "api.request.completed"], types
    assert valid, failure
    print(
        json.dumps(
            {
                "http_status": response.status,
                "bounded_metrics_scan": "passed",
                "metrics_database_up": "counterstrike_database_up 1" in metrics,
                "metrics_request_audit": types,
                "audit_chain_valid": valid,
            }
        )
    )
