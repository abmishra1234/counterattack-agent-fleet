import json
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://counterstrike_app:counterstrike-app-local-only"
    "@db:5432/counterstrike_llm_recovery_check"
)

from counterstrike.audit import verify_chain
from counterstrike.db import session_scope
from counterstrike.db_models import AuditEvent, JobRecord, LLMCall, RunRecord
from counterstrike.worker import claim_job

run_id, job_id, call_id = (str(uuid4()) for _ in range(3))
now = datetime.now(timezone.utc)
with session_scope() as session:
    session.add(RunRecord(id=run_id, trigger_type="acceptance", status="running"))
    session.flush()
    session.add(
        JobRecord(
            id=job_id,
            job_type="analysis",
            status="running",
            payload={},
            run_id=run_id,
            attempt=1,
            max_attempts=3,
            available_at=now - timedelta(minutes=3),
            lease_owner="expired-worker",
            lease_expires_at=now - timedelta(minutes=2),
        )
    )
    session.add(
        LLMCall(
            id=call_id,
            job_id=job_id,
            run_id=run_id,
            task="extract",
            provider="acceptance",
            model="synthetic",
            prompt_version="acceptance-v1",
            prompt_hash="a" * 64,
            attempt_key="recovery-check",
            attempt_number=1,
            started_at=now - timedelta(minutes=2),
            outcome="pending",
            budget_estimate_usd=Decimal("0.001"),
            cost_currency="USD",
        )
    )

claimed = claim_job("recovery-worker", lease_seconds=60)
assert claimed == job_id, f"expected recovered job {job_id}, got {claimed}"

with session_scope() as session:
    job = session.get(JobRecord, job_id)
    call = session.get(LLMCall, call_id)
    audit = session.query(AuditEvent).order_by(AuditEvent.sequence_number).all()
    valid, failure = verify_chain(session)
    assert call.outcome == "unknown"
    assert call.safe_error_code == "worker_lost_during_llm_attempt"
    assert call.completed_at is not None and call.latency_ms is not None
    assert call.budget_estimate_usd == Decimal("0.001")
    assert job.status == "running" and job.attempt == 2
    assert job.lease_owner == "recovery-worker"
    event_types = [item.event_type for item in audit]
    assert event_types == ["llm.call.outcome_unknown", "job.lifecycle.claimed"], event_types
    assert valid, failure

print(json.dumps({
    "claimed_job": job.id,
    "job_attempt": job.attempt,
    "llm_outcome": call.outcome,
    "safe_error_code": call.safe_error_code,
    "budget_estimate_usd": str(call.budget_estimate_usd),
    "audit_events": event_types,
    "audit_chain_valid": valid,
}))
