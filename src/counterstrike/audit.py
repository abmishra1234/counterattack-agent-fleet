"""Append-only, hash-chained application audit events."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select  # type: ignore
from sqlalchemy.orm import Session  # type: ignore

from counterstrike.db_models import AuditEvent, AuditStreamHead


def _canonical(value: dict[str, Any]) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return encoded.encode("utf-8")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def append_event(
    session: Session,
    *,
    actor_type: str,
    action: str,
    event_type: str,
    outcome: str,
    resource_type: str,
    actor_id: str | None = None,
    resource_id: str | None = None,
    request_id: str | None = None,
    job_id: str | None = None,
    run_id: str | None = None,
    source_id: str | None = None,
    advisory_id: str | None = None,
    asset_id: str | None = None,
    alert_id: str | None = None,
    review_id: str | None = None,
    llm_call_id: str | None = None,
    reason: str | None = None,
    safe_details: dict[str, Any] | None = None,
    evidence_refs: list[str] | None = None,
    policy_version: str | None = None,
    prompt_version: str | None = None,
) -> AuditEvent:
    """Add event and update singleton chain head in the caller's transaction."""
    head = session.scalar(
        select(AuditStreamHead).where(AuditStreamHead.stream_name == "global").with_for_update()
    )
    if head is None:
        dialect = session.get_bind().dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert  # type: ignore
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert  # type: ignore
        else:
            raise RuntimeError(f"Audit stream initialization is unsupported for {dialect}")
        session.execute(
            insert(AuditStreamHead)
            .values(stream_name="global", last_hash=None, sequence_number=0)
            .on_conflict_do_nothing(index_elements=[AuditStreamHead.stream_name])
        )
        head = session.scalar(
            select(AuditStreamHead).where(AuditStreamHead.stream_name == "global").with_for_update()
        )
        if head is None:
            raise RuntimeError("The global audit stream head could not be initialized")

    event_id = str(uuid4())
    head.sequence_number += 1
    occurred_at = datetime.now(timezone.utc)
    fields: dict[str, Any] = {
        "id": event_id,
        "sequence_number": head.sequence_number,
        "schema_version": 1,
        "occurred_at": occurred_at.isoformat(),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "event_type": event_type,
        "outcome": outcome,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "request_id": request_id,
        "job_id": job_id,
        "run_id": run_id,
        "source_id": source_id,
        "advisory_id": advisory_id,
        "asset_id": asset_id,
        "alert_id": alert_id,
        "review_id": review_id,
        "llm_call_id": llm_call_id,
        "reason": reason,
        "safe_details": safe_details or {},
        "evidence_refs": evidence_refs or [],
        "policy_version": policy_version,
        "prompt_version": prompt_version,
        "previous_hash": head.last_hash,
    }
    digest_payload = (head.last_hash or "").encode("ascii") + b"\n" + _canonical(fields)
    digest = hashlib.sha256(digest_payload).hexdigest()
    event = AuditEvent(**{**fields, "occurred_at": occurred_at}, event_hash=digest)
    session.add(event)
    head.last_hash = digest
    session.flush()
    return event


def verify_chain(session: Session) -> tuple[bool, str | None]:
    """Verify ordered event links and the stored global chain head."""
    events = session.scalars(select(AuditEvent).order_by(AuditEvent.sequence_number)).all()
    previous_hash: str | None = None
    previous_sequence_number = 0
    for event in events:
        if event.sequence_number != previous_sequence_number + 1:
            return False, event.id
        fields = {
            "id": event.id,
            "sequence_number": event.sequence_number,
            "schema_version": event.schema_version,
            "occurred_at": _timestamp(event.occurred_at),
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "action": event.action,
            "event_type": event.event_type,
            "outcome": event.outcome,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "request_id": event.request_id,
            "job_id": event.job_id,
            "run_id": event.run_id,
            "source_id": event.source_id,
            "advisory_id": event.advisory_id,
            "asset_id": event.asset_id,
            "alert_id": event.alert_id,
            "review_id": event.review_id,
            "llm_call_id": event.llm_call_id,
            "reason": event.reason,
            "safe_details": event.safe_details,
            "evidence_refs": event.evidence_refs,
            "policy_version": event.policy_version,
            "prompt_version": event.prompt_version,
            "previous_hash": event.previous_hash,
        }
        digest_payload = (previous_hash or "").encode("ascii") + b"\n" + _canonical(fields)
        expected = hashlib.sha256(digest_payload).hexdigest()
        if event.previous_hash != previous_hash or event.event_hash != expected:
            return False, event.id
        previous_hash = event.event_hash
        previous_sequence_number = event.sequence_number
    head = session.get(AuditStreamHead, "global")
    if (head.last_hash if head else None) != previous_hash or (
        head.sequence_number if head else 0
    ) != previous_sequence_number:
        return False, "global-head"
    return True, None
