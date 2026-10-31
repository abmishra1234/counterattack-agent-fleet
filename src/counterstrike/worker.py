"""Durable background execution for queued Counterstrike runs."""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import or_, select

from counterstrike.artifacts import purge_expired_artifacts
from counterstrike.audit import append_event
from counterstrike.config import load_settings
from counterstrike.db import session_scope
from counterstrike.db_models import JobRecord, OutboxMessage, RunRecord
from counterstrike.delivery import DeliveryFailure, send_outbox_message
from counterstrike.digest_scheduler import start_digest_scheduler
from counterstrike.graph import run
from counterstrike.llm import get_llm
from counterstrike.llm_metering import mark_pending_attempts_unknown
from counterstrike.observability import configure_logging
from counterstrike.repositories import (
    load_source_cursors,
    mark_run_started,
    persist_run_results,
)
from counterstrike.source_scheduler import start_source_scheduler

logger = logging.getLogger("counterstrike.worker")


def claim_job(worker_id: str, lease_seconds: int = 90) -> str | None:
    """Atomically claim one due job, reclaiming expired leases after restarts."""
    now = datetime.now(timezone.utc)
    with session_scope() as session:
        query = (
            select(JobRecord)
            .where(
                or_(
                    (JobRecord.status.in_(("queued", "retry")) & (JobRecord.available_at <= now)),
                    (JobRecord.status == "running") & (JobRecord.lease_expires_at < now),
                )
            )
            .order_by(JobRecord.available_at, JobRecord.created_at, JobRecord.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = session.scalar(query)
        if job is None:
            return None
        if job.attempt > 0:
            abandoned_calls = mark_pending_attempts_unknown(session, job_id=job.id)
            if abandoned_calls:
                logger.warning(
                    "Recovered unresolved LLM attempts from a previous worker lease",
                    extra={
                        "event": "llm.call.outcome_unknown",
                        "job_id": job.id,
                        "run_id": job.run_id,
                        "call_count": abandoned_calls,
                    },
                )
        if job.attempt >= job.max_attempts:
            job.status = "failed"
            job.completed_at = now
            job.lease_owner = None
            job.lease_expires_at = None
            job.last_error_code = job.last_error_code or "attempt_limit_reached"
            if job.run_id:
                record = session.get(RunRecord, job.run_id)
                if record is not None and record.status in {"queued", "running"}:
                    record.status = "failed"
                    record.safe_error_code = job.last_error_code
                    record.completed_at = now
                    append_event(
                        session,
                        actor_type="service",
                        action="run_failed",
                        event_type="run.lifecycle.failed",
                        outcome="failure",
                        resource_type="run",
                        resource_id=record.id,
                        request_id=record.request_id,
                        run_id=record.id,
                        safe_details={"error_code": job.last_error_code},
                    )
            append_event(
                session, actor_type="service", action="job_failed",
                event_type="job.lifecycle.failed", outcome="failure",
                resource_type="job", resource_id=job.id, run_id=job.run_id,
                safe_details={"error_code": job.last_error_code},
            )
            return None
        job.status = "running"
        job.attempt += 1
        job.lease_owner = worker_id
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        append_event(
            session, actor_type="service", action="job_claimed",
            event_type="job.lifecycle.claimed", outcome="success",
            resource_type="job", resource_id=job.id, run_id=job.run_id,
            request_id=session.get(RunRecord, job.run_id).request_id if job.run_id else None,
            safe_details={"attempt": job.attempt, "lease_seconds": lease_seconds},
        )
        return job.id


def heartbeat(job_id: str, worker_id: str, lease_seconds: int) -> bool:
    """Extend a lease only while this worker still owns the running job."""
    now = datetime.now(timezone.utc)
    with session_scope() as session:
        job = session.get(JobRecord, job_id)
        if job is None or job.status != "running" or job.lease_owner != worker_id:
            return False
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        append_event(
            session, actor_type="service", action="job_heartbeat",
            event_type="job.lifecycle.heartbeat", outcome="success",
            resource_type="job", resource_id=job.id, run_id=job.run_id,
            safe_details={"lease_seconds": lease_seconds},
        )
        return True


def process_outbox_once(worker_id: str, settings=None) -> bool:
    """Claim and deliver at most one outbox row with durable retry and audit states."""
    settings = settings or load_settings()
    if not settings.outbox_delivery_enabled:
        return False
    now = datetime.now(timezone.utc)
    claim = None
    with session_scope(settings) as session:
        row = session.scalar(
            select(OutboxMessage)
            .where(
                OutboxMessage.channel == settings.outbox_channel,
                or_(
                    (OutboxMessage.status.in_(("queued", "retry")))
                    & or_(
                        OutboxMessage.next_attempt_at.is_(None),
                        OutboxMessage.next_attempt_at <= now,
                    ),
                    (OutboxMessage.status == "delivering")
                    & (OutboxMessage.delivery_lease_expires_at <= now),
                )
            )
            .order_by(OutboxMessage.created_at, OutboxMessage.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if row is None:
            return False
        if row.status == "delivering":
            row.status = "unknown"
            row.last_response_code = "delivery_lease_expired"
            row.delivery_worker_id = None
            row.delivery_lease_expires_at = None
            append_event(
                session,
                actor_type="service",
                actor_id=worker_id,
                action="delivery_outcome_unknown",
                event_type="delivery.outbox.outcome_unknown",
                outcome="unknown",
                resource_type="outbox_message",
                resource_id=row.id,
                run_id=row.run_id,
                alert_id=row.alert_id,
                safe_details={"reason": "delivery_lease_expired", "attempt": row.attempt},
            )
            return True
        if row.attempt >= settings.outbox_delivery_max_attempts:
            row.status = "failed"
            row.last_response_code = "attempt_limit_reached"
            row.next_attempt_at = None
            append_event(
                session,
                actor_type="service",
                actor_id=worker_id,
                action="delivery_failed",
                event_type="delivery.outbox.failed",
                outcome="failure",
                resource_type="outbox_message",
                resource_id=row.id,
                run_id=row.run_id,
                alert_id=row.alert_id,
                safe_details={"reason": "attempt_limit_reached", "attempt": row.attempt},
            )
            return True
        row.status = "delivering"
        row.attempt += 1
        row.delivery_worker_id = worker_id
        row.delivery_started_at = now
        row.delivery_lease_expires_at = now + timedelta(
            seconds=settings.outbox_delivery_lease_seconds
        )
        claim = {
            "id": row.id,
            "run_id": row.run_id,
            "alert_id": row.alert_id,
            "channel": row.channel,
            "recipient_ref": row.recipient_ref,
            "idempotency_key": row.idempotency_key,
            "payload": row.payload,
            "attempt": row.attempt,
        }
        append_event(
            session,
            actor_type="service",
            actor_id=worker_id,
            action="delivery_attempt_started",
            event_type="delivery.outbox.attempt_started",
            outcome="started",
            resource_type="outbox_message",
            resource_id=row.id,
            run_id=row.run_id,
            alert_id=row.alert_id,
            safe_details={
                "channel": row.channel,
                "attempt": row.attempt,
                "recipient_hash": hashlib.sha256(row.recipient_ref.encode("utf-8")).hexdigest()[
                    :16
                ],
            },
        )
    if claim is None:
        return False

    from types import SimpleNamespace

    try:
        response_code = send_outbox_message(SimpleNamespace(**claim), settings)
        result = ("delivered", response_code, None)
    except DeliveryFailure as exc:
        result = (
            "unknown" if exc.ambiguous else "retry" if exc.retryable else "failed",
            exc.code,
            exc,
        )
    except Exception as exc:
        result = ("unknown", "delivery_internal_error", exc)

    status, response_code, failure = result
    with session_scope(settings) as session:
        row = session.scalar(
            select(OutboxMessage)
            .where(
                OutboxMessage.id == claim["id"],
                OutboxMessage.status == "delivering",
                OutboxMessage.delivery_worker_id == worker_id,
            )
            .with_for_update()
        )
        if row is None:
            return True
        row.status = status
        row.last_response_code = response_code[:80]
        row.delivery_worker_id = None
        row.delivery_lease_expires_at = None
        if status == "delivered":
            row.delivered_at = datetime.now(timezone.utc)
            row.next_attempt_at = None
            action, outcome = "delivery_succeeded", "success"
        elif status == "retry" and row.attempt < settings.outbox_delivery_max_attempts:
            delay = min(300, 5 * (2 ** max(0, row.attempt - 1)))
            row.status = "retry"
            row.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            action, outcome = "delivery_retry_scheduled", "retry"
        elif status == "retry":
            row.status = "failed"
            row.next_attempt_at = None
            action, outcome = "delivery_failed", "failure"
        else:
            row.next_attempt_at = None
            action = "delivery_outcome_unknown" if status == "unknown" else "delivery_failed"
            outcome = "unknown" if status == "unknown" else "failure"
        append_event(
            session,
            actor_type="service",
            actor_id=worker_id,
            action=action,
            event_type=f"delivery.outbox.{action.removeprefix('delivery_')}",
            outcome=outcome,
            resource_type="outbox_message",
            resource_id=row.id,
            run_id=row.run_id,
            alert_id=row.alert_id,
            safe_details={
                "status": row.status,
                "response_code": row.last_response_code,
                "attempt": row.attempt,
                "error_type": type(failure).__name__ if failure else None,
                "next_attempt_at": row.next_attempt_at.isoformat() if row.next_attempt_at else None,
            },
        )
    if failure:
        logger.warning(
            "outbox_delivery_not_confirmed",
            extra={"event": "delivery.outbox.attempt_finished", "outbox_id": claim["id"],
                   "run_id": claim["run_id"], "status": status, "response_code": response_code},
        )
    return True


def _finish_job_session(
    session, job_id: str, worker_id: str, *, error_code: str | None = None
) -> None:
    now = datetime.now(timezone.utc)
    job = session.get(JobRecord, job_id)
    if job is None or job.status != "running" or job.lease_owner != worker_id:
        logger.error("worker_lease_lost", extra={"job_id": job_id})
        raise RuntimeError("lease_lost")
    if error_code is None:
        job.status = "succeeded"
        job.completed_at = now
        action, outcome = "job_succeeded", "success"
    elif job.attempt < job.max_attempts:
        job.status = "retry"
        job.available_at = now + timedelta(seconds=min(300, 2**job.attempt * 5))
        job.last_error_code = error_code
        action, outcome = "job_retry_scheduled", "retry"
    else:
        job.status = "failed"
        job.completed_at = now
        job.last_error_code = error_code
        action, outcome = "job_failed", "failure"
    job.lease_owner = None
    job.lease_expires_at = None
    append_event(
        session, actor_type="service", action=action,
        event_type=f"job.lifecycle.{job.status}", outcome=outcome,
        resource_type="job", resource_id=job.id, run_id=job.run_id,
        safe_details={"attempt": job.attempt, **({"error_code": error_code} if error_code else {})},
    )
    if error_code and job.run_id:
        record = session.get(RunRecord, job.run_id)
        if record is not None and record.status in {"queued", "running"}:
            if job.status == "retry":
                record.status = "queued"
                record.started_at = None
                record.safe_error_code = error_code
                event_action, event_outcome = "run_retry_queued", "retry"
            else:
                record.status = "failed"
                record.safe_error_code = error_code
                record.completed_at = now
                event_action, event_outcome = "run_failed", "failure"
            append_event(
                session, actor_type="service", action=event_action,
                event_type=f"run.lifecycle.{record.status}", outcome=event_outcome,
                resource_type="run", resource_id=record.id,
                request_id=record.request_id, run_id=record.id,
                safe_details={"error_code": error_code},
            )


def _finish_job(job_id: str, worker_id: str, *, error_code: str | None = None) -> None:
    with session_scope() as session:
        _finish_job_session(session, job_id, worker_id, error_code=error_code)


def process_job(job_id: str, worker_id: str, lease_seconds: int = 90) -> None:
    """Execute a persisted run; prompts and provider responses stay in the LLM audit store."""
    run_id: str | None = None
    request_id: str | None = None
    actor_id: str | None = None
    try:
        with session_scope() as session:
            job = session.get(JobRecord, job_id)
            if job is None or job.status != "running" or job.lease_owner != worker_id:
                return
            run_id = job.run_id
            if not run_id or job.job_type != "run":
                raise ValueError("unsupported_job")
            run_record = session.get(RunRecord, run_id)
            request_id = run_record.request_id if run_record else None
            actor_id = run_record.triggered_by if run_record else None
            mark_run_started(session, run_id)
    except Exception as exc:
        error_code = (
            "unsupported_job" if str(exc) == "unsupported_job" else "worker_execution_failed"
        )
        _finish_job(job_id, worker_id, error_code=error_code)
        logger.exception("worker_job_failed", extra={"job_id": job_id, "error_code": error_code})
        return

    stopped = threading.Event()
    lost_lease = threading.Event()

    def maintain_lease() -> None:
        while not stopped.wait(max(5, lease_seconds // 3)):
            try:
                if not heartbeat(job_id, worker_id, lease_seconds):
                    lost_lease.set()
                    return
            except Exception:
                logger.exception("worker_heartbeat_failed", extra={"job_id": job_id})

    heartbeat_thread = threading.Thread(target=maintain_lease, daemon=True)
    heartbeat_thread.start()
    settings = load_settings()
    try:
        llm = get_llm(
            settings=settings,
            run_id=run_id,
            request_id=request_id,
            actor_id=actor_id,
            job_id=job_id,
        )
        source_cursors: dict[str, str | None] = {}
        if settings.public_feeds_enabled:
            with session_scope(settings) as session:
                source_cursors = load_source_cursors(session)
        result = run(
            settings.data_dir,
            settings.out_dir,
            llm,
            settings=settings,
            source_cursors=source_cursors,
        )
        stopped.set()
        heartbeat_thread.join(timeout=2)
        if lost_lease.is_set():
            raise RuntimeError("lease_lost")
        with session_scope() as session:
            persist_run_results(session, run_id, result, settings=settings)
            _finish_job_session(session, job_id, worker_id)
    except Exception as exc:
        stopped.set()
        heartbeat_thread.join(timeout=2)
        error_code = (
            str(exc)
            if str(exc)
            in {
                "unsupported_job",
                "lease_lost",
                "run_not_queued",
                "run_not_running",
                "public_feeds_unavailable",
            }
            else "worker_execution_failed"
        )
        _finish_job(job_id, worker_id, error_code=error_code)
        logger.exception(
            "worker_job_failed",
            extra={"job_id": job_id, "run_id": run_id, "error_code": error_code},
        )


def main() -> None:
    configure_logging()
    settings = load_settings()
    worker_id = os.getenv("WORKER_ID", f"{socket.gethostname()}-{uuid4().hex[:8]}")
    lease_seconds = max(15, int(os.getenv("WORKER_LEASE_SECONDS", "90")))
    poll_seconds = max(1, float(os.getenv("WORKER_POLL_SECONDS", "2")))
    retention_sweep_interval = 300.0
    last_retention_sweep = 0.0
    source_scheduler = start_source_scheduler(settings)
    digest_scheduler = start_digest_scheduler(settings)
    logger.info("worker_started", extra={"worker_id": worker_id})
    while True:
        try:
            monotonic_now = time.monotonic()
            if monotonic_now - last_retention_sweep >= retention_sweep_interval:
                last_retention_sweep = monotonic_now
                settings = load_settings()
                if (
                    settings.llm_audit_content_capture
                    and settings.llm_audit_artifact_retention_days is not None
                ):
                    with session_scope(settings) as session:
                        purged_count = purge_expired_artifacts(session, actor_id=worker_id)
                    if purged_count:
                        logger.info(
                            "Expired LLM artifacts purged",
                            extra={
                                "event": "llm.artifact.retention.purge_completed",
                                "artifact_count": purged_count,
                            },
                        )
            outbox_worked = process_outbox_once(worker_id, settings)
            job_id = claim_job(worker_id, lease_seconds)
            if job_id is None:
                if not outbox_worked:
                    time.sleep(poll_seconds)
                continue
            process_job(job_id, worker_id, lease_seconds)
        except KeyboardInterrupt:
            logger.info("worker_stopping", extra={"worker_id": worker_id})
            if source_scheduler is not None:
                source_scheduler.shutdown(wait=True)
            if digest_scheduler is not None:
                digest_scheduler.shutdown(wait=True)
            return
        except Exception:
            logger.exception("worker_loop_error")
            time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
