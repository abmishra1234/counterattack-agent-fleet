"""Daily, idempotent alert digest creation for the transactional delivery outbox."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, time, timedelta, timezone
from uuid import uuid4

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from counterstrike.audit import append_event
from counterstrike.config import Settings
from counterstrike.db import session_scope
from counterstrike.db_models import AlertRecord, OutboxMessage

logger = logging.getLogger("counterstrike.digest")


def _utc_day_window(now: datetime) -> tuple[datetime, datetime, str]:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    today = now.astimezone(timezone.utc).date()
    start_date = today - timedelta(days=1)
    start = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
    end = datetime.combine(today, time.min, tzinfo=timezone.utc)
    return start, end, start_date.isoformat()


def _alert_item(alert: AlertRecord) -> dict[str, object]:
    return {
        "cve_id": alert.cve_id,
        "priority": alert.priority,
        "service": alert.service,
        "asset_key": alert.asset_key,
        "component": alert.component,
        "installed_version": alert.installed_version,
        "fixed_version": alert.fixed_version,
        "risk_score": format(alert.risk_score, ".3f"),
        "sla_hours": alert.sla_hours,
        "owner": alert.owner,
        "summary": alert.summary[:1200],
        "remediation": alert.remediation[:1200],
    }


def _enqueue_digest(
    session,
    *,
    settings: Settings,
    start: datetime,
    end: datetime,
    digest_date: str,
    route: str,
    recipient: str,
    alerts: list[AlertRecord],
) -> bool:
    if not alerts:
        return False
    shown = alerts[: settings.outbox_daily_digest_max_items]
    items = [_alert_item(alert) for alert in shown]
    payload = {
        "digest": True,
        "digest_type": "daily_alerts",
        "digest_date": digest_date,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "alert_count": len(alerts),
        "displayed_count": len(items),
        "truncated": len(alerts) > len(items),
        "delivery_route": route,
        "alerts": items,
    }
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    recipient_hash = hashlib.sha256(recipient.encode("utf-8")).hexdigest()
    idempotency_key = hashlib.sha256(
        f"daily-digest:{settings.outbox_channel}:{digest_date}:{route}:{recipient_hash}".encode()
    ).hexdigest()
    dialect = session.bind.dialect.name if session.bind is not None else ""
    insert = (
        postgresql_insert
        if dialect == "postgresql"
        else sqlite_insert
        if dialect == "sqlite"
        else None
    )
    if insert is None:
        raise RuntimeError("Daily digest outbox requires PostgreSQL or SQLite")
    message_id = str(uuid4())
    result = session.execute(
        insert(OutboxMessage)
        .values(
            id=message_id,
            run_id=None,
            alert_id=None,
            channel=settings.outbox_channel,
            recipient_ref=recipient,
            idempotency_key=idempotency_key,
            payload=payload,
            payload_hash=payload_hash,
            status="queued",
            attempt=0,
        )
        .on_conflict_do_nothing(index_elements=[OutboxMessage.idempotency_key])
        .returning(OutboxMessage.id)
    )
    inserted_id = result.scalar_one_or_none()
    if inserted_id is None:
        return False
    append_event(
        session,
        actor_type="service",
        actor_id="daily-digest-scheduler",
        action="daily_digest_enqueued",
        event_type="delivery.digest.enqueued",
        outcome="success",
        resource_type="outbox_message",
        resource_id=inserted_id,
        safe_details={
            "channel": settings.outbox_channel,
            "route": route,
            "digest_date": digest_date,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "alert_count": len(alerts),
            "displayed_count": len(items),
            "truncated": len(alerts) > len(items),
            "payload_hash": payload_hash,
            "recipient_hash": recipient_hash[:16],
            "idempotency_key": idempotency_key,
        },
    )
    return True


def enqueue_daily_digest(settings: Settings, *, now: datetime | None = None) -> int:
    """Queue the previous full UTC day's alerts once per channel, route, and recipient."""
    if not settings.outbox_daily_digest_enabled:
        return 0
    start, end, digest_date = _utc_day_window(now or datetime.now(timezone.utc))
    inserted = 0
    scanned_alert_count = 0
    mapped_alert_count = 0
    unmapped_alert_count = 0
    owner_group_count = 0
    critical_alert_count = 0
    candidate_message_count = 0
    with session_scope(settings) as session:
        alerts = session.scalars(
            select(AlertRecord)
            .where(AlertRecord.created_at >= start, AlertRecord.created_at < end)
            .order_by(
                AlertRecord.priority,
                AlertRecord.risk_score.desc(),
                AlertRecord.created_at,
                AlertRecord.id,
            )
        ).all()
        scanned_alert_count = len(alerts)
        by_recipient: dict[str, list[AlertRecord]] = {}
        for alert in alerts:
            recipient = settings.outbox_recipient_refs.get(alert.owner)
            if recipient:
                by_recipient.setdefault(recipient, []).append(alert)
            else:
                unmapped_alert_count += 1
        owner_group_count = len(by_recipient)
        mapped_alert_count = sum(len(group) for group in by_recipient.values())
        candidate_message_count += owner_group_count
        for recipient in sorted(by_recipient):
            inserted += _enqueue_digest(
                session,
                settings=settings,
                start=start,
                end=end,
                digest_date=digest_date,
                route="owner_digest",
                recipient=recipient,
                alerts=by_recipient[recipient],
            )
        critical_alerts = [alert for alert in alerts if alert.priority in {"P1", "P2"}]
        critical_alert_count = len(critical_alerts)
        if settings.outbox_security_recipient_ref and critical_alerts:
            candidate_message_count += 1
            inserted += _enqueue_digest(
                session,
                settings=settings,
                start=start,
                end=end,
                digest_date=digest_date,
                route="security_digest",
                recipient=settings.outbox_security_recipient_ref.get_secret_value(),
                alerts=critical_alerts,
            )
        append_event(
            session,
            actor_type="service",
            actor_id="daily-digest-scheduler",
            action="daily_digest_evaluated",
            event_type="delivery.digest.evaluated",
            outcome="success",
            resource_type="digest_window",
            resource_id=digest_date,
            safe_details={
                "digest_date": digest_date,
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "scanned_alert_count": scanned_alert_count,
                "mapped_alert_count": mapped_alert_count,
                "unmapped_alert_count": unmapped_alert_count,
                "owner_group_count": owner_group_count,
                "critical_alert_count": critical_alert_count,
                "candidate_message_count": candidate_message_count,
                "enqueued_message_count": inserted,
                "deduplicated_message_count": candidate_message_count - inserted,
            },
        )
    logger.info(
        "daily_digest_enqueued",
        extra={"digest_date": digest_date, "message_count": inserted},
    )
    return inserted


def start_digest_scheduler(settings: Settings) -> BackgroundScheduler | None:
    """Start the UTC digest schedule and queue yesterday once for restart catch-up."""
    if not settings.outbox_daily_digest_enabled:
        return None
    scheduler = BackgroundScheduler(timezone=timezone.utc)
    scheduler.add_job(
        enqueue_daily_digest,
        trigger="cron",
        hour=settings.outbox_daily_digest_hour_utc,
        minute=settings.outbox_daily_digest_minute_utc,
        args=[settings],
        id="daily-alert-digest",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.start()
    now_utc = datetime.now(timezone.utc)
    scheduled_time = time(
        settings.outbox_daily_digest_hour_utc,
        settings.outbox_daily_digest_minute_utc,
        tzinfo=timezone.utc,
    )
    if now_utc.timetz() >= scheduled_time:
        enqueue_daily_digest(settings, now=now_utc)
    logger.info(
        "daily_digest_scheduler_started",
        extra={
            "hour_utc": settings.outbox_daily_digest_hour_utc,
            "minute_utc": settings.outbox_daily_digest_minute_utc,
        },
    )
    return scheduler
