"""Database-deduplicated scheduler for explicitly approved public-feed runs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from counterstrike.audit import append_event
from counterstrike.config import Settings
from counterstrike.db import session_scope
from counterstrike.db_models import JobRecord
from counterstrike.repositories import create_run

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from apscheduler.schedulers.background import BackgroundScheduler


def enqueue_source_poll(settings: Settings) -> bool:
    """Create one auditable run/job per UTC schedule window across worker replicas."""
    interval_seconds = settings.public_feed_poll_interval_minutes * 60
    now = datetime.now(timezone.utc)
    window_epoch = int(now.timestamp()) // interval_seconds * interval_seconds
    window_start = datetime.fromtimestamp(window_epoch, tz=timezone.utc)
    schedule_key = f"public-feed:{settings.public_feed_poll_interval_minutes}:{window_epoch}"
    request_id = f"source-poll-{window_epoch}"

    try:
        with session_scope(settings) as session:
            existing = session.scalar(
                select(JobRecord.id).where(JobRecord.schedule_key == schedule_key)
            )
            if existing is not None:
                logger.info(
                    "Public feed schedule window already enqueued",
                    extra={
                        "event": "source.schedule.deduplicated",
                        "schedule_key": schedule_key,
                        "job_id": existing,
                    },
                )
                return False

            run = create_run(
                session,
                trigger_type="scheduled",
                actor_id=None,
                request_id=request_id,
            )
            job = JobRecord(
                job_type="run",
                status="queued",
                payload={
                    "scope": "configured_data_dir",
                    "schedule_window_start": window_start.isoformat(),
                },
                run_id=run.id,
                schedule_key=schedule_key,
                max_attempts=3,
            )
            session.add(job)
            session.flush()
            append_event(
                session,
                actor_type="service",
                actor_id="source-scheduler",
                action="source_poll_job_queued",
                event_type="source.poll.job_queued",
                outcome="success",
                resource_type="job",
                resource_id=job.id,
                request_id=request_id,
                job_id=job.id,
                run_id=run.id,
                safe_details={
                    "schedule_window_start": window_start.isoformat(),
                    "interval_minutes": settings.public_feed_poll_interval_minutes,
                },
            )
        logger.info(
            "Public feed poll queued",
            extra={
                "event": "source.schedule.enqueued",
                "schedule_key": schedule_key,
                "job_id": job.id,
                "run_id": run.id,
            },
        )
        return True
    except IntegrityError:
        # A different worker may have inserted this schedule window concurrently.
        with session_scope(settings) as session:
            existing = session.scalar(
                select(JobRecord.id).where(JobRecord.schedule_key == schedule_key)
            )
        if existing is None:
            raise
        logger.info(
            "Public feed schedule window won by another worker",
            extra={
                "event": "source.schedule.deduplicated",
                "schedule_key": schedule_key,
                "job_id": existing,
            },
        )
        return False


def _enqueue_source_poll_observed(settings: Settings) -> bool:
    """Log failed schedule attempts without exposing exception text or credentials."""
    try:
        return enqueue_source_poll(settings)
    except Exception as exc:
        error_code = "database_error" if isinstance(exc, SQLAlchemyError) else type(exc).__name__
        logger.error(
            "Public feed schedule enqueue failed",
            extra={
                "event": "source.schedule.enqueue_failed",
                "interval_minutes": settings.public_feed_poll_interval_minutes,
                "error_code": error_code[:80],
            },
        )
        raise


def start_source_scheduler(settings: Settings) -> BackgroundScheduler | None:
    """Start the interval scheduler only after all source and database gates pass."""
    if not settings.public_feed_scheduler_enabled:
        return None
    if not settings.public_feeds_enabled or not settings.public_feeds_approved:
        raise RuntimeError("public_feed_scheduler_approval_required")
    if settings.database_url is None:
        raise RuntimeError("public_feed_scheduler_database_required")

    from apscheduler.schedulers.background import BackgroundScheduler

    interval_seconds = settings.public_feed_poll_interval_minutes * 60
    now = datetime.now(timezone.utc)
    next_epoch = (int(now.timestamp()) // interval_seconds + 1) * interval_seconds
    first_run = datetime.fromtimestamp(next_epoch, tz=timezone.utc)
    scheduler = BackgroundScheduler(timezone=timezone.utc)
    scheduler.add_job(
        _enqueue_source_poll_observed,
        trigger="interval",
        seconds=interval_seconds,
        start_date=first_run,
        args=(settings,),
        id="approved-public-feed-poll",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=max(60, interval_seconds),
    )
    scheduler.start()
    logger.info(
        "Public feed scheduler started",
        extra={
            "event": "source.schedule.started",
            "interval_minutes": settings.public_feed_poll_interval_minutes,
            "first_run_at": first_run.isoformat(),
        },
    )
    return scheduler
