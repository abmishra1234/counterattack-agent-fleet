import json
import smtplib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from counterstrike import delivery, digest_scheduler, source_scheduler, worker
from counterstrike.audit import verify_chain
from counterstrike.config import Settings
from counterstrike.db import session_scope
from counterstrike.db_models import AlertRecord, JobRecord, OutboxMessage, RunRecord
from counterstrike.repositories import create_run, mark_run_started, persist_run_results


@pytest.mark.parametrize(
    "status,expected,retryable,ambiguous",
    [
        (200, "http_200", False, False),
        (429, "teams_http_429", True, False),
        (500, "teams_http_500", False, True),
        (400, "teams_http_400", False, False),
    ],
)
def test_teams_delivery_classifies_provider_response(
    monkeypatch, status, expected, retryable, ambiguous
):
    post = MagicMock(return_value=httpx.Response(status))
    monkeypatch.setattr(delivery.httpx, "post", post)
    settings = Settings(
        outbox_teams_webhook_url="https://teams.example/owner",
        outbox_teams_security_webhook_url="https://teams.example/security",
    )
    message = SimpleNamespace(
        channel="teams", payload={"delivery_route": "security"}, idempotency_key="key"
    )
    if status == 200:
        assert delivery.send_outbox_message(message, settings) == expected
    else:
        with pytest.raises(delivery.DeliveryFailure) as error:
            delivery.send_outbox_message(message, settings)
        assert (error.value.code, error.value.retryable, error.value.ambiguous) == (
            expected,
            retryable,
            ambiguous,
        )
    assert post.call_args.args[0] == "https://teams.example/security"
    assert post.call_args.kwargs["follow_redirects"] is False


@pytest.mark.parametrize(
    "exc,code",
    [
        (httpx.ConnectError("offline"), "teams_connect_error"),
        (httpx.ReadTimeout("timeout"), "teams_timeout"),
        (httpx.RemoteProtocolError("broken"), "teams_transport_error"),
    ],
)
def test_teams_transport_failures(monkeypatch, exc, code):
    monkeypatch.setattr(delivery.httpx, "post", MagicMock(side_effect=exc))
    message = SimpleNamespace(channel="teams", payload={}, idempotency_key="key")
    with pytest.raises(delivery.DeliveryFailure, match=code):
        delivery.send_outbox_message(
            message,
            Settings(
                outbox_teams_webhook_url="https://teams.example/owner",
            ),
        )


@pytest.mark.parametrize(
    "failure,code",
    [
        (None, "smtp_accepted"),
        (smtplib.SMTPAuthenticationError(535, b"bad"), "smtp_authentication_failed"),
        (smtplib.SMTPRecipientsRefused({}), "smtp_recipient_refused"),
        (smtplib.SMTPResponseException(450, b"busy"), "smtp_response_450"),
        (smtplib.SMTPServerDisconnected(), "smtp_transport_ambiguous"),
        (smtplib.SMTPException(), "smtp_transport_ambiguous"),
    ],
)
def test_smtp_delivery(monkeypatch, failure, code):
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    smtp.send_message.return_value = {}
    if failure:
        smtp.send_message.side_effect = failure
    monkeypatch.setattr(delivery.smtplib, "SMTP", MagicMock(return_value=smtp))
    settings = Settings(
        outbox_smtp_host="smtp.example",
        outbox_smtp_from="sender@example.com",
        outbox_smtp_username="user",
        outbox_smtp_password="password",
    )
    message = SimpleNamespace(
        channel="email",
        payload={"priority": "P1", "evidence": ["fact"]},
        recipient_ref="owner@example.com",
        idempotency_key="stable-key",
    )
    if failure:
        with pytest.raises(delivery.DeliveryFailure, match=code):
            delivery.send_outbox_message(message, settings)
    else:
        assert delivery.send_outbox_message(message, settings) == code
        email = smtp.send_message.call_args.args[0]
        assert email["Message-ID"] == "<stable-key@counterstrike.local>"
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("user", "password")


@pytest.mark.parametrize(
    "channel,recipient,code",
    [
        ("teams", "owner", "teams_not_configured"),
        ("other", "owner", "unsupported_channel"),
        ("email", "Name <owner@example.com>", "invalid_email_recipient"),
        ("email", "owner@example.com", "smtp_not_configured"),
    ],
)
def test_delivery_configuration_failures(channel, recipient, code):
    message = SimpleNamespace(
        channel=channel, payload={}, recipient_ref=recipient, idempotency_key="x"
    )
    with pytest.raises(delivery.DeliveryFailure, match=code):
        delivery.send_outbox_message(message, Settings())


@pytest.mark.parametrize(
    "result,expected",
    [
        ("ok", "delivered"),
        ("retry", "retry"),
        ("failed", "failed"),
        ("ambiguous", "unknown"),
        ("unexpected", "unknown"),
        ("exhausted", "failed"),
        ("expired", "unknown"),
    ],
)
def test_outbox_worker_transitions(db_settings, monkeypatch, result, expected):
    settings = db_settings.model_copy(
        update={
            "outbox_delivery_enabled": True,
            "outbox_channel": "teams",
        }
    )
    now = datetime.now(timezone.utc)
    with session_scope(settings) as session:
        message = OutboxMessage(
            channel="teams",
            recipient_ref="owner",
            idempotency_key="key",
            payload={"priority": "P1"},
            payload_hash="0" * 64,
        )
        if result == "expired":
            message.status = "delivering"
            message.delivery_lease_expires_at = now - timedelta(seconds=1)
        elif result == "exhausted":
            message.attempt = settings.outbox_delivery_max_attempts
        session.add(message)
        session.flush()
        message_id = message.id

    def send(*args):
        if result == "retry":
            raise delivery.DeliveryFailure("busy", retryable=True)
        if result == "failed":
            raise delivery.DeliveryFailure("refused")
        if result == "ambiguous":
            raise delivery.DeliveryFailure("timeout", ambiguous=True)
        if result == "unexpected":
            raise RuntimeError("internal")
        return "http_200"

    monkeypatch.setattr(worker, "send_outbox_message", send)
    assert worker.process_outbox_once("test-worker", settings) is True
    with session_scope(settings) as session:
        message = session.get(OutboxMessage, message_id)
        assert message.status == expected
        assert message.delivery_worker_id is None
        assert (message.next_attempt_at is not None) == (expected == "retry")
        assert verify_chain(session) == (True, None)
    assert worker.process_outbox_once("test-worker", settings) is False


def test_job_failure_retries_then_exhausts(db_settings, monkeypatch):
    with session_scope(db_settings) as session:
        run = create_run(session, trigger_type="manual", actor_id=None, request_id=None)
        job = JobRecord(job_type="run", run_id=run.id, max_attempts=2)
        session.add(job)
        session.flush()
        job_id, run_id = job.id, run.id
    monkeypatch.setattr(worker, "run", MagicMock(side_effect=RuntimeError("provider unavailable")))
    assert worker.claim_job("test-worker") == job_id
    worker.process_job(job_id, "test-worker")
    with session_scope(db_settings) as session:
        assert session.get(JobRecord, job_id).status == "retry"
        assert session.get(RunRecord, run_id).status == "queued"
        session.get(JobRecord, job_id).available_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
    assert worker.claim_job("test-worker") == job_id
    worker.process_job(job_id, "test-worker")
    with session_scope(db_settings) as session:
        assert session.get(JobRecord, job_id).status == "failed"
        assert session.get(RunRecord, run_id).status == "failed"
    assert worker.heartbeat("missing", "test-worker", 90) is False
    worker.process_job("missing", "test-worker")


def test_stale_job_at_attempt_limit_is_failed(db_settings):
    with session_scope(db_settings) as session:
        run = create_run(session, trigger_type="manual", actor_id=None, request_id=None)
        job = JobRecord(
            job_type="run",
            run_id=run.id,
            status="running",
            attempt=3,
            max_attempts=3,
            lease_expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        session.add(job)
        session.flush()
        job_id = job.id
    assert worker.claim_job("new-worker") is None
    with session_scope(db_settings) as session:
        assert session.get(JobRecord, job_id).last_error_code == "attempt_limit_reached"


def test_schedulers_deduplicate_and_digest_routes(db_settings, persisted_run):
    run_id, state = persisted_run
    refs = {asset.owner: f"{asset.owner}@example.com" for asset in state["inventory"]}
    settings = db_settings.model_copy(
        update={
            "outbox_enqueue_enabled": True,
            "outbox_channel": "email",
            "outbox_recipient_map_json": SecretStr(json.dumps(refs)),
            "outbox_security_recipient_ref": SecretStr("security@example.com"),
            "outbox_daily_digest_enabled": True,
        }
    )
    with session_scope(settings) as session:
        new_run = create_run(session, trigger_type="manual", actor_id=None, request_id=None)
        mark_run_started(session, new_run.id)
        persist_run_results(session, new_run.id, state, settings=settings)
        rows = session.scalars(select(OutboxMessage)).all()
        assert len(rows) > len(state["alerts"])
        assert {row.payload["delivery_route"] for row in rows} == {"owner", "security"}
        alerts = session.scalars(select(AlertRecord)).all()
        for alert in alerts:
            alert.created_at = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    now = datetime(2026, 1, 2, 12)
    count = digest_scheduler.enqueue_daily_digest(settings, now=now)
    assert count > 1
    assert digest_scheduler.enqueue_daily_digest(settings, now=now) == 0
    with session_scope(settings) as session:
        digests = [
            row for row in session.scalars(select(OutboxMessage)) if row.payload.get("digest")
        ]
        assert len(digests) == count
        assert {row.payload["delivery_route"] for row in digests} == {
            "owner_digest",
            "security_digest",
        }
        body = delivery._body(digests[0].payload, "owner_digest", "key")
        assert "daily vulnerability digest" in body
        assert "Delivery key: key" in body
    assert source_scheduler.enqueue_source_poll(settings) is True
    assert source_scheduler.enqueue_source_poll(settings) is False
    assert source_scheduler.start_source_scheduler(db_settings) is None
    assert digest_scheduler.start_digest_scheduler(db_settings) is None


def test_scheduler_startup_registers_bounded_jobs(db_settings, monkeypatch):
    scheduler = MagicMock()
    monkeypatch.setattr(
        "apscheduler.schedulers.background.BackgroundScheduler", lambda **kwargs: scheduler
    )
    monkeypatch.setattr(digest_scheduler, "BackgroundScheduler", lambda **kwargs: scheduler)
    monkeypatch.setattr(digest_scheduler, "enqueue_daily_digest", MagicMock())
    settings = db_settings.model_copy(
        update={
            "public_feed_scheduler_enabled": True,
            "public_feeds_enabled": True,
            "public_feeds_approved": True,
            "outbox_daily_digest_enabled": True,
        }
    )
    assert source_scheduler.start_source_scheduler(settings) is scheduler
    assert digest_scheduler.start_digest_scheduler(settings) is scheduler
    assert scheduler.add_job.call_count == 2
    assert scheduler.start.call_count == 2
