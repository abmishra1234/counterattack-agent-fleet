import base64
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from counterstrike.artifacts import purge_expired_artifacts, read_artifact, store_artifact
from counterstrike.audit import verify_chain
from counterstrike.db import session_scope
from counterstrike.db_models import AuditEvent, LLMExchangeArtifact
from counterstrike.llm_metering import (
    complete_attempt,
    fail_attempt,
    mark_pending_attempts_unknown,
    prepare_attempt,
)
from counterstrike.repositories import create_run


@pytest.fixture
def audit_settings(db_settings):
    return db_settings.model_copy(
        update={
            "llm_audit_content_capture": True,
            "llm_audit_artifact_retention_days": 30,
            "llm_provider": "openai_compatible",
            "llm_audit_encryption_key": SecretStr(base64.urlsafe_b64encode(b"a" * 32).decode()),
            "llm_input_price_usd_per_1m": Decimal("0.15"),
            "llm_output_price_usd_per_1m": Decimal("0.60"),
            "llm_model": "test-model",
        }
    )


def pending(session, settings, run_id, job_id="test-job"):
    return prepare_attempt(
        session,
        settings=settings,
        run_id=run_id,
        job_id=job_id,
        task="summarise",
        model="test-model",
        prompt_version="test-v1",
        request_id="req-test",
        actor_id="tester",
        advisory_id="CVE-2099-0001",
        attempt_number=1,
        parent_call_id=None,
        exact_request={"provider_request": {"messages": [{"content": "private source"}]}},
    )


def test_exact_exchange_encryption_metering_and_api(audit_settings):
    from counterstrike.api import create_app

    with session_scope(audit_settings) as session:
        run = create_run(session, trigger_type="manual", actor_id="tester", request_id="req-test")
        record = pending(session, audit_settings, run.id)
        call_id, run_id = record.id, run.id
        complete_attempt(
            session,
            record,
            settings=audit_settings,
            raw_response='{"result":"summary"}',
            usage={"prompt_tokens": 1000, "completion_tokens": 500},
            response_id="provider-response",
            latency_ms=10,
            parsed_output="summary",
        )
        assert record.cost_amount == Decimal("0.00045")
        assert record.total_tokens == 1500
        artifacts = session.scalars(select(LLMExchangeArtifact)).all()
        assert len(artifacts) == 3
        assert all(b"private source" not in item.encrypted_payload for item in artifacts)
        assert verify_chain(session) == (True, None)
    with TestClient(create_app(audit_settings)) as client:
        usage = client.get("/api/v1/llm/usage", params={"run_id": run_id}).json()
        assert usage["total"] == 1
        detail = client.get(f"/api/v1/llm/usage/{call_id}").json()
        assert len(detail["artifacts"]) == 3
        for group in (
            "day",
            "run",
            "task",
            "provider",
            "model",
            "prompt_version",
            "advisory",
            "actor",
            "outcome",
        ):
            response = client.get("/api/v1/llm/usage/report", params={"group_by": group})
            assert response.status_code == 200, response.text
            assert response.json()["total_calls"] == 1
            assert response.json()["groups"][0]["total_tokens"] == 1500
        assert client.get("/api/v1/llm/budgets", params={"run_id": run_id}).status_code == 200
        content = client.post(
            f"/api/v1/llm/usage/{call_id}/content",
            json={
                "kind": "request",
                "purpose": "Investigate source grounding",
            },
        )
        assert content.status_code == 200, content.text
        assert "private source" in content.json()["content"]
        assert (
            client.post(
                f"/api/v1/llm/usage/{call_id}/content",
                json={
                    "kind": "provider_error",
                    "purpose": "Investigate source grounding",
                },
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/v1/llm/usage/missing/content",
                json={
                    "kind": "request",
                    "purpose": "Investigate source grounding",
                },
            ).status_code
            == 404
        )
        assert (
            client.post(
                f"/api/v1/llm/usage/{call_id}/content",
                json={
                    "kind": "request",
                    "purpose": "   ",
                },
            ).status_code
            == 422
        )
        filters = {
            "since": "2000-01-01T00:00:00",
            "until": "2099-01-01T00:00:00Z",
            "request_id": "req-test",
            "job_id": "test-job",
            "provider": record.provider,
            "model": "test-model",
            "task": "summarise",
            "actor_id": "tester",
            "advisory_id": "CVE-2099-0001",
            "prompt_version": "test-v1",
            "currency": "USD",
            "outcome": "succeeded",
        }
        assert client.get("/api/v1/llm/usage", params=filters).json()["total"] == 1
        assert (
            client.get(
                "/api/v1/llm/usage",
                params={
                    "since": "2099-01-01",
                    "until": "2000-01-01",
                },
            ).status_code
            == 422
        )


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("denied", "denied"),
        ("empty_purpose", "denied"),
        ("expired", "expired"),
        ("purged", "purged"),
        ("tampered", "integrity_failure"),
        ("hash", "integrity_failure"),
        ("missing_key", "key_unavailable"),
    ],
)
def test_artifact_access_failures_are_audited(audit_settings, scenario, expected):
    with session_scope(audit_settings) as session:
        run = create_run(session, trigger_type="manual", actor_id=None, request_id=None)
        record = pending(session, audit_settings, run.id)
        artifact = session.scalar(select(LLMExchangeArtifact))
        settings = audit_settings
        if scenario == "expired":
            artifact.retention_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        elif scenario == "purged":
            artifact.encrypted_payload = b""
        elif scenario == "tampered":
            artifact.encrypted_payload = b"x" * 50
        elif scenario == "hash":
            artifact.plaintext_hash = "0" * 64
        elif scenario == "missing_key":
            settings = audit_settings.model_copy(update={"llm_audit_encryption_key": None})
        content, outcome = read_artifact(
            session,
            artifact,
            actor_id="tester",
            request_id=None,
            purpose="" if scenario == "empty_purpose" else "investigation",
            authorized=scenario != "denied",
            settings=settings,
        )
        assert content is None and outcome == expected
        assert (
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.llm_call_id == record.id,
                    AuditEvent.outcome == expected,
                )
            ).first()
            is not None
        )


def test_failure_recovery_and_retention(audit_settings):
    with session_scope(audit_settings) as session:
        run = create_run(session, trigger_type="manual", actor_id=None, request_id=None)
        record = pending(session, audit_settings, run.id)
        fail_attempt(
            session,
            record,
            settings=audit_settings,
            error_code="http_429",
            safe_error="secret-token refused",
            provider_secret="secret-token",
            raw_response="rate limited",
            latency_ms=20,
            response_status=429,
        )
        assert record.outcome == "failed"
        artifact = session.scalar(
            select(LLMExchangeArtifact).where(
                LLMExchangeArtifact.artifact_kind == "provider_error",
            )
        )
        content, outcome = read_artifact(
            session,
            artifact,
            actor_id="tester",
            request_id=None,
            purpose="investigation",
            authorized=True,
            settings=audit_settings,
        )
        assert outcome == "success"
        assert "secret-token" not in content
        assert "[REDACTED]" in json.loads(content)["body"]
        with pytest.raises(RuntimeError, match="already finalized"):
            fail_attempt(
                session,
                record,
                settings=audit_settings,
                error_code="repeat",
                safe_error="repeat",
                latency_ms=1,
            )
        abandoned = pending(session, audit_settings, run.id)
        assert mark_pending_attempts_unknown(session, job_id="test-job") == 1
        assert abandoned.outcome == "unknown"
        assert mark_pending_attempts_unknown(session, job_id="test-job") == 0
        assert (
            purge_expired_artifacts(
                session,
                actor_id="tester",
                now=(datetime.now(timezone.utc) + timedelta(days=31)).replace(tzinfo=None),
            )
            == 4
        )
        assert all(
            item.encrypted_payload == b""
            for item in session.scalars(
                select(LLMExchangeArtifact),
            )
        )
        assert verify_chain(session) == (True, None)


def test_storage_requires_capture_and_retention(db_settings):
    with session_scope(db_settings) as session:
        with pytest.raises(RuntimeError, match="disabled"):
            store_artifact(session, call_id="x", kind="request", content="x", settings=db_settings)
