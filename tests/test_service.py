"""Offline service contracts against a temporary, real SQL database."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from counterstrike.audit import verify_chain
from counterstrike.config import Settings
from counterstrike.db import session_scope
from counterstrike.db_models import AlertRecord, FindingRecord, JobRecord, RunRecord


def create_app(settings):
    # Import after the offline environment fixture has isolated deployment settings.
    from counterstrike.api import create_app as factory

    return factory(settings)


@pytest.fixture
def client(db_settings):
    with TestClient(create_app(db_settings)) as client:
        yield client


def test_empty_database_and_schema(client):
    dashboard = client.get("/api/v1/dashboard").json()
    assert dashboard["latest_run"] is None
    assert dashboard["affected_assets"] == 0
    for path in ("runs", "alerts", "reviews", "inventory", "deliveries", "llm/usage"):
        response = client.get(f"/api/v1/{path}")
        assert response.status_code == 200, response.text
        assert response.json()["items"] == []
    assert client.get("/api/v1/auth/context").json()["role"] == "admin"
    schema = client.get("/openapi.json").json()
    assert "/api/v1/runs" in schema["paths"]
    assert client.get("/openapi.json").json() == schema


def test_queue_is_idempotent_and_worker_persists_results(client, db_settings):
    from counterstrike.worker import claim_job, heartbeat, process_job

    headers = {"Idempotency-Key": "test-manual-run", "X-Request-ID": "req-test"}
    first = client.post("/api/v1/runs", headers=headers)
    assert first.status_code == 202, first.text
    accepted = first.json()
    again = client.post("/api/v1/runs", headers=headers).json()
    assert again["deduplicated"] is True
    assert again["run_id"] == accepted["run_id"]
    job_id = claim_job("test-worker")
    assert job_id == accepted["job_id"]
    assert heartbeat(job_id, "other-worker", 90) is False
    assert heartbeat(job_id, "test-worker", 90) is True
    process_job(job_id, "test-worker")
    with session_scope(db_settings) as session:
        assert session.get(JobRecord, job_id).status == "succeeded"
        record = session.get(RunRecord, accepted["run_id"])
        assert record.status == "succeeded"
        assert record.summary["alerts"] == 5
        assert verify_chain(session) == (True, None)
    assert claim_job("test-worker") is None
    detail = client.get(accepted["status_url"]).json()
    assert detail["status"] == "succeeded"
    assert detail["trace"]


def test_findings_inventory_and_review_lifecycle(client, persisted_run, db_settings):
    run_id, state = persisted_run
    dashboard = client.get("/api/v1/dashboard").json()
    assert dashboard["latest_run"]["id"] == run_id
    assert sum(dashboard["by_priority"].values()) == len(state["alerts"])
    runs = client.get("/api/v1/runs", params={"status": "succeeded"}).json()
    assert runs["total"] == 1
    alerts = client.get("/api/v1/alerts").json()
    assert alerts["total"] == 5
    alert = alerts["items"][0]
    detail = client.get(f"/api/v1/alerts/{alert['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence"]
    filtered = client.get(
        "/api/v1/alerts",
        params={
            "priority": alert["priority"],
            "owner": alert["owner"],
            "service": alert["service"],
            "search": alert["cve_id"],
            "since": "2000-01-01T00:00:00Z",
        },
    ).json()
    assert alert["id"] in {item["id"] for item in filtered["items"]}
    inventory = client.get("/api/v1/inventory").json()
    assert len(inventory["items"]) == len(state["inventory"])
    assert (
        client.get(
            "/api/v1/inventory",
            params={
                "search": "log4j",
                "criticality": "high",
                "internet_facing": True,
                "asset_type": "application",
            },
        ).status_code
        == 200
    )
    assert client.get("/api/v1/sources").json()["items"]
    reviews = client.get("/api/v1/reviews", params={"state": "open", "run_id": run_id}).json()
    assert reviews["items"]
    case = reviews["items"][0]
    body = {"disposition": "insufficient_evidence", "note": "Reviewed source evidence"}
    response = client.post(f"/api/v1/reviews/{case['id']}/decision", json=body)
    assert response.status_code == 201, response.text
    assert response.json()["state"] == "resolved"
    assert client.post(f"/api/v1/reviews/{case['id']}/decision", json=body).status_code == 409
    resolved = client.get("/api/v1/reviews", params={"state": "resolved"}).json()
    assert resolved["items"][0]["decisions"][0]["note"] == body["note"]
    audit = client.get("/api/v1/audit/events", params={"run_id": run_id}).json()
    assert audit["total"] > 0
    assert client.get("/api/v1/audit/integrity").status_code == 200
    with session_scope(db_settings) as session:
        assert len(session.scalars(select(AlertRecord)).all()) == 5
        assert verify_chain(session) == (True, None)


def test_repeated_runs_update_findings_instead_of_duplicating(client, persisted_run, db_settings):
    from counterstrike.repositories import create_run, mark_run_started, persist_run_results

    first_run_id, state = persisted_run
    with session_scope(db_settings) as session:
        finding = session.scalars(select(FindingRecord)).first()
        finding.status = "resolved"
        resolved_key = finding.finding_key
        second = create_run(session, trigger_type="scheduled", actor_id=None, request_id="req-2")
        mark_run_started(session, second.id)
        persist_run_results(session, second.id, state, settings=db_settings)
        second_run_id = second.id

    alerts = client.get("/api/v1/alerts").json()
    assert alerts["total"] == len(state["alerts"]) == 5
    keys = {(item["cve_id"], item["asset_key"]) for item in alerts["items"]}
    assert len(keys) == 5
    for item in alerts["items"]:
        assert item["occurrences"] == 2
        assert item["run_id"] == second_run_id
        assert item["first_seen_at"] <= item["last_seen_at"]
    history = client.get("/api/v1/alerts", params={"run_id": first_run_id}).json()
    assert history["total"] == 5
    assert all(item["finding_id"] is None for item in history["items"])
    with session_scope(db_settings) as session:
        assert len(session.scalars(select(AlertRecord)).all()) == 10
        findings = session.scalars(select(FindingRecord)).all()
        assert len(findings) == 5
        assert {item.first_run_id for item in findings} == {first_run_id}
        reopened = next(item for item in findings if item.finding_key == resolved_key)
        assert reopened.status == "open"


@pytest.mark.parametrize("path", ["runs/missing", "alerts/missing", "llm/usage/missing"])
def test_missing_resources_return_safe_errors(client, path):
    response = client.get(f"/api/v1/{path}")
    assert response.status_code == 404
    assert response.json()["error"]["request_id"]


def test_invalid_requests_are_rejected(client):
    assert client.post("/api/v1/runs").status_code == 422
    assert (
        client.post("/api/v1/runs", headers={"Idempotency-Key": "invalid key!"}).status_code == 422
    )
    assert client.get("/api/v1/alerts?limit=-1").status_code == 422
    assert (
        client.post(
            "/api/v1/reviews/missing/decision",
            json={
                "disposition": "insufficient_evidence",
                "note": "checked",
            },
        ).status_code
        == 404
    )
    assert client.get("/api/v1/new-unmapped-route").status_code == 403


@pytest.mark.parametrize("path", ["runs", "reviews", "deliveries", "audit/events", "llm/usage"])
def test_viewer_cannot_mutate_or_read_restricted_records(db_settings, path):
    settings = db_settings.model_copy(update={"local_dev_role": "viewer"})
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/v1/runs") if path == "runs" else client.get(f"/api/v1/{path}")
        assert response.status_code == 403


def test_fixture_health_preview_metrics_and_missing_database(tmp_path, data_dir):
    from counterstrike.graph import run
    from counterstrike.llm import FakeLLM

    settings = Settings(data_dir=data_dir, out_dir=tmp_path)
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 503
        assert client.get("/api/data").status_code == 503
        assert client.get("/api/v1/runs").status_code == 503
        run(data_dir, tmp_path, FakeLLM(), settings=settings)
        assert client.get("/health/ready").status_code == 200
        preview = client.get("/api/data")
        assert preview.status_code == 503
        assert preview.json()["error"]["code"] == "audit_unavailable"
        assert client.get("/metrics").status_code == 200
        (tmp_path / "alerts.json").write_text("invalid json")
        assert client.get("/api/data").status_code == 503
    assert json.loads((tmp_path / "run_report.json").read_text())["alerts"] == 5


def test_preview_and_metrics_with_audit_storage(client, persisted_run):
    assert len(client.get("/api/data").json()["alerts"]) == 5
    response = client.get("/metrics")
    assert response.status_code == 200, response.text
    assert "counterstrike" in response.text
