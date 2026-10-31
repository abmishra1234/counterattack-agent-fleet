"""Create the initial Counterstrike service schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-31
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

_DDL = (
    """CREATE TABLE sources (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(80) NOT NULL UNIQUE,
        source_type VARCHAR(40) NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        safe_configuration JSON NOT NULL DEFAULT '{}'::json,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE source_checkpoints (
        id VARCHAR(36) PRIMARY KEY,
        source_id VARCHAR(36) NOT NULL REFERENCES sources(id),
        cursor TEXT,
        modified_after TIMESTAMPTZ,
        last_attempt_at TIMESTAMPTZ,
        last_success_at TIMESTAMPTZ,
        last_status VARCHAR(24),
        last_error_code VARCHAR(80),
        failure_count INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT uq_source_checkpoint_source UNIQUE(source_id)
    )""",
    """CREATE TABLE advisories (
        id VARCHAR(36) PRIMARY KEY,
        source_id VARCHAR(36) NOT NULL REFERENCES sources(id),
        external_id VARCHAR(160) NOT NULL,
        canonical_id VARCHAR(80),
        title VARCHAR(500) NOT NULL,
        published_at TIMESTAMPTZ,
        modified_at TIMESTAMPTZ,
        cvss NUMERIC(4, 2),
        source_url TEXT,
        source_references JSON NOT NULL DEFAULT '[]'::json,
        content_hash VARCHAR(64) NOT NULL,
        raw_payload_hash VARCHAR(64),
        normalized_payload JSON NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT uq_advisory_source_external UNIQUE(source_id, external_id)
    )""",
    """CREATE TABLE advisory_enrichments (
        id VARCHAR(36) PRIMARY KEY,
        advisory_id VARCHAR(36) NOT NULL REFERENCES advisories(id),
        kind VARCHAR(40) NOT NULL,
        value JSON NOT NULL,
        source_id VARCHAR(36) NOT NULL REFERENCES sources(id),
        observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        source_url TEXT
    )""",
    """CREATE TABLE inventory_snapshots (
        id VARCHAR(36) PRIMARY KEY,
        source_name VARCHAR(100) NOT NULL,
        imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        content_hash VARCHAR(64) NOT NULL,
        record_count INTEGER NOT NULL
    )""",
    """CREATE TABLE inventory_assets (
        id VARCHAR(36) PRIMARY KEY,
        snapshot_id VARCHAR(36) NOT NULL REFERENCES inventory_snapshots(id),
        asset_key VARCHAR(160) NOT NULL,
        service VARCHAR(200) NOT NULL,
        vendor VARCHAR(200),
        component VARCHAR(200) NOT NULL,
        version VARCHAR(120) NOT NULL,
        owner VARCHAR(200) NOT NULL,
        owner_contact VARCHAR(320),
        criticality VARCHAR(24) NOT NULL,
        internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
        data_classification VARCHAR(80),
        extra_context JSON NOT NULL DEFAULT '{}'::json,
        CONSTRAINT uq_inventory_snapshot_asset UNIQUE(snapshot_id, asset_key)
    )""",
    """CREATE TABLE runs (
        id VARCHAR(36) PRIMARY KEY,
        trigger_type VARCHAR(32) NOT NULL,
        status VARCHAR(24) NOT NULL DEFAULT 'queued',
        triggered_by VARCHAR(200),
        request_id VARCHAR(64),
        inventory_snapshot_id VARCHAR(36) REFERENCES inventory_snapshots(id),
        started_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        policy_version VARCHAR(80),
        prompt_versions JSON NOT NULL DEFAULT '{}'::json,
        summary JSON NOT NULL DEFAULT '{}'::json,
        safe_error_code VARCHAR(100),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE jobs (
        id VARCHAR(36) PRIMARY KEY,
        job_type VARCHAR(40) NOT NULL,
        status VARCHAR(24) NOT NULL DEFAULT 'queued',
        payload JSON NOT NULL DEFAULT '{}'::json,
        run_id VARCHAR(36) REFERENCES runs(id),
        idempotency_key VARCHAR(160),
        schedule_key VARCHAR(160),
        attempt INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        lease_owner VARCHAR(160),
        lease_expires_at TIMESTAMPTZ,
        last_error_code VARCHAR(100),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        completed_at TIMESTAMPTZ,
        CONSTRAINT uq_jobs_idempotency_key UNIQUE(idempotency_key),
        CONSTRAINT uq_jobs_schedule_key UNIQUE(schedule_key)
    )""",
    """CREATE TABLE matches (
        id VARCHAR(36) PRIMARY KEY,
        run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
        advisory_id VARCHAR(36) NOT NULL REFERENCES advisories(id),
        inventory_asset_id VARCHAR(36) NOT NULL REFERENCES inventory_assets(id),
        outcome VARCHAR(24) NOT NULL,
        confidence DOUBLE PRECISION,
        explanation JSON NOT NULL DEFAULT '{}'::json,
        affected_range VARCHAR(300),
        comparator VARCHAR(80),
        evidence JSON NOT NULL DEFAULT '[]'::json,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT uq_match_run_pair UNIQUE(run_id, advisory_id, inventory_asset_id)
    )""",
    """CREATE TABLE alerts (
        id VARCHAR(36) PRIMARY KEY,
        run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
        match_id VARCHAR(36) NOT NULL REFERENCES matches(id),
        alert_key VARCHAR(200) NOT NULL,
        cve_id VARCHAR(80) NOT NULL,
        asset_key VARCHAR(160) NOT NULL,
        service VARCHAR(200) NOT NULL,
        component VARCHAR(200) NOT NULL,
        installed_version VARCHAR(120) NOT NULL,
        fixed_version VARCHAR(120),
        priority VARCHAR(8) NOT NULL,
        risk_score NUMERIC(8, 3) NOT NULL,
        score_breakdown JSON NOT NULL DEFAULT '{}'::json,
        policy_version VARCHAR(80) NOT NULL,
        sla_hours INTEGER NOT NULL,
        owner VARCHAR(200) NOT NULL,
        summary TEXT NOT NULL,
        remediation TEXT NOT NULL,
        evidence JSON NOT NULL DEFAULT '[]'::json,
        source_references JSON NOT NULL DEFAULT '[]'::json,
        status VARCHAR(24) NOT NULL DEFAULT 'open',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT uq_alert_run_key UNIQUE(run_id, alert_key)
    )""",
    """CREATE TABLE review_cases (
        id VARCHAR(36) PRIMARY KEY,
        run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
        advisory_id VARCHAR(36) NOT NULL REFERENCES advisories(id),
        stage VARCHAR(40) NOT NULL,
        reason TEXT NOT NULL,
        state VARCHAR(24) NOT NULL DEFAULT 'open',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        resolved_at TIMESTAMPTZ,
        CONSTRAINT uq_review_run_advisory_stage UNIQUE(run_id, advisory_id, stage)
    )""",
    """CREATE TABLE review_decisions (
        id VARCHAR(36) PRIMARY KEY,
        review_case_id VARCHAR(36) NOT NULL REFERENCES review_cases(id),
        actor_id VARCHAR(200) NOT NULL,
        disposition VARCHAR(40) NOT NULL,
        note TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE audit_events (
        id VARCHAR(36) PRIMARY KEY,
        sequence_number INTEGER NOT NULL UNIQUE,
        schema_version INTEGER NOT NULL DEFAULT 1,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        actor_type VARCHAR(24) NOT NULL,
        actor_id VARCHAR(200),
        action VARCHAR(100) NOT NULL,
        event_type VARCHAR(100) NOT NULL,
        outcome VARCHAR(24) NOT NULL,
        resource_type VARCHAR(80) NOT NULL,
        resource_id VARCHAR(200),
        request_id VARCHAR(64),
        job_id VARCHAR(36),
        run_id VARCHAR(36),
        source_id VARCHAR(36),
        advisory_id VARCHAR(80),
        asset_id VARCHAR(160),
        alert_id VARCHAR(36),
        review_id VARCHAR(36),
        llm_call_id VARCHAR(36),
        reason TEXT,
        safe_details JSON NOT NULL DEFAULT '{}'::json,
        evidence_refs JSON NOT NULL DEFAULT '[]'::json,
        policy_version VARCHAR(80),
        prompt_version VARCHAR(80),
        previous_hash VARCHAR(64),
        event_hash VARCHAR(64) NOT NULL,
        CONSTRAINT uq_audit_event_hash UNIQUE(event_hash)
    )""",
    """CREATE TABLE audit_stream_heads (
        stream_name VARCHAR(80) PRIMARY KEY,
        last_hash VARCHAR(64),
        sequence_number INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    (
        "INSERT INTO audit_stream_heads(stream_name, last_hash, sequence_number) "
        "VALUES ('global', NULL, 0)"
    ),
    """CREATE TABLE llm_calls (
        id VARCHAR(36) PRIMARY KEY,
        request_id VARCHAR(64),
        job_id VARCHAR(36),
        run_id VARCHAR(36) REFERENCES runs(id),
        actor_id VARCHAR(200),
        advisory_id VARCHAR(80),
        parent_call_id VARCHAR(36) REFERENCES llm_calls(id),
        task VARCHAR(40) NOT NULL,
        provider VARCHAR(80) NOT NULL,
        model VARCHAR(160) NOT NULL,
        prompt_version VARCHAR(100) NOT NULL,
        prompt_hash VARCHAR(64) NOT NULL,
        attempt_key VARCHAR(120) NOT NULL,
        attempt_number INTEGER NOT NULL DEFAULT 1,
        started_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        latency_ms INTEGER,
        outcome VARCHAR(32) NOT NULL DEFAULT 'pending',
        input_tokens INTEGER,
        output_tokens INTEGER,
        total_tokens INTEGER,
        token_source VARCHAR(32),
        pricing_version VARCHAR(80),
        input_rate_per_million NUMERIC(18, 8),
        output_rate_per_million NUMERIC(18, 8),
        cost_amount NUMERIC(20, 10),
        cost_currency VARCHAR(8),
        cost_source VARCHAR(32),
        safe_error_code VARCHAR(100),
        response_id VARCHAR(160),
        CONSTRAINT uq_llm_call_run_task_attempt UNIQUE(run_id, task, attempt_key)
    )""",
    """CREATE TABLE llm_exchange_artifacts (
        id VARCHAR(36) PRIMARY KEY,
        llm_call_id VARCHAR(36) NOT NULL REFERENCES llm_calls(id),
        artifact_kind VARCHAR(32) NOT NULL,
        encrypted_payload BYTEA NOT NULL,
        plaintext_hash VARCHAR(64) NOT NULL,
        encryption_key_version VARCHAR(100) NOT NULL,
        payload_bytes INTEGER NOT NULL,
        captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        retention_expires_at TIMESTAMPTZ NOT NULL,
        CONSTRAINT uq_llm_artifact_call_kind UNIQUE(llm_call_id, artifact_kind)
    )""",
    """CREATE TABLE llm_audit_access (
        id VARCHAR(36) PRIMARY KEY,
        llm_call_id VARCHAR(36) NOT NULL REFERENCES llm_calls(id),
        artifact_id VARCHAR(36) REFERENCES llm_exchange_artifacts(id),
        actor_id VARCHAR(200) NOT NULL,
        request_id VARCHAR(64),
        purpose TEXT NOT NULL,
        action VARCHAR(24) NOT NULL,
        outcome VARCHAR(24) NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE FUNCTION counterstrike_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Append-only audit data cannot be updated or deleted';
        END;
        $$""",
    """CREATE TRIGGER trg_audit_events_immutable
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()""",
    """CREATE TRIGGER trg_llm_audit_access_immutable
        BEFORE UPDATE OR DELETE ON llm_audit_access
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()""",
    """CREATE TRIGGER trg_review_decisions_immutable
        BEFORE UPDATE OR DELETE ON review_decisions
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()""",
    """CREATE TRIGGER trg_llm_artifacts_no_update
        BEFORE UPDATE ON llm_exchange_artifacts
        FOR EACH ROW EXECUTE FUNCTION counterstrike_reject_audit_mutation()""",
    """CREATE TABLE outbox_messages (
        id VARCHAR(36) PRIMARY KEY,
        run_id VARCHAR(36) NOT NULL REFERENCES runs(id),
        alert_id VARCHAR(36) REFERENCES alerts(id),
        channel VARCHAR(32) NOT NULL,
        recipient_ref VARCHAR(320) NOT NULL,
        idempotency_key VARCHAR(200) NOT NULL,
        payload JSON NOT NULL,
        payload_hash VARCHAR(64) NOT NULL,
        status VARCHAR(24) NOT NULL DEFAULT 'queued',
        attempt INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TIMESTAMPTZ,
        last_response_code VARCHAR(80),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        delivered_at TIMESTAMPTZ,
        CONSTRAINT uq_outbox_idempotency_key UNIQUE(idempotency_key)
    )""",
    "CREATE INDEX ix_advisories_canonical_id ON advisories(canonical_id)",
    "CREATE INDEX ix_advisories_modified_at ON advisories(modified_at)",
    (
        "CREATE INDEX ix_enrichment_advisory_kind_observed "
        "ON advisory_enrichments(advisory_id, kind, observed_at)"
    ),
    "CREATE INDEX ix_inventory_snapshot_imported ON inventory_snapshots(imported_at)",
    "CREATE INDEX ix_inventory_component_version ON inventory_assets(component, version)",
    "CREATE INDEX ix_inventory_owner ON inventory_assets(owner)",
    "CREATE INDEX ix_runs_status_created ON runs(status, created_at)",
    "CREATE INDEX ix_jobs_claimable ON jobs(status, available_at)",
    "CREATE INDEX ix_matches_outcome_confidence ON matches(outcome, confidence)",
    "CREATE INDEX ix_alerts_priority_created ON alerts(priority, created_at)",
    "CREATE INDEX ix_alerts_owner ON alerts(owner)",
    "CREATE INDEX ix_review_cases_state_created ON review_cases(state, created_at)",
    "CREATE INDEX ix_review_decisions_case_created ON review_decisions(review_case_id, created_at)",
    "CREATE INDEX ix_audit_time_type ON audit_events(occurred_at, event_type)",
    "CREATE INDEX ix_audit_run ON audit_events(run_id)",
    "CREATE INDEX ix_audit_actor ON audit_events(actor_id)",
    "CREATE INDEX ix_audit_resource ON audit_events(resource_type, resource_id)",
    "CREATE INDEX ix_llm_calls_started ON llm_calls(started_at)",
    "CREATE INDEX ix_llm_calls_run_task ON llm_calls(run_id, task)",
    "CREATE INDEX ix_llm_calls_model_outcome ON llm_calls(provider, model, outcome)",
    "CREATE INDEX ix_llm_calls_prompt_version ON llm_calls(prompt_version)",
    "CREATE INDEX ix_llm_calls_advisory ON llm_calls(advisory_id)",
    "CREATE INDEX ix_llm_calls_actor ON llm_calls(actor_id)",
    "CREATE INDEX ix_llm_artifact_retention ON llm_exchange_artifacts(retention_expires_at)",
    "CREATE INDEX ix_llm_audit_access_call_time ON llm_audit_access(llm_call_id, occurred_at)",
    "CREATE INDEX ix_outbox_status_next_attempt ON outbox_messages(status, next_attempt_at)",
)

_TABLES_REVERSE = (
    "outbox_messages",
    "llm_audit_access",
    "llm_exchange_artifacts",
    "llm_calls",
    "audit_events",
    "audit_stream_heads",
    "review_decisions",
    "review_cases",
    "alerts",
    "matches",
    "jobs",
    "runs",
    "inventory_assets",
    "inventory_snapshots",
    "advisory_enrichments",
    "advisories",
    "source_checkpoints",
    "sources",
)


def upgrade() -> None:
    for statement in _DDL:
        op.execute(statement)


def downgrade() -> None:
    for table in _TABLES_REVERSE:
        op.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE')
    op.execute("DROP FUNCTION IF EXISTS counterstrike_reject_audit_mutation() CASCADE")
