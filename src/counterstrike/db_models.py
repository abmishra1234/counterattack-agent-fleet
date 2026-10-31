"""Durable service records for runs, findings, review, audit, and LLM accounting.

The schema stores prompt/response artifacts encrypted as opaque bytes. This module deliberately
does not implement encryption or access policy; those are enforced by the audited repository layer
before it is allowed to create live-model requests.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class Source(Base, TimestampMixin):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    safe_configuration: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SourceCheckpoint(Base):
    __tablename__ = "source_checkpoints"
    __table_args__ = (UniqueConstraint("source_id", name="uq_source_checkpoint_source"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), nullable=False)
    cursor: Mapped[str | None] = mapped_column(Text)
    modified_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(24))
    last_error_code: Mapped[str | None] = mapped_column(String(80))
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AdvisoryRecord(Base, TimestampMixin):
    __tablename__ = "advisories"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_advisory_source_external"),
        Index("ix_advisories_canonical_id", "canonical_id"),
        Index("ix_advisories_modified_at", "modified_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    canonical_id: Mapped[str | None] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss: Mapped[Decimal | None] = mapped_column(Numeric(4, 2))
    source_url: Mapped[str | None] = mapped_column(Text)
    source_references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload_hash: Mapped[str | None] = mapped_column(String(64))
    normalized_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AdvisoryEnrichment(Base):
    __tablename__ = "advisory_enrichments"
    __table_args__ = (
        Index("ix_enrichment_advisory_kind_observed", "advisory_id", "kind", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    source_url: Mapped[str | None] = mapped_column(Text)


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"
    __table_args__ = (Index("ix_inventory_snapshot_imported", "imported_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)


class InventoryAsset(Base):
    __tablename__ = "inventory_assets"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "asset_key", name="uq_inventory_snapshot_asset"),
        Index("ix_inventory_component_version", "component", "version"),
        Index("ix_inventory_owner", "owner"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("inventory_snapshots.id"), nullable=False)
    asset_key: Mapped[str] = mapped_column(String(160), nullable=False)
    service: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(200))
    component: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_contact: Mapped[str | None] = mapped_column(String(320))
    criticality: Mapped[str] = mapped_column(String(24), nullable=False)
    internet_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    data_classification: Mapped[str | None] = mapped_column(String(80))
    extra_context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class RunRecord(Base):
    __tablename__ = "runs"
    __table_args__ = (Index("ix_runs_status_created", "status", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    triggered_by: Mapped[str | None] = mapped_column(String(200))
    request_id: Mapped[str | None] = mapped_column(String(64))
    inventory_snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_snapshots.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    policy_version: Mapped[str | None] = mapped_column(String(80))
    prompt_versions: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    safe_error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class JobRecord(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_jobs_idempotency_key"),
        UniqueConstraint("schedule_key", name="uq_jobs_schedule_key"),
        Index("ix_jobs_claimable", "status", "available_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    job_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"))
    idempotency_key: Mapped[str | None] = mapped_column(String(160))
    schedule_key: Mapped[str | None] = mapped_column(String(160))
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    lease_owner: Mapped[str | None] = mapped_column(String(160))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MatchRecord(Base):
    __tablename__ = "matches"
    __table_args__ = (
        UniqueConstraint("run_id", "advisory_id", "inventory_asset_id", name="uq_match_run_pair"),
        Index("ix_matches_outcome_confidence", "outcome", "confidence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    inventory_asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    affected_range: Mapped[str | None] = mapped_column(String(300))
    comparator: Mapped[str | None] = mapped_column(String(80))
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AlertRecord(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("run_id", "alert_key", name="uq_alert_run_key"),
        Index("ix_alerts_priority_created", "priority", "created_at"),
        Index("ix_alerts_owner", "owner"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    match_id: Mapped[str] = mapped_column(ForeignKey("matches.id"), nullable=False)
    alert_key: Mapped[str] = mapped_column(String(200), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_key: Mapped[str] = mapped_column(String(160), nullable=False)
    service: Mapped[str] = mapped_column(String(200), nullable=False)
    component: Mapped[str] = mapped_column(String(200), nullable=False)
    installed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    priority: Mapped[str] = mapped_column(String(8), nullable=False)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(8, 3), nullable=False)
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_version: Mapped[str] = mapped_column(String(80), nullable=False)
    sla_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ReviewCase(Base):
    __tablename__ = "review_cases"
    __table_args__ = (
        UniqueConstraint("run_id", "advisory_id", "stage", name="uq_review_run_advisory_stage"),
        Index("ix_review_cases_state_created", "state", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    stage: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReviewDecision(Base):
    __tablename__ = "review_decisions"
    __table_args__ = (Index("ix_review_decisions_case_created", "review_case_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_case_id: Mapped[str] = mapped_column(ForeignKey("review_cases.id"), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(200), nullable=False)
    disposition: Mapped[str] = mapped_column(String(40), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("event_hash", name="uq_audit_event_hash"),
        UniqueConstraint("sequence_number", name="uq_audit_sequence"),
        Index("ix_audit_time_type", "occurred_at", "event_type"),
        Index("ix_audit_run", "run_id"),
        Index("ix_audit_actor", "actor_id"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    actor_type: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(200))
    request_id: Mapped[str | None] = mapped_column(String(64))
    job_id: Mapped[str | None] = mapped_column(String(36))
    run_id: Mapped[str | None] = mapped_column(String(36))
    source_id: Mapped[str | None] = mapped_column(String(36))
    advisory_id: Mapped[str | None] = mapped_column(String(80))
    asset_id: Mapped[str | None] = mapped_column(String(160))
    alert_id: Mapped[str | None] = mapped_column(String(36))
    review_id: Mapped[str | None] = mapped_column(String(36))
    llm_call_id: Mapped[str | None] = mapped_column(String(36))
    reason: Mapped[str | None] = mapped_column(Text)
    safe_details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str | None] = mapped_column(String(80))
    prompt_version: Mapped[str | None] = mapped_column(String(80))
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditStreamHead(Base):
    __tablename__ = "audit_stream_heads"

    stream_name: Mapped[str] = mapped_column(String(80), primary_key=True)
    last_hash: Mapped[str | None] = mapped_column(String(64))
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class LLMCall(Base):
    __tablename__ = "llm_calls"
    __table_args__ = (
        UniqueConstraint("run_id", "task", "attempt_key", name="uq_llm_call_run_task_attempt"),
        Index("ix_llm_calls_started", "started_at"),
        Index("ix_llm_calls_run_task", "run_id", "task"),
        Index("ix_llm_calls_model_outcome", "provider", "model", "outcome"),
        Index("ix_llm_calls_prompt_version", "prompt_version"),
        Index("ix_llm_calls_advisory", "advisory_id"),
        Index("ix_llm_calls_actor", "actor_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str | None] = mapped_column(String(64))
    job_id: Mapped[str | None] = mapped_column(String(36))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"))
    actor_id: Mapped[str | None] = mapped_column(String(200))
    advisory_id: Mapped[str | None] = mapped_column(String(80))
    parent_call_id: Mapped[str | None] = mapped_column(ForeignKey("llm_calls.id"))
    task: Mapped[str] = mapped_column(String(40), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_key: Mapped[str] = mapped_column(String(120), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    token_source: Mapped[str | None] = mapped_column(String(32))
    pricing_version: Mapped[str | None] = mapped_column(String(80))
    pricing_effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    input_rate_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    output_rate_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    cost_amount: Mapped[Decimal | None] = mapped_column(Numeric(20, 10))
    budget_estimate_usd: Mapped[Decimal | None] = mapped_column(Numeric(20, 10))
    cost_currency: Mapped[str | None] = mapped_column(String(8))
    cost_source: Mapped[str | None] = mapped_column(String(32))
    safe_error_code: Mapped[str | None] = mapped_column(String(100))
    response_id: Mapped[str | None] = mapped_column(String(160))


class LLMExchangeArtifact(Base):
    __tablename__ = "llm_exchange_artifacts"
    __table_args__ = (
        UniqueConstraint("llm_call_id", "artifact_kind", name="uq_llm_artifact_call_kind"),
        Index("ix_llm_artifact_retention", "retention_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    llm_call_id: Mapped[str] = mapped_column(ForeignKey("llm_calls.id"), nullable=False)
    artifact_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    plaintext_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(100), nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retention_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LLMPricingRate(Base):
    __tablename__ = "llm_pricing_rates"
    __table_args__ = (
        UniqueConstraint(
            "provider", "model", "pricing_version", name="uq_llm_pricing_provider_model_version"
        ),
        UniqueConstraint(
            "provider", "model", "effective_from", name="uq_llm_pricing_provider_model_effective"
        ),
        Index("ix_llm_pricing_effective", "provider", "model", "effective_from"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    pricing_version: Mapped[str] = mapped_column(String(80), nullable=False)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    input_rate_per_million: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    output_rate_per_million: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, default="USD")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LLMAuditAccess(Base):
    __tablename__ = "llm_audit_access"
    __table_args__ = (Index("ix_llm_audit_access_call_time", "llm_call_id", "occurred_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    llm_call_id: Mapped[str] = mapped_column(ForeignKey("llm_calls.id"), nullable=False)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("llm_exchange_artifacts.id"))
    actor_id: Mapped[str] = mapped_column(String(200), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OutboxMessage(Base):
    __tablename__ = "outbox_messages"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_outbox_idempotency_key"),
        Index("ix_outbox_status_next_attempt", "status", "next_attempt_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"))
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient_ref: Mapped[str] = mapped_column(String(320), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_response_code: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
