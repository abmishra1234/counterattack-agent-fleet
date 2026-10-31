"""FastAPI application for local Counterstrike UI and API foundations."""
# FastAPI dependency and query declarations intentionally use function-call defaults.
# ruff: noqa: B008

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from counterstrike.audit import append_event, verify_chain
from counterstrike.config import PROJECT_ROOT, load_settings
from counterstrike.db import get_session_factory
from counterstrike.db_models import (
    AdvisoryEnrichment,
    AdvisoryRecord,
    AlertRecord,
    AuditEvent,
    InventoryAsset,
    JobRecord,
    LLMAuditAccess,
    LLMCall,
    LLMExchangeArtifact,
    MatchRecord,
    OutboxMessage,
    ReviewCase,
    ReviewDecision,
    RunRecord,
    Source,
    SourceCheckpoint,
)
from counterstrike.inventory import load_inventory_document
from counterstrike.metrics import HTTPMetrics
from counterstrike.observability import configure_logging, request_id_context
from counterstrike.repositories import create_run

REQUEST_ID_PATTERN = re.compile("^[A-Za-z0-9._-]{1,64}$")
IDEMPOTENCY_KEY_PATTERN = re.compile("^[A-Za-z0-9._:-]{8,160}$")
AUDIT_QUERY_VALUE_PATTERNS = {
    "limit": re.compile(r"^[0-9]{1,3}$"),
    "offset": re.compile(r"^[0-9]{1,7}$"),
    "priority": re.compile(r"^P[1-4]$"),
    "criticality": re.compile(r"^(critical|high|medium|low)$"),
    "internet_facing": re.compile(r"^(true|false)$"),
    "state": re.compile(r"^[a-z_]{1,24}$"),
    "status": re.compile(r"^[a-z_]{1,24}$"),
    "outcome": re.compile(r"^[a-z_]{1,24}$"),
    "run_id": re.compile(r"^[0-9a-fA-F-]{1,36}$"),
    "job_id": re.compile(r"^[0-9a-fA-F-]{1,36}$"),
    "request_id": re.compile(r"^[A-Za-z0-9._:-]{1,64}$"),
    "advisory_id": re.compile(r"^[0-9a-fA-F-]{1,36}$"),
    "source_id": re.compile(r"^[0-9a-fA-F-]{1,36}$"),
    "since": re.compile(r"^[0-9TZ:+.\-]{1,40}$"),
    "until": re.compile(r"^[0-9TZ:+.\-]{1,40}$"),
    "provider": re.compile(r"^[A-Za-z0-9._-]{1,80}$"),
    "model": re.compile(r"^[A-Za-z0-9._:-]{1,160}$"),
    "task": re.compile(r"^[A-Za-z0-9._-]{1,40}$"),
    "prompt_version": re.compile(r"^[A-Za-z0-9._:-]{1,80}$"),
    "group_by": re.compile(r"^[a-z_]{1,24}$"),
    "currency": re.compile(r"^[A-Z]{3}$"),
    "channel": re.compile(r"^(email|teams)$"),
}
AUDIT_QUERY_VALUE_OMITTED = frozenset({"search", "owner", "service", "actor_id"})
AUDIT_QUERY_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _safe_audit_query_parameters(query_params):
    """Keep bounded, recognized filters in audit records, never free-text values."""
    values: dict[str, str | list[str]] = {}
    omitted_names: set[str] = set()
    items = query_params.multi_items()
    truncated_count = max(0, len(items) - 32)
    for key, value in items[:32]:
        pattern = AUDIT_QUERY_VALUE_PATTERNS.get(key)
        if pattern is not None and pattern.fullmatch(value):
            if key in values:
                existing = values[key]
                values[key] = (
                    [*existing, value] if isinstance(existing, list) else [existing, value]
                )
            else:
                values[key] = value
        elif key in AUDIT_QUERY_VALUE_OMITTED or AUDIT_QUERY_NAME_PATTERN.fullmatch(key):
            omitted_names.add(key)
    return values, sorted(omitted_names), truncated_count


class HealthResponse(BaseModel):
    status: Literal["ok", "ready", "not_ready"]
    checks: (
        dict[str, Literal["ready", "missing", "fixture_mode", "not_migrated", "unreachable"]] | None
    ) = None


class ErrorDetail(BaseModel):
    location: list[str]
    message: str
    code: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] | None = None
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class LegacyPreviewResponse(BaseModel):
    """Deprecated fixture preview contract retained during frontend migration."""

    model_config = ConfigDict(populate_by_name=True)

    alerts: list[dict[str, Any]]
    needs_human: list[dict[str, Any]] = Field(alias="needsHuman")
    report: dict[str, Any]
    advisories: list[dict[str, Any]]
    inventory: list[dict[str, Any]]
    kev: list[dict[str, Any]]
    last_run: str = Field(alias="lastRun")


class RunSummary(BaseModel):
    advisories_ingested: int
    advisories_extracted: int
    matches: int
    alerts: int
    needs_human: int


class RunTraceItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent: str | None = None
    ms: float | None = None
    source_id: str | None = None
    source_status: str | None = None
    source_error_code: str | None = None
    fetched_at: str | None = None
    advisories: int | None = None
    assets: int | None = None
    matches: int | None = None
    affected: int | None = None
    not_affected: int | None = None
    possible_match: int | None = None
    needs_human: int | None = None
    scored: int | None = None
    by_priority: dict[str, int] | None = None
    prompt_version: str | None = None
    llm: str | None = None
    llm_calls: int | None = None
    extracted: int | None = None
    suspected_injection: list[str] | None = None
    alerts: int | None = None
    summary_fallbacks: int | None = None
    owners: int | None = None


class RunListItem(BaseModel):
    id: str
    status: str
    trigger_type: str
    triggered_by: str | None
    request_id: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    safe_error_code: str | None
    summary: RunSummary


class RunListResponse(BaseModel):
    items: list[RunListItem]
    total: int
    limit: int
    offset: int


class RunDetailResponse(RunListItem):
    policy_version: str | None
    prompt_versions: dict[str, str]
    trace: list[RunTraceItem]


class RunAcceptedResponse(BaseModel):
    run: RunListItem
    run_id: str
    status_url: str
    accepted_at: datetime
    job_id: str
    deduplicated: bool


class AuthContextResponse(BaseModel):
    identity: str
    role: str
    mode: str
    capabilities: list[str]
    data_mode: str
    persistence_mode: str
    llm_provider: str
    llm_live_calls_enabled: bool


class SourceItem(BaseModel):
    id: str
    name: str
    source_type: str
    enabled: bool
    health: Literal["disabled", "unknown", "healthy", "degraded"]
    has_checkpoint: bool
    modified_after: datetime | None
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_status: str | None
    last_error_code: str | None
    failure_count: int


class SourceListResponse(BaseModel):
    items: list[SourceItem]


class InventoryItem(BaseModel):
    asset_key: str
    asset_type: str | None = None
    service: str
    vendor: str | None = None
    product: str | None = None
    component: str
    version: str
    owner: str
    owner_contact: str | None = None
    criticality: str
    internet_facing: bool
    data_classification: str | None = None
    aliases: list[str] = Field(default_factory=list)


class InventoryResponse(BaseModel):
    items: list[InventoryItem]
    total: int
    limit: int
    offset: int
    mode: Literal["persisted_snapshot"]
    snapshot_id: str | None


class AuditEventItem(BaseModel):
    id: str
    sequence_number: int
    schema_version: int
    occurred_at: datetime
    actor_type: str
    actor_id: str | None
    action: str
    event_type: str
    outcome: str
    resource_type: str
    resource_id: str | None
    request_id: str | None
    job_id: str | None
    run_id: str | None
    source_id: str | None
    advisory_id: str | None
    asset_id: str | None
    alert_id: str | None
    review_id: str | None
    llm_call_id: str | None
    policy_version: str | None
    prompt_version: str | None
    previous_hash: str | None
    event_hash: str


class AuditEventListResponse(BaseModel):
    items: list[AuditEventItem]
    total: int
    limit: int
    offset: int


class AuditIntegrityResponse(BaseModel):
    status: Literal["valid", "invalid"]
    event_count: int
    failure_reference: str | None


class ReviewDecisionItem(BaseModel):
    id: str
    actor_id: str
    disposition: str
    note: str | None
    created_at: datetime


class ReviewSourceEvidence(BaseModel):
    source: str | None = None
    external_id: str | None = None
    published: str | None = None
    cvss: float | None = None
    text: str = ""
    content_hash: str | None = None


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str | None = None
    name: str | None = None
    source: str | None = None
    advisory_id: str | None = None
    type: str | None = None
    tags: list[str] = Field(default_factory=list)


class MatchExplanation(BaseModel):
    model_config = ConfigDict(extra="allow")

    version_note: str | None = None
    confidence_scope: Literal["deterministic_version_comparison"] | None = None


class MatchEvidenceItem(BaseModel):
    asset_id: str
    component: str
    installed_version: str
    outcome: Literal["affected", "not_affected", "possible_match"]
    confidence: float | None
    affected_range: str | None
    comparator: str | None
    explanation: MatchExplanation
    evidence: list[str]


class MatchHistoryItem(BaseModel):
    run_id: str
    outcome: Literal["affected", "not_affected", "possible_match"]
    asset_key: str
    component: str
    installed_version: str
    confidence: float | None
    affected_range: str | None
    comparator: str | None
    evidence: list[str]
    compared_at: datetime


class ReviewListItem(BaseModel):
    id: str
    run_id: str
    advisory_id: str
    cve_id: str | None
    title: str | None
    stage: str
    reason: str
    source_evidence: ReviewSourceEvidence
    source_references: list[SourceReference]
    candidate_matches: list[MatchEvidenceItem]
    candidate_matches_truncated: bool
    state: str
    created_at: datetime
    resolved_at: datetime | None
    decisions: list[ReviewDecisionItem]


class ReviewListResponse(BaseModel):
    items: list[ReviewListItem]
    total: int
    limit: int
    offset: int


class ReviewDecisionResponse(BaseModel):
    review_id: str
    state: str
    decision: ReviewDecisionItem


class ReviewDecisionRequest(BaseModel):
    disposition: Literal[
        "affected_confirmed", "possible_match", "not_affected", "insufficient_evidence"
    ]
    note: str = Field(min_length=1, max_length=2000)

    @field_validator("note")
    @classmethod
    def validate_note(cls, value):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("A review note is required")
        return cleaned


def _is_http_source_url(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    try:
        ascii_host = host.encode("idna").decode("ascii") if host else ""
    except UnicodeError:
        return False
    return bool(
        parsed.scheme.lower() in {"http", "https"}
        and ascii_host
        and re.fullmatch(r"[A-Za-z0-9.:-]+", ascii_host)
        and parsed.username is None
        and parsed.password is None
        and (port is None or 1 <= port <= 65535)
    )


class AlertListItem(BaseModel):
    id: str
    run_id: str
    cve_id: str
    asset_key: str
    service: str
    component: str
    installed_version: str
    fixed_version: str | None
    priority: str
    risk_score: float
    owner: str
    status: str
    summary: str
    sla_hours: int
    created_at: datetime


class AlertEPSSContext(BaseModel):
    status: Literal["available", "not_scored"]
    score: float | None = None
    percentile: float | None = None
    score_date: str | None = None
    source_url: str | None = None
    observed_at: datetime | None = None


class AlertAdvisoryContext(BaseModel):
    title: str | None = None
    source: str | None = None
    published: str | None = None
    cvss: float | None = None
    text: str = ""
    in_kev: bool | None = None
    kev_status: Literal["listed", "not_listed", "unknown"] = "unknown"
    references: list[SourceReference] = Field(default_factory=list)
    epss: AlertEPSSContext | None = None


class AlertAssetContext(BaseModel):
    asset_key: str | None = None
    asset_type: str | None = None
    criticality: str | None = None
    internet_facing: bool | None = None
    data_classification: str | None = None
    vendor: str | None = None
    product: str | None = None
    owner_contact: str | None = None
    aliases: list[str] = Field(default_factory=list)


class AlertScoreBreakdown(BaseModel):
    cvss: float | None = None
    kev: float | None = None
    kev_status: Literal["listed", "not_listed", "unknown"] | None = None
    internet_facing: float | None = None
    criticality: float | None = None
    epss: float | None = None
    epss_weight: float | None = None
    epss_status: str | None = None
    epss_probability: float | None = None
    epss_score_date: str | None = None
    epss_observed_at: datetime | None = None
    epss_source_url: str | None = None
    kev_internet_p1_override: float | None = None


class AlertDetailResponse(AlertListItem):
    remediation: str
    sla_hours: int
    score_breakdown: AlertScoreBreakdown
    policy_version: str
    evidence: list[str]
    source_references: list[SourceReference]
    remediation_sources: list[SourceReference]
    remediation_citation_status: Literal["cited", "unverified"]
    advisory: AlertAdvisoryContext
    asset_context: AlertAssetContext
    match: MatchEvidenceItem
    match_history: list[MatchHistoryItem]
    match_history_truncated: bool


class AlertListResponse(BaseModel):
    items: list[AlertListItem]
    total: int
    limit: int
    offset: int


class DeliveryItem(BaseModel):
    id: str
    run_id: str | None
    alert_id: str | None
    channel: Literal["email", "teams"]
    route: str | None
    recipient_hash: str
    status: Literal["queued", "delivering", "retry", "delivered", "failed", "unknown"]
    attempt: int
    next_attempt_at: datetime | None
    last_response_code: str | None
    created_at: datetime
    delivered_at: datetime | None
    digest_date: str | None = None
    alert_count: int | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None


class DeliveryListResponse(BaseModel):
    items: list[DeliveryItem]
    total: int
    limit: int
    offset: int


class DashboardResponse(BaseModel):
    latest_run: RunListItem | None
    by_priority: dict[str, int]
    affected_assets: int
    review_count: int
    top_findings: list[AlertListItem]


class LLMCallItem(BaseModel):
    id: str
    request_id: str | None
    job_id: str | None
    run_id: str | None
    parent_call_id: str | None
    actor_id: str | None
    advisory_id: str | None
    task: str
    provider: str
    model: str
    prompt_version: str
    prompt_hash: str
    attempt_number: int
    started_at: datetime
    completed_at: datetime | None
    latency_ms: int | None
    outcome: str
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    token_source: str | None
    pricing_version: str | None
    pricing_effective_at: datetime | None
    input_rate_per_million: str | None
    output_rate_per_million: str | None
    cost_amount: str | None
    budget_estimate_usd: str | None
    cost_currency: str | None
    cost_source: str | None
    safe_error_code: str | None


class LLMUsageResponse(BaseModel):
    items: list[LLMCallItem]
    total: int
    retries: int
    limit: int
    offset: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    unknown_token_calls: int
    known_cost_by_currency: dict[str, str]
    unknown_cost_calls: int


LLMUsageGroupBy = Literal[
    "day",
    "run",
    "task",
    "provider",
    "model",
    "prompt_version",
    "advisory",
    "actor",
    "outcome",
]


class LLMUsageReportGroup(BaseModel):
    key: date | str | None
    calls: int
    retries: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    unknown_token_calls: int
    currency: str
    known_cost: str
    estimated_unknown_cost_usd: str
    budget_enforced_cost_usd: str
    unknown_cost_calls: int
    unknown_outcome_calls: int
    pending_calls: int


class LLMUsageReportResponse(BaseModel):
    group_by: LLMUsageGroupBy
    groups: list[LLMUsageReportGroup]
    total_calls: int
    total_retries: int
    unknown_outcome_calls: int
    pending_calls: int
    total_groups: int
    limit: int
    offset: int
    has_more: bool


class LLMBudgetLimits(BaseModel):
    per_run: str | None
    per_month: str | None


class LLMBudgetSummary(BaseModel):
    calls: int
    unknown_cost_calls: int
    unpriced_calls: int
    budget_enforced_usd: str
    estimated_unknown_cost_usd: str
    known_cost_by_currency: dict[str, str]
    limit_status: Literal["not_configured", "unknown", "exceeded", "at_limit", "within_limit"]
    remaining_usd: str | None


class LLMRunBudgetSummary(LLMBudgetSummary):
    run_id: str
    limit_usd: str | None


class LLMBudgetsResponse(BaseModel):
    period_start: datetime
    configured_limits_usd: LLMBudgetLimits
    month_to_date: LLMBudgetSummary
    run: LLMRunBudgetSummary | None


class LLMArtifactMetadata(BaseModel):
    id: str
    kind: str
    plaintext_hash: str
    payload_bytes: int
    key_version: str
    captured_at: datetime
    retention_expires_at: datetime
    purged_at: datetime | None


class LLMCallDetailResponse(LLMCallItem):
    artifacts: list[LLMArtifactMetadata]


class LLMContentReadRequest(BaseModel):
    kind: Literal["request", "response", "parsed_output", "error", "provider_error"]
    purpose: str = Field(min_length=8, max_length=500)

    @field_validator("purpose")
    @classmethod
    def validate_purpose(cls, value):
        cleaned = value.strip()
        if len(cleaned) < 8:
            raise ValueError("A specific audit purpose is required")
        return cleaned


class LLMContentReadResponse(BaseModel):
    call_id: str
    kind: Literal["request", "response", "parsed_output", "error", "provider_error"]
    content: Any
    plaintext_hash: str
    purpose: str


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _preview_payload(settings, *, include_owner_contact=False):
    """Temporary fixture-backed response retained for the existing UI during migration."""

    try:
        report_path = settings.out_dir / "run_report.json"
        report_stat = report_path.stat()
        return {
            "alerts": _read_json(settings.out_dir / "alerts.json"),
            "needsHuman": _read_json(settings.out_dir / "needs_human.json"),
            "report": _read_json(report_path),
            "advisories": _read_json(settings.data_dir / "advisories.json"),
            "inventory": [
                {
                    **asset.model_dump(mode="json"),
                    **({} if include_owner_contact else {"owner_contact": None}),
                }
                for asset in load_inventory_document(settings.data_dir / "inventory.json").assets
            ],
            "kev": _read_json(settings.data_dir / "kev.json"),
            "lastRun": datetime.fromtimestamp(report_stat.st_mtime, timezone.utc).isoformat(),
        }
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Local preview data is not ready. Run the Counterstrike CLI first."
        ) from exc
    except (ValueError, OSError) as exc:
        raise RuntimeError(
            "Local preview data could not be read. Check the input and output files."
        ) from exc


def _ready_checks(settings):
    """Check the configured fixture-backed service dependencies for this foundation phase."""

    required = {
        "advisories": settings.data_dir / "advisories.json",
        "inventory": settings.data_dir / "inventory.json",
        "aliases": settings.data_dir / "aliases.json",
        "kev": settings.data_dir / "kev.json",
        "alerts": settings.out_dir / "alerts.json",
        "review_queue": settings.out_dir / "needs_human.json",
        "latest_report": settings.out_dir / "run_report.json",
    }
    checks = {name: "ready" if path.is_file() else "missing" for name, path in required.items()}
    from counterstrike.db import database_readiness

    checks["database"] = database_readiness(settings)
    return checks


def create_app(settings=None):
    settings = settings or load_settings()
    app_logger = configure_logging(settings.log_level)
    if (
        settings.api_host.lower() not in {"::1", "127.0.0.1", "localhost"}
        and not settings.api_trusted_local_client_cidrs
    ):
        app_logger.warning(
            "API authorization middleware will deny protected routes on a non-loopback bind "
            "without trusted local CIDRs",
            extra={"event": "api.security.remote_bind", "error_code": "development_only"},
        )
    app = FastAPI(
        title="Counterstrike API",
        description="Vulnerability triage API, UI service, and local run queue.",
        version="0.1.0",
        docs_url="/docs" if settings.environment in {"test", "development"} else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment in {"test", "development"} else None,
        debug=False,
    )
    app.state.settings = settings
    http_metrics = HTTPMetrics()
    app.state.http_metrics = http_metrics
    role_capabilities = {
        "viewer": {"read"},
        "analyst": {"read", "review"},
        "operator": {"read", "review", "run", "usage", "metrics", "delivery"},
        "audit_reader": {"read", "audit"},
        "llm_audit_reader": {"read", "usage", "llm_content"},
        "admin": {"read", "review", "run", "usage", "llm_content", "audit", "metrics", "delivery"},
    }

    def can_view_owner_contact():
        return "review" in role_capabilities.get(settings.local_dev_role, set())

    def required_capability(path, method):
        if path == "/metrics":
            return "metrics" if settings.metrics_enabled else None
        if path in {
            "/health/live",
            "/api/v1/health/live",
            "/health/ready",
            "/api/v1/health/ready",
        } and method == "GET":
            return None
        if path == "/api/v1/auth/context" and method == "GET":
            return "read"
        if path == "/api/v1/deliveries" and method == "GET":
            return "delivery"
        if path == "/api/data":
            return "read" if method == "GET" else "unmapped"
        if path in {
            "/api/v1/dashboard",
            "/api/v1/sources",
            "/api/v1/alerts",
            "/api/v1/inventory",
        } or re.fullmatch(
            r"/api/v1/alerts/[^/]+", path
        ):
            return "read" if method == "GET" else "unmapped"
        if path == "/api/v1/runs" and method == "POST":
            return "run"
        if path == "/api/v1/runs" or re.fullmatch(r"/api/v1/runs/[^/]+", path):
            return "read" if method == "GET" else "unmapped"
        if path == "/api/v1/reviews" and method == "GET":
            return "review"
        if re.fullmatch(r"/api/v1/reviews/[^/]+/decision", path) and method == "POST":
            return "review"
        if re.fullmatch(r"/api/v1/llm/usage/[^/]+/content", path) and method == "POST":
            return "llm_content"
        if method == "GET" and (
            path
            in {
                "/api/v1/llm/budgets",
                "/api/v1/llm/usage",
                "/api/v1/llm/usage/report",
            }
            or re.fullmatch(r"/api/v1/llm/usage/[^/]+", path)
        ):
            return "usage"
        if path in {"/api/v1/audit/events", "/api/v1/audit/integrity"} and method == "GET":
            return "audit"
        # New versioned routes are closed until their capability is explicitly
        # assigned above; never let an omitted route fall through as public.
        if path.startswith("/api/v1/"):
            return "unmapped"
        return None

    @app.middleware("http")
    async def authorize_local_roles(request, call_next):
        capability = required_capability(request.url.path, request.method)
        if capability is None:
            return await call_next(request)
        local_host = settings.api_host.lower() in {"::1", "127.0.0.1", "localhost"}
        client_host = request.client.host if request.client else ""
        local_client = client_host in {"::1", "127.0.0.1", "localhost", "testclient"}
        if not local_client and settings.api_trusted_local_client_cidrs:
            try:
                client_ip = ipaddress.ip_address(client_host)
                trusted_networks = (
                    ipaddress.ip_network(item)
                    for item in settings.api_trusted_local_client_cidrs.split(",")
                )
                local_client = any(client_ip in network for network in trusted_networks)
            except ValueError:
                local_client = False
        local_host = local_host or bool(settings.api_trusted_local_client_cidrs)
        role = settings.local_dev_role
        allowed = (
            settings.environment in {"development", "test"}
            and local_host
            and local_client
            and capability in role_capabilities.get(role, set())
        )
        if allowed:
            return await call_next(request)
        request_id = request_id_context.get()
        denial = {
            "capability": capability,
            "role": role,
            "route": request.url.path,
            "environment": settings.environment,
            "client_host": client_host,
            "local_host_allowed": local_host,
            "local_client_allowed": local_client,
        }
        try:
            factory = get_session_factory(settings)
            with factory() as session:
                append_event(
                    session,
                    actor_type="service",
                    actor_id=settings.local_dev_identity,
                    action="api_authorization_denied",
                    event_type="api.authorization.denied",
                    outcome="denied",
                    resource_type="api_route",
                    resource_id=request.url.path[:200],
                    request_id=request_id,
                    safe_details=denial,
                )
                session.commit()
        except Exception as exc:
            app_logger.error(
                "Authorization denial could not be persisted",
                extra={
                    "event": "api.authorization.audit_failed",
                    "error_code": type(exc).__name__,
                    **denial,
                },
            )
        app_logger.warning(
            "API capability denied",
            extra={
                "event": "api.authorization.denied",
                "actor_id": settings.local_dev_identity,
                **denial,
            },
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "forbidden",
                    "message": "This configured identity is not authorized for this operation.",
                    "request_id": request_id,
                }
            },
        )

    def db_session():
        try:
            factory = get_session_factory(settings)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="Database is not configured") from exc
        with factory() as session:
            yield session

    def run_summary(record):
        summary = record.summary or {}
        return {
            name: int(summary.get(name, 0))
            for name in (
                "advisories_ingested",
                "advisories_extracted",
                "matches",
                "alerts",
                "needs_human",
            )
        }

    def run_item(record):
        return {
            "id": record.id,
            "status": record.status,
            "trigger_type": record.trigger_type,
            "triggered_by": record.triggered_by,
            "request_id": record.request_id,
            "created_at": record.created_at,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "safe_error_code": record.safe_error_code,
            "summary": run_summary(record),
        }

    def alert_item(record):
        return {
            "id": record.id,
            "run_id": record.run_id,
            "cve_id": record.cve_id,
            "asset_key": record.asset_key,
            "service": record.service,
            "component": record.component,
            "installed_version": record.installed_version,
            "fixed_version": record.fixed_version,
            "priority": record.priority,
            "risk_score": float(record.risk_score),
            "owner": record.owner,
            "status": record.status,
            "summary": record.summary,
            "sla_hours": record.sla_hours,
            "created_at": record.created_at,
        }

    def match_evidence_item(record, asset=None):
        return {
            "asset_id": asset.asset_key if asset else record.inventory_asset_id,
            "component": asset.component if asset else "unknown",
            "installed_version": asset.version if asset else "unknown",
            "outcome": record.outcome,
            "confidence": record.confidence,
            "affected_range": record.affected_range,
            "comparator": record.comparator,
            "explanation": record.explanation or {},
            "evidence": record.evidence or [],
        }

    def llm_call_item(record):
        return {
            "id": record.id,
            "request_id": record.request_id,
            "job_id": record.job_id,
            "run_id": record.run_id,
            "parent_call_id": record.parent_call_id,
            "actor_id": record.actor_id,
            "advisory_id": record.advisory_id,
            "task": record.task,
            "provider": record.provider,
            "model": record.model,
            "prompt_version": record.prompt_version,
            "prompt_hash": record.prompt_hash,
            "attempt_number": record.attempt_number,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "latency_ms": record.latency_ms,
            "outcome": record.outcome,
            "input_tokens": record.input_tokens,
            "output_tokens": record.output_tokens,
            "total_tokens": record.total_tokens,
            "token_source": record.token_source,
            "pricing_version": record.pricing_version,
            "pricing_effective_at": record.pricing_effective_at,
            "input_rate_per_million": format(record.input_rate_per_million, "f")
            if record.input_rate_per_million is not None
            else None,
            "output_rate_per_million": format(record.output_rate_per_million, "f")
            if record.output_rate_per_million is not None
            else None,
            "cost_amount": format(record.cost_amount, "f")
            if record.cost_amount is not None
            else None,
            "budget_estimate_usd": format(record.budget_estimate_usd, "f")
            if record.budget_estimate_usd is not None
            else None,
            "cost_currency": record.cost_currency,
            "cost_source": record.cost_source,
            "safe_error_code": record.safe_error_code,
        }

    @app.get(
        "/api/v1/auth/context", response_model=AuthContextResponse, tags=["auth"]
    )
    def auth_context():
        return {
            "identity": settings.local_dev_identity,
            "role": settings.local_dev_role,
            "mode": "local-development"
            if settings.environment in {"development", "test"}
            else "unavailable",
            "capabilities": sorted(role_capabilities.get(settings.local_dev_role, set())),
            "data_mode": "public_feeds" if settings.public_feeds_enabled else "fixture",
            "persistence_mode": "database" if settings.database_url is not None else "unconfigured",
            "llm_provider": settings.llm_provider,
            "llm_live_calls_enabled": settings.llm_live_calls_enabled,
        }

    def llm_conditions(
        since,
        until,
        run_id,
        request_id,
        job_id,
        provider,
        model,
        task,
        actor_id,
        advisory_id,
        prompt_version,
        outcome,
    ):
        conditions = []
        if since:
            since = (
                since.replace(tzinfo=timezone.utc)
                if since.tzinfo is None
                else since.astimezone(timezone.utc)
            )
            conditions.append(LLMCall.started_at >= since)
        if until:
            until = (
                until.replace(tzinfo=timezone.utc)
                if until.tzinfo is None
                else until.astimezone(timezone.utc)
            )
            conditions.append(LLMCall.started_at < until)
        for column, value in (
            (LLMCall.run_id, run_id),
            (LLMCall.request_id, request_id),
            (LLMCall.job_id, job_id),
            (LLMCall.provider, provider),
            (LLMCall.model, model),
            (LLMCall.task, task),
            (LLMCall.actor_id, actor_id),
            (LLMCall.advisory_id, advisory_id),
            (LLMCall.prompt_version, prompt_version),
            (LLMCall.outcome, outcome),
        ):
            if value:
                conditions.append(column == value)
        if since and until and since >= until:
            raise HTTPException(status_code=422, detail="since must be earlier than until")
        return conditions

    @app.get("/api/v1/dashboard", response_model=DashboardResponse, tags=["dashboard"])
    def dashboard(session=Depends(db_session)):
        latest = session.scalar(
            select(RunRecord).order_by(RunRecord.created_at.desc(), RunRecord.id.desc()).limit(1)
        )
        if latest is None:
            return {
                "latest_run": None,
                "by_priority": {priority: 0 for priority in ("P1", "P2", "P3", "P4")},
                "affected_assets": 0,
                "review_count": 0,
                "top_findings": [],
            }
        priority_rows = session.execute(
            select(AlertRecord.priority, func.count(AlertRecord.id))
            .where(AlertRecord.run_id == latest.id)
            .group_by(AlertRecord.priority)
        ).all()
        by_priority = {priority: 0 for priority in ("P1", "P2", "P3", "P4")}
        by_priority.update({str(priority): int(count) for priority, count in priority_rows})
        asset_count = (
            session.scalar(
                select(func.count(distinct(AlertRecord.asset_key))).where(
                    AlertRecord.run_id == latest.id
                )
            )
            or 0
        )
        reviews = (
            session.scalar(
                select(func.count(ReviewCase.id)).where(
                    ReviewCase.run_id == latest.id, ReviewCase.state == "open"
                )
            )
            or 0
        )
        priority_order = case(
            (AlertRecord.priority == "P1", 1),
            (AlertRecord.priority == "P2", 2),
            (AlertRecord.priority == "P3", 3),
            else_=4,
        )
        top = session.scalars(
            select(AlertRecord)
            .where(AlertRecord.run_id == latest.id)
            .order_by(priority_order, AlertRecord.risk_score.desc(), AlertRecord.created_at.desc())
            .limit(5)
        ).all()
        return {
            "latest_run": run_item(latest),
            "by_priority": by_priority,
            "affected_assets": int(asset_count),
            "review_count": int(reviews),
            "top_findings": [alert_item(item) for item in top],
        }

    @app.get("/api/v1/runs", response_model=RunListResponse, tags=["runs"])
    def list_runs(
        status: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        conditions = [RunRecord.status == status] if status else []
        total = int(session.scalar(select(func.count(RunRecord.id)).where(*conditions)) or 0)
        records = session.scalars(
            select(RunRecord)
            .where(*conditions)
            .order_by(RunRecord.created_at.desc(), RunRecord.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return {
            "items": [run_item(item) for item in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.post(
        "/api/v1/runs",
        status_code=202,
        response_model=RunAcceptedResponse,
        tags=["runs"],
    )
    def queue_run(
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=160),
        session=Depends(db_session),
    ):
        """Queue a manual run for the configured local identity."""

        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
            raise HTTPException(status_code=422, detail="Invalid Idempotency-Key")
        existing = session.scalar(
            select(JobRecord).where(JobRecord.idempotency_key == idempotency_key)
        )
        if existing is not None and existing.run_id:
            record = session.get(RunRecord, existing.run_id)
            if record is not None:
                append_event(
                    session,
                    actor_type="user",
                    actor_id=settings.local_dev_identity,
                    action="run_enqueue_deduplicated",
                    event_type="run.enqueue.deduplicated",
                    outcome="success",
                    resource_type="job",
                    resource_id=existing.id,
                    request_id=request_id_context.get(),
                    job_id=existing.id,
                    run_id=record.id,
                    safe_details={"trigger_type": "manual"},
                )
                session.commit()
                return {
                    "run": run_item(record),
                    "run_id": record.id,
                    "status_url": f"/api/v1/runs/{record.id}",
                    "accepted_at": record.created_at,
                    "job_id": existing.id,
                    "deduplicated": True,
                }
        current_request_id = request_id_context.get()
        actor_id = settings.local_dev_identity
        try:
            record = create_run(
                session, trigger_type="manual", actor_id=actor_id, request_id=current_request_id
            )
            job = JobRecord(
                job_type="run",
                status="queued",
                payload={"scope": "configured_data_dir"},
                run_id=record.id,
                idempotency_key=idempotency_key,
            )
            session.add(job)
            session.flush()
            append_event(
                session,
                actor_type="user",
                actor_id=actor_id,
                action="job_queued",
                event_type="job.lifecycle.queued",
                outcome="success",
                resource_type="job",
                resource_id=job.id,
                request_id=current_request_id,
                job_id=job.id,
                run_id=record.id,
                safe_details={"job_type": job.job_type, "trigger_type": "manual"},
            )
            session.commit()
            session.refresh(record)
            return {
                "run": run_item(record),
                "run_id": record.id,
                "status_url": f"/api/v1/runs/{record.id}",
                "accepted_at": record.created_at,
                "job_id": job.id,
                "deduplicated": False,
            }
        except IntegrityError:
            session.rollback()
            duplicate = session.scalar(
                select(JobRecord).where(JobRecord.idempotency_key == idempotency_key)
            )
            if duplicate is None or duplicate.run_id is None:
                raise HTTPException(status_code=409, detail="Run could not be queued") from None
            duplicate_run = session.get(RunRecord, duplicate.run_id)
            if duplicate_run is None:
                raise HTTPException(status_code=409, detail="Run could not be queued") from None
            append_event(
                session,
                actor_type="user",
                actor_id=settings.local_dev_identity,
                action="run_enqueue_deduplicated",
                event_type="run.enqueue.deduplicated",
                outcome="success",
                resource_type="job",
                resource_id=duplicate.id,
                request_id=current_request_id,
                job_id=duplicate.id,
                run_id=duplicate_run.id,
                safe_details={"trigger_type": "manual"},
            )
            session.commit()
            return {
                "run": run_item(duplicate_run),
                "run_id": duplicate_run.id,
                "status_url": f"/api/v1/runs/{duplicate_run.id}",
                "accepted_at": duplicate_run.created_at,
                "job_id": duplicate.id,
                "deduplicated": True,
            }

    @app.get("/api/v1/runs/{run_id}", response_model=RunDetailResponse, tags=["runs"])
    def run_detail(run_id, session=Depends(db_session)):
        record = session.get(RunRecord, run_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Run not found")
        summary = record.summary or {}
        trace = summary.get("trace", [])
        safe_trace = [
            {
                key: item[key]
                for key in (
                    "agent",
                    "source_id",
                    "fetched_at",
                    "ms",
                    "prompt_version",
                    "llm",
                    "llm_calls",
                    "source_status",
                    "source_error_code",
                    "assets",
                    "extracted",
                    "matches",
                    "alerts",
                    "owners",
                )
                if key in item
            }
            for item in trace
            if isinstance(item, dict)
        ]
        return {
            **run_item(record),
            "policy_version": record.policy_version,
            "prompt_versions": record.prompt_versions or {},
            "trace": safe_trace,
        }

    @app.get("/api/v1/reviews", response_model=ReviewListResponse, tags=["reviews"])
    def list_reviews(
        state: str | None = Query(default=None, max_length=24),
        run_id: str | None = Query(default=None, max_length=36),
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        conditions = []
        if state:
            conditions.append(ReviewCase.state == state)
        if run_id:
            conditions.append(ReviewCase.run_id == run_id)
        total = int(session.scalar(select(func.count(ReviewCase.id)).where(*conditions)) or 0)
        cases = session.scalars(
            select(ReviewCase)
            .where(*conditions)
            .order_by(ReviewCase.created_at.desc(), ReviewCase.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        case_ids = [item.id for item in cases]
        advisory_ids = {item.advisory_id for item in cases}
        advisories = (
            {
                item.id: item
                for item in session.scalars(
                    select(AdvisoryRecord).where(AdvisoryRecord.id.in_(advisory_ids))
                ).all()
            }
            if advisory_ids
            else {}
        )
        decisions = {}
        if case_ids:
            for item in session.scalars(
                select(ReviewDecision)
                .where(ReviewDecision.review_case_id.in_(case_ids))
                .order_by(ReviewDecision.created_at, ReviewDecision.id)
            ).all():
                decisions.setdefault(item.review_case_id, []).append(item)
        candidate_matches: dict[tuple[str, str], list[dict[str, Any]]] = {}
        candidate_matches_truncated = False
        if cases:
            match_rows = session.execute(
                select(MatchRecord, InventoryAsset)
                .join(InventoryAsset, InventoryAsset.id == MatchRecord.inventory_asset_id)
                .where(
                    MatchRecord.run_id.in_({item.run_id for item in cases}),
                    MatchRecord.advisory_id.in_(advisory_ids),
                    MatchRecord.outcome == "possible_match",
                )
                .order_by(MatchRecord.created_at, MatchRecord.id)
                .limit(2001)
            ).all()
            candidate_matches_truncated = len(match_rows) > 2000
            for match_record, asset_record in match_rows[:2000]:
                key = (match_record.run_id, match_record.advisory_id)
                bucket = candidate_matches.setdefault(key, [])
                if len(bucket) < 21:
                    bucket.append(match_evidence_item(match_record, asset_record))
        items = []
        for review_case in cases:
            advisory = advisories.get(review_case.advisory_id)
            payload = (advisory.normalized_payload or {}) if advisory else {}
            source_evidence = (
                {
                    "source": payload.get("source"),
                    "external_id": advisory.external_id,
                    "published": payload.get("published"),
                    "cvss": float(advisory.cvss) if advisory.cvss is not None else None,
                    "text": str(payload.get("text") or "")[:20000],
                    "content_hash": advisory.content_hash,
                }
                if advisory
                else {}
            )
            items.append(
                {
                    "id": review_case.id,
                    "run_id": review_case.run_id,
                    "advisory_id": review_case.advisory_id,
                    "cve_id": advisory.canonical_id if advisory else None,
                    "title": advisory.title if advisory else None,
                    "stage": review_case.stage,
                    "reason": review_case.reason,
                    "source_evidence": source_evidence,
                    "source_references": (advisory.source_references or []) if advisory else [],
                    "candidate_matches": candidate_matches.get(
                        (review_case.run_id, review_case.advisory_id), []
                    )[:20],
                    "candidate_matches_truncated": (
                        candidate_matches_truncated
                        or len(
                            candidate_matches.get(
                                (review_case.run_id, review_case.advisory_id), []
                            )
                        ) > 20
                    ),
                    "state": review_case.state,
                    "created_at": review_case.created_at,
                    "resolved_at": review_case.resolved_at,
                    "decisions": [
                        {
                            "id": decision.id,
                            "actor_id": decision.actor_id,
                            "disposition": decision.disposition,
                            "note": decision.note,
                            "created_at": decision.created_at,
                        }
                        for decision in decisions.get(review_case.id, [])
                    ],
                }
            )
        append_event(
            session,
            actor_type="user",
            actor_id=settings.local_dev_identity,
            action="review_queue_viewed",
            event_type="review.queue.viewed",
            outcome="success",
            resource_type="review_queue",
            request_id=request_id_context.get(),
            safe_details={"state": state, "run_id": run_id, "limit": limit, "offset": offset},
        )
        session.commit()
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.post(
        "/api/v1/reviews/{review_id}/decision",
        status_code=201,
        response_model=ReviewDecisionResponse,
        tags=["reviews"],
    )
    def submit_review_decision(
        review_id: str, decision: ReviewDecisionRequest, session=Depends(db_session)
    ):
        case = session.scalar(
            select(ReviewCase).where(ReviewCase.id == review_id).with_for_update()
        )
        if case is None:
            raise HTTPException(status_code=404, detail="Review case not found")
        if case.state != "open":
            append_event(
                session,
                actor_type="user",
                actor_id=settings.local_dev_identity,
                action="review_decision_rejected",
                event_type="review.decision.rejected",
                outcome="conflict",
                resource_type="review_case",
                resource_id=case.id,
                request_id=request_id_context.get(),
                run_id=case.run_id,
                advisory_id=case.advisory_id,
                review_id=case.id,
                safe_details={"error_code": "review_case_not_open", "state": case.state},
            )
            session.commit()
            raise HTTPException(status_code=409, detail="Review case is already resolved")
        now = datetime.now(timezone.utc)
        stored = ReviewDecision(
            review_case_id=case.id,
            actor_id=settings.local_dev_identity,
            disposition=decision.disposition,
            note=decision.note,
            created_at=now,
        )
        session.add(stored)
        case.state = "resolved"
        case.resolved_at = now
        session.flush()
        append_event(
            session,
            actor_type="user",
            actor_id=settings.local_dev_identity,
            action="review_decision_recorded",
            event_type="review.decision.recorded",
            outcome="success",
            resource_type="review_case",
            resource_id=case.id,
            request_id=request_id_context.get(),
            run_id=case.run_id,
            advisory_id=case.advisory_id,
            review_id=case.id,
            safe_details={
                "decision_id": stored.id,
                "disposition": stored.disposition,
                "state": case.state,
            },
        )
        session.commit()
        session.refresh(stored)
        return {
            "review_id": case.id,
            "state": case.state,
            "decision": {
                "id": stored.id,
                "actor_id": stored.actor_id,
                "disposition": stored.disposition,
                "note": stored.note,
                "created_at": stored.created_at,
            },
        }

    @app.get("/api/v1/sources", response_model=SourceListResponse, tags=["sources"])
    def list_sources(session=Depends(db_session)):
        rows = session.execute(
            select(Source, SourceCheckpoint)
            .outerjoin(SourceCheckpoint, SourceCheckpoint.source_id == Source.id)
            .order_by(Source.name)
        ).all()
        return {
            "items": [
                {
                    "id": source.id,
                    "name": source.name,
                    "source_type": source.source_type,
                    "enabled": source.enabled,
                    "health": (
                        "disabled"
                        if not source.enabled
                        else "unknown"
                        if checkpoint is None or checkpoint.last_status is None
                        else "degraded"
                        if checkpoint.failure_count > 0
                        else "healthy"
                        if checkpoint.last_status == "success"
                        else "unknown"
                        if checkpoint.last_status == "skipped"
                        else "degraded"
                    ),
                    "has_checkpoint": checkpoint is not None,
                    "modified_after": checkpoint.modified_after if checkpoint else None,
                    "last_attempt_at": checkpoint.last_attempt_at if checkpoint else None,
                    "last_success_at": checkpoint.last_success_at if checkpoint else None,
                    "last_status": checkpoint.last_status if checkpoint else None,
                    "last_error_code": checkpoint.last_error_code if checkpoint else None,
                    "failure_count": checkpoint.failure_count if checkpoint else 0,
                }
                for source, checkpoint in rows
            ]
        }

    @app.get("/api/v1/inventory", response_model=InventoryResponse, tags=["inventory"])
    def list_inventory(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        search: str | None = Query(default=None, max_length=200),
        criticality: Literal["critical", "high", "medium", "low"] | None = Query(default=None),
        internet_facing: bool | None = Query(default=None),
        session=Depends(db_session),
    ):
        snapshot_id = session.scalar(
            select(RunRecord.inventory_snapshot_id)
            .where(RunRecord.inventory_snapshot_id.is_not(None))
            .order_by(RunRecord.created_at.desc(), RunRecord.id.desc())
            .limit(1)
        )
        if snapshot_id is None:
            return {
                "items": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "mode": "persisted_snapshot",
                "snapshot_id": None,
            }
        statement = select(InventoryAsset).where(InventoryAsset.snapshot_id == snapshot_id)
        if criticality is not None:
            statement = statement.where(InventoryAsset.criticality == criticality)
        if internet_facing is not None:
            statement = statement.where(InventoryAsset.internet_facing.is_(internet_facing))
        if search:
            pattern = f"%{search}%"
            statement = statement.where(
                or_(
                    InventoryAsset.asset_key.ilike(pattern),
                    InventoryAsset.service.ilike(pattern),
                    InventoryAsset.vendor.ilike(pattern),
                    InventoryAsset.component.ilike(pattern),
                    InventoryAsset.version.ilike(pattern),
                    InventoryAsset.owner.ilike(pattern),
                )
            )
        total = session.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = session.scalars(
            statement.order_by(InventoryAsset.asset_key)
            .limit(limit)
            .offset(offset)
        ).all()
        items = []
        for asset in rows:
            context = asset.extra_context or {}
            items.append(
                {
                    "asset_key": asset.asset_key,
                    "asset_type": context.get("asset_type"),
                    "service": asset.service,
                    "vendor": asset.vendor,
                    "product": context.get("product", asset.component),
                    "component": asset.component,
                    "version": asset.version,
                    "owner": asset.owner,
                    "owner_contact": asset.owner_contact if can_view_owner_contact() else None,
                    "criticality": asset.criticality,
                    "internet_facing": asset.internet_facing,
                    "data_classification": asset.data_classification,
                    "aliases": context.get("aliases", []),
                }
            )
        return {
            "items": items,
            "total": int(total),
            "limit": limit,
            "offset": offset,
            "mode": "persisted_snapshot",
            "snapshot_id": str(snapshot_id),
        }

    @app.get(
        "/api/v1/deliveries",
        response_model=DeliveryListResponse,
        tags=["delivery"],
    )
    def list_deliveries(
        status: Literal["queued", "delivering", "retry", "delivered", "failed", "unknown"]
        | None = Query(default=None),
        channel: Literal["email", "teams"] | None = Query(default=None),
        run_id: str | None = Query(default=None, max_length=36),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        session=Depends(db_session),
    ):
        conditions = []
        if status:
            conditions.append(OutboxMessage.status == status)
        if channel:
            conditions.append(OutboxMessage.channel == channel)
        if run_id:
            conditions.append(OutboxMessage.run_id == run_id)
        total = int(session.scalar(select(func.count(OutboxMessage.id)).where(*conditions)) or 0)
        records = session.scalars(
            select(OutboxMessage)
            .where(*conditions)
            .order_by(OutboxMessage.created_at.desc(), OutboxMessage.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return {
            "items": [
                {
                    "id": item.id,
                    "run_id": item.run_id,
                    "alert_id": item.alert_id,
                    "channel": item.channel,
                    "route": (item.payload or {}).get("delivery_route"),
                    "recipient_hash": hashlib.sha256(
                        item.recipient_ref.encode("utf-8")
                    ).hexdigest()[:16],
                    "status": item.status,
                    "attempt": item.attempt,
                    "next_attempt_at": item.next_attempt_at,
                    "last_response_code": item.last_response_code,
                    "created_at": item.created_at,
                    "delivered_at": item.delivered_at,
                    "digest_date": (item.payload or {}).get("digest_date"),
                    "alert_count": (item.payload or {}).get("alert_count"),
                    "window_start": (item.payload or {}).get("window_start"),
                    "window_end": (item.payload or {}).get("window_end"),
                }
                for item in records
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/v1/audit/events", response_model=AuditEventListResponse, tags=["audit"])
    def list_audit_events(
        since: datetime | None = Query(default=None),
        until: datetime | None = Query(default=None),
        event_type: str | None = Query(default=None, max_length=100),
        outcome: str | None = Query(default=None, max_length=24),
        actor_id: str | None = Query(default=None, max_length=200),
        run_id: str | None = Query(default=None, max_length=36),
        request_id: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        if since and (since.tzinfo is None or since.utcoffset() is None):
            raise HTTPException(status_code=422, detail="since must include a timezone")
        if until and (until.tzinfo is None or until.utcoffset() is None):
            raise HTTPException(status_code=422, detail="until must include a timezone")
        if since and until and since > until:
            raise HTTPException(status_code=422, detail="since must not be later than until")
        conditions = []
        if since:
            conditions.append(AuditEvent.occurred_at >= since.astimezone(timezone.utc))
        if until:
            conditions.append(AuditEvent.occurred_at <= until.astimezone(timezone.utc))
        if event_type:
            conditions.append(AuditEvent.event_type == event_type)
        if outcome:
            conditions.append(AuditEvent.outcome == outcome)
        if actor_id:
            conditions.append(AuditEvent.actor_id == actor_id)
        if run_id:
            conditions.append(AuditEvent.run_id == run_id)
        if request_id:
            conditions.append(AuditEvent.request_id == request_id)
        total = int(session.scalar(select(func.count(AuditEvent.id)).where(*conditions)) or 0)
        events = session.scalars(
            select(AuditEvent)
            .where(*conditions)
            .order_by(AuditEvent.sequence_number.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return {
            "items": [
                {
                    field: getattr(event, field)
                    for field in AuditEventItem.model_fields
                }
                for event in events
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/v1/audit/integrity", response_model=AuditIntegrityResponse, tags=["audit"])
    def audit_integrity(session=Depends(db_session)):
        valid, failure_reference = verify_chain(session)
        event_count = int(session.scalar(select(func.count(AuditEvent.id))) or 0)
        return {
            "status": "valid" if valid else "invalid",
            "event_count": event_count,
            "failure_reference": failure_reference,
        }

    @app.get("/api/v1/alerts", response_model=AlertListResponse, tags=["alerts"])
    def list_alerts(
        priority: str | None = Query(default=None, max_length=2),
        owner: str | None = Query(default=None, max_length=200),
        service: str | None = Query(default=None, max_length=200),
        search: str | None = Query(default=None, max_length=200),
        since: datetime | None = Query(default=None),
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        conditions = []
        if priority:
            conditions.append(AlertRecord.priority == priority)
        if owner:
            conditions.append(AlertRecord.owner.ilike(f"%{owner}%"))
        if service:
            conditions.append(AlertRecord.service.ilike(f"%{service}%"))
        if search:
            pattern = f"%{search}%"
            conditions.append(
                or_(
                    AlertRecord.cve_id.ilike(pattern),
                    AlertRecord.component.ilike(pattern),
                    AlertRecord.asset_key.ilike(pattern),
                    AlertRecord.summary.ilike(pattern),
                )
            )
        if since:
            since = (
                since.replace(tzinfo=timezone.utc)
                if since.tzinfo is None
                else since.astimezone(timezone.utc)
            )
            conditions.append(AlertRecord.created_at >= since)
        total = int(session.scalar(select(func.count(AlertRecord.id)).where(*conditions)) or 0)
        priority_order = case(
            (AlertRecord.priority == "P1", 1),
            (AlertRecord.priority == "P2", 2),
            (AlertRecord.priority == "P3", 3),
            else_=4,
        )
        records = session.scalars(
            select(AlertRecord)
            .where(*conditions)
            .order_by(priority_order, AlertRecord.risk_score.desc(), AlertRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return {
            "items": [alert_item(item) for item in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/v1/alerts/{alert_id}", response_model=AlertDetailResponse, tags=["alerts"])
    def alert_detail(alert_id, session=Depends(db_session)):
        record = session.get(AlertRecord, alert_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        match_record = session.get(MatchRecord, record.match_id)
        if match_record is None:
            raise HTTPException(status_code=500, detail="Alert match record is missing")
        advisory_record = session.scalar(
            select(AdvisoryRecord)
            .where(AdvisoryRecord.canonical_id == record.cve_id)
            .order_by(AdvisoryRecord.modified_at.desc(), AdvisoryRecord.id)
            .limit(1)
        )
        epss_record = session.scalar(
            select(AdvisoryEnrichment)
            .join(AdvisoryRecord, AdvisoryRecord.id == AdvisoryEnrichment.advisory_id)
            .where(
                AdvisoryRecord.canonical_id == record.cve_id,
                AdvisoryEnrichment.kind == "epss",
            )
            .order_by(AdvisoryEnrichment.observed_at.desc(), AdvisoryEnrichment.id.desc())
            .limit(1)
        )
        references_record = session.scalar(
            select(AdvisoryEnrichment)
            .join(AdvisoryRecord, AdvisoryRecord.id == AdvisoryEnrichment.advisory_id)
            .where(
                AdvisoryRecord.canonical_id == record.cve_id,
                AdvisoryEnrichment.kind == "references",
            )
            .order_by(AdvisoryEnrichment.observed_at.desc(), AdvisoryEnrichment.id.desc())
            .limit(1)
        )
        references_payload = (
            references_record.value
            if references_record and isinstance(references_record.value, dict)
            else {}
        )
        source_references = references_payload.get("references")
        if not isinstance(source_references, list):
            source_references = advisory_record.source_references if advisory_record else []
        source_references = [
            reference
            for reference in source_references
            if isinstance(reference, dict) and _is_http_source_url(reference.get("url"))
        ]
        remediation_tags = (
            {"patch", "vendor advisory", "release notes"}
            if record.fixed_version
            else {"mitigation", "vendor advisory"}
        )
        remediation_sources = [
            reference
            for reference in source_references
            if remediation_tags
            & {
                tag.strip().casefold()
                for tag in reference.get("tags", [])
                if isinstance(tag, str)
            }
        ]
        citation_status = "cited" if remediation_sources else "unverified"
        epss_payload = (
            epss_record.value
            if epss_record and isinstance(epss_record.value, dict)
            else {}
        )
        epss_status = epss_payload.get("status")
        epss_context = (
            {
                "status": epss_status,
                "score": epss_payload.get("score"),
                "percentile": epss_payload.get("percentile"),
                "score_date": epss_payload.get("score_date"),
                "source_url": epss_record.source_url,
                "observed_at": epss_record.observed_at,
            }
            if epss_status in {"available", "not_scored"}
            else None
        )
        advisory_payload = advisory_record.normalized_payload or {} if advisory_record else {}
        advisory_context = (
            {
                "title": advisory_record.title,
                "source": advisory_payload.get("source"),
                "published": advisory_payload.get("published"),
                "cvss": float(advisory_record.cvss) if advisory_record.cvss is not None else None,
                "text": str(advisory_payload.get("text") or "")[:20000],
                "in_kev": advisory_payload.get("in_kev"),
                "kev_status": advisory_payload.get(
                    "kev_status",
                    "listed"
                    if advisory_payload.get("in_kev") is True
                    else "not_listed"
                    if advisory_payload.get("in_kev") is False
                    else "unknown",
                ),
                "references": source_references,
                "epss": epss_context,
            }
            if advisory_record
            else {}
        )
        run = session.get(RunRecord, record.run_id)
        asset = (
            session.scalar(
                select(InventoryAsset).where(
                    InventoryAsset.snapshot_id == run.inventory_snapshot_id,
                    InventoryAsset.asset_key == record.asset_key,
                )
            )
            if run is not None and run.inventory_snapshot_id
            else None
        )
        asset_context = (
            {
                "asset_key": asset.asset_key,
                "asset_type": (asset.extra_context or {}).get("asset_type"),
                "criticality": asset.criticality,
                "internet_facing": asset.internet_facing,
                "data_classification": asset.data_classification,
                "vendor": asset.vendor,
                "product": (asset.extra_context or {}).get("product", asset.component),
                "owner_contact": asset.owner_contact if can_view_owner_contact() else None,
                "aliases": (asset.extra_context or {}).get("aliases", []),
            }
            if asset
            else {}
        )
        history_rows = session.execute(
            select(MatchRecord, InventoryAsset)
            .join(InventoryAsset, InventoryAsset.id == MatchRecord.inventory_asset_id)
            .join(AdvisoryRecord, AdvisoryRecord.id == MatchRecord.advisory_id)
            .where(
                AdvisoryRecord.canonical_id == record.cve_id,
                InventoryAsset.asset_key == record.asset_key,
            )
            .order_by(MatchRecord.created_at.desc(), MatchRecord.id.desc())
            .limit(21)
        ).all()
        match_history = [
            {
                "run_id": historical_match.run_id,
                "outcome": historical_match.outcome,
                "asset_key": historical_asset.asset_key,
                "component": historical_asset.component,
                "installed_version": historical_asset.installed_version,
                "confidence": historical_match.confidence,
                "affected_range": historical_match.affected_range,
                "comparator": historical_match.comparator,
                "evidence": historical_match.evidence or [],
                "compared_at": historical_match.created_at,
            }
            for historical_match, historical_asset in history_rows[:20]
        ]
        return {
            **alert_item(record),
            "summary": record.summary,
            "remediation": record.remediation,
            "sla_hours": record.sla_hours,
            "score_breakdown": record.score_breakdown or {},
            "policy_version": record.policy_version,
            "evidence": record.evidence or [],
            "source_references": source_references,
            "remediation_sources": remediation_sources,
            "remediation_citation_status": citation_status,
            "advisory": advisory_context,
            "asset_context": asset_context,
            "match": match_evidence_item(match_record, asset),
            "match_history": match_history,
            "match_history_truncated": len(history_rows) > 20,
        }

    def budget_summary(session, filters):
        budget_effective_cost = case(
            (LLMCall.cost_amount.is_(None), LLMCall.budget_estimate_usd),
            (LLMCall.budget_estimate_usd.is_(None), LLMCall.cost_amount),
            (LLMCall.cost_amount >= LLMCall.budget_estimate_usd, LLMCall.cost_amount),
            else_=LLMCall.budget_estimate_usd,
        )
        totals = session.execute(
            select(
                func.count(LLMCall.id),
                func.sum(case((LLMCall.cost_amount.is_(None), 1), else_=0)),
                func.sum(case((budget_effective_cost.is_(None), 1), else_=0)),
                func.sum(budget_effective_cost),
                func.sum(
                    case((LLMCall.cost_amount.is_(None), LLMCall.budget_estimate_usd), else_=0)
                ),
            ).where(*filters)
        ).one()
        amounts = session.execute(
            select(LLMCall.cost_currency, func.sum(LLMCall.cost_amount))
            .where(*filters, LLMCall.cost_amount.is_not(None))
            .group_by(LLMCall.cost_currency)
        ).all()
        return {
            "calls": int(totals[0] or 0),
            "unknown_cost_calls": int(totals[1] or 0),
            "unpriced_calls": int(totals[2] or 0),
            "budget_enforced_usd": format(totals[3] or Decimal(0), "f"),
            "estimated_unknown_cost_usd": format(totals[4] or Decimal(0), "f"),
            "known_cost_by_currency": {
                currency or "unknown": format(amount, "f") for currency, amount in amounts
            },
        }

    @app.get("/api/v1/llm/budgets", response_model=LLMBudgetsResponse, tags=["llm-usage"])
    def llm_budgets(run_id=Query(default=None, max_length=36), session=Depends(db_session)):
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month = budget_summary(
            session, [LLMCall.started_at >= period_start, LLMCall.started_at < now]
        )
        month_usd = Decimal(month["budget_enforced_usd"])
        month_limit = settings.llm_max_cost_per_month_usd
        month["limit_status"] = (
            "not_configured"
            if month_limit is None
            else "unknown"
            if month["unpriced_calls"]
            else "exceeded"
            if month_usd > month_limit
            else "at_limit"
            if month_usd == month_limit
            else "within_limit"
        )
        month["remaining_usd"] = (
            format(max(month_limit - month_usd, Decimal(0)), "f")
            if month_limit is not None and not month["unpriced_calls"]
            else None
        )
        run_summary = None
        if run_id:
            run_summary = budget_summary(session, [LLMCall.run_id == run_id])
            run_usd = Decimal(run_summary["budget_enforced_usd"])
            run_limit = settings.llm_max_cost_per_run_usd
            run_summary.update(
                {
                    "run_id": run_id,
                    "limit_usd": format(run_limit, "f") if run_limit is not None else None,
                    "limit_status": "not_configured"
                    if run_limit is None
                    else "unknown"
                    if run_summary["unpriced_calls"]
                    else "exceeded"
                    if run_usd > run_limit
                    else "at_limit"
                    if run_usd == run_limit
                    else "within_limit",
                    "remaining_usd": format(max(run_limit - run_usd, Decimal(0)), "f")
                    if run_limit is not None and not run_summary["unpriced_calls"]
                    else None,
                }
            )
        return {
            "period_start": period_start,
            "configured_limits_usd": {
                "per_run": format(settings.llm_max_cost_per_run_usd, "f")
                if settings.llm_max_cost_per_run_usd is not None
                else None,
                "per_month": format(month_limit, "f") if month_limit is not None else None,
            },
            "month_to_date": month,
            "run": run_summary,
        }

    @app.get("/api/v1/llm/usage/report", response_model=LLMUsageReportResponse, tags=["llm-usage"])
    def llm_usage_report(
        group_by: LLMUsageGroupBy = Query(default="day"),
        since: datetime | None = Query(default=None),
        until: datetime | None = Query(default=None),
        run_id: str | None = Query(default=None, max_length=36),
        request_id: str | None = Query(default=None, max_length=64),
        job_id: str | None = Query(default=None, max_length=36),
        provider: str | None = Query(default=None, max_length=80),
        model: str | None = Query(default=None, max_length=160),
        task: str | None = Query(default=None, max_length=40),
        actor_id: str | None = Query(default=None, max_length=200),
        advisory_id: str | None = Query(default=None, max_length=80),
        prompt_version: str | None = Query(default=None, max_length=100),
        outcome: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        conditions = llm_conditions(
            since,
            until,
            run_id,
            request_id,
            job_id,
            provider,
            model,
            task,
            actor_id,
            advisory_id,
            prompt_version,
            outcome,
        )
        day_timestamp = LLMCall.started_at
        if session.get_bind().dialect.name == "postgresql":
            day_timestamp = func.timezone("UTC", LLMCall.started_at)
        grouping = {
            "day": func.date(day_timestamp),
            "run": LLMCall.run_id,
            "task": LLMCall.task,
            "provider": LLMCall.provider,
            "model": LLMCall.model,
            "prompt_version": LLMCall.prompt_version,
            "advisory": LLMCall.advisory_id,
            "actor": LLMCall.actor_id,
            "outcome": LLMCall.outcome,
        }[group_by]
        budget_effective_cost = case(
            (LLMCall.cost_amount.is_(None), LLMCall.budget_estimate_usd),
            (LLMCall.budget_estimate_usd.is_(None), LLMCall.cost_amount),
            (LLMCall.cost_amount >= LLMCall.budget_estimate_usd, LLMCall.cost_amount),
            else_=LLMCall.budget_estimate_usd,
        )
        grouped_rows = (
            select(
                grouping.label("group_key"),
                LLMCall.cost_currency.label("currency"),
            )
            .where(*conditions)
            .group_by(grouping, LLMCall.cost_currency)
            .subquery()
        )
        total_groups = int(
            session.scalar(select(func.count()).select_from(grouped_rows)) or 0
        )
        rows = session.execute(
            select(
                grouping.label("group_key"),
                func.count(LLMCall.id).label("calls"),
                func.sum(case((LLMCall.attempt_number > 1, 1), else_=0)).label("retries"),
                func.sum(LLMCall.input_tokens).label("input_tokens"),
                func.sum(LLMCall.output_tokens).label("output_tokens"),
                func.sum(LLMCall.total_tokens).label("total_tokens"),
                func.sum(
                    case(
                        (or_(LLMCall.input_tokens.is_(None), LLMCall.output_tokens.is_(None)), 1),
                        else_=0,
                    )
                ).label("unknown_token_calls"),
                LLMCall.cost_currency.label("currency"),
                func.sum(LLMCall.cost_amount).label("known_cost"),
                func.sum(
                    case((LLMCall.cost_amount.is_(None), LLMCall.budget_estimate_usd), else_=0)
                ).label("estimated_unknown_cost"),
                func.sum(budget_effective_cost).label("budget_enforced_cost"),
                func.sum(case((LLMCall.cost_amount.is_(None), 1), else_=0)).label(
                    "unknown_cost_calls"
                ),
                func.sum(case((LLMCall.outcome == "unknown", 1), else_=0)).label(
                    "unknown_outcome_calls"
                ),
                func.sum(case((LLMCall.outcome == "pending", 1), else_=0)).label(
                    "pending_calls"
                ),
            )
            .where(*conditions)
            .group_by(grouping, LLMCall.cost_currency)
            .order_by(grouping, LLMCall.cost_currency)
            .limit(limit)
            .offset(offset)
        ).all()
        total = int(session.scalar(select(func.count(LLMCall.id)).where(*conditions)) or 0)
        total_retries = int(
            session.scalar(
                select(func.sum(case((LLMCall.attempt_number > 1, 1), else_=0))).where(*conditions)
            )
            or 0
        )
        unknown_outcome_calls = int(
            session.scalar(
                select(func.count(LLMCall.id)).where(*conditions, LLMCall.outcome == "unknown")
            )
            or 0
        )
        pending_calls = int(
            session.scalar(
                select(func.count(LLMCall.id)).where(*conditions, LLMCall.outcome == "pending")
            )
            or 0
        )
        return {
            "group_by": group_by,
            "total_calls": total,
            "total_retries": total_retries,
            "unknown_outcome_calls": unknown_outcome_calls,
            "pending_calls": pending_calls,
            "total_groups": total_groups,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(rows) < total_groups,
            "groups": [
                {
                    "key": row.group_key,
                    "calls": int(row.calls or 0),
                    "retries": int(row.retries or 0),
                    "input_tokens": int(row.input_tokens or 0),
                    "output_tokens": int(row.output_tokens or 0),
                    "total_tokens": int(row.total_tokens or 0),
                    "unknown_token_calls": int(row.unknown_token_calls or 0),
                    "currency": row.currency or "unknown",
                    "known_cost": format(row.known_cost or Decimal(0), "f"),
                    "estimated_unknown_cost_usd": format(
                        row.estimated_unknown_cost or Decimal(0), "f"
                    ),
                    "budget_enforced_cost_usd": format(row.budget_enforced_cost or Decimal(0), "f"),
                    "unknown_cost_calls": int(row.unknown_cost_calls or 0),
                    "unknown_outcome_calls": int(row.unknown_outcome_calls or 0),
                    "pending_calls": int(row.pending_calls or 0),
                }
                for row in rows
            ],
        }

    @app.get("/api/v1/llm/usage", response_model=LLMUsageResponse, tags=["llm-usage"])
    def llm_usage(
        since: datetime | None = Query(default=None),
        until: datetime | None = Query(default=None),
        run_id: str | None = Query(default=None, max_length=36),
        request_id: str | None = Query(default=None, max_length=64),
        job_id: str | None = Query(default=None, max_length=36),
        provider: str | None = Query(default=None, max_length=80),
        model: str | None = Query(default=None, max_length=160),
        task: str | None = Query(default=None, max_length=40),
        actor_id: str | None = Query(default=None, max_length=200),
        advisory_id: str | None = Query(default=None, max_length=80),
        prompt_version: str | None = Query(default=None, max_length=100),
        outcome: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=1000000),
        session=Depends(db_session),
    ):
        conditions = llm_conditions(
            since,
            until,
            run_id,
            request_id,
            job_id,
            provider,
            model,
            task,
            actor_id,
            advisory_id,
            prompt_version,
            outcome,
        )
        stats = session.execute(
            select(
                func.count(LLMCall.id),
                func.sum(case((LLMCall.attempt_number > 1, 1), else_=0)),
                func.sum(LLMCall.input_tokens),
                func.sum(LLMCall.output_tokens),
                func.sum(LLMCall.total_tokens),
                func.sum(
                    case(
                        (or_(LLMCall.input_tokens.is_(None), LLMCall.output_tokens.is_(None)), 1),
                        else_=0,
                    )
                ),
                func.sum(case((LLMCall.cost_amount.is_(None), 1), else_=0)),
            ).where(*conditions)
        ).one()
        costs = session.execute(
            select(LLMCall.cost_currency, func.sum(LLMCall.cost_amount))
            .where(*conditions, LLMCall.cost_amount.is_not(None))
            .group_by(LLMCall.cost_currency)
        ).all()
        records = session.scalars(
            select(LLMCall)
            .where(*conditions)
            .order_by(LLMCall.started_at.desc(), LLMCall.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return {
            "items": [llm_call_item(record) for record in records],
            "total": int(stats[0] or 0),
            "retries": int(stats[1] or 0),
            "limit": limit,
            "offset": offset,
            "input_tokens": int(stats[2] or 0),
            "output_tokens": int(stats[3] or 0),
            "total_tokens": int(stats[4] or 0),
            "unknown_token_calls": int(stats[5] or 0),
            "known_cost_by_currency": {
                currency or "unknown": format(amount, "f") for currency, amount in costs
            },
            "unknown_cost_calls": int(stats[6] or 0),
        }

    @app.get(
        "/api/v1/llm/usage/{call_id}", response_model=LLMCallDetailResponse, tags=["llm-usage"]
    )
    def llm_call_detail(call_id, session=Depends(db_session)):
        record = session.get(LLMCall, call_id)
        if record is None:
            raise HTTPException(status_code=404, detail="LLM call not found")
        artifacts = session.scalars(
            select(LLMExchangeArtifact)
            .where(LLMExchangeArtifact.llm_call_id == record.id)
            .order_by(LLMExchangeArtifact.artifact_kind)
        ).all()
        return {
            **llm_call_item(record),
            "artifacts": [
                {
                    "id": artifact.id,
                    "kind": artifact.artifact_kind,
                    "plaintext_hash": artifact.plaintext_hash,
                    "payload_bytes": artifact.payload_bytes,
                    "key_version": artifact.encryption_key_version,
                    "captured_at": artifact.captured_at,
                    "retention_expires_at": artifact.retention_expires_at,
                    "purged_at": artifact.purged_at,
                }
                for artifact in artifacts
            ],
        }

    @app.post(
        "/api/v1/llm/usage/{call_id}/content",
        response_model=LLMContentReadResponse,
        tags=["llm-usage"],
    )
    def read_llm_content(call_id, request_body: LLMContentReadRequest, session=Depends(db_session)):
        from counterstrike.artifacts import read_artifact

        record = session.get(LLMCall, call_id)
        if record is None:
            append_event(
                session,
                actor_type="user",
                actor_id=settings.local_dev_identity,
                action="llm_artifact_read_missing_call",
                event_type="llm.audit.content_access",
                outcome="not_found",
                resource_type="llm_call",
                resource_id=call_id[:36],
                request_id=request_id_context.get(),
                safe_details={"artifact_kind": request_body.kind},
            )
            session.commit()
            raise HTTPException(status_code=404, detail="LLM call not found")
        artifact = session.scalar(
            select(LLMExchangeArtifact).where(
                LLMExchangeArtifact.llm_call_id == call_id,
                LLMExchangeArtifact.artifact_kind == request_body.kind,
            )
        )
        if artifact is None:
            session.add(
                LLMAuditAccess(
                    id=str(uuid.uuid4()),
                    llm_call_id=call_id,
                    artifact_id=None,
                    actor_id=settings.local_dev_identity,
                    request_id=request_id_context.get(),
                    purpose=request_body.purpose,
                    action="read",
                    outcome="not_found",
                )
            )
            append_event(
                session,
                actor_type="user",
                actor_id=settings.local_dev_identity,
                action="llm_artifact_read_missing",
                event_type="llm.audit.content_access",
                outcome="not_found",
                resource_type="llm_call",
                resource_id=call_id,
                request_id=request_id_context.get(),
                llm_call_id=call_id,
                safe_details={"artifact_kind": request_body.kind},
            )
            session.commit()
            raise HTTPException(status_code=404, detail="LLM artifact not found")
        content, outcome = read_artifact(
            session,
            artifact,
            actor_id=settings.local_dev_identity,
            request_id=request_id_context.get(),
            purpose=request_body.purpose,
            authorized=True,
            settings=settings,
        )
        session.commit()
        if outcome != "success":
            status_code = (
                410
                if outcome in {"expired", "purged"}
                else 503
                if outcome == "key_unavailable"
                else 500
                if outcome == "integrity_failure"
                else 403
            )
            raise HTTPException(
                status_code=status_code, detail="LLM artifact content could not be released"
            )
        return {
            "call_id": call_id,
            "kind": artifact.artifact_kind,
            "content": content,
            "plaintext_hash": artifact.plaintext_hash,
            "purpose": request_body.purpose,
        }

    @app.middleware("http")
    async def correlated_access_log(request, call_next):
        supplied_id = request.headers.get("x-request-id", "")
        request_id = supplied_id if REQUEST_ID_PATTERN.fullmatch(supplied_id) else uuid.uuid4().hex
        token = request_id_context.set(request_id)
        started = datetime.now(timezone.utc)
        response = None
        capability = required_capability(request.url.path, request.method)
        try:
            if capability is not None:
                (
                    query_parameters,
                    omitted_filter_names,
                    truncated_query_parameter_count,
                ) = _safe_audit_query_parameters(request.query_params)
                try:
                    factory = get_session_factory(settings)
                    with factory() as session:
                        append_event(
                            session,
                            actor_type="user",
                            actor_id=settings.local_dev_identity,
                            action="api_request_started",
                            event_type="api.request.started",
                            outcome="started",
                            resource_type="api_route",
                            resource_id=request.url.path[:200],
                            request_id=request_id,
                            safe_details={
                                "capability": capability,
                                "method": request.method,
                                "query_parameters": query_parameters,
                                "omitted_filter_names": omitted_filter_names,
                                "truncated_query_parameter_count": truncated_query_parameter_count,
                            },
                        )
                        session.commit()
                except Exception as exc:
                    if request.url.path == "/metrics":
                        app_logger.warning(
                            "Metrics scrape is continuing without a persisted start event",
                            extra={
                                "event": "api.metrics.audit_unavailable",
                                "error_code": type(exc).__name__,
                                "method": request.method,
                                "route": "/metrics",
                                "request_id": request_id,
                            },
                        )
                    else:
                        app_logger.error(
                            "Protected API request stopped because its start event could not be "
                            "persisted",
                            extra={
                                "event": "api.request.audit_unavailable",
                                "error_code": type(exc).__name__,
                                "method": request.method,
                                "route": request.url.path,
                                "request_id": request_id,
                            },
                        )
                        unavailable = JSONResponse(
                            status_code=503,
                            content={
                                "error": {
                                    "code": "audit_unavailable",
                                    "message": (
                                        "The request could not be processed because audit "
                                        "storage is unavailable."
                                    ),
                                    "request_id": request_id,
                                }
                            },
                        )
                        unavailable.headers["X-Request-ID"] = request_id
                        http_metrics.observe(
                            request.method,
                            "audit_unavailable",
                            unavailable.status_code,
                            (datetime.now(timezone.utc) - started).total_seconds(),
                        )
                        return unavailable
            response = await call_next(request)
        except Exception as exc:
            route = request.scope.get("route")
            route_template = getattr(route, "path", "unmatched")
            http_metrics.observe(
                request.method,
                route_template,
                500,
                (datetime.now(timezone.utc) - started).total_seconds(),
            )
            app_logger.error(
                "Request failed before a response was produced",
                extra={
                    "event": "api.request.failed",
                    "method": request.method,
                    "route": request.url.path,
                    "error_code": type(exc).__name__,
                },
            )
            if required_capability(request.url.path, request.method) is not None:
                try:
                    factory = get_session_factory(settings)
                    with factory() as session:
                        append_event(
                            session,
                            actor_type="user",
                            actor_id=settings.local_dev_identity,
                            action="api_request",
                            event_type="api.request.failed",
                            outcome="failure",
                            resource_type="api_route",
                            resource_id=request.url.path[:200],
                            request_id=request_id,
                            safe_details={"method": request.method, "status_code": 500},
                        )
                        session.commit()
                except Exception as audit_exc:
                    app_logger.error(
                        "Failed API request audit could not be persisted",
                        extra={
                            "event": "api.request.audit_failed",
                            "error_code": type(audit_exc).__name__,
                            "method": request.method,
                            "route": request.url.path,
                        },
                    )
            raise
        else:
            duration_ms = round((datetime.now(timezone.utc) - started).total_seconds() * 1000, 2)
            route = request.scope.get("route")
            route_template = getattr(route, "path", "unmatched")
            http_metrics.observe(
                request.method,
                route_template,
                response.status_code,
                (datetime.now(timezone.utc) - started).total_seconds(),
            )
            app_logger.info(
                "HTTP request completed",
                extra={
                    "event": "api.request.completed",
                    "method": request.method,
                    "route": route_template,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
            response.headers["X-Request-ID"] = request_id
            if required_capability(request.url.path, request.method) is not None:
                (
                    query_parameters,
                    omitted_filter_names,
                    truncated_query_parameter_count,
                ) = _safe_audit_query_parameters(request.query_params)
                try:
                    factory = get_session_factory(settings)
                    with factory() as session:
                        append_event(
                            session,
                            actor_type="user",
                            actor_id=settings.local_dev_identity,
                            action="api_request",
                            event_type="api.request.completed",
                            outcome="success" if response.status_code < 400 else "failure",
                            resource_type="api_route",
                            resource_id=route_template[:200],
                            request_id=request_id,
                            safe_details={
                                "method": request.method,
                                "status_code": response.status_code,
                                "duration_ms": duration_ms,
                                "query_parameters": query_parameters,
                                "omitted_filter_names": omitted_filter_names,
                                "truncated_query_parameter_count": truncated_query_parameter_count,
                            },
                        )
                        session.commit()
                except Exception as exc:
                    app_logger.error(
                        "API request audit could not be persisted",
                        extra={
                            "event": "api.request.audit_failed",
                            "error_code": type(exc).__name__,
                            "method": request.method,
                            "route": route_template,
                            "status_code": response.status_code,
                        },
                    )
            return response
        finally:
            request_id_context.reset(token)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request, exc):
        safe_errors = [
            {
                "location": [str(part) for part in error.get("loc", ())],
                "message": str(error.get("msg", "Invalid value")),
                "code": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed.",
                    "details": safe_errors,
                    "request_id": request_id_context.get(),
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request, exc):
        code = "not_found" if exc.status_code == 404 else "http_error"
        message = (
            "The requested resource was not found."
            if exc.status_code == 404
            else "The request could not be completed."
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {"code": code, "message": message, "request_id": request_id_context.get()}
            },
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request, exc):
        app_logger.error(
            "Unhandled application error",
            extra={"event": "api.error.unhandled", "error_code": type(exc).__name__},
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "The request could not be completed.",
                    "request_id": request_id_context.get(),
                }
            },
        )

    @app.get("/metrics", include_in_schema=False)
    def metrics_endpoint():
        if not settings.metrics_enabled:
            raise HTTPException(status_code=404, detail="Not found")
        lines = [http_metrics.render().rstrip()]
        database_up = 0
        if settings.database_url is not None:
            try:
                factory = get_session_factory(settings)
                with factory() as session:
                    job_rows = session.execute(
                        select(JobRecord.status, func.count(JobRecord.id)).group_by(
                            JobRecord.status
                        )
                    ).all()
                    llm_rows = session.execute(
                        select(
                            LLMCall.outcome,
                            func.count(LLMCall.id),
                            func.coalesce(func.sum(LLMCall.input_tokens), 0),
                            func.coalesce(func.sum(LLMCall.output_tokens), 0),
                            func.coalesce(
                                func.sum(
                                    case(
                                        (LLMCall.cost_currency == "USD", LLMCall.cost_amount),
                                        else_=None,
                                    )
                                ),
                                0,
                            ),
                        ).group_by(LLMCall.outcome)
                    ).all()
                database_up = 1
                lines.extend(
                    [
                        "# HELP counterstrike_jobs Current jobs by status.",
                        "# TYPE counterstrike_jobs gauge",
                    ]
                )
                allowed_job_statuses = {
                    "queued",
                    "running",
                    "retry_wait",
                    "succeeded",
                    "failed",
                    "cancelled",
                }
                for status, count in job_rows:
                    bounded_status = status if status in allowed_job_statuses else "other"
                    lines.append(
                        f'counterstrike_jobs{{status="{bounded_status}"}} {int(count)}'
                    )
                lines.extend(
                    [
                        "# HELP counterstrike_llm_calls Recorded LLM calls by outcome.",
                        "# TYPE counterstrike_llm_calls gauge",
                        "# HELP counterstrike_llm_tokens Persisted LLM tokens by direction.",
                        "# TYPE counterstrike_llm_tokens gauge",
                        "# HELP counterstrike_llm_cost_known_usd Known USD cost of LLM calls.",
                        "# TYPE counterstrike_llm_cost_known_usd gauge",
                    ]
                )
                allowed_outcomes = {
                    "pending",
                    "succeeded",
                    "failed",
                    "unknown",
                }
                for outcome, count, input_tokens, output_tokens, cost_usd in llm_rows:
                    bounded_outcome = outcome if outcome in allowed_outcomes else "other"
                    lines.append(
                        f'counterstrike_llm_calls{{outcome="{bounded_outcome}"}} {int(count)}'
                    )
                    lines.append(
                        f'counterstrike_llm_tokens{{direction="input",'
                        f'outcome="{bounded_outcome}"}} {int(input_tokens)}'
                    )
                    lines.append(
                        f'counterstrike_llm_tokens{{direction="output",'
                        f'outcome="{bounded_outcome}"}} {int(output_tokens)}'
                    )
                    lines.append(
                        f'counterstrike_llm_cost_known_usd{{outcome="{bounded_outcome}"}} '
                        f"{Decimal(cost_usd):.10f}"
                    )
            except Exception as exc:
                app_logger.error(
                    "Metrics database snapshot could not be collected",
                    extra={
                        "event": "api.metrics.database_unavailable",
                        "error_code": type(exc).__name__,
                    },
                )
        lines.append(
            "# HELP counterstrike_database_up Whether the metrics database query succeeded."
        )
        lines.append("# TYPE counterstrike_database_up gauge")
        lines.append(f"counterstrike_database_up {database_up}")
        return Response(
            content="\n".join(lines) + "\n",
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/health/live", response_model=HealthResponse, tags=["health"])
    @app.get("/api/v1/health/live", response_model=HealthResponse, tags=["health"])
    async def liveness():
        return {"status": "ok"}

    @app.get(
        "/health/ready",
        response_model=HealthResponse,
        responses={503: {"model": HealthResponse}},
        tags=["health"],
    )
    @app.get(
        "/api/v1/health/ready",
        response_model=HealthResponse,
        responses={503: {"model": HealthResponse}},
        tags=["health"],
    )
    async def readiness():
        checks = _ready_checks(settings)
        if settings.database_url is not None:
            ready = checks.get("database") == "ready"
        else:
            fixture_checks = [value for name, value in checks.items() if name != "database"]
            ready = (
                settings.environment != "production"
                and checks.get("database") == "fixture_mode"
                and bool(fixture_checks)
                and all(value == "ready" for value in fixture_checks)
            )
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "not_ready", "checks": checks},
        )

    @app.get(
        "/api/data",
        response_model=LegacyPreviewResponse,
        responses={503: {"model": ErrorResponse}},
        deprecated=True,
    )
    async def legacy_preview_data():
        try:
            return _preview_payload(settings, include_owner_contact=can_view_owner_contact())
        except RuntimeError as exc:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "preview_data_unavailable",
                        "message": str(exc),
                        "request_id": request_id_context.get(),
                    }
                },
            )

    frontend_dir = settings.frontend_dir
    if not frontend_dir.is_absolute():
        frontend_dir = PROJECT_ROOT / frontend_dir
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
    else:
        app_logger.warning(
            "Frontend directory is missing; API will run without static UI",
            extra={"event": "api.frontend.unavailable", "error_code": "frontend_missing"},
        )

    def custom_openapi():
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        error_response = {
            "description": "The request could not be completed.",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                }
            },
        }
        for path, operations in schema.get("paths", {}).items():
            for method, operation in operations.items():
                if method not in {"get", "post", "put", "patch", "delete", "options"}:
                    continue
                responses = operation.setdefault("responses", {})
                if "422" in responses:
                    responses["422"] = {
                        **error_response,
                        "description": "Request validation failed.",
                    }
                responses.setdefault(
                    "500",
                    {**error_response, "description": "An unexpected error occurred."},
                )
                if "{" in path:
                    responses.setdefault(
                        "404",
                        {**error_response, "description": "The requested resource was not found."},
                    )
                if method == "post" and path in {
                    "/api/v1/runs",
                    "/api/v1/reviews/{review_id}/decision",
                }:
                    responses.setdefault(
                        "409",
                        {
                            **error_response,
                            "description": "The requested state transition conflicted.",
                        },
                    )
                if method == "post" and path.endswith("/content"):
                    responses.setdefault(
                        "410",
                        {
                            **error_response,
                            "description": "The captured artifact expired or was purged.",
                        },
                    )
                if required_capability(path, method.upper()) is not None:
                    responses.setdefault(
                        "403",
                        {
                            **error_response,
                            "description": "The configured identity is not authorized.",
                        },
                    )
                    responses.setdefault(
                        "503",
                        {
                            **error_response,
                            "description": "Audit storage or a required service is unavailable.",
                        },
                    )
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi
    return app


app = create_app()
