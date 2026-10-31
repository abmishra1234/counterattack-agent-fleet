"""Durable metering operations used by network-capable LLM adapters."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import ROUND_CEILING, Decimal
from typing import Any
from uuid import uuid4

from sqlalchemy import case, func, select, text
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from counterstrike.artifacts import serialize_exchange, store_artifact
from counterstrike.audit import append_event
from counterstrike.config import Settings
from counterstrike.db_models import LLMCall, LLMPricingRate
from counterstrike.observability import redact


class LLMBudgetExceeded(RuntimeError):
    """Raised after a durable audit event records that a spend limit blocked a call."""


def _provider_name(settings: Settings) -> str:
    if settings.llm_provider not in {"openai_compatible", "azure_openai"}:
        raise RuntimeError("LLM metering requires a configured live provider")
    return settings.llm_provider


def _pricing_rate(session: Session, settings: Settings, now: datetime) -> LLMPricingRate | None:
    """Register the immutable configured rate version and select the active model rate."""
    provider = _provider_name(settings)
    if settings.llm_input_price_usd_per_1m is not None:
        values = {
            "provider": provider,
            "model": settings.llm_model or "unknown",
            "pricing_version": settings.llm_pricing_version,
            "effective_from": settings.llm_pricing_effective_at,
            "input_rate_per_million": settings.llm_input_price_usd_per_1m,
            "output_rate_per_million": settings.llm_output_price_usd_per_1m,
            "currency": "USD",
        }
        existing = session.scalar(
            select(LLMPricingRate).where(
                LLMPricingRate.provider == values["provider"],
                LLMPricingRate.model == values["model"],
                LLMPricingRate.pricing_version == values["pricing_version"],
            )
        )
        competing_rate = session.scalar(
            select(LLMPricingRate.id).where(
                LLMPricingRate.provider == values["provider"],
                LLMPricingRate.model == values["model"],
                LLMPricingRate.effective_from == settings.llm_pricing_effective_at,
                LLMPricingRate.pricing_version != values["pricing_version"],
            )
        )
        if competing_rate is not None:
            raise RuntimeError("LLM pricing versions for one model need distinct effective dates")
        if existing is None:
            dialect = session.bind.dialect.name if session.bind is not None else ""
            insert = (
                postgresql_insert
                if dialect == "postgresql"
                else sqlite_insert
                if dialect == "sqlite"
                else None
            )
            if insert is None:
                raise RuntimeError("LLM pricing registry requires PostgreSQL or SQLite")
            result = session.execute(
                insert(LLMPricingRate)
                .values(**values)
                .on_conflict_do_nothing()
            )
            session.flush()
            existing = session.scalar(
                select(LLMPricingRate).where(
                    LLMPricingRate.provider == values["provider"],
                    LLMPricingRate.model == values["model"],
                    LLMPricingRate.pricing_version == values["pricing_version"],
                )
            )
            if existing is None:
                raise RuntimeError("Configured LLM pricing rate could not be registered")
            if result.rowcount:
                append_event(
                    session,
                    actor_type="service",
                    action="llm_pricing_rate_registered",
                    event_type="llm.pricing.rate_registered",
                    outcome="success",
                    resource_type="llm_pricing_rate",
                    resource_id=existing.id,
                    safe_details={
                        "provider": existing.provider,
                        "model": existing.model,
                        "pricing_version": existing.pricing_version,
                        "effective_from": existing.effective_from.isoformat(),
                        "input_rate_per_million": format(existing.input_rate_per_million, "f"),
                        "output_rate_per_million": format(existing.output_rate_per_million, "f"),
                        "currency": existing.currency,
                    },
                )
        configured_input = Decimal(str(settings.llm_input_price_usd_per_1m)).quantize(
            Decimal("0.00000001")
        )
        configured_output = Decimal(str(settings.llm_output_price_usd_per_1m)).quantize(
            Decimal("0.00000001")
        )
        existing_effective = existing.effective_from
        if existing_effective.tzinfo is None:
            existing_effective = existing_effective.replace(tzinfo=timezone.utc)
        else:
            existing_effective = existing_effective.astimezone(timezone.utc)
        if (
            existing.input_rate_per_million != configured_input
            or existing.output_rate_per_million != configured_output
            or existing_effective != settings.llm_pricing_effective_at
        ):
            raise RuntimeError("LLM pricing version is immutable; use a new LLM_PRICING_VERSION")
    return session.scalar(
        select(LLMPricingRate)
        .where(
            LLMPricingRate.provider == provider,
            LLMPricingRate.model == (settings.llm_model or "unknown"),
            LLMPricingRate.effective_from <= now,
        )
        .order_by(LLMPricingRate.effective_from.desc(), LLMPricingRate.id.desc())
        .limit(1)
    )


def _reserve_budget(
    session: Session,
    *,
    settings: Settings,
    run_id: str,
    provider_request: dict[str, Any],
    rate: LLMPricingRate | None,
    request_id: str | None,
    job_id: str | None,
    actor_id: str | None,
    task: str,
    prompt_version: str,
    advisory_id: str | None,
) -> tuple[Decimal | None, datetime | None]:
    run_limit = settings.llm_max_cost_per_run_usd
    month_limit = settings.llm_max_cost_per_month_usd
    if run_limit is None and month_limit is None:
        return None, None
    if session.bind is None or session.bind.dialect.name != "postgresql":
        raise RuntimeError("LLM spend ceilings require PostgreSQL")
    if rate is None:
        append_event(
            session,
            actor_type="service",
            actor_id=actor_id,
            action="llm_call_budget_denied",
            event_type="llm.budget.call_denied",
            outcome="blocked",
            resource_type="run",
            resource_id=run_id,
            request_id=request_id,
            job_id=job_id,
            run_id=run_id,
            advisory_id=advisory_id,
            prompt_version=prompt_version,
            safe_details={"task": task, "reason": "no_active_pricing_rate"},
        )
        return None, None

    input_bound = len(serialize_exchange(provider_request).encode("utf-8"))
    estimate = (
        Decimal(input_bound) * rate.input_rate_per_million
        + Decimal(settings.llm_max_output_tokens) * rate.output_rate_per_million
    ) / Decimal(1_000_000)
    estimate = estimate.quantize(Decimal("0.0000000001"), rounding=ROUND_CEILING)
    scopes = []
    if month_limit is not None:
        # Serialize period selection across month boundaries too. The lock is held
        # only through request persistence, before provider I/O begins.
        scopes.append(("month:global", None, month_limit, "month"))
    if run_limit is not None:
        scopes.append((f"run:{run_id}", None, run_limit, "run"))
    for lock_key, _, _, _ in sorted(scopes):
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:budget_scope, 0))"),
            {"budget_scope": lock_key},
        )

    # Capture the billing window only after acquiring the lock. Capturing it
    # before a wait lets a concurrent transaction omit reservations committed
    # while it was waiting.
    budget_checked_at = datetime.now(timezone.utc)
    month_start = budget_checked_at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    effective_cost = case(
        (LLMCall.cost_amount.is_(None), LLMCall.budget_estimate_usd),
        (LLMCall.budget_estimate_usd.is_(None), LLMCall.cost_amount),
        (LLMCall.cost_amount >= LLMCall.budget_estimate_usd, LLMCall.cost_amount),
        else_=LLMCall.budget_estimate_usd,
    )
    for _, _period_start, limit, scope in scopes:
        filters = [LLMCall.run_id == run_id] if scope == "run" else [
            LLMCall.started_at >= month_start,
        ]
        unknown_count = session.scalar(
            select(func.count(LLMCall.id)).where(
                *filters,
                LLMCall.cost_amount.is_(None),
                LLMCall.budget_estimate_usd.is_(None),
            )
        ) or 0
        used = session.scalar(select(func.sum(effective_cost)).where(*filters)) or Decimal(0)
        reason = "unknown_historical_cost" if unknown_count else (
            "limit_exceeded" if Decimal(used) + estimate > limit else None
        )
        if reason:
            append_event(
                session,
                actor_type="service",
                actor_id=actor_id,
                action="llm_call_budget_denied",
                event_type="llm.budget.call_denied",
                outcome="blocked",
                resource_type="run",
                resource_id=run_id,
                run_id=run_id,
                request_id=request_id,
                job_id=job_id,
                advisory_id=advisory_id,
                prompt_version=prompt_version,
                safe_details={
                    "scope": scope,
                    "task": task,
                    "prompt_version": prompt_version,
                    "reason": reason,
                    "limit_usd": format(limit, "f"),
                    "used_or_reserved_usd": format(Decimal(used), "f"),
                    "estimated_call_usd": format(estimate, "f"),
                },
            )
            return None, None
    return estimate, budget_checked_at
def prepare_attempt(
    session: Session,
    *,
    settings: Settings,
    run_id: str,
    job_id: str | None,
    task: str,
    model: str,
    prompt_version: str,
    request_id: str | None,
    actor_id: str | None,
    advisory_id: str | None,
    attempt_number: int,
    parent_call_id: str | None,
    exact_request: dict[str, Any],
) -> LLMCall | None:
    """Persist request + pending call. Caller MUST commit before provider dispatch."""
    request_json = serialize_exchange(exact_request)
    provider_request = exact_request.get("provider_request", exact_request)
    provider_request_json = serialize_exchange(provider_request)
    now = datetime.now(timezone.utc)
    rate = _pricing_rate(session, settings, now)
    budget_estimate, budget_checked_at = _reserve_budget(
        session,
        settings=settings,
        run_id=run_id,
        provider_request=provider_request,
        rate=rate,
        request_id=request_id,
        job_id=job_id,
        actor_id=actor_id,
        task=task,
        prompt_version=prompt_version,
        advisory_id=advisory_id,
    )
    if (
        settings.llm_max_cost_per_run_usd is not None
        or settings.llm_max_cost_per_month_usd is not None
    ) and budget_estimate is None:
        return None
    call_id = str(uuid4())
    record = LLMCall(
        id=call_id,
        request_id=request_id,
        job_id=job_id,
        run_id=run_id,
        actor_id=actor_id,
        advisory_id=advisory_id,
        parent_call_id=parent_call_id,
        task=task,
        provider=_provider_name(settings),
        model=model,
        prompt_version=prompt_version,
        prompt_hash=hashlib.sha256(provider_request_json.encode("utf-8")).hexdigest(),
        attempt_key=call_id,
        attempt_number=attempt_number,
        started_at=budget_checked_at or datetime.now(timezone.utc),
        outcome="pending",
        budget_estimate_usd=budget_estimate,
        pricing_version=rate.pricing_version if rate else None,
        pricing_effective_at=rate.effective_from if rate else None,
        input_rate_per_million=(
            rate.input_rate_per_million if rate else None
        ),
        output_rate_per_million=(
            rate.output_rate_per_million if rate else None
        ),
    )
    session.add(record)
    session.flush()
    store_artifact(
        session,
        call_id=record.id,
        kind="request",
        content=request_json,
        settings=settings,
    )
    append_event(
        session,
        actor_type="service",
        actor_id=actor_id,
        action="llm_request_persisted",
        event_type="llm.call.request_persisted",
        outcome="success",
        resource_type="llm_call",
        resource_id=record.id,
        request_id=request_id,
        run_id=run_id,
        advisory_id=advisory_id,
        llm_call_id=record.id,
        prompt_version=prompt_version,
        safe_details={
            "task": task,
            "provider": record.provider,
            "model": model,
            "attempt_number": attempt_number,
            "prompt_hash": record.prompt_hash,
        },
    )
    session.flush()
    return record


def _usage_value(usage: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _lock_pending_attempt(session: Session, attempt_id: str) -> LLMCall:
    record = session.scalar(
        select(LLMCall)
        .where(LLMCall.id == attempt_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if record is None:
        raise RuntimeError("LLM audit attempt disappeared")
    if record.outcome != "pending":
        raise RuntimeError("LLM attempt outcome was already finalized")
    return record


def mark_pending_attempts_unknown(session: Session, *, job_id: str) -> int:
    """Finalize attempts left pending when a prior worker attempt was interrupted."""
    now = datetime.now(timezone.utc)
    records = session.scalars(
        select(LLMCall)
        .where(LLMCall.job_id == job_id, LLMCall.outcome == "pending")
        .order_by(LLMCall.attempt_number, LLMCall.id)
        .with_for_update()
    ).all()
    for record in records:
        started_at = record.started_at
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        record.outcome = "unknown"
        record.safe_error_code = "worker_lost_during_llm_attempt"
        record.completed_at = now
        record.latency_ms = max(0, round((now - started_at).total_seconds() * 1000))
        append_event(
            session,
            actor_type="service",
            actor_id=record.actor_id,
            action="llm_attempt_abandoned",
            event_type="llm.call.outcome_unknown",
            outcome="unknown",
            resource_type="llm_call",
            resource_id=record.id,
            request_id=record.request_id,
            job_id=record.job_id,
            run_id=record.run_id,
            advisory_id=record.advisory_id,
            llm_call_id=record.id,
            prompt_version=record.prompt_version,
            safe_details={
                "task": record.task,
                "attempt_number": record.attempt_number,
                "reason": "worker_lease_recovered",
            },
        )
    session.flush()
    return len(records)


def complete_attempt(
    session: Session,
    record: LLMCall,
    *,
    settings: Settings,
    raw_response: str | bytes,
    usage: dict[str, Any] | None,
    response_id: str | None,
    latency_ms: int,
    parsed_output: str | None = None,
) -> None:
    """Persist the raw provider body and usage/cost status in caller transaction."""
    record = _lock_pending_attempt(session, record.id)
    usage = usage or {}
    store_artifact(
        session,
        call_id=record.id,
        kind="response",
        content=raw_response,
        settings=settings,
    )
    if parsed_output is not None:
        store_artifact(
            session,
            call_id=record.id,
            kind="parsed_output",
            content=parsed_output,
            settings=settings,
        )
    input_tokens = _usage_value(usage, "prompt_tokens", "input_tokens")
    output_tokens = _usage_value(usage, "completion_tokens", "output_tokens")
    total_tokens = _usage_value(usage, "total_tokens")
    record.input_tokens = input_tokens
    record.output_tokens = output_tokens
    record.total_tokens = (
        total_tokens
        if total_tokens is not None
        else input_tokens + output_tokens
        if input_tokens is not None and output_tokens is not None
        else None
    )
    record.token_source = (
        "provider"
        if input_tokens is not None and output_tokens is not None
        else "provider_partial"
        if input_tokens is not None or output_tokens is not None
        else None
    )
    record.cost_currency = "USD" if record.cost_amount is not None else None
    if (
        input_tokens is not None
        and output_tokens is not None
        and record.input_rate_per_million is not None
        and record.output_rate_per_million is not None
    ):
        record.cost_amount = (
            Decimal(input_tokens) * record.input_rate_per_million
            + Decimal(output_tokens) * record.output_rate_per_million
        ) / Decimal(1_000_000)
        record.cost_currency = "USD"
        record.cost_source = "provider_tokens_configured_rates"
    else:
        record.cost_amount = None
        record.cost_currency = None
        record.cost_source = None
    record.response_id = response_id[:160] if response_id else None
    record.completed_at = datetime.now(timezone.utc)
    record.latency_ms = max(0, latency_ms)
    record.outcome = "succeeded"
    session.flush()
    append_event(
        session,
        actor_type="service",
        actor_id=record.actor_id,
        action="llm_call_completed",
        event_type="llm.call.completed",
        outcome="success",
        resource_type="llm_call",
        resource_id=record.id,
        request_id=record.request_id,
        run_id=record.run_id,
        advisory_id=record.advisory_id,
        llm_call_id=record.id,
        prompt_version=record.prompt_version,
        safe_details={
            "task": record.task,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": record.total_tokens,
            "token_source": record.token_source,
            "cost_known": record.cost_amount is not None,
            "cost_currency": record.cost_currency,
            "latency_ms": record.latency_ms,
        },
    )
    session.flush()


def fail_attempt(
    session: Session,
    record: LLMCall,
    *,
    settings: Settings,
    error_code: str,
    safe_error: str,
    latency_ms: int,
    response_status: int | None = None,
    provider_secret: str | None = None,
    raw_response: str | bytes | None = None,
) -> None:
    """Persist sanitized provider failure details and a failed attempt outcome."""
    record = _lock_pending_attempt(session, record.id)
    if provider_secret:
        safe_error = safe_error.replace(provider_secret, "[REDACTED]")
    safe_body = redact(safe_error)[:8_000]
    if raw_response is not None:
        store_artifact(
            session,
            call_id=record.id,
            kind="response",
            content=raw_response,
            settings=settings,
        )
    error_payload = json.dumps(
        {"error_code": error_code[:100], "status": response_status, "body": safe_body},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    store_artifact(
        session,
        call_id=record.id,
        kind="provider_error",
        content=error_payload,
        settings=settings,
    )
    record.completed_at = datetime.now(timezone.utc)
    record.latency_ms = max(0, latency_ms)
    record.outcome = "failed"
    record.safe_error_code = error_code[:100]
    session.flush()
    append_event(
        session,
        actor_type="service",
        actor_id=record.actor_id,
        action="llm_call_failed",
        event_type="llm.call.failed",
        outcome="failure",
        resource_type="llm_call",
        resource_id=record.id,
        request_id=record.request_id,
        run_id=record.run_id,
        advisory_id=record.advisory_id,
        llm_call_id=record.id,
        prompt_version=record.prompt_version,
        safe_details={
            "task": record.task,
            "error_code": record.safe_error_code,
            "response_status": response_status,
            "latency_ms": record.latency_ms,
        },
    )
    session.flush()
