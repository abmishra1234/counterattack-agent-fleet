"""Transactional persistence operations for analysis runs and their outputs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from counterstrike.audit import append_event
from counterstrike.config import Settings, load_settings
from counterstrike.db_models import (
    AdvisoryEnrichment,
    AdvisoryRecord,
    AlertRecord,
    InventoryAsset,
    InventorySnapshot,
    MatchRecord,
    OutboxMessage,
    ReviewCase,
    RunRecord,
    Source,
    SourceCheckpoint,
)
from counterstrike.models import FleetState
from counterstrike.risk_policy import POLICY_VERSION


def _json(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _persist_source_syncs(session: Session, run_id: str, state: FleetState) -> None:
    """Persist public-source checkpoints and outcomes with the owning run transaction."""
    for sync in state.get("source_syncs", []):
        source_id = sync.get("source_id")
        status = sync.get("status")
        if not isinstance(source_id, str) or not source_id or len(source_id) > 40:
            raise ValueError("invalid_source_sync_id")
        if status not in {"success", "partial", "failure", "skipped"}:
            raise ValueError("invalid_source_sync_status")
        cursor = sync.get("next_cursor")
        if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 2_000_000):
            raise ValueError("invalid_source_sync_cursor")

        source_name = f"public:{source_id}"
        source = session.scalar(select(Source).where(Source.name == source_name))
        if source is None:
            source = Source(
                name=source_name,
                source_type="public_feed",
                safe_configuration={"adapter": source_id},
            )
            session.add(source)
            session.flush()

        checkpoint = session.scalar(
            select(SourceCheckpoint).where(SourceCheckpoint.source_id == source.id)
        )
        if checkpoint is None:
            checkpoint = SourceCheckpoint(source_id=source.id)
            session.add(checkpoint)
        now = datetime.now(timezone.utc)
        checkpoint.last_attempt_at = now
        checkpoint.last_status = status
        error_code = sync.get("error_code")
        checkpoint.last_error_code = (
            str(error_code)[:80]
            if status != "success" and isinstance(error_code, str) and error_code
            else None
        )
        if status in {"success", "partial"} or cursor is not None:
            checkpoint.cursor = cursor
        if status == "success":
            checkpoint.modified_after = _date(sync.get("fetched_at"))
            checkpoint.last_success_at = now
            checkpoint.failure_count = 0
        elif status == "failure":
            checkpoint.failure_count += 1

        append_event(
            session,
            actor_type="service",
            action=f"source_poll_{status}",
            event_type=f"source.poll.{status}",
            outcome="success" if status == "success" else status,
            resource_type="source",
            resource_id=source.id,
            request_id=session.get(RunRecord, run_id).request_id,
            run_id=run_id,
            safe_details={
                "source_id": source_id,
                "record_count": max(0, int(sync.get("record_count", 0))),
                **(
                    {"catalog_version": str(sync["catalog_version"])[:80]}
                    if isinstance(sync.get("catalog_version"), str)
                    else {}
                ),
                **(
                    {"error_code": checkpoint.last_error_code}
                    if checkpoint.last_error_code
                    else {}
                ),
            },
        )


def create_run(
    session: Session,
    *,
    trigger_type: str,
    actor_id: str | None,
    request_id: str | None,
    run_id: str | None = None,
) -> RunRecord:
    """Create a queued run and its audit event in the caller's transaction."""
    record = RunRecord(
        id=run_id or str(uuid4()),
        trigger_type=trigger_type,
        status="queued",
        triggered_by=actor_id,
        request_id=request_id,
    )
    session.add(record)
    session.flush()
    append_event(
        session,
        actor_type="user" if actor_id else "service",
        actor_id=actor_id,
        action="run_queued",
        event_type="run.lifecycle.queued",
        outcome="success",
        resource_type="run",
        resource_id=record.id,
        request_id=request_id,
        run_id=record.id,
        safe_details={"trigger_type": trigger_type},
    )
    return record


def load_source_cursors(session: Session) -> dict[str, str | None]:
    """Load the last committed public-feed cursor for the next run attempt."""
    rows = session.execute(
        select(Source.name, SourceCheckpoint.cursor)
        .join(SourceCheckpoint, SourceCheckpoint.source_id == Source.id)
        .where(Source.name.like("public:%"))
    ).all()
    return {name.removeprefix("public:"): cursor for name, cursor in rows}


def mark_run_started(session: Session, run_id: str) -> RunRecord:
    """Move a queued run to running and append the same-transaction audit event."""
    record = session.get(RunRecord, run_id)
    if record is None:
        raise LookupError("run_not_found")
    if record.status != "queued":
        raise ValueError("run_not_queued")
    record.status = "running"
    record.started_at = datetime.now(timezone.utc)
    session.flush()
    append_event(
        session,
        actor_type="service",
        action="run_started",
        event_type="run.lifecycle.started",
        outcome="success",
        resource_type="run",
        resource_id=record.id,
        request_id=record.request_id,
        run_id=record.id,
    )
    return record


def persist_run_results(
    session: Session,
    run_id: str,
    state: FleetState,
    *,
    policy_version: str | None = None,
    settings: Settings | None = None,
) -> RunRecord:
    """Persist a complete graph result atomically with run completion.

    The caller owns the transaction. Any exception leaves no partial output once
    the surrounding transaction rolls back.
    """
    settings = settings or load_settings()
    policy_version = policy_version or next(
        (
            str(item["policy_version"])
            for item in state.get("trace", [])
            if item.get("agent") == "score" and item.get("policy_version")
        ),
        POLICY_VERSION,
    )
    run = session.get(RunRecord, run_id)
    if run is None:
        raise LookupError("run_not_found")
    if run.status != "running":
        raise ValueError("run_not_running")

    _persist_source_syncs(session, run_id, state)
    advisories = state.get("advisories", [])
    inventory = state.get("inventory", [])
    extracted = {item.advisory_id: item for item in state.get("extracted", [])}
    kev_ids = set(state.get("kev", []))

    source_records: dict[str, Source] = {}
    public_source_ids = {
        item.get("source_id")
        for item in state.get("source_syncs", [])
        if isinstance(item, dict) and isinstance(item.get("source_id"), str)
    }
    for advisory in advisories:
        if advisory.source not in source_records:
            is_public = advisory.source in public_source_ids
            name = f"{'public' if is_public else 'fixture'}:{advisory.source}"
            source = session.scalar(select(Source).where(Source.name == name))
            if source is None:
                source = Source(
                    name=name,
                    source_type="public_feed" if is_public else "fixture",
                    safe_configuration={"feed": advisory.source},
                )
                session.add(source)
                session.flush()
            source_records[advisory.source] = source

    advisory_records: dict[str, AdvisoryRecord] = {}
    for advisory in advisories:
        source = source_records[advisory.source]
        payload = _json(advisory)
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        content_hash = hashlib.sha256(encoded).hexdigest()
        record = session.scalar(
            select(AdvisoryRecord).where(
                AdvisoryRecord.source_id == source.id,
                AdvisoryRecord.external_id == advisory.id,
            )
        )
        enriched = extracted.get(advisory.id)
        kev_value = (
            enriched.in_kev
            if enriched is not None
            else (advisory.id in kev_ids) if state.get("kev_complete", True) else None
        )
        normalized_payload = {
            **payload,
            "in_kev": kev_value,
            "kev_status": (
                "listed" if kev_value is True else "not_listed" if kev_value is False else "unknown"
            ),
            "extraction": _json(enriched) if enriched else None,
        }
        if record is None:
            record = AdvisoryRecord(
                source_id=source.id,
                external_id=advisory.id,
                canonical_id=advisory.id,
                title=advisory.title[:500],
                published_at=_date(advisory.published),
                cvss=Decimal(str(advisory.cvss)) if advisory.cvss is not None else None,
                source_url=advisory.source_url,
                source_references=advisory.source_references or [],
                content_hash=content_hash,
                raw_payload_hash=content_hash,
                normalized_payload=normalized_payload,
            )
            session.add(record)
            session.flush()
        # Existing advisory rows are immutable here. A changed feed version needs
        # a dedicated advisory-version schema before it may replace stored content.
        advisory_records[advisory.id] = record

    # Keep source-derived enrichment separate from the immutable advisory payload.
    # This permits each observation to retain its provenance and capture time.
    enrichment_sources: dict[str, Source] = {}
    for item in state.get("source_enrichments", []):
        if not isinstance(item, dict):
            continue
        advisory_id = item.get("advisory_id")
        source_id = item.get("source_id")
        kind = item.get("kind")
        value = item.get("value")
        if (
            not isinstance(advisory_id, str)
            or not isinstance(source_id, str)
            or not isinstance(kind, str)
            or not isinstance(value, dict)
            or len(kind) > 40
            or len(json.dumps(value, ensure_ascii=False)) > 100_000
        ):
            continue
        advisory_record = advisory_records.get(advisory_id)
        if advisory_record is None:
            continue
        source = enrichment_sources.get(source_id)
        if source is None:
            source = session.scalar(
                select(Source).where(Source.name == f"public:{source_id}")
            )
            if source is None:
                continue
            enrichment_sources[source_id] = source
        observed_at = _date(item.get("observed_at"))
        enrichment = AdvisoryEnrichment(
            advisory_id=advisory_record.id,
            kind=kind,
            value=value,
            source_id=source.id,
            observed_at=observed_at or datetime.now(timezone.utc),
            source_url=item.get("source_url") if isinstance(item.get("source_url"), str) else None,
        )
        session.add(enrichment)

    inventory_payload = [_json(asset) for asset in inventory]
    inventory_bytes = json.dumps(
        inventory_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    snapshot = InventorySnapshot(
        source_name="run-input",
        content_hash=hashlib.sha256(inventory_bytes).hexdigest(),
        record_count=len(inventory),
    )
    session.add(snapshot)
    session.flush()
    run.inventory_snapshot_id = snapshot.id

    assets_by_key: dict[str, InventoryAsset] = {}
    for asset in inventory:
        criticality = getattr(asset.criticality, "value", asset.criticality)
        row = InventoryAsset(
            snapshot_id=snapshot.id,
            asset_key=asset.asset_id,
            service=asset.service,
            component=asset.component,
            version=asset.version,
            vendor=asset.vendor,
            owner=asset.owner,
            owner_contact=asset.owner_contact,
            criticality=str(criticality),
            internet_facing=asset.internet_facing,
            data_classification=asset.data_classification,
            extra_context={
                "product": asset.inventory_product,
                "asset_type": asset.asset_type,
                "aliases": asset.aliases,
            },
        )
        session.add(row)
        assets_by_key[asset.asset_id] = row
    session.flush()

    matches_by_pair: dict[tuple[str, str], MatchRecord] = {}
    for match in state.get("matches", []):
        advisory = advisory_records.get(match.advisory_id)
        asset = assets_by_key.get(match.asset_id)
        if advisory is None or asset is None:
            raise ValueError("run_result_reference_missing")
        row = MatchRecord(
            run_id=run.id,
            advisory_id=advisory.id,
            inventory_asset_id=asset.id,
            outcome=match.outcome,
            confidence=match.confidence,
            explanation={
                **({"version_note": match.version_note} if match.version_note else {}),
                **(
                    {"confidence_scope": "deterministic_version_comparison"}
                    if match.confidence is not None
                    else {}
                ),
            },
            affected_range=match.affected,
            comparator=match.comparator,
            evidence=match.evidence,
        )
        session.add(row)
        matches_by_pair[(match.advisory_id, match.asset_id)] = row
    session.flush()

    score_details = {(item.advisory_id, item.asset_id): item for item in state.get("scored", [])}
    for alert in state.get("alerts", []):
        pair = (alert.cve_id, alert.asset_id)
        match_row = matches_by_pair.get(pair)
        if match_row is None:
            raise ValueError("alert_match_reference_missing")
        advisory = advisory_records.get(alert.cve_id)
        scored_match = score_details.get(pair)
        row = AlertRecord(
            # The graph's alert ID is a deterministic finding key and can recur
            # in later runs. Persist a new row ID per run while retaining that
            # stable value as alert_key.
            id=str(uuid4()),
            run_id=run.id,
            match_id=match_row.id,
            alert_key=alert.alert_id,
            cve_id=alert.cve_id,
            asset_key=alert.asset_id,
            service=alert.service,
            component=alert.component,
            installed_version=alert.installed_version,
            fixed_version=alert.fixed_version,
            priority=str(getattr(alert.priority, "value", alert.priority)),
            risk_score=Decimal(str(alert.risk_score)),
            score_breakdown=scored_match.score_breakdown if scored_match else {},
            policy_version=policy_version,
            sla_hours=alert.sla_hours,
            owner=alert.owner,
            summary=alert.summary,
            remediation=alert.remediation,
            evidence=alert.evidence,
            source_references=(
                [*advisory.source_references, {"advisory_id": advisory.external_id}]
                if advisory
                else []
            ),
        )
        session.add(row)
        session.flush()
        if settings.outbox_enqueue_enabled:
            _enqueue_alert_delivery(session, run=run, alert=row, settings=settings)

    seen_reviews: set[tuple[str, str]] = set()
    for item in state.get("needs_human", []):
        advisory = advisory_records.get(item.advisory_id)
        if advisory is None:
            continue
        key = (item.advisory_id, item.stage)
        if key in seen_reviews:
            continue
        seen_reviews.add(key)
        session.add(ReviewCase(
            run_id=run.id,
            advisory_id=advisory.id,
            stage=item.stage,
            reason=item.reason,
        ))

    alert_count = len(state.get("alerts", []))
    review_count = len(state.get("needs_human", []))
    run.summary = {
        "advisories_ingested": len(advisories),
        "advisories_extracted": len(state.get("extracted", [])),
        "matches": len(state.get("matches", [])),
        "alerts": alert_count,
        "needs_human": review_count,
        "extracted": [_json(item) for item in state.get("extracted", [])],
        "trace": state.get("trace", []),
    }
    run.policy_version = policy_version
    run.prompt_versions = {
        str(item.get("agent")): str(item.get("prompt_version"))
        for item in state.get("trace", [])
        if item.get("prompt_version")
    }
    run.status = "succeeded"
    run.completed_at = datetime.now(timezone.utc)
    session.flush()
    append_event(
        session,
        actor_type="service",
        action="run_completed",
        event_type="run.lifecycle.completed",
        outcome="success",
        resource_type="run",
        resource_id=run.id,
        request_id=run.request_id,
        run_id=run.id,
        safe_details={"alerts": alert_count, "needs_human": review_count},
        policy_version=policy_version,
    )
    return run


def _enqueue_alert_delivery(
    session: Session,
    *,
    run: RunRecord,
    alert: AlertRecord,
    settings: Settings,
) -> None:
    """Persist one stable delivery intent in the run-results transaction."""
    channel = settings.outbox_channel
    owner_recipient_ref = settings.outbox_recipient_refs.get(alert.owner)
    if channel is None or owner_recipient_ref is None:
        raise ValueError("delivery_recipient_not_configured")
    payload = {
        "run_id": run.id,
        "alert_id": alert.id,
        "alert_key": alert.alert_key,
        "cve_id": alert.cve_id,
        "asset_key": alert.asset_key,
        "service": alert.service,
        "component": alert.component,
        "installed_version": alert.installed_version,
        "fixed_version": alert.fixed_version,
        "priority": alert.priority,
        "risk_score": format(Decimal(str(alert.risk_score)).quantize(Decimal("0.001")), "f"),
        "sla_hours": alert.sla_hours,
        "owner": alert.owner,
        "summary": alert.summary,
        "remediation": alert.remediation,
        "evidence": alert.evidence,
        "source_references": alert.source_references,
    }
    dialect = session.bind.dialect.name if session.bind is not None else ""
    insert = (
        postgresql_insert
        if dialect == "postgresql"
        else sqlite_insert
        if dialect == "sqlite"
        else None
    )
    if insert is None:
        raise RuntimeError("Delivery outbox requires PostgreSQL or SQLite")
    targets = [("owner", owner_recipient_ref)]
    if alert.priority in {"P1", "P2"}:
        security_recipient_ref = settings.outbox_security_recipient_ref
        if not security_recipient_ref:
            raise ValueError("security_recipient_not_configured_for_priority_alert")
        security_recipient = security_recipient_ref.get_secret_value()
        if channel == "email" and security_recipient == owner_recipient_ref:
            targets[0] = ("owner_security", owner_recipient_ref)
        else:
            targets.append(("security", security_recipient))
    for route, recipient_ref in targets:
        routed_payload = {**payload, "delivery_route": route}
        routed_hash = hashlib.sha256(
            json.dumps(
                routed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        identity = f"{run.id}:{alert.alert_key}:{channel}:{route}:{recipient_ref}".encode()
        idempotency_key = hashlib.sha256(identity).hexdigest()
        proposed_outbox_id = str(uuid4())
        result = session.execute(
            insert(OutboxMessage)
            .values(
                id=proposed_outbox_id,
                run_id=run.id,
                alert_id=alert.id,
                channel=channel,
                recipient_ref=recipient_ref,
                idempotency_key=idempotency_key,
                payload=routed_payload,
                payload_hash=routed_hash,
                status="queued",
                attempt=0,
            )
            .on_conflict_do_nothing(index_elements=[OutboxMessage.idempotency_key])
            .returning(OutboxMessage.id)
        )
        outbox_id = result.scalar_one_or_none()
        if outbox_id is not None:
            append_event(
                session,
                actor_type="service",
                actor_id="delivery-outbox",
                action="delivery_enqueued",
                event_type="delivery.outbox.enqueued",
                outcome="success",
                resource_type="outbox_message",
                resource_id=outbox_id,
                request_id=run.request_id,
                run_id=run.id,
                alert_id=alert.id,
                safe_details={
                    "channel": channel,
                    "route": route,
                    "idempotency_key": idempotency_key,
                    "payload_hash": routed_hash,
                    "recipient_hash": hashlib.sha256(recipient_ref.encode("utf-8")).hexdigest()[
                        :16
                    ],
                },
            )
