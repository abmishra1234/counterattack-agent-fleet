"""Transactional persistence operations for analysis runs and their outputs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from counterstrike.audit import append_event
from counterstrike.db_models import (
    AdvisoryRecord,
    AlertRecord,
    InventoryAsset,
    InventorySnapshot,
    MatchRecord,
    ReviewCase,
    RunRecord,
    Source,
)
from counterstrike.models import FleetState


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
    policy_version: str = "risk-v1",
) -> RunRecord:
    """Persist a complete graph result atomically with run completion.

    The caller owns the transaction. Any exception leaves no partial output once
    the surrounding transaction rolls back.
    """
    run = session.get(RunRecord, run_id)
    if run is None:
        raise LookupError("run_not_found")
    if run.status != "running":
        raise ValueError("run_not_running")

    advisories = state.get("advisories", [])
    inventory = state.get("inventory", [])
    extracted = {item.advisory_id: item for item in state.get("extracted", [])}
    kev_ids = set(state.get("kev", []))

    source_records: dict[str, Source] = {}
    for advisory in advisories:
        if advisory.source not in source_records:
            name = f"fixture:{advisory.source}"
            source = session.scalar(select(Source).where(Source.name == name))
            if source is None:
                source = Source(name=name, source_type="fixture", safe_configuration={"feed": advisory.source})
                session.add(source)
                session.flush()
            source_records[advisory.source] = source

    advisory_records: dict[str, AdvisoryRecord] = {}
    for advisory in advisories:
        source = source_records[advisory.source]
        payload = _json(advisory)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        content_hash = hashlib.sha256(encoded).hexdigest()
        record = session.scalar(
            select(AdvisoryRecord).where(
                AdvisoryRecord.source_id == source.id,
                AdvisoryRecord.external_id == advisory.id,
            )
        )
        enriched = extracted.get(advisory.id)
        normalized_payload = {
            **payload,
            "in_kev": advisory.id in kev_ids,
            "extraction": _json(enriched) if enriched else None,
        }
        if record is None:
            record = AdvisoryRecord(
                source_id=source.id,
                external_id=advisory.id,
                canonical_id=advisory.id,
                title=advisory.title[:500],
                published_at=_date(advisory.published),
                cvss=Decimal(str(advisory.cvss)),
                source_url=None,
                source_references=[],
                content_hash=content_hash,
                raw_payload_hash=content_hash,
                normalized_payload=normalized_payload,
            )
            session.add(record)
            session.flush()
        # Existing advisory rows are immutable here. A changed feed version needs
        # a dedicated advisory-version schema before it may replace stored content.
        advisory_records[advisory.id] = record

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
            owner=asset.owner,
            criticality=str(criticality),
            internet_facing=asset.internet_facing,
            extra_context={},
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
            outcome="affected",
            explanation={"version_note": match.version_note} if match.version_note else {},
            affected_range=match.affected,
            comparator="pep440",
            evidence=[],
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
            id=alert.alert_id,
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
            source_references=[
                {"advisory_id": advisory.external_id}
            ] if advisory else [],
        )
        session.add(row)

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
