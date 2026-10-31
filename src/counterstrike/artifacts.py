"""Encrypted storage and audited access for exact LLM exchange content."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from counterstrike.audit import append_event
from counterstrike.config import Settings, load_settings
from counterstrike.db_models import LLMAuditAccess, LLMExchangeArtifact
from counterstrike.key_providers import get_encryption_key_provider


def _cipher(settings: Settings, version: str | None = None) -> tuple[AESGCM, str]:
    key_version = version or settings.llm_audit_encryption_key_version
    key = get_encryption_key_provider(settings).get_key(key_version)
    return AESGCM(key), key_version


def store_artifact(
    session: Session,
    *,
    call_id: str,
    kind: str,
    content: str | bytes,
    settings: Settings | None = None,
) -> LLMExchangeArtifact:
    """Encrypt request/response content before it is sent or considered stored."""
    settings = settings or load_settings()
    if not settings.llm_audit_content_capture:
        raise RuntimeError("LLM content capture is disabled")
    if settings.llm_audit_artifact_retention_days is None:
        raise RuntimeError("LLM artifact retention period is not configured")
    if kind not in {"request", "response", "parsed_output", "error", "provider_error"}:
        raise ValueError("Unsupported LLM artifact kind")
    cipher, key_version = _cipher(settings)
    raw = content if isinstance(content, bytes) else content.encode("utf-8")
    artifact_id = str(uuid4())
    nonce = secrets.token_bytes(12)
    aad = f"{artifact_id}:{call_id}:{kind}:{key_version}".encode()
    encrypted = nonce + cipher.encrypt(nonce, raw, aad)
    artifact = LLMExchangeArtifact(
        id=artifact_id,
        llm_call_id=call_id,
        artifact_kind=kind,
        encrypted_payload=encrypted,
        plaintext_hash=hashlib.sha256(raw).hexdigest(),
        encryption_key_version=key_version,
        payload_bytes=len(raw),
        retention_expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.llm_audit_artifact_retention_days),
    )
    session.add(artifact)
    session.flush()
    return artifact


def read_artifact(
    session: Session,
    artifact: LLMExchangeArtifact,
    *,
    actor_id: str,
    request_id: str | None,
    purpose: str,
    authorized: bool,
    settings: Settings | None = None,
) -> tuple[str | None, str]:
    """Record every access attempt; caller commits even for denied/corrupt reads."""
    settings = settings or load_settings()
    outcome = "denied"
    content: str | None = None
    now = datetime.now(timezone.utc)
    expires_at = artifact.retention_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    bounded_purpose = purpose.strip()[:500]
    if authorized and (not bounded_purpose or len(purpose) > 500):
        outcome = "denied"
    elif authorized and (artifact.purged_at is not None or not artifact.encrypted_payload):
        outcome = "purged"
    elif authorized and expires_at <= now:
        outcome = "expired"
    elif authorized:
        try:
            cipher, _ = _cipher(settings, artifact.encryption_key_version)
            nonce, ciphertext = artifact.encrypted_payload[:12], artifact.encrypted_payload[12:]
            aad = (
                f"{artifact.id}:{artifact.llm_call_id}:{artifact.artifact_kind}:"
                f"{artifact.encryption_key_version}"
            ).encode()
            raw = cipher.decrypt(nonce, ciphertext, aad)
            if hashlib.sha256(raw).hexdigest() != artifact.plaintext_hash:
                raise InvalidTag
            content = raw.decode("utf-8")
            outcome = "success"
        except RuntimeError:
            outcome = "key_unavailable"
        except (InvalidTag, UnicodeDecodeError, ValueError):
            outcome = "integrity_failure"
    session.add(LLMAuditAccess(
        id=str(uuid4()), llm_call_id=artifact.llm_call_id, artifact_id=artifact.id,
        actor_id=actor_id, request_id=request_id, purpose=bounded_purpose or "missing purpose",
        action="read", outcome=outcome,
    ))
    append_event(
        session, actor_type="user", actor_id=actor_id, action="llm_artifact_read",
        event_type="llm.audit.content_access", outcome=outcome,
        resource_type="llm_exchange_artifact", resource_id=artifact.id,
        request_id=request_id, llm_call_id=artifact.llm_call_id,
        safe_details={"artifact_kind": artifact.artifact_kind},
    )
    session.flush()
    return content, outcome


def purge_expired_artifacts(
    session: Session,
    *,
    actor_id: str,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
    """Erase expired ciphertext while retaining immutable metadata and chained purge events."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    artifacts = session.scalars(
        select(LLMExchangeArtifact)
        .where(
            LLMExchangeArtifact.retention_expires_at <= now,
            LLMExchangeArtifact.purged_at.is_(None),
            LLMExchangeArtifact.encrypted_payload != b"",
        )
        .order_by(LLMExchangeArtifact.retention_expires_at, LLMExchangeArtifact.id)
        .limit(max(1, min(limit, 500)))
        .with_for_update(skip_locked=True)
    ).all()
    for artifact in artifacts:
        artifact.encrypted_payload = b""
        artifact.purged_at = now
        append_event(
            session,
            actor_type="service",
            actor_id=actor_id,
            action="llm_artifact_purged",
            event_type="llm.audit.artifact_purged",
            outcome="success",
            resource_type="llm_exchange_artifact",
            resource_id=artifact.id,
            llm_call_id=artifact.llm_call_id,
            safe_details={
                "artifact_kind": artifact.artifact_kind,
                "plaintext_hash": artifact.plaintext_hash,
                "payload_bytes": artifact.payload_bytes,
                "retention_expires_at": _timestamp(artifact.retention_expires_at),
            },
        )
    session.flush()
    return len(artifacts)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def serialize_exchange(value: object) -> str:
    """Stable JSON representation used for the exact captured exchange payload."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
