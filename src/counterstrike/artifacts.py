"""Encrypted storage and audited access for exact LLM exchange content."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from counterstrike.audit import append_event
from counterstrike.config import Settings, load_settings
from counterstrike.db_models import LLMAuditAccess, LLMExchangeArtifact


def _cipher(settings: Settings) -> tuple[AESGCM, str]:
    configured = settings.llm_audit_encryption_key
    if configured is None:
        raise RuntimeError("LLM audit encryption key is not configured")
    try:
        key = base64.b64decode(
            configured.get_secret_value().encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("LLM audit encryption key must be URL-safe base64") from exc
    if len(key) != 32:
        raise RuntimeError("LLM audit encryption key must decode to 32 bytes")
    return AESGCM(key), settings.llm_audit_encryption_key_version


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
    import secrets

    nonce = secrets.token_bytes(12)
    aad = f"{artifact_id}:{call_id}:{kind}:{key_version}".encode("utf-8")
    encrypted = nonce + cipher.encrypt(nonce, raw, aad)
    artifact = LLMExchangeArtifact(
        id=artifact_id,
        llm_call_id=call_id,
        artifact_kind=kind,
        encrypted_payload=encrypted,
        plaintext_hash=hashlib.sha256(raw).hexdigest(),
        encryption_key_version=key_version,
        payload_bytes=len(raw),
        retention_expires_at=datetime.now(timezone.utc) + timedelta(days=settings.llm_audit_artifact_retention_days),
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
    elif authorized and expires_at <= now:
        outcome = "expired"
    elif authorized:
        try:
            cipher, active_version = _cipher(settings)
            if active_version != artifact.encryption_key_version:
                raise RuntimeError("Artifact key version unavailable")
            nonce, ciphertext = artifact.encrypted_payload[:12], artifact.encrypted_payload[12:]
            aad = f"{artifact.id}:{artifact.llm_call_id}:{artifact.artifact_kind}:{artifact.encryption_key_version}".encode()
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


def serialize_exchange(value: object) -> str:
    """Stable JSON representation used for the exact captured exchange payload."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
