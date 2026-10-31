"""Versioned encryption key-provider boundary for LLM audit artifacts.

The local provider reads one active key from process configuration. Deployments can
replace the provider implementation with a managed KMS adapter without changing the
artifact storage or access paths.
"""

from __future__ import annotations

import base64
from typing import Protocol

from counterstrike.config import Settings


class EncryptionKeyProvider(Protocol):
    """Resolve encryption keys by immutable key version identifier."""

    def get_key(self, version: str) -> bytes:
        """Return the raw key for ``version`` or raise when it is unavailable."""


class LocalEnvironmentKeyProvider:
    """Resolve the single active AES-256 key supplied by local environment settings."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get_key(self, version: str) -> bytes:
        if version != self._settings.llm_audit_encryption_key_version:
            raise RuntimeError("Artifact key version unavailable")
        configured = self._settings.llm_audit_encryption_key
        if configured is None:
            raise RuntimeError("LLM audit encryption key is not configured")
        try:
            key = base64.b64decode(
                configured.get_secret_value().encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("LLM audit encryption key must be URL-safe base64") from exc
        if len(key) != 32:
            raise RuntimeError("LLM audit encryption key must decode to 32 bytes")
        return key


def get_encryption_key_provider(settings: Settings) -> EncryptionKeyProvider:
    """Return the configured local provider; hosted providers plug in at this seam."""
    return LocalEnvironmentKeyProvider(settings)
