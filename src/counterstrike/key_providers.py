"""Versioned encryption key-provider boundary for LLM audit artifacts.

The local provider reads retained keys by immutable version from process configuration,
with a legacy single-key fallback for the active version. Deployments can replace the
provider with a managed KMS adapter without changing artifact storage or access paths.
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
    """Resolve versioned AES-256 keys from the local environment."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get_key(self, version: str) -> bytes:
        configured_keys = self._settings.llm_audit_encryption_keys
        encoded = configured_keys.get(version)
        if encoded is None and version == self._settings.llm_audit_encryption_key_version:
            configured = self._settings.llm_audit_encryption_key
            encoded = configured.get_secret_value() if configured is not None else None
        if encoded is None:
            raise RuntimeError("LLM audit encryption key is not configured")
        try:
            key = base64.b64decode(
                encoded.encode("ascii"),
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
