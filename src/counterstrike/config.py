"""Validated process configuration and local .env loading.

The committed example file contains placeholders only. Environment variables override local .env
values so deployment secret stores remain authoritative.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

_MODULE_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = _MODULE_ROOT if (_MODULE_ROOT / "pyproject.toml").is_file() else Path.cwd()
DOTENV_PATH = PROJECT_ROOT / ".env"


def _dotenv_value(raw: str) -> str:
    """Parse the simple single-line KEY=value subset used by this project's .env file."""
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        if end < 0:
            raise ValueError("Unterminated quoted value in .env")
        trailing = value[end + 1 :].strip()
        if trailing and not trailing.startswith("#"):
            raise ValueError("Unexpected text after quoted .env value")
        return value[1:end]
    return value.split("#", 1)[0].strip()


def read_dotenv(path: Path = DOTENV_PATH) -> dict[str, str]:
    """Read a local dotenv file without changing process environment or exposing its values."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"Invalid .env assignment on line {line_number}")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            raise ValueError(f"Invalid .env key on line {line_number}")
        values[key] = _dotenv_value(raw_value)
    return values


def _as_bool(value: str | bool, name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{name} must be true or false")


def _decode_llm_audit_key(encoded_key: str, setting_name: str) -> bytes:
    try:
        decoded = base64.b64decode(encoded_key.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{setting_name} must contain URL-safe base64 keys") from exc
    if len(decoded) != 32:
        raise ValueError(f"{setting_name} keys must decode to 32 bytes")
    return decoded


def _is_mailbox_address(value: str) -> bool:
    if (
        len(value) > 254
        or any(char.isspace() for char in value)
        or "\r" in value
        or "\n" in value
    ):
        return False
    if value.count("@") != 1:
        return False
    local, domain = value.split("@", 1)
    return bool(
        local
        and domain
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


class Settings(BaseModel):
    """Validated settings used by the API and worker processes."""

    model_config = ConfigDict(extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_trusted_local_client_cidrs: str = Field(default="", max_length=512)
    metrics_enabled: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    local_dev_identity: str = Field(default="local-development", min_length=1, max_length=200)
    local_dev_role: Literal[
        "viewer", "analyst", "operator", "audit_reader", "llm_audit_reader", "admin"
    ] = (
        "operator"
    )
    frontend_dir: Path = PROJECT_ROOT / "frontend"
    data_dir: Path = PROJECT_ROOT / "data"
    out_dir: Path = PROJECT_ROOT / "out"
    database_url: SecretStr | None = None

    outbox_enqueue_enabled: bool = False
    outbox_channel: Literal["email", "teams"] | None = None
    outbox_recipient_map_json: SecretStr | None = None
    outbox_security_recipient_ref: SecretStr | None = None
    outbox_delivery_enabled: bool = False
    outbox_delivery_max_attempts: int = Field(default=3, ge=1, le=10)
    outbox_delivery_lease_seconds: int = Field(default=90, ge=15, le=3600)
    outbox_delivery_timeout_seconds: float = Field(default=10, gt=0, le=120)
    outbox_teams_webhook_url: SecretStr | None = None
    outbox_teams_security_webhook_url: SecretStr | None = None
    outbox_smtp_host: str | None = Field(default=None, max_length=255)
    outbox_smtp_port: int = Field(default=587, ge=1, le=65535)
    outbox_smtp_username: SecretStr | None = None
    outbox_smtp_password: SecretStr | None = None
    outbox_smtp_from: str | None = Field(default=None, max_length=254)
    outbox_smtp_starttls: bool = True
    outbox_daily_digest_enabled: bool = False
    outbox_daily_digest_hour_utc: int = Field(default=9, ge=0, le=23)
    outbox_daily_digest_minute_utc: int = Field(default=0, ge=0, le=59)
    outbox_daily_digest_max_items: int = Field(default=100, ge=1, le=500)

    public_feeds_enabled: bool = False
    public_feeds_approved: bool = False
    epss_enabled: bool = False
    epss_approved: bool = False
    epss_scoring_approved: bool = False
    epss_risk_weight: Decimal | None = Field(
        default=None, gt=0, le=10, max_digits=6, decimal_places=3
    )
    epss_max_age_days: int | None = Field(default=None, ge=1, le=365)
    public_feed_scheduler_enabled: bool = False
    public_feed_poll_interval_minutes: int = Field(default=15, ge=1, le=1440)
    nvd_api_key: SecretStr | None = None
    public_feed_timeout_seconds: float = Field(default=20, gt=0, le=120)

    llm_provider: Literal["fake", "openai_compatible", "azure_openai"] = "fake"
    llm_live_calls_enabled: bool = False
    llm_data_boundary_approved: bool = False
    llm_artifact_retention_approved: bool = False
    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None
    llm_timeout_seconds: float = Field(default=30, gt=0, le=300)
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    llm_max_output_tokens: int = Field(default=1200, ge=1, le=100_000)
    llm_max_response_bytes: int = Field(default=2_097_152, ge=1024, le=67_108_864)
    llm_extraction_enabled: bool = True
    llm_summary_enabled: bool = True
    llm_audit_content_capture: bool = False
    llm_audit_encryption_key: SecretStr | None = None
    llm_audit_encryption_keyring_json: SecretStr | None = Field(default=None, max_length=16_384)
    llm_audit_encryption_key_version: str = Field(default="local-v1", min_length=1, max_length=100)
    llm_audit_artifact_retention_days: int | None = Field(default=None, ge=1, le=3650)
    llm_input_price_usd_per_1m: Decimal | None = Field(default=None, ge=0)
    llm_output_price_usd_per_1m: Decimal | None = Field(default=None, ge=0)
    llm_pricing_version: str = "environment-rates-v1"
    llm_pricing_effective_at: datetime = datetime(2000, 1, 1, tzinfo=timezone.utc)
    llm_max_cost_per_run_usd: Decimal | None = Field(default=None, gt=0)
    llm_max_cost_per_month_usd: Decimal | None = Field(default=None, gt=0)

    @field_validator("api_host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("API_HOST cannot be empty")
        return value

    @field_validator("api_trusted_local_client_cidrs")
    @classmethod
    def validate_trusted_client_cidrs(cls, value: str) -> str:
        networks = [part.strip() for part in value.split(",") if part.strip()]
        try:
            parsed = [ipaddress.ip_network(network, strict=False) for network in networks]
        except ValueError as exc:
            raise ValueError("API_TRUSTED_LOCAL_CLIENT_CIDRS must contain valid CIDRs") from exc
        if len(parsed) > 16:
            raise ValueError("API_TRUSTED_LOCAL_CLIENT_CIDRS may contain at most 16 networks")
        for network in parsed:
            minimum_prefix = 16 if network.version == 4 else 48
            if not network.is_private or network.prefixlen < minimum_prefix:
                raise ValueError("Trusted local CIDRs must be bounded private networks")
        return ",".join(str(network) for network in parsed)

    @field_validator("local_dev_identity")
    @classmethod
    def validate_local_identity(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("LOCAL_DEV_IDENTITY cannot be empty")
        return cleaned

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip().rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("LLM_BASE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "LLM_BASE_URL must not contain credentials, query parameters, or fragments"
            )
        return value

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None or not value.get_secret_value().strip():
            return None
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"postgresql+psycopg", "sqlite"}:
            raise ValueError("DATABASE_URL must use postgresql+psycopg or sqlite")
        return value

    @field_validator("llm_pricing_effective_at")
    @classmethod
    def validate_pricing_effective_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("LLM_PRICING_EFFECTIVE_AT must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("outbox_recipient_map_json")
    @classmethod
    def validate_outbox_recipient_map(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            mapping = json.loads(value.get_secret_value())
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("OUTBOX_RECIPIENT_MAP_JSON must be a JSON object") from exc
        if (
            not isinstance(mapping, dict)
            or not mapping
            or len(mapping) > 5000
            or any(
                not isinstance(owner, str)
                or not owner.strip()
                or len(owner) > 200
                or not isinstance(recipient, str)
                or not recipient.strip()
                or len(recipient) > 320
                for owner, recipient in mapping.items()
            )
        ):
            raise ValueError("OUTBOX_RECIPIENT_MAP_JSON must map owners to bounded recipient refs")
        return value

    @field_validator("outbox_teams_webhook_url")
    @classmethod
    def validate_outbox_teams_webhook_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("OUTBOX_TEAMS_WEBHOOK_URL must be an HTTPS URL")
        if len(value.get_secret_value()) > 4096:
            raise ValueError("Teams webhook URL is too long")
        return value

    @field_validator("outbox_teams_security_webhook_url")
    @classmethod
    def validate_outbox_teams_security_webhook_url(
        cls, value: SecretStr | None
    ) -> SecretStr | None:
        if value is None:
            return None
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("OUTBOX_TEAMS_SECURITY_WEBHOOK_URL must be an HTTPS URL")
        if len(value.get_secret_value()) > 4096:
            raise ValueError("Teams security webhook URL is too long")
        return value

    @field_validator("outbox_security_recipient_ref")
    @classmethod
    def validate_outbox_security_recipient_ref(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        cleaned = value.get_secret_value().strip()
        if len(cleaned) > 320:
            raise ValueError("OUTBOX_SECURITY_RECIPIENT_REF is too long")
        return SecretStr(cleaned) if cleaned else None

    @field_validator("outbox_smtp_host")
    @classmethod
    def validate_outbox_smtp_host(cls, value: str | None) -> str | None:
        cleaned = value.strip() if value else None
        if cleaned and (
            any(char.isspace() for char in cleaned) or "\r" in cleaned or "\n" in cleaned
        ):
            raise ValueError("OUTBOX_SMTP_HOST must be a hostname without whitespace")
        return cleaned or None

    @field_validator("llm_audit_encryption_keyring_json")
    @classmethod
    def validate_llm_audit_keyring(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            mapping = json.loads(value.get_secret_value())
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("LLM_AUDIT_ENCRYPTION_KEYRING_JSON must be a JSON object") from exc
        if (
            not isinstance(mapping, dict)
            or not mapping
            or len(mapping) > 32
            or any(
                not isinstance(version, str)
                or not version.strip()
                or len(version) > 100
                or not isinstance(encoded_key, str)
                for version, encoded_key in mapping.items()
            )
        ):
            raise ValueError(
                "LLM_AUDIT_ENCRYPTION_KEYRING_JSON must map at most 32 key versions to keys"
            )
        for encoded_key in mapping.values():
            _decode_llm_audit_key(encoded_key, "LLM_AUDIT_ENCRYPTION_KEYRING_JSON")
        return value

    @field_validator("llm_audit_encryption_key")
    @classmethod
    def validate_llm_audit_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            _decode_llm_audit_key(value.get_secret_value(), "LLM_AUDIT_ENCRYPTION_KEY")
        return value

    @field_validator("llm_audit_encryption_key_version")
    @classmethod
    def validate_llm_audit_key_version(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 100:
            raise ValueError("LLM_AUDIT_ENCRYPTION_KEY_VERSION must be 1-100 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_runtime_policy(self) -> Settings:
        keyring = self.llm_audit_encryption_keys
        active_key = keyring.get(self.llm_audit_encryption_key_version)
        legacy_key = (
            self.llm_audit_encryption_key.get_secret_value()
            if self.llm_audit_encryption_key
            else None
        )
        if (
            active_key
            and legacy_key
            and _decode_llm_audit_key(
                active_key, "LLM_AUDIT_ENCRYPTION_KEYRING_JSON"
            )
            != _decode_llm_audit_key(legacy_key, "LLM_AUDIT_ENCRYPTION_KEY")
        ):
            raise ValueError(
                "LLM_AUDIT_ENCRYPTION_KEY conflicts with the active keyring version"
            )
        if self.llm_audit_content_capture and not (active_key or legacy_key):
            raise ValueError(
                "LLM audit content capture requires a key for the active key version"
            )
        if self.outbox_enqueue_enabled and (
            self.outbox_channel is None or self.outbox_recipient_map_json is None
        ):
            raise ValueError("Enabled outbox enqueue requires OUTBOX_CHANNEL and recipient mapping")
        if self.outbox_enqueue_enabled and not self.outbox_security_recipient_ref:
            raise ValueError(
                "Enabled outbox enqueue requires OUTBOX_SECURITY_RECIPIENT_REF for P1/P2 routing"
            )
        if self.outbox_enqueue_enabled and self.database_url is None:
            raise ValueError("Enabled outbox enqueue requires DATABASE_URL")
        if self.outbox_delivery_enabled:
            if not self.outbox_enqueue_enabled or self.outbox_channel is None:
                raise ValueError("Outbox delivery requires outbox enqueue and a selected channel")
            if self.database_url is None or not self.database_url.get_secret_value().startswith(
                "postgresql+psycopg://"
            ):
                raise ValueError("Outbox delivery requires PostgreSQL row-lock support")
            if self.outbox_delivery_lease_seconds <= self.outbox_delivery_timeout_seconds:
                raise ValueError("Outbox delivery lease must exceed the provider timeout")
            if self.outbox_channel == "teams" and self.outbox_teams_webhook_url is None:
                raise ValueError("Teams delivery requires OUTBOX_TEAMS_WEBHOOK_URL")
            if self.outbox_channel == "teams" and self.outbox_teams_security_webhook_url is None:
                raise ValueError("Teams delivery requires a security webhook for priority alerts")
            if self.outbox_channel == "email" and not (
                self.outbox_smtp_host
                and self.outbox_smtp_from
                and self.outbox_security_recipient_ref
            ):
                raise ValueError(
                    "Email delivery requires SMTP host/from and a security recipient reference"
                )
            if self.outbox_channel == "email":
                recipients = list(self.outbox_recipient_refs.values())
                if self.outbox_security_recipient_ref:
                    recipients.append(self.outbox_security_recipient_ref.get_secret_value())
                if not _is_mailbox_address(self.outbox_smtp_from or "") or any(
                    not _is_mailbox_address(recipient) for recipient in recipients
                ):
                    raise ValueError(
                        "Email delivery requires plain mailbox addresses for sender and recipients"
                    )
            if self.outbox_channel == "email" and not self.outbox_smtp_starttls:
                raise ValueError("Email delivery requires SMTP STARTTLS")
            if bool(self.outbox_smtp_username) != bool(self.outbox_smtp_password):
                raise ValueError("SMTP username and password must be configured together")
        if self.outbox_daily_digest_enabled and not (
            self.outbox_delivery_enabled and self.outbox_enqueue_enabled
        ):
            raise ValueError("Daily digest requires enabled outbox enqueue and delivery")
        if self.outbox_smtp_username and not self.outbox_smtp_starttls:
            raise ValueError("SMTP authentication requires STARTTLS")
        if self.public_feeds_enabled:
            if not self.public_feeds_approved:
                raise ValueError("Live public feeds require PUBLIC_FEEDS_APPROVED=true")
            if self.database_url is None:
                raise ValueError("Live public feeds require DATABASE_URL for checkpoints")
        if self.epss_enabled and not (
            self.public_feeds_enabled and self.public_feeds_approved and self.epss_approved
        ):
            raise ValueError(
                "EPSS enrichment requires enabled, approved public feeds and EPSS_APPROVED=true"
            )
        if self.epss_scoring_approved:
            if not self.epss_enabled or not self.epss_approved:
                raise ValueError(
                    "EPSS scoring approval requires enabled and approved EPSS enrichment"
                )
            if self.epss_risk_weight is None or self.epss_max_age_days is None:
                raise ValueError(
                    "EPSS scoring approval requires an explicit weight and maximum age"
                )
        elif self.epss_risk_weight is not None or self.epss_max_age_days is not None:
            raise ValueError("EPSS scoring weight and age require EPSS_SCORING_APPROVED=true")
        if self.public_feed_scheduler_enabled and not (
            self.public_feeds_enabled and self.public_feeds_approved and self.database_url
        ):
            raise ValueError(
                "Feed scheduling requires enabled, approved public feeds and DATABASE_URL"
            )
        if self.environment == "production" and self.api_trusted_local_client_cidrs:
            raise ValueError("API_TRUSTED_LOCAL_CLIENT_CIDRS is only permitted outside production")
        if self.environment == "production" and self.api_host.lower() not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ValueError(
                "Production API must remain on loopback until authentication is implemented"
            )

        if self.llm_provider in {"openai_compatible", "azure_openai"}:
            if (
                not self.llm_base_url
                or not self.llm_api_key
                or not self.llm_api_key.get_secret_value().strip()
            ):
                raise ValueError("Live LLM provider requires LLM_BASE_URL and LLM_API_KEY")
            if not self.llm_model or not self.llm_model.strip():
                raise ValueError("Live LLM provider requires LLM_MODEL")
            parsed = urlsplit(self.llm_base_url)
            if self.environment != "development" and parsed.scheme != "https":
                raise ValueError("Live LLM calls require HTTPS outside development")
            if not self.llm_audit_content_capture:
                raise ValueError("Live LLM calls require LLM_AUDIT_CONTENT_CAPTURE=true")
            if not (active_key or legacy_key):
                raise ValueError(
                    "Live LLM calls require a key for LLM_AUDIT_ENCRYPTION_KEY_VERSION"
                )
            if self.llm_audit_artifact_retention_days is None:
                raise ValueError("Live LLM calls require an approved LLM artifact retention period")
            if self.database_url is None:
                raise ValueError("Live LLM calls require DATABASE_URL for durable request auditing")
        if self.llm_live_calls_enabled:
            if self.llm_provider not in {"openai_compatible", "azure_openai"}:
                raise ValueError(
                    "Live LLM calls require LLM_PROVIDER=openai_compatible or azure_openai"
                )
            if not self.llm_data_boundary_approved:
                raise ValueError("Live LLM calls require approval of the provider data boundary")
            if not self.llm_artifact_retention_approved:
                raise ValueError("Live LLM calls require approval of prompt/response retention")
            if (
                (
                    self.llm_max_cost_per_run_usd is not None
                    or self.llm_max_cost_per_month_usd is not None
                )
                and self.database_url is not None
                and not self.database_url.get_secret_value().startswith("postgresql+psycopg://")
            ):
                raise ValueError(
                    "Live LLM spend ceilings require PostgreSQL transactional budget locks"
                )
        if (self.llm_max_cost_per_run_usd or self.llm_max_cost_per_month_usd) and (
            self.llm_input_price_usd_per_1m is None or self.llm_output_price_usd_per_1m is None
        ):
            raise ValueError("LLM spend limits require both input and output prices")
        if (self.llm_input_price_usd_per_1m is None) != (self.llm_output_price_usd_per_1m is None):
            raise ValueError("Configure both input and output LLM prices, or leave both unset")
        if not self.llm_pricing_version.strip():
            raise ValueError("LLM_PRICING_VERSION cannot be empty")
        if self.environment == "production" and self.database_url is None:
            raise ValueError("Production mode requires DATABASE_URL")
        return self

    @property
    def outbox_recipient_refs(self) -> dict[str, str]:
        if self.outbox_recipient_map_json is None:
            return {}
        return json.loads(self.outbox_recipient_map_json.get_secret_value())

    @property
    def llm_audit_encryption_keys(self) -> dict[str, str]:
        if self.llm_audit_encryption_keyring_json is None:
            return {}
        return json.loads(self.llm_audit_encryption_keyring_json.get_secret_value())


def load_settings(dotenv_path: Path = DOTENV_PATH) -> Settings:
    """Load settings with OS environment taking precedence over local .env values."""
    values = read_dotenv(dotenv_path)
    values.update(os.environ)

    legacy_provider = values.get("COUNTERSTRIKE_LLM")
    provider = values.get("LLM_PROVIDER", legacy_provider or "fake").strip().lower()
    if provider == "gateway":
        provider = "openai_compatible"

    def optional(name: str) -> str | None:
        value = values.get(name, "").strip()
        return value or None

    def configured_path(name: str, default: Path) -> Path:
        path = Path(values.get(name, str(default)))
        return path if path.is_absolute() else PROJECT_ROOT / path

    try:
        return Settings(
            environment=values.get("COUNTERSTRIKE_ENV", "development").strip().lower(),
            api_host=values.get("API_HOST", "127.0.0.1"),
            api_port=values.get("API_PORT", "8000"),
            api_trusted_local_client_cidrs=values.get("API_TRUSTED_LOCAL_CLIENT_CIDRS", ""),
            metrics_enabled=_as_bool(values.get("METRICS_ENABLED", "true"), "METRICS_ENABLED"),
            log_level=values.get("LOG_LEVEL", "INFO").strip().upper(),
            local_dev_identity=values.get("LOCAL_DEV_IDENTITY", "local-development"),
            local_dev_role=values.get("LOCAL_DEV_ROLE", "operator").strip().lower(),
            frontend_dir=configured_path("FRONTEND_DIR", PROJECT_ROOT / "frontend"),
            data_dir=configured_path("DATA_DIR", PROJECT_ROOT / "data"),
            out_dir=configured_path("OUT_DIR", PROJECT_ROOT / "out"),
            database_url=optional("DATABASE_URL"),
            outbox_enqueue_enabled=_as_bool(
                values.get("OUTBOX_ENQUEUE_ENABLED", "false"), "OUTBOX_ENQUEUE_ENABLED"
            ),
            outbox_channel=optional("OUTBOX_CHANNEL"),
            outbox_recipient_map_json=optional("OUTBOX_RECIPIENT_MAP_JSON"),
            outbox_security_recipient_ref=values.get("OUTBOX_SECURITY_RECIPIENT_REF") or None,
            outbox_delivery_enabled=_as_bool(
                values.get("OUTBOX_DELIVERY_ENABLED", "false"), "OUTBOX_DELIVERY_ENABLED"
            ),
            outbox_delivery_max_attempts=values.get("OUTBOX_DELIVERY_MAX_ATTEMPTS", "3"),
            outbox_delivery_lease_seconds=values.get("OUTBOX_DELIVERY_LEASE_SECONDS", "90"),
            outbox_delivery_timeout_seconds=values.get("OUTBOX_DELIVERY_TIMEOUT_SECONDS", "10"),
            outbox_teams_webhook_url=optional("OUTBOX_TEAMS_WEBHOOK_URL"),
            outbox_teams_security_webhook_url=optional("OUTBOX_TEAMS_SECURITY_WEBHOOK_URL"),
            outbox_smtp_host=values.get("OUTBOX_SMTP_HOST") or None,
            outbox_smtp_port=values.get("OUTBOX_SMTP_PORT", "587"),
            outbox_smtp_username=optional("OUTBOX_SMTP_USERNAME"),
            outbox_smtp_password=optional("OUTBOX_SMTP_PASSWORD"),
            outbox_smtp_from=values.get("OUTBOX_SMTP_FROM") or None,
            outbox_smtp_starttls=_as_bool(
                values.get("OUTBOX_SMTP_STARTTLS", "true"), "OUTBOX_SMTP_STARTTLS"
            ),
            outbox_daily_digest_enabled=_as_bool(
                values.get("OUTBOX_DAILY_DIGEST_ENABLED", "false"),
                "OUTBOX_DAILY_DIGEST_ENABLED",
            ),
            outbox_daily_digest_hour_utc=values.get("OUTBOX_DAILY_DIGEST_HOUR_UTC", "9"),
            outbox_daily_digest_minute_utc=values.get("OUTBOX_DAILY_DIGEST_MINUTE_UTC", "0"),
            outbox_daily_digest_max_items=values.get("OUTBOX_DAILY_DIGEST_MAX_ITEMS", "100"),
            public_feeds_enabled=_as_bool(
                values.get("PUBLIC_FEEDS_ENABLED", "false"), "PUBLIC_FEEDS_ENABLED"
            ),
            public_feeds_approved=_as_bool(
                values.get("PUBLIC_FEEDS_APPROVED", "false"), "PUBLIC_FEEDS_APPROVED"
            ),
            epss_enabled=_as_bool(values.get("EPSS_ENABLED", "false"), "EPSS_ENABLED"),
            epss_approved=_as_bool(values.get("EPSS_APPROVED", "false"), "EPSS_APPROVED"),
            epss_scoring_approved=_as_bool(
                values.get("EPSS_SCORING_APPROVED", "false"), "EPSS_SCORING_APPROVED"
            ),
            epss_risk_weight=optional("EPSS_RISK_WEIGHT"),
            epss_max_age_days=optional("EPSS_MAX_AGE_DAYS"),
            public_feed_scheduler_enabled=_as_bool(
                values.get("PUBLIC_FEED_SCHEDULER_ENABLED", "false"),
                "PUBLIC_FEED_SCHEDULER_ENABLED",
            ),
            public_feed_poll_interval_minutes=values.get(
                "PUBLIC_FEED_POLL_INTERVAL_MINUTES", "15"
            ),
            nvd_api_key=optional("NVD_API_KEY"),
            public_feed_timeout_seconds=values.get("PUBLIC_FEED_TIMEOUT_SECONDS", "20"),
            llm_provider=provider,
            llm_live_calls_enabled=_as_bool(
                values.get("LLM_LIVE_CALLS_ENABLED", "false"), "LLM_LIVE_CALLS_ENABLED"
            ),
            llm_data_boundary_approved=_as_bool(
                values.get("LLM_DATA_BOUNDARY_APPROVED", "false"), "LLM_DATA_BOUNDARY_APPROVED"
            ),
            llm_artifact_retention_approved=_as_bool(
                values.get("LLM_ARTIFACT_RETENTION_APPROVED", "false"),
                "LLM_ARTIFACT_RETENTION_APPROVED",
            ),
            llm_base_url=optional("LLM_BASE_URL"),
            llm_api_key=optional("LLM_API_KEY"),
            llm_model=optional("LLM_MODEL"),
            llm_timeout_seconds=values.get("LLM_TIMEOUT_SECONDS", "30"),
            llm_max_retries=values.get("LLM_MAX_RETRIES", "2"),
            llm_max_output_tokens=values.get("LLM_MAX_OUTPUT_TOKENS", "1200"),
            llm_max_response_bytes=values.get("LLM_MAX_RESPONSE_BYTES", "2097152"),
            llm_extraction_enabled=_as_bool(
                values.get("LLM_EXTRACTION_ENABLED", "true"), "LLM_EXTRACTION_ENABLED"
            ),
            llm_summary_enabled=_as_bool(
                values.get("LLM_SUMMARY_ENABLED", "true"), "LLM_SUMMARY_ENABLED"
            ),
            llm_audit_content_capture=_as_bool(
                values.get("LLM_AUDIT_CONTENT_CAPTURE", "false"), "LLM_AUDIT_CONTENT_CAPTURE"
            ),
            llm_audit_encryption_key=optional("LLM_AUDIT_ENCRYPTION_KEY"),
            llm_audit_encryption_keyring_json=optional("LLM_AUDIT_ENCRYPTION_KEYRING_JSON"),
            llm_audit_encryption_key_version=values.get(
                "LLM_AUDIT_ENCRYPTION_KEY_VERSION", "local-v1"
            ),
            llm_audit_artifact_retention_days=optional("LLM_AUDIT_ARTIFACT_RETENTION_DAYS"),
            llm_input_price_usd_per_1m=optional("LLM_INPUT_PRICE_USD_PER_1M"),
            llm_output_price_usd_per_1m=optional("LLM_OUTPUT_PRICE_USD_PER_1M"),
            llm_pricing_version=values.get("LLM_PRICING_VERSION", "environment-rates-v1"),
            llm_pricing_effective_at=values.get("LLM_PRICING_EFFECTIVE_AT", "2000-01-01T00:00:00Z"),
            llm_max_cost_per_run_usd=optional("LLM_MAX_COST_PER_RUN_USD"),
            llm_max_cost_per_month_usd=optional("LLM_MAX_COST_PER_MONTH_USD"),
        )
    except ValidationError as exc:
        invalid_fields = sorted(
            {str(error["loc"][0]) for error in exc.errors() if error.get("loc")}
        )
        field_list = ", ".join(invalid_fields) or "configuration"
        raise ValueError(f"Invalid Counterstrike settings for: {field_list}") from None
