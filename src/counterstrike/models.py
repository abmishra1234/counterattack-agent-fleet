"""Typed contracts shared by every agent. Agents talk only through these models."""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Priority = Literal["P1", "P2", "P3", "P4"]
Criticality = Literal["critical", "high", "medium", "low"]


class Advisory(BaseModel):
    """One raw item from the vulnerability feed (NVD-style or free-text vendor bulletin)."""

    id: str
    source: Literal["nvd", "vendor_bulletin"]
    source_url: str | None = None
    source_retrieved_at: str | None = None
    source_references: list[dict[str, Any]] = Field(default_factory=list)
    published: str
    title: str
    cvss: float | None = Field(default=None, ge=0, le=10)
    structured: dict | None = None
    text: str = ""


class AffectedProduct(BaseModel):
    product: str  # normalised component name, e.g. "openssl"
    affected: str  # PEP 440 specifier set, e.g. ">=3.0.0,<=3.0.7"
    fixed_version: str | None = None


class ExtractedAdvisory(BaseModel):
    advisory_id: str
    title: str
    cvss: float
    in_kev: bool = False
    products: list[AffectedProduct]
    method: Literal["structured", "llm"]
    evidence: list[str] = Field(default_factory=list)
    suspected_injection: bool = False


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=128)
    service: str = Field(min_length=1, max_length=200)
    component: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=120)
    internet_facing: bool
    criticality: Criticality
    owner: str = Field(min_length=1, max_length=200)
    owner_contact: str | None = Field(default=None, max_length=254)
    vendor: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=200)
    asset_type: Literal["application", "service", "vendor_product", "saas"] = "application"
    data_classification: Literal["public", "internal", "confidential", "restricted"] | None = None
    aliases: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("asset_id", "service", "component", "version", "owner")
    @classmethod
    def trim_required_inventory_values(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("inventory values must not be empty")
        return cleaned

    @field_validator("vendor", "product")
    @classmethod
    def trim_optional_inventory_values(cls, value: str | None) -> str | None:
        cleaned = value.strip() if value else None
        return cleaned or None

    @field_validator("owner_contact")
    @classmethod
    def trim_owner_contact(cls, value: str | None) -> str | None:
        cleaned = value.strip() if value else None
        return cleaned or None

    @field_validator("aliases")
    @classmethod
    def normalize_asset_aliases(cls, values: list[str]) -> list[str]:
        aliases = [value.strip() for value in values]
        if any(not alias for alias in aliases):
            raise ValueError("inventory aliases must not be empty")
        if len({alias.casefold() for alias in aliases}) != len(aliases):
            raise ValueError("inventory aliases must be unique per asset")
        return aliases

    @property
    def inventory_product(self) -> str:
        return self.product or self.component


class InventoryDocument(BaseModel):
    """Versioned inventory file contract; product-level data stays local to matching."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    assets: list[Asset] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_inventory_identity(self):
        asset_ids = [asset.asset_id.casefold() for asset in self.assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("inventory asset_id values must be unique")
        alias_targets: dict[str, str] = {}
        for asset in self.assets:
            canonical = asset.inventory_product.strip().casefold()
            for alias in asset.aliases:
                normalized = alias.strip().casefold()
                if not normalized:
                    raise ValueError("inventory aliases must not be empty")
                previous = alias_targets.setdefault(normalized, canonical)
                if previous != canonical:
                    raise ValueError("inventory alias cannot map to multiple products")
        return self


class Match(BaseModel):
    advisory_id: str
    asset_id: str
    component: str
    installed_version: str
    affected: str
    fixed_version: str | None
    comparator: Literal["pep440", "pep440_tolerant"] | None = None
    outcome: Literal["affected", "not_affected", "possible_match"] = "affected"
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    version_note: str | None = None  # set when the installed version needed tolerant parsing


class ScoredMatch(Match):
    risk_score: float
    priority: Priority
    sla_hours: int
    score_breakdown: dict[str, float]


class Alert(BaseModel):
    alert_id: str
    cve_id: str
    asset_id: str
    service: str
    component: str
    installed_version: str
    fixed_version: str | None
    risk_score: float
    priority: Priority
    sla_hours: int
    owner: str
    summary: str
    remediation: str
    evidence: list[str]
    generated_by: str


class NeedsHuman(BaseModel):
    advisory_id: str
    stage: str
    reason: str


class FleetState(TypedDict, total=False):
    """LangGraph state. Lists with operator.add are append-only across agents."""

    data_dir: str
    out_dir: str
    advisories: list[Advisory]
    kev: list[str]
    inventory: list[Asset]
    aliases: dict[str, str]
    source_syncs: list[dict[str, Any]]
    source_enrichments: list[dict[str, Any]]
    extracted: list[ExtractedAdvisory]
    matches: list[Match]
    scored: list[ScoredMatch]
    alerts: list[Alert]
    needs_human: Annotated[list[NeedsHuman], operator.add]
    trace: Annotated[list[dict], operator.add]
