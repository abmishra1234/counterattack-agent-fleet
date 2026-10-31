"""Typed contracts shared by every agent. Agents talk only through these models."""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field

Priority = Literal["P1", "P2", "P3", "P4"]
Criticality = Literal["critical", "high", "medium", "low"]


class Advisory(BaseModel):
    """One raw item from the vulnerability feed (NVD-style or free-text vendor bulletin)."""

    id: str
    source: Literal["nvd", "vendor_bulletin"]
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
    asset_id: str
    service: str
    component: str
    version: str
    internet_facing: bool
    criticality: Criticality
    owner: str


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
