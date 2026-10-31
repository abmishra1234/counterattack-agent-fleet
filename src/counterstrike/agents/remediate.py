"""Agent 5 - Remediation & Alert Writer: builds one owner-ready alert per scored match.

Facts (versions, priority, SLA, owner) are filled by code. The LLM only writes the plain-language
summary, and that summary is rejected if it mentions any version not in the facts.
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlsplit, urlunsplit

from counterstrike.guards import summary_is_grounded
from counterstrike.llm import LLMPort
from counterstrike.models import Alert, FleetState
from counterstrike.versions import spec_versions, versions_in

PROMPT_VERSION = "impact_summary_v1"
logger = logging.getLogger("counterstrike.agent.remediate")
SYSTEM = """Write exactly three concise sentences for an engineering owner, labeled Security impact,
Operational impact, and Business impact. Use only the supplied facts. For security, describe CVSS
and KEV status. For operations, describe the affected component/version and service. For business,
describe the supplied criticality and internet exposure. Do not infer a breach, outage, exploit
activity, financial loss, or other facts. Do not change priority, SLA, ownership, match outcome, or
recommend a remediation. No markdown beyond the three labels."""


def _safe_provenance_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not hostname:
        return None
    if ":" in hostname:
        hostname = f"[{hostname}]"
    return urlunsplit((parsed.scheme, hostname, parsed.path[:800], "", ""))


def _template(
    *,
    cve: str,
    title: str,
    component: str,
    installed: str,
    service: str,
    cvss: float,
    in_kev: bool | None,
    internet_facing: bool,
    criticality: str,
) -> str:
    kev_text = (
        "is listed in CISA KEV"
        if in_kev is True
        else "is not listed in CISA KEV"
        if in_kev is False
        else "has unknown CISA KEV status because the catalog was unavailable"
    )
    exposure_text = "internet-facing" if internet_facing else "not internet-facing"
    return (
        f"Security impact: {cve} ({title}) has CVSS {cvss:.1f} and {kev_text}. "
        f"Operational impact: {service} runs affected {component} {installed}. "
        f"Business impact: {service} is classified as {criticality} criticality "
        f"and is {exposure_text}."
    )


def _impact_summary_is_grounded(
    summary: str,
    *,
    cvss: float,
    in_kev: bool | None,
    internet_facing: bool,
    criticality: str,
    component: str,
    installed: str,
    service: str,
) -> str | None:
    lowered = summary.lower()
    required_labels = ("security impact:", "operational impact:", "business impact:")
    label_positions = [lowered.find(label) for label in required_labels]
    if (
        any(position < 0 for position in label_positions)
        or label_positions != sorted(label_positions)
        or lowered.count("security impact:") != 1
        or lowered.count("operational impact:") != 1
        or lowered.count("business impact:") != 1
        or summary[: label_positions[0]].strip()
    ):
        return "invalid_structure"
    required_facts = (
        f"{cvss:.1f}",
        criticality.lower(),
        component.lower(),
        installed.lower(),
        service.lower(),
    )
    if not all(fact in lowered for fact in required_facts):
        return "missing_required_fact"
    kev_conflict = (
        (in_kev is True and "not listed" in lowered)
        or (in_kev is False and "not listed" not in lowered)
        or (
            in_kev is None
            and (
                "unknown" not in lowered
                or re.search(r"\b(?:listed|not listed)\b", lowered)
            )
        )
    )
    if "kev" not in lowered or kev_conflict:
        return "kev_status_conflict"
    if internet_facing and not re.search(r"\binternet[- ]facing\b", lowered):
        return "missing_exposure_fact"
    if not internet_facing and not re.search(
        r"\bnot\s+internet[- ]facing\b|\binternally isolated\b", lowered
    ):
        return "exposure_status_conflict"
    if re.search(
        r"\b(?:breach(?:ed)?|compromis(?:e|ed)|data theft|data loss|ransomware|"
        r"service outage|financial loss|customer records exposed)\b",
        lowered,
    ):
        return "unsupported_incident_claim"
    if in_kev is not True and re.search(
        r"\b(?:actively exploited|exploited in the wild|known exploited|exploitation observed)\b",
        lowered,
    ):
        return "kev_status_conflict"
    if not internet_facing and re.search(
        r"\b(?:is|remains|currently)\s+(?:publicly\s+)?(?:internet-facing|exposed|accessible)\b",
        lowered,
    ):
        return "exposure_status_conflict"
    return None


def _impact_provenance_evidence(
    advisory,
    asset,
    *,
    in_kev: bool | None,
    source_syncs: list[dict],
    source_enrichments: list[dict],
) -> list[str]:
    """Tie each summary dimension to its persisted source record or inventory fact."""
    evidence = [
        (
            f"Impact evidence [operational]: inventory asset {asset.asset_id}; "
            "fields=service,component,version"
        ),
        (
            f"Impact evidence [business]: inventory asset {asset.asset_id}; "
            "fields=criticality,internet_facing"
        ),
    ]
    if advisory is not None:
        source = getattr(advisory, "source", "unknown")
        source_url = _safe_provenance_url(getattr(advisory, "source_url", None))
        retrieved_at = getattr(advisory, "source_retrieved_at", None)
        detail = f"source={source}; fields=title,cvss"
        if source_url:
            detail += f"; source_url={source_url}"
        if retrieved_at:
            detail += f"; retrieved_at={str(retrieved_at)[:64]}"
        evidence.append(f"Impact evidence [security]: advisory {advisory.id}; {detail}")
    kev_sync = next(
        (item for item in source_syncs if item.get("source_id") == "cisa_kev"),
        None,
    )
    kev_observation = next(
        (
            item
            for item in source_enrichments
            if item.get("source_id") == "cisa_kev"
            and isinstance(item.get("value"), dict)
            and item.get("advisory_id") == getattr(advisory, "id", None)
        ),
        None,
    )
    if kev_sync is None:
        if in_kev is None:
            detail = "source_id=cisa_kev; catalog_status=unknown"
        else:
            fixture_result = "listed" if in_kev else "not_listed"
            detail = (
                "source=fixture; file=kev.json; catalog_status=complete; "
                f"result={fixture_result}"
            )
    else:
        status = kev_sync.get("status", "unknown")
        detail = f"source_id=cisa_kev; catalog_status={status}"
        if in_kev is True:
            detail += "; result=listed"
        elif in_kev is False and status == "success":
            detail += "; result=not_listed_in_complete_catalog"
        else:
            detail += "; result=unknown"
        catalog = (kev_observation or {}).get("value", {}).get("catalog_version")
        catalog = catalog or kev_sync.get("catalog_version")
        if catalog:
            detail += f"; catalog_version={str(catalog)[:80]}"
        if kev_sync.get("record_count") is not None:
            detail += f"; record_count={int(kev_sync['record_count'])}"
        if kev_sync.get("fetched_at"):
            detail += f"; fetched_at={str(kev_sync['fetched_at'])[:64]}"
        if kev_sync.get("error_code"):
            detail += f"; error_code={str(kev_sync['error_code'])[:80]}"
    evidence.append(f"Impact evidence [security/KEV]: {detail}")
    return evidence


def remediate_agent(state: FleetState, llm: LLMPort) -> dict:
    t0 = time.perf_counter()
    advs = {a.advisory_id: a for a in state["extracted"]}
    raw_advs = {a.id: a for a in state.get("advisories", [])}
    assets = {a.asset_id: a for a in state["inventory"]}
    alerts: list[Alert] = []
    fallbacks = 0
    fallback_reasons: dict[str, int] = {}
    for i, s in enumerate(state["scored"], start=1):
        adv, asset = advs[s.advisory_id], assets[s.asset_id]
        kev_status = (
            "listed"
            if adv.in_kev is True
            else "not_listed"
            if adv.in_kev is False
            else "unknown"
        )
        facts = {
            "cve_id": s.advisory_id,
            "title": adv.title,
            "component": s.component,
            "installed_version": s.installed_version,
            "affected_range": s.affected,
            "fixed_version": s.fixed_version,
            "service": asset.service,
            "priority": s.priority,
            "cvss": f"{adv.cvss:.1f}",
            "kev_listed": adv.in_kev,
            "kev_status": kev_status,
            "internet_facing": asset.internet_facing,
            "business_criticality": asset.criticality,
        }
        user = "\n".join(f"{k}: {v}" for k, v in facts.items())
        call_failed = False
        try:
            summary = llm.complete(
                "summarise",
                SYSTEM,
                user,
                context={
                    **facts,
                    "_counterstrike_audit": {
                        "prompt_version": PROMPT_VERSION,
                        "advisory_id": s.advisory_id,
                    },
                },
            ).strip()
        except Exception as exc:
            call_failed = True
            logger.warning(
                "Summary model call failed; using deterministic summary",
                extra={
                    "event": "agent.remediate.call_failed",
                    "task": "summarise",
                    "advisory_id": s.advisory_id,
                    "error_code": type(exc).__name__,
                },
            )
            summary = ""
        allowed = (
            {s.installed_version, s.fixed_version or ""}
            | spec_versions(s.affected)
            | versions_in(adv.title)
            | {f"{adv.cvss:.1f}"}
        )
        fallback_reason = None
        if call_failed:
            fallback_reason = "model_call_failed"
        elif not summary:
            fallback_reason = "empty_response"
        elif not summary_is_grounded(summary, allowed):
            fallback_reason = "unsupported_version_or_number"
        else:
            fallback_reason = _impact_summary_is_grounded(
                summary,
                cvss=adv.cvss,
                in_kev=adv.in_kev,
                internet_facing=asset.internet_facing,
                criticality=asset.criticality,
                component=s.component,
                installed=s.installed_version,
                service=asset.service,
            )
        if fallback_reason:
            fallbacks += 1
            fallback_reasons[fallback_reason] = fallback_reasons.get(fallback_reason, 0) + 1
            summary = _template(
                cve=s.advisory_id,
                title=adv.title,
                component=s.component,
                installed=s.installed_version,
                service=asset.service,
                cvss=adv.cvss,
                in_kev=adv.in_kev,
                internet_facing=asset.internet_facing,
                criticality=asset.criticality,
            )
        remediation = (
            f"Upgrade {s.component} from {s.installed_version} to {s.fixed_version} or later, "
            f"rebuild and redeploy {asset.service}, then re-run the dependency scan to confirm."
            if s.fixed_version
            else (
                f"No fixed version is recorded in the advisory data for {s.component}. "
                "Review vendor guidance and use only analyst-approved mitigations "
                f"for {asset.service}."
            )
        )
        evidence = [
            *adv.evidence,
            f"inventory {asset.asset_id}: {s.component}=={s.installed_version}",
            f"affected range {s.affected}",
            *_impact_provenance_evidence(
                raw_advs.get(s.advisory_id),
                asset,
                in_kev=adv.in_kev,
                source_syncs=state.get("source_syncs", []),
                source_enrichments=state.get("source_enrichments", []),
            ),
        ]
        if s.version_note:
            evidence.append(s.version_note)
        alerts.append(
            Alert(
                alert_id=f"ALR-{i:04d}",
                cve_id=s.advisory_id,
                asset_id=s.asset_id,
                service=asset.service,
                component=s.component,
                installed_version=s.installed_version,
                fixed_version=s.fixed_version,
                risk_score=s.risk_score,
                priority=s.priority,
                sla_hours=s.sla_hours,
                owner=asset.owner,
                summary=summary,
                remediation=remediation,
                evidence=evidence,
                generated_by=f"{llm.name}/{PROMPT_VERSION}",
            )
        )
    return {
        "alerts": alerts,
        "trace": [
            {
                "agent": "remediate",
                "alerts": len(alerts),
                "summary_fallbacks": fallbacks,
                "summary_fallback_reasons": fallback_reasons,
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
