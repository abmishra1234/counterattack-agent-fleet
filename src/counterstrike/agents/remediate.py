"""Agent 5 - Remediation & Alert Writer: builds one owner-ready alert per scored match.

Facts (versions, priority, SLA, owner) are filled by code. The LLM only writes the plain-language
summary, and that summary is rejected if it mentions any version not in the facts.
"""

from __future__ import annotations

import logging
import re
import time

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


def _template(
    *,
    cve: str,
    title: str,
    component: str,
    installed: str,
    service: str,
    cvss: float,
    in_kev: bool,
    internet_facing: bool,
    criticality: str,
) -> str:
    kev_text = "is listed in CISA KEV" if in_kev else "is not listed in CISA KEV"
    exposure_text = "internet-facing" if internet_facing else "not internet-facing"
    return (
        f"Security impact: {cve} ({title}) has CVSS {cvss:.1f} and {kev_text}. "
        f"Operational impact: {service} runs affected {component} {installed}. "
        f"Business impact: {service} is classified as {criticality} criticality and is {exposure_text}."
    )


def _impact_summary_is_grounded(
    summary: str,
    *,
    cvss: float,
    in_kev: bool,
    internet_facing: bool,
    criticality: str,
    component: str,
    installed: str,
    service: str,
) -> bool:
    lowered = summary.lower()
    required_labels = ("security impact:", "operational impact:", "business impact:")
    required_facts = (f"{cvss:.1f}", criticality.lower(), component.lower(), installed.lower(), service.lower())
    if not all(label in lowered for label in required_labels) or not all(
        fact in lowered for fact in required_facts
    ):
        return False
    if "kev" not in lowered or (in_kev == ("not listed" in lowered)):
        return False
    if internet_facing and not re.search(r"\binternet[- ]facing\b", lowered):
        return False
    if not internet_facing and not re.search(
        r"\bnot\s+internet[- ]facing\b|\binternally isolated\b", lowered
    ):
        return False
    if not in_kev and re.search(
        r"\b(?:actively exploited|exploited in the wild|known exploited|exploitation observed)\b",
        lowered,
    ):
        return False
    if not internet_facing and re.search(
        r"\b(?:is|remains|currently)\s+(?:publicly\s+)?(?:internet-facing|exposed|accessible)\b",
        lowered,
    ):
        return False
    return True


def remediate_agent(state: FleetState, llm: LLMPort) -> dict:
    t0 = time.perf_counter()
    advs = {a.advisory_id: a for a in state["extracted"]}
    assets = {a.asset_id: a for a in state["inventory"]}
    alerts: list[Alert] = []
    fallbacks = 0
    for i, s in enumerate(state["scored"], start=1):
        adv, asset = advs[s.advisory_id], assets[s.asset_id]
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
            "internet_facing": asset.internet_facing,
            "business_criticality": asset.criticality,
        }
        user = "\n".join(f"{k}: {v}" for k, v in facts.items())
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
        if (
            not summary
            or not summary_is_grounded(summary, allowed)
            or not _impact_summary_is_grounded(
                summary,
                cvss=adv.cvss,
                in_kev=adv.in_kev,
                internet_facing=asset.internet_facing,
                criticality=asset.criticality,
                component=s.component,
                installed=s.installed_version,
                service=asset.service,
            )
        ):
            fallbacks += 1
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
                f"Review vendor guidance and use only analyst-approved mitigations for {asset.service}."
            )
        )
        evidence = [
            *adv.evidence,
            f"inventory {asset.asset_id}: {s.component}=={s.installed_version}",
            f"affected range {s.affected}",
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
                "ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        ],
    }
