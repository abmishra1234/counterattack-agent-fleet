"""Agent 5 - Remediation & Alert Writer: builds one owner-ready alert per scored match.

Facts (versions, priority, SLA, owner) are filled by code. The LLM only writes the plain-language
summary, and that summary is rejected if it mentions any version not in the facts.
"""

from __future__ import annotations

import time

from counterstrike.guards import summary_is_grounded
from counterstrike.llm import LLMPort
from counterstrike.models import Alert, FleetState
from counterstrike.versions import spec_versions, versions_in

PROMPT_VERSION = "summarise_v1"
SYSTEM = """Write a 1-2 sentence alert summary for an engineering owner.
Use only the facts given. Do not invent versions, exploits or priorities. No markdown."""


def _template(
    cve: str, title: str, component: str, installed: str, service: str, fixed: str | None
) -> str:
    fix = f"Upgrade to {fixed}." if fixed else "No fixed version published yet."
    return f"{component} {installed} on {service} is affected by {cve} ({title}). {fix}"


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
            "fixed_version": s.fixed_version,
            "service": asset.service,
            "priority": s.priority,
        }
        user = "\n".join(f"{k}: {v}" for k, v in facts.items())
        summary = llm.complete("summarise", SYSTEM, user, context=facts).strip()
        allowed = (
            {s.installed_version, s.fixed_version or ""}
            | spec_versions(s.affected)
            | versions_in(adv.title)
        )
        if not summary or not summary_is_grounded(summary, allowed):
            fallbacks += 1
            summary = _template(
                s.advisory_id,
                adv.title,
                s.component,
                s.installed_version,
                asset.service,
                s.fixed_version,
            )
        remediation = (
            f"Upgrade {s.component} from {s.installed_version} to {s.fixed_version} or later, "
            f"rebuild and redeploy {asset.service}, then re-run the dependency scan to confirm."
            if s.fixed_version
            else f"No fix yet: apply vendor workarounds and limit exposure of {asset.service}."
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
