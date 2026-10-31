"""Bounded SMTP and Microsoft Teams Workflows delivery adapters for outbox rows."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any

import httpx

from counterstrike.config import Settings


class DeliveryFailure(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False, ambiguous: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


def _body(payload: dict[str, Any], route: str, idempotency_key: str) -> str:
    if payload.get("digest") is True:
        start = payload.get("window_start", "unknown")
        end = payload.get("window_end", "unknown")
        total = payload.get("alert_count", 0)
        lines = [
            f"Counterstrike daily vulnerability digest ({route} route)",
            f"UTC window: {start} to {end}",
            f"Alerts in window: {total}",
        ]
        rendered = 0
        alerts = payload.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []
        for item in alerts[:500]:
            if not isinstance(item, dict):
                continue
            block = "\n".join(
                [
                    "",
                    f"[{item.get('priority', 'unknown')}] {item.get('cve_id', 'unknown')} — "
                    f"{item.get('service', 'unknown')} / {item.get('component', 'unknown')} "
                    f"{item.get('installed_version', 'unknown')}",
                    f"Fixed version: {item.get('fixed_version') or 'not published'}",
                    f"Risk score: {item.get('risk_score', 'unknown')} | "
                    f"SLA: {item.get('sla_hours', 'unknown')} h",
                    f"Impact: {str(item.get('summary', ''))[:1200]}",
                    f"Recommended action: {str(item.get('remediation', ''))[:1200]}",
                ]
            )
            # Reserve room for an explicit omission count and idempotency key.
            if sum(map(len, lines)) + len(block) + 300 > 20_000:
                break
            lines.append(block)
            rendered += 1
        omitted = max(0, int(total or 0) - rendered)
        if omitted:
            lines.append(
                f"\n{omitted} alerts omitted from this message; "
                "review the Counterstrike alert queue."
            )
        lines.append(f"Delivery key: {idempotency_key}")
        return "\n".join(lines)[:20_000]
    lines = [
        f"Counterstrike vulnerability alert ({route} route)",
        f"Priority: {payload.get('priority', 'unknown')} | CVE: {payload.get('cve_id', 'unknown')}",
        f"Service: {payload.get('service', 'unknown')} ({payload.get('asset_key', 'unknown')})",
        "Component: "
        f"{payload.get('component', 'unknown')} {payload.get('installed_version', 'unknown')}",
        f"Fixed version: {payload.get('fixed_version') or 'not published'}",
        "Risk score: "
        f"{payload.get('risk_score', 'unknown')} | SLA: {payload.get('sla_hours', 'unknown')} h",
        f"Owner: {payload.get('owner', 'unknown')}",
        f"Impact: {payload.get('summary', '')}",
        f"Recommended action: {payload.get('remediation', '')}",
        f"Delivery key: {idempotency_key}",
    ]
    evidence = payload.get("evidence")
    if isinstance(evidence, list):
        lines.append("Evidence:")
        lines.extend(f"- {str(item)[:2000]}" for item in evidence[:20])
    return "\n".join(str(line)[:3000] for line in lines)[:20_000]


def send_outbox_message(message, settings: Settings) -> str:
    """Send one claimed message; return only a bounded provider response category."""
    payload = message.payload if isinstance(message.payload, dict) else {}
    route = str(payload.get("delivery_route") or "owner")[:16]
    text = _body(payload, route, message.idempotency_key)
    if message.channel == "teams":
        webhook = (
            settings.outbox_teams_security_webhook_url
            if route in {"security", "security_digest"}
            else settings.outbox_teams_webhook_url
        )
        if webhook is None:
            raise DeliveryFailure("teams_not_configured")
        url = webhook.get_secret_value()
        try:
            response = httpx.post(
                url,
                json={"text": text},
                timeout=settings.outbox_delivery_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.ConnectError as exc:
            raise DeliveryFailure("teams_connect_error", retryable=True) from exc
        except httpx.TimeoutException as exc:
            raise DeliveryFailure("teams_timeout", ambiguous=True) from exc
        except httpx.HTTPError as exc:
            raise DeliveryFailure("teams_transport_error", ambiguous=True) from exc
        if 200 <= response.status_code < 300:
            return f"http_{response.status_code}"
        if response.status_code == 429:
            raise DeliveryFailure(f"teams_http_{response.status_code}", retryable=True)
        if response.status_code >= 500:
            raise DeliveryFailure(f"teams_http_{response.status_code}", ambiguous=True)
        raise DeliveryFailure(f"teams_http_{response.status_code}")

    if message.channel != "email":
        raise DeliveryFailure("unsupported_channel")
    recipient = message.recipient_ref.strip()
    address = parseaddr(recipient)[1]
    if not address or address != recipient or any(char in recipient for char in "\r\n"):
        raise DeliveryFailure("invalid_email_recipient")
    if not settings.outbox_smtp_host or not settings.outbox_smtp_from:
        raise DeliveryFailure("smtp_not_configured")
    sender = settings.outbox_smtp_from.strip()
    if not parseaddr(sender)[1] or any(char in sender for char in "\r\n"):
        raise DeliveryFailure("invalid_email_sender")

    email = EmailMessage()
    email["From"] = sender
    email["To"] = recipient
    if payload.get("digest") is True:
        subject = (
            f"[Counterstrike] Daily vulnerability digest — "
            f"{payload.get('alert_count', 0)} alerts"
        )
    else:
        subject = (
            f"[{payload.get('priority', 'unknown')}] {payload.get('cve_id', 'Security alert')} "
            f"affects {payload.get('service', 'asset')}"
        )
    email["Subject"] = subject[:200]
    email["Message-ID"] = f"<{message.idempotency_key}@counterstrike.local>"
    email["X-Counterstrike-Delivery-Key"] = message.idempotency_key
    email.set_content(text)

    try:
        with smtplib.SMTP(
            settings.outbox_smtp_host,
            settings.outbox_smtp_port,
            timeout=settings.outbox_delivery_timeout_seconds,
        ) as smtp:
            smtp.ehlo()
            if settings.outbox_smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if settings.outbox_smtp_username and settings.outbox_smtp_password:
                smtp.login(
                    settings.outbox_smtp_username.get_secret_value(),
                    settings.outbox_smtp_password.get_secret_value(),
                )
            refused = smtp.send_message(email)
    except smtplib.SMTPAuthenticationError as exc:
        raise DeliveryFailure("smtp_authentication_failed") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise DeliveryFailure("smtp_recipient_refused") from exc
    except smtplib.SMTPResponseException as exc:
        retryable = 400 <= int(exc.smtp_code) < 500
        raise DeliveryFailure(f"smtp_response_{int(exc.smtp_code)}", retryable=retryable) from exc
    except (smtplib.SMTPConnectError, smtplib.SMTPHeloError) as exc:
        raise DeliveryFailure("smtp_connection_rejected", retryable=True) from exc
    except (smtplib.SMTPServerDisconnected, TimeoutError, OSError) as exc:
        raise DeliveryFailure("smtp_transport_ambiguous", ambiguous=True) from exc
    except smtplib.SMTPException as exc:
        raise DeliveryFailure("smtp_protocol_error", ambiguous=True) from exc
    if refused:
        raise DeliveryFailure("smtp_recipient_refused")
    return "smtp_accepted"
