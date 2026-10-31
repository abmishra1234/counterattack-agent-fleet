"""LLM port. Agents call `llm.complete(...)`; the backend is swappable.

* FakeLLM   - deterministic test double used in CI and the default demo (no network, no keys).
* GatewayLLM - retained provider implementation, currently gated until every request and response
               is durably audited and metered by the service.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Protocol

import httpx

from counterstrike.config import Settings, load_settings
from counterstrike.db import get_session_factory
from counterstrike.db_models import LLMCall
from counterstrike.llm_metering import (
    LLMBudgetExceeded,
    complete_attempt,
    fail_attempt,
    prepare_attempt,
)
from counterstrike.observability import request_id_context

NUM = r"(\d+(?:\.\d+)+)"
logger = logging.getLogger("counterstrike.llm")


class LLMPort(Protocol):
    name: str

    def complete(self, task: str, system: str, user: str, context: dict) -> str: ...


class FakeLLM:
    """Imitates what a well-behaved model returns, using simple patterns.

    It only sees the same inputs a real model would (bulletin text + vocabulary) via `context`.
    It intentionally ignores embedded instructions, as a well-prompted model should; the guard
    layer still checks every output, so tests also cover a misbehaving model (see tests).
    """

    name = "fake-llm"

    def complete(self, task: str, system: str, user: str, context: dict) -> str:
        if task == "extract":
            return json.dumps(self._extract(context["text"], context["vocabulary"]))
        if task == "summarise":
            c = context
            return (
                f"{c['component']} {c['installed_version']} on {c['service']} is affected by "
                f"{c['cve_id']} ({c['title']}). The fixed release is {c['fixed_version']}."
            )
        raise ValueError(f"unknown task {task}")

    @staticmethod
    def _extract(text: str, vocabulary: list[str]) -> dict:
        lower = text.lower()
        product = next(
            (
                v
                for v in sorted(vocabulary, key=len, reverse=True)
                if re.search(rf"\b{re.escape(v)}\b", lower)
            ),
            None,
        )
        sentences = re.split(r"(?<=\.)\s+", text)
        affected, fixed, evidence = None, None, []
        if m := re.search(rf"versions?\s+{NUM}\s+through\s+{NUM}", text, re.I):
            affected = f">={m.group(1)},<={m.group(2)}"
            evidence.append(m.group(0))
        elif m := re.search(rf"(?:before|prior to)\s+{NUM}", text, re.I):
            affected = f"<{m.group(1)}"
            evidence.append(m.group(0))
        if m := re.search(rf"(?:upgrade to|fixed in)\s+(?:[A-Za-z]+\s+)?{NUM}", text, re.I):
            fixed = m.group(1)
            evidence.append(m.group(0))
        if not (product and affected):
            return {"products": [], "evidence": []}
        ev = [s.strip() for s in sentences if any(e in s for e in evidence)]
        return {
            "products": [{"product": product, "affected": affected, "fixed_version": fixed}],
            "evidence": ev,
        }


class GatewayLLM:
    """OpenAI-compatible adapter that durably audits each provider attempt."""

    name = "openai-compatible"

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        run_id: str | None = None,
        request_id: str | None = None,
        actor_id: str | None = None,
        job_id: str | None = None,
    ) -> None:
        self.settings = settings or load_settings()
        if not self.settings.llm_live_calls_enabled:
            raise RuntimeError("Live LLM calls are disabled; set LLM_LIVE_CALLS_ENABLED only after approvals")
        if not run_id:
            raise RuntimeError("Audited live LLM calls require a persisted run_id")
        if not self.settings.llm_base_url or not self.settings.llm_api_key or not self.settings.llm_model:
            raise RuntimeError("Live LLM provider configuration is incomplete")
        self.run_id = run_id
        self.request_id = request_id
        self.actor_id = actor_id
        self.job_id = job_id
        self._session_factory = get_session_factory(self.settings)

    def _persist_failure(
        self,
        *,
        record_id: str,
        error_code: str,
        safe_error: str,
        latency_ms: int,
        response_status: int | None = None,
        raw_response: str | bytes | None = None,
        provider_secret: str | None = None,
        attempt: int,
    ) -> None:
        try:
            with self._session_factory() as session:
                persisted = session.get(LLMCall, record_id)
                if persisted is None:
                    raise RuntimeError("LLM audit attempt disappeared")
                fail_attempt(
                    session,
                    persisted,
                    settings=self.settings,
                    error_code=error_code,
                    safe_error=safe_error,
                    latency_ms=latency_ms,
                    response_status=response_status,
                    raw_response=raw_response,
                    provider_secret=provider_secret,
                )
                session.commit()
        except Exception:
            logger.error(
                "LLM attempt failure outcome could not be persisted",
                extra={
                    "event": "llm.call.outcome_persistence_failed",
                    "run_id": self.run_id,
                    "attempt": attempt,
                    "error_code": "audit_persistence_unavailable",
                },
            )
            raise RuntimeError("LLM attempt outcome could not be durably audited") from None

    def _persist_success(
        self,
        *,
        record_id: str,
        raw_response: str | bytes,
        usage: dict[str, Any] | None,
        response_id: str | None,
        latency_ms: int,
        parsed_output: str,
        attempt: int,
    ) -> None:
        try:
            with self._session_factory() as session:
                persisted = session.get(LLMCall, record_id)
                if persisted is None:
                    raise RuntimeError("LLM audit attempt disappeared")
                complete_attempt(
                    session,
                    persisted,
                    settings=self.settings,
                    raw_response=raw_response,
                    usage=usage,
                    response_id=response_id,
                    latency_ms=latency_ms,
                    parsed_output=parsed_output,
                )
                session.commit()
        except Exception:
            logger.error(
                "LLM response outcome could not be persisted",
                extra={
                    "event": "llm.call.outcome_persistence_failed",
                    "run_id": self.run_id,
                    "attempt": attempt,
                    "error_code": "audit_persistence_unavailable",
                },
            )
            raise RuntimeError("LLM response could not be durably audited") from None

    def complete(self, task: str, system: str, user: str, context: dict) -> str:
        settings = self.settings
        provider_request = {
            "model": settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": settings.llm_max_output_tokens,
            "temperature": 0,
        }
        request_body = json.dumps(
            provider_request, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        metadata = context.get("_counterstrike_audit", {})
        prompt_version = str(metadata.get("prompt_version") or f"{task}_v1")
        advisory_id = metadata.get("advisory_id")
        exact_request = {
            "provider_request": provider_request,
            "provider_request_body": request_body.decode("utf-8"),
            "task": task,
            "prompt_version": prompt_version,
            "advisory_id": advisory_id,
            "context": context,
        }
        attempt_base = 1
        endpoint = settings.llm_base_url.rstrip("/")
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"
        api_key = settings.llm_api_key.get_secret_value()
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        parent_call_id: str | None = None
        request_id = self.request_id or request_id_context.get()
        last_error_code = "provider_unavailable"

        for retry_index in range(settings.llm_max_retries + 1):
            with self._session_factory() as session:
                try:
                    record = prepare_attempt(
                        session,
                        settings=settings,
                        run_id=self.run_id,
                        job_id=self.job_id,
                        task=task,
                        model=settings.llm_model,
                        prompt_version=prompt_version,
                        request_id=request_id,
                        actor_id=self.actor_id,
                        advisory_id=str(advisory_id) if advisory_id else None,
                        attempt_number=attempt_base + retry_index,
                        parent_call_id=parent_call_id,
                        exact_request=exact_request,
                    )
                    if record is None:
                        session.commit()
                        raise LLMBudgetExceeded("LLM call blocked by configured spend ceiling")
                    # The request artifact and pending call are durable before network I/O.
                    session.commit()
                except LLMBudgetExceeded:
                    raise
                except Exception:
                    session.rollback()
                    logger.error(
                        "LLM request audit could not be committed",
                        extra={
                            "event": "llm.call.request_persistence_failed",
                            "run_id": self.run_id,
                            "error_code": "audit_persistence_unavailable",
                        },
                    )
                    raise RuntimeError(
                        "LLM request could not be durably audited; provider call was not sent"
                    ) from None
            parent_call_id = record.id
            started = time.perf_counter()
            retryable = False
            delay = min(2**retry_index, 8)
            try:
                with httpx.Client(timeout=settings.llm_timeout_seconds, follow_redirects=False) as client:
                    response = client.post(endpoint, headers=headers, content=request_body)
                latency_ms = round((time.perf_counter() - started) * 1000)
                if not 200 <= response.status_code < 300:
                    status = response.status_code
                    error_code = (
                        "provider_rate_limited" if status == 429 else
                        "provider_timeout" if status == 408 else
                        "provider_unavailable" if status >= 500 else
                        "provider_request_rejected"
                    )
                    retryable = status in {408, 429, 500, 502, 503, 504}
                    if retry_after := response.headers.get("Retry-After"):
                        try:
                            delay = min(max(float(retry_after), 0.0), 8.0)
                        except ValueError:
                            pass
                    self._persist_failure(
                        record_id=record.id,
                        error_code=error_code,
                        safe_error=response.text,
                        latency_ms=latency_ms,
                        response_status=status,
                        provider_secret=api_key,
                        attempt=attempt_base + retry_index,
                    )
                    logger.warning(
                        "LLM provider attempt failed",
                        extra={
                            "event": "llm.call.attempt_failed",
                            "run_id": self.run_id,
                            "attempt": attempt_base + retry_index,
                            "error_code": error_code,
                        },
                    )
                    last_error_code = error_code
                else:
                    try:
                        raw_response = response.content.decode("utf-8")
                        body = response.json()
                        choices = body.get("choices") if isinstance(body, dict) else None
                        output = choices[0]["message"]["content"] if choices else None
                        if not isinstance(output, str):
                            raise ValueError("invalid_chat_completion")
                    except (UnicodeDecodeError, ValueError, TypeError, KeyError, IndexError):
                        raw_response = response.content
                        self._persist_failure(
                            record_id=record.id,
                            error_code="provider_invalid_response",
                            safe_error="Provider returned an invalid chat completion response",
                            latency_ms=latency_ms,
                            raw_response=raw_response,
                            provider_secret=api_key,
                            attempt=attempt_base + retry_index,
                        )
                        raise RuntimeError("LLM provider returned an invalid response") from None
                    self._persist_success(
                        record_id=record.id,
                        raw_response=raw_response,
                        usage=body.get("usage") if isinstance(body.get("usage"), dict) else None,
                        response_id=body.get("id") if isinstance(body.get("id"), str) else None,
                        latency_ms=latency_ms,
                        parsed_output=output,
                        attempt=attempt_base + retry_index,
                    )
                    logger.info(
                        "Audited LLM attempt completed",
                        extra={
                            "event": "llm.call.completed",
                            "run_id": self.run_id,
                            "attempt": attempt_base + retry_index,
                        },
                    )
                    return output
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                latency_ms = round((time.perf_counter() - started) * 1000)
                error_code = (
                    "provider_timeout" if isinstance(exc, httpx.TimeoutException)
                    else "provider_connection_error"
                )
                self._persist_failure(
                    record_id=record.id,
                    error_code=error_code,
                    safe_error=type(exc).__name__,
                    latency_ms=latency_ms,
                    provider_secret=api_key,
                    attempt=attempt_base + retry_index,
                )
                logger.warning(
                    "LLM provider attempt failed",
                    extra={
                        "event": "llm.call.attempt_failed",
                        "run_id": self.run_id,
                        "attempt": attempt_base + retry_index,
                        "error_code": error_code,
                    },
                )
                last_error_code = error_code
                retryable = True
            if not retryable or retry_index >= settings.llm_max_retries:
                break
            time.sleep(delay)

        logger.warning(
            "Audited LLM call exhausted retries",
            extra={"event": "llm.call.failed", "run_id": self.run_id, "error_code": last_error_code},
        )
        raise RuntimeError(f"LLM provider call failed ({last_error_code})")


def get_llm(
    kind: str | None = None,
    *,
    settings: Settings | None = None,
    run_id: str | None = None,
    request_id: str | None = None,
    actor_id: str | None = None,
    job_id: str | None = None,
) -> LLMPort:
    if kind == "fake":
        return FakeLLM()
    settings = settings or load_settings()
    provider = kind or settings.llm_provider
    if provider in {"gateway", "openai_compatible"}:
        return GatewayLLM(
            settings,
            run_id=run_id,
            request_id=request_id,
            actor_id=actor_id,
            job_id=job_id,
        )
    if provider == "fake":
        return FakeLLM()
    raise ValueError(f"unknown llm backend '{provider}' (use fake or gateway)")
