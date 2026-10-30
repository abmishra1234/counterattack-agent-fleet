"""LLM port. Agents call `llm.complete(...)`; the backend is swappable.

* FakeLLM   - deterministic test double used in CI and the default demo (no network, no keys).
* GatewayLLM - any OpenAI-compatible /chat/completions endpoint (e.g. an enterprise AI gateway).
              Configure with LLM_BASE_URL, LLM_API_KEY, LLM_MODEL.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Protocol

NUM = r"(\d+(?:\.\d+)+)"


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
    """Minimal OpenAI-compatible client (stdlib only) so the repo needs no vendor SDK."""

    def __init__(self) -> None:
        self.base_url = os.environ["LLM_BASE_URL"].rstrip("/")
        self.api_key = os.environ["LLM_API_KEY"]
        self.model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.name = f"gateway:{self.model}"

    def complete(self, task: str, system: str, user: str, context: dict) -> str:
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if task == "extract":
            body["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - URL comes from config
            payload = json.load(resp)
        return payload["choices"][0]["message"]["content"]


def get_llm(kind: str) -> LLMPort:
    if kind == "fake":
        return FakeLLM()
    if kind == "gateway":
        return GatewayLLM()
    raise ValueError(f"unknown llm backend '{kind}' (use fake or gateway)")
