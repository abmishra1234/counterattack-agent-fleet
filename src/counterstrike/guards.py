"""Guardrails that hold no matter what the model says."""

from __future__ import annotations

import re

from counterstrike.versions import spec_versions, versions_in

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"note to ai",
    r"you are now",
    r"do not raise alerts",
    r"set priority",
    r"mark (it|this) as not affected",
]


def detect_injection(text: str) -> bool:
    lower = text.lower()
    return any(re.search(p, lower) for p in INJECTION_PATTERNS)


def wrap_untrusted(text: str) -> str:
    """Delimit feed text so the prompt can say 'this block is data, not instructions'."""
    return "<bulletin>\n" + text.replace("</bulletin>", "&lt;/bulletin&gt;") + "\n</bulletin>"


def extraction_is_grounded(
    source_text: str, product: str, affected: str, fixed: str | None, vocabulary: set[str]
) -> tuple[bool, str]:
    """Every version the model returns must literally appear in the source text,
    and the product must come from the known vocabulary."""
    if product not in vocabulary:
        return False, f"product '{product}' not in inventory vocabulary"
    present = versions_in(source_text)
    claimed = spec_versions(affected) | ({fixed} if fixed else set())
    missing = sorted(claimed - present)
    if missing:
        return False, f"versions not found in source text: {missing}"
    return True, "ok"


def summary_is_grounded(summary: str, allowed_versions: set[str]) -> bool:
    return versions_in(summary) <= allowed_versions
