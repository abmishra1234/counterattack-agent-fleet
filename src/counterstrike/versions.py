"""Version helpers. Matching is deterministic code, never an LLM decision."""

from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_LEADING_NUMERIC = re.compile(r"^(\d+(?:\.\d+)*)")
VERSION_TOKEN = re.compile(r"\b\d+\.\d+(?:\.\d+)*[a-z]?\b")


def tolerant_version(raw: str) -> tuple[Version | None, str | None]:
    """Parse a version; fall back to its numeric prefix (e.g. OpenSSL '1.1.1w' -> 1.1.1).

    Returns (version, note). note is set when the fallback was used; version is None when
    nothing numeric could be recovered.
    """
    try:
        return Version(raw), None
    except InvalidVersion:
        m = _LEADING_NUMERIC.match(raw.strip())
        if not m:
            return None, f"unparseable version '{raw}'"
        return Version(m.group(1)), f"'{raw}' compared as {m.group(1)} (suffix ignored)"


def parse_spec(spec: str) -> SpecifierSet | None:
    try:
        return SpecifierSet(spec)
    except InvalidSpecifier:
        return None


def is_affected(installed: Version, spec: SpecifierSet) -> bool:
    return spec.contains(installed, prereleases=True)


def versions_in(text: str) -> set[str]:
    return set(VERSION_TOKEN.findall(text))


def spec_versions(spec: str) -> set[str]:
    return set(re.findall(r"\d+(?:\.\d+)*", spec))
