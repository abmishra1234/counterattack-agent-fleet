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


def parse_ranges(spec: str) -> tuple[SpecifierSet, ...] | None:
    """Parse a union of specifier sets separated by '||' (feeds list disjoint ranges)."""
    parts = [part.strip() for part in spec.split("||")]
    if not all(parts):
        return None
    ranges = tuple(parse_spec(part) for part in parts)
    return None if any(r is None for r in ranges) else ranges  # type: ignore[return-value]


def matching_range(installed: Version, ranges: tuple[SpecifierSet, ...]) -> SpecifierSet | None:
    return next((r for r in ranges if is_affected(installed, r)), None)


def exclusive_upper_bound(spec: SpecifierSet) -> str | None:
    """The '<' bound of one range: the first fixed release when the range came from a feed."""
    bounds = [s.version for s in spec if s.operator == "<"]
    return bounds[0] if len(bounds) == 1 else None


def versions_in(text: str) -> set[str]:
    return set(VERSION_TOKEN.findall(text))


def spec_versions(spec: str) -> set[str]:
    return set(re.findall(r"\d+(?:\.\d+)*", spec))
