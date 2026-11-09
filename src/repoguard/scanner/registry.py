"""Rule registry: rules register themselves with @rule and the engine runs the matching ones."""
from __future__ import annotations

from collections.abc import Callable
from fnmatch import fnmatch

from repoguard.models import Finding

# A check receives (path, content) and returns zero or more findings.
Check = Callable[[str, str], list[Finding]]

RULES: list[tuple[tuple[str, ...], Check]] = []


def rule(*globs: str) -> Callable[[Check], Check]:
    """Register a check. It runs on files whose path matches one of the globs (default: all)."""

    def register(fn: Check) -> Check:
        RULES.append((globs or ("*",), fn))
        return fn

    return register


def matches(path: str, globs: tuple[str, ...]) -> bool:
    """True if path matches a glob, either from the repo root or inside any subfolder."""
    return any(fnmatch(path, g) or fnmatch(path, "*/" + g) for g in globs)


def checks_for(path: str) -> list[Check]:
    return [fn for globs, fn in RULES if matches(path, globs)]
