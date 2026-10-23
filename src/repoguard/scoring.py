"""Partner B: combine findings and repo metadata into a risk level."""
from __future__ import annotations

from collections.abc import Sequence

from repoguard.models import Finding, RepoMeta, Risk

POINTS = {"low": 1, "medium": 3, "high": 8}


def score(findings: Sequence[Finding], meta: RepoMeta | None = None) -> Risk:
    points = sum(POINTS.get(f.severity, 0) for f in findings)
    if meta:
        points += 2 * len(meta.flags)
    level = "high" if points >= 8 else "medium" if points >= 3 else "low"
    return Risk(level=level, points=points)
