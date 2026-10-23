"""Shared contract between Partner A (scanner) and Partner B (fetcher/scoring/report).

Change this file only through a PR approved by BOTH partners.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# A "file" is a (relative_path, text_content) pair. Scanners never touch the disk or network.
FileItem = tuple[str, str]
Files = Iterable[FileItem]


@dataclass(frozen=True)
class Finding:
    """One suspicious thing found by the scanner (produced by Partner A)."""
    rule_id: str          # e.g. "CODE-EVAL-EXEC"
    severity: str         # "low" | "medium" | "high"
    file: str
    line: int
    snippet: str
    explanation: str      # plain-language: why this is dangerous
    advice: str           # plain-language: what to do


@dataclass
class RepoMeta:
    """Information about the repo/author (produced by Partner B)."""
    account_age_days: int | None = None
    commit_count: int | None = None
    stars: int | None = None
    is_fork: bool | None = None
    flags: list[str] = field(default_factory=list)   # e.g. ["single-commit", "new-account"]


@dataclass
class Risk:
    """Final verdict (produced by Partner B)."""
    level: str            # "low" | "medium" | "high"
    points: int
