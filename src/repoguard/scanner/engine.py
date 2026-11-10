"""Partner A: turn files into findings. Pure function: no disk, no network, no execution."""
from __future__ import annotations

from repoguard.models import Files, Finding

from . import checks  # noqa: F401  (importing registers all rules)
from .registry import checks_for


def scan_files(files: Files) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in files:
        path = path.replace("\\", "/")  # Windows paths use backslashes
        for check in checks_for(path):
            findings.extend(check(path, content))
    return findings
