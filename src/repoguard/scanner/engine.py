"""Partner A: turn files into findings. Pure function: no disk, no network, no execution."""
from __future__ import annotations

import re

from repoguard.models import Files, Finding

MAX_SNIPPET = 120

# (rule_id, severity, compiled regex, explanation, advice)
LINE_RULES = [
    (
        "CODE-EVAL-EXEC",
        "medium",
        re.compile(r"\b(eval|exec)\s*\("),
        "Code that runs text as a program can hide what the project really does.",
        "Read what is being evaluated. Do not run this project until you understand it.",
    ),
    (
        "CODE-BASE64-BLOB",
        "medium",
        re.compile(r"[A-Za-z0-9+/=]{200,}"),
        "A very long encoded string is a common way to hide a malicious payload.",
        "Decode it safely in a disposable environment, or avoid the project.",
    ),
]


def scan_files(files: Files) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in files:
        for lineno, line in enumerate(content.splitlines(), start=1):
            for rule_id, severity, regex, why, advice in LINE_RULES:
                if regex.search(line):
                    findings.append(
                        Finding(rule_id, severity, path, lineno, line.strip()[:MAX_SNIPPET], why, advice)
                    )
    return findings
