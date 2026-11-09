"""The two original starter rules, moved here unchanged (except eval is now low severity)."""
from __future__ import annotations

import re

from repoguard.models import Finding
from repoguard.scanner.registry import rule

MAX_SNIPPET = 120

# (rule_id, severity, regex, explanation, advice)
LINE_RULES = [
    (
        "CODE-EVAL-EXEC",
        "low",  # a lone eval is very common and noisy; paired rules will cover the dangerous cases
        re.compile(r"(?<![\w.$])(eval|exec)\s*\("),
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


@rule()  # no globs = runs on every file
def line_rules(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        for rule_id, severity, regex, why, advice in LINE_RULES:
            if regex.search(line):
                findings.append(
                    Finding(rule_id, severity, path, lineno, line.strip()[:MAX_SNIPPET], why, advice)
                )
    return findings
