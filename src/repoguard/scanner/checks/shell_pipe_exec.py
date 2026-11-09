"""SHELL-PIPE-EXEC: downloads a file and runs it immediately (curl | sh, iwr | iex)."""
from __future__ import annotations

import re

from repoguard.models import Finding
from repoguard.scanner.registry import rule

MAX_SNIPPET = 120
DOC_EXTENSIONS = (".md", ".markdown", ".rst", ".txt")

PATTERNS = [
    # bash: curl/wget ... | sh / bash / zsh (optionally with sudo)
    re.compile(
        r"\b(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b",
        re.IGNORECASE,
    ),
    # PowerShell: iwr/irm ... | iex
    re.compile(
        r"\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)\b",
        re.IGNORECASE,
    ),
    # PowerShell: iex (iwr ...)  or  iex (New-Object Net.WebClient).DownloadString(...)
    # Single collapsed whitespace class per gap — no adjacent \s quantifiers
    # that can split the same space run (that caused the iex timeouts).
    re.compile(
        r"\b(iex|invoke-expression)\b[\s(]{0,40}"
        r"(?:[\s(]{0,40}(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b"
        r"|[\s(]{0,40}new-object\s+net\.webclient)",
        re.IGNORECASE,
    ),
]

EXPLANATION = (
    "This downloads a file from the internet and runs it immediately, without giving you a "
    "chance to read it. The server can change the file at any time."
)
ADVICE = (
    "Do not run it. Download the file separately, read it, and only then decide. "
    "If you already ran it, treat the machine as compromised."
)
DOC_EXPLANATION = (
    "A documentation file suggests an install command that downloads and runs a script. "
    "This is common in legitimate projects, but it is exactly what attackers copy."
)
DOC_ADVICE = "Check that the URL belongs to the project's official site before running it."


@rule()
def shell_pipe_exec(path: str, content: str) -> list[Finding]:
    is_doc = path.lower().endswith(DOC_EXTENSIONS)
    findings: list[Finding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        if any(p.search(line) for p in PATTERNS):
            findings.append(
                Finding(
                    rule_id="SHELL-PIPE-EXEC",
                    severity="low" if is_doc else "high",
                    file=path,
                    line=lineno,
                    snippet=line.strip()[:MAX_SNIPPET],
                    explanation=DOC_EXPLANATION if is_doc else EXPLANATION,
                    advice=DOC_ADVICE if is_doc else ADVICE,
                )
            )
    return findings