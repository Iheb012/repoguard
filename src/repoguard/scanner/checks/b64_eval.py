"""CODE-B64-EVAL: decodes hidden (base64) text and runs it as code.

Neither half is suspicious alone (decoding base64 is normal; eval is common), so the rule only
fires when a decode and an execution appear within WINDOW lines of each other.
"""
from __future__ import annotations

import re

from repoguard.models import Finding
from repoguard.scanner.registry import rule

RULE_ID = "CODE-B64-EVAL"
WINDOW = 10  # max distance in lines between the decode and the execution (either order)
MAX_SNIPPET = 120

# Decoding: atob(...), b64decode(...) (also base64.b64decode, urlsafe_b64decode, window.atob),
# and Buffer.from(..., 'base64') in single or double quotes.
DECODE = re.compile(
    r"(?<![A-Za-z0-9])(?:atob|b64decode)\s*\("
    r"|Buffer\.from\(.*['\"]base64(?:url)?['\"]"
)

# Execution: a bare eval( / exec( / Function( call. The lookbehind rejects method calls and
# longer names: model.eval(), pattern.exec(), ast.literal_eval(), $eval(.
EXEC = re.compile(r"(?<![\w.$])(?:eval|exec|Function)\s*\(")

EXPLANATION = (
    "This file decodes hidden (base64) text and then runs it as code. Attackers use this to "
    "hide malware from anyone reading the source."
)
ADVICE = (
    "Do not run this project. If you must investigate, decode the string in a disposable, "
    "offline environment to see what it does."
)


@rule()
def b64_eval(path: str, content: str) -> list[Finding]:
    lines = content.splitlines()
    decode_lines = [n for n, line in enumerate(lines, start=1) if DECODE.search(line)]
    if not decode_lines:
        return []

    findings: list[Finding] = []
    for n, line in enumerate(lines, start=1):
        if EXEC.search(line) and any(abs(n - d) <= WINDOW for d in decode_lines):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity="high",
                    file=path,
                    line=n,  # the execution line, not the decode line
                    snippet=line.strip()[:MAX_SNIPPET],
                    explanation=EXPLANATION,
                    advice=ADVICE,
                )
            )
    return findings
