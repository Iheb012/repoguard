"""UNICODE-HIDDEN: invisible or text-direction-changing characters.

Only characters with no legitimate use in normal Arabic / French / English text are flagged:
  bidi controls (U+202A-202E, U+2066-2069)  -> "Trojan Source": code reads differently than it runs
  invisible characters (U+200B, U+2060-2064, U+FEFF inside a file)

NOT flagged, because real text needs them: U+200C / U+200D (Persian, Hindi, emoji sequences),
U+200E / U+200F / U+061C (left-to-right / right-to-left marks used in Arabic text).
"""
from __future__ import annotations

import unicodedata

from repoguard.models import Finding
from repoguard.scanner.registry import rule

RULE_ID = "UNICODE-HIDDEN"
MAX_SNIPPET = 120
MAX_FINDINGS = 20  # per file, so one noisy file cannot flood a report
DOC_EXTENSIONS = (".md", ".markdown", ".rst", ".txt")

BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
INVISIBLE = {0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}

# kind -> (severity in code/config files, severity in documentation)
SEVERITY = {"bidi": ("high", "medium"), "invisible": ("medium", "low")}

EXPLANATIONS = {
    "bidi": (
        "This line contains hidden text-direction control characters ({names}). In source code "
        "they can make the code look different from what actually runs (the 'Trojan Source' trick)."
    ),
    "invisible": (
        "This line contains invisible characters ({names}). Attackers use them to hide code or "
        "to disguise names; most editors show nothing."
    ),
}
ADVICE = (
    "Open the file in an editor that shows invisible characters, remove them, and compare with a "
    "trusted copy. Do not run the code until you know why they are there."
)


def _describe(ch: str) -> str:
    return f"U+{ord(ch):04X} {unicodedata.name(ch, 'UNKNOWN')}"


@rule()
def unicode_hidden(path: str, content: str) -> list[Finding]:
    is_doc = path.lower().endswith(DOC_EXTENSIONS)
    findings: list[Finding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        hits = []
        for col, ch in enumerate(line):
            code = ord(ch)
            if code == 0xFEFF and lineno == 1 and col == 0:
                continue  # a byte order mark at the very start of a file is normal
            if code in BIDI:
                hits.append(("bidi", ch))
            elif code in INVISIBLE:
                hits.append(("invisible", ch))
        if not hits:
            continue

        kind = "bidi" if any(k == "bidi" for k, _ in hits) else "invisible"
        names = ", ".join(sorted({_describe(ch) for _, ch in hits}))
        visible = line
        for ch in {ch for _, ch in hits}:
            visible = visible.replace(ch, f"<U+{ord(ch):04X}>")
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=SEVERITY[kind][1 if is_doc else 0],
                file=path,
                line=lineno,
                snippet=visible.strip()[:MAX_SNIPPET],
                explanation=EXPLANATIONS[kind].format(names=names),
                advice=ADVICE,
            )
        )
        if len(findings) >= MAX_FINDINGS:
            break
    return findings
