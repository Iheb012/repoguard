"""ENV-EXFIL: environment variables (often secrets) sent over the network.

Reading `process.env.PORT` and calling `fetch` is normal, so the rule is deliberately narrow:
  high  the WHOLE environment (process.env / os.environ as an object, printenv) near a network call
  high  any env access near a network call AND a known data-collection address (webhook, bot API)
  low   a secret-looking variable (TOKEN, SECRET, ...) near a network call
  nothing for ordinary named variables like process.env.PORT
"""
from __future__ import annotations

import re

from repoguard.models import Finding
from repoguard.scanner.proximity import near
from repoguard.scanner.registry import rule

RULE_ID = "ENV-EXFIL"
WINDOW = 10
MAX_SNIPPET = 120
DOC_EXTENSIONS = (".md", ".markdown", ".rst", ".txt")

ENV_ACCESS = re.compile(r"process\.env\b|os\.environ\b|os\.getenv\s*\(|System\.getenv\s*\(|\bgetenv\s*\(")

# The environment used as a whole object (not process.env.X / process.env["X"] / os.environ.get).
DUMP = [
    re.compile(r"process\.env\b(?!\s*\??\.|\s*\[)"),
    re.compile(r"os\.environ\b(?!\s*\.|\s*\[)"),
    re.compile(r"os\.environ\.(copy|items|keys|values)\s*\("),
    re.compile(r"System\.getenv\s*\(\s*\)"),
    re.compile(r"\bprintenv\b|\benv\s*\|"),
]
# Lines that look like a dump but are ordinary named access.
NOT_DUMP = re.compile(r"\{[^}]{0,200}\}\s{0,20}=\s{0,20}(process\.env|os\.environ)|\bin\s+(process\.env|os\.environ)")

NETWORK = re.compile(
    r"\bfetch\s*\(|\baxios\b|\brequests\.(get|post|put|request)\b|\bhttps?\.(request|get)\s*\("
    r"|\burllib\.request\b|\burlopen\s*\(|\bXMLHttpRequest\b|\bhttpx\.|\bnew\s+WebSocket\b"
    r"|\bsocket\.(connect|create_connection)\b|\bcurl\b|\bwget\b",
    re.IGNORECASE,
)
SINK = re.compile(
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|requestbin"
    r"|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com|transfer\.sh|interact\.sh"
    r"|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net"
    r"|https?://(?!127\.|10\.|192\.168\.|0\.0\.0\.0|172\.(?:1[6-9]|2\d|3[01])\.)"
    r"\d{1,3}(?:\.\d{1,3}){3}",
    re.IGNORECASE,
)
SENSITIVE = re.compile(
    r"token|secret|passw(?:or)?d|api[_-]?key|private[_-]?key|credential|aws_|github|ssh",
    re.IGNORECASE,
)

FINDING_TEXT = {
    "dump": (
        "high",
        (
            "sends the whole set of environment variables, which often holds passwords and keys, "
            "over the network"
        ),
    ),
    "sink": (
        "high",
        "sends environment variables to an address commonly used to collect stolen data",
    ),
    "secret": ("low", "sends a secret-looking environment variable over the network"),
}
EXPLANATION = "This code {why}. Malware uses this to steal credentials from the machine that runs it."
ADVICE = (
    "Do not run this code. Check where the data is sent. If you already ran it, "
    "rotate any keys and tokens that were in your environment."
)


def _is_dump(line: str) -> bool:
    return any(rx.search(line) for rx in DUMP) and not NOT_DUMP.search(line)


@rule()
def env_exfil(path: str, content: str) -> list[Finding]:
    if path.lower().endswith(DOC_EXTENSIONS):
        return []
    lines = content.splitlines()
    numbered = list(enumerate(lines, start=1))
    network = [n for n, ln in numbered if NETWORK.search(ln)]
    if not network:
        return []

    dumps = [n for n, ln in numbered if _is_dump(ln)]
    dump_set = set(dumps)
    access = [n for n, ln in numbered if n in dump_set or ENV_ACCESS.search(ln)]
    sinks = [n for n, ln in numbered if SINK.search(ln)]
    secrets = [n for n, ln in numbered if ENV_ACCESS.search(ln) and SENSITIVE.search(ln)]

    findings: list[Finding] = []
    for n in network:
        if near(n, dumps, WINDOW):
            kind = "dump"
        elif near(n, access, WINDOW) and near(n, sinks, WINDOW):
            kind = "sink"
        elif near(n, secrets, WINDOW):
            kind = "secret"
        else:
            continue
        severity, why = FINDING_TEXT[kind]
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=severity,
                file=path,
                line=n,
                snippet=lines[n - 1].strip()[:MAX_SNIPPET],
                explanation=EXPLANATION.format(why=why),
                advice=ADVICE,
            )
        )
    return findings
