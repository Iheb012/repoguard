"""NPM-LIFECYCLE-SCRIPT: package.json scripts that run automatically on `npm install`.

Install-time scripts are the favourite trick of fake-interview repos: the victim only runs
`npm install` and the malware starts. Severity depends on WHAT the script does:

  high   downloads files, pipes into a shell, decodes base64, runs inline code, PowerShell/cmd
  medium runs a program or script file (node setup.js, bash ./x.sh, ./run)
  low    runs some other command (informational)
  none   known-benign tools (husky, patch-package, tsc, node-gyp, ...)

`npm run <name>` is followed into the referenced script, so hiding behind it does not work.
"""
from __future__ import annotations

import json
import re

from repoguard.models import Finding
from repoguard.scanner.registry import rule

RULE_ID = "NPM-LIFECYCLE-SCRIPT"
MAX_SNIPPET = 120
MAX_DEPTH = 3  # how many `npm run x` hops to follow

# Scripts npm runs by itself during a plain `npm install` of a project.
LIFECYCLE = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
)
RANK = {"low": 1, "medium": 2, "high": 3}

# (regex, short description). Checked against the whole command first.
HIGH = [
    (
        re.compile(
            r"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|certutil|bitsadmin)\b",
            re.IGNORECASE,
        ),
        "downloads files from the internet",
    ),
    (re.compile(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.IGNORECASE), "pipes data into a shell"),
    (
        re.compile(r"\b(atob|base64|b64decode|frombase64string)\b", re.IGNORECASE),
        "decodes hidden (base64) data",
    ),
    (
        re.compile(r"\beval\b|\bnode(js)?\s+(-e|--eval|-p|--print)\b|\bpython3?\s+-c\b", re.IGNORECASE),
        "runs inline code",
    ),
    (re.compile(r"\b(powershell|pwsh)\b|\bcmd(\.exe)?\s+/c\b", re.IGNORECASE), "starts PowerShell or cmd"),
]

# An interpreter followed by a file, or a direct path such as ./run.sh
RUN_FILE = re.compile(
    r"(?:^|\s)(?:node(?:js)?|python3?|bash|sh|zsh|ruby|perl|php)\s+(?:-\S+\s+)*\S+"
    r"|^\s*\.{0,2}[/\\]\S+",
    re.IGNORECASE,
)

# Commands that are normal in lifecycle scripts (must match the whole command segment).
SAFE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"husky(\s+install)?(\s+[\w./-]+)?",
        r"is-ci",
        r"lefthook\s+install",
        r"simple-git-hooks",
        r"patch-package",
        r"tsc(\s+[^&|;]*)?",
        r"node-gyp(\s+(rebuild|build))?",
        r"node-gyp-build",
        r"prebuild-install(\s+[^&|;]*)?",
        r"npx\s+only-allow\s+\w+",
    )
]

SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\|")
RUN_SCRIPT = re.compile(r"(?:npm|pnpm|yarn|bun)(?:\s+run(?:-script)?)?\s+([\w:.-]+)(?:\s+--.*)?", re.IGNORECASE)

EXPLANATIONS = {
    "high": (
        'The "{key}" script runs automatically when someone installs this project, '
        "and it {why}. Attackers use install scripts to infect developers who only "
        "wanted to look at the code."
    ),
    "medium": (
        'The "{key}" script runs automatically on install and {why}. '
        "Some real packages do this, but attackers rely on it too."
    ),
    "low": (
        'The "{key}" script runs automatically on install and {why}. '
        "This is usually a harmless build or setup step, but you should know it exists."
    ),
}

ADVICE = {
    "high": (
        "Do not run npm/yarn/pnpm install here. Read the script first. "
        "If you must install, use `npm install --ignore-scripts`."
    ),
    "medium": (
        "Read the file that the script runs before installing. "
        "Installing with `--ignore-scripts` stops it from running."
    ),
    "low": (
        "Check the command if you do not recognise it. "
        "`--ignore-scripts` skips install scripts."
    ),
}


def evaluate(cmd: str, scripts: dict, seen: frozenset = frozenset(), depth: int = 0):
    """Return (severity, why) for the worst thing in this command, or None if it looks benign."""
    cmd = cmd.strip()
    if not cmd:
        return None
    for regex, why in HIGH:
        if regex.search(cmd):
            return "high", why

    worst = None
    for segment in SEGMENT_SPLIT.split(cmd):
        segment = segment.strip()
        if not segment or any(rx.fullmatch(segment) for rx in SAFE):
            continue
        match = RUN_SCRIPT.fullmatch(segment)
        if match:  # `npm run x`: judge what x does
            name = match.group(1)
            target = scripts.get(name)
            if isinstance(target, str) and name not in seen and depth < MAX_DEPTH:
                result = evaluate(target, scripts, seen | {name}, depth + 1)
            else:
                result = None
        elif RUN_FILE.search(segment):
            result = ("medium", f"runs a program or script file ({segment})")
        else:
            result = ("low", f"runs `{segment}`")
        if result and (worst is None or RANK[result[0]] > RANK[worst[0]]):
            worst = result
    return worst


def key_line(lines: list[str], key: str) -> int:
    """1-based line of `"key":` inside the "scripts" block (1 if not found)."""
    start = next((i for i, line in enumerate(lines) if re.search(r'"scripts"\s*:', line)), 0)
    pattern = re.compile(r'"' + re.escape(key) + r'"\s*:')
    for i in range(start, len(lines)):
        if pattern.search(lines[i]):
            return i + 1
    return 1


@rule("package.json")
def npm_lifecycle(path: str, content: str) -> list[Finding]:
    try:
        data = json.loads(content.lstrip("\ufeff"))
    except ValueError:
        return []  # not valid JSON: npm would not run it either
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []

    lines = content.splitlines()
    findings: list[Finding] = []
    for key, cmd in scripts.items():
        if key not in LIFECYCLE or not isinstance(cmd, str):
            continue
        result = evaluate(cmd, scripts, seen=frozenset({key}))
        if result is None:
            continue
        severity, why = result
        n = key_line(lines, key)
        snippet = lines[n - 1].strip() if n <= len(lines) else f'"{key}": "{cmd}"'
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=severity,
                file=path,
                line=n,
                snippet=snippet[:MAX_SNIPPET],
                explanation=EXPLANATIONS[severity].format(key=key, why=why),
                advice=ADVICE[severity],
            )
        )
    return findings
