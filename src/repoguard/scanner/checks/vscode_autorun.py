"""VSCODE-AUTORUN-TASK: .vscode/tasks.json that runs a command as soon as the folder is opened.

A task with `"runOptions": {"runOn": "folderOpen"}` starts by itself when the folder is opened
in VS Code. Fake-interview repos use it so that merely opening the project infects you.

tasks.json is JSONC (comments and trailing commas allowed), so it is cleaned before parsing.
The task's command is judged with the same classifier as npm lifecycle scripts; because nothing
asked the user to run it, the severity is one step higher than there.
"""
from __future__ import annotations

import json
import re

from repoguard.models import Finding
from repoguard.scanner.registry import rule

from .npm_lifecycle import RANK, evaluate

RULE_ID = "VSCODE-AUTORUN-TASK"
MAX_SNIPPET = 120
OS_KEYS = ("windows", "linux", "osx")
AUTORUN_LINE = re.compile(r'"runOn"\s*:\s*"folderOpen"', re.IGNORECASE)

# npm-lifecycle severity -> severity when it runs on folder open
BUMP = {"high": "high", "medium": "high", "low": "medium"}

EXPLANATION = (
    'VS Code is set to run the task "{label}" automatically as soon as this folder is opened, '
    "and it {why}. Fake-interview repos use this so that just opening the project infects you."
)
ADVICE = (
    "Do not trust this folder in VS Code (stay in Restricted Mode) until you have read "
    ".vscode/tasks.json. Delete the runOptions block if you do not need it."
)


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas. Line numbers stay the same."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.extend("\n" if ch == "\n" else " " for ch in text[i:end])
            i = end
        else:
            out.append(c)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    out = list(text)
    in_string = False
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                out[i] = " "
        i += 1
    return "".join(out)


def _arg_text(arg: object) -> str:
    if isinstance(arg, str):
        return arg
    if isinstance(arg, dict):
        return str(arg.get("value", ""))
    return ""


def _join(command: object, args: object) -> str:
    parts = [command] if isinstance(command, str) else []
    if isinstance(args, list):
        parts += [_arg_text(a) for a in args]
    return " ".join(p for p in parts if p).strip()


def commands_for(task: dict, by_label: dict, seen: frozenset) -> list[str]:
    """All command lines this task can run: its own, OS overrides, and tasks it depends on."""
    cmds = [_join(task.get("command"), task.get("args"))]
    for key in OS_KEYS:
        override = task.get(key)
        if isinstance(override, dict):
            cmds.append(
                _join(
                    override.get("command", task.get("command")),
                    override.get("args", task.get("args")),
                )
            )
    deps = task.get("dependsOn")
    for dep in [deps] if isinstance(deps, (str, dict)) else deps or []:
        label = dep.get("task") if isinstance(dep, dict) else dep
        target = by_label.get(label) if isinstance(label, str) else None
        if target is not None and label not in seen:
            cmds += commands_for(target, by_label, seen | {label})
    return [c for c in cmds if c]


def judge(cmds: list[str]) -> tuple[str, str]:
    best: tuple[str, str] | None = None
    for cmd in cmds:
        result = evaluate(cmd, {})
        severity, why = ("low", f"runs `{cmd}`") if result is None else (BUMP[result[0]], result[1])
        if best is None or RANK[severity] > RANK[best[0]]:
            best = (severity, why)
    return best or ("medium", "has no command that could be read")


def _finding(path, line, raw_lines, severity, label, why):
    snippet = raw_lines[line - 1].strip() if line <= len(raw_lines) else ""
    return Finding(
        rule_id=RULE_ID,
        severity=severity,
        file=path,
        line=line,
        snippet=snippet[:MAX_SNIPPET],
        explanation=EXPLANATION.format(label=label, why=why),
        advice=ADVICE,
    )


@rule(".vscode/tasks.json")
def vscode_autorun(path: str, content: str) -> list[Finding]:
    cleaned = strip_jsonc(content.lstrip("\ufeff"))
    raw_lines = content.lstrip("\ufeff").splitlines()
    autorun_lines = [i for i, ln in enumerate(cleaned.splitlines(), 1) if AUTORUN_LINE.search(ln)]
    if not autorun_lines:
        return []

    try:
        data = json.loads(cleaned)
    except ValueError:  # cannot read it, but it does ask to run on folder open
        why = "runs something (the file could not be fully read, so the command is unknown)"
        return [_finding(path, n, raw_lines, "high", "?", why) for n in autorun_lines]

    tasks = [t for t in data.get("tasks", []) if isinstance(t, dict)] if isinstance(data, dict) else []
    by_label = {t["label"]: t for t in tasks if isinstance(t.get("label"), str)}

    findings: list[Finding] = []
    autorun_tasks = [
        t
        for t in tasks
        if isinstance(t.get("runOptions"), dict)
        and str(t["runOptions"].get("runOn", "")).lower() == "folderopen"
    ]
    for index, task in enumerate(autorun_tasks):
        label = task.get("label", "(unnamed)")
        seen = frozenset({label}) if isinstance(label, str) else frozenset()
        severity, why = judge(commands_for(task, by_label, seen))
        line = autorun_lines[index] if index < len(autorun_lines) else autorun_lines[-1]
        findings.append(_finding(path, line, raw_lines, severity, label, why))
    return findings
