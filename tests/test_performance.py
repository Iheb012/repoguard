"""RepoGuard scans UNTRUSTED files, so a hostile file must never make the scanner hang.

Each case below froze or slowed an earlier version of a rule (unbounded regex gaps). Every case
runs in its own process that is killed after LIMIT seconds, so a bad pattern makes the test FAIL
instead of freezing pytest. If one fails, a pattern has an unbounded `.*` / `[^x]*` / adjacent
`\\s*`; bound it, e.g. `{0,200}`.
"""
import multiprocessing

import pytest

from repoguard.scanner import scan_files
from repoguard.scanner.proximity import near

SIZE = 200_000
LIMIT = 5.0  # seconds, including starting the helper process. A linear scan needs well under 1 s.

CASES = {
    "buffer_from_repeated": ("a.js", "Buffer.from(" * (SIZE // 12)),
    "curl_repeated": ("a.sh", "curl " * (SIZE // 5)),
    "iwr_repeated": ("a.ps1", "iwr " * (SIZE // 4)),
    "iex_then_spaces": ("a.ps1", "iex" + " " * SIZE),
    "iex_paren_spaces": ("a.ps1", "iex (" + " " * SIZE),
    "zero_width_run": ("a.js", "\u200b" * SIZE),
    "open_braces_with_env": ("a.js", "process.env " + "{" * SIZE + " fetch("),
    "unterminated_comment": (".vscode/tasks.json", "/*" + "x" * SIZE),
    "comma_whitespace": (".vscode/tasks.json", '{"a": [1' + ",  " * (SIZE // 3) + "]}"),
    "many_lines": ("a.js", "atob(x);\neval(y);\nfetch(u);\n" * (SIZE // 30)),
    "many_decode_exec_pairs": ("a.js", "atob(x);\neval(y);\nfetch(u);\n" * 20_000),
    "many_env_dumps": (
        "a.js",
        "const e = JSON.stringify(process.env);\nfetch(u, { body: e });\n" * 20_000,
    ),
    "huge_package_json_script": (
        "package.json",
        '{"scripts": {"postinstall": "node ' + "-a " * (SIZE // 3) + 'x.js"}}',
    ),
}


def _scan(path, content):
    scan_files([(path, content)])


def finishes_within_limit(path, content):
    proc = multiprocessing.Process(target=_scan, args=(path, content))
    proc.start()
    proc.join(LIMIT)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return False
    return True


@pytest.mark.parametrize("name", CASES)
def test_hostile_input_is_scanned_quickly(name):
    path, content = CASES[name]
    assert finishes_within_limit(path, content), f"{name}: scan took longer than {LIMIT} s"


def test_proximity_helper():
    assert near(10, [1, 20], 10)  # 10 away from both
    assert near(10, [1], 9)  # |10 - 1| = 9
    assert not near(10, [1], 8)
    assert not near(10, [], 10)
    assert near(5, [5], 0)
