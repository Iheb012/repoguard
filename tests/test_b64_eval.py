from repoguard.scanner import scan_files

RULE_ID = "CODE-B64-EVAL"
WINDOW = 10  # must match scanner/checks/b64_eval.py


def scan_one(path, content):
    return [f for f in scan_files([(path, content)]) if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# 1. Window boundaries
# ---------------------------------------------------------------------------

def _gap_block(decode_line: int, exec_line: int) -> str:
    """Build content with atob on decode_line and eval( on exec_line (1-based)."""
    assert exec_line > decode_line
    return (
        'atob("ZXZhbA==");\n'
        + "\n" * (exec_line - decode_line - 1)
        + "eval(s);\n"
    )


def test_decode_and_exec_exactly_WINDOW_lines_apart_is_flagged():
    found = scan_one("a.js", _gap_block(1, 1 + WINDOW))
    assert len(found) == 1
    assert found[0].line == 1 + WINDOW


def test_decode_and_exec_WINDOW_plus_one_lines_apart_is_not_flagged():
    assert not scan_one("a.js", _gap_block(1, 1 + WINDOW + 1))


# ---------------------------------------------------------------------------
# 2. Reversed order (eval before decode) — symmetric window
# ---------------------------------------------------------------------------

def test_exec_before_decode_within_window_is_flagged():
    content = "eval(s);\n" + "\n" * 3 + 'atob("ZXZhbA==");\n'
    found = scan_one("a.js", content)
    assert len(found) == 1
    assert found[0].line == 1  # points at the exec line


def test_exec_before_decode_outside_window_is_not_flagged():
    content = "eval(s);\n" + "\n" * (WINDOW + 2) + 'atob("ZXZhbA==");\n'
    assert not scan_one("a.js", content)


# ---------------------------------------------------------------------------
# 3. Finding counts
# ---------------------------------------------------------------------------

def test_two_decodes_near_one_exec_yields_one_finding():
    content = (
        'atob("AA==");\n'
        'atob("BB==");\n'
        "eval(s);\n"
    )
    found = scan_one("a.js", content)
    assert len(found) == 1
    assert found[0].line == 3


def test_one_decode_near_two_execs_yields_two_findings():
    content = (
        'atob("AA==");\n'
        "eval(a);\n"
        "eval(b);\n"
    )
    found = scan_one("a.js", content)
    assert len(found) == 2
    assert sorted(f.line for f in found) == [2, 3]


# ---------------------------------------------------------------------------
# 4. Benign near-misses (word-boundary / lookbehind)
# ---------------------------------------------------------------------------

def test_pytorch_model_eval_near_b64decode_is_fine():
    content = (
        "payload = base64.b64decode(blob)\n"
        "model.eval()\n"
    )
    assert not scan_one("m.py", content)


def test_js_regex_exec_near_atob_is_fine():
    content = (
        'const data = atob(input);\n'
        "const m = pattern.exec(text);\n"
    )
    assert not scan_one("a.js", content)


def test_literal_eval_near_b64decode_is_fine():
    content = (
        "import ast\n"
        "data = base64.b64decode(blob)\n"
        "value = ast.literal_eval(data)\n"
    )
    assert not scan_one("a.py", content)


def test_bare_eval_at_start_of_file_is_flagged():
    # guards against the lookbehind being wrong at position 0
    found = scan_one("a.js", 'atob("AA==");\neval(s);\n')
    assert len(found) == 1


# ---------------------------------------------------------------------------
# 5. More decode / exec variants
# ---------------------------------------------------------------------------

def test_imported_b64decode_is_detected():
    content = (
        "from base64 import b64decode\n"
        "exec(b64decode(x))\n"
    )
    assert scan_one("a.py", content)


def test_buffer_from_double_quotes_is_detected():
    content = (
        'const raw = Buffer.from(x, "base64");\n'
        "eval(raw.toString());\n"
    )
    assert scan_one("a.js", content)


def test_plain_Function_without_new_is_detected():
    content = (
        'const s = atob(input);\n'
        "Function(s)();\n"
    )
    assert scan_one("a.js", content)


# ---------------------------------------------------------------------------
# Original cases (kept — they protect against a typo'd RULE_ID)
# ---------------------------------------------------------------------------

def test_same_line_js_eval_atob_is_high():
    found = scan_one("a.js", 'eval(atob("ZXZhbA=="))\n')
    assert len(found) == 1
    assert found[0].severity == "high"
    assert found[0].line == 1


def test_python_exec_b64decode_is_high():
    found = scan_one("a.py", "exec(base64.b64decode(payload))\n")
    assert len(found) == 1
    assert found[0].severity == "high"


def test_node_decode_and_run_on_separate_lines_is_high():
    content = (
        "const raw = Buffer.from(x, 'base64');\n"
        "const s = raw.toString();\n"
        "// comment\n"
        "new Function(s)();\n"
    )
    assert scan_one("a.js", content)


def test_decode_early_run_within_window_is_high():
    content = 'atob("ZXZhbA==");\n' + "\n" * 6 + "eval(s);\n"
    assert scan_one("a.js", content)


def test_decode_only_is_fine():
    assert not scan_one("upload.js", "const data = atob(input);\n")


def test_eval_only_is_fine():
    assert not scan_one("eval.js", "eval(userInput);\n")


def test_decode_and_eval_too_far_apart_is_fine():
    content = 'atob("ZXZhbA==");\n' + "\n" * 38 + "eval(s);\n"
    assert not scan_one("a.js", content)


def test_empty_file_does_not_crash():
    assert not scan_one("empty.js", "")


def test_finding_line_is_the_exec_line_not_the_decode_line():
    content = 'atob("ZXZhbA==");\n' + "\n" * 3 + "eval(s);\n"
    found = scan_one("a.js", content)
    assert len(found) == 1
    assert found[0].line == 5