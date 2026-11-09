from repoguard.models import Finding
from repoguard.scanner import scan_files


def test_detects_eval():
    findings = scan_files([("a.py", "x = eval('1+1')\n")])
    assert [f.rule_id for f in findings] == ["CODE-EVAL-EXEC"]
    assert isinstance(findings[0], Finding)
    assert findings[0].line == 1


def test_detects_long_blob():
    findings = scan_files([("b.js", "var p = '" + "A" * 250 + "';")])
    assert any(f.rule_id == "CODE-BASE64-BLOB" for f in findings)


def test_clean_file_has_no_findings():
    assert scan_files([("ok.py", "print('hello')\n")]) == []


def test_eval_method_calls_are_not_flagged():
    # model.eval() (PyTorch), pattern.exec() (JS regex), ast.literal_eval() are not the builtin
    for code in ("model.eval()\n", "m = pattern.exec(text)\n", "v = ast.literal_eval(s)\n"):
        assert scan_files([("a.py", code)]) == []
