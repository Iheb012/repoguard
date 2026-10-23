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
