from pathlib import Path

from repoguard.cli import main

FIXTURES = str(Path(__file__).parent / "fixtures")


def test_scan_fixture_flags_it(capsys):
    code = main(["scan", FIXTURES])
    out = capsys.readouterr().out
    assert "CODE-EVAL-EXEC" in out
    assert code in (0, 1)
