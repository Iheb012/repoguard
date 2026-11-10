from repoguard.scanner import scan_files

RULE_ID = "UNICODE-HIDDEN"
RLO = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
ZWSP = "\u200b"  # ZERO WIDTH SPACE


def scan_one(path, content):
    return [f for f in scan_files([(path, content)]) if f.rule_id == RULE_ID]


# --- flagged ---------------------------------------------------------------------------

def test_bidi_override_in_code_is_high():
    found = scan_one("a.js", f"const a = 1; // {RLO}hidden\n")
    assert [f.severity for f in found] == ["high"]
    assert "202E" in found[0].explanation


def test_zero_width_space_in_code_is_medium():
    assert [f.severity for f in scan_one("a.py", f"x = 1{ZWSP}\n")] == ["medium"]


def test_bidi_in_docs_is_medium_and_invisible_in_docs_is_low():
    assert [f.severity for f in scan_one("README.md", f"hello {RLO}\n")] == ["medium"]
    assert [f.severity for f in scan_one("README.md", f"hello{ZWSP}\n")] == ["low"]


def test_other_invisible_characters_are_flagged():
    assert scan_one("a.js", "x\u2060y\n")  # word joiner
    assert scan_one("a.js", "x\u2062y\n")  # invisible times
    assert scan_one("a.js", "a\n" + "b\ufeffc\n")  # BOM in the middle of a file


def test_line_number_and_visible_snippet():
    found = scan_one("a.js", f"ok\nlet admin = false;{RLO} // x\n")
    assert len(found) == 1
    assert found[0].line == 2
    assert "<U+202E>" in found[0].snippet
    assert RLO not in found[0].snippet


def test_one_finding_per_line_even_with_many_characters():
    assert len(scan_one("a.js", f"a{ZWSP}{ZWSP}{RLO}b\n")) == 1


def test_findings_are_capped_per_file():
    content = "".join(f"x{ZWSP}\n" for _ in range(100))
    assert len(scan_one("a.js", content)) == 20


# --- benign: real text must not be flagged -----------------------------------------------

def test_arabic_text_is_fine():
    assert not scan_one("a.md", "مرحبا بكم في المشروع\n")


def test_arabic_with_direction_marks_is_fine():
    assert not scan_one("a.md", "مرحبا \u200f(hello)\u200e بكم\n")  # RLM / LRM
    assert not scan_one("a.md", "مرحبا\u061c بكم\n")  # Arabic letter mark


def test_persian_zwnj_and_emoji_zwj_are_fine():
    assert not scan_one("a.md", "می\u200cخواهم\n")  # ZWNJ
    assert not scan_one("a.md", "family: \U0001f468\u200d\U0001f469\u200d\U0001f467\n")  # ZWJ


def test_french_accents_are_fine():
    assert not scan_one("a.md", "Bienvenue à tous, été prêt, garçon, naïve, œuvre\n")


def test_bom_at_start_of_file_is_fine():
    assert not scan_one("a.js", "\ufeffconsole.log(1)\n")


def test_empty_file_does_not_crash():
    assert scan_one("a.js", "") == []
