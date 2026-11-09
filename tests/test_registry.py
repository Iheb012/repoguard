from repoguard.scanner.registry import matches


def test_glob_matches_root_and_subfolder():
    assert matches("package.json", ("package.json",))
    assert matches("app/web/package.json", ("package.json",))
    assert matches(".vscode/tasks.json", (".vscode/tasks.json",))
    assert matches("x/.vscode/tasks.json", (".vscode/tasks.json",))


def test_glob_does_not_match_other_files():
    assert not matches("package-lock.json", ("package.json",))
    assert not matches("src/main.py", ("package.json",))
