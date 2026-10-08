"""Phase 6/8 - web application (FastAPI) tested in-process with TestClient."""

import re

import pytest
from fastapi.testclient import TestClient

from app import main as web
from app.config.settings import AnalyzerSettings
from app.main import MAX_FILE_BYTES, MAX_FILES, create_app, sanitize_filename, UploadError
from app.storage import ScanStore, is_valid_scan_id

VULNERABLE = b"import os\ncommand = input('Command: ')\nos.system(command)\n"


@pytest.fixture
def client(tmp_path) -> TestClient:
    app = create_app(settings=AnalyzerSettings.load(), store=ScanStore(tmp_path / "scans"))
    return TestClient(app)


def upload(client: TestClient, files=(), code: str = "", follow: bool = False):
    parts = [("files", (name, content, "text/x-python")) for name, content in files]
    client.get("/")
    return client.post("/scan", files=parts or None, data={"code": code, "filename": "pasted.py",
                       "csrf_token": client.cookies["csrf_token"]},
                       follow_redirects=follow)


def scan_id_of(response) -> str:
    match = re.search(r"/scan/([0-9a-f]{32})", response.headers["location"])
    assert match, response.headers
    return match.group(1)


# =========================================================== pages & flow


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    for text in ("Secure Code Analyzer", "Upload Source File", "Paste Code", "Start Scan", "Java", "C#"):
        assert text in response.text
    assert 'id="language-switcher"' in response.text
    assert "🇬🇧 English" in response.text and "🇻🇳 Tiếng Việt" in response.text
    assert 'data-i18n-lang="en"' in response.text
    assert "v1.1" in response.text and 'id="version-details-trigger"' in response.text
    assert 'id="version-details-dialog"' in response.text
    assert "Fixed the CSRF validation issue." in response.text
    assert "Added English and Vietnamese language selection" in response.text
    assert "Information and Help button" in response.text
    assert "Scan history" in response.text
    assert "Added animations to some buttons" in response.text
    assert 'id="scan-history-tab"' in response.text
    assert 'id="scan-loading-overlay"' in response.text
    assert 'data-i18n="malware_message_0"' in response.text
    assert 'id="info-help-trigger"' in response.text
    assert 'id="info-help-dialog"' in response.text
    assert "Information and help are here" in response.text
    assert "This is a project for the Information Security Programming course." in response.text
    for github in ("LowKeyLifeeee", "KoliangFish", "Vu-Van-Trung"):
        assert f"https://github.com/{github}" in response.text
    assert "Choose Upload Source File" in response.text


def test_upload_scan_result_detail_flow(client):
    response = upload(client, files=[("app.py", VULNERABLE)])
    assert response.status_code == 303
    scan_id = scan_id_of(response)

    result = client.get(f"/scan/{scan_id}")
    assert result.status_code == 200
    for text in ("Files Scanned", "Lines Scanned", "Total Findings", "Critical", "severity-chart", "PY003"):
        assert text in result.text

    detail = client.get(f"/scan/{scan_id}/finding/0")
    assert detail.status_code == 200
    for text in ("Rule ID", "CWE-78", "Vulnerable Code", "Recommendation", "Taint Path", "input()", "os.system()"):
        assert text in detail.text


def test_scan_history_lists_saved_scan_and_returns_details(client):
    response = upload(client, files=[("history_sample.py", VULNERABLE)])
    assert response.status_code == 303
    scan_id = scan_id_of(response)

    home = client.get("/")
    assert home.status_code == 200
    assert "history_sample.py" in home.text
    assert scan_id in home.text
    assert "View details" in home.text

    details = client.get(f"/scan/{scan_id}/history-data")
    assert details.status_code == 200
    payload = details.json()
    assert payload["scan"]["target"] == "history_sample.py"
    assert payload["summary"]["files_scanned"] == 1
    assert payload["findings"]
    assert payload["findings"][0]["rule_id"] == "PY003"


def test_scan_history_details_rejects_unknown_scan(client):
    response = client.get("/scan/00000000000000000000000000000000/history-data")
    assert response.status_code == 404


def test_paste_code(client):
    response = upload(client, code="eval(input())\n", follow=True)
    assert response.status_code == 200
    assert "PY001" in response.text and "pasted.py" in response.text


def test_multiple_files_and_duplicate_names(client):
    response = upload(client, files=[("a.py", b"eval(x)\n"), ("a.py", b"exec(y)\n")], follow=True)
    assert "a.py" in response.text and "a_2.py" in response.text


def test_syntax_error_is_shown_not_crashing(client):
    response = upload(client, code="x = 1\n\ndef broken(:\n    pass\n", follow=True)
    assert response.status_code == 200
    assert "Scan failed" in response.text and "SyntaxError" in response.text and "Line: 3" in response.text


def test_invalid_utf8_upload_is_reported(client):
    response = upload(client, files=[("bad.py", b"x = '\xff\xfe'\n")], follow=True)
    assert "Scan failed" in response.text and "UnicodeDecodeError" in response.text


def test_scan_without_input_is_rejected(client):
    response = upload(client)
    assert response.status_code == 400
    assert "Upload at least one source file" in response.text


# =========================================================== upload security


@pytest.mark.parametrize("name", ["notes.txt", "script.sh", "evil.py.exe", "module.pyc", "noext"])
def test_only_supported_files_are_accepted(client, name):
    response = upload(client, files=[(name, b"print(1)\n")])
    assert response.status_code == 400
    assert "only .py, .java, .cs files are accepted" in response.text


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("../../etc/passwd.py", "passwd.py"),
        ("..\\..\\Windows\\win.py", "win.py"),
        ("/abs/path/app.py", "app.py"),
        ("my file (1).py", "my_file__1_.py"),
        ("<script>.py", "_script_.py"),
        (".hidden.py", "hidden.py"),
        ("a" * 300 + ".py", "a" * 97 + ".py"),
    ],
)
def test_sanitize_filename(raw, expected):
    assert sanitize_filename(raw) == expected


def test_path_traversal_filename_is_only_a_label(client, tmp_path):
    response = upload(client, files=[("../../outside.py", b"eval(x)\n")], follow=True)
    assert "outside.py" in response.text and "../" not in response.text
    assert not (tmp_path.parent / "outside.py").exists()


def test_file_too_large(client):
    response = upload(client, files=[("big.py", b"#" * (MAX_FILE_BYTES + 1))])
    assert response.status_code == 400
    assert "larger than" in response.text


def test_too_many_files(client):
    files = [(f"f{i}.py", b"x = 1\n") for i in range(MAX_FILES + 1)]
    response = upload(client, files=files)
    assert response.status_code == 400
    assert "Too many files" in response.text


def test_request_too_large_is_rejected_before_parsing(client):
    response = client.post("/scan", content=b"x" * 10, headers={"content-length": str(web.MAX_REQUEST_BYTES + 1)})
    assert response.status_code == 413


def test_uploaded_code_is_never_executed(client, tmp_path):
    marker = tmp_path / "pwned.txt"
    payload = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('echo pwned > {marker.as_posix()}')\n"
    upload(client, files=[("payload.py", payload.encode())], follow=True)
    upload(client, code=payload, follow=True)
    assert not marker.exists()


def test_uploaded_code_is_escaped_in_html(client):
    response = upload(client, code="eval('<script>alert(1)</script>')\n", follow=True)
    scan_id = re.search(r"/scan/([0-9a-f]{32})/report", response.text).group(1)
    detail = client.get(f"/scan/{scan_id}/finding/0")
    assert "<script>alert(1)</script>" not in detail.text
    assert "&lt;script&gt;" in detail.text


def test_security_headers(client):
    headers = client.get("/").headers
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"


# =========================================================== reports & ids


@pytest.mark.parametrize("fmt, media", [
    ("json", "application/json"),
    ("csv", "text/csv"),
    ("html", "text/html"),
    ("sarif", "application/sarif+json"),
])
def test_report_downloads(client, fmt, media):
    scan_id = scan_id_of(upload(client, files=[("app.py", VULNERABLE)]))
    response = client.get(f"/scan/{scan_id}/report.{fmt}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media)
    assert "attachment" in response.headers["content-disposition"]
    assert "PY003" in response.text


def test_unknown_report_format(client):
    scan_id = scan_id_of(upload(client, files=[("app.py", VULNERABLE)]))
    assert client.get(f"/scan/{scan_id}/report.pdf").status_code == 404


@pytest.mark.parametrize("path", ["/scan/" + "0" * 32, "/scan/not-an-id", "/scan/..%2F..%2Fetc%2Fpasswd",
                                  "/scan/" + "0" * 32 + "/report.json"])
def test_unknown_or_malicious_scan_ids(client, path):
    assert client.get(path).status_code == 404


def test_finding_index_out_of_range(client):
    scan_id = scan_id_of(upload(client, files=[("app.py", VULNERABLE)]))
    assert client.get(f"/scan/{scan_id}/finding/99").status_code == 404


def test_scan_id_validation():
    assert is_valid_scan_id("a" * 32)
    assert not is_valid_scan_id("../" + "a" * 29)
    assert not is_valid_scan_id("A" * 32)


def test_store_keeps_only_recent_scans(tmp_path, engine):
    store = ScanStore(tmp_path, max_scans=3)
    result = engine.scan_source("eval(x)\n")
    for _ in range(20):
        scan_id = store.save(result)
        # The scan just saved must always be readable, even when files share an mtime.
        assert store.load(scan_id) is not None
    assert len(list(tmp_path.glob("*.json"))) == 3


# =========================================================== JSON API


def test_api_scan_and_fetch(client):
    response = client.post("/api/scan", json={"code": VULNERABLE.decode(), "filename": "app.py"})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["severity_counts"]["CRITICAL"] == 1
    assert body["findings"][0]["taint_path"] == ["input()", "command", "os.system()"]
    again = client.get(f"/api/scan/{body['scan_id']}")
    assert again.json()["findings"] == body["findings"]


def test_api_validation(client):
    assert client.post("/api/scan", json={"code": ""}).status_code == 422
    assert client.post("/api/scan", json={"code": "x=1", "filename": "a.txt"}).status_code == 400


def test_api_rules(client):
    ids = [rule["id"] for rule in client.get("/api/rules").json()]
    assert {"PY001", "PY011"} <= set(ids)


def test_errors_do_not_leak_details(client, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(web.AnalyzerEngine, "scan_sources", boom)
    response = TestClient(client.app, raise_server_exceptions=False).post(
        "/api/scan", json={"code": "x = 1", "filename": "a.py"})
    assert response.status_code == 500
    assert "secret internal detail" not in response.text


# =========================================================== Java / C# through the web


@pytest.mark.parametrize(
    "name, content, rule",
    [
        ("Ping.java", b'class P { void m(HttpServletRequest r) throws Exception { '
                      b'Runtime.getRuntime().exec("ping " + r.getParameter("h")); } }', "JV001"),
        ("Ping.cs", b'class P { void M() { Process.Start("cmd.exe", "/c ping " + Console.ReadLine()); } }', "CS001"),
    ],
)
def test_java_and_csharp_uploads(client, name, content, rule):
    response = upload(client, files=[(name, content)], follow=True)
    assert response.status_code == 200
    assert rule in response.text and "CRITICAL" in response.text


def test_pasted_code_uses_selected_language(client):
    java = 'class P { void m() throws Exception { Runtime.getRuntime().exec(System.getenv("CMD")); } }'
    client.get("/")
    response = client.post("/scan", data={"code": java, "filename": "snippet.py", "language": "java",
                           "csrf_token": client.cookies["csrf_token"]},
                           follow_redirects=True)
    assert "JV001" in response.text and "snippet.java" in response.text


def test_invalid_language_is_rejected(client):
    response = client.post("/scan", data={"code": "x = 1", "language": "cobol"})
    assert response.status_code == 400


def test_api_scan_with_language(client):
    body = {"code": 'class P { void M(string p) { var c = new SqlCommand("SELECT * FROM T WHERE A = " + p); } }',
            "filename": "a.txt", "language": "csharp"}
    response = client.post("/api/scan", json=body)
    assert response.status_code == 200
    [finding] = response.json()["findings"]
    assert (finding["rule_id"], finding["language"], finding["file"]) == ("CS002", "csharp", "a.cs")


def test_java_syntax_error_is_shown(client):
    response = upload(client, files=[("Broken.java", b"class B { void m( { }")], follow=True)
    assert "Scan failed" in response.text and "Java syntax error" in response.text


def test_sanitize_keeps_supported_extensions():
    assert sanitize_filename("../src/Main.java") == "Main.java"
    assert sanitize_filename("Program.CS") == "Program.cs"


def test_csrf_cookie_issued_on_get(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "csrf_token" in response.cookies
    assert 'name="csrf_token"' in response.text


def test_csrf_validation_passes_with_matching_token(client):
    get_res = client.get("/")
    token = get_res.cookies["csrf_token"]
    post_res = client.post(
        "/scan",
        data={"code": "x = 1\n", "filename": "test.py", "csrf_token": token},
        follow_redirects=False,
    )
    assert post_res.status_code == 303


def test_csrf_validation_fails_on_mismatch(client):
    client.get("/")
    post_res = client.post(
        "/scan",
        data={"code": "x = 1\n", "filename": "test.py", "csrf_token": "wrong_token"},
    )
    assert post_res.status_code == 403
    assert "CSRF validation failed" in post_res.text


def test_basic_auth_when_configured(client, monkeypatch):
    monkeypatch.setenv("ANALYZER_WEB_USER", "admin")
    monkeypatch.setenv("ANALYZER_WEB_PASSWORD", "secret123")

    # Request without auth
    unauth = client.get("/")
    assert unauth.status_code == 401
    assert "Basic" in unauth.headers.get("www-authenticate", "")

    # Request with valid basic auth
    import base64
    valid_cred = base64.b64encode(b"admin:secret123").decode()
    auth = client.get("/", headers={"Authorization": f"Basic {valid_cred}"})
    assert auth.status_code == 200


def test_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("ANALYZER_API_KEY", "super-secret-key")

    body = {"code": "x = 1\n", "filename": "a.py"}

    # No key -> 401
    unauth = client.post("/api/scan", json=body)
    assert unauth.status_code == 401

    # With X-API-Key -> 200
    auth = client.post("/api/scan", json=body, headers={"X-API-Key": "super-secret-key"})
    assert auth.status_code == 200
