"""Regression coverage for interprocedural analysis, sanitizers, SARIF and CSRF."""

import io
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.analyzer.engine import AnalyzerEngine
from app.analyzer.ts.taint import TSTaintConfig
from app.config.loader import ConfigError
from app.config.settings import AnalyzerSettings
from app.main import create_app
from app.models.finding import Severity
from app.reports import render_report
from app.storage import ScanStore


def scan(engine, source, extension, rule):
    result = engine.scan_source(source, "regression." + extension)
    assert not result.errors, result.errors
    return [f for f in result.findings if f.rule_id == rule]


def test_python_long_reverse_call_chain(engine):
    functions = ["def f0(x):\n    import os\n    os.system(x)\n"]
    functions += [f"def f{i}(x):\n    f{i-1}(x)\n" for i in range(1, 10)]
    source = "\n".join(functions) + "\nf9(input())"
    [finding] = scan(engine, source, "py", "PY003")
    assert finding.severity is Severity.CRITICAL


@pytest.mark.parametrize("invocation", ["relay(x=input())", "relay(input())"])
def test_python_returns_are_call_specific(engine, invocation):
    code = f"""import os
def relay(x):
    return x
dirty = {invocation}
os.system(relay("fixed"))
os.system(dirty)
"""
    safe, unsafe = scan(engine, code, "py", "PY003")
    assert safe.severity is Severity.LOW and safe.source is None
    assert unsafe.severity is Severity.CRITICAL


def test_python_duplicate_nested_names_do_not_collide(engine):
    source = """import os
def a(x):
    def helper(y):
        return y
    return helper(x)
def b(x):
    def helper(y):
        return "fixed"
    return helper(x)
os.system(a(input()))
os.system(b(input()))
"""
    unsafe, safe = scan(engine, source, "py", "PY003")
    assert unsafe.severity is Severity.CRITICAL
    assert safe.severity is Severity.LOW and safe.source is None


@pytest.mark.parametrize("signature,call", [
    ("x=input()", "f()"), ("*, x", "f(x=input())"),
    ("*args", "f(input())"), ("**kwargs", "f(x=input())"),
    ("x, y", "f(*[input(), 'fixed'])"),
])
def test_python_parameter_binding(engine, signature, call):
    name = "args[0]" if signature == "*args" else "kwargs['x']" if signature == "**kwargs" else "x"
    code = f"import os\ndef f({signature}):\n    os.system({name})\n{call}"
    assert scan(engine, code, "py", "PY003")[0].severity is Severity.CRITICAL


def test_python_recursive_cycle_is_bounded(engine):
    source = "import os\ndef a(x):\n    return b(x)\ndef b(x):\n    return a(x)\nos.system(a(input()))"
    assert scan(engine, source, "py", "PY003")[0].severity is Severity.CRITICAL


def test_python_parameter_shadowing_is_not_a_local_call(engine):
    code = """import os
def helper(x):
    os.system(x)
def caller(helper):
    helper(input())
"""
    [finding] = scan(engine, code, "py", "PY003")
    assert finding.source is None


@pytest.mark.parametrize("ext,rule,call,source", [
    ("java", "JV001", "Runtime.getRuntime().exec(x)", 'System.getenv("CMD")'),
    ("cs", "CS001", "Process.Start(x)", "Console.ReadLine()"),
])
def test_ts_long_reverse_call_chain(engine, ext, rule, call, source):
    methods = [f"void f0(String x) {{ {call}; }}" if ext == "java" else f"void f0(string x) {{ {call}; }}"]
    typ = "String" if ext == "java" else "string"
    methods += [f"void f{i}({typ} x) {{ f{i-1}(x); }}" for i in range(1, 10)]
    code = "class C { " + " ".join(methods) + f" void handle() {{ f9({source}); }} }}"
    assert scan(engine, code, ext, rule)[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("ext,rule,typ,source,sink", [
    ("java", "JV001", "String", 'System.getenv("CMD")', "Runtime.getRuntime().exec"),
    ("cs", "CS001", "string", "Console.ReadLine()", "Process.Start"),
])
def test_ts_returns_do_not_leak_between_calls(engine, ext, rule, typ, source, sink):
    code = f"""class C {{
{typ} relay({typ} x) {{ return x; }}
void m() {{
{typ} dirty = relay({source});
{sink}(relay("fixed"));
{sink}(dirty);
}}
}}"""
    safe, unsafe = scan(engine, code, ext, rule)
    assert safe.severity is Severity.LOW and safe.source is None
    assert unsafe.severity is Severity.CRITICAL


@pytest.mark.parametrize("ext,rule,typ,source,sink", [
    ("java", "JV001", "String", 'System.getenv("CMD")', "Runtime.getRuntime().exec"),
    ("cs", "CS001", "string", "Console.ReadLine()", "Process.Start"),
])
def test_ts_unrelated_receiver_does_not_seed_local_method(engine, ext, rule, typ, source, sink):
    code = f"""class A {{
void run({typ} x) {{ {sink}(x); }}
void m(External external) {{ external.run({source}); }}
}}"""
    assert scan(engine, code, ext, rule)[0].source is None


@pytest.mark.parametrize("ext,rule,typ,source,sink", [
    ("java", "JV001", "String", 'System.getenv("CMD")', "Runtime.getRuntime().exec"),
    ("cs", "CS001", "string", "Console.ReadLine()", "Process.Start"),
])
def test_ts_duplicate_names_in_different_classes(engine, ext, rule, typ, source, sink):
    code = f"""class A {{
void run({typ} x) {{ {sink}(x); }}
void m() {{ run({source}); }}
}}
class B {{
void run({typ} x) {{ {sink}(x); }}
}}"""
    dirty, unknown = scan(engine, code, ext, rule)
    assert dirty.severity is Severity.CRITICAL
    assert unknown.source is None


def test_csharp_expression_body_returns_source(engine):
    code = 'class C { string Get() => Console.ReadLine(); void M() { Process.Start(Get()); } }'
    assert scan(engine, code, "cs", "CS001")[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("function", ["urlparse", "quote", "quote_plus"])
def test_url_parsing_and_encoding_do_not_suppress_ssrf(engine, function):
    code = f"import urllib.parse\nimport requests\nrequests.get(urllib.parse.{function}(input()))"
    assert scan(engine, code, "py", "PY015")


@pytest.mark.parametrize("config", [
    {"sink_sanitizers": []}, {"sink_sanitizers": {"sql": "Codec.encode"}},
    {"sink_sanitizers": {"sql": [123]}},
])
def test_sink_sanitizer_config_validation(config):
    with pytest.raises(ConfigError):
        TSTaintConfig.from_dict(config)


def test_configured_sql_sanitizer_only_affects_sql():
    settings = AnalyzerSettings.load()
    config = replace(settings.language_taint["java"], sink_sanitizers={"sql": frozenset({"Custom.escape"})})
    engine = AnalyzerEngine(settings=settings.with_changes(language_taint={**settings.language_taint, "java": config}))
    code = '''class C { void m() {
String q = Custom.escape(System.getenv("Q"));
stmt.executeQuery(q);
Runtime.getRuntime().exec(q);
} }'''
    result = engine.scan_source(code, "C.java")
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["JV002"].severity is Severity.LOW
    assert by_rule["JV001"].severity is Severity.CRITICAL
    assert "None()" not in by_rule["JV002"].message


def test_mixed_shell_arguments_do_not_lose_unsanitized_taint():
    settings = AnalyzerSettings.load()
    config = replace(settings.language_taint["java"], sink_sanitizers={"command": frozenset({"Custom.escape"})})
    engine = AnalyzerEngine(settings=settings.with_changes(language_taint={**settings.language_taint, "java": config}))
    code = '''class C { void m() {
new ProcessBuilder("sh", "-c", Custom.escape(System.getenv("A")), System.getenv("B"));
} }'''
    assert scan(engine, code, "java", "JV001")[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("path,expected", [
    ("src/a #%.py", "src/a%20%23%25.py"),
    ("C:\\source\\a b.py", "file:///C:/source/a%20b.py"),
])
def test_sarif_paths_are_uri_encoded(engine, path, expected):
    result = engine.scan_source("eval(input())", path)
    run = json.loads(render_report(result, "sarif"))["runs"][0]
    item = run["results"][0]
    assert item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == expected
    assert run["tool"]["driver"]["rules"][item["ruleIndex"]]["id"] == item["ruleId"]
    locations = item["codeFlows"][0]["threadFlows"][0]["locations"]
    assert all("physicalLocation" not in x["location"] for x in locations[:-1])


def test_sarif_reports_scan_failure_and_cli_returns_two(tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def (:", encoding="utf-8")
    output = io.StringIO()
    status = cli.main(["scan", str(target), "--format", "sarif"], stdout=output, stderr=io.StringIO())
    assert status == 2
    invocation = json.loads(output.getvalue())["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"]


@pytest.fixture
def web_client(tmp_path):
    with TestClient(create_app(store=ScanStore(tmp_path / "scans"))) as client:
        yield client


@pytest.mark.parametrize("token", [None, "arbitrary", "a" * 64 + "." + "b" * 64, "\u0111"])
def test_csrf_requires_server_issued_token(web_client, token):
    if token is not None and token.isascii():
        web_client.cookies.set("csrf_token", token)
    response = web_client.post("/scan", data={"code": "x=1", "csrf_token": token or ""})
    assert response.status_code == 403


def test_csrf_rejects_missing_cookie_even_with_valid_form_token(web_client):
    web_client.get("/")
    token = web_client.cookies["csrf_token"]
    web_client.cookies.clear()
    assert web_client.post("/scan", data={"code": "x=1", "csrf_token": token}).status_code == 403


def test_csrf_header_and_cookie_flags(web_client):
    response = web_client.get("/")
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    token = web_client.cookies["csrf_token"]
    response = web_client.post("/scan", data={"code": "x=1"}, headers={"X-CSRF-Token": token}, follow_redirects=False)
    assert response.status_code == 303


def test_csrf_invalid_cookie_is_replaced(web_client):
    web_client.cookies.set("csrf_token", "forged", domain="testserver.local", path="/")
    response = web_client.get("/")
    assert response.cookies["csrf_token"] != "forged"


@pytest.mark.parametrize("headers", [
    {"Origin": "https://attacker.example"}, {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Referer": "https://attacker.example/form"},
])
def test_csrf_rejects_foreign_origin_even_with_token(web_client, headers):
    web_client.get("/")
    token = web_client.cookies["csrf_token"]
    response = web_client.post("/scan", data={"code": "x=1", "csrf_token": token}, headers=headers)
    assert response.status_code == 403


def test_csrf_accepts_same_origin(web_client):
    web_client.get("/")
    token = web_client.cookies["csrf_token"]
    response = web_client.post("/scan", data={"code": "x=1", "csrf_token": token},
                               headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert response.status_code == 303


def test_csrf_accepts_opaque_origin_when_fetch_metadata_is_same_origin(web_client):
    web_client.get("/")
    token = web_client.cookies["csrf_token"]
    response = web_client.post(
        "/scan",
        data={"code": "x=1", "csrf_token": token},
        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_csrf_https_cookie_is_secure(tmp_path):
    app = create_app(store=ScanStore(tmp_path / "scans"))
    with TestClient(app, base_url="https://testserver") as client:
        assert "secure" in client.get("/").headers["set-cookie"].lower()


def test_sarif_custom_rule_has_descriptor(engine):
    result = engine.scan_source("eval(input())", "test.py")
    result.findings[0].rule_id = "CUSTOM001"
    run = json.loads(render_report(result, "sarif"))["runs"][0]
    item = run["results"][0]
    assert run["tool"]["driver"]["rules"][item["ruleIndex"]]["id"] == "CUSTOM001"


@pytest.mark.parametrize("expression,expected", [
    ('Pick(second: Console.ReadLine(), first: "fixed")', Severity.LOW),
    ('Pick(second: "fixed", first: Console.ReadLine())', Severity.CRITICAL),
])
def test_csharp_named_arguments_map_by_name(engine, expression, expected):
    code = f"""class C {{
string Pick(string first, string second) {{ return first; }}
void M() {{ Process.Start({expression}); }}
}}"""
    assert scan(engine, code, "cs", "CS001")[0].severity is expected
