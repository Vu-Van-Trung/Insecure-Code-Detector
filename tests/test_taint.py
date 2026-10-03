"""Phase 4 - basic taint tracking (source -> variables -> sanitizer -> sink)."""

import ast
import json
import textwrap

import pytest

from app import cli
from app.analyzer.engine import AnalyzerEngine
from app.analyzer.taint import STATIC, TaintConfig, TaintInfo, analyze_taint
from app.analyzer.utils import collect_imports
from app.config.loader import ConfigError
from app.config.settings import AnalyzerSettings
from app.models.finding import Severity

DEFAULT_CONFIG = TaintConfig.load()


def label_at_sink(code: str, config: TaintConfig = DEFAULT_CONFIG):
    """Label of the argument of the last ``sink(...)`` call in ``code``."""
    tree = ast.parse(textwrap.dedent(code))
    result = analyze_taint(tree, collect_imports(tree), config)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "sink"]
    argument = max(calls, key=lambda call: call.lineno).args[0]
    return result.labels.get(argument)


def assert_tainted(label, source: str, path: tuple[str, ...] | None = None) -> TaintInfo:
    assert isinstance(label, TaintInfo), f"expected taint, got {label!r}"
    assert label.source == source
    if path is not None:
        assert label.path == path
    return label


# =========================================================== sources


@pytest.mark.parametrize(
    "code, source",
    [
        ("x = input()\nsink(x)", "input()"),
        ("x = request.args.get('q')\nsink(x)", "request.args"),
        ("from flask import request\nx = request.form['name']\nsink(x)", "request.form"),
        ("x = request.get_json()\nsink(x)", "request.get_json()"),
        ("import sys\nx = sys.argv[1]\nsink(x)", "sys.argv"),
        ("from sys import argv\nx = argv[1]\nsink(x)", "argv"),
        ("import os\nx = os.environ['HOME']\nsink(x)", "os.environ"),
        ("import os\nx = os.getenv('HOME')\nsink(x)", "os.getenv()"),
        ("def view(request):\n    sink(request.GET['id'])", "request.GET"),  # Django
    ],
)
def test_sources_are_detected(code, source):
    assert_tainted(label_at_sink(code), source)


def test_non_sources_are_not_tainted():
    assert label_at_sink("x = get_value()\nsink(x)") is None
    assert label_at_sink("x = form.input()\nsink(x)") is None  # a method named input


# =========================================================== propagation


def test_taint_path_records_each_variable():
    code = """
    command = input("Command: ")
    cmd = command
    full = "ls " + cmd
    sink(full)
    """
    assert_tainted(label_at_sink(code), "input()", ("input()", "command", "cmd", "full"))


@pytest.mark.parametrize(
    "expression",
    [
        "'ls ' + data",
        "f'ls {data}'",
        "'ls %s' % data",
        "'ls {}'.format(data)",
        "data.strip().lower()",
        "' '.join([data, 'x'])",
        "str(data)",
        "[data][0]",
        "data if flag else 'x'",
        "(data or 'default')",
    ],
)
def test_taint_propagates_through_expressions(expression):
    assert_tainted(label_at_sink(f"data = input()\nsink({expression})"), "input()")


def test_taint_propagates_through_containers_loops_and_with():
    assert_tainted(label_at_sink("args = sys.argv\nfor a in args:\n    sink(a)".replace("sys.argv", "input()")), "input()")
    assert_tainted(label_at_sink("parts = [input()]\nsink(' '.join(p for p in parts))"), "input()")
    assert_tainted(label_at_sink("d = {}\nd['k'] = input()\nsink(d)"), "input()")
    assert_tainted(label_at_sink("with open(input()) as fh:\n    sink(fh)"), "input()")
    assert_tainted(label_at_sink("a, b = input(), 1\nsink(a)"), "input()")
    assert_tainted(label_at_sink("if (n := input()):\n    sink(n)"), "input()")


def test_augmented_assignment_keeps_taint():
    code = """
    q = "SELECT * FROM t WHERE 1=1"
    q += " AND a = " + input()
    sink(q)
    """
    assert_tainted(label_at_sink(code), "input()")


def test_attribute_assignment_is_tracked():
    code = """
    class Job:
        def run(self):
            self.cmd = input()
            sink(self.cmd)
    """
    assert_tainted(label_at_sink(code), "input()")


def test_comparison_result_is_not_tainted():
    assert label_at_sink("ok = input() == 'yes'\nsink(ok)") is None


# =========================================================== flow sensitivity


def test_reassignment_with_constant_clears_taint():
    assert label_at_sink("x = input()\nx = 'ls'\nsink(x)") is STATIC


def test_assignment_in_branch_does_not_clear_taint():
    code = """
    x = input()
    if safe_mode:
        x = "ls"
    sink(x)
    """
    assert_tainted(label_at_sink(code), "input()")


def test_taint_assigned_in_branch_reaches_sink():
    code = """
    x = "ls"
    if interactive:
        x = input()
    sink(x)
    """
    assert_tainted(label_at_sink(code), "input()")


def test_try_body_runs_before_except_handler():
    code = """
    try:
        x = input()
    except ValueError:
        sink(x)
    """
    assert_tainted(label_at_sink(code), "input()")


def test_use_before_taint_is_not_tainted():
    assert label_at_sink("x = 'ls'\nsink(x)\nx = input()") is STATIC


# =========================================================== static values & scopes


def test_variables_holding_literals_are_static():
    assert label_at_sink("base = 'ls'\nopts = ' -l'\nsink(base + opts)") is STATIC


def test_module_constant_is_visible_in_function():
    assert label_at_sink("CMD = 'ls -l'\ndef f():\n    sink(CMD)") is STATIC


def test_function_parameters_are_unknown():
    assert label_at_sink("def f(cmd):\n    sink(cmd)") is None


def test_parameter_shadows_module_variable():
    assert label_at_sink("cmd = input()\ndef f(cmd):\n    sink(cmd)") is None


def test_no_inter_procedural_analysis():
    """Documented limitation: taint does not flow through calls into other functions."""
    code = """
    def run(cmd):
        sink(cmd)

    run(input())
    """
    assert label_at_sink(code) is None


# =========================================================== sanitizers


def test_sanitizer_marks_flow_as_sanitized():
    code = """
    import shlex
    host = input()
    safe = shlex.quote(host)
    sink("ping " + safe)
    """
    info = assert_tainted(label_at_sink(code), "input()")
    assert info.sanitizer == "shlex.quote"
    assert info.path == ("input()", "host", "shlex.quote()", "safe")


def test_int_conversion_is_a_sanitizer():
    info = assert_tainted(label_at_sink("uid = int(request.args['id'])\nsink(uid)"), "request.args")
    assert info.sanitized


def test_unsanitized_part_wins_over_sanitized_part():
    code = "import shlex\na = input()\nsink(shlex.quote(a) + a)"
    assert not assert_tainted(label_at_sink(code), "input()").sanitized


def test_sanitizers_come_from_configuration():
    config = TaintConfig(
        source_functions=frozenset({"read_user"}), source_attributes=frozenset(), sanitizers=frozenset({"my.clean"}),
    )
    code = "import my\nx = my.clean(read_user())\nsink(x)"
    assert assert_tainted(label_at_sink(code, config), "read_user()").sanitizer == "my.clean"
    # The same code without the sanitizer configured is plainly tainted.
    default_like = TaintConfig(config.source_functions, frozenset(), frozenset())
    assert not assert_tainted(label_at_sink(code, default_like), "read_user()").sanitized


# =========================================================== sink-specific sanitizers


def test_sink_sanitizer_marks_data_safe_for_its_category_only():
    code = "import os\nname = os.path.basename(input())\nsink(name)"
    info = assert_tainted(label_at_sink(code), "input()", ("input()", "os.path.basename()", "name"))
    assert info.safe_for == {"path"}
    assert not info.sanitized  # every other sink still sees plain taint


def test_concatenation_keeps_safe_category_of_tainted_parts():
    code = "import os\nsink('/data/' + os.path.basename(input()))"
    assert label_at_sink(code).safe_for == {"path"}


def test_unsafe_part_removes_safe_category():
    code = "import os\na = input()\nsink(os.path.basename(a) + a)"
    assert label_at_sink(code).safe_for == frozenset()


def test_branch_merge_keeps_only_common_safe_categories():
    code = """
    import os, html
    x = os.path.basename(input())
    if cond:
        x = html.escape(input())
    sink(x)
    """
    assert label_at_sink(code).safe_for == frozenset()


def test_sink_sanitizers_come_from_configuration():
    config = TaintConfig(
        source_functions=frozenset({"read_user"}), source_attributes=frozenset(), sanitizers=frozenset(),
        sink_sanitizers={"url": frozenset({"my.allow_url"})},
    )
    info = label_at_sink("import my\nsink(my.allow_url(read_user()))", config)
    assert info.safe_for == {"url"}


def test_default_config_has_path_and_html_sink_sanitizers():
    assert "werkzeug.utils.secure_filename" in DEFAULT_CONFIG.sink_sanitizers["path"]
    assert "html.escape" in DEFAULT_CONFIG.sink_sanitizers["html"]


# =========================================================== rules integration


def test_command_injection_from_input_is_critical_with_path(find):
    code = """
    import os
    command = input("Command: ")
    os.system(command)
    """
    [finding] = find(code, "PY003")
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == 0.95
    assert (finding.source, finding.sink) == ("input()", "os.system()")
    assert finding.taint_path == ["input()", "command", "os.system()"]


def test_eval_of_argv_is_critical(find):
    [finding] = find("import sys\nresult = eval(sys.argv[1])", "PY001")
    assert finding.severity is Severity.CRITICAL
    assert finding.taint_path == ["sys.argv", "eval()"]


def test_subprocess_shell_with_request_data_is_critical(find):
    code = """
    import subprocess
    from flask import request

    def ping():
        host = request.args.get("host")
        return subprocess.run(f"ping -c 1 {host}", shell=True)
    """
    [finding] = find(code, "PY004")
    assert finding.severity is Severity.CRITICAL
    assert finding.taint_path == ["request.args", "host", "subprocess.run()"]


def test_subprocess_with_uncertain_shell_and_taint_is_high(find):
    [finding] = find("import subprocess\nsubprocess.run(input(), shell=use_shell)", "PY004")
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 0.7


def test_sql_injection_from_request_is_critical_with_path(find):
    code = """
    def get_user(cursor):
        user_id = request.args.get("id")
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
    """
    [finding] = find(code, "PY011")
    assert finding.severity is Severity.CRITICAL
    assert finding.taint_path == ["request.args", "user_id", "query", "cursor.execute()"]


def test_pickle_of_request_data_is_critical(find):
    [finding] = find("import pickle\nobj = pickle.loads(request.data)", "PY005")
    assert finding.severity is Severity.CRITICAL
    assert finding.source == "request.data"


def test_sanitized_flow_is_reported_low_not_hidden(find):
    code = """
    import os, shlex
    host = input()
    os.system("ping -c 1 " + shlex.quote(host))
    """
    [finding] = find(code, "PY003")
    assert finding.severity is Severity.LOW
    assert finding.confidence == 0.4
    assert "shlex.quote" in finding.message and "cannot prove" in finding.message
    assert finding.taint_path[-1] == "os.system()"


def test_sql_with_int_sanitized_id_is_low(find):
    code = """
    uid = int(request.args["id"])
    cursor.execute("SELECT * FROM users WHERE id = " + str(uid))
    """
    [finding] = find(code, "PY011")
    assert finding.severity is Severity.LOW


def test_constant_command_in_variable_is_low(find):
    """Phase 2 reported this as HIGH; taint tracking knows the value is constant."""
    [finding] = find("import os\ncmd = 'ls -l'\nos.system(cmd)", "PY003")
    assert finding.severity is Severity.LOW


def test_sql_built_only_from_constants_is_not_reported(find):
    code = "TABLE = 'users'\nquery = 'SELECT * FROM ' + TABLE\ncursor.execute(query)"
    assert find(code, "PY011") == []


def test_unknown_origin_keeps_phase_2_behaviour(find):
    [finding] = find("import os\ndef run(cmd):\n    os.system(cmd)", "PY003")
    assert finding.severity is Severity.HIGH
    assert finding.source is None and finding.taint_path == []


# =========================================================== configuration errors


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "Invalid JSON"),
        ("[1, 2]", "must contain a JSON object"),
        ('{"sources": []}', "'sources'"),
        ('{"sources": {"functions": "input"}}', "'functions'"),
        ('{"sanitizers": [1]}', "'sanitizers'"),
        ('{"sink_sanitizers": ["os.path.basename"]}', "'sink_sanitizers'"),
        ('{"sink_sanitizers": {"path": "os.path.basename"}}', "'path'"),
    ],
)
def test_invalid_taint_config_raises_config_error(tmp_path, content, message):
    path = tmp_path / "taint.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        TaintConfig.load(path)


def test_missing_taint_config(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        TaintConfig.load(tmp_path / "missing.json")


def test_default_config_contains_spec_sources_and_sanitizer():
    assert {"input", "os.getenv"} <= DEFAULT_CONFIG.source_functions
    assert {"request.args", "request.form", "request.json", "sys.argv", "os.environ"} <= DEFAULT_CONFIG.source_attributes
    assert "shlex.quote" in DEFAULT_CONFIG.sanitizers


def test_custom_config_file_is_used_by_engine(tmp_path):
    path = tmp_path / "taint.json"
    path.write_text(json.dumps({"sources": {"functions": ["read_secret_input"]}}), encoding="utf-8")
    engine = AnalyzerEngine(settings=AnalyzerSettings.load(taint_config=TaintConfig.load(path)))
    result = engine.scan_source("import os\nos.system(read_secret_input())")
    [finding] = result.findings
    assert finding.source == "read_secret_input()"


def test_cli_reports_invalid_configuration(monkeypatch, tmp_path, capsys):
    def broken_engine(**kwargs):
        raise ConfigError("taint.json: bad")

    monkeypatch.setattr(cli, "AnalyzerEngine", broken_engine)
    monkeypatch.setattr(cli, "setup_logging", lambda: None)
    (tmp_path / "a.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path)]) == cli.EXIT_USAGE_ERROR
    assert "invalid configuration" in capsys.readouterr().err
