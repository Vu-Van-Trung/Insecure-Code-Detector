import ast

import pytest

from app.analyzer.utils import (
    collect_imports,
    get_argument,
    get_dotted_name,
    get_keyword,
    is_constant,
    is_static_value,
    resolve_name,
)


def first_call(source: str) -> ast.Call:
    return next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call))


def test_collect_imports_handles_aliases_and_from_imports():
    tree = ast.parse(
        "import os\nimport subprocess as sp\nimport os.path\n"
        "from os import system\nfrom os import popen as p\nfrom . import local\n"
    )
    imports = collect_imports(tree)
    assert imports["os"] == "os"
    assert imports["sp"] == "subprocess"
    assert imports["system"] == "os.system"
    assert imports["p"] == "os.popen"
    assert "local" not in imports


@pytest.mark.parametrize(
    "source, expected",
    [
        ("import subprocess as sp\nsp.run('ls')", "subprocess.run"),
        ("from os import system as s\ns('ls')", "os.system"),
        ("import os\nos.system('ls')", "os.system"),
        ("eval('1')", "eval"),
        ("import os.path\nos.path.join('a')", "os.path.join"),
    ],
)
def test_resolve_call_names(source, expected):
    tree = ast.parse(source)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert resolve_name(call.func, collect_imports(tree)) == expected


def test_dotted_name_of_non_name_chain_is_none():
    assert get_dotted_name(first_call("get_mod().system('x')").func) is None


def test_get_keyword_and_is_constant():
    call = first_call("run(cmd, shell=True, check=1)")
    assert is_constant(get_keyword(call, "shell").value, True)
    # 1 == True in Python, but it must not be treated as the literal True.
    assert not is_constant(get_keyword(call, "check").value, True)
    assert get_keyword(call, "missing") is None


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("'ls -l'", True),
        ("'a' + 'b'", True),
        ("f'plain text'", True),
        ("['ls', '-l']", True),
        ("b'data'", True),
        ("user_input", False),
        ("'ls ' + path", False),
        ("f'rm {path}'", False),
        ("['ls', path]", False),
        ("get_command()", False),
    ],
)
def test_is_static_value(expression, expected):
    node = ast.parse(expression, mode="eval").body
    assert is_static_value(node) is expected


def test_get_argument_positional_keyword_and_starred():
    assert isinstance(get_argument(first_call("run(cmd)"), 0), ast.Name)
    assert isinstance(get_argument(first_call("run(args=cmd)"), 0, "args"), ast.Name)
    assert get_argument(first_call("run()"), 0, "args") is None
    assert get_argument(first_call("run(*parts)"), 0) is None
