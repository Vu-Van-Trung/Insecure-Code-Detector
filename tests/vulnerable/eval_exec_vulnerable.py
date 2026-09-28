"""Intentionally vulnerable test fixture: PY001 / PY002. Never run this file."""
import builtins


def calculate():
    expression = input("Expression: ")
    return eval(expression)  # expect: PY001


def run_plugin(code: str):
    exec(code)  # expect: PY002


def run_template(name: str):
    builtins.exec(f"handler_{name}()")  # expect: PY002


VERSION = eval("(1, 0)")  # expect: PY001
