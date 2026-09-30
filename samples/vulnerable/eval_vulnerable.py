"""Demo: a calculator that evaluates user input with eval()/exec().

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
Do not run this file and do not deploy it.
"""
import sys


def calculate() -> None:
    expression = input("Enter an expression: ")
    print("Result:", eval(expression))  # PY001: arbitrary code execution


def run_plugin() -> None:
    plugin_code = sys.argv[1]
    exec(plugin_code)  # PY002


if __name__ == "__main__":
    calculate()
