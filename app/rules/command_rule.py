"""PY003 - os.system() / os.popen() and PY004 - subprocess with shell=True."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_keyword
from app.models.finding import Finding, Severity
from app.rules.base import (
    SANITIZED_CONFIDENCE,
    SANITIZED_SEVERITY,
    TAINTED_CONFIDENCE,
    ArgumentKind,
    DangerousCallRule,
    SecurityRule,
    classify_argument,
    sanitized_message,
    taint_details,
)
from app.rules.registry import register_rule

_COMMAND_INJECTION_DESCRIPTION = (
    "The command string is interpreted by the system shell (/bin/sh or cmd.exe). "
    "Shell metacharacters such as ; | & $() in attacker-controlled data let the "
    "attacker run additional commands (OS command injection)."
)


@register_rule
class OsSystemRule(DangerousCallRule):
    id = "PY003"
    name = "OS command execution via os.system()"
    description = _COMMAND_INJECTION_DESCRIPTION
    severity = Severity.HIGH
    cwe = "CWE-78"
    category = "Command Injection"
    recommendation = (
        "Use subprocess.run() with a list of arguments and shell=False. Never build "
        "shell command strings from untrusted input."
    )
    # os.popen() also passes its command to the shell.
    target_functions = frozenset({"os.system", "os.popen", "posix.system", "nt.system"})
    dynamic_message = "{name}() runs a dynamically built command through the shell."
    static_message = "{name}() runs a constant command through the shell."


# subprocess functions that accept shell=... and default to shell=False.
_SHELL_OPTIONAL = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
})
# Functions that ALWAYS run their command through the shell.
_SHELL_ALWAYS = frozenset({
    "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
})

_SHELL_ON, _SHELL_OFF, _SHELL_MAYBE = "on", "off", "maybe"


@register_rule
class SubprocessShellRule(SecurityRule):
    id = "PY004"
    name = "subprocess call with shell=True"
    description = _COMMAND_INJECTION_DESCRIPTION
    severity = Severity.HIGH
    cwe = "CWE-78"
    category = "Command Injection"
    recommendation = (
        "Pass the command as a list of arguments with shell=False (the default), "
        "e.g. subprocess.run(['ls', '-l', path]). If a shell is unavoidable, quote "
        "every untrusted value with shlex.quote()."
    )

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if not isinstance(node, ast.Call):
            return
        name = context.call_name(node)
        if name in _SHELL_ALWAYS:
            shell = _SHELL_ON
        elif name in _SHELL_OPTIONAL:
            shell = self._shell_state(node)
        else:
            return
        if shell == _SHELL_OFF:
            return

        command = get_argument(node, 0, "args") or get_argument(node, 0, "cmd")
        if command is None:
            return
        kind, info = classify_argument(command, context)
        sink = f"{name}()"

        if kind is ArgumentKind.TAINTED:
            yield self.create_finding(
                node, context, f"Untrusted input from {info.source} reaches {sink} through the shell.",
                severity=Severity.CRITICAL if shell == _SHELL_ON else Severity.HIGH,
                confidence=TAINTED_CONFIDENCE if shell == _SHELL_ON else 0.7,
                **taint_details(info, sink),
            )
        elif kind is ArgumentKind.SANITIZED:
            yield self.create_finding(
                node, context, sanitized_message(info, sink),
                severity=SANITIZED_SEVERITY, confidence=SANITIZED_CONFIDENCE, **taint_details(info, sink),
            )
        elif shell == _SHELL_ON and kind is ArgumentKind.DYNAMIC:
            yield self.create_finding(
                node, context, f"{name}() runs a dynamically built command with shell=True.",
                confidence=0.85,
            )
        elif shell == _SHELL_ON:
            yield self.create_finding(
                node, context, f"{name}() runs a constant command with shell=True.",
                severity=Severity.LOW, confidence=0.6,
            )
        elif kind is ArgumentKind.DYNAMIC:
            yield self.create_finding(
                node, context,
                f"{name}() may enable the shell (shell= is not a constant) with a dynamic command.",
                severity=Severity.MEDIUM, confidence=0.5,
            )

    @staticmethod
    def _shell_state(call: ast.Call) -> str:
        keyword = get_keyword(call, "shell")
        if keyword is None:
            # shell defaults to False. If it may hide in **kwargs we stay quiet
            # rather than guess, to avoid false positives.
            return _SHELL_OFF
        if isinstance(keyword.value, ast.Constant):
            # Any truthy constant (True, 1, "yes") enables the shell.
            return _SHELL_ON if keyword.value.value else _SHELL_OFF
        return _SHELL_MAYBE  # e.g. shell=use_shell
