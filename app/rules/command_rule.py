"""PY003 - os.system() / os.popen() và PY004 - subprocess với shell=True (OS command injection)."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_keyword
from app.models.finding import Finding, Severity
from app.rules.base import TAINTED_CONFIDENCE, ArgumentKind, CallRule, DangerousCallRule, classify_argument
from app.rules.registry import register_rule

# Mô tả dùng chung cho cả hai rule (cùng một loại lỗ hổng).
_COMMAND_INJECTION_DESCRIPTION = (
    "The command string is interpreted by the system shell (/bin/sh or cmd.exe). "
    "Shell metacharacters such as ; | & $() in attacker-controlled data let the "
    "attacker run additional commands (OS command injection)."
)


@register_rule
class OsSystemRule(DangerousCallRule):
    """PY003: os.system/os.popen luôn chạy lệnh qua shell.

    Chỉ cần khai báo thuộc tính; việc chấm điểm (CRITICAL/HIGH/LOW theo nguồn
    dữ liệu) do lớp cha DangerousCallRule đảm nhận.
    Vd ``os.system("ping " + input())`` -> CRITICAL.
    """

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
    # os.popen() cũng chuyển lệnh cho shell. posix/nt là module nền của os trên Linux/Windows.
    target_functions = frozenset({"os.system", "os.popen", "posix.system", "nt.system"})
    dynamic_message = "{name}() runs a dynamically built command through the shell."
    static_message = "{name}() runs a constant command through the shell."


# Hàm subprocess có tham số shell=... và mặc định shell=False.
_SHELL_OPTIONAL = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
})
# Hàm LUÔN chạy lệnh qua shell.
_SHELL_ALWAYS = frozenset({
    "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
})

# Trạng thái shell: chắc chắn bật / chắc chắn tắt / không xác định (shell=biến).
_SHELL_ON, _SHELL_OFF, _SHELL_MAYBE = "on", "off", "maybe"


@register_rule
class SubprocessShellRule(CallRule):
    """PY004: subprocess chạy lệnh qua shell.

    ``subprocess.run(["ls", path])`` (list, không shell) an toàn: mỗi phần tử là
    một argument riêng, ký tự ; | & không có ý nghĩa đặc biệt. Chỉ khi shell=True
    thì chuỗi lệnh mới được shell diễn giải.
    """

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

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        if name in _SHELL_ALWAYS:
            shell = _SHELL_ON
        elif name in _SHELL_OPTIONAL:
            shell = self._shell_state(node)
        else:
            return
        if shell == _SHELL_OFF:
            return

        # Lệnh có thể truyền theo vị trí hoặc theo tên args= / cmd=.
        command = get_argument(node, 0, "args") or get_argument(node, 0, "cmd")
        if command is None:
            return
        kind, info = classify_argument(command, context)
        sink = f"{name}()"

        # Bảng chấm điểm (shell chắc chắn bật / có thể bật) x (nguồn gốc của lệnh).
        if kind is ArgumentKind.TAINTED:
            yield self.tainted_finding(
                node, context, info, sink, f"Untrusted input from {info.source} reaches {sink} through the shell.",
                # Chỉ CRITICAL khi chắc chắn có shell; shell=<biến> thì HIGH với confidence thấp hơn.
                severity=Severity.CRITICAL if shell == _SHELL_ON else Severity.HIGH,
                confidence=TAINTED_CONFIDENCE if shell == _SHELL_ON else 0.7,
            )
        elif kind is ArgumentKind.SANITIZED:
            yield self.sanitized_finding(node, context, info, sink)
        elif shell == _SHELL_ON and kind is ArgumentKind.DYNAMIC:
            yield self.create_finding(
                node, context, f"{name}() runs a dynamically built command with shell=True.",
                confidence=0.85,
            )
        elif shell == _SHELL_ON:
            # Lệnh hằng số với shell=True: không khai thác được nhưng vẫn là thói quen xấu.
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
        """Đọc giá trị của tham số shell= trong lời gọi."""
        keyword = get_keyword(call, "shell")
        if keyword is None:
            # shell mặc định là False. Nếu shell có thể ẩn trong **kwargs thì im lặng
            # thay vì đoán, để tránh false positive.
            return _SHELL_OFF
        if isinstance(keyword.value, ast.Constant):
            # Mọi hằng số "truthy" (True, 1, "yes") đều bật shell.
            return _SHELL_ON if keyword.value.value else _SHELL_OFF
        return _SHELL_MAYBE  # vd shell=use_shell
