"""Các khối dựng dùng chung cho rule Java (JVxxx) và C# (CSxxx).

Dấu gạch dưới ở đầu tên khiến registry không nạp module này như một module
rule; các rule cụ thể nằm trong java_rules.py và csharp_rules.py và phần lớn
chỉ khai báo tên API. Logic chung của mỗi loại lỗ hổng nằm ở các lớp
``*RuleBase`` bên dưới (kế thừa TSRule).
"""

from __future__ import annotations

import ast
import re
from abc import abstractmethod
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any, ClassVar

from app.analyzer.taint import TaintInfo
from app.analyzer.ts.context import TSContext
from app.analyzer.utils import split_identifier
from app.models.finding import Finding, Severity
from app.rules.base import ArgumentKind, SecurityRule, classify_argument
from app.rules.crypto_rule import InsecureRandomMixin
from app.rules.secret_rule import HardcodedSecretMixin, is_placeholder, masked_line
from app.rules.sql_rule import SQL_KEYWORDS

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

# Thứ tự từ tệ nhất: một argument tainted quyết định finding dù các argument khác là hằng số.
_KIND_ORDER = {ArgumentKind.TAINTED: 0, ArgumentKind.DYNAMIC: 1, ArgumentKind.SANITIZED: 2, ArgumentKind.STATIC: 3}

# Chương trình shell: chạy chúng với "-c <lệnh>" thì chuỗi lệnh được shell diễn giải.
SHELLS = frozenset({"sh", "bash", "zsh", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh",
                    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"})
# Cờ đi kèm shell để chạy một chuỗi lệnh (bỏ qua khi tìm argument là lệnh thật).
SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "-command", "/k", "/K"})


class TSRule(SecurityRule):
    """Rule cho ngôn ngữ dùng tree-sitter: xem xét toàn bộ context của file một lần.

    Khác rule Python (engine gọi ``check`` cho từng node), engine gọi
    ``check_file(ctx)`` một lần cho mỗi file Java/C#.
    """

    _abstract_rule = True
    node_types = ()

    def check(self, node: ast.AST, context: Any) -> Iterable[Finding]:
        return ()  # không dùng: engine gọi check_file() cho Java/C#

    @abstractmethod
    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        """Yield các finding của một file Java/C#."""

    # ------------------------------------------------------------------ tiện ích chấm điểm

    # Finding được chấm điểm bằng SecurityRule.graded_finding / tainted_finding, giống rule Python.

    def worst_argument(self, args: Iterable[Node], ctx: TSContext) -> tuple[ArgumentKind, TaintInfo | None]:
        """Argument "tệ nhất" trong danh sách (vd lệnh shell ghép từ nhiều phần)."""
        graded = [classify_argument(arg, ctx) for arg in args]
        if not graded:
            return ArgumentKind.DYNAMIC, None
        return min(graded, key=lambda item: _KIND_ORDER[item[0]])


def string_value(ctx: TSContext, node: Node | None) -> str | None:
    """Giá trị chuỗi hằng của node (đã bỏ lớp ngoặc/ép kiểu), hoặc None."""
    if node is None:
        return None
    return ctx.adapter.string_value(ctx.adapter.unwrap(node))


def string_parts(ctx: TSContext, node: Node) -> list[str]:
    """Các mảnh chữ cố định của một biểu thức (nối chuỗi, chuỗi nội suy, lời gọi format)."""
    parts: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        value = ctx.adapter.string_value(current)
        if value is not None:
            parts.append(value)
            continue
        # Phần chữ bên trong chuỗi nội suy $"..." của C#.
        if current.type == "string_content":
            parts.append(ctx.adapter.text(current))
        stack.extend(current.named_children)
    return parts


# --------------------------------------------------------------------------- command injection


def flatten_command(ctx: TSContext, args: list[Node]) -> list[Node]:
    """Chương trình + các argument: ``new String[]{"sh", "-c", c}``, ``List.of(...)``, varargs."""
    if len(args) == 1:
        elements = ctx.adapter.array_elements(ctx.adapter.unwrap(args[0]))
        if elements is not None:
            return elements
        inner = ctx.call_by_node.get(ctx.adapter.unwrap(args[0]).id)
        if inner is not None and inner.names & {"Arrays.asList", "List.of"}:
            return inner.args
    return args


class CommandRuleBase(TSRule):
    """JV001 / CS001: chấm điểm một chương trình + danh sách argument giống PY003/PY004 của Python."""

    _abstract_rule = True
    severity = Severity.HIGH
    cwe = "CWE-78"
    category = "Command Injection"

    def grade_program(self, node: Node, ctx: TSContext, program: list[Node], sink: str) -> Finding | None:
        """``program[0]`` là file chạy, phần còn lại là argument (ProcessBuilder, exec(String[]))."""
        if not program:
            return None
        executable = program[0]
        # Bản thân chương trình được chọn lúc chạy -> nguy hiểm dù không có shell.
        if not ctx.taint.is_static(executable):
            kind, info = classify_argument(executable, ctx)
            return self.graded_finding(node, ctx, kind, info, sink,
                                       dynamic_message=f"{sink} runs a program chosen at runtime.")
        name = (string_value(ctx, executable) or "").strip().lower()
        if name.split(" ", 1)[0] not in SHELLS and name not in SHELLS:
            # Chương trình cố định và không qua shell: argument không thể chèn thêm lệnh mới.
            return None
        # Chạy qua shell: xét các argument còn lại (bỏ cờ -c, /c).
        rest = [arg for arg in program[1:] if (string_value(ctx, arg) or "") not in SHELL_FLAGS]
        kind, info = self.worst_argument(rest, ctx)
        return self.graded_finding(
            node, ctx, kind, info, sink,
            dynamic_message=f"{sink} runs a dynamically built command through a shell.",
            static_message=f"{sink} runs a constant command through a shell.",
            dynamic_confidence=0.85,
        )

    def grade_command_line(self, node: Node, ctx: TSContext, command: Node, sink: str) -> Finding | None:
        """Một chuỗi lệnh duy nhất (Runtime.exec(String), Process.Start(string))."""
        kind, info = classify_argument(command, ctx)
        return self.graded_finding(
            node, ctx, kind, info, sink,
            dynamic_message=f"{sink} runs a dynamically built command line.",
            static_message=f"{sink} runs a constant command line.",
        )


# --------------------------------------------------------------------------- SQL injection


def unsafe_query_build(ctx: TSContext, node: Node) -> bool:
    """Chuỗi ghép từ chữ cố định và giá trị động (+, chuỗi nội suy, format) - bản Java/C# của sql_rule."""
    adapter = ctx.adapter
    node = adapter.unwrap(node)
    if adapter.is_static(node):
        return False
    if node.type == adapter.binary_type and adapter.operator(node) == "+":
        return bool(string_parts(ctx, node))
    if node.type in adapter.interpolated_types:
        return bool(adapter.interpolation_values(node))
    # String.format(...), "...".formatted(...), String.Concat(...), String.Join(...)
    call = ctx.call_by_node.get(node.id)
    if call is not None and call.method.lower() in {"format", "formatted", "concat", "join"}:
        return bool(string_parts(ctx, node)) and not all(ctx.taint.is_static(arg) for arg in call.args)
    return False


class SqlRuleBase(TSRule):
    """Logic chung của JV002 / CS002 (cùng cách chấm điểm với PY011)."""

    _abstract_rule = True
    cwe = "CWE-89"
    category = "SQL Injection"
    severity = Severity.HIGH
    # Từ trong tên biến/kiểu của đối tượng nhận cho thấy đó là đối tượng database.
    db_words: ClassVar[frozenset[str]] = frozenset({
        "statement", "stmt", "st", "ps", "conn", "connection", "db", "database", "session", "jdbc", "template",
        "em", "entity", "manager", "cmd", "command", "context", "ctx", "sql",
    })

    def grade_query(self, node: Node, ctx: TSContext, query: Node, sink: str, certain_sink: bool,
                    receiver: Node | None = None) -> Finding | None:
        """Chấm điểm câu query đi vào sink.

        ``certain_sink``: method chắc chắn nhận SQL (executeQuery) hay chỉ là tên
        chung (execute, Query) cần thêm bằng chứng từ đối tượng nhận / từ khóa SQL.
        """
        likely_db = certain_sink or self._db_receiver(ctx, receiver)
        kind, info = classify_argument(query, ctx)
        if kind in (ArgumentKind.TAINTED, ArgumentKind.SANITIZED):
            if not likely_db and not SQL_KEYWORDS.search(" ".join(string_parts(ctx, query))):
                return None
            if kind is ArgumentKind.TAINTED:
                return self.tainted_finding(
                    node, ctx, info, sink,
                    f"Untrusted input from {info.source} is used to build the SQL query passed to {sink}.",
                    severity=Severity.CRITICAL,
                )
            return self.sanitized_finding(node, ctx, info, sink)
        if kind is ArgumentKind.STATIC:
            return None
        # Không rõ nguồn: báo hành vi ghép chuỗi SQL.
        built_at, parts = self._find_unsafe_build(ctx, query, node)
        if built_at is None:
            return None
        looks_like_sql = bool(SQL_KEYWORDS.search(" ".join(parts)))
        if not looks_like_sql and not likely_db:
            return None
        where = "" if built_at == node.start_point[0] + 1 else f" (built on line {built_at})"
        if looks_like_sql:
            return self.create_finding(node, ctx, f"SQL query built from dynamic values{where} is passed to {sink}.",
                                       confidence=0.85, sink=sink)
        return self.create_finding(node, ctx, f"Dynamically built string{where} is passed to {sink}.",
                                   severity=Severity.MEDIUM, confidence=0.55, sink=sink)

    def _find_unsafe_build(self, ctx: TSContext, query: Node, sink_node: Node) -> tuple[int | None, list[str]]:
        """Dòng nơi câu SQL không an toàn được ghép, kèm các mảnh chữ (lần theo biến qua nhiều dòng)."""
        query = ctx.adapter.unwrap(query)
        if unsafe_query_build(ctx, query):
            return sink_node.start_point[0] + 1, string_parts(ctx, query)
        if query.type != "identifier":
            return None, []
        history = ctx.assignments_before(ctx.adapter.text(query), sink_node)
        # Bắt đầu từ phép gán thường cuối cùng (các giá trị trước đó đã bị ghi đè).
        start = max((i for i, (_, _, augmented) in enumerate(history) if not augmented), default=0)
        relevant = history[start:]
        parts = [part for _, value, _ in relevant for part in string_parts(ctx, value)]
        for line, value, augmented in relevant:
            unsafe = not ctx.taint.is_static(value) if augmented else unsafe_query_build(ctx, value)
            if unsafe:
                return line, parts
        return None, []

    def _db_receiver(self, ctx: TSContext, receiver: Node | None) -> bool:
        """True nếu tên biến hoặc kiểu của đối tượng nhận giống database (vd jdbcTemplate, SqlConnection)."""
        if receiver is None:
            return False
        words = split_identifier(ctx.adapter.text(receiver).rsplit(".", 1)[-1])
        type_name = ctx.type_of(receiver) or ""
        return any(word in self.db_words for word in words) or any(
            word in self.db_words for word in split_identifier(type_name))


# --------------------------------------------------------------------------- deserialization, code injection


class DeserializationRuleBase(TSRule):
    """JV003 / CS003: bộ deserialize có thể tạo đối tượng của kiểu bất kỳ."""

    _abstract_rule = True
    name = "Unsafe deserialization"
    severity = Severity.HIGH
    cwe = "CWE-502"
    category = "Insecure Deserialization"
    # Lớp con có thể thay message; {call} được thay bằng tên lời gọi.
    dynamic_message: ClassVar[str] = "{call} deserializes data that may be attacker-controlled."

    def deserialization_finding(self, call: Any, ctx: TSContext, data: Node | None) -> Finding | None:
        """Chấm điểm theo nguồn của dữ liệu được deserialize (``data`` None = không xác định được)."""
        kind, info = classify_argument(data, ctx) if data is not None else (ArgumentKind.DYNAMIC, None)
        if kind is ArgumentKind.STATIC:
            kind = ArgumentKind.DYNAMIC  # stream/file "cố định" vẫn có thể bị kẻ tấn công thay nội dung
        return self.graded_finding(call.node, ctx, kind, info, call.display,
                                   dynamic_message=self.dynamic_message.format(call=call.display))


class CodeInjectionRuleBase(TSRule):
    """JV004 / CS004: code hoặc biểu thức được thực thi từ một chuỗi."""

    _abstract_rule = True
    severity = Severity.CRITICAL
    cwe = "CWE-95"
    category = "Code Injection"
    # Lớp con bắt buộc khai báo hai message ({call} = tên lời gọi).
    dynamic_message: ClassVar[str]
    static_message: ClassVar[str]

    def code_finding(self, call: Any, ctx: TSContext, cwe: str | None = None) -> Finding | None:
        """Chấm điểm theo nguồn của chuỗi code (argument đầu tiên)."""
        kind, info = classify_argument(call.args[0], ctx)
        return self.graded_finding(
            call.node, ctx, kind, info, call.display,
            dynamic_message=self.dynamic_message.format(call=call.display),
            static_message=self.static_message.format(call=call.display), dynamic_confidence=0.85, cwe=cwe,
        )


# --------------------------------------------------------------------------- crypto, random


class WeakAlgorithmRuleBase(TSRule):
    """Lời gọi mà tên (hoặc argument thuật toán là hằng số) chọn một thuật toán yếu.

    Lớp con chỉ khai báo dữ liệu (weak_calls, algorithm_calls, weak_algorithm,
    weak_members) - không cần viết thêm code.
    """

    _abstract_rule = True
    severity = Severity.MEDIUM
    category = "Weak Cryptography"
    weak_calls: ClassVar[frozenset[str]] = frozenset()       # MD5.Create, new MD5CryptoServiceProvider
    algorithm_calls: ClassVar[frozenset[str]] = frozenset()  # MessageDigest.getInstance("MD5")
    weak_algorithm: ClassVar[re.Pattern[str]] = re.compile(r"(?!)")  # regex không bao giờ khớp (mặc định)
    weak_members: ClassVar[frozenset[str]] = frozenset()     # CipherMode.ECB
    confidence: ClassVar[float] = 0.7

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.names & self.weak_calls:
                yield self.create_finding(call.node, ctx, f"{call.display} uses a weak algorithm.",
                                          confidence=self.confidence)
            elif call.names & self.algorithm_calls and call.args:
                # Thuật toán chọn bằng chuỗi: chỉ báo khi là hằng số khớp regex (biết chắc là yếu).
                algorithm = string_value(ctx, call.args[0])
                if algorithm is not None and self.weak_algorithm.search(algorithm):
                    yield self.create_finding(call.node, ctx, f"{call.display} selects weak algorithm '{algorithm}'.",
                                              confidence=0.85)
        if self.weak_members:
            # Duyệt cây tìm truy cập thành viên như CipherMode.ECB.
            stack = [ctx.root]
            while stack:
                node = stack.pop()
                if node.type in ctx.adapter.member_types and ctx.adapter.text(node).replace(" ", "") in self.weak_members:
                    yield self.create_finding(node, ctx, f"{ctx.adapter.text(node)} is an insecure mode.",
                                              confidence=0.8)
                    continue
                stack.extend(node.named_children)


class InsecureRandomRuleBase(InsecureRandomMixin, TSRule):
    """JV007 / CS007: logic quyết định dùng chung với PY009 qua InsecureRandomMixin."""

    _abstract_rule = True
    # Kiểu của đối tượng nhận được coi là bộ sinh không an toàn (rnd.nextInt() với Random rnd).
    random_types: ClassVar[frozenset[str]] = frozenset({"Random"})
    random_calls: ClassVar[frozenset[str]] = frozenset()  # Math.random, RandomStringUtils.random...

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            # new Random() chưa sinh giá trị nào; chỉ xét lời gọi method trên nó.
            if call.is_constructor:
                continue
            uses_random = (call.receiver_type in self.random_types) or bool(call.names & self.random_calls)
            if not uses_random:
                continue
            finding = self.random_use_finding(
                call.node, ctx, call.display, ctx.assigned_name(call.node), ctx.enclosing_method_name(call.node),
            )
            if finding is not None:
                yield finding


# --------------------------------------------------------------------------- secrets

# "Password=xyz;" bên trong JDBC URL / connection string của ADO.NET.
_CONNECTION_PASSWORD = re.compile(r"(?i)(?:^|[;?&])\s*(?:password|pwd)\s*=\s*([^;&\s\"']+)")


class HardcodedSecretRuleBase(HardcodedSecretMixin, TSRule):
    """JV008 / CS008: dùng chung logic với PY007 qua HardcodedSecretMixin, thêm kiểm tra connection string."""

    _abstract_rule = True
    description = (
        "A credential (password, API key, token, private key, connection string password) is written "
        "directly in the source code, where anyone with access to the repository or binaries can read it."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        # Id các chuỗi đã báo, để bước kiểm tra theo tên không báo trùng.
        reported: set[int] = set()
        # Bước 1: mọi chuỗi hằng - định dạng secret nổi tiếng và mật khẩu trong connection string.
        for string in ctx.strings:
            value = ctx.adapter.string_value(string)
            if value is None or self.whitelist.is_secret_allowed(value):
                continue
            known = list(self.check_known_format(string, ctx, value))
            if known:
                reported.add(string.id)
                yield from known
                continue
            match = _CONNECTION_PASSWORD.search(value)
            if match and not is_placeholder(match.group(1)):
                reported.add(string.id)
                # Chỉ che phần mật khẩu, giữ phần còn lại của connection string để dễ nhận ra.
                yield self.create_finding(string, ctx, "Connection string contains a hardcoded password.",
                                          confidence=0.85, code=masked_line(string, ctx, match.group(1)))
        # Bước 2: chuỗi hằng được gán cho tên giống thông tin đăng nhập.
        for name, value_node in self._named_values(ctx):
            value_node = ctx.adapter.unwrap(value_node)
            value = ctx.adapter.string_value(value_node)
            if value is not None and value_node.id not in reported:
                yield from self.check_named_value(value_node, ctx, name, value)

    @staticmethod
    def _named_values(ctx: TSContext) -> Iterator[tuple[str, Node]]:
        """Các cặp (tên, giá trị) từ khai báo, phép gán và object initializer."""
        for declaration in ctx.declarations:
            if declaration.value is not None:
                yield declaration.name, declaration.value
        for assignment in ctx.assignments:
            # this.dbPassword = "..." -> tên "dbPassword"
            yield assignment.target.rsplit(".", 1)[-1], assignment.value
        for call in ctx.calls:
            for prop, value in call.initializer.items():  # C#: new X { Password = "..." }
                yield prop, value
