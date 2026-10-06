"""Lớp cơ sở mà mọi security rule kế thừa, cùng các hàm chấm điểm finding dùng chung.

Cây kế thừa:

    SecurityRule            metadata + tạo finding + chấm điểm theo taint (dùng cho cả 3 ngôn ngữ)
    ├── CallRule            rule Python chỉ xét lời gọi hàm
    │   ├── DangerousCallRule   chỉ cần khai báo danh sách hàm nguy hiểm
    │   └── TaintedSinkRule     chỉ báo khi dữ liệu không tin cậy tới được sink
    └── TSRule (_ts_common.py)  rule Java/C#
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar

from app.analyzer.context import AnalysisContext
from app.analyzer.taint import TaintInfo
from app.analyzer.utils import get_argument
from app.models.finding import Finding, Severity

if TYPE_CHECKING:
    from app.config.settings import AnalyzerSettings


# Dữ liệu không tin cậy được chứng minh là tới được sink.
TAINTED_CONFIDENCE = 0.95
# Dữ liệu đã qua một sanitizer trong cấu hình. Vẫn được báo: analyzer không chứng
# minh được sanitizer phù hợp với sink này (vd shlex.quote không chống SQL injection).
SANITIZED_SEVERITY = Severity.LOW
SANITIZED_CONFIDENCE = 0.4


class ArgumentKind(Enum):
    """Phân loại nguồn gốc của argument đi vào sink - quyết định mức độ của finding."""

    TAINTED = "tainted"      # đến từ một source không tin cậy
    SANITIZED = "sanitized"  # đến từ source nhưng đã qua sanitizer
    STATIC = "static"        # cố định trong mã nguồn
    DYNAMIC = "dynamic"      # không rõ nguồn (tham số hàm, kết quả lời gọi hàm...)


class SecurityRule(ABC):
    """Bộ phát hiện (có thể cắm thêm) cho một mẫu code không an toàn.

    Lớp con khai báo metadata bằng thuộc tính class và cài đặt :meth:`check`.
    Engine chỉ gọi ``check`` với node AST có loại nằm trong ``node_types``, nên
    rule không bao giờ phải tự duyệt cây.
    """

    # ---- metadata bắt buộc của mọi rule (hiển thị trong report và `main.py rules`)
    id: ClassVar[str]               # vd "PY001"
    name: ClassVar[str]
    description: ClassVar[str]      # vì sao mẫu code này nguy hiểm
    severity: ClassVar[Severity]    # mức mặc định; từng finding có thể cao/thấp hơn theo ngữ cảnh
    cwe: ClassVar[str]
    category: ClassVar[str]
    recommendation: ClassVar[str]   # cách sửa
    # Loại node AST mà rule muốn nhận (Visitor chỉ gửi đúng các loại này).
    node_types: ClassVar[tuple[type[ast.AST], ...]] = (ast.Call,)
    # Rule "chung" (dựa trên blacklist) nhường cho rule chuyên biệt báo cùng vị trí.
    generic: ClassVar[bool] = False
    # Ngôn ngữ mà rule kiểm tra (python, java, csharp).
    language: ClassVar[str] = "python"

    _REQUIRED_ATTRIBUTES: ClassVar[tuple[str, ...]] = (
        "id", "name", "description", "severity", "cwe", "category", "recommendation",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Được Python gọi tự động mỗi khi một lớp con được định nghĩa."""
        super().__init_subclass__(**kwargs)
        # Báo lỗi ngay khi import nếu một rule cụ thể quên khai báo metadata
        # (thay vì lỗi khó hiểu lúc đang scan). Lớp cơ sở trung gian được bỏ qua
        # nhờ ``_abstract_rule = True``.
        if getattr(cls, "__abstractmethods__", None) or cls.__dict__.get("_abstract_rule", False):
            return
        missing = [attr for attr in cls._REQUIRED_ATTRIBUTES if not hasattr(cls, attr)]
        if missing:
            raise TypeError(f"Rule {cls.__name__} is missing attributes: {', '.join(missing)}")
        # Cho phép khai báo severity bằng chuỗi ("high") - chuẩn hóa thành enum.
        cls.severity = Severity.parse(cls.severity)

    def configure(self, settings: AnalyzerSettings) -> None:
        """Engine gọi một lần sau khi tạo rule; rule cần cấu hình (vd whitelist) thì ghi đè."""

    @abstractmethod
    def check(self, node: ast.AST, context: AnalysisContext) -> Iterable[Finding]:
        """Kiểm tra một node AST và yield 0 hoặc nhiều finding."""

    def create_finding(
        self,
        node: ast.AST,
        context: AnalysisContext,
        message: str,
        *,
        confidence: float,
        severity: Severity | None = None,
        source: str | None = None,
        sink: str | None = None,
        taint_path: list[str] | None = None,
        code: str | None = None,
        cwe: str | None = None,
    ) -> Finding:
        """Tạo Finding đã điền sẵn metadata của rule và vị trí của node.

        ``severity`` ghi đè mức mặc định khi ngữ cảnh làm vấn đề nặng hơn hoặc
        nhẹ hơn (vd dữ liệu không tin cậy tới được sink).
        ``code`` thay thế dòng code hiển thị trong report, vd để che secret.
        """
        line, column = node_location(node)
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.severity,
            confidence=confidence,
            file=context.filename,
            line=line,
            column=column,
            message=message,
            description=self.description,
            code=code if code is not None else context.get_line(line),
            recommendation=self.recommendation,
            cwe=cwe or self.cwe,
            category=self.category,
            source=source,
            sink=sink,
            taint_path=list(taint_path or []),
        )

    def metadata(self) -> dict[str, str]:
        """Thông tin tóm tắt của rule (dùng cho API /api/rules)."""
        return {
            "id": self.id,
            "language": self.language,
            "name": self.name,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "category": self.category,
            "description": self.description,
        }

    # ------------------------------------------------------------------ chấm điểm finding
    # Dùng chung cho rule Python, Java và C#: ``node`` là node ``ast`` hoặc node
    # tree-sitter, ``context`` là AnalysisContext hoặc TSContext.

    def tainted_finding(
        self,
        node: Any,
        context: Any,
        info: TaintInfo,
        sink: str,
        message: str | None = None,
        *,
        severity: Severity | None = None,
        confidence: float = TAINTED_CONFIDENCE,
        cwe: str | None = None,
    ) -> Finding:
        """Dữ liệu không tin cậy từ ``info.source`` được chứng minh là tới được ``sink``.

        Finding kèm source, sink và taint path để người đọc thấy đường đi của dữ liệu.
        """
        return self.create_finding(
            node, context, message or f"Untrusted input from {info.source} reaches {sink}.",
            severity=severity, confidence=confidence, cwe=cwe, **taint_details(info, sink),
        )

    def sanitized_finding(self, node: Any, context: Any, info: TaintInfo, sink: str, *, cwe: str | None = None) -> Finding:
        """source -> sanitizer -> sink: báo mức LOW vì sanitizer có thể không phù hợp với sink này."""
        return self.create_finding(
            node, context, sanitized_message(info, sink),
            severity=SANITIZED_SEVERITY, confidence=SANITIZED_CONFIDENCE, cwe=cwe, **taint_details(info, sink),
        )

    def graded_finding(
        self,
        node: Any,
        context: Any,
        kind: ArgumentKind,
        info: TaintInfo | None,
        sink: str,
        *,
        dynamic_message: str,
        static_message: str | None = None,
        dynamic_confidence: float = 0.8,
        static_confidence: float = 0.6,
        tainted_severity: Severity = Severity.CRITICAL,
        static_severity: Severity = Severity.LOW,
        cwe: str | None = None,
    ) -> Finding | None:
        """Finding được chấm điểm theo nguồn gốc argument đi vào sink.

        * tainted (source không tin cậy tới được sink): ``tainted_severity``, kèm
          source, sink và taint path;
        * sanitized (source -> sanitizer -> sink): LOW, confidence thấp;
        * dynamic (tham số, kết quả lời gọi hàm...): severity mặc định của rule;
        * static (cố định trong mã nguồn): ``static_severity``, hoặc không báo
          nếu không có ``static_message``, vì kẻ tấn công không tác động trực tiếp được.

        Vd với ``os.system``: ``os.system(input())`` -> CRITICAL,
        ``os.system(cmd)`` (cmd là tham số) -> HIGH, ``os.system("ls")`` -> LOW.
        """
        if kind is ArgumentKind.TAINTED and info is not None:
            return self.tainted_finding(node, context, info, sink, severity=tainted_severity, cwe=cwe)
        if kind is ArgumentKind.SANITIZED and info is not None:
            return self.sanitized_finding(node, context, info, sink, cwe=cwe)
        if kind is ArgumentKind.STATIC:
            if static_message is None:
                return None
            return self.create_finding(
                node, context, static_message, severity=static_severity, confidence=static_confidence, cwe=cwe,
            )
        return self.create_finding(node, context, dynamic_message, confidence=dynamic_confidence, cwe=cwe)


class CallRule(SecurityRule):
    """Lớp cơ sở cho rule Python chỉ kiểm tra lời gọi hàm.

    :meth:`check_call` nhận lời gọi cùng tên đầy đủ của hàm được gọi (đã giải
    alias import; None với vd ``f()()``), nên lớp con không phải lặp lại phần
    kiểm tra ``isinstance(node, ast.Call)`` và lấy tên hàm.
    """

    _abstract_rule = True
    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if isinstance(node, ast.Call):
            yield from self.check_call(node, context.call_name(node), context)

    @abstractmethod
    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterable[Finding]:
        """Kiểm tra một lời gọi hàm và yield 0 hoặc nhiều finding."""


class DangerousCallRule(CallRule):
    """Lớp cơ sở cho rule báo các lời gọi tới một số hàm nguy hiểm cụ thể.

    Finding được chấm điểm bằng :meth:`SecurityRule.graded_finding` theo nguồn
    gốc của argument được kiểm tra. Lớp con chỉ cần khai báo ``target_functions``
    (tên đầy đủ; alias import đã được giải) và các message - xem eval_rule.py.
    """

    _abstract_rule = True

    target_functions: ClassVar[frozenset[str]]
    # Vị trí / tên keyword của argument nguy hiểm (mặc định argument đầu tiên).
    argument_position: ClassVar[int] = 0
    argument_keyword: ClassVar[str | None] = None
    # Message có thể chứa {name} - được thay bằng tên hàm thực tế.
    dynamic_message: ClassVar[str]
    static_message: ClassVar[str]
    dynamic_confidence: ClassVar[float] = 0.8
    static_severity: ClassVar[Severity] = Severity.LOW
    static_confidence: ClassVar[float] = 0.6
    tainted_severity: ClassVar[Severity] = Severity.CRITICAL

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        # Bỏ qua builtin bị file định nghĩa lại (def eval(...) cục bộ).
        if name not in self.target_functions or context.is_shadowed_builtin(name):
            return
        argument = get_argument(node, self.argument_position, self.argument_keyword)
        if argument is None:
            return
        kind, info = classify_argument(argument, context)
        yield self.graded_finding(
            node, context, kind, info, f"{name}()",
            dynamic_message=self.dynamic_message.format(name=name),
            static_message=self.static_message.format(name=name),
            dynamic_confidence=self.dynamic_confidence,
            static_confidence=self.static_confidence,
            tainted_severity=self.tainted_severity,
            static_severity=self.static_severity,
        )


class TaintedSinkRule(CallRule):
    """Lớp cơ sở cho sink chỉ nguy hiểm khi nhận dữ liệu không tin cậy (đường dẫn file, URL).

    Lời gọi như ``open(path)`` hay ``requests.get(url)`` có mặt ở khắp nơi, nên
    báo mọi argument động sẽ nhấn chìm các lỗi thật: chỉ luồng đi từ một taint
    source mới được báo. Dữ liệu đã được làm sạch bởi sanitizer của
    ``sanitizer_category`` của rule (``sink_sanitizers`` trong taint.json, vd
    ``os.path.basename`` cho đường dẫn) thì hoàn toàn không bị báo.

    Lớp con cài đặt :meth:`sink_arguments`; mỗi lời gọi tối đa một finding.
    """

    _abstract_rule = True

    # Loại sink, vd "path" hoặc "url" - khớp với khóa trong sink_sanitizers.
    sanitizer_category: ClassVar[str]

    @abstractmethod
    def sink_arguments(
        self, node: ast.Call, name: str | None, context: AnalysisContext,
    ) -> Iterable[tuple[ast.AST, str]]:
        """Các cặp (argument, tên sink) của ``node`` không được phép mang dữ liệu không tin cậy."""

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        for argument, sink in self.sink_arguments(node, name, context):
            kind, info = classify_argument(argument, context)
            # Không có taint (tĩnh / không rõ nguồn) hoặc đã được làm sạch cho đúng loại sink: bỏ qua.
            if info is None or self.sanitizer_category in info.safe_for:
                continue
            if kind is ArgumentKind.SANITIZED:
                yield self.sanitized_finding(node, context, info, sink)
            else:
                yield self.untrusted_finding(node, context, argument, info, sink)
            return  # một lời gọi chỉ báo một lần (vd shutil.copy có cả src lẫn dst bị taint)

    def untrusted_finding(
        self, node: ast.Call, context: AnalysisContext, argument: ast.AST, info: TaintInfo, sink: str,
    ) -> Finding:
        """Hook (Template Method) cho rule muốn chấm điểm chi tiết hơn (vd PY015 khi host của URL cố định)."""
        return self.tainted_finding(node, context, info, sink)


def node_location(node: Any) -> tuple[int, int]:
    """(dòng, cột) của node ``ast`` Python hoặc node tree-sitter (dòng tính từ 1)."""
    if hasattr(node, "lineno"):
        return node.lineno, getattr(node, "col_offset", 0)
    # tree-sitter đánh số dòng từ 0 -> cộng 1.
    point = getattr(node, "start_point", None)
    if point is not None:
        return point[0] + 1, point[1]
    return 0, 0


# ------------------------------------------------------------------ tiện ích về taint


def classify_argument(argument: ast.AST, context: AnalysisContext) -> tuple[ArgumentKind, TaintInfo | None]:
    """Phân loại một argument (tainted / sanitized / static / dynamic) từ kết quả taint của context.

    Hoạt động với cả TaintResult (Python) lẫn TSTaintResult (Java/C#) vì cùng giao diện.
    """
    info = context.taint.lookup(argument)
    if info is not None:
        return (ArgumentKind.SANITIZED if info.sanitized else ArgumentKind.TAINTED), info
    if context.taint.is_static(argument):
        return ArgumentKind.STATIC, None
    return ArgumentKind.DYNAMIC, None


def taint_details(info: TaintInfo, sink: str) -> dict[str, Any]:
    """Các keyword argument cho create_finding mô tả luồng dữ liệu (source, sink, taint path)."""
    return {"source": info.source, "sink": sink, "taint_path": [*info.path, sink]}


def sanitized_message(info: TaintInfo, sink: str) -> str:
    """Message chung cho luồng đã đi qua sanitizer."""
    sanitizer = f"{info.sanitizer}()" if info.sanitizer else "a configured sink-specific sanitizer"
    return (
        f"Input from {info.source} reaches {sink} after {sanitizer}; "
        "the analyzer cannot prove this sanitizer is sufficient."
    )
