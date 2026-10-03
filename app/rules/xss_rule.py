"""PY018 - Cross-site scripting (XSS) và server-side template injection (SSTI)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.taint import TaintInfo
from app.analyzer.utils import get_argument, get_keyword, string_parts
from app.models.finding import Finding, Severity
from app.rules._values import assigned_values, is_string_building
from app.rules.base import ArgumentKind, CallRule, classify_argument
from app.rules.registry import register_rule

# CWE riêng cho template injection (nặng hơn XSS: chạy code trên server).
_SSTI_CWE = "CWE-1336"
# Hàm biên dịch argument của nó thành MÃ NGUỒN template.
_TEMPLATE_SOURCE = frozenset({
    "flask.render_template_string", "flask.templating.render_template_string", "jinja2.Template",
})
# Hàm đánh dấu chuỗi là HTML an toàn, tức là bỏ qua cơ chế tự động escape.
_MARK_SAFE = frozenset({
    "markupsafe.Markup", "flask.Markup", "jinja2.Markup",
    "django.utils.safestring.mark_safe", "django.utils.html.mark_safe",
})
# Class response mà nội dung mặc định được gửi với kiểu text/html.
_HTML_RESPONSES = frozenset({
    "flask.make_response", "flask.Response", "werkzeug.wrappers.Response",
    "django.http.HttpResponse", "django.http.response.HttpResponse",
    "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse",
})
# Dấu hiệu chuỗi chứa thẻ HTML: <p, </div, <!DOCTYPE...
_HTML_TAG = re.compile(r"<[a-zA-Z!/]")
# Decorator đăng ký một view kiểu Flask/FastAPI: @app.route(...), @bp.get(...).
_ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "patch", "delete"})


@register_rule
class XssRule(CallRule):
    """PY018: gồm 4 nhóm kiểm tra (xem các phương thức bên dưới).

    1. Template injection: ``render_template_string(<chuỗi từ người dùng>)``.
    2. ``Markup()``/``mark_safe()`` bọc dữ liệu chưa escape.
    3. ``jinja2.Environment`` tắt autoescape.
    4. Trả HTML ghép từ dữ liệu request (return hoặc make_response/HttpResponse).
    """

    id = "PY018"
    name = "Cross-site scripting (XSS) / template injection"
    description = (
        "Untrusted data reaches HTML output without escaping, so an attacker can inject "
        "<script> that runs in other users' browsers (session theft, actions on their "
        "behalf). When the data becomes template source code (render_template_string), "
        "the attacker can also run code on the server ({{ ... }} template injection)."
    )
    severity = Severity.HIGH
    cwe = "CWE-79"
    category = "Cross-Site Scripting"
    recommendation = (
        "Render fixed templates and pass data as variables: render_template('page.html', name=name). "
        "Keep Jinja2 autoescaping on (autoescape=select_autoescape()); do not wrap user data in "
        "Markup()/mark_safe(); escape it with markupsafe.escape() / html.escape() when building HTML."
    )
    # Ngoài lời gọi hàm còn xét câu lệnh return (view trả về chuỗi HTML).
    node_types = (ast.Call, ast.Return)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        # Ghi đè check của CallRule để xử lý thêm ast.Return; lời gọi hàm vẫn đi qua lớp cha.
        if isinstance(node, ast.Return):
            if node.value is not None:
                yield from self._check_html_output(node, node.value, context, "return")
        else:
            yield from super().check(node, context)

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        if name in _TEMPLATE_SOURCE:
            yield from self._check_template_source(node, context, name)
        elif name in _MARK_SAFE:
            yield from self._check_mark_safe(node, context, name)
        elif name == "jinja2.Environment":
            yield from self._check_autoescape(node, context)
        elif name in _HTML_RESPONSES:
            if not self._is_non_html_response(node):
                argument = get_argument(node, 0)
                if argument is not None:
                    yield from self._check_html_output(node, argument, context, f"{name}()")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "from_string":
            # jinja2 env.from_string(source): chỉ báo khi dữ liệu không tin cậy,
            # vì không chứng minh được kiểu của đối tượng nhận.
            argument = get_argument(node, 0, "source")
            info = context.taint.lookup(argument)
            if info is not None and not info.sanitized:
                yield self._ssti_finding(node, context, info, ".from_string()")

    # ------------------------------------------------------------------ template injection

    def _check_template_source(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        """render_template_string(source): source phải là template cố định, dữ liệu truyền qua biến."""
        source = get_argument(node, 0, "source")
        if source is None:
            return
        sink = f"{name}()"
        kind, info = classify_argument(source, context)
        # Escape HTML không chặn được {{ 7*7 }} (không có ký tự HTML nào),
        # nên sanitizer loại "html" bị bỏ qua ở đây (không xét safe_for).
        if kind is ArgumentKind.TAINTED:
            yield self._ssti_finding(node, context, info, sink)
        elif kind is ArgumentKind.SANITIZED:
            yield self.sanitized_finding(node, context, info, sink, cwe=_SSTI_CWE)
        elif kind is ArgumentKind.DYNAMIC and any(is_string_building(v) for v in assigned_values(source, context)):
            # Không rõ nguồn nhưng template được ghép chuỗi -> thói quen nguy hiểm.
            # Biến template không rõ nguồn mà không ghép chuỗi (vd đọc từ DB) thì không báo.
            yield self.create_finding(
                node, context,
                f"Template source passed to {sink} is built from dynamic values; "
                "pass them as template variables instead.",
                confidence=0.75, cwe=_SSTI_CWE,
            )

    def _ssti_finding(self, node: ast.Call, context: AnalysisContext, info: TaintInfo, sink: str) -> Finding:
        """Template injection với dữ liệu không tin cậy: CRITICAL (có thể chạy code trên server)."""
        return self.tainted_finding(
            node, context, info, sink, f"Untrusted input from {info.source} is compiled as template source by {sink}.",
            severity=Severity.CRITICAL, cwe=_SSTI_CWE,
        )

    # ------------------------------------------------------------------ XSS

    def _check_mark_safe(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        """Markup(x) / mark_safe(x): x sẽ được chèn vào trang mà không escape."""
        argument = get_argument(node, 0)
        if argument is None:
            return
        sink = f"{name}()"
        kind, info = classify_argument(argument, context)
        # Đã escape HTML trước (Markup(escape(x))) -> an toàn.
        if info is not None and "html" in info.safe_for:
            return
        if kind is ArgumentKind.TAINTED:
            yield self.tainted_finding(
                node, context, info, sink, f"Untrusted input from {info.source} is marked as safe HTML by {sink}.",
            )
        elif kind is ArgumentKind.SANITIZED:
            yield self.sanitized_finding(node, context, info, sink)
        elif kind is ArgumentKind.DYNAMIC:
            yield self.create_finding(
                node, context, f"{sink} disables escaping for a value that is not a constant.",
                severity=Severity.MEDIUM, confidence=0.5,
            )

    def _check_autoescape(self, node: ast.Call, context: AnalysisContext) -> Iterator[Finding]:
        """jinja2.Environment(): MẶC ĐỊNH của Jinja2 là KHÔNG escape (khác với Flask)."""
        autoescape = get_keyword(node, "autoescape")
        if autoescape is None:
            if any(keyword.arg is None for keyword in node.keywords):
                return  # có thể được đặt qua **options - không đoán
            yield self.create_finding(
                node, context, "jinja2.Environment() without autoescape= does not escape HTML (Jinja2 default).",
                severity=Severity.MEDIUM, confidence=0.7,
            )
        elif isinstance(autoescape.value, ast.Constant) and not autoescape.value.value:
            yield self.create_finding(
                node, context, "jinja2.Environment(autoescape=False) disables HTML escaping.", confidence=0.9,
            )
        # autoescape=True / select_autoescape(...) / biến: không báo.

    def _check_html_output(
        self, node: ast.AST, value: ast.AST, context: AnalysisContext, sink: str,
    ) -> Iterator[Finding]:
        """HTML ghép từ dữ liệu request rồi gửi lại trong response (reflected XSS)."""
        info = context.taint.lookup(value)
        # Chỉ xét dữ liệu từ request web (XSS cần trình duyệt); input() của CLI thì không.
        if info is None or info.sanitized or "html" in info.safe_for or not info.source.startswith("request"):
            return
        values = assigned_values(value, context)
        building = any(is_string_building(v) for v in values)
        # Trường hợp 1: chuỗi được ghép VÀ phần chữ chứa thẻ HTML -> chắc chắn là HTML.
        # (Constant được tính vì html = "<ul>"; html += f"<li>{x}</li>" có phần thẻ nằm ở phép gán đầu.)
        if (building or any(isinstance(v, ast.Constant) for v in values)) and any(
            _HTML_TAG.search(part) for v in values for part in string_parts(v)
        ):
            yield self.tainted_finding(
                node, context, info, sink, f"HTML built from untrusted input ({info.source}) is sent in the response.",
                confidence=0.9,
            )
        # Trường hợp 2: lệnh return không có thẻ HTML - chỉ báo trong hàm view (helper trả chuỗi là bình thường).
        elif sink == "return":
            if building and self._is_route_handler(node, context):
                # Flask gửi chuỗi được return với kiểu text/html.
                yield self.tainted_finding(
                    node, context, info, sink,
                    f"A view returns a string built from untrusted input ({info.source}) without escaping.",
                    severity=Severity.MEDIUM, confidence=0.7,
                )
        # Trường hợp 3: make_response(request.args["q"]) - dữ liệu thô làm nội dung HTML.
        # Bỏ qua khi argument là lời gọi hàm (vd jsonify(...)) vì thường không phải HTML.
        elif not isinstance(value, ast.Call):
            yield self.tainted_finding(
                node, context, info, sink, f"Untrusted input from {info.source} is sent unescaped as an HTML response.",
                severity=Severity.MEDIUM, confidence=0.6,
            )

    @staticmethod
    def _is_route_handler(node: ast.AST, context: AnalysisContext) -> bool:
        """True nếu node nằm trong hàm có decorator kiểu @app.route / @bp.get."""
        scope = context.enclosing_scope(node)
        for decorator in getattr(scope, "decorator_list", []):
            # @app.route("/x") là Call; @app.get không ngoặc là Attribute.
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr in _ROUTE_DECORATORS:
                return True
        return False

    @staticmethod
    def _is_non_html_response(node: ast.Call) -> bool:
        """True nếu response khai báo rõ kiểu nội dung không phải HTML (vd mimetype="text/plain")."""
        for keyword in ("mimetype", "content_type", "media_type"):
            found = get_keyword(node, keyword)
            if found is not None and isinstance(found.value, ast.Constant):
                return "html" not in str(found.value.value).lower()
        return False
