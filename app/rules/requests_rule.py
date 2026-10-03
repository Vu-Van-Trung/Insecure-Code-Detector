"""PY010 - Tắt kiểm tra chứng chỉ TLS (verify=False, ssl.CERT_NONE)."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_keyword
from app.models.finding import Finding, Severity
from app.rules.base import SecurityRule
from app.rules.registry import register_rule

# Thư viện HTTP client mà hàm/class của chúng nhận tham số verify=.
_HTTP_LIBRARIES = ("requests.", "httpx.")
# Tên method của đối tượng session/client (vd session.get(url, verify=False)),
# khi không suy ra được kiểu của đối tượng bằng phân tích tĩnh.
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "send"})
# Hàm tạo SSL context không kiểm tra chứng chỉ.
_UNVERIFIED_CONTEXT = frozenset({"ssl._create_unverified_context", "ssl._create_stdlib_context"})


@register_rule
class TlsVerificationDisabledRule(SecurityRule):
    """PY010 kế thừa thẳng SecurityRule (không phải CallRule) vì còn xét node Attribute/Name (ssl.CERT_NONE)."""

    id = "PY010"
    name = "TLS certificate verification disabled"
    description = (
        "Without certificate verification the client accepts any certificate, so an "
        "attacker on the network (public Wi-Fi, compromised router, proxy) can intercept "
        "and modify HTTPS traffic, including credentials (man-in-the-middle)."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-295"
    category = "Insecure Transport"
    recommendation = (
        "Keep verify=True (the default). For internal or self-signed certificates, pass "
        "the CA bundle path instead: requests.get(url, verify='/path/to/ca.pem')."
    )
    node_types = (ast.Call, ast.Attribute, ast.Name)

    def check(self, node: ast.AST, context: AnalysisContext) -> Iterator[Finding]:
        if isinstance(node, ast.Call):
            yield from self._check_call(node, context)
        # Chỉ xét khi ĐỌC giá trị (Load), không xét khi gán vào tên CERT_NONE.
        elif isinstance(node.ctx, ast.Load) and context.resolve(node) == "ssl.CERT_NONE":
            # vd ctx.verify_mode = ssl.CERT_NONE
            yield self.create_finding(
                node, context, "ssl.CERT_NONE disables certificate verification.", confidence=0.8,
            )

    def _check_call(self, node: ast.Call, context: AnalysisContext) -> Iterator[Finding]:
        name = context.call_name(node)
        if name in _UNVERIFIED_CONTEXT:
            yield self.create_finding(
                node, context, f"{name}() creates an SSL context without certificate verification.",
                confidence=0.85,
            )
            return

        verify = get_keyword(node, "verify")
        # Chỉ báo khi là hằng False/0. verify='ca.pem' là cách dùng đúng và
        # verify=None nghĩa là "dùng mặc định" (vẫn kiểm tra) trong requests.
        if verify is None or not isinstance(verify.value, ast.Constant):
            return
        if verify.value.value is None or verify.value.value not in (False, 0):
            return
        if name and name.startswith(_HTTP_LIBRARIES):
            yield self.create_finding(
                node, context, f"{name}() is called with verify=False.", confidence=0.9,
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _HTTP_METHODS:
            # Có lẽ là method của requests.Session / httpx.Client; không chứng minh được kiểu.
            yield self.create_finding(
                node, context, f".{node.func.attr}() is called with verify=False.", confidence=0.7,
            )
