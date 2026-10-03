"""PY015 - Server-side request forgery (SSRF): dữ liệu không tin cậy được dùng làm URL của request."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.taint import TaintInfo
from app.analyzer.utils import get_argument
from app.models.finding import Finding, Severity
from app.rules._values import assigned_values, leading_literal
from app.rules.base import TaintedSinkRule
from app.rules.registry import register_rule

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
# Hàm gửi HTTP request -> (vị trí, tên keyword) của argument URL.
# requests.request("GET", url): URL là argument thứ hai.
_URL_FUNCTIONS: dict[str, tuple[int, str]] = {
    **{f"{library}.{verb}": (0, "url") for library in ("requests", "httpx") for verb in _HTTP_VERBS},
    "requests.request": (1, "url"),
    "httpx.request": (1, "url"),
    "httpx.stream": (1, "url"),
    "urllib.request.urlopen": (0, "url"),
    "urllib.request.Request": (0, "url"),
    "urllib3.request": (1, "url"),
}
# "https://api.example.com/..." - scheme và host cố định, chỉ phần path/query thay đổi được.
# Bắt buộc có "/", "?" hoặc "#" sau host: "https://example.com" + x vẫn nguy hiểm
# vì x = "@evil.com" biến URL thành https://example.com@evil.com (host là evil.com).
_FIXED_HOST = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#@\s]+[/?#]")


@register_rule
class SsrfRule(TaintedSinkRule):
    """PY015: URL do người dùng kiểm soát -> HIGH; chỉ path/query do người dùng kiểm soát -> MEDIUM."""

    id = "PY015"
    name = "Server-side request forgery (SSRF)"
    description = (
        "The server sends an HTTP request to a URL controlled by the user. An attacker "
        "can make it reach internal services (http://localhost:8080/admin, databases, "
        "cloud metadata at http://169.254.169.254/) that are not reachable from outside."
    )
    severity = Severity.HIGH
    cwe = "CWE-918"
    category = "Server-Side Request Forgery"
    recommendation = (
        "Do not fetch arbitrary user URLs. Map user choices to a fixed list of allowed URLs, "
        "or parse the URL and check its scheme and host against an allowlist (and reject "
        "private/loopback IP addresses after DNS resolution)."
    )
    sanitizer_category = "url"

    def sink_arguments(
        self, node: ast.Call, name: str | None, context: AnalysisContext,
    ) -> Iterator[tuple[ast.AST, str]]:
        if name in _URL_FUNCTIONS:
            argument = get_argument(node, *_URL_FUNCTIONS[name])
            if argument is not None:
                yield argument, f"{name}()"

    def untrusted_finding(
        self, node: ast.Call, context: AnalysisContext, argument: ast.AST, info: TaintInfo, sink: str,
    ) -> Finding:
        """Ghi đè hook của TaintedSinkRule: hạ xuống MEDIUM khi host của URL đã cố định."""
        # Mọi cách tạo ra URL (kể cả qua biến) đều phải bắt đầu bằng "scheme://host/".
        if all(_FIXED_HOST.match(leading_literal(value) or "") for value in assigned_values(argument, context)):
            return self.tainted_finding(
                node, context, info, sink,
                f"Input from {info.source} is used in the path/query of a URL passed to {sink} "
                "(the host is fixed).",
                severity=Severity.MEDIUM, confidence=0.6,
            )
        return self.tainted_finding(
            node, context, info, sink, f"Untrusted input from {info.source} controls the URL passed to {sink}.",
        )
