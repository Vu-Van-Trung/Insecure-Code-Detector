"""PY016 - XML external entity (XXE) và parse XML không an toàn."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from app.analyzer.context import AnalysisContext
from app.analyzer.utils import get_argument, get_keyword
from app.models.finding import Finding, Severity
from app.rules.base import ArgumentKind, CallRule, classify_argument
from app.rules.registry import register_rule

# Hàm parse của lxml -> vị trí của argument "parser".
_LXML_PARSE = {
    "lxml.etree.parse": 1,
    "lxml.etree.fromstring": 1,
    "lxml.etree.XML": 1,
}
# Hàm/class tạo parser của lxml - độ an toàn phụ thuộc tham số resolve_entities / no_network.
_LXML_PARSERS = frozenset({"lxml.etree.XMLParser", "lxml.etree.XMLPullParser", "lxml.etree.iterparse"})
# Parser của thư viện chuẩn: mặc định không đọc external entity (từ Python 3.7.1), nhưng
# vẫn có thể bị tấn công mở rộng entity ("billion laughs") với phiên bản expat cũ.
_STDLIB_PARSE = frozenset({
    f"{module}.{function}"
    for module in ("xml.etree.ElementTree", "xml.etree.cElementTree")
    for function in ("parse", "fromstring", "XML", "iterparse", "fromstringlist")
} | {
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
    "xml.sax.parse", "xml.sax.parseString",
})
# Feature của xml.sax bật đọc external entity (general / parameter entity).
_SAX_EXTERNAL_FEATURES = frozenset({"feature_external_ges", "feature_external_pes"})


@register_rule
class XxeRule(CallRule):
    """PY016: các tình huống XXE, từ chắc chắn (bật tường minh) tới phụ thuộc phiên bản thư viện.

    Hàm của defusedxml có tên đầy đủ khác (defusedxml.*) nên không bao giờ bị báo.
    """

    id = "PY016"
    name = "XML external entity (XXE)"
    description = (
        "An XML parser that resolves external entities lets a crafted document read local "
        "files (<!ENTITY x SYSTEM \"file:///etc/passwd\">) or make the server send requests "
        "to internal hosts. Entity expansion can also exhaust memory (billion laughs)."
    )
    severity = Severity.HIGH
    cwe = "CWE-611"
    category = "XML External Entity"
    recommendation = (
        "Parse untrusted XML with defusedxml (defusedxml.ElementTree.fromstring, ...). With lxml, "
        "pass a parser created with XMLParser(resolve_entities=False, no_network=True). Never "
        "enable xml.sax feature_external_ges/feature_external_pes."
    )

    def check_call(self, node: ast.Call, name: str | None, context: AnalysisContext) -> Iterator[Finding]:
        if name in _LXML_PARSERS:
            yield from self._check_lxml_parser(node, context, name)
        elif name in _LXML_PARSE:
            yield from self._check_lxml_parse(node, context, name)
        elif name in _STDLIB_PARSE:
            yield from self._check_stdlib_parse(node, context, name)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "setFeature":
            yield from self._check_sax_feature(node, context)

    def _check_lxml_parser(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        """etree.XMLParser(...): xét các tham số cấu hình."""
        resolve = get_keyword(node, "resolve_entities")
        no_network = get_keyword(node, "no_network")
        if resolve is not None and _is_true(resolve.value):
            # Bật tường minh -> chắc chắn có XXE.
            yield self.create_finding(
                node, context, f"{name}() is created with resolve_entities=True.", confidence=0.9,
            )
        elif no_network is not None and _is_false(no_network.value):
            yield self.create_finding(
                node, context, f"{name}() is created with no_network=False (fetches remote DTDs/entities).",
                confidence=0.8,
            )
        elif resolve is None:
            # Không đặt rõ: an toàn từ lxml 5.0 nhưng không an toàn với bản cũ hơn -> MEDIUM.
            yield self.create_finding(
                node, context,
                f"{name}() does not set resolve_entities=False; lxml before 5.0 resolves external entities.",
                severity=Severity.MEDIUM, confidence=0.5,
            )

    def _check_lxml_parse(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        """etree.fromstring(data) dùng parser mặc định khi không truyền parser."""
        if get_argument(node, _LXML_PARSE[name], "parser") is not None:
            return  # parser đã được kiểm tra tại nơi nó được tạo (_check_lxml_parser)
        data = get_argument(node, 0, "source" if name == "lxml.etree.parse" else "text")
        if data is None:
            return
        kind, info = classify_argument(data, context)
        sink = f"{name}()"
        if kind is ArgumentKind.TAINTED:
            yield self.tainted_finding(
                node, context, info, sink,
                f"Untrusted XML from {info.source} is parsed by {sink} with the default parser.",
            )
        elif kind is not ArgumentKind.STATIC:
            # XML hằng số (viết sẵn trong code) không thể chứa entity độc hại -> không báo.
            yield self.create_finding(
                node, context,
                f"{sink} uses the default parser; lxml before 5.0 resolves external entities.",
                severity=Severity.MEDIUM, confidence=0.5,
            )

    def _check_stdlib_parse(self, node: ast.Call, context: AnalysisContext, name: str) -> Iterator[Finding]:
        """xml.etree / minidom / sax: chỉ báo khi dữ liệu XML đến từ người dùng."""
        data = get_argument(node, 0)
        info = context.taint.lookup(data)
        if info is None or info.sanitized:
            return
        sink = f"{name}()"
        yield self.tainted_finding(
            node, context, info, sink,
            f"Untrusted XML from {info.source} is parsed by {sink}, which is not hardened against "
            "entity expansion (billion laughs).",
            # CWE-776: mở rộng entity đệ quy (DoS), khác với đọc file qua external entity.
            severity=Severity.MEDIUM, confidence=0.7, cwe="CWE-776",
        )

    def _check_sax_feature(self, node: ast.Call, context: AnalysisContext) -> Iterator[Finding]:
        """parser.setFeature(feature_external_ges, True) bật đọc external entity."""
        feature, value = get_argument(node, 0), get_argument(node, 1)
        feature_name = context.resolve(feature) if feature is not None else None
        # So khớp tên cuối để nhận cả xml.sax.handler.feature_external_ges lẫn tên đã import trực tiếp.
        if feature_name is None or feature_name.rsplit(".", 1)[-1] not in _SAX_EXTERNAL_FEATURES:
            return
        if value is not None and _is_true(value):
            yield self.create_finding(
                node, context, f"setFeature({feature_name.rsplit('.', 1)[-1]}, True) enables external entities.",
                confidence=0.9,
            )


def _is_true(node: ast.AST) -> bool:
    """Hằng số "truthy" (True, 1, "yes"...)."""
    return isinstance(node, ast.Constant) and node.value not in (None, False, 0, "")


def _is_false(node: ast.AST) -> bool:
    """Hằng False hoặc 0."""
    return isinstance(node, ast.Constant) and node.value in (False, 0)
