"""Rule Java JV001 - JV009 (dựa trên tree-sitter).

Mỗi rule kế thừa một lớp cơ sở trong _ts_common.py (logic dùng chung với C#);
phần lớn chỉ khai báo tên API đặc trưng của Java.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.analyzer.languages import JAVA
from app.analyzer.ts.context import TSContext
from app.models.finding import Finding, Severity
from app.rules._ts_common import (
    CodeInjectionRuleBase,
    CommandRuleBase,
    DeserializationRuleBase,
    HardcodedSecretRuleBase,
    InsecureRandomRuleBase,
    OpenRedirectRuleBase,
    SqlRuleBase,
    TSRule,
    WeakAlgorithmRuleBase,
    flatten_command,
)
from app.rules.registry import register_rule


@register_rule
class JavaCommandInjectionRule(CommandRuleBase):
    """JV001: Runtime.exec(...) và ProcessBuilder."""

    id = "JV001"
    language = JAVA
    name = "OS command execution (Runtime.exec / ProcessBuilder)"
    description = (
        "Runtime.exec() and ProcessBuilder start operating-system processes. A command line built from "
        "untrusted data, or a shell (sh -c / cmd /c) running such data, allows command injection."
    )
    recommendation = (
        "Use ProcessBuilder with a fixed program and separate arguments, never through 'sh -c' or 'cmd /c'. "
        "Validate untrusted values against an allow-list."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            finding = None
            # Runtime.getRuntime().exec(...) hoặc rt.exec(...) với Runtime rt.
            is_runtime_exec = call.method == "exec" and (
                call.receiver_type == "Runtime" or (call.receiver_text or "").endswith("getRuntime()"))
            if is_runtime_exec and call.args:
                # exec(String[]) = chương trình + argument; exec(String) = cả một dòng lệnh.
                elements = ctx.adapter.array_elements(ctx.adapter.unwrap(call.args[0]))
                if elements is not None:
                    finding = self.grade_program(call.node, ctx, elements, "Runtime.exec()")
                else:
                    finding = self.grade_command_line(call.node, ctx, call.args[0], "Runtime.exec()")
            # new ProcessBuilder(...) hoặc pb.command(...)
            elif (call.is_constructor and call.method == "ProcessBuilder") or (
                    call.method == "command" and call.receiver_type == "ProcessBuilder"):
                finding = self.grade_program(call.node, ctx, flatten_command(ctx, call.args), "ProcessBuilder")
            if finding is not None:
                yield finding


# Method luôn nhận SQL, và tên chung chung cần thêm bằng chứng (đối tượng nhận giống database).
_JAVA_SQL_SINKS = frozenset({
    "executeQuery", "executeUpdate", "executeLargeUpdate", "prepareStatement", "prepareCall", "addBatch",
    "createNativeQuery", "createQuery", "createSQLQuery", "queryForList", "queryForObject", "queryForMap",
    "queryForRowSet", "nativeQuery",
})
_JAVA_SQL_GENERIC = frozenset({"execute", "query", "update", "batchUpdate"})


@register_rule
class JavaSqlInjectionRule(SqlRuleBase):
    """JV002: JDBC (Statement), JPA (createQuery), Spring JdbcTemplate."""

    id = "JV002"
    language = JAVA
    name = "SQL query built with string concatenation"
    description = (
        "The SQL statement is assembled from strings and variables, so input containing quotes or SQL syntax "
        "changes the query (SQL injection)."
    )
    recommendation = (
        "Use PreparedStatement with '?' placeholders (or named parameters in JPA/JdbcTemplate) and bind values "
        "with setString()/setInt(); never concatenate values into SQL."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.is_constructor or not call.args:
                continue
            certain = call.method in _JAVA_SQL_SINKS
            if not certain and call.method not in _JAVA_SQL_GENERIC:
                continue
            finding = self.grade_query(call.node, ctx, call.args[0], call.display, certain, call.receiver)
            if finding is not None:
                yield finding


# Kiểu đối tượng -> các method deserialize nguy hiểm của nó.
_DESERIALIZERS = {"ObjectInputStream": {"readObject", "readUnshared"}, "XMLDecoder": {"readObject"},
                  "XStream": {"fromXML"}, "Yaml": {"load", "loadAll"}}


@register_rule
class JavaDeserializationRule(DeserializationRuleBase):
    """JV003: ObjectInputStream, XMLDecoder, XStream, SnakeYAML."""

    id = "JV003"
    language = JAVA
    description = (
        "Java native deserialization (ObjectInputStream), XMLDecoder, XStream and SnakeYAML's default "
        "constructor can instantiate arbitrary classes; gadget chains in the classpath turn attacker "
        "controlled data into remote code execution."
    )
    recommendation = (
        "Do not deserialize untrusted data. Use a data-only format (JSON with explicit types), an "
        "ObjectInputFilter allow-list, or SnakeYAML with SafeConstructor."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            methods = _DESERIALIZERS.get(call.receiver_type or "")
            if call.is_constructor or not methods or call.method not in methods:
                continue
            finding = self.deserialization_finding(call, ctx, self._data_source(ctx, call))
            if finding is not None:
                yield finding

    @staticmethod
    def _data_source(ctx: TSContext, call):  # type: ignore[no-untyped-def]
        """Dữ liệu được deserialize: argument của lời gọi, hoặc argument của constructor stream.

        vd ``ois.readObject()`` với ``ois = new ObjectInputStream(request.getInputStream())``
        -> request.getInputStream().
        """
        if call.args:
            return call.args[0]
        receiver = ctx.adapter.unwrap(call.receiver)
        # new ObjectInputStream(x).readObject()
        creation = ctx.call_by_node.get(receiver.id)
        # ois.readObject(): tìm giá trị khởi tạo của biến ois.
        if creation is None and receiver.type == "identifier":
            initial = ctx.initializer_of(ctx.adapter.text(receiver), receiver)
            creation = ctx.call_by_node.get(ctx.adapter.unwrap(initial).id) if initial is not None else None
        return creation.args[0] if creation is not None and creation.args else None


@register_rule
class JavaCodeInjectionRule(CodeInjectionRuleBase):
    """JV004: ScriptEngine.eval, GroovyShell.evaluate, SpEL parseExpression."""

    id = "JV004"
    language = JAVA
    name = "Dynamic code / expression evaluation"
    description = (
        "ScriptEngine.eval(), GroovyShell.evaluate() and SpEL parseExpression() execute code or expressions "
        "given as strings; untrusted input leads to code injection."
    )
    recommendation = "Never evaluate strings built from user input; use a fixed set of operations instead."
    dynamic_message = "{call} evaluates a dynamically built expression."
    static_message = "{call} evaluates a constant expression."

    # Kiểu đối tượng -> method thực thi code.
    _SINKS = {"ScriptEngine": "eval", "GroovyShell": "evaluate", "SpelExpressionParser": "parseExpression",
              "ExpressionParser": "parseExpression"}

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            # manager.getEngineByName("js").eval(code): không có biến nên không biết kiểu, nhận theo văn bản.
            engine_call = call.method == "eval" and "getEngineBy" in (call.receiver_text or "")
            if not call.args or not (self._SINKS.get(call.receiver_type or "") == call.method or engine_call):
                continue
            # SpEL là expression language injection (CWE-917) hơn là code injection.
            finding = self.code_finding(call, ctx, cwe="CWE-917" if call.method == "parseExpression" else None)
            if finding is not None:
                yield finding


@register_rule
class JavaWeakHashRule(WeakAlgorithmRuleBase):
    """JV005: chỉ khai báo dữ liệu, logic nằm ở WeakAlgorithmRuleBase."""

    id = "JV005"
    language = JAVA
    name = "Weak cryptographic hash (MD5/SHA-1)"
    description = "MD5 and SHA-1 are broken (practical collisions) and far too fast for password storage."
    cwe = "CWE-328"
    recommendation = "Use SHA-256/SHA-3 for integrity and PBKDF2, bcrypt, scrypt or Argon2 for passwords."
    # Apache Commons Codec và Guava.
    weak_calls = frozenset({"DigestUtils.md5", "DigestUtils.md5Hex", "DigestUtils.sha1", "DigestUtils.sha1Hex",
                            "DigestUtils.shaHex", "Hashing.md5", "Hashing.sha1"})
    algorithm_calls = frozenset({"MessageDigest.getInstance"})
    # "SHA" trong Java chính là SHA-1.
    weak_algorithm = re.compile(r"^(MD2|MD4|MD5|SHA-?1|SHA)$", re.IGNORECASE)


@register_rule
class JavaWeakCipherRule(WeakAlgorithmRuleBase):
    """JV006: thuật toán mã hóa lỗi thời hoặc chế độ ECB."""

    id = "JV006"
    language = JAVA
    name = "Weak cipher or ECB mode"
    description = (
        "DES, 3DES, RC2, RC4 and Blowfish are obsolete; ECB mode (the default of Cipher.getInstance(\"AES\")) "
        "leaks patterns of the plaintext."
    )
    cwe = "CWE-327"
    recommendation = "Use AES/GCM/NoPadding (or ChaCha20-Poly1305) with a random IV/nonce."
    algorithm_calls = frozenset({"Cipher.getInstance"})
    # "AES" đơn thuần = "AES/ECB/PKCS5Padding" theo mặc định của Java -> cũng là ECB.
    weak_algorithm = re.compile(r"^(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)\b|/ECB/|^AES$", re.IGNORECASE)


@register_rule
class JavaInsecureRandomRule(InsecureRandomRuleBase):
    """JV007: java.util.Random / Math.random cho token, mật khẩu..."""

    id = "JV007"
    language = JAVA
    description = "java.util.Random and Math.random() are predictable; tokens generated with them can be guessed."
    recommendation = "Use java.security.SecureRandom for tokens, passwords, keys and reset codes."
    random_calls = frozenset({"Math.random", "RandomStringUtils.random", "RandomStringUtils.randomAlphanumeric",
                              "RandomStringUtils.randomAlphabetic", "RandomStringUtils.randomNumeric",
                              "ThreadLocalRandom.current().nextInt"})


@register_rule
class JavaHardcodedSecretRule(HardcodedSecretRuleBase):
    """JV008: toàn bộ logic nằm ở HardcodedSecretRuleBase + HardcodedSecretMixin."""

    id = "JV008"
    language = JAVA
    recommendation = "Read secrets from environment variables, a vault or an external configuration at runtime."


@register_rule
class JavaTlsValidationRule(TSRule):
    """JV009: TrustManager/HostnameVerifier chấp nhận mọi chứng chỉ."""

    id = "JV009"
    language = JAVA
    name = "TLS certificate or hostname verification disabled"
    description = (
        "A TrustManager that accepts every certificate or a HostnameVerifier that always returns true lets "
        "an attacker on the network intercept HTTPS traffic (man-in-the-middle)."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-295"
    category = "Insecure Transport"
    recommendation = "Use the default TrustManager/HostnameVerifier; for private CAs load them into a KeyStore."

    # Các lớp/hằng của thư viện (Apache HttpClient...) tắt kiểm tra hostname/chứng chỉ.
    _ALLOW_ALL = re.compile(r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|"
                            r"TrustAllStrategy|TrustSelfSignedStrategy")

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        adapter = ctx.adapter
        # 1) Class tự cài đặt TrustManager / HostnameVerifier.
        for method in ctx.methods:
            body = method.body
            statements = [c for c in body.named_children if c.type not in adapter.comment_types] if body else None
            # checkServerTrusted rỗng = không bao giờ ném lỗi = tin mọi chứng chỉ.
            if method.name in {"checkServerTrusted", "checkClientTrusted"} and statements == []:
                yield self.create_finding(method.node, ctx,
                                          f"TrustManager.{method.name}() is empty: every certificate is trusted.",
                                          confidence=0.9)
            elif method.name == "verify" and statements and len(statements) == 1 \
                    and adapter.text(statements[0]).replace(" ", "") == "returntrue;":
                yield self.create_finding(method.node, ctx, "HostnameVerifier.verify() always returns true.",
                                          confidence=0.85)
        # 2) Gán một verifier "cho qua tất cả": lambda (h, s) -> true hoặc NoopHostnameVerifier.
        for call in ctx.calls:
            if call.method not in {"setHostnameVerifier", "setDefaultHostnameVerifier", "setSSLHostnameVerifier"}:
                continue
            argument = adapter.unwrap(call.args[0]) if call.args else None
            if argument is None:
                continue
            if (argument.type in adapter.lambda_types and adapter.lambda_returns_true(argument)) \
                    or self._ALLOW_ALL.search(adapter.text(argument)):
                yield self.create_finding(call.node, ctx, f"{call.display} disables hostname verification.",
                                          confidence=0.9)


@register_rule
class JavaOpenRedirectRule(OpenRedirectRuleBase):
    """JV010: HttpServletResponse.sendRedirect / Spring RedirectView."""

    id = "JV010"
    language = JAVA
    name = "Open redirect"
    description = (
        "A redirect destination taken from an untrusted request value can send users to an attacker-controlled "
        "site for phishing or to bypass trust in the application domain."
    )
    recommendation = (
        "Prefer redirects to fixed local routes. If a destination must be configurable, validate it against an "
        "allow-list of trusted hosts or route identifiers before redirecting."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            # sendRedirect is the servlet response API; RedirectView is Spring MVC's redirect sink.
            if call.method == "sendRedirect" or (call.is_constructor and call.method == "RedirectView"):
                finding = self.report_redirect(call, ctx)
                if finding is not None:
                    yield finding
