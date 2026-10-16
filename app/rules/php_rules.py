"""Rule PHP PH001 - PH013 (dựa trên tree-sitter).

Dùng chung adapter/taint/lớp cơ sở với Java và C# (xem _ts_common.py). Source
mặc định là các biến toàn cục $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES,
$_SERVER (app/config/taint_php.json). Script PHP thường chạy ngay ở cấp file
(như DVWA), nên taint được tính cả cho code nằm ngoài hàm.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, ClassVar

from app.analyzer.languages import PHP
from app.analyzer.taint import TaintInfo
from app.analyzer.ts.context import TSContext
from app.models.finding import Finding, Severity
from app.rules._keywords import is_password_name
from app.rules._ts_common import (
    CodeInjectionRuleBase,
    CommandRuleBase,
    DeserializationRuleBase,
    HardcodedSecretRuleBase,
    InsecureRandomRuleBase,
    SqlRuleBase,
    TSRule,
    string_parts,
    string_value,
)
from app.rules.base import ArgumentKind, classify_argument
from app.rules.registry import register_rule

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node

    from app.analyzer.ts.adapters import CallSite


def _arg(call: CallSite, index: int) -> Node | None:
    return call.args[index] if len(call.args) > index else None


def _has_variable(ctx: TSContext, node: Node) -> bool:
    """True nếu biểu thức có chứa biến ($x) - phân biệt đường dẫn ghép từ hằng số với đường dẫn động."""
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in ctx.adapter.identifier_types:
            return True
        stack.extend(current.named_children)
    return False


# --------------------------------------------------------------------------- PH001 command injection


@register_rule
class PhpCommandInjectionRule(CommandRuleBase):
    """PH001: system(), exec(), shell_exec(), passthru(), popen(), proc_open(), `...`."""

    id = "PH001"
    language = PHP
    name = "OS command execution (system / exec / shell_exec)"
    description = (
        "system(), exec(), shell_exec(), passthru(), popen(), proc_open() and the backtick operator run a "
        "command line through the shell; untrusted data in it allows command injection."
    )
    recommendation = (
        "Avoid the shell. If a command is unavoidable, use a fixed program, validate input against an "
        "allow-list and wrap every argument with escapeshellarg()."
    )
    _SINKS = frozenset({"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"})

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or call.method not in self._SINKS or not call.args:
                continue
            sink = "`...` (shell_exec)" if call.node.type == "shell_command_expression" else call.display
            elements = ctx.adapter.array_elements(call.args[0])
            if elements is not None:
                # proc_open(['ls', $dir], ...): chương trình + argument, không qua shell.
                finding = self.grade_program(call.node, ctx, elements, sink)
            else:
                finding = self.grade_command_line(call.node, ctx, call.args[0], sink)
            if finding is not None:
                yield finding


# --------------------------------------------------------------------------- PH002 SQL injection

# Hàm -> vị trí argument chứa câu SQL (hàm luôn nhận SQL).
_SQL_FUNCTIONS = {
    "mysqli_query": 1, "mysqli_real_query": 1, "mysqli_multi_query": 1, "mysqli_prepare": 1,
    "mysql_query": 0, "mysql_unbuffered_query": 0, "mysql_db_query": 1,
    "pg_query": -1, "pg_send_query": 1, "pg_prepare": 2, "sqlsrv_query": 1, "sqlsrv_prepare": 1,
    "odbc_exec": 1, "odbc_prepare": 1, "db2_exec": 1, "oci_parse": 1, "sqlite_query": -1,
}
# Method trên đối tượng: tên chung chung, cần thêm bằng chứng (receiver giống database / từ khóa SQL).
_SQL_METHODS = frozenset({"query", "exec", "prepare", "multi_query", "real_query", "unbuffered_query",
                          "get_results", "get_row", "get_var", "get_col", "querySingle", "raw", "statement",
                          "select", "whereRaw", "selectRaw", "orderByRaw", "havingRaw"})


@register_rule
class PhpSqlInjectionRule(SqlRuleBase):
    """PH002: mysqli_query, mysql_query, pg_query, PDO/mysqli/SQLite3 ->query() ..."""

    id = "PH002"
    language = PHP
    name = "SQL query built with string concatenation"
    description = (
        "The SQL statement is assembled from strings and variables (concatenation or \"...$var...\" "
        "interpolation), so input containing quotes or SQL syntax changes the query (SQL injection)."
    )
    recommendation = (
        "Use prepared statements with bound parameters (PDO::prepare + execute([...]), mysqli_prepare + "
        "bind_param). Escaping functions are not a substitute, especially for numeric values without quotes."
    )
    db_words = SqlRuleBase.db_words | frozenset({"mysqli", "mysql", "pdo", "dbh", "wpdb", "sqlite", "pg", "link",
                                                 "ston"})

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.is_constructor or not call.args:
                continue
            if call.receiver is None and call.method in _SQL_FUNCTIONS:
                index = _SQL_FUNCTIONS[call.method]
                # pg_query($sql) hoặc pg_query($conn, $sql): câu SQL là argument cuối.
                query = call.args[-1] if index == -1 else _arg(call, index)
                certain, receiver = True, None
            elif call.receiver is not None and call.method in _SQL_METHODS:
                query, certain, receiver = call.args[0], False, call.receiver
            else:
                continue
            if query is None:
                continue
            finding = self.grade_query(call.node, ctx, query, call.display, certain, receiver)
            if finding is not None:
                yield finding


# --------------------------------------------------------------------------- PH003 code injection


@register_rule
class PhpCodeInjectionRule(CodeInjectionRuleBase):
    """PH003: eval(), assert(string), create_function(), preg_replace với modifier /e."""

    id = "PH003"
    language = PHP
    name = "Dynamic code evaluation (eval / assert / create_function)"
    description = (
        "eval(), assert() with a string, create_function() and preg_replace() with the /e modifier execute "
        "PHP code built from strings; untrusted input leads to remote code execution."
    )
    recommendation = "Never execute strings as code; use a fixed set of operations or a safe parser instead."
    dynamic_message = "{call} executes dynamically built PHP code."
    static_message = "{call} executes constant PHP code."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or not call.args:
                continue
            finding = None
            if call.method == "eval" or (call.method == "assert" and not ctx.taint.is_static(call.args[0])):
                finding = self.code_finding(call, ctx)
            elif call.method == "create_function" and len(call.args) > 1:
                kind, info = classify_argument(call.args[1], ctx)
                finding = self.graded_finding(call.node, ctx, kind, info, call.display,
                                              dynamic_message=self.dynamic_message.format(call=call.display),
                                              static_message=self.static_message.format(call=call.display))
            elif call.method == "preg_replace" and len(call.args) > 1:
                pattern = string_value(ctx, call.args[0]) or ""
                # Modifier đứng sau dấu phân cách cuối: '/(.*)/e'
                if re.search(r"[/#~|!@%][a-zA-Z]*e[a-zA-Z]*$", pattern):
                    kind, info = classify_argument(call.args[1], ctx)
                    finding = self.graded_finding(
                        call.node, ctx, kind if kind is not ArgumentKind.STATIC else ArgumentKind.DYNAMIC, info,
                        call.display, dynamic_message="preg_replace() with the /e modifier evaluates the "
                                                      "replacement as PHP code.")
            if finding is not None:
                yield finding


# --------------------------------------------------------------------------- PH004 file inclusion


@register_rule
class PhpFileInclusionRule(TSRule):
    """PH004: include/require với đường dẫn động (Local/Remote File Inclusion)."""

    id = "PH004"
    language = PHP
    name = "File inclusion (include / require)"
    description = (
        "include/require execute the PHP code of the given file. A path controlled by the user lets an "
        "attacker run other local files (LFI: logs, uploads, /proc/self/environ) or remote code (RFI)."
    )
    severity = Severity.HIGH
    cwe = "CWE-98"
    category = "File Inclusion"
    recommendation = (
        "Never pass user input to include/require. Map the input to a fixed allow-list of files, e.g. "
        "$pages = ['home' => 'home.php']; include $pages[$page] ?? 'home.php';"
    )
    _SINKS = frozenset({"include", "include_once", "require", "require_once"})

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.method not in self._SINKS or call.receiver is not None or not call.args:
                continue
            path = call.args[0]
            kind, info = classify_argument(path, ctx)
            if kind is ArgumentKind.DYNAMIC:
                # __DIR__ . '/x.php' (chỉ ghép từ hằng số) hoặc $pages['home'] (tra bảng allow-list): bỏ qua.
                if not _has_variable(ctx, path) or self._allow_list_lookup(ctx, path):
                    continue
                yield self.create_finding(call.node, ctx, f"{call.method} loads a file whose path is chosen at "
                                          "runtime.", severity=Severity.MEDIUM, confidence=0.5)
                continue
            if kind is ArgumentKind.TAINTED and info is not None:
                yield self.tainted_finding(call.node, ctx, info, call.method, severity=Severity.CRITICAL)
            elif kind is ArgumentKind.SANITIZED and info is not None:
                yield self.sanitized_finding(call.node, ctx, info, call.method)

    @staticmethod
    def _allow_list_lookup(ctx: TSContext, path: Node) -> bool:
        """``$pages['home']``: phần tử với khóa hằng số của một mảng (bảng ánh xạ cố định)."""
        path = ctx.adapter.unwrap(path)
        if path.type not in ctx.adapter.element_types:
            return False
        _, indexes = ctx.adapter.element_parts(path)
        return bool(indexes) and all(ctx.taint.is_static(index) for index in indexes)


# --------------------------------------------------------------------------- PH005 path traversal

# Hàm -> vị trí các argument là đường dẫn.
_FILE_FUNCTIONS = {
    "fopen": (0,), "file_get_contents": (0,), "file_put_contents": (0,), "readfile": (0,), "file": (0,),
    "unlink": (0,), "rmdir": (0,), "mkdir": (0,), "opendir": (0,), "scandir": (0,), "copy": (0, 1),
    "rename": (0, 1), "highlight_file": (0,), "show_source": (0,), "parse_ini_file": (0,),
    "simplexml_load_file": (0,), "move_uploaded_file": (1,), "fpassthru": (), "touch": (0,), "chmod": (0,),
    "is_file": (), "file_exists": (),
}


@register_rule
class PhpPathTraversalRule(TSRule):
    """PH005: đường dẫn file/URL lấy từ request (giống PY014 + PY015 của Python)."""

    id = "PH005"
    language = PHP
    name = "Path traversal / file access with user input"
    description = (
        "A file function (fopen, file_get_contents, readfile, unlink, ...) receives a path built from user "
        "input; '../' sequences or absolute paths reach files outside the intended directory. With "
        "allow_url_fopen the same functions also fetch attacker-chosen URLs (SSRF)."
    )
    severity = Severity.HIGH
    cwe = "CWE-22"
    category = "Path Traversal"
    recommendation = (
        "Use basename() or an allow-list of file names, then check that realpath() stays inside the base "
        "directory."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or call.method not in _FILE_FUNCTIONS:
                continue
            for index in _FILE_FUNCTIONS[call.method]:
                path = _arg(call, index)
                if path is None:
                    continue
                kind, info = classify_argument(path, ctx)
                # Chỉ báo khi tainted (giống PY014): basename/realpath coi là đã làm sạch.
                if kind is ArgumentKind.TAINTED and info is not None:
                    yield self.tainted_finding(call.node, ctx, info, call.display, severity=Severity.HIGH)
                    break


# --------------------------------------------------------------------------- PH006 XSS

_HTML_TAG = re.compile(r"<\s*/?\s*[a-zA-Z!]")
# Sanitizer thật sự chống XSS; sanitizer khác (mysqli_real_escape_string...) không có tác dụng với HTML.
_HTML_SANITIZERS = frozenset({"htmlspecialchars", "htmlentities", "strip_tags", "urlencode", "rawurlencode",
                              "intval", "floatval", "boolval", "abs"})
_OUTPUT_FUNCTIONS = frozenset({"echo", "print", "printf", "vprintf", "print_r", "exit", "die"})


@register_rule
class PhpXssRule(TSRule):
    """PH006: dữ liệu request được in ra (echo/print) hoặc ghép vào chuỗi HTML."""

    id = "PH006"
    language = PHP
    name = "Cross-site scripting (XSS)"
    description = (
        "Untrusted input is written into the HTML response without escaping, so an attacker can inject "
        "<script> or event-handler attributes that run in the victim's browser."
    )
    severity = Severity.HIGH
    cwe = "CWE-79"
    category = "Cross-Site Scripting"
    recommendation = (
        "Escape every value at output time with htmlspecialchars($value, ENT_QUOTES, 'UTF-8'), or use a "
        "template engine with auto-escaping (Twig, Blade)."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        # 1) echo / print / printf ... của dữ liệu tainted.
        for call in ctx.calls:
            if call.receiver is not None or call.method not in _OUTPUT_FUNCTIONS:
                continue
            for arg in call.args:
                finding = self._grade(ctx, call.node, arg, f"{call.method}",
                                      "Untrusted input from {source} is written to the response by {sink}.")
                if finding is not None:
                    yield finding
                    break
        # 2) Chuỗi HTML ghép từ dữ liệu tainted rồi gán vào biến ($html .= '<pre>' . $_GET['x'] ...).
        for assignment in ctx.assignments:
            if not _HTML_TAG.search(" ".join(string_parts(ctx, assignment.value))):
                continue
            finding = self._grade(ctx, assignment.node, assignment.value, assignment.target,
                                  "HTML built from untrusted input ({source}) is stored in '{sink}'.",
                                  confidence=0.85)
            if finding is not None:
                yield finding

    def _grade(self, ctx: TSContext, node: Node, value: Node, sink: str, message: str,
               confidence: float = 0.9) -> Finding | None:
        kind, info = classify_argument(value, ctx)
        if info is None:
            return None
        if kind is ArgumentKind.SANITIZED:
            if info.sanitizer in _HTML_SANITIZERS:
                return None
            return self.sanitized_finding(node, ctx, info, sink)
        return self.tainted_finding(node, ctx, info, sink, message.format(source=info.source, sink=sink),
                                    confidence=confidence)


# --------------------------------------------------------------------------- PH007 weak hash


@register_rule
class PhpWeakHashRule(TSRule):
    """PH007: md5(), sha1(), hash('md5'|'sha1', ...); dùng cho mật khẩu -> HIGH."""

    id = "PH007"
    language = PHP
    name = "Weak cryptographic hash (MD5/SHA-1)"
    description = "MD5 and SHA-1 are broken (practical collisions) and far too fast for password storage."
    severity = Severity.MEDIUM
    cwe = "CWE-328"
    category = "Weak Cryptography"
    recommendation = (
        "Use password_hash()/password_verify() (bcrypt/Argon2) for passwords and hash('sha256', ...) for integrity."
    )
    _WEAK = re.compile(r"^(md2|md4|md5|sha1|ripemd128)$", re.IGNORECASE)

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or not call.args:
                continue
            if call.method in {"md5", "sha1"}:
                algorithm, data = call.method.upper().replace("SHA1", "SHA-1"), call.args[0]
            elif call.method in {"hash", "hash_init"}:
                value = string_value(ctx, call.args[0])
                if value is None or not self._WEAK.match(value):
                    continue
                algorithm, data = value.upper(), _arg(call, 1)
            else:
                continue
            if self._is_password(ctx, call, data):
                yield self.create_finding(call.node, ctx, f"{algorithm} is used to hash a password.",
                                          severity=Severity.HIGH, confidence=0.85)
            else:
                yield self.create_finding(call.node, ctx, f"{call.display} uses the weak algorithm {algorithm}.",
                                          confidence=0.7)

    @staticmethod
    def _is_password(ctx: TSContext, call: CallSite, data: Node | None) -> bool:
        """Dữ liệu được hash hoặc biến nhận kết quả có tên giống mật khẩu ($pass, $password_new...)."""
        names = [ctx.assigned_name(call.node) or ""]
        if data is not None:
            names += [ctx.adapter.text(n) for n in _variables(ctx, data)]
        return any(is_password_name(name.lstrip("$")) or "pass" in name.lower() for name in names)


def _variables(ctx: TSContext, node: Node) -> list[Node]:
    found, stack = [], [node]
    while stack:
        current = stack.pop()
        if current.type in ctx.adapter.identifier_types:
            found.append(current)
        stack.extend(current.named_children)
    return found


# --------------------------------------------------------------------------- PH008 insecure random


@register_rule
class PhpInsecureRandomRule(InsecureRandomRuleBase):
    """PH008: rand(), mt_rand(), uniqid(), lcg_value(), str_shuffle() cho token, mật khẩu, session id..."""

    id = "PH008"
    language = PHP
    description = (
        "rand(), mt_rand(), uniqid(), lcg_value() and str_shuffle() are predictable; tokens, session ids "
        "or reset codes generated with them can be guessed."
    )
    recommendation = "Use random_bytes() / bin2hex(random_bytes(32)) or random_int() for security values."
    random_types = frozenset()
    random_calls = frozenset({"rand", "mt_rand", "uniqid", "lcg_value", "str_shuffle", "array_rand", "shuffle",
                              "mt_getrandmax"})


# --------------------------------------------------------------------------- PH009 hardcoded secret


@register_rule
class PhpHardcodedSecretRule(HardcodedSecretRuleBase):
    """PH009: $password = '...', $_CONFIG['db_password'] = '...', define('API_KEY', '...'), 'pass' => '...'."""

    id = "PH009"
    language = PHP
    recommendation = "Read secrets from environment variables (getenv) or a configuration file outside the web root."

    @staticmethod
    def _named_values(ctx: TSContext) -> Iterator[tuple[str, Node]]:
        adapter = ctx.adapter
        for declaration in ctx.declarations:
            if declaration.value is not None:
                yield declaration.name, declaration.value
        for assignment in ctx.assignments:
            target = adapter.unwrap(assignment.node.child_by_field_name("left"))
            if target.type in adapter.element_types:
                # $_DVWA['db_password'] = '...' -> tên là khóa 'db_password'
                _, indexes = adapter.element_parts(target)
                key = string_value(ctx, indexes[0]) if indexes else None
                if key:
                    yield key, assignment.value
                continue
            # $password / $this->password -> "password"
            yield re.split(r"->|::", assignment.target)[-1].lstrip("$"), assignment.value
        for call in ctx.calls:
            # define('DB_PASSWORD', '...')
            if call.method == "define" and call.receiver is None and len(call.args) > 1:
                name = string_value(ctx, call.args[0])
                if name:
                    yield name, call.args[1]
        # Phần tử mảng 'password' => '...'
        stack = [ctx.root]
        while stack:
            node = stack.pop()
            if node.type == "array_element_initializer" and len(node.named_children) == 2:
                key = string_value(ctx, node.named_children[0])
                if key:
                    yield key, node.named_children[1]
            stack.extend(node.named_children)


# --------------------------------------------------------------------------- PH010 deserialization


@register_rule
class PhpDeserializationRule(DeserializationRuleBase):
    """PH010: unserialize() dữ liệu từ người dùng (PHP object injection)."""

    id = "PH010"
    language = PHP
    description = (
        "unserialize() recreates arbitrary PHP objects; magic methods (__wakeup, __destruct, __toString) of "
        "classes in the application or its libraries turn attacker data into code execution (POP chains)."
    )
    cwe = "CWE-502"
    recommendation = (
        "Use json_decode() for untrusted data. If unserialize() is unavoidable, pass "
        "['allowed_classes' => false]."
    )
    dynamic_message: ClassVar[str] = "{call} deserializes data that may be attacker-controlled."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or call.method != "unserialize" or not call.args:
                continue
            options = _arg(call, 1)
            if options is not None and re.search(r"allowed_classes['\"]\s*=>\s*false",
                                                 ctx.adapter.text(options), re.IGNORECASE):
                continue
            finding = self.deserialization_finding(call, ctx, call.args[0])
            if finding is not None:
                yield finding


# --------------------------------------------------------------------------- PH011 TLS


@register_rule
class PhpTlsValidationRule(TSRule):
    """PH011: CURLOPT_SSL_VERIFYPEER/VERIFYHOST tắt, 'verify_peer' => false."""

    id = "PH011"
    language = PHP
    name = "TLS certificate verification disabled"
    description = (
        "Disabling certificate or host name verification (CURLOPT_SSL_VERIFYPEER = false, "
        "'verify_peer' => false) lets a man-in-the-middle read and modify HTTPS traffic."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-295"
    category = "Insecure Transport"
    recommendation = "Keep verification enabled; for a private CA set CURLOPT_CAINFO / 'cafile' instead."
    _OPTIONS = frozenset({"CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST", "CURLOPT_PROXY_SSL_VERIFYPEER"})
    _CONTEXT_KEYS = frozenset({"verify_peer", "verify_peer_name", "allow_self_signed"})

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is None and call.method == "curl_setopt" and len(call.args) > 2:
                option = ctx.adapter.text(call.args[1]).lstrip("\\")
                if option in self._OPTIONS and self._disabled(ctx, call.args[2], allow=option.endswith("HOST")):
                    yield self.create_finding(call.node, ctx, f"curl_setopt() sets {option} to "
                                              f"{ctx.adapter.text(call.args[2])}.", confidence=0.9)
        stack = [ctx.root]
        while stack:
            node = stack.pop()
            if node.type == "array_element_initializer" and len(node.named_children) == 2:
                key = string_value(ctx, node.named_children[0])
                value = node.named_children[1]
                disabled = self._disabled(ctx, value) if key != "allow_self_signed" else \
                    ctx.adapter.text(value).lower() in {"true", "1"}
                if key in self._CONTEXT_KEYS and disabled:
                    yield self.create_finding(node, ctx, f"SSL context option '{key}' disables certificate checks.",
                                              confidence=0.85)
            stack.extend(node.named_children)

    @staticmethod
    def _disabled(ctx: TSContext, value: Node, allow: bool = False) -> bool:
        text = ctx.adapter.text(value).strip().lower()
        # CURLOPT_SSL_VERIFYHOST nhận 2 (bật) hoặc 0 (tắt); 1 cũng không còn kiểm tra tên từ cURL 7.28.
        return text in {"false", "0"} or (allow and text == "1")


# --------------------------------------------------------------------------- PH012 open redirect


@register_rule
class PhpOpenRedirectRule(TSRule):
    """PH012: header('Location: ' . $_GET['url']) và header() chứa dữ liệu người dùng."""

    id = "PH012"
    language = PHP
    name = "Open redirect / HTTP header injection"
    description = (
        "A Location header built from user input sends victims to any site the attacker chooses (phishing); "
        "other headers built from user input may allow header injection."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-601"
    category = "Open Redirect"
    recommendation = "Redirect only to relative paths or to URLs from a fixed allow-list."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or call.method != "header" or not call.args:
                continue
            kind, info = classify_argument(call.args[0], ctx)
            if kind is not ArgumentKind.TAINTED or info is None:
                continue
            if re.search(r"\blocation\s*:", " ".join(string_parts(ctx, call.args[0])), re.IGNORECASE):
                yield self.tainted_finding(call.node, ctx, info, "header()",
                                           f"Untrusted input from {info.source} chooses the redirect target.")
            else:
                yield self.tainted_finding(call.node, ctx, info, "header()",
                                           f"Untrusted input from {info.source} is written into a response header.",
                                           cwe="CWE-113", confidence=0.7)


# --------------------------------------------------------------------------- PH013 file upload


@register_rule
class PhpFileUploadRule(TSRule):
    """PH013: move_uploaded_file() giữ tên/phần mở rộng do client gửi lên."""

    id = "PH013"
    language = PHP
    name = "Unrestricted file upload"
    description = (
        "The uploaded file is saved under a name taken from $_FILES[...]['name'], so the client chooses the "
        "extension. Uploading shell.php into a web-accessible folder gives remote code execution."
    )
    severity = Severity.HIGH
    cwe = "CWE-434"
    category = "File Upload"
    recommendation = (
        "Generate the file name on the server (random name + extension from an allow-list), check the real "
        "content type, and store uploads outside the web root or in a folder where PHP cannot execute."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver is not None or call.method != "move_uploaded_file" or len(call.args) < 2:
                continue
            info = ctx.taint.lookup(call.args[1])
            if isinstance(info, TaintInfo) and info.source == "$_FILES":
                yield self.create_finding(
                    call.node, ctx, "The destination of move_uploaded_file() uses the client-supplied file name.",
                    confidence=0.8, source=info.source, sink="move_uploaded_file()",
                    taint_path=[*info.path, "move_uploaded_file()"],
                )

