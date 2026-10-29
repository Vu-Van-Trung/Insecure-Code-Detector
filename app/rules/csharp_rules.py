"""Rule C# CS001 - CS012 (dựa trên tree-sitter).

Mỗi rule kế thừa một lớp cơ sở trong _ts_common.py (logic dùng chung với Java);
phần lớn chỉ khai báo tên API đặc trưng của .NET.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import TYPE_CHECKING

from app.analyzer.languages import CSHARP
from app.analyzer.ts.context import TSContext
from app.models.finding import Finding, Severity
from app.rules._ts_common import (
    CodeInjectionRuleBase,
    CommandRuleBase,
    DeserializationRuleBase,
    HardcodedSecretRuleBase,
    InsecureRandomRuleBase,
    RECEIVER,
    OpenRedirectRuleBase,
    PathTraversalRuleBase,
    SqlRuleBase,
    TaintedSinkRuleBase,
    TSRule,
    WeakAlgorithmRuleBase,
    string_value,
)
from app.rules.registry import register_rule

if TYPE_CHECKING:  # pragma: no cover
    from tree_sitter import Node


@register_rule
class CSharpCommandInjectionRule(CommandRuleBase):
    """CS001: Process.Start(...) và ProcessStartInfo."""

    id = "CS001"
    language = CSHARP
    name = "OS command execution (Process.Start)"
    description = (
        "Process.Start / ProcessStartInfo start operating-system processes. Running a program chosen at "
        "runtime, or passing untrusted data to cmd.exe /c or a shell, allows command injection."
    )
    recommendation = (
        "Start a fixed executable with UseShellExecute = false and pass arguments through "
        "ProcessStartInfo.ArgumentList; never run cmd.exe /c with user input."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            finding = None
            if call.method == "Start" and call.receiver_text == "Process" and call.args:
                if len(call.args) == 1 and self._is_start_info(ctx, call.args[0]):
                    continue  # Process.Start(psi): đã báo tại nơi tạo ProcessStartInfo
                if len(call.args) == 1:
                    # Process.Start("cmd /c ...") - một chuỗi lệnh.
                    finding = self.grade_command_line(call.node, ctx, call.args[0], "Process.Start()")
                else:
                    # Process.Start(fileName, arguments)
                    finding = self.grade_program(call.node, ctx, call.args[:2], "Process.Start()")
            elif call.is_constructor and call.method == "ProcessStartInfo":
                # new ProcessStartInfo(file, args) hoặc new ProcessStartInfo { FileName = ..., Arguments = ... }
                program = list(call.args[:2])
                if "FileName" in call.initializer:
                    program = [call.initializer["FileName"], *program[1:]]
                if "Arguments" in call.initializer:
                    program = [*program[:1], call.initializer["Arguments"]]
                finding = self.grade_program(call.node, ctx, program, "ProcessStartInfo")
            if finding is not None:
                yield finding

    @staticmethod
    def _is_start_info(ctx: TSContext, node) -> bool:  # type: ignore[no-untyped-def]
        return ctx.type_of(node) == "ProcessStartInfo"


# Class command của các driver database: new SqlCommand(sql, conn).
_CS_SQL_COMMANDS = frozenset({"SqlCommand", "SqliteCommand", "OleDbCommand", "OdbcCommand", "NpgsqlCommand",
                              "MySqlCommand", "OracleCommand", "SqlDataAdapter"})
# Method chắc chắn nhận SQL thô (EF Core, LINQ to SQL).
_CS_SQL_METHODS = frozenset({"FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlRawAsync", "SqlQueryRaw", "ExecuteQuery",
                             "ExecuteCommand"})
# Tên chung chung của Dapper - cần thêm bằng chứng (đối tượng nhận giống database / từ khóa SQL).
_CS_SQL_GENERIC = frozenset({"Query", "QueryAsync", "QueryFirst", "QueryFirstOrDefault", "QuerySingle",
                             "Execute", "ExecuteAsync", "ExecuteScalar"})  # Dapper


@register_rule
class CSharpSqlInjectionRule(SqlRuleBase):
    """CS002: ADO.NET, EF Core, Dapper. FromSqlInterpolated tự tham số hóa nên không có trong danh sách."""

    id = "CS002"
    language = CSHARP
    name = "SQL query built with string concatenation"
    description = (
        "The SQL command text is assembled from strings and variables (concatenation or $\"...\" "
        "interpolation), so input containing quotes or SQL syntax changes the query (SQL injection)."
    )
    recommendation = (
        "Use parameters (cmd.Parameters.AddWithValue(\"@id\", id)), EF Core FromSqlInterpolated / LINQ, or "
        "Dapper parameters; never build SQL text from values."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            finding = None
            if call.is_constructor and call.method in _CS_SQL_COMMANDS:
                # new SqlCommand(sql) hoặc new SqlCommand { CommandText = sql }
                query = call.args[0] if call.args else call.initializer.get("CommandText")
                if query is not None:
                    finding = self.grade_query(call.node, ctx, query, f"new {call.method}()", True)
            elif not call.is_constructor and call.args and (call.method in _CS_SQL_METHODS
                                                            or call.method in _CS_SQL_GENERIC):
                finding = self.grade_query(call.node, ctx, call.args[0], call.display,
                                           call.method in _CS_SQL_METHODS, call.receiver)
            if finding is not None:
                yield finding
        # cmd.CommandText = sql;
        for assignment in ctx.assignments:
            if assignment.target.endswith(".CommandText") and not assignment.augmented:
                finding = self.grade_query(assignment.node, ctx, assignment.value, assignment.target, True)
                if finding is not None:
                    yield finding


# Formatter nhị phân không an toàn (Microsoft đã đánh dấu BinaryFormatter là nguy hiểm).
_CS_FORMATTERS = frozenset({"BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter",
                            "ObjectStateFormatter"})
# Json.NET với TypeNameHandling khác None cho phép dữ liệu JSON chọn kiểu .NET được tạo.
_TYPE_NAME_HANDLING = re.compile(r"TypeNameHandling\.(All|Auto|Objects|Arrays)")


def _property_assignments(ctx: TSContext) -> Iterator[tuple[Node, str, Node]]:
    """(node, đích, giá trị) của ``x.Prop = value`` và ``new T { Prop = value }`` (dùng cho CS003, CS009)."""
    for assignment in ctx.assignments:
        yield assignment.node, assignment.target, assignment.value
    for call in ctx.calls:
        for prop, value in call.initializer.items():
            yield call.node, prop, value


@register_rule
class CSharpDeserializationRule(DeserializationRuleBase):
    """CS003: formatter nhị phân và cấu hình TypeNameHandling của Json.NET."""

    id = "CS003"
    language = CSHARP
    description = (
        "BinaryFormatter, SoapFormatter, NetDataContractSerializer and LosFormatter (and Json.NET with "
        "TypeNameHandling other than None) instantiate types named in the data; gadget chains turn attacker "
        "controlled data into remote code execution. Microsoft marks BinaryFormatter as dangerous."
    )
    recommendation = (
        "Use System.Text.Json or DataContractSerializer with known types; keep Json.NET TypeNameHandling = None."
    )
    dynamic_message = "{call} deserializes data with an unsafe formatter."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        # 1) formatter.Deserialize(stream)
        for call in ctx.calls:
            if call.is_constructor or call.method not in {"Deserialize", "UnsafeDeserialize"} \
                    or call.receiver_type not in _CS_FORMATTERS:
                continue
            finding = self.deserialization_finding(call, ctx, call.args[0] if call.args else None)
            if finding is not None:
                yield finding
        # 2) settings.TypeNameHandling = TypeNameHandling.All (hoặc trong object initializer)
        for node, target, value in _property_assignments(ctx):
            if target.endswith("TypeNameHandling") and _TYPE_NAME_HANDLING.search(ctx.adapter.text(value)):
                yield self.create_finding(node, ctx, f"Json.NET {ctx.adapter.text(value)} lets the data choose "
                                                     "which .NET types are created.", confidence=0.8)


@register_rule
class CSharpCodeInjectionRule(CodeInjectionRuleBase):
    """CS004: Roslyn scripting (CSharpScript)."""

    id = "CS004"
    language = CSHARP
    name = "Dynamic code evaluation (Roslyn scripting)"
    description = "CSharpScript.EvaluateAsync/RunAsync compile and run C# code given as a string."
    recommendation = "Never compile or run code built from user input; use a fixed set of operations instead."
    dynamic_message = "{call} runs dynamically built C# code."
    static_message = "{call} runs constant C# code."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver_text != "CSharpScript" or call.method not in {"EvaluateAsync", "RunAsync", "Create"} \
                    or not call.args:
                continue
            finding = self.code_finding(call, ctx)
            if finding is not None:
                yield finding


@register_rule
class CSharpWeakHashRule(WeakAlgorithmRuleBase):
    """CS005: chỉ khai báo dữ liệu, logic nằm ở WeakAlgorithmRuleBase."""

    id = "CS005"
    language = CSHARP
    name = "Weak cryptographic hash (MD5/SHA-1)"
    description = "MD5 and SHA-1 are broken (practical collisions) and far too fast for password storage."
    cwe = "CWE-328"
    recommendation = "Use SHA256/SHA512 for integrity and Rfc2898DeriveBytes.Pbkdf2 (or bcrypt/Argon2) for passwords."
    weak_calls = frozenset({
        "MD5.Create", "SHA1.Create", "MD5.HashData", "SHA1.HashData",
        "new MD5CryptoServiceProvider", "new SHA1CryptoServiceProvider", "new SHA1Managed", "new MD5Cng",
        "new SHA1Cng",
    })
    # Chọn thuật toán bằng tên chuỗi: HashAlgorithm.Create("MD5").
    algorithm_calls = frozenset({"HashAlgorithm.Create", "CryptoConfig.CreateFromName"})
    weak_algorithm = re.compile(r"^(MD5|SHA1|SHA|System\.Security\.Cryptography\.(MD5|SHA1))$", re.IGNORECASE)


@register_rule
class CSharpWeakCipherRule(WeakAlgorithmRuleBase):
    """CS006: DES/TripleDES/RC2 và chế độ CipherMode.ECB."""

    id = "CS006"
    language = CSHARP
    name = "Weak cipher or ECB mode"
    description = "DES, TripleDES and RC2 are obsolete; ECB mode leaks patterns of the plaintext."
    cwe = "CWE-327"
    recommendation = "Use AesGcm (or Aes with CBC + HMAC) with a random IV/nonce."
    weak_calls = frozenset({"DES.Create", "TripleDES.Create", "RC2.Create", "new DESCryptoServiceProvider",
                            "new TripleDESCryptoServiceProvider", "new RC2CryptoServiceProvider"})
    weak_members = frozenset({"CipherMode.ECB"})


@register_rule
class CSharpInsecureRandomRule(InsecureRandomRuleBase):
    """CS007: System.Random cho token, mật khẩu..."""

    id = "CS007"
    language = CSHARP
    description = "System.Random is predictable; tokens generated with it can be guessed."
    recommendation = "Use RandomNumberGenerator.GetBytes()/GetInt32() for tokens, passwords, keys and codes."
    random_calls = frozenset({"Random.Shared.Next", "Random.Shared.NextBytes"})


@register_rule
class CSharpHardcodedSecretRule(HardcodedSecretRuleBase):
    """CS008: toàn bộ logic nằm ở HardcodedSecretRuleBase + HardcodedSecretMixin."""

    id = "CS008"
    language = CSHARP
    recommendation = (
        "Use the .NET Secret Manager in development and environment variables, Azure Key Vault or another "
        "secret store in production."
    )


# Thuộc tính callback kiểm tra chứng chỉ của ServicePointManager / HttpClientHandler / SslStream.
_TLS_CALLBACKS = ("ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback",
                  "RemoteCertificateValidationCallback")


@register_rule
class CSharpTlsValidationRule(TSRule):
    """CS009: callback kiểm tra chứng chỉ luôn trả về true."""

    id = "CS009"
    language = CSHARP
    name = "TLS certificate validation disabled"
    description = (
        "A certificate validation callback that always returns true (or DangerousAcceptAnyServerCertificateValidator) "
        "accepts any certificate, allowing man-in-the-middle attacks on HTTPS."
    )
    severity = Severity.MEDIUM
    cwe = "CWE-295"
    category = "Insecure Transport"
    recommendation = "Remove the callback, or validate the certificate (e.g. pin the expected thumbprint)."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for node, target, value in _property_assignments(ctx):
            if not target.endswith(_TLS_CALLBACKS):
                continue
            value = ctx.adapter.unwrap(value)
            text = ctx.adapter.text(value)
            # (sender, cert, chain, errors) => true  hoặc  HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            if (value.type in ctx.adapter.lambda_types and ctx.adapter.lambda_returns_true(value)) \
                    or "DangerousAcceptAnyServerCertificateValidator" in text:
                yield self.create_finding(node, ctx, f"{target.rsplit('.', 1)[-1]} accepts every certificate.",
                                          confidence=0.9)


@register_rule
class CSharpOpenRedirectRule(OpenRedirectRuleBase):
    """CS010: ASP.NET response/controller redirect APIs that accept external URLs."""

    id = "CS010"
    language = CSHARP
    name = "Open redirect"
    description = (
        "A redirect destination taken from an untrusted request value can send users to an attacker-controlled "
        "site for phishing or to bypass trust in the application domain."
    )
    recommendation = (
        "Use LocalRedirect for local paths where available. Otherwise redirect only to fixed routes or validate "
        "the destination against an allow-list of trusted hosts or route identifiers."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        response_receivers = {"Response", "HttpResponse", "HttpResponseBase", "HttpResponseWrapper"}
        framework_receivers = {"Results", "TypedResults"}
        for call in ctx.calls:
            if call.method != "Redirect" or call.is_constructor or not call.args:
                continue
            receiver = (call.receiver_text or "").rsplit(".", 1)[-1]
            receiver_type = call.receiver_type or ""
            # Also match Controller.Redirect(url), represented as an unqualified call.
            if receiver not in response_receivers | framework_receivers and receiver_type not in response_receivers:
                if call.receiver is not None:
                    continue
            if self._is_local_url_guarded(ctx, call):
                continue
            finding = self.report_redirect(call, ctx)
            if finding is not None:
                yield finding

    @staticmethod
    def _is_local_url_guarded(ctx: TSContext, redirect) -> bool:  # type: ignore[no-untyped-def]
        """Recognize an exact Url.IsLocalUrl check enclosing the redirect's safe branch."""
        adapter = ctx.adapter
        destination = "".join(adapter.text(adapter.unwrap(redirect.args[0])).split())
        if not destination:
            return False
        expected = f"Url.IsLocalUrl({destination})"
        negated = f"!{expected}"
        guards = [
            guard for guard in ctx.calls
            if guard.method == "IsLocalUrl" and guard.receiver_text == "Url" and len(guard.args) == 1
            and "".join(adapter.text(adapter.unwrap(guard.args[0])).split()) == destination
        ]
        parent = redirect.node.parent
        while parent is not None:
            if parent.type == "if_statement":
                condition = parent.child_by_field_name("condition")
                consequence = parent.child_by_field_name("consequence")
                alternative = parent.child_by_field_name("alternative")
                condition_text = "".join(adapter.text(condition).split())
                in_consequence = consequence is not None and consequence.start_byte <= redirect.node.start_byte \
                    and redirect.node.end_byte <= consequence.end_byte
                in_alternative = alternative is not None and alternative.start_byte <= redirect.node.start_byte \
                    and redirect.node.end_byte <= alternative.end_byte
                for guard in guards:
                    if condition is None or not (condition.start_byte <= guard.node.start_byte
                                                  and guard.node.end_byte <= condition.end_byte):
                        continue
                    if (condition_text == expected and in_consequence) or (condition_text == negated and in_alternative):
                        return True
            parent = parent.parent

        # Also accept the common early-exit form:
        # if (!Url.IsLocalUrl(destination)) return BadRequest(); return Redirect(destination);
        statement = redirect.node
        while statement.parent is not None and statement.parent.type != "block":
            statement = statement.parent
        block = statement.parent
        if block is not None:
            siblings = list(block.named_children)
            position = next((i for i, child in enumerate(siblings) if child.id == statement.id), -1)
            if position > 0:
                previous = siblings[position - 1]
                if previous.type == "if_statement":
                    condition = previous.child_by_field_name("condition")
                    consequence = previous.child_by_field_name("consequence")
                    alternative = previous.child_by_field_name("alternative")
                    condition_text = "".join(adapter.text(condition).split())
                    exits_early = consequence is not None and (
                        consequence.type in {"return_statement", "throw_statement"}
                        or (consequence.type == "block" and consequence.named_children
                            and all(child.type in {"return_statement", "throw_statement"}
                                    for child in consequence.named_children))
                    )
                    if alternative is None and exits_early and condition_text == negated:
                        if any(condition is not None and condition.start_byte <= guard.node.start_byte
                               and guard.node.end_byte <= condition.end_byte for guard in guards):
                            return True
        return False


_FILE_READ_WRITE = (
    "ReadAllText", "ReadAllBytes", "ReadAllLines", "ReadLines", "OpenRead", "OpenText", "OpenWrite", "Open",
    "Create", "CreateText", "AppendAllText", "AppendAllLines", "AppendText", "WriteAllText", "WriteAllBytes",
    "WriteAllLines", "Delete",
)
# Lời gọi thật sự đọc/ghi/xóa file -> vị trí argument là đường dẫn (RECEIVER = đối tượng FileInfo).
# new StreamReader(...) không có trong bảng vì thường nhận một Stream (new StreamReader(Request.Body)).
_CS_PATH_SINKS: dict[str, tuple[int, ...]] = {
    **{f"File.{method}": (0,) for method in _FILE_READ_WRITE},
    **{f"File.{method}Async": (0,) for method in _FILE_READ_WRITE if method.startswith(("Read", "Write", "Append"))},
    **{f"File.{method}": (0, 1) for method in ("Copy", "Move", "Replace")},
    **{f"Directory.{method}": (0,) for method in (
        "Delete", "GetFiles", "GetDirectories", "EnumerateFiles", "EnumerateDirectories", "CreateDirectory")},
    "Directory.Move": (0, 1),
    "new FileStream": (0,),
    **{f"FileInfo.{method}": (RECEIVER,) for method in (
        "Delete", "OpenRead", "OpenText", "OpenWrite", "Open", "Create", "CreateText", "AppendText")},
    **{f"FileInfo.{method}": (RECEIVER, 0) for method in ("CopyTo", "MoveTo")},
    # Controller ASP.NET Core trả về file theo đường dẫn vật lý.
    "PhysicalFile": (0,),
}


@register_rule
class CSharpPathTraversalRule(PathTraversalRuleBase):
    """CS011: System.IO.File/Directory/FileStream, PhysicalFile... với đường dẫn từ request."""

    id = "CS011"
    language = CSHARP
    recommendation = (
        "Keep only the file name with Path.GetFileName(), or resolve Path.GetFullPath(Path.Combine(baseDir, name)) "
        "and verify it starts with the full base directory path. Prefer server-generated file names for uploads."
    )
    path_sinks = _CS_PATH_SINKS


# Đối tượng nhận là HTTP response: Response.Write(...), HttpContext.Response.WriteAsync(...).
_RESPONSE_TYPES = frozenset({"HttpResponse", "HttpResponseBase", "HttpResponseWrapper"})
# Tạo nội dung HTML "đã tin cậy" (không được encode khi render): Html.Raw(x), new HtmlString(x).
_RAW_HTML_SINKS: dict[str, tuple[int, ...]] = {
    "new HtmlString": (0,), "new MvcHtmlString": (0,), "MvcHtmlString.Create": (0,), "Html.Raw": (0,),
}


@register_rule
class CSharpXssRule(TaintedSinkRuleBase):
    """CS012: dữ liệu request ghi vào response, đánh dấu là HTML tin cậy hoặc trả về với Content-Type HTML."""

    id = "CS012"
    language = CSHARP
    name = "Cross-site scripting (XSS)"
    description = (
        "Untrusted input is written into an HTML response without encoding (Response.Write, Html.Raw, "
        "HtmlString, Content(..., \"text/html\")), so an attacker can inject scripts that run in the victim's browser."
    )
    severity = Severity.HIGH
    cwe = "CWE-79"
    category = "Cross-Site Scripting"
    recommendation = (
        "Let Razor encode output (@value instead of Html.Raw), or encode explicitly with "
        "HtmlEncoder.Default.Encode() / WebUtility.HtmlEncode() before writing HTML."
    )
    sanitizer_category = "html"
    tainted_message = "Untrusted input from {source} is written to the HTML response by {sink}."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            values = self._sink_values(ctx, call)
            if not values:
                continue
            finding = self.grade_sink(call.node, ctx, values, call.display)
            if finding is not None:
                yield finding

    @staticmethod
    def _sink_values(ctx: TSContext, call) -> list:  # type: ignore[no-untyped-def]
        """Các giá trị được đưa vào HTML của lời gọi, hoặc rỗng nếu lời gọi không phải sink XSS."""
        if call.is_constructor and call.method == "ContentResult":
            # new ContentResult { Content = html, ContentType = "text/html" }
            content_type = string_value(ctx, call.initializer.get("ContentType")) or ""
            content = call.initializer.get("Content")
            return [content] if content is not None and "html" in content_type.lower() else []
        if not call.args:
            return []
        if call.method in {"Write", "WriteAsync"} and not call.is_constructor:
            receiver = (call.receiver_text or "").rsplit(".", 1)[-1]
            if receiver == "Response" or call.receiver_type in _RESPONSE_TYPES:
                return [call.args[0]]
            return []
        if call.method == "Content" and call.receiver is None and len(call.args) >= 2:
            # Controller.Content(html, "text/html"): Content(text) mặc định là text/plain nên không báo.
            content_type = string_value(ctx, call.args[1]) or ""
            return [call.args[0]] if "html" in content_type.lower() else []
        positions = next((_RAW_HTML_SINKS[name] for name in sorted(call.names) if name in _RAW_HTML_SINKS), None)
        return [call.args[i] for i in positions if i < len(call.args)] if positions else []
