"""C# rules CS001 - CS009 (tree-sitter based)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.analyzer.languages import CSHARP
from app.analyzer.ts.context import TSContext
from app.models.finding import Finding, Severity
from app.rules._ts_common import (
    CommandRuleMixin,
    HardcodedSecretRuleBase,
    InsecureRandomRuleBase,
    SqlRuleBase,
    TSRule,
    WeakAlgorithmRuleBase,
)
from app.rules.base import ArgumentKind, classify_argument
from app.rules.registry import register_rule


@register_rule
class CSharpCommandInjectionRule(CommandRuleMixin):
    id = "CS001"
    language = CSHARP
    name = "OS command execution (Process.Start)"
    description = (
        "Process.Start / ProcessStartInfo start operating-system processes. Running a program chosen at "
        "runtime, or passing untrusted data to cmd.exe /c or a shell, allows command injection."
    )
    severity = Severity.HIGH
    cwe = "CWE-78"
    category = "Command Injection"
    recommendation = (
        "Start a fixed executable with UseShellExecute = false and pass arguments through "
        "ProcessStartInfo.ArgumentList; never run cmd.exe /c with user input."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            finding = None
            if call.method == "Start" and call.receiver_text == "Process" and call.args:
                if len(call.args) == 1 and self._is_start_info(ctx, call.args[0]):
                    continue  # Process.Start(psi): reported where the ProcessStartInfo is built
                if len(call.args) == 1:
                    finding = self.grade_command_line(call.node, ctx, call.args[0], "Process.Start()")
                else:
                    finding = self.grade_program(call.node, ctx, call.args[:2], "Process.Start()")
            elif call.is_constructor and call.method == "ProcessStartInfo":
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


_CS_SQL_COMMANDS = frozenset({"SqlCommand", "SqliteCommand", "OleDbCommand", "OdbcCommand", "NpgsqlCommand",
                              "MySqlCommand", "OracleCommand", "SqlDataAdapter"})
_CS_SQL_METHODS = frozenset({"FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlRawAsync", "SqlQueryRaw", "ExecuteQuery",
                             "ExecuteCommand"})
_CS_SQL_GENERIC = frozenset({"Query", "QueryAsync", "QueryFirst", "QueryFirstOrDefault", "QuerySingle",
                             "Execute", "ExecuteAsync", "ExecuteScalar"})  # Dapper


@register_rule
class CSharpSqlInjectionRule(SqlRuleBase):
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
                query = call.args[0] if call.args else call.initializer.get("CommandText")
                if query is not None:
                    finding = self.grade_query(call.node, ctx, query, f"new {call.method}()", True)
            elif not call.is_constructor and call.args and (call.method in _CS_SQL_METHODS
                                                            or call.method in _CS_SQL_GENERIC):
                finding = self.grade_query(call.node, ctx, call.args[0], call.display,
                                           call.method in _CS_SQL_METHODS, call.receiver)
            if finding is not None:
                yield finding
        for assignment in ctx.assignments:
            if assignment.target.endswith(".CommandText") and not assignment.augmented:
                finding = self.grade_query(assignment.node, ctx, assignment.value, assignment.target, True)
                if finding is not None:
                    yield finding


_CS_FORMATTERS = frozenset({"BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter",
                            "ObjectStateFormatter"})
_TYPE_NAME_HANDLING = re.compile(r"TypeNameHandling\.(All|Auto|Objects|Arrays)")


@register_rule
class CSharpDeserializationRule(TSRule):
    id = "CS003"
    language = CSHARP
    name = "Unsafe deserialization"
    description = (
        "BinaryFormatter, SoapFormatter, NetDataContractSerializer and LosFormatter (and Json.NET with "
        "TypeNameHandling other than None) instantiate types named in the data; gadget chains turn attacker "
        "controlled data into remote code execution. Microsoft marks BinaryFormatter as dangerous."
    )
    severity = Severity.HIGH
    cwe = "CWE-502"
    category = "Insecure Deserialization"
    recommendation = (
        "Use System.Text.Json or DataContractSerializer with known types; keep Json.NET TypeNameHandling = None."
    )

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.is_constructor or call.method not in {"Deserialize", "UnsafeDeserialize"} \
                    or call.receiver_type not in _CS_FORMATTERS:
                continue
            kind, info = classify_argument(call.args[0], ctx) if call.args else (ArgumentKind.DYNAMIC, None)
            if kind is ArgumentKind.STATIC:
                kind = ArgumentKind.DYNAMIC
            finding = self.graded_finding(call.node, ctx, kind, info, call.display,
                                          dynamic_message=f"{call.display} deserializes data with an unsafe formatter.")
            if finding is not None:
                yield finding
        values = [(a.node, a.target, a.value) for a in ctx.assignments]
        values += [(call.node, prop, value) for call in ctx.calls for prop, value in call.initializer.items()]
        for node, target, value in values:
            if target.endswith("TypeNameHandling") and _TYPE_NAME_HANDLING.search(ctx.adapter.text(value)):
                yield self.create_finding(node, ctx, f"Json.NET {ctx.adapter.text(value)} lets the data choose "
                                                     "which .NET types are created.", confidence=0.8)


@register_rule
class CSharpCodeInjectionRule(TSRule):
    id = "CS004"
    language = CSHARP
    name = "Dynamic code evaluation (Roslyn scripting)"
    description = "CSharpScript.EvaluateAsync/RunAsync compile and run C# code given as a string."
    severity = Severity.CRITICAL
    cwe = "CWE-95"
    category = "Code Injection"
    recommendation = "Never compile or run code built from user input; use a fixed set of operations instead."

    def check_file(self, ctx: TSContext) -> Iterator[Finding]:
        for call in ctx.calls:
            if call.receiver_text != "CSharpScript" or call.method not in {"EvaluateAsync", "RunAsync", "Create"} \
                    or not call.args:
                continue
            kind, info = classify_argument(call.args[0], ctx)
            finding = self.graded_finding(
                call.node, ctx, kind, info, call.display,
                dynamic_message=f"{call.display} runs dynamically built C# code.",
                static_message=f"{call.display} runs constant C# code.", dynamic_confidence=0.85,
            )
            if finding is not None:
                yield finding


@register_rule
class CSharpWeakHashRule(WeakAlgorithmRuleBase):
    id = "CS005"
    language = CSHARP
    name = "Weak cryptographic hash (MD5/SHA-1)"
    description = "MD5 and SHA-1 are broken (practical collisions) and far too fast for password storage."
    severity = Severity.MEDIUM
    cwe = "CWE-328"
    category = "Weak Cryptography"
    recommendation = "Use SHA256/SHA512 for integrity and Rfc2898DeriveBytes.Pbkdf2 (or bcrypt/Argon2) for passwords."
    weak_calls = frozenset({
        "MD5.Create", "SHA1.Create", "MD5.HashData", "SHA1.HashData",
        "new MD5CryptoServiceProvider", "new SHA1CryptoServiceProvider", "new SHA1Managed", "new MD5Cng",
        "new SHA1Cng",
    })
    algorithm_calls = frozenset({"HashAlgorithm.Create", "CryptoConfig.CreateFromName"})
    weak_algorithm = re.compile(r"^(MD5|SHA1|SHA|System\.Security\.Cryptography\.(MD5|SHA1))$", re.IGNORECASE)


@register_rule
class CSharpWeakCipherRule(WeakAlgorithmRuleBase):
    id = "CS006"
    language = CSHARP
    name = "Weak cipher or ECB mode"
    description = "DES, TripleDES and RC2 are obsolete; ECB mode leaks patterns of the plaintext."
    severity = Severity.MEDIUM
    cwe = "CWE-327"
    category = "Weak Cryptography"
    recommendation = "Use AesGcm (or Aes with CBC + HMAC) with a random IV/nonce."
    weak_calls = frozenset({"DES.Create", "TripleDES.Create", "RC2.Create", "new DESCryptoServiceProvider",
                            "new TripleDESCryptoServiceProvider", "new RC2CryptoServiceProvider"})
    weak_members = frozenset({"CipherMode.ECB"})


@register_rule
class CSharpInsecureRandomRule(InsecureRandomRuleBase):
    id = "CS007"
    language = CSHARP
    name = "Insecure random generator for security value"
    description = "System.Random is predictable; tokens generated with it can be guessed."
    recommendation = "Use RandomNumberGenerator.GetBytes()/GetInt32() for tokens, passwords, keys and codes."
    random_calls = frozenset({"Random.Shared.Next", "Random.Shared.NextBytes"})


@register_rule
class CSharpHardcodedSecretRule(HardcodedSecretRuleBase):
    id = "CS008"
    language = CSHARP
    name = "Hardcoded secret"
    recommendation = (
        "Use the .NET Secret Manager in development and environment variables, Azure Key Vault or another "
        "secret store in production."
    )


_TLS_CALLBACKS = ("ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback",
                  "RemoteCertificateValidationCallback")


@register_rule
class CSharpTlsValidationRule(TSRule):
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
        values = [(a.node, a.target, a.value) for a in ctx.assignments]
        values += [(call.node, prop, value) for call in ctx.calls for prop, value in call.initializer.items()]
        for node, target, value in values:
            if not target.endswith(_TLS_CALLBACKS):
                continue
            value = ctx.adapter.unwrap(value)
            text = ctx.adapter.text(value)
            if (value.type in ctx.adapter.lambda_types and ctx.adapter.lambda_returns_true(value)) \
                    or "DangerousAcceptAnyServerCertificateValidator" in text:
                yield self.create_finding(node, ctx, f"{target.rsplit('.', 1)[-1]} accepts every certificate.",
                                          confidence=0.9)

