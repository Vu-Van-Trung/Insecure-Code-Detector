"""C# rules CS001 - CS010 and C# taint tracking (tree-sitter)."""

import textwrap

import pytest

from app.models.finding import Severity


@pytest.fixture
def cs(engine):
    """cs(body, "CS001") -> findings of that rule; body is wrapped in a class/method."""

    def _find(code: str, rule_id: str, wrap: bool = True):
        code = textwrap.dedent(code)
        if wrap:
            code = "class T : Controller {\n void M(string param, SqlConnection conn) {\n" + code + "\n }\n}\n"
        result = engine.scan_source(code, "T.cs")
        assert not result.errors, result.errors
        return [f for f in result.findings if f.rule_id == rule_id]

    return _find


# ---------------------------------------------------------------- CS001 command injection


def test_process_start_with_console_input_is_critical(cs):
    [finding] = cs('var input = Console.ReadLine();\nProcess.Start("cmd.exe", "/c " + input);', "CS001")
    assert finding.severity is Severity.CRITICAL
    assert finding.language == "csharp"
    assert finding.taint_path == ["Console.ReadLine()", "input", "Process.Start()"]


@pytest.mark.parametrize(
    "code, severity",
    [
        ('Process.Start("cmd.exe", "/c " + param);', Severity.HIGH),
        ('Process.Start(param);', Severity.HIGH),                       # program chosen at runtime
        ('Process.Start("cmd.exe", "/c dir");', Severity.LOW),
        ('var psi = new ProcessStartInfo { FileName = "powershell", Arguments = param };', Severity.HIGH),
        ('var psi = new ProcessStartInfo("bash", "-c " + Request.Query["c"]);', Severity.CRITICAL),
    ],
)
def test_process_start(cs, code, severity):
    [finding] = cs(code, "CS001")
    assert finding.severity is severity


@pytest.mark.parametrize(
    "code",
    [
        'Process.Start("ping", param);',                                # fixed program, no shell
        'var psi = new ProcessStartInfo("git") { UseShellExecute = false };\npsi.ArgumentList.Add(param);',
        'runner.Start(param);',
    ],
)
def test_process_safe(cs, code):
    assert cs(code, "CS001") == []


# ---------------------------------------------------------------- CS002 SQL injection


@pytest.mark.parametrize(
    "code, severity",
    [
        ('var sql = $"SELECT * FROM U WHERE N = \'{Request.Query["n"]}\'";\nvar c = new SqlCommand(sql, conn);',
         Severity.CRITICAL),
        ('var c = new SqlCommand("SELECT * FROM U WHERE Id = " + param, conn);', Severity.HIGH),
        ('var c = conn.CreateCommand();\nc.CommandText = "DELETE FROM T WHERE Id = " + param;', Severity.HIGH),
        ('db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = {param}");', Severity.HIGH),
        ('conn.Query<User>("SELECT * FROM Users WHERE Name = \'" + param + "\'");', Severity.HIGH),
        ('var c = new SqlCommand(@"SELECT * FROM U WHERE N = " + param, conn);', Severity.HIGH),
    ],
)
def test_sql_injection(cs, code, severity):
    [finding] = cs(code, "CS002")
    assert finding.severity is severity
    assert finding.cwe == "CWE-89"


@pytest.mark.parametrize(
    "code",
    [
        'var c = new SqlCommand("SELECT * FROM U WHERE N = @n", conn);\nc.Parameters.AddWithValue("@n", param);',
        'db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {param}");',  # parameterized by EF
        'conn.Query<User>("SELECT * FROM Users WHERE Name = @Name", new { Name = param });',
        'logger.Execute("done " + param);',
    ],
)
def test_sql_safe(cs, code):
    assert cs(code, "CS002") == []


# ---------------------------------------------------------------- CS003 - CS007


def test_deserialization(cs):
    [tainted] = cs("var f = new BinaryFormatter();\nvar o = f.Deserialize(Request.Body);", "CS003")
    assert tainted.severity is Severity.CRITICAL
    assert cs("var o = new BinaryFormatter().Deserialize(stream);", "CS003")
    assert cs("var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };", "CS003")
    assert cs("var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };", "CS003") == []
    assert cs("var o = JsonSerializer.Deserialize<User>(param);", "CS003") == []


def test_code_injection(cs):
    [finding] = cs("var r = CSharpScript.EvaluateAsync(param);", "CS004")
    assert finding.severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "code, flagged",
    [("var h = MD5.Create();", True), ("var h = SHA1.Create();", True), ("var h = new SHA1Managed();", True),
     ('var h = HashAlgorithm.Create("MD5");', True), ("var h = SHA256.Create();", False)],
)
def test_weak_hash(cs, code, flagged):
    assert bool(cs(code, "CS005")) is flagged


@pytest.mark.parametrize(
    "code, flagged",
    [("var d = DES.Create();", True), ("var d = TripleDES.Create();", True),
     ("var a = Aes.Create();\na.Mode = CipherMode.ECB;", True), ("var a = Aes.Create();\na.Mode = CipherMode.CBC;", False)],
)
def test_weak_cipher(cs, code, flagged):
    assert bool(cs(code, "CS006")) is flagged


def test_insecure_random(cs):
    assert cs("var r = new Random();\nvar resetCode = r.Next(100000, 999999);", "CS007")
    assert cs("var r = new Random();\nvar dice = r.Next(1, 7);", "CS007") == []
    assert cs("var token = RandomNumberGenerator.GetInt32(1000000);", "CS007") == []


# ---------------------------------------------------------------- CS008 secrets


@pytest.mark.parametrize(
    "code, severity",
    [
        ('const string ApiKey = "a8f5f167f44f4964e6c998dee827110c";', Severity.HIGH),
        ('var cs = "Server=db;User Id=sa;Password=S3cr3t!Pass;";', Severity.HIGH),
        ('var client = new SmtpClient { Password = "hunter2!" };', Severity.MEDIUM),
    ],
)
def test_hardcoded_secrets(cs, code, severity):
    [finding] = cs(code, "CS008")
    assert finding.severity is severity


@pytest.mark.parametrize(
    "code",
    ['var password = Environment.GetEnvironmentVariable("DB_PASSWORD");',
     'var cs = "Server=db;User Id=sa;Password=changeme;";', 'var cs = "Server=db;Integrated Security=true;";',
     "const int PasswordMinLength = 12;"],
)
def test_non_secrets(cs, code):
    assert cs(code, "CS008") == []


def test_secret_property_initializer_is_masked(cs):
    code = 'class S { public string Password { get; set; } = "a8f5f167f44f4964e6c998dee827110c"; }'
    [finding] = cs(code, "CS008", wrap=False)
    assert "a8f5f167" not in finding.code


# ---------------------------------------------------------------- CS009 TLS


@pytest.mark.parametrize(
    "code, flagged",
    [
        ("ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;", True),
        ("var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = "
         "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };", True),
        ("ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };", True),
        ("ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => e == SslPolicyErrors.None;",
         False),
    ],
)
def test_tls(cs, code, flagged):
    assert bool(cs(code, "CS009")) is flagged


# ---------------------------------------------------------------- taint details & engine behaviour


def test_aspnet_parameter_source_and_main_args(cs):
    code = 'class C { IActionResult Get([FromQuery] string host) { Process.Start("cmd.exe", "/c ping " + host); ' \
           'return Ok(); } static void Main(string[] args) { Process.Start(args[0]); } }'
    findings = cs(code, "CS001", wrap=False)
    assert [f.source for f in findings] == ["[FromQuery]", "args (command line)"]


def test_foreach_and_ternary_propagate(cs):
    code = 'foreach (var h in Request.Query["hosts"]) { var cmd = flag ? "/c ping " + h : "/c dir"; ' \
           'Process.Start("cmd.exe", cmd); }'
    [finding] = cs(code, "CS001")
    assert finding.severity is Severity.CRITICAL


def test_inline_ignore_comment(engine):
    code = "class C { void M(string p) {\n  Process.Start(p); // analyzer-ignore: CS001\n} }"
    result = engine.scan_source(code, "C.cs")
    assert result.findings == [] and len(result.suppressed) == 1


def test_syntax_error_is_reported(engine):
    [error] = engine.scan_source("class C { void M( { }", "Broken.cs").errors
    assert error.error_type == "SyntaxError" and "C#" in error.reason


def test_generic_encoder_does_not_sanitize_sql(cs):
    code = """
    string id = Request.Query["id"];
    var p = SqlParameter(id);
    string q = "SELECT * FROM users WHERE id = " + p;
    new SqlCommand(q, conn);
    """
    [finding] = cs(code, "CS002")
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence >= 0.9


def test_inter_procedural_call_in_csharp(cs):
    code = """
    class Controller {
        void ExecuteCmd(string c) {
            Process.Start("cmd.exe", "/c " + c);
        }
        void Handle() {
            ExecuteCmd(Console.ReadLine());
        }
    }
    """
    findings = cs(code, "CS001", wrap=False)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].source == "Console.ReadLine()"


# ---------------------------------------------------------------- CS010 open redirect


def test_open_redirect_from_request_query(cs):
    [finding] = cs('Response.Redirect(Request.Query["next"]);', "CS010")
    assert finding.cwe == "CWE-601"
    assert finding.severity is Severity.HIGH
    assert finding.source == "Request.Query"
    assert finding.sink == "Response.Redirect()"


def test_mvc_redirect_tracks_assigned_query_value(cs):
    findings = cs('var target = Request.Query["next"];\nRedirect(target);', "CS010")
    assert len(findings) == 1 and findings[0].line == 4


def test_local_redirect_and_fixed_target_are_not_reported(cs):
    assert cs('LocalRedirect(Request.Query["next"]);', "CS010") == []
    assert cs('Response.Redirect("/dashboard");', "CS010") == []


def test_redirect_inside_positive_local_url_guard_is_not_reported(cs):
    code = '''
    class Demo : Controller {
        IActionResult Go() {
            var destination = Request.Query["next"];
            if (Url.IsLocalUrl(destination)) {
                return Redirect(destination);
            }
            return BadRequest();
        }
    }
    '''
    assert cs(code, "CS010", wrap=False) == []


def test_redirect_after_early_rejection_of_nonlocal_url_is_not_reported(cs):
    code = '''
    class Demo : Controller {
        IActionResult Go() {
            var destination = Request.Query["next"];
            if (!Url.IsLocalUrl(destination)) return BadRequest();
            return Redirect(destination);
        }
    }
    '''
    assert cs(code, "CS010", wrap=False) == []


def test_local_url_check_for_a_different_value_does_not_suppress(cs):
    code = '''
    if (Url.IsLocalUrl("/dashboard")) {
        Response.Redirect(Request.Query["next"]);
    }
    '''
    assert cs(code, "CS010")
