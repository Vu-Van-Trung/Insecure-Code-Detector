"""Java rules JV001 - JV010 and Java taint tracking (tree-sitter)."""

import textwrap

import pytest

from app.models.finding import Severity


@pytest.fixture
def java(engine):
    """java(body, "JV001") -> findings of that rule; body is wrapped in a class/method."""

    def _find(code: str, rule_id: str, wrap: bool = True):
        code = textwrap.dedent(code)
        if wrap:
            code = "class T {\n void m(HttpServletRequest request, Connection conn, String param) throws Exception {\n" \
                   + code + "\n }\n}\n"
        result = engine.scan_source(code, "T.java")
        assert not result.errors, result.errors
        return [f for f in result.findings if f.rule_id == rule_id]

    return _find


# ---------------------------------------------------------------- JV001 command injection


def test_runtime_exec_with_request_data_is_critical_with_path(java):
    [finding] = java('String host = request.getParameter("host");\nRuntime.getRuntime().exec("ping " + host);', "JV001")
    assert finding.severity is Severity.CRITICAL
    assert finding.language == "java"
    assert finding.taint_path == ["request.getParameter()", "host", "Runtime.exec()"]


@pytest.mark.parametrize(
    "code, severity",
    [
        ('Runtime.getRuntime().exec("ls " + param);', Severity.HIGH),        # parameter: origin unknown
        ('Runtime rt = Runtime.getRuntime();\nrt.exec(param);', Severity.HIGH),
        ('Runtime.getRuntime().exec("ls -l");', Severity.LOW),                # constant command
        ('new ProcessBuilder("bash", "-c", param).start();', Severity.HIGH),  # shell
        ('Runtime.getRuntime().exec(new String[]{"sh", "-c", request.getParameter("c")});', Severity.CRITICAL),
        ('ProcessBuilder pb = new ProcessBuilder();\npb.command("cmd.exe", "/c", param);', Severity.HIGH),
    ],
)
def test_command_execution(java, code, severity):
    [finding] = java(code, "JV001")
    assert finding.severity is severity
    assert finding.cwe == "CWE-78"


@pytest.mark.parametrize(
    "code",
    [
        'new ProcessBuilder("ping", "-c", "1", param).start();',   # fixed program, no shell
        'new ProcessBuilder(List.of("ls", param)).start();',
        'executor.exec(param);',                                    # not Runtime
        'String s = "Runtime.getRuntime().exec(x)";',
    ],
)
def test_command_safe(java, code):
    assert java(code, "JV001") == []


# ---------------------------------------------------------------- JV002 SQL injection


def test_sql_injection_tainted(java):
    code = """
    String id = request.getParameter("id");
    String q = "SELECT * FROM users WHERE id = " + id;
    q += " AND active = 1";
    Statement st = conn.createStatement();
    st.executeQuery(q);
    """
    [finding] = java(code, "JV002")
    assert finding.severity is Severity.CRITICAL
    assert finding.taint_path[-1] == "Statement.executeQuery()"


@pytest.mark.parametrize(
    "code",
    [
        'conn.createStatement().executeUpdate("DELETE FROM t WHERE id = " + param);',
        'conn.prepareStatement(String.format("SELECT * FROM t WHERE n = \'%s\'", param));',
        'jdbcTemplate.query("SELECT * FROM t WHERE a = " + param, mapper);',
        'em.createNativeQuery("SELECT * FROM t WHERE a = " + param);',
    ],
)
def test_sql_built_by_concatenation_is_high(java, code):
    [finding] = java(code, "JV002")
    assert finding.severity is Severity.HIGH


@pytest.mark.parametrize(
    "code",
    [
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\nps.setString(1, param);',
        'conn.createStatement().executeQuery("SELECT * FROM t");',
        'String q = "SELECT * FROM t";\nconn.createStatement().executeQuery(q);',
        'executor.execute(task + param);',                   # not a database
        'int id = Integer.parseInt(param);\nlist.add(id);',
    ],
)
def test_sql_safe(java, code):
    assert java(code, "JV002") == []


def test_sql_with_sanitizer_is_low(java):
    code = 'int id = Integer.parseInt(request.getParameter("id"));\n' \
           'conn.createStatement().executeQuery("SELECT * FROM t WHERE id = " + id);'
    [finding] = java(code, "JV002")
    assert finding.severity is Severity.LOW
    assert "Integer.parseInt" in finding.message


# ---------------------------------------------------------------- JV003 - JV007


def test_deserialization(java):
    [tainted] = java("ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nin.readObject();", "JV003")
    assert tainted.severity is Severity.CRITICAL
    [unknown] = java("ObjectInputStream in = new ObjectInputStream(stream);\nObject o = in.readObject();", "JV003")
    assert unknown.severity is Severity.HIGH
    assert java('XStream x = new XStream();\nx.fromXML(param);', "JV003")
    assert java("Gson g = new Gson();\ng.fromJson(param, User.class);", "JV003") == []


def test_code_injection(java):
    code = 'ScriptEngine e = new ScriptEngineManager().getEngineByName("js");\ne.eval(request.getParameter("x"));'
    [finding] = java(code, "JV004")
    assert finding.severity is Severity.CRITICAL
    [spel] = java('ExpressionParser p = new SpelExpressionParser();\np.parseExpression(param);', "JV004")
    assert spel.cwe == "CWE-917"


@pytest.mark.parametrize("algorithm, flagged", [("MD5", True), ("SHA-1", True), ("SHA1", True), ("SHA-256", False)])
def test_weak_hash(java, algorithm, flagged):
    assert bool(java(f'MessageDigest.getInstance("{algorithm}");', "JV005")) is flagged


@pytest.mark.parametrize(
    "transformation, flagged",
    [("DES", True), ("DESede/CBC/PKCS5Padding", True), ("AES/ECB/PKCS5Padding", True), ("AES", True),
     ("RC4", True), ("AES/GCM/NoPadding", False), ("AES/CBC/PKCS5Padding", False)],
)
def test_weak_cipher(java, transformation, flagged):
    assert bool(java(f'Cipher.getInstance("{transformation}");', "JV006")) is flagged


def test_insecure_random(java):
    assert java("Random r = new Random();\nString token = Integer.toString(r.nextInt());", "JV007")
    assert java("String sessionId = String.valueOf(Math.random());", "JV007")
    assert java("Random r = new Random();\nint dice = r.nextInt(6);", "JV007") == []
    assert java("SecureRandom r = new SecureRandom();\nString token = Integer.toString(r.nextInt());", "JV007") == []


# ---------------------------------------------------------------- JV008 secrets


@pytest.mark.parametrize(
    "code, severity",
    [
        ('private static final String API_KEY = "a8f5f167f44f4964e6c998dee827110c";', Severity.HIGH),
        ('String password = "hunter2!";', Severity.MEDIUM),
        ('String url = "jdbc:mysql://db/app?user=root&password=S3cr3tPass";', Severity.HIGH),
        ('String k = "AKIAIOSFODNN7EXAMPLE";', Severity.HIGH),
    ],
)
def test_hardcoded_secrets(java, code, severity):
    [finding] = java(code, "JV008")
    assert finding.severity is severity
    assert "a8f5f167f44f4964e6c998dee827110c" not in finding.code  # masked


@pytest.mark.parametrize(
    "code",
    ['String password = System.getenv("DB_PASSWORD");', 'String password = "changeme";',
     'int PASSWORD_MIN_LENGTH = 12;', 'String passwordField = "password";'],
)
def test_non_secrets(java, code):
    assert java(code, "JV008") == []


# ---------------------------------------------------------------- JV009 TLS


def test_tls_disabled(java):
    code = """
    class TrustAll implements X509TrustManager {
        public void checkServerTrusted(X509Certificate[] c, String a) { }
        public boolean verify(String host, SSLSession s) { return true; }
    }
    class U { void m(HttpsURLConnection c) { c.setHostnameVerifier(NoopHostnameVerifier.INSTANCE); } }
    """
    findings = java(code, "JV009", wrap=False)
    assert len(findings) == 3
    safe = "class S { public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { tm.checkServerTrusted(c, a); } }"
    assert java(safe, "JV009", wrap=False) == []


# ---------------------------------------------------------------- taint details & engine behaviour


@pytest.mark.parametrize(
    "header",
    ['@GetMapping("/p") void m(@RequestParam("h") String host)', "public static void main(String[] args)"],
)
def test_parameter_sources(java, header):
    variable = "host" if "RequestParam" in header else "args[0]"
    code = f"class C {{ {header} throws Exception {{ Runtime.getRuntime().exec({variable}); }} }}"
    [finding] = java(code, "JV001", wrap=False)
    assert finding.severity is Severity.CRITICAL


def test_taint_through_branches_loops_and_fields(java):
    code = """
    class C {
        private String cmd;
        void m(HttpServletRequest request, boolean flag) throws Exception {
            String c = "ls";
            if (flag) { c = request.getParameter("c"); }
            for (String part : request.getParameterValues("p")) { this.cmd = part; }
            Runtime.getRuntime().exec(c);
            Runtime.getRuntime().exec(this.cmd);
        }
    }
    """
    findings = java(code, "JV001", wrap=False)
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.CRITICAL]


def test_inline_ignore_comment(engine):
    code = "class C { void m(String p) throws Exception {\n  // analyzer-ignore: JV001\n  Runtime.getRuntime().exec(p);\n} }"
    result = engine.scan_source(code, "C.java")
    assert result.findings == [] and [f.rule_id for f in result.suppressed] == ["JV001"]


def test_syntax_error_is_reported(engine):
    result = engine.scan_source("class C {\n  void m( {\n}\n", "Broken.java")
    [error] = result.errors
    assert error.error_type == "SyntaxError" and "Java" in error.reason and error.line is not None


def test_comment_and_string_are_not_code(java):
    code = '// Runtime.getRuntime().exec(request.getParameter("x"));\nString s = "Runtime.getRuntime().exec(x)";'
    assert java(code, "JV001") == []


# ---------------------------------------------------------------- JV010 open redirect


def test_open_redirect_from_request_parameter(java):
    [finding] = java('response.sendRedirect(request.getParameter("next"));', "JV010")
    assert finding.cwe == "CWE-601"
    assert finding.severity is Severity.HIGH
    assert finding.source == "request.getParameter()"
    assert finding.sink == "response.sendRedirect()"


def test_open_redirect_tracks_assigned_request_value(java):
    findings = java('String target = request.getParameter("next");\nresponse.sendRedirect(target);', "JV010")
    assert len(findings) == 1 and findings[0].line == 4


def test_fixed_redirect_target_is_not_reported(java):
    assert java('response.sendRedirect("/dashboard");', "JV010") == []


def test_generic_encoder_does_not_sanitize_sql(java):
    code = """
    String id = request.getParameter("id");
    String safeId = Codec.encode(id);
    String q = "SELECT * FROM users WHERE id = " + safeId;
    Statement st = conn.createStatement();
    st.executeQuery(q);
    """
    [finding] = java(code, "JV002")
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence >= 0.9


def test_inter_procedural_call_in_java(java):
    code = """
    class Controller {
        void executeCmd(String c) throws Exception {
            Runtime.getRuntime().exec(c);
        }
        void handle(HttpServletRequest req) throws Exception {
            executeCmd(req.getParameter("p"));
        }
    }
    """
    findings = java(code, "JV001", wrap=False)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].source == "req.getParameter()"
