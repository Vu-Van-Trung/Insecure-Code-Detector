"""PHP rules PH001 - PH013 and PHP taint tracking (tree-sitter)."""

import textwrap

import pytest

from app.models.finding import Severity


@pytest.fixture
def php(engine):
    """php(code, "PH001") -> findings of that rule; ``<?php`` is added in front of the code."""

    def _find(code: str, rule_id: str):
        result = engine.scan_source("<?php\n" + textwrap.dedent(code), "page.php")
        assert not result.errors, result.errors
        return [f for f in result.findings if f.rule_id == rule_id]

    return _find


# ---------------------------------------------------------------- taint tracking


def test_superglobal_flows_through_variables_to_sink(php):
    [finding] = php("$id = $_GET['id'];\n$q = \"SELECT * FROM t WHERE id = '$id'\";\nmysqli_query($c, $q);", "PH002")
    assert finding.severity is Severity.CRITICAL
    assert finding.language == "php"
    assert finding.taint_path == ["$_GET", "$id", "$q", "mysqli_query()"]


def test_augmented_concatenation_keeps_taint(php):
    [finding] = php("$q = 'SELECT * FROM t WHERE a = ';\n$q .= $_POST['a'];\nmysql_query($q);", "PH002")
    assert finding.severity is Severity.CRITICAL


def test_taint_inside_function_and_branches(php):
    code = """
    function run() {
        if (isset($_GET['x'])) {
            $cmd = $_GET['x'];
        } else {
            $cmd = 'ls';
        }
        passthru($cmd);
    }
    """
    [finding] = php(code, "PH001")
    assert finding.severity is Severity.CRITICAL


def test_numeric_cast_and_intval_are_sanitizers(php):
    for expression in ("(int) $_GET['id']", "intval($_GET['id'])"):
        [finding] = php(f"mysqli_query($c, 'SELECT * FROM t WHERE id = ' . {expression});", "PH002")
        assert finding.severity is Severity.LOW
        assert "intval()" in finding.message


def test_html_mixed_with_php_is_parsed(php):
    code = "?>\n<html><body>\n<?php echo $_GET['q']; ?>\n</body></html>\n"
    [finding] = php(code, "PH006")
    assert finding.line == 4


# ---------------------------------------------------------------- rules


@pytest.mark.parametrize(
    "code, severity",
    [
        ("exec('ping ' . $_GET['h']);", Severity.CRITICAL),
        ("exec('ping ' . $host);", Severity.HIGH),
        ("exec('uptime');", Severity.LOW),
        ("$o = `cat {$_GET['f']}`;", Severity.CRITICAL),
        ("exec('ping ' . escapeshellarg($_GET['h']));", Severity.LOW),
    ],
)
def test_command_injection(php, code, severity):
    [finding] = php(code, "PH001")
    assert finding.severity is severity


def test_sql_method_needs_database_like_receiver(php):
    assert php("$cache->query('k' . $_GET['k']);", "PH002") == []
    [finding] = php("$mysqli->query('SELECT * FROM t WHERE k = ' . $_GET['k']);", "PH002")
    assert finding.severity is Severity.CRITICAL


def test_prepared_statement_is_not_reported(php):
    assert php("$s = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n$s->execute([$_GET['id']]);", "PH002") == []


@pytest.mark.parametrize(
    "code, expected",
    [
        ("include $_GET['p'];", Severity.CRITICAL),
        ("require_once $page;", Severity.MEDIUM),
        ("require_once __DIR__ . '/config.php';", None),
        ("include DVWA_ROOT . 'header.php';", None),
        ("$m = ['a' => 'a.php'];\ninclude $m['a'];", None),
    ],
)
def test_file_inclusion(php, code, expected):
    findings = php(code, "PH004")
    assert [f.severity for f in findings] == ([expected] if expected else [])


def test_xss_escaped_output_is_not_reported(php):
    assert php("echo htmlspecialchars($_GET['q'], ENT_QUOTES);", "PH006") == []
    # SQL escaping does not protect HTML: reported, but only as LOW.
    [finding] = php("echo mysqli_real_escape_string($c, $_GET['q']);", "PH006")
    assert finding.severity is Severity.LOW


def test_weak_hash_of_password_is_high(php):
    [high] = php("$pass = md5($_POST['pass']);", "PH007")
    [medium] = php("$etag = sha1($body);", "PH007")
    assert (high.severity, medium.severity) == (Severity.HIGH, Severity.MEDIUM)
    assert php("$h = hash('sha256', $data);", "PH007") == []
    assert len(php("$h = hash('md5', $data);", "PH007")) == 1


def test_insecure_random_only_for_security_values(php):
    assert len(php("$csrf_token = mt_rand();", "PH008")) == 1
    assert php("$dice = rand(1, 6);", "PH008") == []


def test_hardcoded_secrets_in_arrays_and_properties(php):
    code = """
    $config = ['db_password' => 'Xy7#kLm2pQ9!'];
    class A { private $apiKey = 'a8f5f167f44f4964e6c998dee827110c'; }
    $pw = 'changeme';
    """
    assert [f.line for f in php(code, "PH009")] == [3, 4]


def test_unserialize_with_allowed_classes_false_is_safe(php):
    assert php("unserialize($_COOKIE['c'], ['allowed_classes' => false]);", "PH010") == []
    [finding] = php("unserialize($_COOKIE['c']);", "PH010")
    assert finding.severity is Severity.CRITICAL


def test_open_redirect_and_header_injection(php):
    [redirect] = php("header('Location: ' . $_GET['u']);", "PH012")
    [header] = php("header('X-User: ' . $_GET['u']);", "PH012")
    assert (redirect.cwe, header.cwe) == ("CWE-601", "CWE-113")


def test_upload_keeping_client_file_name(php):
    code = "$p = 'up/' . basename($_FILES['f']['name']);\nmove_uploaded_file($_FILES['f']['tmp_name'], $p);"
    [finding] = php(code, "PH013")
    assert finding.taint_path == ["$_FILES", "basename()", "$p", "move_uploaded_file()"]
    # basename() removes "../", so this is not path traversal.
    assert php(code, "PH005") == []


def test_inline_ignore_comment(php):
    assert php("system($_GET['c']); // analyzer-ignore: PH001", "PH001") == []
    assert php("# analyzer-ignore\nsystem($_GET['c']);", "PH001") == []


def test_syntax_error_is_reported(engine):
    result = engine.scan_source("<?php\nfunction (", "broken.php")
    assert result.errors and result.errors[0].error_type == "SyntaxError"
