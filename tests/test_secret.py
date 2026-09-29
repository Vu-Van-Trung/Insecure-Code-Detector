"""PY007 - hardcoded secrets.

Realistic-looking tokens are assembled at runtime (e.g. "gh" + "p_...") so this
file itself does not trip secret scanners such as GitHub push protection.
"""

import pytest

from app.models.finding import Severity
from app.rules._keywords import is_secret_name
from app.rules.secret_rule import is_placeholder, mask_secret, shannon_entropy

RANDOM_HEX = "a8f5f167f44f4964e6c998dee827110c"
GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow..."


# ---------------------------------------------------------------- name-based


@pytest.mark.parametrize(
    "code",
    [
        f'API_KEY = "{RANDOM_HEX}"',
        f'SECRET_KEY = "{RANDOM_HEX}"',
        f'self.auth_token = "{RANDOM_HEX}"',
        f'settings["client_secret"] = "{RANDOM_HEX}"',
        f'client = Client(api_key="{RANDOM_HEX}")',
        f'config = {{"access_key": "{RANDOM_HEX}"}}',
        f'apiKey: str = "{RANDOM_HEX}"',
    ],
)
def test_high_entropy_secret_is_high(find, code):
    [finding] = find(code, "PY007")
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 0.85
    assert finding.cwe == "CWE-798"


@pytest.mark.parametrize("code", ['PASSWORD = "admin123"', 'db_password = "hunter2!"', 'connect(passwd="qwerty1")'])
def test_low_entropy_password_is_medium(find, code):
    [finding] = find(code, "PY007")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.6


# ---------------------------------------------------------------- format-based


@pytest.mark.parametrize(
    "value, severity",
    [
        ("AKIAIOSFODNN7EXAMPLE", Severity.HIGH),  # AWS documentation example key
        (GITHUB_TOKEN, Severity.HIGH),
        (PRIVATE_KEY, Severity.CRITICAL),
    ],
)
def test_known_formats_are_detected_regardless_of_variable_name(find, value, severity):
    [finding] = find(f"value = {value!r}", "PY007")
    assert finding.severity is severity
    assert finding.confidence == 0.95


def test_known_format_in_secret_named_variable_is_reported_once(find):
    assert len(find(f"GITHUB_TOKEN = {GITHUB_TOKEN!r}", "PY007")) == 1


# ---------------------------------------------------------------- masking


def test_secret_is_masked_in_finding(find):
    [finding] = find(f'API_KEY = "{RANDOM_HEX}"', "PY007")
    assert RANDOM_HEX not in finding.code
    assert RANDOM_HEX not in finding.message
    assert finding.code.startswith('API_KEY = "a8f5')


def test_multiline_secret_is_fully_masked(find):
    [finding] = find(f"key = {PRIVATE_KEY!r}", "PY007")
    assert "MIIE" not in finding.code


def test_mask_secret_keeps_short_prefix():
    assert mask_secret("abcdefghijklmnop") == "abcd********"
    assert mask_secret("abc12") == "a********"


# ---------------------------------------------------------------- false positives


@pytest.mark.parametrize(
    "code",
    [
        'PASSWORD = ""',
        'PASSWORD = "changeme"',
        'API_KEY = "your_api_key_here"',
        'API_KEY = "<API_KEY>"',
        'SECRET = "${SECRET}"',
        'TOKEN = "xxxxxxxx"',
        'TOKEN = "GITHUB_TOKEN"',  # name of an env var, not the value
        'password = "password"',
        'PASSWORD_MIN_LENGTH = "8"',  # metadata about a password
        'TOKEN_URL = "https://example.com/oauth/token"',
        'password_field = "user_password"',
        'PASSWORD_PROMPT = "Enter password: "',
        'sort_key = "created_at"',  # "key" alone is not a secret
        'username = "admin"',
        'api_key = os.environ["API_KEY"]',  # loaded at runtime: the correct way
        'password = getpass.getpass()',
        'MAX_TOKENS = 1000',  # not a string
    ],
)
def test_non_secrets_are_not_flagged(find, code):
    assert find(code, "PY007") == []


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    "name, expected",
    [
        ("API_KEY", True), ("apiKey", True), ("db_password", True), ("GITHUB_TOKEN", True),
        ("private_key", True), ("client_secret", True),
        ("sort_key", False), ("PASSWORD_MIN_LENGTH", False), ("token_url", False), ("username", False),
    ],
)
def test_is_secret_name(name, expected):
    assert is_secret_name(name) is expected


def test_entropy_distinguishes_random_from_words():
    assert shannon_entropy(RANDOM_HEX) > 3.5
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("password") < 3.0


@pytest.mark.parametrize("value", ["", "abc", "changeme", "<token>", "your-password", "{{ secret }}", "DB_PASSWORD"])
def test_placeholders(value):
    assert is_placeholder(value)
