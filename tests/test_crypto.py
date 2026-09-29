"""PY008 - weak hash algorithms and PY009 - insecure randomness."""

import pytest

from app.models.finding import Severity

# ---------------------------------------------------------------- PY008


@pytest.mark.parametrize(
    "code",
    [
        "import hashlib\nhashlib.md5(data).hexdigest()",
        "import hashlib\nhashlib.sha1(data)",
        "import hashlib\nhashlib.new('md5', data)",
        "import hashlib\nhashlib.new('SHA1')",
        "from hashlib import md5\nmd5(data)",
        "from cryptography.hazmat.primitives import hashes\nhashes.Hash(hashes.SHA1())",
        "from Crypto.Hash import MD5\nMD5.new(data)",
    ],
)
def test_weak_hash_is_medium(find, code):
    [finding] = find(code, "PY008")
    assert finding.severity is Severity.MEDIUM
    assert finding.cwe == "CWE-328"
    assert finding.category == "Weak Cryptography"


@pytest.mark.parametrize(
    "code",
    [
        "import hashlib\nhashlib.md5(password.encode()).hexdigest()",
        "import hashlib\nhashlib.sha1(user.password_hash + salt)",
        "import hashlib\nhashlib.md5(pwd)",
    ],
)
def test_weak_hash_of_password_is_high(find, code):
    [finding] = find(code, "PY008")
    assert finding.severity is Severity.HIGH
    assert "password" in finding.message


@pytest.mark.parametrize(
    "code",
    [
        "import hashlib\nhashlib.sha256(data)",
        "import hashlib\nhashlib.new('sha256', data)",
        "import hashlib\nhashlib.md5(data, usedforsecurity=False)",  # explicit non-security use
        "import hashlib\nhashlib.pbkdf2_hmac('sha256', password, salt, 600_000)",
        "md5(data)",  # not imported from hashlib
        "import hashlib\nhashlib.new(algorithm)",  # unknown algorithm: not reported
    ],
)
def test_safe_hashing_is_not_flagged(find, code):
    assert find(code, "PY008") == []


# ---------------------------------------------------------------- PY009


@pytest.mark.parametrize(
    "code",
    [
        "import random\ntoken = ''.join(random.choice(chars) for _ in range(32))",
        "import random\nreset_code = random.randint(100000, 999999)",
        "import random\nself.session_id = random.getrandbits(128)",
        "import random\ndata['otp'] = random.randint(0, 9999)",
        "import random\nsalt = random.randbytes(16)",
        "import random\nuser.create(password=random.choice(words))",
        "from random import choice\napi_key = choice(alphabet)",
    ],
)
def test_random_for_security_value_is_medium(find, code):
    [finding] = find(code, "PY009")
    assert finding.severity is Severity.MEDIUM
    assert finding.cwe == "CWE-330"
    assert finding.confidence == 0.75


def test_random_inside_security_function_is_lower_confidence(find):
    code = """
    import random

    def generate_token(length):
        return ''.join(random.choice(CHARS) for _ in range(length))
    """
    [finding] = find(code, "PY009")
    assert finding.confidence == 0.6
    assert "generate_token" in finding.message


@pytest.mark.parametrize(
    "code",
    [
        "import random\ndice = random.randint(1, 6)",
        "import random\nrandom.shuffle(playlist)",
        "import random\nsample = random.sample(population, 10)",
        "import random\nrandom.seed(42)",
        "import random\ncache_key = random.choice(keys)",  # 'key' alone is not security
        "import secrets\ntoken = secrets.token_urlsafe(32)",  # the correct API
        "import random\ntoken = random.SystemRandom().choice(chars)",  # CSPRNG
        "import numpy as np\ntoken = np.random.rand()",  # other library: out of scope
    ],
)
def test_non_security_random_is_not_flagged(find, code):
    assert find(code, "PY009") == []
