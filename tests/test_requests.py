"""PY010 - TLS certificate verification disabled."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code, confidence",
    [
        ("import requests\nrequests.get(url, verify=False)", 0.9),
        ("import requests\nrequests.post(url, data=d, verify=False)", 0.9),
        ("import requests\nrequests.request('GET', url, verify=0)", 0.9),
        ("import httpx\nhttpx.Client(verify=False)", 0.9),
        ("from requests import get\nget(url, verify=False)", 0.9),
        ("session.get(url, verify=False)", 0.7),  # session type cannot be proven
        ("import ssl\nctx = ssl._create_unverified_context()", 0.85),
        ("import ssl\nctx.verify_mode = ssl.CERT_NONE", 0.8),
        ("from ssl import CERT_NONE\nctx.verify_mode = CERT_NONE", 0.8),
    ],
)
def test_disabled_verification_is_medium(find, code, confidence):
    [finding] = find(code, "PY010")
    assert finding.severity is Severity.MEDIUM
    assert finding.cwe == "CWE-295"
    assert finding.confidence == confidence


@pytest.mark.parametrize(
    "code",
    [
        "import requests\nrequests.get(url)",
        "import requests\nrequests.get(url, verify=True)",
        "import requests\nrequests.get(url, verify='/etc/ssl/ca.pem')",  # custom CA bundle
        "import requests\nrequests.get(url, verify=None)",  # None = use default
        "import requests\nrequests.get(url, verify=settings.VERIFY)",  # not provably False
        "import jwt\njwt.decode(token, verify=False)",  # different issue, not TLS
        "import ssl\nctx.verify_mode = ssl.CERT_REQUIRED",
        "import ssl\nctx = ssl.create_default_context()",
    ],
)
def test_verified_tls_is_not_flagged(find, code):
    assert find(code, "PY010") == []
