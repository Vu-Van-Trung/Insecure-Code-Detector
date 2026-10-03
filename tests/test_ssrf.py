"""PY015 - server-side request forgery."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code, sink",
    [
        ("import requests\nrequests.get(request.args['url'])", "requests.get()"),
        ("import requests\nrequests.post(url=request.json['u'], data={})", "requests.post()"),
        ("import requests\nrequests.request('GET', request.args['url'])", "requests.request()"),
        ("import httpx\nu = request.args['u']\nhttpx.get('http://' + u)", "httpx.get()"),
        ("from urllib.request import urlopen\nurlopen(input())", "urllib.request.urlopen()"),
        ("import urllib.request\nurllib.request.Request(request.args['u'])", "urllib.request.Request()"),
        # Host is not fixed: "https://" + host lets the attacker choose the server.
        ("import requests\nrequests.get(f\"https://{request.args['host']}/api\")", "requests.get()"),
        # No "/" after the host: https://example.com@evil.com is possible.
        ("import requests\nrequests.get('https://example.com' + request.args['p'])", "requests.get()"),
    ],
)
def test_tainted_url_is_high(find, code, sink):
    [finding] = find(code, "PY015")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-918"
    assert finding.confidence == 0.95
    assert finding.sink == sink


@pytest.mark.parametrize(
    "code",
    [
        "import requests\nrequests.get(f\"https://api.example.com/users/{request.args['id']}\")",
        "import requests\nrequests.get('https://api.example.com/search?q=' + request.args['q'])",
        "import requests\nrequests.get('https://api.example.com/users/{}'.format(request.args['id']))",
        "import requests\nu = f\"https://api.example.com/u/{request.args['id']}\"\nrequests.get(u)",
    ],
)
def test_fixed_host_is_medium(find, code):
    [finding] = find(code, "PY015")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.6


@pytest.mark.parametrize(
    "code",
    [
        "import requests\nrequests.get('https://example.com')",
        "import requests\ndef fetch(url):\n    return requests.get(url)",  # unknown origin
        "import requests\nrequests.get('https://example.com', params={'q': request.args['q']})",
        "d = {}\nd.get(request.args['k'])",  # dict.get, not an HTTP call
        "import requests\nrequests.Session().get(request.args['u'])",  # receiver type not resolved (documented)
    ],
)
def test_safe_urls_are_not_flagged(find, code):
    assert find(code, "PY015") == []
