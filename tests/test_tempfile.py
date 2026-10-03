"""PY017 - insecure temporary file."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        "import tempfile\ntempfile.mktemp()",
        "import tempfile\npath = tempfile.mktemp(suffix='.txt', dir='/tmp')",
        "from tempfile import mktemp\nmktemp()",
        "import tempfile as tf\ntf.mktemp()",
    ],
)
def test_mktemp_is_medium(find, code):
    [finding] = find(code, "PY017")
    assert finding.severity is Severity.MEDIUM
    assert finding.cwe == "CWE-377"


def test_blacklist_duplicate_is_dropped(find):
    assert find("import tempfile\ntempfile.mktemp()", "PY012") == []


@pytest.mark.parametrize(
    "code",
    [
        "import tempfile\ntempfile.mkstemp()",
        "import tempfile\ntempfile.NamedTemporaryFile()",
        "import tempfile\ntempfile.TemporaryDirectory()",
        "def mktemp():\n    return 1\nmktemp()",
    ],
)
def test_safe_temp_files_are_not_flagged(find, code):
    assert find(code, "PY017") == []
