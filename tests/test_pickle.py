"""PY005 - unsafe deserialization."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        "import pickle\nobj = pickle.loads(message.body)",
        "import pickle\nwith open(path, 'rb') as f:\n    obj = pickle.load(f)",
        "import pickle\npickle.Unpickler(stream).load()",
        "import pickle as pk\npk.loads(blob)",
        "from pickle import loads\nloads(blob)",
        "import _pickle\n_pickle.loads(blob)",
        "import dill\ndill.loads(blob)",
        "import pandas as pd\ndf = pd.read_pickle(uploaded_path)",
    ],
)
def test_pickle_loading_is_high(find, code):
    [finding] = find(code, "PY005")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-502"
    assert finding.category == "Insecure Deserialization"


def test_pickle_of_constant_bytes_is_low(find):
    [finding] = find("import pickle\npickle.loads(b'\\x80\\x04K\\x01.')", "PY005")
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize(
    "code",
    [
        "import pickle\ndata = pickle.dumps(obj)",  # serializing is safe
        "import pickle\npickle.dump(obj, f)",
        "import json\njson.loads(body)",
        "loads(blob)",  # not imported from pickle
        "import pickle",  # importing alone is not a finding
    ],
)
def test_safe_code_is_not_flagged(find, code):
    assert find(code, "PY005") == []
