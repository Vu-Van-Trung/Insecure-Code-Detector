"""PY006 - unsafe YAML loading."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        "import yaml\nyaml.load(data)",
        "import yaml\nyaml.load(data, Loader=yaml.Loader)",
        "import yaml\nyaml.load(data, yaml.UnsafeLoader)",  # Loader passed positionally
        "import yaml\nyaml.unsafe_load(data)",
        "import yaml\nlist(yaml.load_all(stream))",
        "from yaml import load, Loader\nload(data, Loader=Loader)",
    ],
)
def test_unsafe_yaml_is_high(find, code):
    [finding] = find(code, "PY006")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-502"


@pytest.mark.parametrize(
    "code",
    [
        "import yaml\nyaml.full_load(data)",
        "import yaml\nyaml.load(data, Loader=yaml.FullLoader)",
    ],
)
def test_full_loader_is_medium(find, code):
    [finding] = find(code, "PY006")
    assert finding.severity is Severity.MEDIUM


def test_unknown_loader_is_medium_low_confidence(find):
    [finding] = find("import yaml\nyaml.load(data, Loader=get_loader())", "PY006")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.5


@pytest.mark.parametrize(
    "code",
    [
        "import yaml\nyaml.safe_load(data)",
        "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)",
        "import yaml\nyaml.load(data, Loader=yaml.CSafeLoader)",
        "from yaml import SafeLoader\nimport yaml\nyaml.load(data, SafeLoader)",
        "import yaml\nyaml.safe_load_all(stream)",
        "import yaml\nyaml.dump(obj)",
        "import json\njson.load(f)",
        "config.load(data)",
    ],
)
def test_safe_code_is_not_flagged(find, code):
    assert find(code, "PY006") == []
