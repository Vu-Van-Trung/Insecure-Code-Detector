"""PY016 - XML external entities."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code, severity, confidence",
    [
        ("from lxml import etree\netree.XMLParser(resolve_entities=True)", Severity.HIGH, 0.9),
        ("from lxml import etree\netree.XMLParser(no_network=False)", Severity.HIGH, 0.8),
        ("from lxml import etree\netree.XMLParser()", Severity.MEDIUM, 0.5),
        ("from lxml import etree\netree.fromstring(request.data)", Severity.HIGH, 0.95),
        ("import lxml.etree\nlxml.etree.parse(request.files['x'])", Severity.HIGH, 0.95),
        ("from lxml import etree\ndef f(data):\n    return etree.XML(data)", Severity.MEDIUM, 0.5),
        ("import xml.sax\np.setFeature(xml.sax.handler.feature_external_ges, True)", Severity.HIGH, 0.9),
        ("from xml.sax.handler import feature_external_pes\np.setFeature(feature_external_pes, 1)",
         Severity.HIGH, 0.9),
    ],
)
def test_xxe_is_reported(find, code, severity, confidence):
    [finding] = find(code, "PY016")
    assert finding.severity is severity
    assert finding.confidence == confidence
    assert finding.cwe == "CWE-611"


@pytest.mark.parametrize(
    "code",
    [
        "import xml.etree.ElementTree as ET\nET.fromstring(request.data)",
        "from xml.dom import minidom\nminidom.parseString(input())",
    ],
)
def test_stdlib_parser_with_untrusted_data_is_entity_expansion(find, code):
    [finding] = find(code, "PY016")
    assert finding.severity is Severity.MEDIUM
    assert finding.cwe == "CWE-776"


@pytest.mark.parametrize(
    "code",
    [
        "from lxml import etree\netree.XMLParser(resolve_entities=False)",
        "from lxml import etree\np = etree.XMLParser(resolve_entities=False)\netree.fromstring(request.data, p)",
        "from lxml import etree\netree.fromstring('<a/>')",
        "import defusedxml.ElementTree as ET\nET.fromstring(request.data)",
        "import xml.etree.ElementTree as ET\nET.parse('config.xml')",  # trusted local file
        "import xml.sax\np.setFeature(xml.sax.handler.feature_external_ges, False)",
        "import xml.sax\np.setFeature(xml.sax.handler.feature_namespaces, True)",
    ],
)
def test_safe_xml_is_not_flagged(find, code):
    assert find(code, "PY016") == []
