"""PY014 - path traversal."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code, sink",
    [
        ("open(request.args['f'])", "open()"),
        ("f = request.args.get('f')\nopen('/data/' + f)", "open()"),
        ("import os\nos.remove(os.path.join('/data', request.form['f']))", "os.remove()"),
        ("import io\nio.open(file=request.args['f'])", "io.open()"),
        ("import shutil\nshutil.copy('/tmp/a', request.args['dst'])", "shutil.copy()"),
        ("from flask import send_file\nsend_file(request.args['f'])", "flask.send_file()"),
        ("from pathlib import Path\nPath(request.args['f']).read_text()", "Path.read_text()"),
        ("from pathlib import Path\n(Path('/data') / request.args['f']).write_bytes(b'')", "Path.write_bytes()"),
        ("f = request.files['doc']\nf.save('/up/' + f.filename)", "FileStorage.save()"),
        ("import sys\nopen(sys.argv[1])", "open()"),
    ],
)
def test_tainted_path_is_high(find, code, sink):
    [finding] = find(code, "PY014")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-22"
    assert finding.confidence == 0.95
    assert finding.sink == sink
    assert finding.taint_path[-1] == sink


@pytest.mark.parametrize(
    "code",
    [
        "open('/etc/app.conf')",
        "def read(path):\n    return open(path).read()",  # unknown origin: too common to report
        "import os\nopen(os.path.join('/up', os.path.basename(request.args['f'])))",
        "from werkzeug.utils import secure_filename\nopen('/up/' + secure_filename(request.args['f']))",
        "f = request.files['doc']\nfrom werkzeug.utils import secure_filename\nf.save('/up/' + secure_filename(f.filename))",
        "from flask import send_from_directory\nsend_from_directory('/up', request.args['f'])",
        "model.save(request.args['name'])",  # not an uploaded file
        "import zipfile\nzipfile.ZipFile(request.files['z']).open('a.txt')",
        "def open(x):\n    return x\nopen(request.args['f'])",  # shadowed builtin
    ],
)
def test_safe_paths_are_not_flagged(find, code):
    assert find(code, "PY014") == []


def test_basename_does_not_hide_command_injection(find):
    """A path sanitizer only cleans data for file paths, not for other sinks."""
    code = "import os\nname = os.path.basename(input())\nos.system('cat ' + name)"
    assert find(code, "PY014") == []
    [finding] = find(code, "PY003")
    assert finding.severity is Severity.CRITICAL


def test_generic_sanitizer_is_low(find):
    [finding] = find("open('/data/%d.txt' % int(request.args['id']))", "PY014")
    assert finding.severity is Severity.LOW
    assert finding.confidence == 0.4
