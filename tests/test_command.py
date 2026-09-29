"""PY003 - os.system()/os.popen() and PY004 - subprocess with shell=True."""

import pytest

from app.models.finding import Severity

# ---------------------------------------------------------------- PY003


@pytest.mark.parametrize(
    "code",
    [
        "import os\ndef run(command):\n    os.system(command)",  # parameter: origin unknown
        "import os\nos.system('ping ' + host)",
        "import os\nos.system(f'rm -rf {path}')",
        "import os as operating\noperating.system(cmd)",
        "from os import system\nsystem(cmd)",
        "from os import system as run_it\nrun_it(cmd)",
        "import os\nos.popen('cat ' + filename).read()",
    ],
)
def test_os_system_with_dynamic_command_is_high(find, code):
    [finding] = find(code, "PY003")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-78"
    assert finding.category == "Command Injection"


def test_os_system_with_constant_command_is_low(find):
    [finding] = find("import os\nos.system('ls')", "PY003")
    assert finding.severity is Severity.LOW
    assert finding.confidence == 0.6


@pytest.mark.parametrize(
    "code",
    [
        "import subprocess\nsubprocess.run(['ls', '-l', path])",
        "import os\nos.path.join(a, b)",
        "platform.system()",  # platform.system() returns the OS name
        "import platform\nplatform.system()",
        "system(cmd)",  # unknown function, not imported from os
    ],
)
def test_safe_code_is_not_flagged_by_py003(find, code):
    assert find(code, "PY003") == []


# ---------------------------------------------------------------- PY004


@pytest.mark.parametrize(
    "code",
    [
        "import subprocess\nsubprocess.run(command, shell=True)",
        "import subprocess\nsubprocess.call('ls ' + d, shell=True)",
        "import subprocess\nsubprocess.check_output(f'grep {p} f', shell=True)",
        "import subprocess\nsubprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)",
        "import subprocess as sp\nsp.check_call(cmd, shell=1)",
        "from subprocess import Popen\nPopen(args=cmd, shell=True)",
        "import subprocess\nsubprocess.getoutput(cmd)",  # always uses the shell
    ],
)
def test_shell_true_with_dynamic_command_is_high(find, code):
    [finding] = find(code, "PY004")
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 0.85
    assert finding.cwe == "CWE-78"


def test_shell_true_with_constant_command_is_low(find):
    [finding] = find("import subprocess\nsubprocess.run('ls -l', shell=True)", "PY004")
    assert finding.severity is Severity.LOW


def test_non_constant_shell_flag_is_medium(find):
    [finding] = find("import subprocess\nsubprocess.run(cmd, shell=use_shell)", "PY004")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.5


@pytest.mark.parametrize(
    "code",
    [
        "import subprocess\nsubprocess.run(['ls', path])",  # shell defaults to False
        "import subprocess\nsubprocess.run(cmd, shell=False)",
        "import subprocess\nsubprocess.run(cmd, shell=0)",
        "import subprocess\nsubprocess.run(cmd, **options)",  # cannot know: stay quiet
        "import subprocess\nsubprocess.run('ls', shell=use_shell)",  # constant command
        "runner.run(cmd, shell=True)",  # not subprocess
    ],
)
def test_safe_code_is_not_flagged_by_py004(find, code):
    assert find(code, "PY004") == []
