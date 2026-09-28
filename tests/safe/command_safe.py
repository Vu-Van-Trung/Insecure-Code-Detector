"""Safe counterpart of command_vulnerable.py."""
import platform
import shutil
import subprocess


def ping(host: str) -> int:
    return subprocess.run(["ping", "-c", "1", host], check=False).returncode


def archive(path: str) -> None:
    subprocess.run(["tar", "czf", "backup.tgz", path], shell=False, check=True)


def search(pattern: str) -> bytes:
    return subprocess.check_output(["grep", "--", pattern, "log.txt"])


def os_name() -> str:
    return platform.system()


def copy(src: str, dst: str) -> None:
    shutil.copy(src, dst)
