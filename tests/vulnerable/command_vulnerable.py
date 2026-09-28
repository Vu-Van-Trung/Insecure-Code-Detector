"""Intentionally vulnerable test fixture: PY003 / PY004. Never run this file."""
import os
import subprocess
import subprocess as sp
from os import system


def ping(host: str):
    os.system("ping -c 1 " + host)  # expect: PY003


def list_files():
    command = input("Command: ")
    system(command)  # expect: PY003


def archive(path: str):
    subprocess.run(f"tar czf backup.tgz {path}", shell=True)  # expect: PY004


def search(pattern: str):
    return sp.check_output("grep " + pattern + " log.txt", shell=True)  # expect: PY004


def disk_usage():
    return subprocess.getoutput(f"du -sh {os.getcwd()}")  # expect: PY004


def clear_screen():
    os.system("clear")  # expect: PY003
