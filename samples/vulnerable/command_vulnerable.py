"""Demo: a small network tool that builds shell commands from user input.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
Input such as "8.8.8.8; rm -rf ~" would run a second command.
"""
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


def ping_from_console() -> None:
    host = input("Host to ping: ")
    os.system("ping -c 1 " + host)  # PY003: command injection


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    output = subprocess.check_output(f"nslookup {domain}", shell=True)  # PY004
    return output


def backup(folder: str) -> None:
    subprocess.run("tar czf backup.tgz " + folder, shell=True)  # PY004 (origin unknown)
