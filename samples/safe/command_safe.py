"""Demo: the network tool using argument lists (no shell)."""
import ipaddress
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


def ping_from_console() -> None:
    host = input("Host to ping: ")
    ipaddress.ip_address(host)  # raises ValueError for anything that is not an IP
    subprocess.run(["ping", "-c", "1", host], check=False)


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    if not domain.replace(".", "").replace("-", "").isalnum():
        abort(400)
    return subprocess.check_output(["nslookup", "--", domain])


def backup(folder: str) -> None:
    subprocess.run(["tar", "czf", "backup.tgz", "--", folder], check=True)
