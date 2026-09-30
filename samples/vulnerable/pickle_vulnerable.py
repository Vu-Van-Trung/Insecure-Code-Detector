"""Demo: a session/config loader using pickle and unsafe YAML.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
A crafted cookie or config file can execute arbitrary code when loaded.
"""
import base64
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    raw = base64.b64decode(request.cookies.get("session", ""))
    session = pickle.loads(raw)  # PY005 (tainted: cookie)
    return session.get("name", "anonymous")


def load_config(path: str) -> dict:
    with open(path) as handle:
        return yaml.load(handle, Loader=yaml.Loader)  # PY006
