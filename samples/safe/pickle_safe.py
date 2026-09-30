"""Demo: session/config loading with data-only formats."""
import base64
import json

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    raw = base64.b64decode(request.cookies.get("session", ""))
    session = json.loads(raw)
    return session.get("name", "anonymous")


def load_config(path: str) -> dict:
    with open(path) as handle:
        return yaml.safe_load(handle)
