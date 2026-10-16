"""Testbench: SAFE code that looks dangerous. A good analyzer reports nothing HIGH/CRITICAL here.

Each function mimics a risky pattern but is actually safe. Any finding above LOW is a false positive.
"""
import ast
import hashlib
import os
import random
import secrets
import shlex
import sqlite3
import subprocess
import tempfile

import yaml
from defusedxml import ElementTree as SafeET
from flask import Flask, request, send_from_directory
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY")
PASSWORD_PLACEHOLDER = "changeme"
DB_PASSWORD = "<your-password-here>"


class Model:
    def eval(self):
        return self


def parse_literal(text: str):
    return ast.literal_eval(text)


def train(model: Model):
    model.eval()


@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    return {"row": db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    subprocess.run(["ping", "-c", "1", host], check=False)
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)  # sanitized -> LOW at most
    return "ok"


@app.route("/download")
def download():
    name = secure_filename(request.args.get("name", ""))
    return send_from_directory("/srv/files", name)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return f"<p>Hello, {escape(name)}!</p>"


@app.route("/xml", methods=["POST"])
def xml():
    return {"tag": SafeET.fromstring(request.data).tag}


def load_config(path: str):
    with open(path) as fh:
        return yaml.safe_load(fh)


def file_checksum(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def roll_dice() -> int:
    return random.randint(1, 6)


def session_token() -> str:
    return secrets.token_urlsafe(32)


def scratch_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


def restart_service():
    os.system("systemctl restart nginx")  # constant command -> LOW
