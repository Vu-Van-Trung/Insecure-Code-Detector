"""Demo: a small file-sharing web app.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
?name=../../etc/passwd reads any file, ?url=http://169.254.169.254/ reaches the
cloud metadata service, ?title={{7*7}} runs template code on the server.
"""
import tempfile

import requests
from flask import Flask, render_template_string, request
from lxml import etree

app = Flask(__name__)


@app.route("/files")
def read_file():
    with open("/srv/files/" + request.args["name"]) as handle:  # PY014: path traversal
        return {"content": handle.read()}


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    return {"body": requests.get(url, timeout=5).text}  # PY015: SSRF


@app.route("/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True)  # PY016: XXE
    return {"root": etree.fromstring(request.data, parser).tag}


@app.route("/page")
def page():
    title = request.args.get("title", "")
    return render_template_string(f"<h1>{title}</h1>")  # PY018: template injection


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<p>Hello, {name}!</p>"  # PY018: reflected XSS


def export_report(data: str) -> str:
    path = tempfile.mktemp(suffix=".csv")  # PY017: insecure temporary file
    with open(path, "w") as handle:
        handle.write(data)
    return path
