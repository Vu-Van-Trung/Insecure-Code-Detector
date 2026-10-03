"""Demo: the file-sharing web app from web_vulnerable.py, fixed."""
import tempfile

import requests
from defusedxml import ElementTree
from flask import Flask, abort, render_template_string, request, send_from_directory
from markupsafe import escape

app = Flask(__name__)
PAGE_TEMPLATE = "<h1>{{ title }}</h1>"
PREVIEW_SOURCES = {"docs": "https://docs.example.com/", "blog": "https://blog.example.com/"}


@app.route("/files")
def read_file():
    # send_from_directory rejects paths that leave the directory.
    return send_from_directory("/srv/files", request.args["name"])


@app.route("/preview")
def preview():
    # The user chooses a key; the URL itself comes from an allowlist.
    source = request.args.get("source", "docs")
    if source not in PREVIEW_SOURCES:
        abort(404)
    return {"body": requests.get(PREVIEW_SOURCES[source], timeout=5).text}


@app.route("/import", methods=["POST"])
def import_xml():
    return {"root": ElementTree.fromstring(request.data).tag}


@app.route("/page")
def page():
    return render_template_string(PAGE_TEMPLATE, title=request.args.get("title", ""))


@app.route("/hello")
def hello():
    name = escape(request.args.get("name", ""))
    return f"<p>Hello, {name}!</p>"


def export_report(data: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as handle:
        handle.write(data)
        return handle.name
