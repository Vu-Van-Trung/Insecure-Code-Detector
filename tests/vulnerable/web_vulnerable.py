"""Intentionally vulnerable test fixture: PY014-PY018. Never run this file."""
import os
import shutil
import tempfile
import urllib.request
import xml.sax
from pathlib import Path

import jinja2
import requests
from flask import Flask, Markup, make_response, render_template_string, request, send_file
from lxml import etree

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


# ----------------------------------------------------------------- PY014 path traversal

@app.route("/read")
def read_file():
    with open(request.args["name"]) as handle:  # expect: PY014
        return {"content": handle.read()}


@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)  # expect: PY014


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["document"]
    uploaded.save(os.path.join(UPLOAD_DIR, uploaded.filename))  # expect: PY014
    return {"ok": True}


@app.route("/delete", methods=["POST"])
def delete():
    target = request.form["path"]
    shutil.rmtree(target)  # expect: PY014
    (Path(UPLOAD_DIR) / request.form["name"]).unlink()  # expect: PY014
    return {"ok": True}


# ----------------------------------------------------------------- PY015 SSRF

@app.route("/preview")
def preview():
    url = request.args["url"]
    return {"body": requests.get(url, timeout=5).text}  # expect: PY015


@app.route("/proxy")
def proxy():
    target = request.json["target"]
    return {"body": urllib.request.urlopen(target).read().decode()}  # expect: PY015


@app.route("/user")
def user():
    user_id = request.args["id"]
    return requests.get(f"https://api.example.com/users/{user_id}", timeout=5).json()  # expect: PY015


# ----------------------------------------------------------------- PY016 XXE

@app.route("/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True)  # expect: PY016
    tree = etree.fromstring(request.data, parser)
    return {"root": tree.tag}


@app.route("/import2", methods=["POST"])
def import_xml_default_parser():
    return {"root": etree.fromstring(request.get_data()).tag}  # expect: PY016


def sax_parser():
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)  # expect: PY016
    return parser


# ----------------------------------------------------------------- PY017 insecure temp file

def write_report(data: str) -> str:
    path = tempfile.mktemp(suffix=".txt")  # expect: PY017
    with open(path, "w") as handle:
        handle.write(data)
    return path


# ----------------------------------------------------------------- PY018 XSS / SSTI

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")  # expect: PY018


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return f"<p>Welcome, {name}!</p>"  # expect: PY018


@app.route("/bio")
def bio():
    return {"bio": Markup(request.form["bio"])}  # expect: PY018


@app.route("/search")
def search():
    query = request.args.get("q", "")
    html = "<ul><li>No results for " + query + "</li></ul>"
    return make_response(html)  # expect: PY018


def render_email(template_text: str, context: dict) -> str:
    env = jinja2.Environment(autoescape=False)  # expect: PY018
    return env.from_string(template_text).render(context)
