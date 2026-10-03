"""Safe counterpart of web_vulnerable.py."""
import html
import os
import tempfile
import xml.sax
from pathlib import Path

import jinja2
import requests
from defusedxml import ElementTree as SafeElementTree
from flask import Flask, Markup, abort, escape, make_response, render_template, render_template_string, request
from flask import send_from_directory
from lxml import etree
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"
CONFIG_PATH = "/etc/myapp/config.json"
ALLOWED_FEEDS = {"news": "https://feeds.example.com/news.xml", "blog": "https://feeds.example.com/blog.xml"}
GREETING_TEMPLATE = "<h1>Hello {{ name }}</h1>"


# ----------------------------------------------------------------- paths

def load_config() -> str:
    with open(CONFIG_PATH) as handle:
        return handle.read()


def read_local(path: str) -> str:
    # Parameter of unknown origin: not reported (no inter-procedural analysis).
    return Path(path).read_text()


@app.route("/download")
def download():
    return send_from_directory(UPLOAD_DIR, request.args["file"])


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["document"]
    uploaded.save(os.path.join(UPLOAD_DIR, secure_filename(uploaded.filename)))
    return {"ok": True}


@app.route("/avatar")
def avatar():
    name = os.path.basename(request.args["name"])
    with open(os.path.join(UPLOAD_DIR, name), "rb") as handle:
        return handle.read()


# ----------------------------------------------------------------- URLs

@app.route("/feed")
def feed():
    feed_name = request.args.get("feed", "news")
    if feed_name not in ALLOWED_FEEDS:
        abort(404)
    return {"body": requests.get(ALLOWED_FEEDS[feed_name], timeout=5).text}


def health_check() -> int:
    return requests.get("https://status.example.com/health", timeout=5).status_code


# ----------------------------------------------------------------- XML

@app.route("/import", methods=["POST"])
def import_xml():
    return {"root": SafeElementTree.fromstring(request.data).tag}


def parse_trusted(data: bytes):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def sax_parser():
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    return parser


# ----------------------------------------------------------------- temp files

def write_report(data: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(data)
        return handle.name


# ----------------------------------------------------------------- HTML

@app.route("/hello")
def hello():
    return render_template_string(GREETING_TEMPLATE, name=request.args.get("name", ""))


@app.route("/profile")
def profile():
    return render_template("profile.html", name=request.args.get("name", ""))


@app.route("/greet")
def greet():
    name = escape(request.args.get("name", ""))
    return f"<p>Welcome, {name}!</p>"


@app.route("/search")
def search():
    query = html.escape(request.args.get("q", ""))
    return make_response("<ul><li>No results for " + query + "</li></ul>")


@app.route("/bio")
def bio():
    return {"bio": Markup("<b>{}</b>").format(request.form["bio"])}


def render_email(template_text: str, context: dict) -> str:
    env = jinja2.Environment(autoescape=jinja2.select_autoescape())
    return env.from_string(template_text).render(context)
