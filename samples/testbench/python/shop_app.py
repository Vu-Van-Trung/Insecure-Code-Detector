"""Testbench: Flask shop app with mixed vulnerabilities.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
All credentials are FAKE. Expected findings are marked with "# EXPECT: <rule>".
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess as sp
import xml.etree.ElementTree as ET

import requests
import yaml
from flask import Flask, request, send_file
from markupsafe import Markup

app = Flask(__name__)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9"  # EXPECT: PY007
STRIPE_KEY = "sk_live_51HxYzAbCdEfGhIjKlMnOpQrStUvWx"  # EXPECT: PY007


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    term = keyword.strip()
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    db = sqlite3.connect("shop.db")
    return {"rows": db.execute(query).fetchall()}  # EXPECT: PY011 (CRITICAL, taint q -> term -> query)


@app.route("/order/<order_id>")
def order(order_id):
    db = sqlite3.connect("shop.db")
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)  # EXPECT: PY011
    return {"order": cur.fetchone()}


@app.route("/admin/backup")
def backup():
    target = request.args["dir"]
    sp.call("tar czf /tmp/backup.tgz " + target, shell=True)  # EXPECT: PY004 (alias sp)
    os.system(f"chmod 600 {target}")  # EXPECT: PY003 (CRITICAL)
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))  # EXPECT: PY001 (CRITICAL)


@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    return {"cart": pickle.loads(request.data)}  # EXPECT: PY005


@app.route("/config/upload", methods=["POST"])
def upload_config():
    return {"cfg": yaml.load(request.data, Loader=yaml.Loader)}  # EXPECT: PY006


@app.route("/invoice")
def invoice():
    filename = request.args.get("file")
    full = os.path.join("/srv/invoices", filename)
    return send_file(full)  # EXPECT: PY014


@app.route("/webhook/test")
def webhook_test():
    callback = request.args.get("callback")
    resp = requests.post(callback, json={"ping": 1}, verify=False)  # EXPECT: PY015 + PY010
    return {"status": resp.status_code}


@app.route("/feed", methods=["POST"])
def feed():
    root = ET.fromstring(request.data)  # EXPECT: PY016 (MEDIUM, CWE-776)
    return {"items": len(root)}


@app.route("/banner")
def banner():
    text = request.args.get("text", "")
    return Markup("<div class='banner'>" + text + "</div>")  # EXPECT: PY018


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # EXPECT: PY008 (HIGH)


def new_reset_token() -> str:
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))  # EXPECT: PY009
    return token
