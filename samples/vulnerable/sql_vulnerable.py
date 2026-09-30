"""Demo: user lookup that concatenates request data into SQL.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
id=1 OR 1=1 would return every user.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    query = "SELECT id, name FROM users WHERE id = " + user_id
    cursor = get_db().cursor()
    cursor.execute(query)  # PY011: SQL injection (tainted)
    return str(cursor.fetchone())


def search_products(cursor, keyword: str):
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")  # PY011
    return cursor.fetchall()
