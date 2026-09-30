"""Demo: the same lookups with parameterized queries."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cursor = get_db().cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchone())


def search_products(cursor, keyword: str):
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",))
    return cursor.fetchall()
