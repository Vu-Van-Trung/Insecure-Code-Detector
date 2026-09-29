"""Intentionally vulnerable test fixture: PY011. Never run this file."""
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: str):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # expect: PY011
    return cursor.fetchone()


def find_by_name(cursor, name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # expect: PY011
    return cursor.fetchall()


def delete_order(cursor, order_id: str):
    cursor.execute("DELETE FROM orders WHERE id = %s" % order_id)  # expect: PY011


def search(cursor, keyword: str, sort: str):
    sql = "SELECT * FROM products WHERE name LIKE '%{}%'".format(keyword)
    sql += " ORDER BY " + sort
    cursor.execute(sql)  # expect: PY011
