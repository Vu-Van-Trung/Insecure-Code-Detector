"""Safe counterpart of sql_vulnerable.py: parameterized queries only."""
import sqlite3

ALLOWED_SORT_COLUMNS = {"name", "price"}


def get_user(conn: sqlite3.Connection, user_id: str):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


def find_by_name(cursor, name: str):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()


def delete_order(cursor, order_id: str):
    cursor.execute("DELETE FROM orders WHERE id = %s", (order_id,))


def list_products(cursor):
    cursor.execute("SELECT * FROM products ORDER BY name")
    return cursor.fetchall()
