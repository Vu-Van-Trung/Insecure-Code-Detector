"""Mẫu 1 - Website quản lý người dùng (Python/Flask) - BẢN ĐÃ SỬA.

Đối chiếu với ../vulnerable/app.py:
    [1] Hardcoded Secret  -> đọc secret từ biến môi trường, không có thì sinh ngẫu nhiên
    [2] SQL Injection     -> truy vấn tham số hóa (placeholder ?), dữ liệu không thành mã SQL
    [3] Weak Cryptography -> PBKDF2-HMAC-SHA256 + salt ngẫu nhiên + so sánh thời gian hằng

Chạy:  python app.py   ->  http://127.0.0.1:5000
"""
import hashlib
import hmac
import os
import secrets
import sqlite3

from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
PBKDF2_ITERATIONS = 600_000

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "..", "templates"))

# [ĐÃ SỬA 1] Secret nằm ngoài mã nguồn (biến môi trường / secret manager).
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

SEED_USERS = [
    ("admin", "Quản trị viên", "admin@demo.local", "admin"),
    ("nguyenvana", "Nguyễn Văn A", "vana@demo.local", "user"),
    ("tranthib", "Trần Thị B", "thib@demo.local", "user"),
    ("levanc", "Lê Văn C", "vanc@demo.local", "user"),
]


def hash_password(password, salt):
   
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS).hex()


def verify_password(password, salt_hex, expected_hash):
    actual = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(actual, expected_hash)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # Mật khẩu demo không viết trong mã: lấy từ DEMO_PASSWORD hoặc sinh ngẫu nhiên.
    demo_password = os.environ.get("DEMO_PASSWORD") or secrets.token_urlsafe(9)
    with get_db() as conn:
        conn.execute("DROP TABLE IF EXISTS users")
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, "
            "salt TEXT, full_name TEXT, email TEXT, role TEXT)"
        )
        rows = []
        for username, full_name, email, role in SEED_USERS:
            salt = secrets.token_bytes(16)
            rows.append((username, hash_password(demo_password, salt), salt.hex(), full_name, email, role))
        conn.executemany(
            "INSERT INTO users (username, password_hash, salt, full_name, email, role) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
    return demo_password


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    executed_sql = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [ĐÃ SỬA 2] Câu SQL cố định, username đi riêng qua tham số.
        # Payload admin' -- giờ chỉ là một tên đăng nhập không tồn tại.
        query = "SELECT id, username, full_name, role, password_hash, salt FROM users WHERE username = ?"
        executed_sql = f"{query}    -- params: ({username!r},)"
        user = get_db().execute(query, (username,)).fetchone()
        if user and verify_password(password, user["salt"], user["password_hash"]):
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("users"))
        error = "Sai tên đăng nhập hoặc mật khẩu."
    return render_template("login.html", error=error, executed_sql=executed_sql, version="ĐÃ SỬA")


@app.route("/users")
def users():
    if "user" not in session:
        return redirect(url_for("login"))
    keyword = request.args.get("q", "")

    # [ĐÃ SỬA 2] Ký tự đại diện % được ghép vào GIÁ TRỊ tham số, không vào câu SQL.
    query = "SELECT id, username, full_name, email, role FROM users WHERE username LIKE ? OR full_name LIKE ?"
    pattern = f"%{keyword}%"
    rows = get_db().execute(query, (pattern, pattern)).fetchall()
    executed_sql = f"{query}    -- params: ({pattern!r}, {pattern!r})"
    return render_template("users.html", rows=rows, keyword=keyword, executed_sql=executed_sql, error=None,
                           version="ĐÃ SỬA")


@app.route("/api/stats")
def stats():
    provided = request.headers.get("X-Api-Key", "")
    if not ADMIN_API_KEY or not hmac.compare_digest(provided, ADMIN_API_KEY):
        return {"error": "unauthorized"}, 401
    count = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"total_users": count}


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    password = init_db()
    print(f"Tai khoan demo: admin / {password}   (dat bien DEMO_PASSWORD de co dinh)")
    app.run(host="127.0.0.1", port=5000, debug=False)
