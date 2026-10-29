"""Mẫu 1 - Website quản lý người dùng (Python/Flask) - BẢN CÓ LỖ HỔNG.

CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.

Lỗ hổng được cài sẵn:
    [1] Hardcoded Secret      (CWE-798) - secret_key, API key viết thẳng trong mã
    [2] SQL Injection         (CWE-89)  - đăng nhập và tìm kiếm ghép chuỗi SQL
    [3] Weak Cryptography     (CWE-328) - băm mật khẩu bằng MD5, không có salt

Chạy:  python app.py   ->  http://127.0.0.1:5000
"""
import hashlib
import os
import sqlite3

from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "..", "templates"))

# [LỖ HỔNG 1 - Hardcoded Secret] Ai đọc được mã nguồn (Git, bản build...) đều có
# khóa ký session -> giả mạo cookie đăng nhập; có API key -> gọi API quản trị.
app.secret_key = "flask-secret-key-2024-khong-duoc-lo"
ADMIN_API_KEY = "sk_live_51HxDemoAdminKey9f8e7d6c5b4a3"

SEED_USERS = [
    ("admin", "admin123", "Quản trị viên", "admin@demo.local", "admin"),
    ("nguyenvana", "matkhau1", "Nguyễn Văn A", "vana@demo.local", "user"),
    ("tranthib", "123456", "Trần Thị B", "thib@demo.local", "user"),
    ("levanc", "levanc@2024", "Lê Văn C", "vanc@demo.local", "user"),
]


def hash_password(password):

    return hashlib.md5(password.encode()).hexdigest()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("DROP TABLE IF EXISTS users")
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, "
            "full_name TEXT, email TEXT, role TEXT)"
        )
        conn.executemany(
            "INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
            [(u, hash_password(p), n, e, r) for u, p, n, e, r in SEED_USERS],
        )


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    executed_sql = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [LỖ HỔNG 2 - SQL Injection] Dữ liệu người dùng (source: request.form) được
        # ghép thẳng vào câu SQL rồi đưa vào execute() (sink).
        # Thử: username = admin' --     password = bất kỳ
        query = (
            "SELECT id, username, full_name, role FROM users "
            "WHERE username = '" + username + "' AND password_hash = '" + hash_password(password) + "'"
        )
        executed_sql = query
        try:
            user = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            user, error = None, f"Lỗi SQL: {exc}"
        if user:
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("users"))
        error = error or "Sai tên đăng nhập hoặc mật khẩu."
    return render_template("login.html", error=error, executed_sql=executed_sql, version="CÓ LỖ HỔNG")


@app.route("/users")
def users():
    if "user" not in session:
        return redirect(url_for("login"))
    keyword = request.args.get("q", "")

    # [LỖ HỔNG 2 - SQL Injection] f-string đưa từ khóa tìm kiếm vào câu SQL.
    # Thử: %' UNION SELECT id, username, password_hash, email, role FROM users --
    query = (
        f"SELECT id, username, full_name, email, role FROM users "
        f"WHERE username LIKE '%{keyword}%' OR full_name LIKE '%{keyword}%'"
    )
    error = None
    try:
        rows = get_db().execute(query).fetchall()
    except sqlite3.Error as exc:
        rows, error = [], f"Lỗi SQL: {exc}"
    return render_template("users.html", rows=rows, keyword=keyword, executed_sql=query, error=error,
                           version="CÓ LỖ HỔNG")


@app.route("/api/stats")
def stats():
    if request.headers.get("X-Api-Key") != ADMIN_API_KEY:
        return {"error": "unauthorized"}, 401
    count = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"total_users": count}


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    print("Tai khoan demo: admin / admin123")
    app.run(host="127.0.0.1", port=5000, debug=False)
