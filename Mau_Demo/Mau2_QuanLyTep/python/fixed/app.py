"""Mẫu 2 - Website quản lý tệp (Python/Flask) - BẢN ĐÃ SỬA.

Đối chiếu với ../vulnerable/app.py:
    [1] Path Traversal    -> secure_filename() làm sạch tên tệp (sanitizer) + kiểm tra đường dẫn
                             sau khi resolve vẫn nằm trong STORAGE_DIR; tải tệp bằng send_from_directory()
    [2] Command Injection -> bỏ hẳn shell: lấy thông tin tệp bằng os.stat() thuần Python

Luồng taint sau khi sửa:
    request.args["name"] -> secure_filename(...) [SANITIZER] -> name sạch -> open(path)
    => công cụ không còn báo PY014 vì taint đã bị cắt tại sanitizer.

Chạy:  python app.py   ->  http://127.0.0.1:5002
"""
import os
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = Path(BASE_DIR, "..", "..", "storage").resolve()

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "..", "templates"))


def safe_storage_path(raw_name):
    """Trả về đường dẫn an toàn bên trong STORAGE_DIR, hoặc 404."""
    name = secure_filename(raw_name)                 # "../secret/config.txt" -> "secret_config.txt"
    if not name:
        abort(404)
    path = (STORAGE_DIR / name).resolve()
    if not path.is_relative_to(STORAGE_DIR) or not path.is_file():   # chặn thêm lớp thứ hai
        abort(404)
    return name, path


@app.route("/")
def index():
    files = sorted(os.listdir(STORAGE_DIR))
    return render_template("index.html", files=files, version="ĐÃ SỬA")


@app.route("/view")
def view_file():
    # [ĐÃ SỬA 1] Tên tệp đi qua sanitizer trước khi chạm tới open().
    name, path = safe_storage_path(request.args.get("name", ""))
    with open(path, encoding="utf-8", errors="replace") as handle:
        content = handle.read()
    return render_template("view.html", name=name, path=str(path), content=content, version="ĐÃ SỬA")


@app.route("/download")
def download_file():
    # [ĐÃ SỬA 1] send_from_directory() tự từ chối đường dẫn thoát khỏi thư mục.
    name = secure_filename(request.args.get("name", ""))
    return send_from_directory(STORAGE_DIR, name, as_attachment=True)


@app.route("/info")
def file_info():
    # [ĐÃ SỬA 2] Không gọi shell nữa -> không còn chỗ để chèn lệnh.
    name, path = safe_storage_path(request.args.get("name", ""))
    stat = path.stat()
    output = (
        f"Tên tệp      : {name}\n"
        f"Kích thước   : {stat.st_size} byte\n"
        f"Sửa lần cuối : {datetime.fromtimestamp(stat.st_mtime):%d/%m/%Y %H:%M:%S}"
    )
    return render_template("info.html", name=name, command="os.stat() - không dùng shell", output=output,
                           version="ĐÃ SỬA")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
