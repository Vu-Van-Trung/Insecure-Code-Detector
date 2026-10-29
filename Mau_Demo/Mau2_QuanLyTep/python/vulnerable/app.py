"""Mẫu 2 - Website quản lý tệp (Python/Flask) - BẢN CÓ LỖ HỔNG.

CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.

Lỗ hổng được cài sẵn:
    [1] Path Traversal     (CWE-22) - /view và /download ghép tên tệp từ người dùng vào đường dẫn
    [2] Command Injection  (CWE-78) - /info đưa tên tệp vào lệnh shell

Luồng taint (source -> propagation -> sink):
    request.args["name"]  ->  name  ->  path = os.path.join(STORAGE_DIR, name)  ->  open(path) / send_file(path)
    request.args["name"]  ->  name  ->  command = "dir " + ...name...           ->  subprocess.run(command, shell=True)

Chạy:  python app.py   ->  http://127.0.0.1:5002
"""
import os
import subprocess

from flask import Flask, render_template, request, send_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "..", "..", "storage")

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "..", "templates"))


@app.route("/")
def index():
    files = sorted(os.listdir(STORAGE_DIR))
    return render_template("index.html", files=files, version="CÓ LỖ HỔNG")


@app.route("/view")
def view_file():
    name = request.args.get("name", "")          # SOURCE: dữ liệu từ URL
    path = os.path.join(STORAGE_DIR, name)       # PROPAGATION: taint lan sang path

    # [LỖ HỔNG 1 - Path Traversal] Không kiểm tra "../" hay đường dẫn tuyệt đối.
    # Thử: /view?name=../secret/config.txt
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:   # SINK
            content = handle.read()
    except OSError as exc:
        content = f"Không đọc được tệp: {exc}"
    return render_template("view.html", name=name, path=os.path.normpath(path), content=content,
                           version="CÓ LỖ HỔNG")


@app.route("/download")
def download_file():
    name = request.args.get("name", "")
    # [LỖ HỔNG 1 - Path Traversal] Tải được mọi tệp mà tiến trình web đọc được.
    # Thử: /download?name=../python/vulnerable/app.py
    return send_file(os.path.join(STORAGE_DIR, name), as_attachment=True)   # SINK


@app.route("/info")
def file_info():
    name = request.args.get("name", "")
    path = os.path.join(STORAGE_DIR, name)
    listing = "dir " if os.name == "nt" else "ls -l "
    command = listing + '"' + path + '"'

    # [LỖ HỔNG 2 - Command Injection] Chuỗi lệnh chứa dữ liệu người dùng được chạy qua shell.
    # Thử (Windows): /info?name=bao_cao.txt" & whoami & echo "
    # Thử (Linux):   /info?name=bao_cao.txt"; id; echo "
    result = subprocess.run(command, shell=True, capture_output=True, text=True)   # SINK
    return render_template("info.html", name=name, command=command, output=result.stdout + result.stderr,
                           version="CÓ LỖ HỔNG")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
