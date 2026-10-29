# Mã mẫu demo — Insecure-Code-Detector

> **Chỉ dùng để demo.** Các bản `vulnerable/` cố ý chứa lỗ hổng. Chỉ chạy trên máy cá nhân (127.0.0.1), không đưa lên mạng.

Mỗi mẫu có **3 bộ nguồn tương đương: Python, C#, Java**, mỗi bộ gồm bản `vulnerable` (có lỗ hổng) và `fixed` (đã sửa).

```
Mau_Demo\
├── Mau1_QuanLyNguoiDung                Website quản lý người dùng
│   ├── python   vulnerable\ fixed\ templates\     Flask + sqlite3          cổng 5000
│   ├── csharp   vulnerable\ fixed\                ASP.NET Core 8 + SQLite  cổng 5001
│   └── java     vulnerable\ fixed\                Spring Boot 3 + SQLite   cổng 5004
└── Mau2_QuanLyTep                      Website quản lý tệp
    ├── python   vulnerable\ fixed\ templates\     Flask                    cổng 5002
    │            demo_ast_taint.py                 minh họa AST + taint analysis
    ├── csharp   vulnerable\ fixed\                ASP.NET Core 8           cổng 5003
    ├── java     vulnerable\ fixed\                Spring Boot 3            cổng 5005
    ├── storage\                                   tệp được phép xem (dùng chung cho cả 3 ngôn ngữ)
    └── secret\config.txt                          tệp bí mật giả lập (nằm NGOÀI storage)
```

---

## 1. Quét bằng công cụ

Chạy từ thư mục gốc của repo (cần `.venv` có tree-sitter để quét C# và Java):

```powershell
$scan = ".venv\Scripts\python.exe main.py scan"
foreach ($m in "Mau1_QuanLyNguoiDung", "Mau2_QuanLyTep") {
  foreach ($lang in "python", "csharp", "java") {
    foreach ($v in "vulnerable", "fixed") {
      Write-Host "== $m\$lang\$v"
      Invoke-Expression "$scan Mau_Demo\$m\$lang\$v"
    }
  }
}
# Một dự án:  .venv\Scripts\python.exe main.py scan Mau_Demo\Mau1_QuanLyNguoiDung\java\vulnerable
# Báo cáo HTML: thêm  --format html -o bao_cao.html
```

Kết quả đã kiểm tra (12 dự án):

| Mẫu | Ngôn ngữ | Bản lỗi | Bản sửa |
|---|---|---|---|
| Mẫu 1 | Python | 5 (2 CRITICAL, 3 HIGH) | 0 |
| Mẫu 1 | C# | 5 (2 CRITICAL, 2 HIGH, 1 MEDIUM) | 0 |
| Mẫu 1 | Java | 5 (2 CRITICAL, 2 HIGH, 1 MEDIUM) | 0 |
| Mẫu 2 | Python | 3 (1 CRITICAL, 2 HIGH) | 0 |
| Mẫu 2 | C# | 1 (1 CRITICAL) — xem lưu ý | 0 |
| Mẫu 2 | Java | 1 (1 CRITICAL) — xem lưu ý | 0 |

### Mẫu 1 — chi tiết phát hiện

| Lỗ hổng | Python | C# | Java |
|---|---|---|---|
| Hardcoded Secret (CWE-798) | PY007 `app.secret_key`, `ADMIN_API_KEY` | CS008 `TokenSigningKey`, `AdminApiKey` | JV008 `TOKEN_SIGNING_KEY`, `ADMIN_API_KEY` |
| SQLi — đăng nhập (CWE-89) | PY011 `request.form -> username -> query -> .execute()` | CS002 `[FromForm] -> username -> sql -> new SqliteCommand()` | JV002 `@RequestParam -> username -> sql -> Statement.executeQuery()` |
| SQLi — tìm kiếm (CWE-89) | PY011 `request.args -> keyword -> query -> .execute()` | CS002 `[FromQuery] -> q -> cmd.CommandText` | JV002 `@RequestParam -> q -> sql -> Statement.executeQuery()` |
| Weak Crypto (CWE-328) | PY008 `hashlib.md5(password)` | CS005 `MD5.Create()` | JV005 `MessageDigest.getInstance("MD5")` |

### Mẫu 2 — chi tiết phát hiện

| Lỗ hổng | Python | C# | Java |
|---|---|---|---|
| Path Traversal — xem tệp (CWE-22) | PY014 `request.args -> name -> path -> open()` | *không báo* | *không báo* |
| Path Traversal — tải tệp (CWE-22) | PY014 `request.args -> name -> flask.send_file()` | *không báo* | *không báo* |
| Command Injection (CWE-78) | PY004 `request.args -> name -> path -> command -> subprocess.run()` | CS001 `[FromQuery] -> name -> path -> arguments -> ProcessStartInfo` | JV001 `@RequestParam -> name -> path -> command -> ProcessBuilder` |

> **Lưu ý:** công cụ hiện **chưa có luật Path Traversal cho C# và Java** (chỉ có PY014 cho Python, PH005 cho PHP). Lỗi Path Traversal ở bản C#/Java vẫn khai thác được nhưng không bị báo (false negative). Có thể dùng điểm này khi trình bày *hạn chế / hướng phát triển*: thêm luật CS/JV cho `File.ReadAllText`, `PhysicalFile`, `Files.readString`, `FileSystemResource`... với sanitizer `Path.GetFileName` / `File.getName`.

---

## 2. Mẫu 1 — Website quản lý người dùng

### Chạy

| Ngôn ngữ | Lệnh | Địa chỉ |
|---|---|---|
| Python | `cd Mau1_QuanLyNguoiDung\python\vulnerable` → `python app.py` | http://127.0.0.1:5000 |
| C# | `cd Mau1_QuanLyNguoiDung\csharp\vulnerable` → `dotnet run` | http://127.0.0.1:5001 |
| Java | `cd Mau1_QuanLyNguoiDung\java\vulnerable` → `mvn spring-boot:run` | http://127.0.0.1:5004 |

- Bản lỗi: tài khoản `admin / admin123`.
- Bản `fixed`: mật khẩu demo sinh ngẫu nhiên và in ra console, hoặc đặt trước bằng `$env:DEMO_PASSWORD="..."`.
- C#: lần build đầu tải gói `Microsoft.Data.Sqlite` từ NuGet. Java: cần JDK 17+ và Maven; lần đầu tải Spring Boot và `sqlite-jdbc`.
- Bản Python có giao diện HTML. Bản C# và Java dùng chung một trang có form đăng nhập/tìm kiếm, kết quả là JSON kèm trường `sql`.

### Kịch bản tấn công (bản lỗi) → kết quả (bản sửa)

Cả 3 ngôn ngữ đều hiển thị **câu SQL thực sự được thực thi**, nên khán giả thấy ngay payload đã thay đổi câu lệnh thế nào.

| # | Thao tác | Bản lỗi | Bản sửa |
|---|---|---|---|
| 1 | Đăng nhập: username `admin' --`, mật khẩu bất kỳ | Vào được với quyền admin. SQL trở thành `... WHERE username = 'admin' --' AND password_hash = ...` (phần kiểm tra mật khẩu bị biến thành chú thích) | "Sai tên đăng nhập hoặc mật khẩu" — `admin' --` chỉ là một tên người dùng không tồn tại |
| 2 | Tìm kiếm: `%' UNION SELECT id, username, password_hash, email, role FROM users --` | Cột "Họ tên" hiện **hash MD5 của mật khẩu**, ví dụ `0192023a7bbd73250516f069df18b500` = `admin123` (tra Google là ra) | Không có kết quả — chuỗi được tìm như văn bản bình thường |
| 3 | Tìm kiếm: `'` | Lỗi SQL lộ ra (dấu hiệu có SQLi) | Không lỗi |
| 4 | Mở mã nguồn | Thấy khóa ký session/token và API key → giả mạo phiên đăng nhập, gọi API quản trị | Secret đọc từ biến môi trường |

### Đối chiếu mã trước/sau

| Lỗ hổng | Python | C# | Java |
|---|---|---|---|
| Hardcoded Secret | `app.secret_key = "..."` → `os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)` | `const string TokenSigningKey = "..."` → `Environment.GetEnvironmentVariable(...)` hoặc `RandomNumberGenerator` | `static final String TOKEN_SIGNING_KEY = "..."` → `System.getenv(...)` hoặc `SecureRandom` |
| SQL Injection | `"... = '" + username + "'"` → `execute("... = ?", (username,))` | `"... = '" + username + "'"` → `@username` + `Parameters.AddWithValue` | `Statement` + nối chuỗi → `PreparedStatement` `?` + `setString` |
| SQLi (LIKE) | `f"LIKE '%{keyword}%'"` → `LIKE ?` với `f"%{keyword}%"` | `$"LIKE '%{q}%'"` → `LIKE @pattern` | `"LIKE '%" + q + "%'"` → `LIKE ?` |
| Weak Crypto | `hashlib.md5` → `hashlib.pbkdf2_hmac("sha256", ..., salt, 600_000)` + `hmac.compare_digest` | `MD5.Create()` → `Rfc2898DeriveBytes.Pbkdf2(..., SHA256)` + `CryptographicOperations.FixedTimeEquals` | `MessageDigest.getInstance("MD5")` → `PBKDF2WithHmacSHA256` + `MessageDigest.isEqual` |

---

## 3. Mẫu 2 — Website quản lý tệp

### Chạy

| Ngôn ngữ | Lệnh | Địa chỉ |
|---|---|---|
| Python | `cd Mau2_QuanLyTep\python\vulnerable` → `python app.py` | http://127.0.0.1:5002 |
| C# | `cd Mau2_QuanLyTep\csharp\vulnerable` → `dotnet run` | http://127.0.0.1:5003 |
| Java | `cd Mau2_QuanLyTep\java\vulnerable` → `mvn spring-boot:run` | http://127.0.0.1:5005 |

Phải chạy từ đúng thư mục `vulnerable`/`fixed`, vì bản C# và Java tìm kho tệp theo đường dẫn tương đối `..\..\storage`.

Bản Python có giao diện HTML; bản C#/Java có ô **"Gọi API với tên tệp tùy ý"** để nhập payload trực tiếp (không cần mã hóa URL).

### Kịch bản tấn công

| # | Payload (tên tệp) | Bản lỗi | Bản sửa |
|---|---|---|---|
| 1 | Xem: `../secret/config.txt` | Đọc được tệp bí mật nằm ngoài `storage` | 404 — chỉ giữ tên tệp (`secure_filename` / `Path.GetFileName` / `File.getName`), không tồn tại trong `storage` |
| 2 | Xem: `C:\Windows\win.ini` (C#, Java) | Đọc được — `Path.Combine` / `Path.resolve` bỏ qua thư mục gốc khi gặp đường dẫn tuyệt đối | 404 |
| 3 | Tải về: `../python/vulnerable/app.py`, `../csharp/vulnerable/Program.cs`, `../java/vulnerable/pom.xml` | Tải được mã nguồn ứng dụng | 404 |
| 4 | Thông tin: `bao_cao.txt" & whoami & echo "` | Kết quả `whoami` hiện trong output của lệnh `dir` | Không còn shell: dùng `os.stat()` / `FileInfo` / `Files.size()` |

Ở bản Python phải nhập payload vào URL: `/info?name=bao_cao.txt" %26 whoami %26 echo "` (`%26` là ký tự `&` đã mã hóa URL; Linux dùng `bao_cao.txt"; id; echo "`).

### Đối chiếu mã trước/sau

| Lỗ hổng | Python | C# | Java |
|---|---|---|---|
| Path Traversal | `open(os.path.join(STORAGE_DIR, name))` → `secure_filename()` + `resolve().is_relative_to()` + `send_from_directory()` | `File.ReadAllText(Path.Combine(dir, name))` → `Path.GetFileName` + `GetFullPath(...).StartsWith(dir)` | `Files.readString(dir.resolve(name))` → `new File(name).getName()` + `normalize().startsWith(dir)` |
| Command Injection | `subprocess.run("dir " + path, shell=True)` → `os.stat()` | `new ProcessStartInfo("cmd.exe", "/c dir ...")` → `new FileInfo(path)` | `new ProcessBuilder("cmd.exe", "/c", "dir ...")` → `Files.size()`, `Files.getLastModifiedTime()` |

### Minh họa AST và Taint Analysis

```powershell
cd Mau_Demo\Mau2_QuanLyTep\python
python demo_ast_taint.py --dump download_file   # 1) cây AST của một hàm
python demo_ast_taint.py                        # 2) lan truyền taint trên bản lỗi -> 3 cảnh báo
python demo_ast_taint.py fixed/app.py           # 3) bản sửa: taint bị cắt tại sanitizer -> 0 cảnh báo
```

Gợi ý trình bày:

1. **AST** — `request.args.get("name")` là nút `Call(func=Attribute(Attribute(Name('request'), 'args'), 'get'))`. Công cụ nhận diện *source* bằng cách so tên đầy đủ của nút này với danh sách trong `app/config/taint.json` (C#: `[FromQuery]` trong `taint_csharp.json`; Java: `@RequestParam` trong `taint_java.json`).
2. **Source → Propagation → Sink** — mỗi phép gán làm taint lan từ vế phải sang biến vế trái: `request.args -> name -> path -> command`. Khi biến nhiễm đi vào tham số của *sink* (`open`, `send_file`, `subprocess.run(shell=True)`) thì phát cảnh báo.
3. **Sanitizer** — ở bản sửa, `secure_filename()` cắt đứt taint nên `open(path)` nhận dữ liệu sạch. Script có bước "tóm tắt hàm" đơn giản để nhận ra `safe_storage_path()` là hàm làm sạch.
4. **Suppression** — hàm `parse_file()` của script có comment `# analyzer-ignore: PY014`: script dòng lệnh mở tệp do chính người chạy chọn nên cảnh báo được chủ động bỏ qua. Đây là ví dụ thật về tính năng ẩn cảnh báo của công cụ.
5. So sánh với kết quả `main.py scan`: công cụ in đúng các *taint path* giống script minh họa, và cùng một luồng dữ liệu được phát hiện trên cả Python, C#, Java.
