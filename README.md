# Secure Code Analyzer

Công cụ **SAST (Static Application Security Testing)** cho mã nguồn **Python, Java, C# và PHP**, xây dựng trong đồ án
*"Xây dựng công cụ phân tích mã nguồn và phát hiện một số mẫu mã không an toàn"*.

Công cụ phân tích mã nguồn bằng **cây cú pháp** (module `ast` cho Python, **tree-sitter** cho Java, C# và PHP),
áp dụng một **Rule Engine** dạng plugin và **Taint Tracking** cơ bản để phát hiện các security anti-pattern.
Mã nguồn được phân tích **chỉ dưới dạng text/cây cú pháp**: không bao giờ bị import, biên dịch hay chạy.

| Ngôn ngữ | Đuôi file | Parser | Rule |
|---|---|---|---|
| Python | `.py` | `ast` (thư viện chuẩn) | PY001–PY018 |
| Java | `.java` | tree-sitter-java | JV001–JV012 |
| C# | `.cs` | tree-sitter-c-sharp | CS001–CS012 |
| PHP | `.php` | tree-sitter-php | PH001–PH013 |

---

## 1. Tổng quan

| Thành phần | Mô tả |
|---|---|
| Core Analyzer | Parser, Rule Engine, Taint Tracking (hỗ trợ inter-procedural nội bộ file). Phần Python chỉ dùng thư viện chuẩn; Java/C#/PHP dùng tree-sitter. Độc lập với Web UI |
| CLI | `python main.py scan <file_or_directory>` — dùng được trong CI/CD (exit code, SARIF output) |
| Web UI | FastAPI + Bootstrap 5 + Chart.js tại `http://127.0.0.1:8000` (có CSRF protection, hỗ trợ Basic Auth / API Key) |
| Report | JSON, CSV, HTML, SARIF (v2.1.0 cho GitHub Code Scanning) |

Không dùng AI/LLM để quyết định finding; không dùng Bandit/Semgrep/SonarQube/CodeQL làm engine.

## 2. Tính năng

- **55 security rules**: 18 cho Python, 12 cho Java, 12 cho C#, 13 cho PHP; mỗi rule có severity, confidence, CWE, recommendation.
- **AST analysis**: nhận diện `Call`, `Name`, `Attribute`, `Assign`, `Constant`, `BinOp`, `JoinedStr`,
  `Import`, `ImportFrom`, keyword arguments; giải quyết alias (`import subprocess as sp` → `subprocess.run`).
- **Taint tracking** (hỗ trợ inter-procedural trong file/class) cho cả 3 ngôn ngữ: `SOURCE → biến → biến → SINK`, hiển thị taint path
  (vd `@RequestParam -> name -> sql -> Statement.executeQuery()`, `[FromQuery] -> host -> Process.Start()`).
- **Sanitizer** cấu hình được (`shlex.quote`, `int`, ...). Luồng đã sanitize vẫn được báo ở mức LOW.
  **Sanitizer theo loại sink** (`secure_filename` cho path, `html.escape` cho HTML) hỗ trợ cho cả Python, Java và C#.
- **Severity theo ngữ cảnh**: cùng `os.system()` nhưng `input()` → CRITICAL, hằng số → LOW.
- **Whitelist** (file, rule, secret, comment `# analyzer-ignore`) và **Blacklist** (JSON).
- **Web UI**: upload nhiều file `.py`/`.java`/`.cs`/`.php`, upload **cả thư mục** (tối đa 1000 file nguồn, 20 MB) hoặc paste code (chọn ngôn ngữ), dashboard, biểu đồ,
  chi tiết finding, export report (JSON, CSV, HTML, SARIF).
- **Bảo mật của chính ứng dụng**: CSRF protection (token có chữ ký, bắt buộc cho form scan), tuỳ chọn xác thực HTTP Basic Auth & API Key,
  không thực thi code upload, không ghi file upload xuống đĩa, chống path traversal, giới hạn kích thước/số lượng/extension, CSP, escape toàn bộ output.
- **CI/CD Integration**: Xuất chuẩn SARIF v2.1.0 và template GitHub Actions (`.github/workflows/security-scan.yml`).
- **Logging** vào `logs/analyzer.log` (chỉ metadata, không log source code hay secret).
- **Kiểm thử tự động** bằng pytest; chạy `python -m pytest -q` để xem kết quả hiện tại.

## 3. Kiến trúc

```text
                +-------------------+      +---------------------+
  CLI  -------> |                   |      |  Rules (plugins)    |
  (main.py)     |   AnalyzerEngine  | ---> |  PY001 ... PY018    |
                |   (app/analyzer)  |      |  auto-discovered    |
  Web UI -----> |                   |      +---------------------+
  (FastAPI)     +---------+---------+
                          |
     languages.py   -> chọn ngôn ngữ theo đuôi file (.py / .java / .cs)
     Python:  parser.py (ast.parse) -> context.py -> taint.py -> visitor.py (ast.NodeVisitor)
     Java/C#: ts/adapters.py (tree-sitter -> mô hình chung: CallSite, khai báo, phép gán, method)
              -> ts/context.py (suy luận kiểu biến) -> ts/taint.py
     suppression.py -> # / // analyzer-ignore
                          |
                    ScanResult  ---> reports/ (JSON, CSV, HTML)
```

Pipeline cho mỗi file:

```text
parse -> rules (AST + taint) -> bỏ trùng lặp rule blacklist -> ghi đè severity
      -> suppression (whitelist / inline) -> ngưỡng min_severity / min_confidence
```

Cấu trúc thư mục:

```text
app/
  main.py              FastAPI web app
  cli.py               CLI (được gọi từ main.py ở thư mục gốc)
  storage.py           Lưu kết quả scan của web dạng JSON (data/scans/)
  logging_config.py    Cấu hình logging
  analyzer/            parser, context, visitor, engine, taint, suppression, languages, utils
  analyzer/ts/         adapters (Java, C#, PHP), context, taint cho tree-sitter
  rules/               base, registry, rule Python (15 file), java_rules.py, csharp_rules.py,
                       _ts_common.py (lớp cơ sở Java/C#), _keywords.py, _values.py (helper dùng chung)
  models/finding.py    Finding, ScanResult, Severity
  reports/             json_report, csv_report, html_report
  config/              rules.json, severity.json, taint.json (Python), taint_java.json, taint_csharp.json,
                       settings.py, loader.py
web/templates, web/static   Giao diện (Jinja2, Bootstrap, Chart.js, app.js)
tests/                 unit test + tests/vulnerable, tests/safe (fixture có marker # expect:)
samples/               mẫu demo vulnerable/ và safe/
whitelist.json, blacklist.json
```

**Cây kế thừa của rule** (`app/rules/base.py`, `_ts_common.py`): logic chấm điểm theo taint
(`tainted_finding`, `sanitized_finding`, `graded_finding`) nằm một chỗ trong `SecurityRule` và được dùng
chung cho cả Python, Java, C#. Phần giống nhau giữa các ngôn ngữ được tách thành mixin.

```text
SecurityRule                      metadata, create_finding, tainted/sanitized/graded_finding
├── CallRule                      chỉ xét ast.Call -> check_call(node, name, context)
│   ├── DangerousCallRule         PY001, PY002, PY003, PY005: chỉ khai báo target_functions + message
│   ├── TaintedSinkRule           PY014, PY015: chỉ báo khi tainted, có sanitizer theo loại sink
│   └── PY004, PY006, PY008, PY009, PY011, PY012, PY016, PY017, PY018
├── PY007, PY010, PY013           xét thêm node khác (Assign, Attribute, Import...)
└── TSRule                        Java/C#: check_file(ctx)
    ├── CommandRuleBase           JV001, CS001
    ├── SqlRuleBase               JV002, CS002
    ├── DeserializationRuleBase   JV003, CS003
    ├── CodeInjectionRuleBase     JV004, CS004
    ├── WeakAlgorithmRuleBase     JV005, JV006, CS005, CS006
    ├── InsecureRandomRuleBase    JV007, CS007   (+ InsecureRandomMixin, dùng chung với PY009)
    ├── HardcodedSecretRuleBase   JV008, CS008   (+ HardcodedSecretMixin, dùng chung với PY007)
    ├── OpenRedirectRuleBase      JV010, CS010
    └── TaintedSinkRuleBase       chỉ báo khi tainted, có sanitizer theo loại sink (bản Java/C# của TaintedSinkRule)
        ├── PathTraversalRuleBase JV011, CS011: chỉ khai báo bảng path_sinks
        └── JV012, CS012          XSS
```

**Thêm rule mới (ví dụ PY019)**: tạo `app/rules/xxx_rule.py` chứa lớp kế thừa một lớp cơ sở ở trên và gắn
`@register_rule`. Registry tự nạp mọi module trong `app/rules/` — **không cần sửa Analyzer Core**.

```python
@register_rule
class MyRule(CallRule):
    id = "PY019"; name = "..."; description = "..."; severity = Severity.HIGH
    cwe = "CWE-xxx"; category = "..."; recommendation = "..."

    def check_call(self, node, name, context):
        if name == "danger.func":
            yield self.create_finding(node, context, "message", confidence=0.8)
```

Rule chỉ cần cấm một hàm theo mức độ nguồn dữ liệu thì kế thừa `DangerousCallRule` và chỉ khai báo thuộc tính
(xem `eval_rule.py`, chỉ ~25 dòng).

## 4. Cài đặt

Yêu cầu Python **3.12+**.

```powershell
python -m venv .venv
.venv\Scripts\activate            # Windows (PowerShell)
# source .venv/bin/activate       # Linux / macOS
pip install -r requirements.txt
```

Phân tích Python chỉ cần thư viện chuẩn. Phân tích Java/C#/PHP cần `tree-sitter`, `tree-sitter-java`,
`tree-sitter-c-sharp`, `tree-sitter-php` (có bản dựng sẵn, không cần cài JDK hay .NET). Nếu thiếu, file Java/C# được báo lỗi
`LanguageUnavailable` còn file Python vẫn được scan bình thường.

## 5. Chạy Web

```powershell
python main.py web                  # http://127.0.0.1:8000
python main.py web --port 8080
# hoặc: uvicorn app.main:app
```

Luồng demo: **Home → Upload file / Paste Code → Start Scan → Dashboard → click finding → Export report**.

- Dashboard: Files/Lines scanned, Total findings, số lượng theo Critical/High/Medium/Low/Info,
  biểu đồ Chart.js, bảng finding có lọc theo severity và tìm kiếm.
- Finding detail: Rule ID, Rule Name, Severity, Confidence, CWE, File, Line, Column, Description,
  Vulnerable Code, Recommendation, Source/Sink và Taint Path.
- Export: nút JSON / CSV / HTML.
- JSON API: `POST /api/scan` (`{"code": "...", "filename": "a.py"}`), `GET /api/scan/{id}`,
  `GET /api/rules`, tài liệu tại `/api/docs`.

Giới hạn upload: chỉ `.py`, `.java`, `.cs`; tối đa 20 file, 1 MB/file, 5 MB/request. Khi paste code, chọn
ngôn ngữ trong ô *Language* (đuôi file được chỉnh tự động). JSON API nhận thêm `"language": "java" | "csharp"`.

## 6. Chạy CLI

```powershell
python main.py scan test.py
python main.py scan UserController.java
python main.py scan ./project            # quét cả .py, .java, .cs
python main.py scan ./project --format json -o report.json
python main.py scan ./project --format html -o report.html
python main.py scan ./project --format csv  -o report.csv
python main.py rules
```

| Tùy chọn | Ý nghĩa |
|---|---|
| `--format text\|json\|csv\|html` | Định dạng output (mặc định `text`) |
| `-o, --output FILE` | Ghi report ra file |
| `--whitelist FILE` / `--no-whitelist` | Chọn whitelist (mặc định `./whitelist.json` nếu có) |
| `--blacklist FILE` | Chọn blacklist (mặc định `blacklist.json` của công cụ) |
| `--disable PY009,PY013` | Tắt rule |
| `--min-severity MEDIUM` | Ẩn finding dưới mức này |
| `--min-confidence 0.7` | Ẩn finding có confidence thấp hơn |
| `--fail-on HIGH` | Chỉ trả exit code 1 khi có finding ≥ HIGH (dùng cho CI/CD) |

Exit code: `0` không có finding (vượt ngưỡng `--fail-on`), `1` có finding, `2` lỗi sử dụng/cấu hình hoặc lỗi phân tích file.

## 7. Danh sách rule

Xem đầy đủ bằng `python main.py rules`.

### Python

| ID | Tên | Severity mặc định | CWE | Ghi chú |
|---|---|---|---|---|
| PY001 | `eval()` | CRITICAL | CWE-95 | hằng số → LOW; bỏ qua `ast.literal_eval`, `model.eval()`, `eval` tự định nghĩa |
| PY002 | `exec()` | CRITICAL | CWE-95 | như PY001 |
| PY003 | `os.system()` / `os.popen()` | HIGH | CWE-78 | tainted → CRITICAL, hằng số → LOW |
| PY004 | `subprocess.*` với `shell=True`, `getoutput` | HIGH | CWE-78 | `shell=<biến>` → MEDIUM; `shell=False`/list → không báo |
| PY005 | `pickle`/`dill`/`pandas.read_pickle` load | HIGH | CWE-502 | `dump`/`dumps` không báo |
| PY006 | YAML loader không an toàn | HIGH | CWE-502 | `FullLoader` → MEDIUM; `SafeLoader`/`safe_load` → không báo |
| PY007 | Hardcoded secret | HIGH | CWE-798 | tên biến + entropy + định dạng key đã biết; bỏ qua placeholder; **giá trị bị che** |
| PY008 | MD5 / SHA-1 | MEDIUM | CWE-328 | hash password → HIGH; `usedforsecurity=False` → không báo |
| PY009 | `random` cho token/password/otp... | MEDIUM | CWE-330 | không báo `random` dùng cho game/mô phỏng |
| PY010 | `verify=False`, `ssl.CERT_NONE` | MEDIUM | CWE-295 | `verify="ca.pem"`, `verify=None` → không báo |
| PY011 | SQL nối chuỗi / f-string / `%` / `.format()` | HIGH | CWE-89 | tainted → CRITICAL; query tham số hóa → không báo |
| PY012 | Hàm trong `blacklist.json` | theo blacklist | theo blacklist | bỏ khi rule chuyên biệt đã báo cùng vị trí |
| PY013 | Import module trong `blacklist.json` | INFO | theo blacklist | nhắc review, không phải lỗ hổng |
| PY014 | Path traversal: `open()`, `send_file`, `os.remove`, `shutil.*`, `Path(...).read_text()`, `FileStorage.save()` | HIGH | CWE-22 | chỉ báo khi tainted; `secure_filename`/`basename`, `send_from_directory` → không báo |
| PY015 | SSRF: `requests.*`, `httpx.*`, `urlopen` với URL từ người dùng | HIGH | CWE-918 | chỉ báo khi tainted; host cố định (`https://api.x/{id}`) → MEDIUM |
| PY016 | XXE: lxml `resolve_entities=True`/`no_network=False`, parser mặc định, `setFeature(feature_external_ges, True)` | HIGH | CWE-611 | `XMLParser()` không đặt `resolve_entities=False` → MEDIUM; `xml.etree`/`minidom` + dữ liệu tainted → MEDIUM (CWE-776); `defusedxml` → không báo |
| PY017 | `tempfile.mktemp()`, `os.tempnam()` | MEDIUM | CWE-377 | `mkstemp`/`NamedTemporaryFile` → không báo |
| PY018 | XSS / template injection: `render_template_string`, `Markup`/`mark_safe`, `jinja2.Environment(autoescape=False)`, HTML trả về từ dữ liệu request | HIGH | CWE-79 | template source tainted → CRITICAL (CWE-1336); `escape()` trước khi ghép HTML → không báo |

### Java và C#

Hai ngôn ngữ dùng cùng một bộ logic (`_ts_common.py`) và cách chấm điểm giống Python:
severity tùy từng rule; nguồn tainted tới sink nguy hiểm thường là CRITICAL, open redirect là HIGH,
đi qua sanitizer → LOW.

| CWE | Java | C# | Ghi chú |
|---|---|---|---|
| CWE-78 | **JV001** `Runtime.exec`, `ProcessBuilder` | **CS001** `Process.Start`, `ProcessStartInfo` | chương trình cố định + tham số riêng, không qua shell → không báo |
| CWE-89 | **JV002** `executeQuery`, `prepareStatement`, JPA, JdbcTemplate | **CS002** `new SqlCommand`, `CommandText`, `FromSqlRaw`, Dapper | query tham số hóa, `FromSqlInterpolated` → không báo |
| CWE-502 | **JV003** `ObjectInputStream.readObject`, `XMLDecoder`, `XStream`, SnakeYAML | **CS003** `BinaryFormatter.Deserialize`, Json.NET `TypeNameHandling` | `System.Text.Json`, Gson → không báo |
| CWE-95 | **JV004** `ScriptEngine.eval`, SpEL (CWE-917), Groovy | **CS004** `CSharpScript.EvaluateAsync` | |
| CWE-328 | **JV005** `MessageDigest.getInstance("MD5"/"SHA-1")`, `DigestUtils.md5` | **CS005** `MD5.Create`, `SHA1`, `HashAlgorithm.Create("MD5")` | |
| CWE-327 | **JV006** `Cipher.getInstance("DES"/"RC4"/".../ECB/..."/"AES")` | **CS006** `DES`, `TripleDES`, `RC2`, `CipherMode.ECB` | |
| CWE-330 | **JV007** `java.util.Random`, `Math.random` cho token/otp... | **CS007** `System.Random` cho token/otp... | `SecureRandom`, `RandomNumberGenerator` → không báo |
| CWE-798 | **JV008** secret theo tên + entropy, key đã biết, `password=` trong JDBC URL | **CS008** như Java + `Password=` trong connection string, property initializer | giá trị bị che |
| CWE-295 | **JV009** TrustManager rỗng, `verify()` luôn `true`, `NoopHostnameVerifier` | **CS009** callback trả `true`, `DangerousAcceptAnyServerCertificateValidator` | |
| CWE-601 | **JV010** `sendRedirect`, Spring `RedirectView` nhận URL từ request | **CS010** ASP.NET `Response.Redirect`/`Redirect` nhận URL từ request | Input không tin cậy → HIGH; ưu tiên route cố định, allow-list host hoặc `LocalRedirect` |
| CWE-22 | **JV011** `new FileInputStream/FileReader/FileWriter...`, `Files.readAllBytes/write/delete...` (NIO), Commons IO `FileUtils.*`, `file.delete()`, `MultipartFile.transferTo` | **CS011** `File.ReadAllText/WriteAllText/Delete/Copy...`, `Directory.*`, `new FileStream`, `FileInfo.Delete/OpenRead...`, `PhysicalFile` | chỉ báo khi tainted → HIGH; `FilenameUtils.getName`, `new File(x).getName()`, `Path.GetFileName` → không báo |
| CWE-79 | **JV012** `response.getWriter()/getOutputStream()` `.print/println/write...`; handler `@GetMapping`... trả về chuỗi HTML ghép từ request | **CS012** `Response.Write/WriteAsync`, `new HtmlString`, `MvcHtmlString.Create`, `Html.Raw`, `Content(x, "text/html")`, `ContentResult` HTML | chỉ báo khi tainted → HIGH; `HtmlUtils.htmlEscape`, `Encode.forHtml`, `WebUtility.HtmlEncode`, `HtmlEncoder.Default.Encode` → không báo |

Chi tiết `JV010`/`CS010` giải thích luồng nguồn → đích, có ví dụ URL bị lợi dụng và khuyến nghị theo ngôn ngữ. Với C#,
`Response.Redirect(destination)` trong nhánh đã kiểm tra chính xác `Url.IsLocalUrl(destination)` được coi là nội bộ;
`LocalRedirect` cũng không bị báo. Các kiểm tra allow-list do dự án tự viết cần được khai báo rõ trong `sink_sanitizers.url`.

`JV011`/`CS011` và `JV012`/`CS012` giống PY014/PY018 của Python: đường dẫn file và nội dung response có mặt ở khắp
nơi, nên **chỉ luồng đi từ source** (`@RequestParam`, `request.getParameter()`, `[FromQuery]`, `Request.Query`...)
mới được báo; tham số không rõ nguồn hay hằng số thì không. Bản thân `new File(x)` / `new FileInfo(x)` không phải
sink (chưa mở file), nhờ đó mẫu `new File(name).getName()` không bị báo. `new StreamReader(...)` cũng không phải sink
vì thường nhận một stream (`new StreamReader(Request.Body)`). `PrintWriter` chỉ là sink XSS khi lấy từ
`response.getWriter()`; `Content(text)` không có Content-Type HTML là text/plain nên không báo.

```text
[HIGH] JV011 UserController_vulnerable.java:48:15 - Untrusted input from @RequestParam is used as a file path in Files.readAllBytes().
    Taint path: @RequestParam -> name -> Files.readAllBytes()
[HIGH] CS012 AccountController_vulnerable.cs:59:15 - Untrusted input from [FromQuery] is written to the HTML response by Content().
    Taint path: [FromQuery] -> name -> Content()
```

### PHP

Dùng chung adapter, taint và lớp cơ sở với Java/C#. Source là các biến toàn cục `$_GET`, `$_POST`,
`$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`; code ở cấp file (ngoài hàm, kiểu DVWA) cũng được phân tích.
Taint đi qua `.`, `.=`, chuỗi `"...$x..."`/`{$a['k']}`, heredoc và backtick.

| Rule | Phát hiện | Severity | CWE | Không báo / giảm mức |
|---|---|---|---|---|
| PH001 | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backtick | HIGH | CWE-78 | `escapeshellarg` → LOW; hằng số → LOW |
| PH002 | `mysqli_query`, `mysql_query`, `pg_query`..., `$db->query()/exec()/prepare()` | HIGH | CWE-89 | query hằng số/tham số hóa → không báo; `intval`/`(int)`/escape → LOW |
| PH003 | `eval`, `assert(string)`, `create_function`, `preg_replace` `/e` | CRITICAL | CWE-95 | |
| PH004 | `include`/`require` đường dẫn động | HIGH | CWE-98 | `__DIR__ . '/x.php'`, `$map['key']` → không báo; biến không rõ nguồn → MEDIUM |
| PH005 | `fopen`, `file_get_contents`, `readfile`, `unlink`, `move_uploaded_file`... với path tainted | HIGH | CWE-22 | `basename`/`realpath` → không báo |
| PH006 | XSS: `echo`/`print`/`printf` dữ liệu tainted; chuỗi HTML ghép từ dữ liệu tainted (`$html .= '<pre>' . $_GET['x']`) | HIGH | CWE-79 | `htmlspecialchars`/`htmlentities` → không báo |
| PH007 | `md5`, `sha1`, `hash('md5'...)` | MEDIUM | CWE-328 | hash mật khẩu → HIGH |
| PH008 | `rand`, `mt_rand`, `uniqid`, `str_shuffle`... cho token/session/otp | MEDIUM | CWE-330 | `rand(1, 6)` cho game → không báo |
| PH009 | Hardcoded secret: biến, `$cfg['db_password']`, `define()`, `'pass' => '...'`, property | HIGH | CWE-798 | placeholder → không báo |
| PH010 | `unserialize()` | HIGH | CWE-502 | `['allowed_classes' => false]` → không báo |
| PH011 | `CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST` tắt, `'verify_peer' => false` | MEDIUM | CWE-295 | |
| PH012 | `header('Location: ' . $_GET[...])` | MEDIUM | CWE-601 | header khác → CWE-113 |
| PH013 | `move_uploaded_file` giữ tên file client gửi (`$_FILES[..]['name']`) | HIGH | CWE-434 | tên file do server sinh → không báo |

### Severity và Confidence

- Severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` — xác định theo **rule và ngữ cảnh**, không phải
  mọi finding đều CRITICAL. Có thể ghi đè theo rule trong `app/config/severity.json`:
  `{"overrides": {"PY009": "LOW"}}`.
- Confidence `0.0 → 1.0` là **mức tin cậy heuristic của analyzer, không phải xác suất toán học chính xác**:

| Confidence | Khi nào |
|---|---|
| 0.95 | Taint tracking chứng minh dữ liệu từ source tới sink |
| 0.80–0.90 | API nguy hiểm với argument động |
| 0.50–0.75 | Dựa vào tên biến / ngữ cảnh |
| 0.40 | Dữ liệu đi qua sanitizer mà analyzer không chứng minh được là đủ |

## 8. Whitelist

> **Whitelist chỉ ẩn (suppress) cảnh báo, KHÔNG làm cho mã nguồn trở nên an toàn.**
> Finding bị ẩn vẫn được đếm và liệt kê trong mục *Suppressed* của report.

Comment trong code (cùng dòng, hoặc dòng ngay phía trên):

```python
# analyzer-ignore: PY001
result = eval(expression)

os.system(cmd)  # analyzer-ignore: PY003, PY004
```

```java
Runtime.getRuntime().exec(cmd); // analyzer-ignore: JV001
/* analyzer-ignore: CS002 */
```

`# analyzer-ignore` không kèm ID sẽ ẩn mọi rule trên dòng đó. Comment được đọc bằng `tokenize`, nên
chuỗi `"# analyzer-ignore"` nằm trong string không có tác dụng.

File `whitelist.json` (của dự án được scan):

```json
{
    "files": ["tests/test_*.py", "legacy/*"],
    "disabled_rules": ["PY009"],
    "allowed_secrets": ["test_[0-9a-f]{32}"]
}
```

- `files`: glob pattern, file khớp sẽ không được scan (đếm trong *Skipped files*).
- `disabled_rules`: tắt rule.
- `allowed_secrets`: regex các giá trị không phải secret thật (dành cho PY007).

## 9. Blacklist

`blacklist.json` cho phép khai báo hàm/module nguy hiểm **không cần sửa code** (rule PY012/PY013).
Mỗi mục là tên (dạng ngắn như đề bài) hoặc object có `severity`, `cwe`, `reason`:

```json
{
    "dangerous_functions": [
        "eval", "exec", "os.system",
        {"name": "marshal.loads", "severity": "HIGH", "cwe": "CWE-502", "reason": "marshal is not secure"}
    ],
    "dangerous_modules": ["pickle", {"name": "telnetlib", "severity": "LOW", "cwe": "CWE-319"}]
}
```

Khi rule chuyên biệt (vd PY001 cho `eval`) đã báo cùng vị trí, finding chung của PY012 bị bỏ để tránh
trùng lặp. Nếu tắt PY001, PY012 vẫn đảm bảo `eval` được báo.

## 10. Taint analysis

Sources và sanitizers khai báo trong `app/config/taint.json` (Python), `taint_java.json` và
`taint_csharp.json`. Ví dụ với Python:

```json
{
    "sources": {
        "functions": ["input", "os.getenv", "sys.stdin.read", "request.get_json"],
        "attributes": ["request.args", "request.form", "request.json", "request.cookies", "sys.argv", "os.environ"]
    },
    "sanitizers": ["shlex.quote", "int", "float"],
    "sink_sanitizers": {
        "path": ["os.path.basename", "werkzeug.utils.secure_filename"],
        "html": ["html.escape", "markupsafe.escape"],
        "url": []
    }
}
```

Sinks là argument nguy hiểm của các rule PY001–PY005, PY011 và PY014–PY018 (`eval`, `exec`, `os.system`,
`subprocess.*`, `pickle.loads`, `cursor.execute`, `open`, `requests.get`, `render_template_string`, ...). Mỗi biểu thức được gắn một nhãn:

- **TAINTED** — chứa dữ liệu từ source (lưu source và đường đi qua các biến);
- **STATIC** — cố định trong code (`cmd = "ls"; os.system(cmd)` → LOW);
- **UNKNOWN** — tham số hàm, kết quả lời gọi hàm bất kỳ.

Ví dụ:

```python
command = input("Command: ")
os.system(command)
```

```text
[CRITICAL] PY003 app.py:2:0 - Untrusted input from input() reaches os.system().
    Source: input()  Sink: os.system()
    Taint path: input() -> command -> os.system()
```

Với Java/C#, có thể cấu hình `sink_sanitizers.url` trong file taint tương ứng để khai báo helper của dự án mà
**trả về URL đã xác thực theo allow-list**. Ghép mục này vào cấu hình hiện có, giữ nguyên sources và sanitizer khác:

```json
"url": ["RedirectPolicy.onlyAllowed"]
```

Khi helper nhận input tainted và trả giá trị đã kiểm tra, luồng được đánh dấu an toàn cho redirect. Chỉ khai báo
helper thực hiện allow-list; mã hóa URL hoặc kiểm tra cú pháp đơn thuần không ngăn chuyển hướng tới máy chủ ngoài.

Với Java/C#, source gồm lời gọi (`request.getParameter()`, `Console.ReadLine()`, `System.getenv()`),
thành viên (`Request.Query`, `Request.Form`), **tham số có annotation/attribute** (`@RequestParam`,
`@PathVariable`, `@RequestPart`, `[FromQuery]`, `[FromBody]`...), tên file upload
(`MultipartFile.getOriginalFilename()`) và `args` của `main`. Sanitizer mặc định:
`Integer.parseInt`, `int.Parse`, `Guid.Parse`... Sanitizer theo loại sink (`sink_sanitizers`):

| Loại sink | Java | C# | Rule dùng |
|---|---|---|---|
| `path` | `FilenameUtils.getName/getBaseName`, `File.getName`, `Path.getFileName` | `Path.GetFileName`, `Path.GetFileNameWithoutExtension` | JV011, CS011 |
| `html` | `HtmlUtils.htmlEscape`, `StringEscapeUtils.escapeHtml4`, `Encode.forHtml*`, `ESAPI.encoder().encodeForHTML` | `HttpUtility.HtmlEncode`, `WebUtility.HtmlEncode`, `HtmlEncoder.Default.Encode`, `AntiXssEncoder.HtmlEncode` | JV012, CS012 |
| `url` | (helper allow-list của dự án) | (helper allow-list của dự án) | JV010, CS010 |
| `sql`, `command` | `ESAPI.encoder().encodeForSQL` | — | JV001/JV002, CS001/CS002 (vẫn báo LOW) |

Sanitizer chỉ làm sạch cho đúng loại sink của nó: `FilenameUtils.getName(x)` an toàn cho JV011 nhưng
`Runtime.exec("cat " + name)` vẫn CRITICAL; `HtmlUtils.htmlEscape(x)` không làm sạch câu SQL.

Với PHP, source là `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` (`app/config/taint_php.json`).
Sanitizer: `intval`, `(int)`, `htmlspecialchars`, `mysqli_real_escape_string`, `escapeshellarg`, `basename`...

```text
[CRITICAL] CS001 AccountController.cs:27:8 - Untrusted input from [FromQuery] reaches Process.Start().
    Source: [FromQuery]  Sink: Process.Start()
    Taint path: [FromQuery] -> host -> Process.Start()
```

Taint được lan truyền qua nối chuỗi, f-string / `$"..."`, `%`, `.format()` / `String.format`, method call (`.strip()`, `.get()`),
list/dict, comprehension, `for`, `with`, unpack tuple, `+=`, `self.x`. Phép gán trong nhánh
`if`/`for`/`try` chỉ **thêm** taint, không xóa (xấp xỉ bảo thủ).

**Sanitizer**: `source → shlex.quote() → sink` vẫn được báo ở mức **LOW, confidence 0.4**, kèm ghi chú
*"the analyzer cannot prove this sanitizer is sufficient"* — vì công cụ không chứng minh được sanitizer
phù hợp với sink (vd `shlex.quote` không chống được SQL injection).

**Sanitizer theo loại sink** (`sink_sanitizers`): hàm chỉ làm sạch dữ liệu cho một loại sink. Ví dụ
`os.path.basename(input())` an toàn cho `open()` (PY014 không báo) nhưng `os.system("cat " + name)` vẫn là
CRITICAL (PY003). Khi ghép nhiều phần, kết quả chỉ an toàn nếu mọi phần tainted đều an toàn.
`html.escape` không được chấp nhận cho template source (PY018), vì `{{ 7*7 }}` không chứa ký tự HTML.

## 11. Testing

```powershell
python -m pytest -q                     # toàn bộ 851 test
python -m pytest tests/test_taint.py -v # một nhóm
```

| Nhóm | File |
|---|---|
| Rule Python (vulnerable / safe / false positive) | `test_eval.py`, `test_exec.py`, `test_command.py`, `test_pickle.py`, `test_yaml.py`, `test_secret.py`, `test_crypto.py`, `test_requests.py`, `test_sql.py`, `test_path.py`, `test_ssrf.py`, `test_xml.py`, `test_tempfile.py`, `test_xss.py` |
| Rule Java / C# / PHP (kèm taint) | `test_java.py`, `test_csharp.py`, `test_php.py` |
| Taint tracking | `test_taint.py` |
| Whitelist / Blacklist / Severity | `test_whitelist.py`, `test_blacklist.py`, `test_severity.py` |
| Core | `test_parser.py`, `test_utils.py`, `test_registry.py`, `test_engine.py`, `test_models.py` |
| CLI / Report / Web | `test_cli.py`, `test_reports.py`, `test_web.py` |
| Fixture & sample | `test_fixtures.py` (so khớp chính xác marker `# expect: PYxxx` trong `tests/vulnerable/`), `test_samples.py` |

File tạm của test nằm trong `.tmp/` của project (không dùng thư mục temp của hệ thống).

## 12. Ví dụ output

```text
$ python main.py scan samples/vulnerable/sql_vulnerable.py
Secure Code Analyzer v1.1

Scanning: samples/vulnerable/sql_vulnerable.py

Files scanned: 1
Lines scanned: 28

CRITICAL: 1
HIGH:     1
MEDIUM:   0
LOW:      0
INFO:     0

Total findings: 2

Findings:
  [CRITICAL] PY011 samples/vulnerable/sql_vulnerable.py:22:4 - Untrusted input from request.args is used to build the SQL query passed to cursor.execute(). (CWE-89, confidence 95%)
      cursor.execute(query)  # PY011: SQL injection (tainted)
      Source: request.args  Sink: cursor.execute()
      Taint path: request.args -> user_id -> query -> cursor.execute()
  [HIGH] PY011 samples/vulnerable/sql_vulnerable.py:27:4 - SQL query built from dynamic values is passed to cursor.execute(). (CWE-89, confidence 85%)
      cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")  # PY011
```

Khi file không parse được:

```text
Errors (1):
  bad.py:12 - SyntaxError: Python SyntaxError: invalid syntax
```

Các file trong `samples/vulnerable/` **cố ý chứa lỗ hổng**, chỉ để kiểm thử cục bộ; không chạy và không
triển khai chúng. Mọi secret trong đó là giá trị giả.

## 13. Hạn chế

- **Phân tích liên hàm xuyên file/module**: Đã hỗ trợ phân tích liên hàm (inter-procedural) trong cùng một file/class (lan truyền taint qua tham số hàm gọi và giá trị trả về của hàm helper); tuy nhiên chưa phân tích đồ thị gọi (call graph) xuyên qua nhiều file/module khác nhau.
- Nhánh điều kiện được hợp nhất bảo thủ; không phân tích đường đi (path-sensitive).
- Container được theo dõi như một khối (`d["a"] = tainted` → cả `d` bị taint).
- Chỉ nhận diện API theo tên đầy đủ; đối tượng mà kiểu không suy ra được (vd `session.get(..., verify=False)`)
  được xử lý bằng heuristic với confidence thấp hơn.
- PY007 dựa vào tên biến và entropy nên vẫn có thể bỏ sót hoặc báo nhầm.
- PY014/PY015 chỉ báo khi chứng minh được dữ liệu đến từ source (đường dẫn/URL không rõ nguồn quá phổ biến).
  Kiểm tra kiểu `Path(base, name).resolve().is_relative_to(base)` hay allowlist host không được nhận diện là
  sanitizer — dùng `# analyzer-ignore: PY014` sau khi review. Method của đối tượng không suy ra được kiểu
  (`requests.Session().get(url)`) không được kiểm tra.
- PY018 chỉ phân tích code Python; không đọc file template (`{{ x|safe }}`, `{% autoescape false %}`).
- Java/C#: không phân giải kiểu đầy đủ như trình biên dịch (không đọc `import`/`using` hay thư viện);
  kiểu của biến được suy từ khai báo và `new T()`, nên đối tượng truyền qua nhiều lớp có thể bị bỏ sót.
  Không phân tích lambda, generic phức tạp, LINQ, annotation cấu hình (Spring Security...).
- JV011/CS011 chỉ báo khi chứng minh được dữ liệu đến từ source; kiểm tra kiểu
  `base.resolve(name).normalize().startsWith(base)` / `GetFullPath(...).StartsWith(baseDir)` không được nhận diện là
  sanitizer — dùng `// analyzer-ignore: JV011` sau khi review. `Files.copy` chỉ xét đường dẫn đích.
- JV012/CS012 không đọc template (JSP, Thymeleaf `th:utext`, Razor `.cshtml` với `@Html.Raw`); handler Spring chỉ bị
  báo khi giá trị trả về chứa thẻ HTML cố định trong code (`"<h1>" + name`), không báo `return name;`.
- Java/C#/PHP yêu cầu UTF-8; file có lỗi cú pháp không được phân tích (báo *Scan failed*).
- PHP: không theo dõi dữ liệu qua `include` giữa các file (vd DVWA gán `$file = $_GET['page']` ở `low.php`
  rồi `include($file)` ở `index.php`: chỉ báo MEDIUM), không theo dõi `$_SESSION` và dữ liệu đọc từ database
  (stored XSS), không phân tích JavaScript trong trang.
- Bootstrap/Chart.js tải từ CDN (cần Internet khi mở trang).
- Static analysis có thể có false positive và false negative — mọi finding cần được review.

## 14. Hướng phát triển

- Phân tích liên hàm xuyên các module và package lớn (inter-module call graph), phân tích path-sensitive.
- Thêm ngôn ngữ khác qua tree-sitter (JavaScript/TypeScript, PHP, Go): chỉ cần một adapter và bộ rule mới.
- Phân giải kiểu Java/C# đầy đủ hơn (đọc `import`/`using`, kiểu trả về của method).
- Thêm rule: JWT không verify, `assert` dùng cho kiểm tra bảo mật, zip slip (`extractall`), open redirect;
  quét file template Jinja2/Django (`|safe`, `autoescape false`).
- Lưu lịch sử scan bằng SQLite + SQLAlchemy, so sánh giữa các lần scan.
- Xuất PDF; tự host Bootstrap/Chart.js kèm Subresource Integrity để chạy offline.

## 15. Phạm vi và vận hành các tính năng bổ sung

### Phân tích liên hàm

Analyzer phân tích lời gọi cục bộ theo từng bộ đối số, truyền taint qua tham số
và giá trị trả về. Các lần gọi với dữ liệu sạch và dữ liệu không tin cậy không
dùng chung một return summary. Nhãn tại sink được gộp bảo thủ từ các ngữ cảnh gọi.

- Python: hỗ trợ hàm gọi trực tiếp bằng tên, hàm lồng, đối số theo tên,
  giá trị mặc định và lan truyền bảo thủ qua `*args` / `**kwargs`.
- Java/C#: đối chiếu lớp chứa method, receiver và số tham số; hỗ trợ return trong
  block và expression-bodied method của C#.
- Giới hạn: tối đa 32 hàm đang mở rộng và 2.000 lần mở rộng trong một file.
  Đệ quy quay lại hàm đang phân tích, lời gọi không xác định hoặc vượt giới hạn
  dùng lan truyền bảo thủ từ đối số; có thể bỏ sót nguồn/sink bên trong callee.
- Chưa phân tích xuyên file, dispatch động/alias hàm, tác dụng phụ lên field/global,
  closure thoát khỏi scope hoặc phân giải overload có cùng số tham số.
  C# optional arguments và Java varargs chưa được phân giải đầy đủ.

### Sanitizer theo loại sink

Cấu hình Java/C# dùng `sink_sanitizers` tương tự Python. Chỉ danh mục đúng với
sink mới được dùng để giảm mức cảnh báo; SQL và command vẫn giữ finding LOW
để người dùng kiểm tra. Dữ liệu sạch cho SQL không tự động sạch cho command.
Khi ghép dữ liệu đã xử lý với đầu vào chưa xử lý, phần chưa xử lý vẫn quyết định
mức nguy hiểm.

Các API parse/encode URL không xác minh host, IP hoặc giao thức, nên không được
coi là sanitizer chống SSRF. Chuẩn hóa đường dẫn cũng không chứng minh đường dẫn
nằm trong thư mục cho phép. `Codec.encode` và `SqlParameter` không được coi là
sanitizer cho chuỗi SQL ghép nối. Tham số hóa SQL phải truyền giá trị tách khỏi query.

Danh mục `path` và `html` của Java/C# được dùng bởi JV011/CS011 (path traversal) và JV012/CS012 (XSS):
dữ liệu đã qua sanitizer đúng loại không bị báo. Java/C# chưa có rule SSRF.

### CSRF cho Web UI

POST `/scan` luôn yêu cầu token hợp lệ, kể cả khi request không gửi cookie.
GET `/` cấp token ngẫu nhiên có chữ ký HMAC và đưa token vào form. Client tự động
phải GET trang chủ trước, giữ cookie, rồi gửi token qua trường `csrf_token`
hoặc header `X-CSRF-Token`. Cookie là HttpOnly, SameSite=Strict và có Secure khi
truy cập HTTPS. Origin/Referer khác nguồn hoặc Fetch Metadata cross-site bị từ chối.

Nếu chạy nhiều worker, đặt cùng `ANALYZER_CSRF_SECRET` ngẫu nhiên, dài ít nhất
32 byte, cho mọi worker. Nếu không cấu hình, mỗi app có secret ngẫu nhiên riêng;
sau khi khởi động lại cần tải lại form. Authentication nằm ngoài phạm vi đợt sửa này.
Tham khảo [hướng dẫn CSRF của OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

### SARIF và CI

`python main.py scan app --format sarif -o results.sarif --fail-on CRITICAL`
xuất báo cáo cho mã ứng dụng. Workflow mẫu scan `app` để không đưa các mẫu cố ý
có lỗ hổng trong `tests` và `samples` vào kết quả CI.

Workflow lưu mã thoát, tải SARIF nếu báo cáo tồn tại, rồi trả lại mã thoát của
analyzer: 0 = thành công dưới ngưỡng, 1 = có finding đạt ngưỡng, 2 = lỗi cấu hình,
đầu vào hoặc lỗi phân tích file. Lỗi phân tích cũng được ghi vào
`invocations[].executionSuccessful` và thông báo trong SARIF.

Đường dẫn được mã hóa URI, relative path có base URI, rule tùy chỉnh có descriptor.
Taint path hiện chỉ lưu tên bước, chưa lưu tọa độ từng bước; SARIF chỉ gắn tọa độ
thật cho sink. Việc upload vẫn cần quyền GitHub Code Scanning phù hợp với repository.
Tham khảo [SARIF support của GitHub](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

#### Repository chưa bật Code Scanning

Workflow luôn lưu `results.sarif` vào artifact **security-scan-sarif** (giữ 14 ngày).
Mở **Actions → lần chạy → Artifacts** để tải báo cáo, không cần bật Code Scanning.
Bước kiểm tra mã thoát vẫn làm CI thất bại khi có finding CRITICAL hoặc lỗi scan;
không bỏ qua các lỗi này để làm checks xanh.

Upload vào tab **Security / Code scanning** là tích hợp tùy chọn:

1. Bật tính năng Code Scanning/GitHub Code Security phù hợp với repository trong
   **Settings → Advanced Security**. Repository private/internal cần quyền sử dụng
   tính năng tương ứng; chỉ thêm quyền vào workflow không thay thế việc bật tính năng.
2. Vào **Settings → Secrets and variables → Actions → Variables**, tạo repository
   variable `CODE_SCANNING_ENABLED` với giá trị `true`.
3. Push thay đổi workflow hoặc chạy lại workflow trên phiên bản đã cập nhật.

Workflow dùng `github/codeql-action/upload-sarif@v4`, giữ quyền
`security-events: write`, và bỏ qua upload Code Scanning đối với PR từ fork.
Khi đã bật variable, lỗi upload vẫn được báo là lỗi CI để phát hiện cấu hình sai.
Nếu variable chưa đặt hoặc khác `true`, workflow chỉ lưu artifact và ghi rõ lý do
trong phần summary. Cảnh báo deprecation v3 không phải nguyên nhân của lỗi
`Code scanning is not enabled for this repository`.

Tham khảo [điều kiện upload SARIF của GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).
