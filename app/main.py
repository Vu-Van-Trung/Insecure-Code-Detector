"""Giao diện web bằng FastAPI: http://127.0.0.1:8000

Tầng web chỉ lo HTTP, kiểm tra đầu vào và hiển thị; mọi lần scan đều được giao
cho lõi analyzer (AnalyzerEngine), giống hệt CLI.

BẢO MẬT của chính ứng dụng web:

* code được upload KHÔNG BAO GIỜ được thực thi, import hay ghi xuống đĩa: nó
  được đọc vào bộ nhớ và chỉ được parse bằng ``ast`` (không exec, không subprocess);
* chỉ nhận file .py / .java / .cs, giới hạn kích thước và số lượng; tên file
  được làm sạch và chỉ dùng làm nhãn hiển thị, nên không thể path traversal;
* kích thước request được kiểm tra trước khi parse body, và dữ liệu multipart
  được giữ trong bộ nhớ (không tạo file tạm);
* template tự động escape; có các security header chặt chẽ (CSP, chống nhúng iframe);
* lỗi không bao giờ để lộ stack trace hay mã nguồn.
"""

from __future__ import annotations

import logging
import os
import secrets
import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartParser

from app import __version__
from app.analyzer.engine import AnalyzerEngine
from app.analyzer.languages import DISPLAY_NAMES, EXTENSIONS, extension_of, language_of, supported_extensions_text
from app.config.settings import DEFAULT_WHITELIST, PROJECT_ROOT, AnalyzerSettings
from app.logging_config import setup_logging
from app.models.finding import Finding, ScanResult, Severity
from app.reports import REPORT_FORMATS, render_report
from app.rules.registry import load_builtin_rules
from app.security import (
    CSRF_COOKIE_NAME,
    generate_csrf_token,
    is_api_auth_configured,
    is_web_auth_configured,
    verify_api_key,
    verify_basic_auth,
    verify_csrf_token,
    same_origin_request,
)
from app.storage import ScanStore

logger = logging.getLogger(__name__)

# Thư mục web/ chứa templates (Jinja2) và static (CSS, JS).
WEB_DIR = PROJECT_ROOT / "web"

# ------------------------------------------------------------------ giới hạn upload
MAX_FILE_BYTES = 1024 * 1024          # mỗi file upload / đoạn code paste
MAX_FILES = 20                        # số file mỗi lần scan
MAX_REQUEST_BYTES = 5 * 1024 * 1024   # toàn bộ request
ALLOWED_EXTENSIONS = set(EXTENSIONS)  # .py, .java, .cs
ALLOWED_EXTENSIONS_TEXT = supported_extensions_text()
# Pydantic/FastAPI tự từ chối mọi giá trị ngôn ngữ ngoài 3 giá trị này.
LanguageName = Literal["python", "java", "csharp"]
MAX_FILENAME_LENGTH = 100

# Giữ dữ liệu multipart upload trong bộ nhớ thay vì ghi ra thư mục temp của hệ
# thống: code được upload không bao giờ chạm tới đĩa.
MultiPartParser.spool_max_size = MAX_REQUEST_BYTES

# Header bảo mật gắn vào MỌI response.
SECURITY_HEADERS = {
    # CSP: chỉ cho phép script/style từ chính site và CDN jsdelivr (Bootstrap, Chart.js);
    # chặn script inline, chặn nhúng trang vào iframe, chặn plugin (object).
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",       # trình duyệt không được "đoán" kiểu nội dung
    "X-Frame-Options": "DENY",                 # chống clickjacking (trình duyệt cũ không hỗ trợ CSP)
    "Referrer-Policy": "no-referrer",          # không gửi URL (chứa scan_id) cho site khác
    "Cross-Origin-Opener-Policy": "same-origin",
}


class UploadError(ValueError):
    """Upload không hợp lệ: báo lại cho người dùng với HTTP 400."""


def sanitize_filename(raw_name: str) -> str:
    """Trả về tên hiển thị an toàn cho file upload, hoặc ném UploadError.

    Chỉ giữ thành phần cuối của đường dẫn (``../../etc/x.py`` -> ``x.py``) và
    thay mọi ký tự ngoài ``[A-Za-z0-9._-]``. Tên này chỉ là nhãn trong report;
    nó không bao giờ được dùng để mở hay tạo file.
    """
    # Đổi "\" thành "/" để tên kiểu Windows (..\..\x.py) cũng bị cắt đúng.
    base = PurePosixPath(raw_name.replace("\\", "/")).name.strip()
    extension = PurePosixPath(base).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise UploadError(f"'{base[:MAX_FILENAME_LENGTH] or raw_name[:40]}' is not a supported source file; "
                          f"only {ALLOWED_EXTENSIONS_TEXT} files are accepted.")
    # lstrip(".") để không tạo ra tên file ẩn / tên chỉ gồm dấu chấm.
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", base[: -len(extension)]).lstrip(".")
    stem = safe[: MAX_FILENAME_LENGTH - len(extension)] or "upload"
    return f"{stem}{extension}"


def with_language(filename: str, language: str | None) -> str:
    """Ép extension khớp với ``language`` (code được paste: người dùng tự chọn ngôn ngữ).

    Vd paste code Java với tên "snippet.py" -> "snippet.java", để engine chọn đúng parser.
    """
    if language is None or language_of(filename) == language:
        return filename
    return f"{PurePosixPath(filename).stem or 'pasted_code'}{extension_of(language)}"


async def read_upload(upload: UploadFile, limit: int = MAX_FILE_BYTES) -> bytes:
    """Đọc file upload theo từng khối 64 KB, từ chối ngay khi vượt quá ``limit`` byte.

    Không đọc cả file một lần, nên file khổng lồ không làm đầy bộ nhớ server.
    """
    chunks, size = [], 0
    while chunk := await upload.read(64 * 1024):
        size += len(chunk)
        if size > limit:
            raise UploadError(f"'{upload.filename}' is larger than {limit // 1024} KB.")
        chunks.append(chunk)
    return b"".join(chunks)


def unique_name(name: str, used: set[str]) -> str:
    """Đổi tên khi có hai file trùng tên trong cùng một lần upload (a.py, a_2.py, ...)."""
    candidate, counter = name, 2
    while candidate in used:
        candidate = f"{name[:-3]}_{counter}.py"
        counter += 1
    used.add(candidate)
    return candidate


# ------------------------------------------------------------------ model của API (Pydantic)
# Pydantic kiểm tra kiểu/độ dài dữ liệu vào và tự sinh tài liệu API tại /api/docs.


class ScanRequest(BaseModel):
    """Body của POST /api/scan."""

    code: str = Field(..., min_length=1, max_length=MAX_FILE_BYTES, description="Python, Java or C# source code")
    filename: str = Field("snippet.py", max_length=MAX_FILENAME_LENGTH)
    language: LanguageName | None = Field(None, description="Overrides the language implied by the file name")


class FindingModel(BaseModel):
    """Một finding trong response JSON (cùng các trường với models.finding.Finding)."""

    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    file: str
    line: int
    column: int
    message: str
    description: str
    code: str
    recommendation: str
    cwe: str
    category: str
    source: str | None = None
    sink: str | None = None
    taint_path: list[str] = []
    language: str = ""


class ScanResponse(BaseModel):
    """Response của API scan."""

    scan_id: str
    summary: dict
    findings: list[FindingModel]
    errors: list[dict]


def to_response(scan_id: str, result: ScanResult) -> ScanResponse:
    """Chuyển ScanResult thành ScanResponse của API."""
    data = result.to_dict()
    return ScanResponse(scan_id=scan_id, summary=data["summary"], findings=data["findings"], errors=data["errors"])


# ------------------------------------------------------------------ ứng dụng


def create_app(settings: AnalyzerSettings | None = None, store: ScanStore | None = None) -> FastAPI:
    """Tạo ứng dụng FastAPI (application factory).

    Test truyền ``settings``/``store`` riêng (vd thư mục lưu tạm) để không đụng dữ liệu thật.
    """
    setup_logging()
    if settings is None:
        whitelist = DEFAULT_WHITELIST if DEFAULT_WHITELIST.is_file() else None
        settings = AnalyzerSettings.load(whitelist_path=whitelist)
    # Engine tạo một lần khi khởi động và dùng chung cho mọi request.
    engine = AnalyzerEngine(settings=settings)
    store = store or ScanStore()
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    # Biến dùng chung cho mọi template (phiên bản, danh sách severity, tên ngôn ngữ).
    templates.env.globals.update(version=__version__, severities=[s.value for s in Severity],
                                 language_names=DISPLAY_NAMES)

    # Share this secret across workers via the environment when deploying.
    configured_secret = os.environ.get("ANALYZER_CSRF_SECRET")
    if configured_secret:
        csrf_secret = configured_secret.encode("utf-8")
    else:
        secret_file = PROJECT_ROOT / "data" / ".csrf_secret"
        try:
            if secret_file.exists():
                csrf_secret = secret_file.read_bytes()
            else:
                secret_file.parent.mkdir(parents=True, exist_ok=True)
                csrf_secret = secrets.token_bytes(32)
                secret_file.write_bytes(csrf_secret)
        except OSError:
            csrf_secret = secrets.token_bytes(32)
    if len(csrf_secret) < 32:
        raise ValueError("ANALYZER_CSRF_SECRET must contain at least 32 bytes.")
    app = FastAPI(title="Secure Code Analyzer", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
    # Các giới hạn hiển thị trên trang upload.
    limits = {"extensions": ALLOWED_EXTENSIONS_TEXT, "max_file_kb": MAX_FILE_BYTES // 1024, "max_files": MAX_FILES, "max_request_mb": MAX_REQUEST_BYTES // 2**20}

    # -------------------------------------------------------------- middleware / xử lý lỗi

    @app.middleware("http")
    async def limit_and_harden(request: Request, call_next):
        """Chạy trước mọi request: kiểm tra auth; chặn POST quá lớn; gắn security headers."""
        path = request.url.path
        if path.startswith("/api/") and path != "/api/docs":
            if is_api_auth_configured() and not verify_api_key(request):
                return _error_response(request, 401, "Invalid or missing API key.")
        elif not path.startswith("/static/") and path != "/health":
            if is_web_auth_configured() and not verify_basic_auth(request):
                response = _error_response(request, 401, "Authentication required.")
                response.headers["WWW-Authenticate"] = 'Basic realm="Secure Code Analyzer"'
                return response

        if request.method == "POST":
            # Bắt buộc có Content-Length để biết kích thước TRƯỚC khi đọc body
            # (không có thì kẻ tấn công có thể gửi body vô hạn kiểu chunked).
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return _error_response(request, 411, "A Content-Length header is required.")
            if int(length) > MAX_REQUEST_BYTES:
                return _error_response(request, 413, f"Request is larger than {limits['max_request_mb']} MB.")
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def _wants_json(request: Request) -> bool:
        """Request gọi API (/api/...) nhận lỗi dạng JSON; trang web nhận trang lỗi HTML."""
        return request.url.path.startswith("/api/")

    def _error_response(request: Request, status: int, message: str) -> Response:
        if _wants_json(request):
            response: Response = JSONResponse({"detail": message}, status_code=status)
        else:
            response = templates.TemplateResponse(
                request, "error.html", {"status": status, "message": message}, status_code=status,
            )
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        return _error_response(request, exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        if _wants_json(request):
            return JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)
        return _error_response(request, 400, "Invalid input: the submitted form is too large or malformed.")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> Response:
        # Không bao giờ để lộ stack trace hay mã nguồn đã scan cho client; chi tiết chỉ nằm trong log.
        logger.exception("Unhandled error on %s", request.url.path)
        return _error_response(request, 500, "Internal error. The scan could not be completed.")

    def load_or_404(scan_id: str) -> ScanResult:
        """Đọc kết quả scan đã lưu, hoặc trả HTTP 404 (cả khi scan_id sai định dạng)."""
        result = store.load(scan_id)
        if result is None:
            raise HTTPException(404, "Scan not found.")
        return result

    # -------------------------------------------------------------- các trang web

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        """Trang chủ: form upload file / paste code."""
        csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
        if not verify_csrf_token(csrf_token, csrf_token, csrf_secret):
            csrf_token = generate_csrf_token(csrf_secret)
        response = templates.TemplateResponse(
            request, "index.html",
            {"limits": limits, "rule_count": len(engine.rules), "csrf_token": csrf_token},
        )
        if request.cookies.get(CSRF_COOKIE_NAME) != csrf_token:
            response.set_cookie(CSRF_COOKIE_NAME, csrf_token, samesite="strict", httponly=True, secure=request.url.scheme == "https")
        return response

    @app.post("/scan")
    async def scan(
        request: Request,
        files: Annotated[list[UploadFile] | None, File()] = None,
        code: Annotated[str, Form(max_length=MAX_FILE_BYTES)] = "",
        filename: Annotated[str, Form(max_length=MAX_FILENAME_LENGTH)] = "pasted_code.py",
        language: Annotated[LanguageName, Form()] = "python",
        csrf_token: Annotated[str, Form()] = "",
    ) -> Response:
        """Nhận form, scan, lưu kết quả rồi chuyển hướng sang trang kết quả."""
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        provided = csrf_token or request.headers.get("X-CSRF-Token")
        if not same_origin_request(request) or not verify_csrf_token(provided, cookie_csrf, csrf_secret):
            return _error_response(request, 403, "CSRF validation failed. Please refresh the page and try again.")
        try:
            sources = await collect_sources(files or [], code, with_language(filename or "pasted_code", language))
        except UploadError as exc:
            # Hiển thị lại form kèm thông báo lỗi và giữ nguyên code người dùng đã paste.
            token = request.cookies.get(CSRF_COOKIE_NAME) or generate_csrf_token(csrf_secret)
            context = {"limits": limits, "rule_count": len(engine.rules), "error": str(exc), "code": code, "csrf_token": token}
            return templates.TemplateResponse(request, "index.html", context, status_code=400)
        result = engine.scan_sources(sources, target=", ".join(name for name, _ in sources))
        scan_id = store.save(result)
        # Mẫu Post/Redirect/Get: 303 chuyển sang GET, nên F5 trang kết quả không gửi lại form.
        return RedirectResponse(f"/scan/{scan_id}", status_code=303)

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    async def scan_result(request: Request, scan_id: str) -> Response:
        """Dashboard kết quả: số liệu, biểu đồ, danh sách finding."""
        result = load_or_404(scan_id)
        return templates.TemplateResponse(
            request, "result.html",
            {"scan_id": scan_id, "result": result, "counts": result.severity_counts(), "summary": result.summary()},
        )

    @app.get("/scan/{scan_id}/finding/{index}", response_class=HTMLResponse)
    async def finding_detail(request: Request, scan_id: str, index: int) -> Response:
        """Trang chi tiết của finding thứ ``index``."""
        result = load_or_404(scan_id)
        if not 0 <= index < len(result.findings):
            raise HTTPException(404, "Finding not found.")
        finding: Finding = result.findings[index]
        return templates.TemplateResponse(
            request, "finding.html",
            {"scan_id": scan_id, "index": index, "finding": finding, "total": len(result.findings)},
        )

    @app.get("/scan/{scan_id}/report.{report_format}")
    async def download_report(scan_id: str, report_format: str) -> Response:
        """Tải report dạng file (json/csv/html)."""
        if report_format not in REPORT_FORMATS:
            raise HTTPException(404, "Unknown report format.")
        result = load_or_404(scan_id)
        _, media_type, extension = REPORT_FORMATS[report_format]
        return Response(
            render_report(result, report_format),
            media_type=f"{media_type}; charset=utf-8",
            # "attachment": trình duyệt tải về thay vì mở (report HTML không chạy trong origin của app).
            headers={"Content-Disposition": f'attachment; filename="security-report-{scan_id[:8]}.{extension}"'},
        )

    # -------------------------------------------------------------- JSON API

    @app.get("/api/rules")
    async def api_rules() -> list[dict[str, str]]:
        """Danh sách mọi rule và metadata của chúng."""
        return [rule_cls().metadata() for rule_cls in load_builtin_rules()]

    @app.post("/api/scan", response_model=ScanResponse)
    async def api_scan(body: ScanRequest) -> ScanResponse:
        """Scan một đoạn code gửi lên dạng JSON."""
        try:
            name = sanitize_filename(with_language(body.filename, body.language))
        except UploadError as exc:
            raise HTTPException(400, str(exc)) from None
        result = engine.scan_sources([(name, body.code.encode("utf-8"))], target=name)
        return to_response(store.save(result), result)

    @app.get("/api/scan/{scan_id}", response_model=ScanResponse)
    async def api_scan_result(scan_id: str) -> ScanResponse:
        return to_response(scan_id, load_or_404(scan_id))

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Kiểm tra server còn sống (dùng cho giám sát / healthcheck)."""
        return {"status": "ok", "version": __version__}

    return app


async def collect_sources(files: list[UploadFile], code: str, filename: str) -> list[tuple[str, bytes]]:
    """Kiểm tra file upload và code được paste; trả về các cặp (tên hiển thị, bytes)."""
    # Ô chọn file để trống vẫn gửi lên một phần không có tên -> bỏ qua.
    uploads = [upload for upload in files if upload.filename]
    if len(uploads) > MAX_FILES:
        raise UploadError(f"Too many files: at most {MAX_FILES} files per scan.")
    sources: list[tuple[str, bytes]] = []
    used: set[str] = set()
    for upload in uploads:
        name = unique_name(sanitize_filename(upload.filename or ""), used)
        sources.append((name, await read_upload(upload)))
    if code.strip():
        data = code.encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise UploadError(f"Pasted code is larger than {MAX_FILE_BYTES // 1024} KB.")
        sources.append((unique_name(sanitize_filename(filename or "pasted_code.py"), used), data))
    if not sources:
        raise UploadError(f"Upload at least one source file ({ALLOWED_EXTENSIONS_TEXT}) or paste some code.")
    return sources


# Đối tượng app mà uvicorn chạy: "uvicorn app.main:app".
app = create_app()
