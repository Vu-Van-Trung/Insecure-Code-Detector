"""FastAPI web interface: http://127.0.0.1:8000

The web layer only handles HTTP, validation and presentation; every scan is
delegated to the analyzer core (AnalyzerEngine), exactly like the CLI.

SECURITY of the web application itself:

* uploaded code is NEVER executed, imported or written to disk: it is read
  into memory and parsed with ``ast`` only (no exec, no subprocess);
* only .py / .java / .cs files, limited size and count; filenames are sanitized and only
  used as display labels, so path traversal is impossible;
* request size is checked before the body is parsed, and multipart data is kept
  in memory (no temporary files);
* templates are auto-escaped; strict security headers (CSP, no framing);
* errors never expose stack traces or source code.
"""

from __future__ import annotations

import logging
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
from app.storage import ScanStore

logger = logging.getLogger(__name__)

WEB_DIR = PROJECT_ROOT / "web"

# ------------------------------------------------------------------ upload limits
MAX_FILE_BYTES = 1024 * 1024          # per uploaded file / pasted code
MAX_FILES = 20                        # files per scan
MAX_REQUEST_BYTES = 5 * 1024 * 1024   # whole request
ALLOWED_EXTENSIONS = set(EXTENSIONS)  # .py, .java, .cs
ALLOWED_EXTENSIONS_TEXT = supported_extensions_text()
LanguageName = Literal["python", "java", "csharp"]
MAX_FILENAME_LENGTH = 100

# Keep multipart uploads in memory instead of spooling them to the system temp
# directory: uploaded code never touches the disk.
MultiPartParser.spool_max_size = MAX_REQUEST_BYTES

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class UploadError(ValueError):
    """Invalid upload: reported to the user with HTTP 400."""


def sanitize_filename(raw_name: str) -> str:
    """Return a safe display name for an uploaded file, or raise UploadError.

    Only the last path component is kept (``../../etc/x.py`` -> ``x.py``) and
    any character outside ``[A-Za-z0-9._-]`` is replaced. The name is only a
    label in reports; it is never used to open or create a file.
    """
    base = PurePosixPath(raw_name.replace("\\", "/")).name.strip()
    extension = PurePosixPath(base).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise UploadError(f"'{base[:MAX_FILENAME_LENGTH] or raw_name[:40]}' is not a supported source file; "
                          f"only {ALLOWED_EXTENSIONS_TEXT} files are accepted.")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", base[: -len(extension)]).lstrip(".")
    stem = safe[: MAX_FILENAME_LENGTH - len(extension)] or "upload"
    return f"{stem}{extension}"


def with_language(filename: str, language: str | None) -> str:
    """Force the extension matching ``language`` (pasted code: the user picks the language)."""
    if language is None or language_of(filename) == language:
        return filename
    return f"{PurePosixPath(filename).stem or 'pasted_code'}{extension_of(language)}"


async def read_upload(upload: UploadFile, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read an upload in chunks, refusing to buffer more than ``limit`` bytes."""
    chunks, size = [], 0
    while chunk := await upload.read(64 * 1024):
        size += len(chunk)
        if size > limit:
            raise UploadError(f"'{upload.filename}' is larger than {limit // 1024} KB.")
        chunks.append(chunk)
    return b"".join(chunks)


def unique_name(name: str, used: set[str]) -> str:
    candidate, counter = name, 2
    while candidate in used:
        candidate = f"{name[:-3]}_{counter}.py"
        counter += 1
    used.add(candidate)
    return candidate


# ------------------------------------------------------------------ API models (Pydantic)


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_FILE_BYTES, description="Python, Java or C# source code")
    filename: str = Field("snippet.py", max_length=MAX_FILENAME_LENGTH)
    language: LanguageName | None = Field(None, description="Overrides the language implied by the file name")


class FindingModel(BaseModel):
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
    scan_id: str
    summary: dict
    findings: list[FindingModel]
    errors: list[dict]


def to_response(scan_id: str, result: ScanResult) -> ScanResponse:
    data = result.to_dict()
    return ScanResponse(scan_id=scan_id, summary=data["summary"], findings=data["findings"], errors=data["errors"])


# ------------------------------------------------------------------ application


def create_app(settings: AnalyzerSettings | None = None, store: ScanStore | None = None) -> FastAPI:
    setup_logging()
    if settings is None:
        whitelist = DEFAULT_WHITELIST if DEFAULT_WHITELIST.is_file() else None
        settings = AnalyzerSettings.load(whitelist_path=whitelist)
    engine = AnalyzerEngine(settings=settings)
    store = store or ScanStore()
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    templates.env.globals.update(version=__version__, severities=[s.value for s in Severity],
                                 language_names=DISPLAY_NAMES)

    app = FastAPI(title="Secure Code Analyzer", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
    limits = {"extensions": ALLOWED_EXTENSIONS_TEXT, "max_file_kb": MAX_FILE_BYTES // 1024, "max_files": MAX_FILES, "max_request_mb": MAX_REQUEST_BYTES // 2**20}

    # -------------------------------------------------------------- middleware / errors

    @app.middleware("http")
    async def limit_and_harden(request: Request, call_next):
        if request.method == "POST":
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return _error_response(request, 411, "A Content-Length header is required.")
            if int(length) > MAX_REQUEST_BYTES:
                return _error_response(request, 413, f"Request is larger than {limits['max_request_mb']} MB.")
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def _wants_json(request: Request) -> bool:
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
        # Never leak stack traces or scanned source to the client.
        logger.exception("Unhandled error on %s", request.url.path)
        return _error_response(request, 500, "Internal error. The scan could not be completed.")

    def load_or_404(scan_id: str) -> ScanResult:
        result = store.load(scan_id)
        if result is None:
            raise HTTPException(404, "Scan not found.")
        return result

    # -------------------------------------------------------------- pages

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        return templates.TemplateResponse(request, "index.html", {"limits": limits, "rule_count": len(engine.rules)})

    @app.post("/scan")
    async def scan(
        request: Request,
        files: Annotated[list[UploadFile] | None, File()] = None,
        code: Annotated[str, Form(max_length=MAX_FILE_BYTES)] = "",
        filename: Annotated[str, Form(max_length=MAX_FILENAME_LENGTH)] = "pasted_code.py",
        language: Annotated[LanguageName, Form()] = "python",
    ) -> Response:
        try:
            sources = await collect_sources(files or [], code, with_language(filename or "pasted_code", language))
        except UploadError as exc:
            context = {"limits": limits, "rule_count": len(engine.rules), "error": str(exc), "code": code}
            return templates.TemplateResponse(request, "index.html", context, status_code=400)
        result = engine.scan_sources(sources, target=", ".join(name for name, _ in sources))
        scan_id = store.save(result)
        return RedirectResponse(f"/scan/{scan_id}", status_code=303)

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    async def scan_result(request: Request, scan_id: str) -> Response:
        result = load_or_404(scan_id)
        return templates.TemplateResponse(
            request, "result.html",
            {"scan_id": scan_id, "result": result, "counts": result.severity_counts(), "summary": result.summary()},
        )

    @app.get("/scan/{scan_id}/finding/{index}", response_class=HTMLResponse)
    async def finding_detail(request: Request, scan_id: str, index: int) -> Response:
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
        if report_format not in REPORT_FORMATS:
            raise HTTPException(404, "Unknown report format.")
        result = load_or_404(scan_id)
        _, media_type, extension = REPORT_FORMATS[report_format]
        return Response(
            render_report(result, report_format),
            media_type=f"{media_type}; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="security-report-{scan_id[:8]}.{extension}"'},
        )

    # -------------------------------------------------------------- JSON API

    @app.get("/api/rules")
    async def api_rules() -> list[dict[str, str]]:
        return [rule_cls().metadata() for rule_cls in load_builtin_rules()]

    @app.post("/api/scan", response_model=ScanResponse)
    async def api_scan(body: ScanRequest) -> ScanResponse:
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
        return {"status": "ok", "version": __version__}

    return app


async def collect_sources(files: list[UploadFile], code: str, filename: str) -> list[tuple[str, bytes]]:
    """Validate uploads and pasted code; returns (display name, bytes) pairs."""
    uploads = [upload for upload in files if upload.filename]  # empty file input sends a nameless part
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


app = create_app()
