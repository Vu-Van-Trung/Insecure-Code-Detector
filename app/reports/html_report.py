"""Report HTML độc lập (một file duy nhất, CSS nhúng sẵn, không JavaScript, không CDN).

Không dùng JavaScript/CDN nên file mở được offline và gửi qua email an toàn.

BẢO MẬT: mọi giá trị lấy từ code được scan (tên file, đoạn code, message) đều
được escape HTML, nên một file độc hại không thể chèn thẻ HTML hay script vào
report (tránh XSS khi người khác mở report).
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from app.analyzer.languages import DISPLAY_NAMES
from app.models.finding import Finding, ScanResult, Severity

# Màu của từng severity (badge, viền finding, thanh tỷ lệ).
_COLORS = {
    Severity.CRITICAL: "#b42318",
    Severity.HIGH: "#d9480f",
    Severity.MEDIUM: "#b08800",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#6c757d",
}

# CSS nhúng thẳng vào thẻ <style> của report.
_CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f6f7f9; color: #1f2328; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin-top: 32px; font-size: 19px; border-bottom: 1px solid #d0d7de; padding-bottom: 6px; }
.meta { color: #57606a; font-size: 14px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 16px; }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px; }
.card .num { font-size: 24px; font-weight: 700; }
.card .lbl { font-size: 12px; color: #57606a; text-transform: uppercase; letter-spacing: .04em; }
.bar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; margin-top: 14px; background: #e6e8eb; }
table { width: 100%; border-collapse: collapse; background: #fff; font-size: 14px; }
th, td { border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #eef1f4; }
.badge { display: inline-block; color: #fff; border-radius: 4px; padding: 1px 7px; font-size: 12px; font-weight: 600; }
.finding { background: #fff; border: 1px solid #d0d7de; border-left-width: 5px; border-radius: 6px; padding: 12px 14px; margin: 12px 0; }
.finding h3 { margin: 0 0 6px; font-size: 16px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 3px 12px; margin: 8px 0; font-size: 14px; }
dt { color: #57606a; }
pre { background: #0d1117; color: #e6edf3; padding: 8px 10px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
.path { font-family: Consolas, monospace; font-size: 13px; }
.note { font-size: 13px; color: #57606a; background: #fff8c5; border: 1px solid #eac54f; padding: 8px 10px; border-radius: 6px; }
"""


def _badge(severity: Severity) -> str:
    """Nhãn màu hiển thị severity (giá trị lấy từ enum cố định nên không cần escape)."""
    return f'<span class="badge" style="background:{_COLORS[severity]}">{severity.value}</span>'


def _finding_html(index: int, finding: Finding) -> str:
    """Khối HTML chi tiết của một finding: thông tin, đoạn code, taint path, mô tả, cách sửa."""
    # (nhãn, giá trị đã escape) - chỉ chuỗi do code sinh ra (badge, số) mới được để nguyên.
    rows = [
        ("Rule", f"{escape(finding.rule_id)} &ndash; {escape(finding.rule_name)}"),
        ("Severity", _badge(finding.severity)),
        ("Confidence", f"{finding.confidence:.0%}"),
        ("CWE", escape(finding.cwe)),
        ("Category", escape(finding.category)),
        ("Language", escape(DISPLAY_NAMES.get(finding.language, finding.language))),
        ("Location", f"{escape(finding.file)}:{finding.line}:{finding.column}"),
    ]
    # Source/Sink chỉ có khi rule chứng minh được luồng dữ liệu (taint tracking).
    if finding.source:
        rows.append(("Source", escape(finding.source)))
        rows.append(("Sink", escape(finding.sink or "")))
    details = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    taint = ""
    if finding.taint_path:
        # Hiển thị đường đi của dữ liệu: input() → host → os.system()
        steps = " &rarr; ".join(escape(step) for step in finding.taint_path)
        taint = f'<p><strong>Taint path:</strong> <span class="path">{steps}</span></p>'
    return (
        f'<div class="finding" style="border-left-color:{_COLORS[finding.severity]}">'
        f"<h3>#{index} {escape(finding.message)}</h3>"
        f"<dl>{details}</dl>"
        f"<pre>{escape(finding.code)}</pre>"
        f"{taint}"
        f"<p>{escape(finding.description)}</p>"
        f"<p><strong>Recommendation:</strong> {escape(finding.recommendation)}</p>"
        "</div>"
    )


def render_html(result: ScanResult) -> str:
    """Tạo trang HTML hoàn chỉnh của report: tổng quan, danh sách file, finding, phần bị ẩn, lỗi."""
    counts = result.severity_counts()
    total = len(result.findings)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Các thẻ số liệu tổng quan ở đầu trang.
    cards = [("Files scanned", result.files_scanned), ("Lines scanned", result.lines_scanned),
             ("Total findings", total)]
    cards += [(severity.value.title(), counts[severity.value]) for severity in Severity]
    cards += [("Suppressed", len(result.suppressed)), ("Errors", len(result.errors))]
    cards_html = "".join(f'<div class="card"><div class="num">{n}</div><div class="lbl">{escape(label)}</div></div>'
                         for label, n in cards)
    # Thanh tỷ lệ severity vẽ bằng CSS thuần (mỗi đoạn rộng theo % số finding),
    # thay cho biểu đồ JavaScript. Bỏ qua mức có 0 finding và tránh chia cho 0.
    bar = "".join(
        f'<span title="{s.value}: {counts[s.value]}" style="width:{counts[s.value] / total * 100:.2f}%;'
        f'background:{_COLORS[s]}"></span>'
        for s in Severity if total and counts[s.value]
    )

    files_rows = "".join(
        f"<tr><td>{escape(item.path)}</td><td>{escape(DISPLAY_NAMES.get(item.language, item.language))}</td>"
        f"<td>{item.lines}</td><td>{item.findings}</td></tr>" for item in result.files
    ) or '<tr><td colspan="4">No files scanned.</td></tr>'

    sections = [
        f"<h1>Secure Code Analyzer report</h1>"
        f'<div class="meta">Target: <strong>{escape(result.target)}</strong> &middot; '
        f"Started: {escape(result.started_at)} &middot; Duration: {result.duration_ms} ms &middot; "
        f"Tool version: {escape(result.tool_version)} &middot; Generated: {generated}</div>",
        "<h2>Summary</h2>" + f'<div class="cards">{cards_html}</div><div class="bar">{bar}</div>',
        "<h2>Files</h2><table><tr><th>File</th><th>Language</th><th>Lines</th><th>Findings</th></tr>" + files_rows + "</table>",
        "<h2>Findings</h2>" + ("".join(_finding_html(i, f) for i, f in enumerate(result.findings, 1))
                               or "<p>No findings.</p>"),
    ]
    # Các mục dưới đây chỉ xuất hiện khi có dữ liệu, để report gọn.
    if result.suppressed:
        rows = "".join(
            f"<tr><td>{escape(f.rule_id)}</td><td>{escape(f.file)}:{f.line}</td><td>{escape(f.message)}</td></tr>"
            for f in result.suppressed
        )
        sections.append(
            "<h2>Suppressed findings</h2>"
            '<p class="note">These were hidden by the whitelist or <code># analyzer-ignore</code> comments. '
            "Suppression does not make the code safe.</p>"
            f"<table><tr><th>Rule</th><th>Location</th><th>Message</th></tr>{rows}</table>"
        )
    if result.errors:
        rows = "".join(
            f"<tr><td>{escape(e.file)}</td><td>{escape(e.error_type)}</td><td>{e.line or ''}</td>"
            f"<td>{escape(e.reason)}</td></tr>" for e in result.errors
        )
        sections.append(f"<h2>Errors</h2><table><tr><th>File</th><th>Type</th><th>Line</th><th>Reason</th></tr>{rows}</table>")
    if result.skipped_files:
        items = "".join(f"<li>{escape(path)}</li>" for path in result.skipped_files)
        sections.append(f"<h2>Skipped files (whitelist)</h2><ul>{items}</ul>")
    sections.append(
        '<p class="note">Confidence is a heuristic score of the analyzer, not an exact probability. '
        "Static analysis can miss issues and report false positives; review each finding.</p>"
    )

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Security report - {escape(result.target)}</title><style>{_CSS}</style></head>"
        f"<body><main>{''.join(sections)}</main></body></html>\n"
    )
