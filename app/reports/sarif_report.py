"""Report SARIF v2.1.0: Định dạng chuẩn cho GitHub Code Scanning, GitLab CI, VS Code.

SARIF (Static Analysis Results Interchange Format) là chuẩn JSON của OASIS
được hỗ trợ bởi hầu hết các nền tảng DevSecOps và CI/CD.
"""

from __future__ import annotations

import json
from typing import Any
from pathlib import Path, PureWindowsPath
from urllib.parse import quote

from app import __version__
from app.models.finding import Finding, ScanResult, Severity
from app.rules.registry import load_builtin_rules

# Map Severity sang level của SARIF: "error" | "warning" | "note" | "none"
SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_to_sarif(rule_cls: type) -> dict[str, Any]:
    """Chuyển đổi một SecurityRule thành SARIF reportingDescriptor."""
    rule_id = getattr(rule_cls, "id", "UNKNOWN")
    name = getattr(rule_cls, "name", rule_id)
    description = getattr(rule_cls, "description", name)
    cwe = getattr(rule_cls, "cwe", None)
    category = getattr(rule_cls, "category", None)
    recommendation = getattr(rule_cls, "recommendation", None)
    severity = getattr(rule_cls, "severity", Severity.MEDIUM)

    tags = ["security"]
    if cwe:
        tags.append(cwe)
    if category:
        tags.append(category)

    rule_def: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
        },
        "properties": {
            "tags": tags,
        },
    }
    if cwe:
        rule_def["properties"]["cwe"] = cwe
    if category:
        rule_def["properties"]["category"] = category
    if recommendation:
        rule_def["help"] = {
            "text": recommendation,
            "markdown": f"**Recommendation:** {recommendation}",
        }
    return rule_def


def _finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Chuyển đổi một Finding thành SARIF result."""
    level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
    clean_path = finding.file.replace("\\", "/")
    if PureWindowsPath(clean_path).is_absolute():
        artifact = {"uri": PureWindowsPath(clean_path).as_uri()}
    elif Path(clean_path).is_absolute():
        artifact = {"uri": Path(clean_path).as_uri()}
    else:
        artifact = {"uri": quote(clean_path, safe="/"), "uriBaseId": "%SRCROOT%"}

    res: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact,
                    "region": {
                        "startLine": max(1, finding.line),
                        "startColumn": max(1, finding.column + 1),
                        "snippet": {"text": finding.code or ""},
                    },
                }
            }
        ],
    }

    # Nếu có taint path, gắn thêm codeFlows để GitHub hiển thị luồng dữ liệu trực quan
    if finding.taint_path:
        thread_flow_locations = []
        for index, step in enumerate(finding.taint_path):
            location = {"message": {"text": step}}
            # Only the sink has known coordinates; do not fabricate source locations.
            if index == len(finding.taint_path) - 1:
                location["physicalLocation"] = res["locations"][0]["physicalLocation"]
            thread_flow_locations.append({"location": location})
        res["codeFlows"] = [
            {
                "message": {"text": f"Taint path: {' -> '.join(finding.taint_path)}"},
                "threadFlows": [{"locations": thread_flow_locations}],
            }
        ]

    return res


def render_sarif(result: ScanResult) -> str:
    """Tạo chuỗi JSON theo chuẩn SARIF v2.1.0."""
    rules_dict = {rule.id: _rule_to_sarif(rule) for rule in load_builtin_rules()}
    for finding in result.findings:
        if finding.rule_id not in rules_dict:
            rules_dict[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.rule_name},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.recommendation},
            }
    results = [_finding_to_sarif_result(f) for f in result.findings]
    indexes = {rule_id: i for i, rule_id in enumerate(rules_dict)}
    for finding, item in zip(result.findings, results):
        item["ruleIndex"] = indexes[finding.rule_id]
        item["properties"] = {"severity": finding.severity.value, "confidence": finding.confidence}

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secure Code Analyzer",
                        "version": result.tool_version or __version__,
                        "informationUri": "https://github.com/Vu-Van-Trung/Insecure-Code-Detector",
                        "rules": list(rules_dict.values()),
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": Path.cwd().as_uri().rstrip("/") + "/"}},
                "invocations": [{
                    "executionSuccessful": not bool(result.errors),
                    "toolExecutionNotifications": [
                        {"level": "error", "message": {"text": f"{error.file}: {error.error_type}: {error.reason}"}}
                        for error in result.errors
                    ],
                }],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n"
