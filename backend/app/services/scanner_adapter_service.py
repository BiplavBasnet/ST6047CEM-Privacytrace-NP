"""Parse external scanner output formats into normalised finding drafts."""

from __future__ import annotations

import json
from typing import Any

from app.schemas.scanner_evidence_schema import SUPPORTED_SOURCE_FORMATS


class UnsupportedSourceFormatError(ValueError):
    pass


class ScannerParseError(ValueError):
    pass


def parse_payload_bytes(raw: bytes, source_format: str | None) -> tuple[str, list[dict[str, Any]]]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise ScannerParseError("Empty scanner payload")

    fmt = source_format or detect_format(text)
    if fmt not in SUPPORTED_SOURCE_FORMATS:
        raise UnsupportedSourceFormatError(f"Unsupported source_format: {fmt}")

    if fmt == "generic_secret_scanner_json":
        return fmt, _parse_generic(text)
    if fmt == "external_secret_scanner_json":
        return fmt, _parse_external_secret(text)
    if fmt == "gitleaks_json":
        return fmt, _parse_gitleaks(text)
    if fmt == "semgrep_sarif":
        return fmt, _parse_semgrep_sarif(text)
    if fmt == "semgrep_json":
        return fmt, _parse_semgrep_json(text)
    raise UnsupportedSourceFormatError(f"Unsupported source_format: {fmt}")


def detect_format(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("{") and '"runs"' in stripped and "results" in stripped:
        return "semgrep_sarif"
    if stripped.startswith("{") and '"results"' in stripped and '"check_id"' in stripped:
        return "semgrep_json"
    if stripped.startswith("{") and '"findings"' in stripped and '"scanner"' in stripped:
        return "generic_secret_scanner_json"
    if stripped.startswith("[") or (
        stripped.startswith("{") and "DetectorName" in stripped
    ):
        return "external_secret_scanner_json"
    if stripped.startswith("[") or (
        stripped.startswith("{") and "RuleID" in stripped
    ):
        return "gitleaks_json"
    if stripped.startswith("{"):
        data = json.loads(stripped)
        if "findings" in data:
            return "generic_secret_scanner_json"
    return "generic_secret_scanner_json"


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScannerParseError("Invalid JSON scanner payload") from exc


def _parse_ndjson_or_array(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if stripped.startswith("["):
        data = _parse_json(stripped)
        if not isinstance(data, list):
            raise ScannerParseError("Expected JSON array")
        return [x for x in data if isinstance(x, dict)]
    items: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = _parse_json(line)
        if isinstance(obj, dict):
            items.append(obj)
    return items


def _parse_generic(text: str) -> list[dict[str, Any]]:
    data = _parse_json(text)
    if not isinstance(data, dict):
        raise ScannerParseError("generic_secret_scanner_json must be an object")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ScannerParseError("Missing findings array")
    return [f for f in findings if isinstance(f, dict)]


def _parse_external_secret(text: str) -> list[dict[str, Any]]:
    items = _parse_ndjson_or_array(text)
    drafts: list[dict[str, Any]] = []
    for item in items:
        git = {}
        sm = item.get("SourceMetadata") or {}
        if isinstance(sm, dict):
            data = sm.get("Data") or {}
            if isinstance(data, dict):
                git = data.get("Git") or {}
        drafts.append(
            {
                "detector_name": item.get("DetectorName") or item.get("DetectorType"),
                "finding_type": item.get("DetectorType") or "secret_exposure",
                "verification_status": "verified" if item.get("Verified") else "unverified",
                "source_file": git.get("file") if isinstance(git, dict) else None,
                "line_number": git.get("line") if isinstance(git, dict) else None,
                "commit_id": git.get("commit") if isinstance(git, dict) else None,
                "repository": git.get("repository") if isinstance(git, dict) else None,
                "masked_value": item.get("Redacted"),
                "confidence": 0.85 if item.get("Verified") else 0.55,
                "severity": "high",
                "scanner_category": "external_secret",
            }
        )
    return drafts


def _parse_gitleaks(text: str) -> list[dict[str, Any]]:
    items = _parse_ndjson_or_array(text)
    drafts: list[dict[str, Any]] = []
    for item in items:
        masked = item.get("Redacted")
        drafts.append(
            {
                "detector_name": item.get("RuleID"),
                "finding_type": item.get("Description") or "secret_exposure",
                "source_file": item.get("File"),
                "line_number": item.get("StartLine"),
                "commit_id": item.get("Commit"),
                "masked_value": masked,
                "tags": item.get("Tags") if isinstance(item.get("Tags"), list) else [],
                "severity": "high",
                "confidence": 0.8,
                "scanner_category": "secret_scan",
                "verification_status": "unknown",
            }
        )
    return drafts


def _parse_semgrep_sarif(text: str) -> list[dict[str, Any]]:
    data = _parse_json(text)
    if not isinstance(data, dict):
        raise ScannerParseError("semgrep_sarif must be an object")
    drafts: list[dict[str, Any]] = []
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            locs = result.get("locations") or []
            uri = None
            line = None
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                uri = art.get("uri")
                region = phys.get("region") or {}
                line = region.get("startLine")
            msg = result.get("message") or {}
            message = msg.get("text") if isinstance(msg, dict) else str(msg)
            props = result.get("properties") or {}
            tags = []
            if isinstance(props, dict):
                tags = list(props.keys())[:10]
            drafts.append(
                {
                    "detector_name": result.get("ruleId"),
                    "finding_type": "code_finding",
                    "source_file": uri,
                    "line_number": line,
                    "explanation": message,
                    "severity": (result.get("level") or "medium").lower(),
                    "tags": tags,
                    "confidence": 0.7,
                    "scanner_category": "sast",
                    "verification_status": "unknown",
                }
            )
    return drafts


def _parse_semgrep_json(text: str) -> list[dict[str, Any]]:
    data = _parse_json(text)
    if not isinstance(data, dict):
        raise ScannerParseError("semgrep_json must be an object")
    drafts: list[dict[str, Any]] = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        meta = extra.get("metadata") if isinstance(extra, dict) else {}
        tags: list[str] = []
        if isinstance(meta, dict):
            tags = [str(k) for k in list(meta.keys())[:10]]
        start = result.get("start") or {}
        drafts.append(
            {
                "detector_name": result.get("check_id"),
                "finding_type": "code_finding",
                "source_file": result.get("path"),
                "line_number": start.get("line") if isinstance(start, dict) else None,
                "explanation": extra.get("message") if isinstance(extra, dict) else None,
                "severity": (extra.get("severity") or "medium") if isinstance(extra, dict) else "medium",
                "tags": tags,
                "confidence": 0.7,
                "scanner_category": "sast",
                "verification_status": "unknown",
            }
        )
    return drafts
