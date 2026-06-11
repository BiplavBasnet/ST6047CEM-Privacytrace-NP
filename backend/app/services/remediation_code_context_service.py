"""Safe, minimal repository code-context extraction for remediation AI."""

from __future__ import annotations

import hashlib
from typing import Any

from app.services import remediation_repository_safety_service as repo_safety


class CodeContextError(ValueError):
    pass


def build_code_context(
    *,
    file_path: str | None,
    max_chars: int = 4000,
    reason: str = "remediation_source_localisation",
) -> dict[str, Any]:
    """Return the smallest safe snippet for an allowlisted file, or an empty package.

    Never invents content. If the path is unknown/unsafe/missing, returns
    ``context_available=False`` with limitations.
    """

    if not file_path:
        return {
            "context_available": False,
            "file_path": None,
            "content_hash": None,
            "excerpt": None,
            "extraction_reason": reason,
            "safety_result": "no_path",
            "limitations": ["Exact source file not established from available evidence."],
        }

    try:
        path = repo_safety.resolve_safe_repo_path(file_path)
    except ValueError as exc:
        return {
            "context_available": False,
            "file_path": file_path,
            "content_hash": None,
            "excerpt": None,
            "extraction_reason": reason,
            "safety_result": "blocked",
            "limitations": [str(exc)],
        }

    raw = path.read_text(encoding="utf-8", errors="replace")
    secrets = repo_safety.scan_text_for_secrets(raw)
    if secrets:
        return {
            "context_available": False,
            "file_path": file_path,
            "content_hash": f"sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}",
            "excerpt": None,
            "extraction_reason": reason,
            "safety_result": "secret_blocked",
            "limitations": [
                "Source context blocked because secret-shaped content was detected.",
                *secrets[:5],
            ],
        }

    excerpt = raw[:max_chars]
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return {
        "context_available": True,
        "file_path": file_path,
        "content_hash": f"sha256:{digest}",
        "excerpt": excerpt,
        "extraction_reason": reason,
        "safety_result": "safe",
        "limitations": (
            ["Excerpt truncated to configured max_chars."] if len(raw) > max_chars else []
        ),
    }
