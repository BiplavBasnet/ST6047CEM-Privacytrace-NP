"""Safety gateway for AI remediation inputs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

UNSAFE_PATTERNS = (
    re.compile(r"\b98[0-9]{8}\b"),
    re.compile(r"\bWALLET-NP-[0-9A-Z]+\b", re.IGNORECASE),
    re.compile(r"\bTXN-NP-[0-9A-Z]+(?:-[0-9A-Z]+)*(?![-A-Z0-9])\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}\b"),
    re.compile(r'(?i)\bBearer\s+[^\s,;}\"]+'),
    re.compile(r'(?i)(?:Authorization|authorization)(?:\\"|")?\s*[:=]\s*(?:\\"|")?Bearer\s+[^\s,;}\"]+'),
    re.compile(r'(?i)\b(?:pk|sk)[_-](?:live|test|prod|dev|np)?[_-]?[A-Za-z0-9][A-Za-z0-9_\-]{7,}\b|\b(?:pk|sk)-[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9_]{8,}\b|\bglpat-[A-Za-z0-9_\-]{8,}\b'),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r'(?i)\b(password|passwd|pwd)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+'),
    re.compile(r"(?i)\bpassword[_-]?hash\b"),
    re.compile(r'(?i)\b(username|user_name|uname|login)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]{3,}'),
    re.compile(r'(?i)\b(access[_-]?token|auth[_-]?token|refresh[_-]?token)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+'),
    re.compile(r'(?i)\bsession[_-]?token(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+'),
)
@dataclass
class AISafetyResult:
    safe: bool
    status: str
    message: str
    violation_codes: list[str] = field(default_factory=list)


def _to_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str) if not isinstance(value, str) else value


def validate_masked_ai_input(payload: dict[str, Any]) -> AISafetyResult:
    text = _to_text(payload)
    violations = [f"unsafe_pattern_{idx}" for idx, pattern in enumerate(UNSAFE_PATTERNS, start=1) if pattern.search(text)]
    if violations:
        return AISafetyResult(
            safe=False,
            status="blocked_input_unsafe",
            message="AI remediation suggestion was blocked because the input contained unsafe unmasked content.",
            violation_codes=violations,
        )
    return AISafetyResult(
        safe=True,
        status="safe_masked_input",
        message="AI input passed masked-only safety validation.",
    )


def contains_unsafe_content(value: Any) -> bool:
    text = _to_text(value)
    return any(pattern.search(text) for pattern in UNSAFE_PATTERNS)

