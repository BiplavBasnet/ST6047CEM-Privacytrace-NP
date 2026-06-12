from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any


def normalize_identifier(value: Any) -> str:
    return re.sub(r"[\s\-/]", "", str(value or "").strip())


def luhn_valid(value: Any) -> bool:
    digits = normalize_identifier(value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def validate_value(value: Any, validator_ids: list[str], source_context: dict[str, str]) -> str:
    text = str(value or "").strip()
    for validator_id in validator_ids:
        if validator_id in {"nonempty_identifier", "nonempty_value"} and not text:
            return "invalid"
        if validator_id == "luhn" and not luhn_valid(text):
            return "invalid"
        if validator_id == "three_or_four_digits" and not re.fullmatch(r"\d{3,4}", text):
            return "invalid"
        if validator_id == "four_to_eight_digits" and not re.fullmatch(r"\d{4,8}", text):
            return "invalid"
        if validator_id == "numeric_value":
            try:
                float(text.replace(",", ""))
            except ValueError:
                return "invalid"
        if validator_id == "trusted_document_context":
            trusted = any(
                str(source_context.get(key) or "").strip()
                for key in ("document_type", "upload_endpoint", "mime_type", "scanner_label")
            )
            if not trusted:
                return "unknown"
    return "valid" if validator_ids else "unknown"


def mask_value(value: Any, strategy: str) -> str:
    text = str(value or "")
    compact = normalize_identifier(text)
    if strategy == "category_only":
        return "[category-only]"
    if not compact:
        return "[masked]"
    if strategy == "last_two":
        return f"{'*' * max(0, len(compact) - 2)}{compact[-2:]}"
    if strategy == "last_four":
        return f"{'*' * max(0, len(compact) - 4)}{compact[-4:]}"
    if strategy == "minimal_suffix":
        return f"{'*' * max(0, len(compact) - 2)}{compact[-2:]}"
    if strategy == "card_pan":
        return f"{'*' * max(0, len(compact) - 4)}{compact[-4:]}"
    return "[masked]"


def hmac_fingerprint(value: Any, taxonomy_code: str, key: str) -> str:
    if not key:
        raise ValueError("A detection HMAC key is required for stable fingerprinting.")
    normalized = normalize_identifier(value).casefold()
    message = f"privacytrace-detection-v1\0{taxonomy_code}\0{normalized}".encode("utf-8")
    digest = hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"HMAC-SHA256-V1:{digest}"
