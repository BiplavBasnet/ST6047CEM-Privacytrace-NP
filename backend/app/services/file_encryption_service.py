"""Encrypt evidence files at rest (server-side decrypt for parsing only)."""

from __future__ import annotations

import json
from pathlib import Path

from app.config import get_backend_root, get_settings
from app.services import field_encryption_service


def resolve_encrypted_upload_dir() -> Path:
    settings = get_settings()
    path = Path(settings.encrypted_upload_dir)
    if not path.is_absolute():
        path = get_backend_root() / path
    path.mkdir(parents=True, exist_ok=True)
    return path


def store_encrypted_evidence(
    *,
    evidence_id: str,
    file_name: str,
    content: bytes,
) -> tuple[str, dict]:
    payload = field_encryption_service.encrypt_bytes(
        plaintext=content,
        table="evidence_files",
        record_id=evidence_id,
        field="file_content",
        extra=file_name,
    )
    enc_dir = resolve_encrypted_upload_dir()
    stored_name = f"{evidence_id}.enc"
    stored_path = enc_dir / stored_name
    stored_path.write_text(json.dumps(payload), encoding="utf-8")
    return str(stored_path.relative_to(get_backend_root())).replace("\\", "/"), payload



def _resolve_safe_encrypted_path(encrypted_relative_path: str) -> Path:
    base_dir = resolve_encrypted_upload_dir().resolve()
    candidate = (get_backend_root() / encrypted_relative_path).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError as exc:
        raise ValueError("Encrypted evidence path is outside the configured encrypted upload directory") from exc
    return candidate

def read_encrypted_evidence(*, encrypted_relative_path: str, file_crypto_metadata: dict) -> bytes:
    path = _resolve_safe_encrypted_path(encrypted_relative_path)
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = file_crypto_metadata
    return field_encryption_service.decrypt_payload(payload)
