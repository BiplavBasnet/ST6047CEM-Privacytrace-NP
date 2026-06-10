"""Field-level hybrid encryption for JSON/text artefacts at rest."""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any

from app.config import get_settings
from app.services import crypto_service, key_management_service

ACTION_CRYPTO_ENCRYPT = "crypto_encrypt"
ACTION_CRYPTO_DECRYPT = "crypto_decrypt"


def encryption_enabled() -> bool:
    settings = get_settings()
    return bool(settings.crypto_encryption_enabled) and key_management_service.data_wrap_keys_configured()


def build_aad(*, table: str, record_id: str, field: str, extra: str | None = None) -> str:
    parts = [table, record_id, field]
    if extra:
        parts.append(extra)
    return "|".join(parts)


def encrypt_bytes(
    *,
    plaintext: bytes,
    table: str,
    record_id: str,
    field: str,
    extra: str | None = None,
) -> dict[str, Any]:
    if not encryption_enabled():
        raise crypto_service.CryptoError("Field encryption is disabled or keys are missing")
    kid = key_management_service.active_kid()
    aad = build_aad(table=table, record_id=record_id, field=field, extra=extra)
    dek = crypto_service.generate_dek()
    nonce = crypto_service.generate_nonce()
    ciphertext = crypto_service.encrypt_aes_gcm(
        plaintext=plaintext,
        dek=dek,
        nonce=nonce,
        associated_data=aad.encode("utf-8"),
    )
    public_key = key_management_service.load_data_wrap_public_key()
    wrapped = crypto_service.wrap_dek_rsa_oaep(dek=dek, public_key=public_key)
    return crypto_service.build_encrypted_payload(
        kid=kid,
        plaintext=plaintext,
        dek=dek,
        wrapped_dek=wrapped,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=aad,
    )


def decrypt_payload(payload: dict[str, Any]) -> bytes:
    kid, nonce, wrapped_dek, ciphertext, aad, _ = crypto_service.parse_encrypted_payload(
        payload
    )
    private_key = key_management_service.load_data_wrap_private_key()
    dek = crypto_service.unwrap_dek_rsa_oaep(wrapped_dek=wrapped_dek, private_key=private_key)
    return crypto_service.decrypt_aes_gcm(
        ciphertext=ciphertext,
        dek=dek,
        nonce=nonce,
        associated_data=aad.encode("utf-8"),
    )


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def encrypt_json(
    *,
    value: dict | list | Any,
    table: str,
    record_id: str,
    field: str,
    extra: str | None = None,
) -> dict[str, Any]:
    raw = json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, default=_json_default
    ).encode("utf-8")
    return encrypt_bytes(
        plaintext=raw,
        table=table,
        record_id=record_id,
        field=field,
        extra=extra,
    )


def decrypt_json(payload: dict[str, Any]) -> dict | list | Any:
    raw = decrypt_payload(payload)
    return json.loads(raw.decode("utf-8"))
