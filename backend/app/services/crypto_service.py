"""NIST-aligned cryptographic primitives (AES-256-GCM, RSA-OAEP-SHA256).

Uses the ``cryptography`` library only — no custom cipher implementations.
"""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG_AES_GCM = "AES-256-GCM"
ALG_RSA_OAEP = "RSA-OAEP-SHA256"
PAYLOAD_VERSION = 1
DEK_SIZE = 32
NONCE_SIZE = 12


class CryptoError(Exception):
    """Base crypto operation error."""


class TamperDetectedError(CryptoError):
    """Authenticated decryption failed (tampering or wrong key)."""


def generate_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def encrypt_aes_gcm(
    *,
    plaintext: bytes,
    dek: bytes,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    if len(dek) != DEK_SIZE:
        raise CryptoError("DEK must be 32 bytes for AES-256-GCM")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError("AES-GCM nonce must be 96 bits (12 bytes)")
    aesgcm = AESGCM(dek)
    return aesgcm.encrypt(nonce, plaintext, associated_data)


def decrypt_aes_gcm(
    *,
    ciphertext: bytes,
    dek: bytes,
    nonce: bytes,
    associated_data: bytes,
) -> bytes:
    if len(dek) != DEK_SIZE:
        raise CryptoError("DEK must be 32 bytes for AES-256-GCM")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError("AES-GCM nonce must be 96 bits (12 bytes)")
    aesgcm = AESGCM(dek)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        raise TamperDetectedError("AES-GCM decryption failed") from exc


def wrap_dek_rsa_oaep(*, dek: bytes, public_key) -> bytes:
    return public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_dek_rsa_oaep(*, wrapped_dek: bytes, private_key) -> bytes:
    try:
        return private_key.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise CryptoError("RSA-OAEP key unwrap failed") from exc


def load_rsa_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_rsa_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return "sha256:" + digest.finalize().hex()[:16]


def build_encrypted_payload(
    *,
    kid: str,
    plaintext: bytes,
    dek: bytes,
    wrapped_dek: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: str,
) -> dict[str, Any]:
    return {
        "version": PAYLOAD_VERSION,
        "alg": ALG_AES_GCM,
        "key_wrap_alg": ALG_RSA_OAEP,
        "kid": kid,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "encrypted_dek": base64.b64encode(wrapped_dek).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": aad,
        "created_at": datetime.now(UTC).isoformat(),
    }


def parse_encrypted_payload(payload: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, str, str]:
    if payload.get("version") != PAYLOAD_VERSION:
        raise CryptoError("Unsupported encrypted payload version")
    if payload.get("alg") != ALG_AES_GCM:
        raise CryptoError("Unsupported symmetric algorithm")
    kid = str(payload.get("kid") or "")
    nonce = base64.b64decode(payload["nonce"])
    wrapped_dek = base64.b64decode(payload["encrypted_dek"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    aad = str(payload.get("aad") or "")
    return kid, nonce, wrapped_dek, ciphertext, aad, kid
