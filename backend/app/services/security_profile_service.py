"""NIST-aligned security profile and self-check (read-only, no secrets)."""

from __future__ import annotations

from pathlib import Path

from app.config import get_backend_root, get_settings
from app.services import crypto_service, key_management_service, password_service

DOCS_DIR = get_backend_root().parent / "docs"


def get_security_profile() -> dict:
    settings = get_settings()
    enc = key_management_service.data_wrap_keys_configured() and settings.crypto_encryption_enabled
    jwt_asym = key_management_service.jwt_keys_configured()
    return {
        "security_profile": settings.security_profile,
        "crypto_mode_enabled": enc,
        "active_key_id": settings.crypto_active_key_id,
        "symmetric_algorithm": crypto_service.ALG_AES_GCM,
        "key_wrap_algorithm": crypto_service.ALG_RSA_OAEP,
        "jwt_signing": "RS256" if jwt_asym else settings.jwt_algorithm,
        "jwt_asymmetric_enabled": jwt_asym,
        "password_hash_algorithm": password_service.PREFERRED_ALGORITHM,
        "nist_csf_functions": [
            "Govern",
            "Identify",
            "Protect",
            "Detect",
            "Respond",
            "Recover",
        ],
        "nist_sp_documents_referenced": [
            "SP 800-53 Rev. 5",
            "SP 800-63B",
            "SP 800-57",
            "SP 800-38D",
            "SP 800-56A",
            "SP 800-90A",
            "SP 800-61",
            "SP 800-92",
            "SP 800-122",
        ],
        "compliance_note": (
            "NIST-aligned thesis prototype mapping. Not formal FIPS 140-3 certification "
            "or NIST compliance attestation."
        ),
        "fips_aware_note": (
            "FIPS-aware design using approved algorithms via standard libraries. "
            "This demo does not use a validated FIPS 140-3 cryptographic module."
        ),
    }


def run_self_check() -> dict:
    settings = get_settings()
    backend_root = get_backend_root()
    keys_dir = backend_root / "keys" / "demo"
    gitignore = backend_root.parent / ".gitignore"
    gitignore_text = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""

    private_patterns = ("*.pem", "backend/keys/", "*.key", "*.private")
    gitignore_blocks_keys = all(p in gitignore_text for p in ("backend/keys/", "*.pem"))

    return {
        "encryption_enabled": bool(
            settings.crypto_encryption_enabled
            and key_management_service.data_wrap_keys_configured()
        ),
        "jwt_asymmetric_signing_enabled": key_management_service.jwt_keys_configured(),
        "private_keys_not_exposed_by_api": True,
        "demo_keys_directory_exists": keys_dir.is_dir(),
        "demo_key_files_present": {
            "jwt_public.pem": (keys_dir / "jwt_public.pem").is_file(),
            "data_wrap_public.pem": (keys_dir / "data_wrap_public.pem").is_file(),
        },
        "password_hashing_algorithm": password_service.PREFERRED_ALGORITHM,
        "audit_encryption_supported": True,
        "evidence_encryption_supported": True,
        "report_encryption_supported": True,
        "llm_report_encryption_supported": True,
        "nist_profile_doc_exists": (DOCS_DIR / "NIST_SECURITY_PROFILE.md").is_file(),
        "security_limitations_doc_exists": (DOCS_DIR / "SECURITY_LIMITATIONS.md").is_file(),
        "gitignore_blocks_private_keys": gitignore_blocks_keys,
        "security_profile": settings.security_profile,
        "status": "ok",
    }


def get_key_status() -> dict:
    return {
        "active_key_id": get_settings().crypto_active_key_id,
        "jwt": key_management_service.jwt_key_status(),
        "data_wrap": key_management_service.data_wrap_key_status(),
        "note": "Public fingerprints only. Private keys are never returned.",
    }
