"""Demo key loading and fingerprints (no private key exposure via API)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.config import get_backend_root, get_settings
from app.services import crypto_service

_jwt_private = None
_jwt_public = None
_wrap_private = None
_wrap_public = None


class KeyConfigurationError(Exception):
    pass


def _resolve_key_path(path_str: str | None) -> Path | None:
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_absolute():
        path = get_backend_root() / path
    return path


def jwt_keys_configured() -> bool:
    settings = get_settings()
    return bool(
        _resolve_key_path(settings.jwt_private_key_path)
        and _resolve_key_path(settings.jwt_public_key_path)
        and _resolve_key_path(settings.jwt_private_key_path).is_file()
        and _resolve_key_path(settings.jwt_public_key_path).is_file()
    )


def data_wrap_keys_configured() -> bool:
    settings = get_settings()
    return bool(
        _resolve_key_path(settings.data_key_private_key_path)
        and _resolve_key_path(settings.data_key_public_key_path)
        and _resolve_key_path(settings.data_key_private_key_path).is_file()
        and _resolve_key_path(settings.data_key_public_key_path).is_file()
    )


def load_jwt_private_key():
    global _jwt_private
    if _jwt_private is not None:
        return _jwt_private
    settings = get_settings()
    path = _resolve_key_path(settings.jwt_private_key_path)
    if not path or not path.is_file():
        raise KeyConfigurationError("JWT private key not configured")
    _jwt_private = crypto_service.load_rsa_private_key(str(path))
    return _jwt_private


def load_jwt_public_key():
    global _jwt_public
    if _jwt_public is not None:
        return _jwt_public
    settings = get_settings()
    path = _resolve_key_path(settings.jwt_public_key_path)
    if not path or not path.is_file():
        raise KeyConfigurationError("JWT public key not configured")
    _jwt_public = crypto_service.load_rsa_public_key(str(path))
    return _jwt_public


def load_data_wrap_private_key():
    global _wrap_private
    if _wrap_private is not None:
        return _wrap_private
    settings = get_settings()
    path = _resolve_key_path(settings.data_key_private_key_path)
    if not path or not path.is_file():
        raise KeyConfigurationError("Data wrap private key not configured")
    _wrap_private = crypto_service.load_rsa_private_key(str(path))
    return _wrap_private


def load_data_wrap_public_key():
    global _wrap_public
    if _wrap_public is not None:
        return _wrap_public
    settings = get_settings()
    path = _resolve_key_path(settings.data_key_public_key_path)
    if not path or not path.is_file():
        raise KeyConfigurationError("Data wrap public key not configured")
    _wrap_public = crypto_service.load_rsa_public_key(str(path))
    return _wrap_public


def active_kid() -> str:
    return get_settings().crypto_active_key_id


def jwt_key_status() -> dict:
    settings = get_settings()
    pub_path = _resolve_key_path(settings.jwt_public_key_path)
    if not pub_path or not pub_path.is_file():
        return {"configured": False}
    pub = load_jwt_public_key()
    return {
        "configured": True,
        "kid": f"jwt-{active_kid()}",
        "public_fingerprint": crypto_service.public_key_fingerprint(pub),
        "algorithm": "RS256",
    }


def data_wrap_key_status() -> dict:
    settings = get_settings()
    pub_path = _resolve_key_path(settings.data_key_public_key_path)
    if not pub_path or not pub_path.is_file():
        return {"configured": False}
    pub = load_data_wrap_public_key()
    return {
        "configured": True,
        "kid": active_kid(),
        "public_fingerprint": crypto_service.public_key_fingerprint(pub),
        "key_wrap_alg": crypto_service.ALG_RSA_OAEP,
    }


def reset_cached_keys() -> None:
    global _jwt_private, _jwt_public, _wrap_private, _wrap_public
    _jwt_private = _jwt_public = _wrap_private = _wrap_public = None
