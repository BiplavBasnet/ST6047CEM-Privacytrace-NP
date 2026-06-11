"""Repository path and content safety for controlled remediation code context."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from app.config import get_backend_root, get_settings
from app.services import audit_safety_service

_BLOCKED_BASENAMES = frozenset({".env", ".env.local", ".env.production", ".env.development"})
_BLOCKED_EXTENSIONS = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".crt",
        ".cer",
        ".der",
        ".env",
        ".secret",
        ".secrets",
    }
)
_BLOCKED_PATH_PARTS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})


def _allowlist_entries() -> list[str]:
    raw = getattr(get_settings(), "remediation_repo_allowlist", "") or ""
    return [entry.strip().replace("\\", "/").strip("/") for entry in raw.split(",") if entry.strip()]


def _normalise_repo_path(path: str) -> str:
    cleaned = str(path or "").strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _is_reparse(path: Path) -> bool:
    try:
        stat = path.lstat()
    except OSError:
        return False
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)


def _allowlist_roots() -> list[Path]:
    backend_raw = get_backend_root()
    if _is_reparse(backend_raw):
        return []
    backend = backend_raw.resolve()
    roots: list[Path] = []
    for entry in _allowlist_entries():
        root = Path(entry)
        lexical = root if root.is_absolute() else backend / root
        current = Path(lexical.anchor)
        unsafe = False
        for part in lexical.parts[1:]:
            current /= part
            if current.exists() and _is_reparse(current):
                unsafe = True
                break
        if not unsafe:
            roots.append(lexical.resolve())
    return roots


def resolve_safe_repo_path(path: str, *, require_file: bool = True) -> Path:
    """Resolve a relative candidate under a configured root without following escapes."""
    assert_safe_repo_path(path)
    relative = Path(_normalise_repo_path(path))
    backend_candidate = get_backend_root() / relative
    for root in _allowlist_roots():
        for candidate in (backend_candidate, root / relative):
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            current = root
            if _is_reparse(current):
                continue
            escaped = False
            for part in candidate.relative_to(root).parts:
                current /= part
                if current.exists() and _is_reparse(current):
                    escaped = True
                    break
            if escaped:
                continue
            try:
                resolved = candidate.resolve(strict=require_file)
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if not require_file or resolved.is_file():
                return resolved
    raise ValueError("Path is missing or escapes the remediation repository allowlist.")


def is_path_allowed(path: str) -> bool:
    """Return True when path is under the configured remediation allowlist."""
    normalised = _normalise_repo_path(path)
    if not normalised:
        return False
    if Path(normalised).is_absolute() or not _allowlist_roots():
        return False
    try:
        resolve_safe_repo_path(normalised, require_file=False)
        return True
    except ValueError:
        return False


def assert_safe_repo_path(path: str) -> None:
    """Reject traversal, secret files, and other unsafe repository paths."""
    normalised = _normalise_repo_path(path)
    if not normalised:
        raise ValueError("Repository path is empty.")

    if os.path.isabs(normalised) or Path(normalised).is_absolute() or normalised.startswith("~"):
        raise ValueError("Absolute or home-relative repository paths are not allowed.")

    pure = PurePosixPath(normalised)
    if ".." in pure.parts:
        raise ValueError("Path traversal is not allowed.")

    basename = pure.name.lower()
    if basename in _BLOCKED_BASENAMES:
        raise ValueError(".env files cannot be accessed for remediation context.")

    suffix = pure.suffix.lower()
    if suffix in _BLOCKED_EXTENSIONS:
        raise ValueError(f"Blocked file extension for remediation context: {suffix}")

    lowered_parts = {part.lower() for part in pure.parts}
    if lowered_parts & _BLOCKED_PATH_PARTS:
        raise ValueError("Path references a blocked repository area.")

    if "private" in basename and "key" in basename:
        raise ValueError("Private key files cannot be accessed for remediation context.")

    if not _allowlist_entries():
        raise ValueError("Remediation repository allowlist is empty.")


def scan_text_for_secrets(text: str) -> list[str]:
    """Return violation codes for sensitive content in repository/code context."""
    return audit_safety_service.scan_text_for_sensitive(text or "")


if __name__ == "__main__":
    assert not is_path_allowed("src/app.py")  # empty allowlist -> deny
    try:
        assert_safe_repo_path("../.env")
        raise AssertionError("expected traversal/.env block")
    except ValueError:
        pass
    assert scan_text_for_secrets("no secrets here") == []
