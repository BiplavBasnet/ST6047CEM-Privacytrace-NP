"""Patch safety gates for controlled remediation workspaces."""

from __future__ import annotations

from pathlib import Path

from app.config import get_settings
from app.services import audit_safety_service, remediation_repository_safety_service as repo_safety

_BLOCKED_BASENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
}
_BLOCKED_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
_DESTRUCTIVE_MARKERS = (
    "rm -rf /",
    "drop database",
    "git push",
    "kubectl apply",
    "disable audit",
    "disable authentication",
    "disable authorization",
    "disable masking",
)


class PatchSafetyError(ValueError):
    pass


def validate_patch_payload(*, file_paths: list[str], diff_text: str) -> None:
    settings = get_settings()
    if len(file_paths) > settings.remediation_patch_max_files:
        raise PatchSafetyError("Patch exceeds allowlisted file count.")
    if diff_text.count("\n") > settings.remediation_patch_max_lines:
        raise PatchSafetyError("Patch exceeds allowlisted changed-line budget.")

    lower = diff_text.lower()
    for marker in _DESTRUCTIVE_MARKERS:
        if marker in lower:
            raise PatchSafetyError(f"Destructive or production-oriented instruction blocked: {marker}")

    hits = audit_safety_service.scan_text_for_sensitive(diff_text)
    if hits:
        raise PatchSafetyError("Patch text contains sensitive-shaped values.")

    for path in file_paths:
        name = Path(path).name.lower()
        if name in _BLOCKED_BASENAMES or Path(path).suffix.lower() in _BLOCKED_SUFFIXES:
            raise PatchSafetyError(f"Blocked path class: {path}")
        if ".." in Path(path).parts:
            raise PatchSafetyError("Path traversal blocked.")
        # If allowlist configured, enforce it; otherwise still block secret paths.
        allowlist = (getattr(settings, "remediation_repo_allowlist", "") or "").strip()
        if allowlist:
            repo_safety.assert_safe_repo_path(path)
