"""Provider-capability-aware AI credential rotation.

OpenCode Zen inference is supported. External Zen API-key lifecycle remains
provider-managed until an official machine credential-management API is
available.

Never scrapes dashboards, never stores provider login passwords, never treats
locally generated random strings as rotated provider keys, and never prints
credential values.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import os
import tempfile
from typing import Mapping, Protocol
import urllib.error
import urllib.request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / "backend" / ".env"
ENV_KEYS = (
    "AI_CREDENTIAL_ROTATION_ENABLED",
    "AI_CREDENTIAL_ROTATION_PROVIDER",
    "AI_CREDENTIAL_MANAGEMENT_SECRET",
    "AI_PROVIDER",
    "AI_BASE_URL",
    "AI_ASSISTANT_ENABLED",
    "AI_API_KEY",
    "AI_BACKUP_API_KEYS",
    "AI_MODEL",
)
ZEN_PROVIDERS = frozenset({"opencode_zen", "opencode", "zen"})
ZEN_BASE_MARKERS = ("opencode.ai/zen",)
CAP_SUPPORTED = "SUPPORTED"
CAP_PROVIDER_MANAGED = "PROVIDER_MANAGED"
CAP_UNSUPPORTED = "UNSUPPORTED"
ZEN_ACTION = (
    "Create or replace keys at opencode.ai/auth, update local .env, then run "
    "python scripts/rotate_ai_credentials.py --validate"
)


def _env_get(env: Mapping[str, str], key: str) -> str:
    return (env.get(key) or "").strip()


def _truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def detect_provider(env: Mapping[str, str]) -> str:
    explicit = _env_get(env, "AI_CREDENTIAL_ROTATION_PROVIDER").lower()
    if explicit:
        return explicit
    base = _env_get(env, "AI_BASE_URL").lower()
    if any(marker in base for marker in ZEN_BASE_MARKERS):
        return "opencode_zen"
    return "unknown"


def rotation_capability(provider: str) -> str:
    if provider in ZEN_PROVIDERS:
        return CAP_PROVIDER_MANAGED
    if provider == "mock_managed":
        return CAP_SUPPORTED
    return CAP_UNSUPPORTED


def failover_key_count(env: Mapping[str, str]) -> int:
    raw = _env_get(env, "AI_BACKUP_API_KEYS")
    return len([part for part in raw.split(",") if part.strip()])


def _safe_status(
    *,
    status: str,
    provider: str,
    capability: str,
    env: Mapping[str, str],
    action_required: str,
    mutation: bool = False,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "status": status,
        "provider": provider,
        "rotation_capability": capability,
        "automatic_rotation_enabled": _truthy(_env_get(env, "AI_CREDENTIAL_ROTATION_ENABLED")),
        "inference_enabled": _truthy(_env_get(env, "AI_ASSISTANT_ENABLED")),
        "primary_key_configured": bool(_env_get(env, "AI_API_KEY")),
        "failover_configured": failover_key_count(env) > 0,
        "failover_backup_count": failover_key_count(env),
        "action_required": action_required,
        "mutation": mutation,
    }
    if extra:
        result.update(extra)
    return result


class CredentialAdapter(Protocol):
    capability: str

    def create_credential(self) -> tuple[str, str]:
        """Return (credential_id, secret). Caller must not log the secret."""

    def verify_credential(self, secret: str) -> bool: ...

    def revoke_credential(self, credential_id: str) -> bool: ...


@dataclass
class MockManagedAdapter:
    """Test-only adapter proving the SUPPORTED workflow. Not a real provider."""

    capability: str = CAP_SUPPORTED
    created: list[str] | None = None
    revoked: list[str] | None = None
    verify_ok: bool = True
    revoke_ok: bool = True

    def __post_init__(self) -> None:
        self.created = [] if self.created is None else self.created
        self.revoked = [] if self.revoked is None else self.revoked

    def create_credential(self) -> tuple[str, str]:
        cred_id = f"mock-{len(self.created) + 1}"
        self.created.append(cred_id)
        return cred_id, "sk-synthetic-new-managed-key-xxxxxxxx"

    def verify_credential(self, secret: str) -> bool:
        return self.verify_ok and secret.startswith("sk-synthetic-")

    def revoke_credential(self, credential_id: str) -> bool:
        if not self.revoke_ok:
            return False
        self.revoked.append(credential_id)
        return True


def adapter_for(provider: str) -> CredentialAdapter | None:
    if rotation_capability(provider) != CAP_SUPPORTED:
        return None
    if provider == "mock_managed":
        return MockManagedAdapter()
    return None


def atomic_update_env_value(path: Path, key: str, new_value: str) -> None:
    """Replace one assignment, preserve other lines. Never prints values."""
    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines = original.splitlines(keepends=True)
    replaced = False
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith(f"{key}=") and not stripped.startswith("#"):
            nl = "\n" if line.endswith("\n") else ""
            out.append(f"{key}={new_value}{nl}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        suffix = "" if original.endswith("\n") or not original else "\n"
        out.append(f"{suffix}{key}={new_value}\n")
    text = "".join(out)
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
        raise


def preflight(env: Mapping[str, str]) -> dict[str, object]:
    provider = detect_provider(env)
    capability = rotation_capability(provider)
    if capability == CAP_PROVIDER_MANAGED:
        return _safe_status(
            status="PROVIDER_MANAGED",
            provider=provider,
            capability=capability,
            env=env,
            action_required=ZEN_ACTION,
        )
    if capability == CAP_UNSUPPORTED:
        return _safe_status(
            status="UNSUPPORTED",
            provider=provider,
            capability=capability,
            env=env,
            action_required="No official machine credential-management API for this provider.",
        )
    if not _truthy(_env_get(env, "AI_CREDENTIAL_ROTATION_ENABLED")):
        return _safe_status(
            status="SUPPORTED_DISABLED",
            provider=provider,
            capability=capability,
            env=env,
            action_required="Set AI_CREDENTIAL_ROTATION_ENABLED=true to run automatic rotation.",
        )
    if not _env_get(env, "AI_CREDENTIAL_MANAGEMENT_SECRET"):
        return _safe_status(
            status="FAILED",
            provider=provider,
            capability=capability,
            env=env,
            action_required="Configure AI_CREDENTIAL_MANAGEMENT_SECRET locally.",
        )
    return _safe_status(
        status="READY",
        provider=provider,
        capability=capability,
        env=env,
        action_required="Run --dry-run, then --execute after explicit approval.",
    )


def dry_run(env: Mapping[str, str]) -> dict[str, object]:
    result = preflight(env)
    result["mode"] = "dry-run"
    result["mutation"] = False
    return result


def execute(
    env: Mapping[str, str],
    *,
    adapter: CredentialAdapter | None = None,
    env_path: Path | None = None,
) -> dict[str, object]:
    result = preflight(env)
    result["mode"] = "execute"
    result["mutation"] = False
    capability = str(result["rotation_capability"])
    if capability != CAP_SUPPORTED or result["status"] != "READY":
        result["create_attempted"] = False
        result["revoke_attempted"] = False
        return result

    adapter = adapter or adapter_for(detect_provider(env))
    if adapter is None or adapter.capability != CAP_SUPPORTED:
        result["status"] = "FAILED"
        result["action_required"] = "No supported provider adapter is registered."
        result["create_attempted"] = False
        result["revoke_attempted"] = False
        return result

    old_id = "local-primary"
    new_id, new_secret = adapter.create_credential()
    result["create_attempted"] = True
    if not adapter.verify_credential(new_secret):
        result["status"] = "FAILED"
        result["action_required"] = "New credential failed verification; old key unchanged."
        return result
    target = env_path or ENV_FILE
    atomic_update_env_value(target, "AI_API_KEY", new_secret)
    if not adapter.verify_credential(new_secret):
        result["status"] = "FAILED"
        result["action_required"] = "Post-update verification failed."
        return result
    revoked = adapter.revoke_credential(old_id)
    result["revoke_attempted"] = True
    result["mutation"] = True
    result["new_credential_id"] = new_id
    if not revoked:
        result["status"] = "PARTIAL"
        result["action_required"] = "New key is active; old credential revocation required."
        return result
    result["status"] = "SUCCEEDED"
    result["action_required"] = "None."
    return result


def validate_inference(
    env: Mapping[str, str],
    *,
    opener=urllib.request.urlopen,
) -> dict[str, object]:
    provider = detect_provider(env)
    capability = rotation_capability(provider)
    key = _env_get(env, "AI_API_KEY")
    base = _env_get(env, "AI_BASE_URL").rstrip("/")
    if not key or not base:
        return _safe_status(
            status="FAILED",
            provider=provider,
            capability=capability,
            env=env,
            action_required="Set AI_API_KEY and AI_BASE_URL, then retry --validate.",
            extra={"connectivity": False},
        )
    url = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    payload = json.dumps(
        {
            "model": _env_get(env, "AI_MODEL") or "deepseek-v4-flash-free",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }
    ).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Authorization", f"Bearer {key}")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", "PrivacyTrace-NP/1.0")
    try:
        with opener(request, timeout=30) as response:
            http_status = getattr(response, "status", 200)
            response.read()
        return _safe_status(
            status="PASS",
            provider=provider,
            capability=capability,
            env=env,
            action_required="None.",
            extra={"connectivity": True, "http_status": http_status},
        )
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except Exception:
            pass
        rejected = exc.code == 401
        return _safe_status(
            status="FAILED",
            provider=provider,
            capability=capability,
            env=env,
            action_required=(
                "Provider rejected the configured inference key."
                if rejected
                else "Provider connectivity or model request failed. Retry --validate."
            ),
            extra={"connectivity": True, "http_status": exc.code},
        )
    except (TimeoutError, urllib.error.URLError):
        return _safe_status(
            status="FAILED",
            provider=provider,
            capability=capability,
            env=env,
            action_required="Provider connectivity failed. Retry --validate.",
            extra={"connectivity": False},
        )


def _load_dotenv_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key not in ENV_KEYS:
            continue
        values[key] = value.strip().strip('"').strip("'")
    return values


def load_runtime_env() -> dict[str, str]:
    env = {key: os.environ.get(key, "") for key in ENV_KEYS}
    env.update(_load_dotenv_values(ENV_FILE))
    return env


def _print_result(result: dict[str, object]) -> int:
    order = (
        "status",
        "provider",
        "rotation_capability",
        "automatic_rotation_enabled",
        "inference_enabled",
        "primary_key_configured",
        "failover_configured",
        "failover_backup_count",
        "connectivity",
        "http_status",
        "mutation",
        "create_attempted",
        "revoke_attempted",
        "action_required",
    )
    for key in order:
        if key in result:
            print(f"{key}={result[key]}")
    status = str(result.get("status") or "")
    if status in {"PROVIDER_MANAGED", "UNSUPPORTED", "SUPPORTED_DISABLED", "READY", "PASS", "SUCCEEDED"}:
        return 0
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provider-capability-aware AI credential rotation")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--validate", action="store_true", help="Verify configured inference key without printing it")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    env = load_runtime_env()
    if args.preflight:
        return _print_result(preflight(env))
    if args.dry_run:
        return _print_result(dry_run(env))
    if args.validate:
        return _print_result(validate_inference(env))
    return _print_result(execute(env))


if __name__ == "__main__":
    raise SystemExit(main())
