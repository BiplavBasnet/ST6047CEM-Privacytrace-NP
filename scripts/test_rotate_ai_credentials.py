"""Capability-aware rotation proofs. Synthetic env only; no live Zen create/revoke."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rotate_ai_credentials import (
    MockManagedAdapter,
    dry_run,
    execute,
    preflight,
    validate_inference,
)


ZEN_ENV = {
    "AI_CREDENTIAL_ROTATION_ENABLED": "false",
    "AI_CREDENTIAL_ROTATION_PROVIDER": "opencode_zen",
    "AI_BASE_URL": "https://opencode.ai/zen/v1",
    "AI_ASSISTANT_ENABLED": "true",
    "AI_API_KEY": "sk-synthetic-primary-inference-key-xxxx",
    "AI_BACKUP_API_KEYS": "sk-synthetic-backup-one-xxxxxxxxxxxx,sk-synthetic-backup-two-xxxxxxxxxxxx",
    "AI_CREDENTIAL_MANAGEMENT_SECRET": "",
}


class ZenProviderManagedTests(unittest.TestCase):
    def test_zen_capability_is_provider_managed(self) -> None:
        result = preflight(ZEN_ENV)
        self.assertEqual(result["status"], "PROVIDER_MANAGED")
        self.assertEqual(result["rotation_capability"], "PROVIDER_MANAGED")
        self.assertIs(result["mutation"], False)
        self.assertIs(result["inference_enabled"], True)
        self.assertIs(result["failover_configured"], True)
        self.assertEqual(result["failover_backup_count"], 2)
        self.assertIs(result["automatic_rotation_enabled"], False)

    def test_zen_execute_does_not_create_or_revoke(self) -> None:
        adapter = MockManagedAdapter()
        result = execute(ZEN_ENV, adapter=adapter)
        self.assertEqual(result["status"], "PROVIDER_MANAGED")
        self.assertIs(result["create_attempted"], False)
        self.assertIs(result["revoke_attempted"], False)
        self.assertEqual(adapter.created, [])
        self.assertEqual(adapter.revoked, [])

    def test_dry_run_no_mutation(self) -> None:
        result = dry_run(ZEN_ENV)
        self.assertIs(result["mutation"], False)
        self.assertEqual(result["status"], "PROVIDER_MANAGED")

    def test_unknown_provider_unsupported(self) -> None:
        result = preflight({"AI_CREDENTIAL_ROTATION_PROVIDER": "unknown-vendor"})
        self.assertEqual(result["status"], "UNSUPPORTED")
        self.assertEqual(result["rotation_capability"], "UNSUPPORTED")

    def test_no_raw_credentials_in_status(self) -> None:
        result = preflight(ZEN_ENV)
        blob = " ".join(str(v) for v in result.values())
        self.assertNotIn("sk-synthetic-primary-inference-key-xxxx", blob)
        self.assertNotIn("sk-synthetic-backup-one-xxxxxxxxxxxx", blob)


class MockSupportedWorkflowTests(unittest.TestCase):
    def test_supported_adapter_rotates(self) -> None:
        env = {
            "AI_CREDENTIAL_ROTATION_ENABLED": "true",
            "AI_CREDENTIAL_ROTATION_PROVIDER": "mock_managed",
            "AI_CREDENTIAL_MANAGEMENT_SECRET": "sk-synthetic-management-not-used",
            "AI_ASSISTANT_ENABLED": "true",
            "AI_API_KEY": "sk-synthetic-old-primary-xxxxxxxxxxxx",
            "AI_BACKUP_API_KEYS": "sk-synthetic-backup-one-xxxxxxxxxxxx",
        }
        adapter = MockManagedAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("AI_API_KEY=sk-synthetic-old-primary-xxxxxxxxxxxx\nOTHER=keep\n", encoding="utf-8")
            result = execute(env, adapter=adapter, env_path=path)
            self.assertEqual(result["status"], "SUCCEEDED")
            self.assertIs(result["mutation"], True)
            self.assertEqual(adapter.created, ["mock-1"])
            self.assertEqual(adapter.revoked, ["local-primary"])
            text = path.read_text(encoding="utf-8")
            self.assertIn("OTHER=keep", text)
            self.assertIn("AI_API_KEY=sk-synthetic-new-managed-key-xxxxxxxx", text)
            self.assertNotIn(str(result.get("action_required")), env["AI_CREDENTIAL_MANAGEMENT_SECRET"])


class ValidateTests(unittest.TestCase):
    def test_validate_pass_without_logging_key(self) -> None:
        class FakeResp:
            status = 200

            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(request, timeout=15):
            self.assertEqual(request.get_method(), "POST")
            self.assertTrue(str(request.full_url).endswith("/chat/completions"))
            self.assertTrue(request.get_header("Authorization").startswith("Bearer "))
            self.assertEqual(request.get_header("User-agent"), "PrivacyTrace-NP/1.0")
            self.assertNotIn("sk-synthetic-primary-inference-key-xxxx", str(request.full_url))
            return FakeResp()

        result = validate_inference(ZEN_ENV, opener=opener)
        self.assertEqual(result["status"], "PASS")
        self.assertIs(result["connectivity"], True)
        blob = " ".join(str(v) for v in result.values())
        self.assertNotIn("sk-synthetic-primary-inference-key-xxxx", blob)

    def test_validate_http_error(self) -> None:
        def opener(request, timeout=15):
            raise HTTPError(request.full_url, 401, "nope", hdrs=None, fp=BytesIO())

        result = validate_inference(ZEN_ENV, opener=opener)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["http_status"], 401)
        self.assertIs(result["connectivity"], True)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
