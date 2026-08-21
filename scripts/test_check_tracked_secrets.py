"""Targeted proofs for the narrow synthetic-secret allowlist."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_tracked_secrets import scan_path, scan_text


class ScanTextTests(unittest.TestCase):
    def test_approved_synthetic_prefix_passes(self) -> None:
        text = 'text: API key sk-testnpfake00000001abcdefghijklmnop copied into log\n'
        self.assertEqual(scan_text("backend/app/evaluation_data/instance_level_cases_v2.yaml", text), [])

    def test_approved_synthetic_frontend_prefix_passes(self) -> None:
        text = 'const rawSecret = "sk-synthetic-raw-secret-value";\n'
        self.assertEqual(scan_text("frontend/src/__tests__/PrivacyResponsePanels.test.tsx", text), [])

    def test_approved_exact_fixture_token_passes(self) -> None:
        text = 'assert rule.pattern.search("sk-abcdefghijklmnopqrstuvwxyz123456")\n'
        self.assertEqual(scan_text("backend/app/tests/test_phase5.py", text), [])

    def test_pem_header_only_passes(self) -> None:
        text = 'raw_value: "-----BEGIN PRIVATE KEY-----"\n'
        self.assertEqual(scan_text("backend/app/evaluation_data/instance_level_cases.yaml", text), [])

    def test_pem_with_body_fails(self) -> None:
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        text = begin + "\nMIIFakeBodyNotARealKeyAAAAAAAAAAAAAAA=\n" + end + "\n"
        hits = scan_text("backend/app/services/ordinary.py", text)
        self.assertTrue(any("PEM" in h for h in hits))

    def test_ordinary_source_sk_fails(self) -> None:
        token = "sk-" + "thisisnotarealkeybutlookslikeone123456"
        hits = scan_text(
            "backend/app/services/ordinary.py",
            f'API_KEY = "{token}"\n',
        )
        self.assertTrue(any("sk- token" in h for h in hits))

    def test_unapproved_test_file_sk_fails(self) -> None:
        token = "sk-" + "unapprovedlookslivevalue0000000001"
        hits = scan_text(
            "backend/app/tests/test_unapproved_secret.py",
            f'TOKEN = "{token}"\n',
        )
        self.assertTrue(any("sk- token" in h for h in hits))

    def test_unapproved_evaluation_file_sk_fails(self) -> None:
        token = "sk-" + "unapprovedlookslivevalue0000000002"
        hits = scan_text(
            "backend/app/evaluation_data/extra.yaml",
            f'raw_value: "{token}"\n',
        )
        self.assertTrue(any("sk- token" in h for h in hits))

    def test_directory_name_grants_no_exemption(self) -> None:
        token = "sk-" + "unapprovedlookslivevalue0000000003"
        hits = scan_text(
            "frontend/src/__tests__/leaked.ts",
            f'export const k = "{token}";\n',
        )
        self.assertTrue(hits)

    def test_clean_source_passes(self) -> None:
        self.assertEqual(scan_text("README.md", "No credentials here.\n"), [])


class ScanPathTests(unittest.TestCase):
    def test_tracked_env_filename_fails(self) -> None:
        hits = scan_path(Path(".env"), ".env")
        self.assertEqual(hits, [".env: tracked .env file"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
