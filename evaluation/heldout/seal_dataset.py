"""Write sealed held-out inputs + ground truth. Refuses to overwrite existing files."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
APPLICATION_FREEZE_SHA = "8b22b670a82b61882cb841b10a9f4d364de30bc7"
NEPALFIN_LAB_SHA = "ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee"

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJob2xkb3V0LXpzIn0.aGVsZG91dC1zaWduYXR1cmU"
API_KEY = "sk_live_HOHELD0UTKEYABCDEFGHIJKLMNOP"


def _det(case_id, source_type, *, text=None, structured=None, environment=None):
    row = {"case_id": case_id, "family": "detection", "source_type": source_type}
    if text is not None:
        row["text"] = text
    if structured is not None:
        row["structured"] = structured
    if environment is not None:
        row["environment"] = environment
    return row


def _gt_det(case_id, expected, *, raw=None, raws=None, label="positive"):
    row = {
        "case_id": case_id,
        "family": "detection",
        "label": label,
        "expected_instances": expected,
        "exclude_from_denominator": False,
    }
    if raw:
        row["raw_value"] = raw
    if raws:
        row["raw_values"] = raws
    return row


def _unsafe(stype):
    return {"sensitive_type": stype, "exposure_decision": "unsafe_exposure"}


def detection_pairs():
    inputs = []
    truth = []

    def add(inp, gt):
        inputs.append(inp)
        truth.append(gt)

    add(
        _det("HO-001", "application_log", text="KYC callback wrote customer phone 9802111001 to the wallet trace"),
        _gt_det("HO-001", [_unsafe("phone_number")], raw="9802111001"),
    )
    add(
        _det("HO-002", "application_log", text="Sender 9802111002 and receiver 9802111003 both appeared in the remittance log"),
        _gt_det("HO-002", [_unsafe("phone_number"), _unsafe("phone_number")], raws=["9802111002", "9802111003"]),
    )
    add(
        _det("HO-003", "file_export", text="Nightly dump included wallet WALLET-NP-HO003 for the batch file"),
        _gt_det("HO-003", [_unsafe("wallet_identifier")], raw="WALLET-NP-HO003"),
    )
    add(
        _det("HO-004", "third_party_log", text="Analytics vendor stored transaction TXN-NP-2026-88004"),
        _gt_det("HO-004", [_unsafe("transaction_reference")], raw="TXN-NP-2026-88004"),
    )
    add(
        _det("HO-005", "application_log", text=f"Authorization: Bearer {JWT} copied into the request logger"),
        _gt_det("HO-005", [_unsafe("bearer_token")], raw=JWT),
    )
    add(
        _det("HO-006", "error_message", text=f"Stack trace printed api key {API_KEY} to stderr"),
        _gt_det("HO-006", [_unsafe("api_key")], raw=API_KEY),
    )
    add(
        _det("HO-007", "cache_entry", text="-----BEGIN PRIVATE KEY----- captured in a Redis cache snapshot"),
        _gt_det("HO-007", [_unsafe("private_key")], raw="-----BEGIN PRIVATE KEY-----"),
    )
    add(
        _det("HO-008", "query_string", structured={"phone": "9802111008"}),
        _gt_det("HO-008", [_unsafe("phone_number")], raw="9802111008"),
    )
    add(
        _det("HO-009", "application_log", text="User email heldout.user09@nepalfin.test leaked in the auth log"),
        _gt_det("HO-009", [_unsafe("email_address")], raw="heldout.user09@nepalfin.test"),
    )
    add(
        _det("HO-010", "application_log", text="Wallet WALLET-NP-HO010 copied into the application trace"),
        _gt_det("HO-010", [_unsafe("wallet_identifier")], raw="WALLET-NP-HO010"),
    )
    add(
        _det("HO-011", "application_log", text="Transaction TXN-NP-2026-88011 copied into the application trace"),
        _gt_det("HO-011", [_unsafe("transaction_reference")], raw="TXN-NP-2026-88011"),
    )
    add(
        _det("HO-012", "webhook_payload", text="Webhook body included customer phone 9802111012"),
        _gt_det("HO-012", [_unsafe("phone_number")], raw="9802111012"),
    )
    add(
        _det("HO-013", "file_export", text=f"Export file contained merchant api key {API_KEY}HO13"),
        _gt_det("HO-013", [_unsafe("api_key")], raw=f"{API_KEY}HO13"),
    )
    add(
        _det("HO-014", "third_party_log", text="Third-party sink stored email heldout.user14@nepalfin.test"),
        _gt_det("HO-014", [_unsafe("email_address")], raw="heldout.user14@nepalfin.test"),
    )
    add(
        _det(
            "HO-015",
            "application_log",
            text="Transfer log phone 9802111015 wallet WALLET-NP-HO015 in one line",
        ),
        _gt_det(
            "HO-015",
            [_unsafe("phone_number"), _unsafe("wallet_identifier")],
            raws=["9802111015", "WALLET-NP-HO015"],
        ),
    )
    add(
        _det(
            "HO-016",
            "application_log",
            text="Phones 9802111016 9802111017 9802111018 in the same debug line",
        ),
        _gt_det(
            "HO-016",
            [_unsafe("phone_number"), _unsafe("phone_number"), _unsafe("phone_number")],
            raws=["9802111016", "9802111017", "9802111018"],
        ),
    )
    add(
        _det("HO-017", "request_header_log", text=f"Authorization: Bearer {JWT} persisted to the header log"),
        _gt_det("HO-017", [_unsafe("bearer_token")], raw=JWT),
    )
    add(
        _det("HO-018", "ai_prompt_context", text="Prompt context included customer phone 9802111018"),
        _gt_det("HO-018", [_unsafe("phone_number")], raw="9802111018"),
    )
    add(
        _det("HO-019", "cache_entry", text="Cache snapshot stored wallet WALLET-NP-HO019"),
        _gt_det("HO-019", [_unsafe("wallet_identifier")], raw="WALLET-NP-HO019"),
    )
    add(
        _det("HO-020", "webhook_payload", text="Merchant webhook included TXN-NP-2026-88020"),
        _gt_det("HO-020", [_unsafe("transaction_reference")], raw="TXN-NP-2026-88020"),
    )
    add(
        _det("HO-021", "error_message", text="Exception dumped customer phone 9802111021"),
        _gt_det("HO-021", [_unsafe("phone_number")], raw="9802111021"),
    )
    add(
        _det("HO-022", "runtime_log", text="Runtime connector line wallet WALLET-NP-HO022"),
        _gt_det("HO-022", [_unsafe("wallet_identifier")], raw="WALLET-NP-HO022"),
    )
    add(
        _det("HO-023", "error_message", text=f"Authorization: Bearer {JWT} printed during panic"),
        _gt_det("HO-023", [_unsafe("bearer_token")], raw=JWT),
    )
    add(
        _det(
            "HO-024",
            "application_log",
            text="Email heldout.user24@nepalfin.test and phone 9802111024 in one log",
        ),
        _gt_det(
            "HO-024",
            [_unsafe("email_address"), _unsafe("phone_number")],
            raws=["heldout.user24@nepalfin.test", "9802111024"],
        ),
    )
    add(
        _det("HO-025", "file_export", text="CSV export row phone 9802111025"),
        _gt_det("HO-025", [_unsafe("phone_number")], raw="9802111025"),
    )
    add(
        _det("HO-026", "application_log", text="Card 4111111111111111 written to the application trace"),
        _gt_det("HO-026", [_unsafe("payment_card_number")], raw="4111111111111111"),
    )
    add(
        _det("HO-027", "query_string", text="https://wallet.nepalfin.test/pay?phone=9802111027"),
        _gt_det("HO-027", [_unsafe("phone_number")], raw="9802111027"),
    )
    add(
        _det("HO-028", "third_party_log", text="SIEM import stored wallet WALLET-NP-HO028"),
        _gt_det("HO-028", [_unsafe("wallet_identifier")], raw="WALLET-NP-HO028"),
    )
    add(
        _det("HO-029", "application_log", text=f"api key {API_KEY}HO29 logged by the payment adapter"),
        _gt_det("HO-029", [_unsafe("api_key")], raw=f"{API_KEY}HO29"),
    )
    add(
        _det("HO-030", "file_export", text="Export contained email heldout.user30@nepalfin.test"),
        _gt_det("HO-030", [_unsafe("email_address")], raw="heldout.user30@nepalfin.test"),
    )

    add(
        _det("HO-031", "application_log", structured={"contact_number": "1712345678"}),
        _gt_det("HO-031", [], label="negative"),
    )
    add(
        _det("HO-032", "request_body", structured={"card_number": "4111111111111112"}),
        _gt_det("HO-032", [], label="negative"),
    )
    add(
        _det("HO-033", "request_body", structured={"verification_code": "839201"}),
        _gt_det("HO-033", [], label="negative"),
    )
    add(
        _det("HO-034", "database_field", structured={"password": "****HO34"}),
        _gt_det(
            "HO-034",
            [{"sensitive_type": "password", "exposure_decision": "already_safely_masked"}],
            raw="****HO34",
            label="negative",
        ),
    )
    add(
        _det("HO-035", "request_header", text=f"Authorization: Bearer {JWT}"),
        _gt_det(
            "HO-035",
            [{"sensitive_type": "bearer_token", "exposure_decision": "legitimate_processing"}],
            raw=JWT,
            label="negative",
        ),
    )
    add(
        _det("HO-036", "database_field", structured={"password": "HeldOutPass36!"}),
        _gt_det(
            "HO-036",
            [{"sensitive_type": "password", "exposure_decision": "legitimate_processing"}],
            raw="HeldOutPass36!",
            label="negative",
        ),
    )
    add(
        _det("HO-037", "application_log", text="Wallet transfer completed successfully for the demo customer account"),
        _gt_det("HO-037", [], label="negative"),
    )
    add(
        _det("HO-038", "application_log", structured={"contact_number": "1700000000"}),
        _gt_det("HO-038", [], label="negative"),
    )
    add(
        _det("HO-039", "application_log", structured={"contact_number": "1212345678"}),
        _gt_det("HO-039", [], label="negative"),
    )
    add(
        _det("HO-040", "application_log", text="Order 88040 settled without customer identifiers"),
        _gt_det("HO-040", [], label="negative"),
    )
    add(
        _det("HO-041", "application_log", text="Health check ok replica=3 latency_ms=12"),
        _gt_det("HO-041", [], label="negative"),
    )
    add(
        _det("HO-042", "application_log", text="Batch job finished 1200 remittance rows with no payload dump"),
        _gt_det("HO-042", [], label="negative"),
    )
    add(
        _det("HO-043", "application_log", text="User identifier was written as user at nepalfin test (not an email)"),
        _gt_det("HO-043", [], label="negative"),
    )
    add(
        _det("HO-044", "application_log", text="Short code 9802 is a product SKU not a phone number"),
        _gt_det("HO-044", [], label="negative"),
    )
    add(
        _det("HO-045", "application_log", text="Correlation id 7f3a9c2e-held-out-045-aaaa-bbbbccccdddd"),
        _gt_det("HO-045", [], label="negative"),
    )
    add(
        _det("HO-046", "application_log", text="Authorization: Bearer **** already redacted before persist"),
        _gt_det("HO-046", [], label="negative"),
    )
    add(
        _det("HO-047", "database_field", structured={"password": "********"}),
        _gt_det(
            "HO-047",
            [{"sensitive_type": "password", "exposure_decision": "already_safely_masked"}],
            label="negative",
        ),
    )
    add(
        _det("HO-048", "request_body", structured={"card_number": "1234 5678 9012 3456"}),
        _gt_det("HO-048", [], label="negative"),
    )
    add(
        _det("HO-049", "database_field", structured={"phone": "9802111049"}),
        _gt_det(
            "HO-049",
            [{"sensitive_type": "phone_number", "exposure_decision": "legitimate_processing"}],
            raw="9802111049",
            label="negative",
        ),
    )
    add(
        _det("HO-050", "application_log", text="Metrics scrape success namespace=wallet replica=b"),
        _gt_det("HO-050", [], label="negative"),
    )
    return inputs, truth


def rca_pairs():
    # A/B variants with held-out IDs. Signals only in inputs; causes only in GT.
    specs = [
        ("HO-051", ["authorization_header_in_log", "bearer_token", "request_header_log", "sast_header_logger"], [],
         "unsafe_request_header_logging", "request logging middleware"),
        ("HO-052", ["phone_in_body", "request_body_log", "sast_body_logger"], [],
         "unsafe_request_body_logging", "request logging middleware"),
        ("HO-053", ["response_body_log", "sast_response_logger", "token_in_response"], [],
         "unsafe_response_body_logging", "request logging middleware"),
        ("HO-054", ["masking_config_gap", "raw_value_persisted", "redaction_rule_absent"], [],
         "missing_redaction_rule", "logging configuration"),
        ("HO-055", ["log_before_redact", "order_violation", "serialise_before_mask"], [],
         "incorrect_redaction_order", "logging configuration"),
        ("HO-056", ["debug_level_enabled", "dev_profile_active", "verbose_logger"], [],
         "debug_logging_enabled", "request logging middleware"),
        ("HO-057", ["access_log_query", "query_string_log", "url_with_secret"], [],
         "query_string_logging", "request logging middleware"),
        ("HO-058", ["gateway_raw_capture", "ingress_mirror", "proxy_full_headers"], [],
         "proxy_log_overcollection", "logging configuration"),
        ("HO-059", ["agent_sensitive_field", "apm_payload_capture", "trace_body_enabled"], [],
         "apm_agent_capture", "logging configuration"),
        ("HO-060", ["error_payload_log", "exception_dump", "stack_with_request"], [],
         "error_handler_serialisation", "logging configuration"),
        ("HO-061", ["export_pipeline", "report_unmasked_field", "transform_bypass"], [],
         "unsafe_report_transformation", "logging configuration"),
        ("HO-062", ["config_scan_hit", "config_secret_plaintext", "env_committed"], [],
         "secret_in_configuration", "logging configuration"),
        ("HO-063", ["authorization_header_in_log", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "unsafe_request_header_logging", "request logging middleware"),
        ("HO-064", ["phone_in_body", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "unsafe_request_body_logging", "request logging middleware"),
        ("HO-065", ["debug_level_enabled", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "debug_logging_enabled", "request logging middleware"),
        ("HO-066", ["access_log_query", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "query_string_logging", "request logging middleware"),
        ("HO-067", ["gateway_raw_capture", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "proxy_log_overcollection", "logging configuration"),
        ("HO-068", ["agent_sensitive_field", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "apm_agent_capture", "logging configuration"),
        ("HO-069", ["error_payload_log", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "error_handler_serialisation", "logging configuration"),
        ("HO-070", ["config_scan_hit", "redaction_rule_absent", "masking_config_gap"],
         ["already_masked_preview"], "secret_in_configuration", "logging configuration"),
    ]
    inputs, truth = [], []
    for case_id, signals, contra, cause, component in specs:
        inputs.append({
            "case_id": case_id,
            "family": "rca",
            "evidence_signals": signals,
            "contradicting_signals": contra,
        })
        truth.append({
            "case_id": case_id,
            "family": "rca",
            "ground_truth_root_cause": cause,
            "ground_truth_component": component,
            "exclude_from_denominator": False,
        })
    return inputs, truth


def scanner_pairs():
    inputs = [
        {
            "case_id": "HO-071",
            "family": "scanner_controlled",
            "label": "CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION",
            "payload": {
                "scanner": "generic_secret_scanner",
                "repository": "nepalfin-wallet",
                "findings": [{
                    "rule": "api-key-pattern",
                    "file": "config/wallet.example.env",
                    "masked_secret": "pk_test_****_heldout",
                    "severity": "high",
                }],
            },
        },
        {
            "case_id": "HO-072",
            "family": "scanner_controlled",
            "label": "CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION",
            "payload": [{
                "RuleID": "generic-api-key",
                "File": "config/wallet_service.example.env",
                "Redacted": "pk_test_np_****_88072",
            }],
        },
        {
            "case_id": "HO-073",
            "family": "scanner_controlled",
            "label": "CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION",
            "payload": {
                "tool": "semgrep-shaped",
                "results": [{"path": "app/logger.py", "extra": {"message": "header logger without redaction"}}],
            },
        },
        {
            "case_id": "HO-074",
            "family": "scanner_controlled",
            "label": "CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION",
            "payload": {
                "scanner": "generic_secret_scanner",
                "findings": [{"rule": "phone", "raw_match": "9802111074", "file": "logs/transfer.log"}],
            },
            "raw_must_not_appear": ["9802111074"],
        },
    ]
    truth = [
        {"case_id": "HO-071", "family": "scanner_controlled", "expected_safe": True,
         "raw_must_not_appear": ["pk_test_live_heldout_full"], "exclude_from_denominator": False},
        {"case_id": "HO-072", "family": "scanner_controlled", "expected_safe": True,
         "raw_must_not_appear": [], "exclude_from_denominator": False},
        {"case_id": "HO-073", "family": "scanner_controlled", "expected_safe": True,
         "raw_must_not_appear": [], "exclude_from_denominator": False},
        {"case_id": "HO-074", "family": "scanner_controlled",
         "expected_safe": False, "expected_raw_absent_if_sanitised": True,
         "raw_must_not_appear": ["9802111074"], "exclude_from_denominator": False},
    ]
    return inputs, truth


def unavailable_and_runtime():
    inputs = [
        {"case_id": "HO-075", "family": "wazuh", "availability": "NOT_AVAILABLE"},
        {"case_id": "HO-076", "family": "wazuh", "availability": "NOT_AVAILABLE"},
        {"case_id": "HO-077", "family": "github_hosted_workflow", "availability": "NOT_AVAILABLE"},
        {"case_id": "HO-078", "family": "github_hosted_workflow", "availability": "NOT_AVAILABLE"},
        {"case_id": "HO-079", "family": "rbac_runtime",
         "evidence_ref": ["SS-052", "SS-053"], "note": "Phase 1 runtime-proven; not a detector case"},
        {"case_id": "HO-080", "family": "human_gate_runtime",
         "evidence_ref": ["SS-054"], "note": "Phase 1 runtime-proven; not a detector case"},
    ]
    truth = [
        {"case_id": "HO-075", "family": "wazuh", "availability": "NOT_AVAILABLE", "exclude_from_denominator": True},
        {"case_id": "HO-076", "family": "wazuh", "availability": "NOT_AVAILABLE", "exclude_from_denominator": True},
        {"case_id": "HO-077", "family": "github_hosted_workflow", "availability": "NOT_AVAILABLE",
         "exclude_from_denominator": True},
        {"case_id": "HO-078", "family": "github_hosted_workflow", "availability": "NOT_AVAILABLE",
         "exclude_from_denominator": True},
        {"case_id": "HO-079", "family": "rbac_runtime", "expected_outcome": "access_denied_unauthorised_role",
         "exclude_from_denominator": True, "qualitative_pass": True, "evidence_ref": ["SS-052", "SS-053"]},
        {"case_id": "HO-080", "family": "human_gate_runtime", "expected_outcome": "verify_fix_blocked_before_review",
         "exclude_from_denominator": True, "qualitative_pass": True, "evidence_ref": ["SS-054"]},
    ]
    return inputs, truth


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    inputs_path = HERE / "inputs.yaml"
    gt_path = HERE / "ground_truth.yaml"
    manifest_path = HERE / "manifest.json"
    if inputs_path.exists() or gt_path.exists() or manifest_path.exists():
        raise SystemExit("Refusing to overwrite sealed held-out files.")

    d_in, d_gt = detection_pairs()
    r_in, r_gt = rca_pairs()
    s_in, s_gt = scanner_pairs()
    u_in, u_gt = unavailable_and_runtime()
    inputs = d_in + r_in + s_in + u_in
    truth = d_gt + r_gt + s_gt + u_gt
    if len(inputs) != 80 or len(truth) != 80:
        raise SystemExit(f"Expected 80/80, got {len(inputs)}/{len(truth)}")

    inputs_doc = {
        "dataset_id": "held_out_80",
        "dataset_version": "heldout_v1",
        "case_count": 80,
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "note": "Inputs only. Ground truth is in ground_truth.yaml and must not be loaded by PrivacyTrace runtime.",
        "cases": inputs,
    }
    gt_doc = {
        "dataset_id": "held_out_80",
        "dataset_version": "heldout_v1",
        "case_count": 80,
        "note": "Score only after system outputs exist. Do not import into backend/app/evaluation_data.",
        "cases": truth,
    }
    inputs_path.write_text(yaml.safe_dump(inputs_doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    gt_path.write_text(yaml.safe_dump(gt_doc, sort_keys=False, allow_unicode=True), encoding="utf-8")

    harness_files = ["rca_rank.py", "run_heldout.py", "seal_dataset.py", "inputs.yaml", "ground_truth.yaml"]
    harness_hash = hashlib.sha256()
    for name in harness_files:
        p = HERE / name
        if p.is_file():
            harness_hash.update(p.read_bytes())
    sealed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    combined = hashlib.sha256((inputs_path.read_bytes() + b"\n" + gt_path.read_bytes())).hexdigest()
    manifest = {
        "dataset_id": "held_out_80",
        "dataset_version": "heldout_v1",
        "case_count": 80,
        "sealed_at_utc": sealed_at,
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "nepalfin_lab_sha": NEPALFIN_LAB_SHA,
        "inputs_sha256": sha256_file(inputs_path),
        "ground_truth_sha256": sha256_file(gt_path),
        "held_out_80_sha256": combined,
        "evaluation_harness_sha256": harness_hash.hexdigest(),
        "families": {
            "detection": "HO-001..HO-050",
            "rca": "HO-051..HO-070",
            "scanner_controlled": "HO-071..HO-074",
            "wazuh": "HO-075..HO-076 NOT_AVAILABLE",
            "github_hosted_workflow": "HO-077..HO-078 NOT_AVAILABLE",
            "rbac_runtime": "HO-079 Phase-1 proven excluded from detector denominator",
            "human_gate_runtime": "HO-080 Phase-1 proven excluded from detector denominator",
        },
        "denominator_policy": "Exclude Wazuh/GitHub NOT AVAILABLE and qualitative runtime-proven cells from performance denominators.",
        "development_set_note": "backend/app/evaluation_data remains DEVELOPMENT/PRELIMINARY and is not this pack.",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sealed": True, "held_out_80_sha256": combined, "case_count": 80}, indent=2))


if __name__ == "__main__":
    main()
