"""Signal-to-cause ranking copied from the frozen runner, without ground-truth append.

The application runner `thesis_evaluation_runner.run_root_cause_evaluation`
appends the labelled cause when it is missing from the ranked list. Held-out
scoring must rank from evidence signals only, then compare to ground truth.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

SPECIFIC_SIGNAL_WEIGHT = 3
GENERIC_SIGNAL_WEIGHT = 1
GENERIC_CAUSES = {"missing_redaction_rule"}

SIGNAL_TO_CAUSE = {
    "authorization_header_in_log": "unsafe_request_header_logging",
    "bearer_token": "unsafe_request_header_logging",
    "request_header_log": "unsafe_request_header_logging",
    "sast_header_logger": "unsafe_request_header_logging",
    "phone_in_body": "unsafe_request_body_logging",
    "request_body_log": "unsafe_request_body_logging",
    "sast_body_logger": "unsafe_request_body_logging",
    "response_body_log": "unsafe_response_body_logging",
    "sast_response_logger": "unsafe_response_body_logging",
    "token_in_response": "unsafe_response_body_logging",
    "debug_enabled": "debug_logging_enabled",
    "debug_level_enabled": "debug_logging_enabled",
    "verbose_debug": "debug_logging_enabled",
    "query_string_log": "query_string_logging",
    "access_log_query": "query_string_logging",
    "proxy_overcollection": "proxy_log_overcollection",
    "gateway_raw_capture": "proxy_log_overcollection",
    "proxy_full_headers": "proxy_log_overcollection",
    "ingress_mirror": "proxy_log_overcollection",
    "apm_capture": "apm_agent_capture",
    "apm_payload_capture": "apm_agent_capture",
    "agent_sensitive_field": "apm_agent_capture",
    "trace_body_enabled": "apm_agent_capture",
    "error_serialisation": "error_handler_serialisation",
    "error_payload_log": "error_handler_serialisation",
    "exception_dump": "error_handler_serialisation",
    "stack_with_request": "error_handler_serialisation",
    "report_transform": "unsafe_report_transformation",
    "export_pipeline": "unsafe_report_transformation",
    "report_unmasked_field": "unsafe_report_transformation",
    "transform_bypass": "unsafe_report_transformation",
    "secret_in_config": "secret_in_configuration",
    "config_scan_hit": "secret_in_configuration",
    "config_secret_plaintext": "secret_in_configuration",
    "env_committed": "secret_in_configuration",
    "redaction_rule_absent": "missing_redaction_rule",
    "masking_config_gap": "missing_redaction_rule",
    "redaction_order_wrong": "incorrect_redaction_order",
    "log_before_redact": "incorrect_redaction_order",
    "order_violation": "incorrect_redaction_order",
    "serialise_before_mask": "incorrect_redaction_order",
    "verbose_logger": "debug_logging_enabled",
    "dev_profile_active": "debug_logging_enabled",
    "url_with_secret": "query_string_logging",
}

COMPONENT_BY_CAUSE = {
    "unsafe_request_header_logging": "request logging middleware",
    "unsafe_request_body_logging": "request logging middleware",
    "unsafe_response_body_logging": "request logging middleware",
    "missing_redaction_rule": "logging configuration",
    "incorrect_redaction_order": "logging configuration",
    "debug_logging_enabled": "request logging middleware",
    "query_string_logging": "request logging middleware",
    "proxy_log_overcollection": "logging configuration",
    "apm_agent_capture": "logging configuration",
    "error_handler_serialisation": "logging configuration",
    "unsafe_report_transformation": "logging configuration",
    "secret_in_configuration": "logging configuration",
}


def rank_causes(
    evidence_signals: list[str] | None,
    contradicting_signals: list[str] | None = None,
) -> dict[str, Any]:
    scores: Counter[str] = Counter()
    for sig in evidence_signals or []:
        cause = SIGNAL_TO_CAUSE.get(sig)
        if not cause:
            continue
        weight = GENERIC_SIGNAL_WEIGHT if cause in GENERIC_CAUSES else SPECIFIC_SIGNAL_WEIGHT
        scores[cause] += weight
    for sig in contradicting_signals or []:
        cause = SIGNAL_TO_CAUSE.get(sig)
        if cause:
            scores[cause] -= 1
    ranked = [c for c, _ in scores.most_common()]
    return {
        "ranked": ranked,
        "top1": ranked[0] if ranked else None,
        "top3": ranked[:3],
        "scores": dict(scores),
        "predicted_component": COMPONENT_BY_CAUSE.get(ranked[0], "unknown") if ranked else None,
    }
