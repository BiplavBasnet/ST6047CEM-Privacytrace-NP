"""Deterministic template fallback for Guarded LLM Investigation Assistant."""

from __future__ import annotations

_CHECKLIST_BY_CAUSE: dict[str, list[str]] = {
    "unsafe_request_body_logging": [
        "Confirm request-body logging is disabled in production configuration.",
        "Verify logs show only redacted or metadata fields for wallet transfer requests.",
        "Re-run detection on a sample API log after the change.",
        "Confirm no new sensitive detections on the affected endpoint.",
    ],
    "debug_logging_enabled_after_deployment": [
        "Verify production log level is not DEBUG.",
        "Confirm deployment configuration no longer enables verbose body logging.",
        "Review recent deployment records for logging-related changes.",
        "Re-scan API logs after configuration rollback.",
    ],
    "jwt_or_token_leakage": [
        "Confirm authorization headers and tokens are redacted in logs.",
        "Verify token values are not written to log lines.",
        "Rotate credentials if exposure window cannot be ruled out.",
        "Re-run secret and log detection on affected evidence.",
    ],
    "hardcoded_secret_or_api_key": [
        "Remove hardcoded secrets from source and configuration.",
        "Rotate exposed keys and store secrets in a vault or environment variables.",
        "Re-run secret scan evidence and confirm findings are cleared.",
    ],
    "access_control_failure": [
        "Review authorization rules for the affected endpoint.",
        "Confirm role-based access tests cover wallet transfer operations.",
        "Verify access event evidence shows expected deny/allow patterns.",
    ],
    "suspicious_dependency_introduced": [
        "Review dependency introduction timeline against deployment evidence.",
        "Confirm package source and version pinning in lock files.",
        "Re-run dependency scan after remediation.",
    ],
}


def _default_checklist() -> list[str]:
    return [
        "Review recommended fix steps with the security team.",
        "Collect missing evidence listed in the causality analysis.",
        "Re-run detection and causality analysis after remediation.",
        "Confirm human review before closing the incident.",
    ]


def generate_investigation_output(context: dict) -> dict:
    ranking = context.get("root_cause_ranking") or []
    if not ranking:
        return _empty_output(context)

    top = ranking[0]
    cause = top.get("likely_root_cause", "unknown")
    band = top.get("confidence_band", "low")
    confidence = top.get("confidence", 0)
    support_ids = top.get("supporting_evidence_ids") or []
    missing = top.get("missing_evidence") or []
    recommended_fix = (top.get("recommended_fix") or "").strip()

    ids_str = ", ".join(support_ids) if support_ids else "no linked evidence IDs"
    endpoint = context.get("affected_endpoint") or "the affected endpoint"
    service = context.get("affected_service") or "the affected service"

    incident_summary = (
        f"Incident {context.get('incident_id')} on {service} at {endpoint} "
        f"shows masked sensitive data exposure with {len(context.get('masked_detection_summary') or [])} "
        f"detection(s) across linked evidence. Human review is required."
    )

    likely_cause_explanation = (
        f"The likely cause is {cause.replace('_', ' ')} (confidence band: {band}, "
        f"score {confidence}). Supporting evidence suggests this based on evidence IDs: {ids_str}. "
        f"This is a likely cause, not confirmed blame."
    )

    supporting_evidence_summary = (
        f"Ranked causes from the Privacy Causality Engine place {cause} first. "
        f"Supporting evidence IDs include: {ids_str}. "
        f"Masked evidence items: {len(context.get('masked_evidence') or [])}."
    )

    alternative_hypotheses = []
    for alt_rank in ranking[1:4]:
        alt_ids = alt_rank.get("supporting_evidence_ids") or []
        alternative_hypotheses.append(
            {
                "hypothesis": (
                    f"Alternative likely cause: {alt_rank.get('likely_root_cause', '').replace('_', ' ')} "
                    f"(rank {alt_rank.get('rank')}, band {alt_rank.get('confidence_band')})."
                ),
                "supporting_evidence_ids": alt_ids,
                "confidence_note": (
                    f"Lower confidence than top cause; evidence IDs: {', '.join(alt_ids) if alt_ids else 'limited'}."
                ),
            }
        )

    missing_evidence_questions = []
    for item in missing:
        missing_evidence_questions.append(f"What additional evidence can confirm: {item}?")
    if not missing_evidence_questions:
        missing_evidence_questions.append(
            "Are there deployment or access logs that strengthen the evidence chain?"
        )

    recommended_fix_draft = recommended_fix or (
        "Review logging and secret-handling configuration for the affected service. "
        "Human review is required before applying changes."
    )

    fix_verification_checklist = _CHECKLIST_BY_CAUSE.get(cause, _default_checklist())

    human_review_note = (
        "This investigation support is evidence-grounded and advisory only. "
        "A human reviewer must approve the likely cause, recommended fix, and any closure decision. "
        "The evidence is limited where missing items are listed."
        if missing
        else "This investigation support is evidence-grounded and advisory only. "
        "A human reviewer must approve the likely cause and recommended fix before closure."
    )

    return {
        "incident_summary": incident_summary,
        "likely_cause_explanation": likely_cause_explanation,
        "supporting_evidence_summary": supporting_evidence_summary,
        "alternative_hypotheses": alternative_hypotheses,
        "missing_evidence_questions": missing_evidence_questions,
        "recommended_fix_draft": recommended_fix_draft,
        "fix_verification_checklist": fix_verification_checklist,
        "human_review_note": human_review_note,
        "safety_notes": {
            "uses_masked_evidence_only": True,
            "contains_raw_sensitive_values": False,
            "contains_overclaiming": False,
            "human_review_required": True,
        },
    }


def _empty_output(context: dict) -> dict:
    return {
        "incident_summary": (
            f"Incident {context.get('incident_id')} has no root-cause ranking. "
            "Run causality analysis first. Human review is required."
        ),
        "likely_cause_explanation": (
            "The evidence is limited and human review is required. "
            "No ranked likely cause is available."
        ),
        "supporting_evidence_summary": "No supporting root-cause scores were provided.",
        "alternative_hypotheses": [],
        "missing_evidence_questions": ["Run POST /incidents/analyse before requesting explanation."],
        "recommended_fix_draft": "Complete causality analysis, then revisit recommended fixes.",
        "fix_verification_checklist": _default_checklist(),
        "human_review_note": "Human review is required. No automated closure is permitted.",
        "safety_notes": {
            "uses_masked_evidence_only": True,
            "contains_raw_sensitive_values": False,
            "contains_overclaiming": False,
            "human_review_required": True,
        },
    }
