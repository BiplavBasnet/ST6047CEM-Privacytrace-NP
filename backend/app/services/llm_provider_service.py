"""Ollama provider for Guarded LLM Investigation Assistant (local only)."""

from __future__ import annotations

import json
import re

import httpx

from app.config import get_settings
from app.services import restricted_data_policy_service

SYSTEM_PROMPT = """You are the Guarded LLM Investigation Assistant for PrivacyTrace-NP.
You receive MASKED evidence only. You must NOT claim definite proof or confirmed blame.
Use wording: likely cause, supporting evidence suggests, confidence level, human review required.
Every important claim must reference evidence IDs from the input (e.g. EVD-S1-API-001).
Respond with a single JSON object only (no markdown fences) containing these keys:
incident_summary, likely_cause_explanation, supporting_evidence_summary,
alternative_hypotheses (array of {hypothesis, supporting_evidence_ids, confidence_note}),
missing_evidence_questions (array of strings), recommended_fix_draft,
fix_verification_checklist (array of strings), human_review_note,
safety_notes ({uses_masked_evidence_only, contains_raw_sensitive_values, contains_overclaiming, human_review_required}).
Do not invent evidence IDs. Base recommended_fix_draft on the top ranked recommended_fix in input.
"""


class OllamaUnavailableError(Exception):
    """Raised when Ollama cannot be reached or returns an invalid response."""


def is_ollama_available() -> bool:
    settings = get_settings()
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            return resp.status_code == 200
    except (httpx.HTTPError, OSError):
        return False


def _parse_json_from_response(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    return json.loads(text)


def _chat(model: str, context: dict) -> dict:
    settings = get_settings()
    context, _restricted_present = restricted_data_policy_service.sanitize_payload(
        context,
        channel="external_ai",
    )
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(context, indent=2, default=str),
            },
        ],
    }
    timeout = float(settings.ollama_timeout_seconds)
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
    message = data.get("message") or {}
    content = message.get("content") or ""
    if not content:
        raise OllamaUnavailableError("Empty response from Ollama")
    return _parse_json_from_response(content)


def generate_with_ollama(
    context: dict,
    model: str | None = None,
    backup_model: str | None = None,
) -> dict:
    settings = get_settings()
    primary = model or settings.ollama_default_model
    backup = backup_model or settings.ollama_backup_model
    try:
        return _chat(primary, context)
    except (httpx.HTTPError, OSError, json.JSONDecodeError, OllamaUnavailableError):
        if backup and backup != primary:
            try:
                return _chat(backup, context)
            except (httpx.HTTPError, OSError, json.JSONDecodeError, OllamaUnavailableError) as exc:
                raise OllamaUnavailableError(str(exc)) from exc
        raise OllamaUnavailableError("Ollama request failed")
