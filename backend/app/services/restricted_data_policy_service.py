from __future__ import annotations

import re
from typing import Any

from app.schemas.restricted_data_policy_schema import (
    DisclosureChannel,
    RestrictedPolicyDecision,
    RestrictedPolicySummary,
)


POLICY_VERSION = "restricted-data-policy-1"
RESTRICTED_REPLACEMENT_CODE = "restricted_compliance_information"
EXTERNAL_CHANNELS = {
    "customer_notification",
    "external_ai",
    "external_webhook",
    "general_report",
    "search_index",
}
FORBIDDEN_VALUE_KEYS = {
    "raw",
    "raw_value",
    "raw_payload",
    "plaintext",
    "full_value",
    "decrypted_payload",
    "value_fingerprint",
}
CATEGORY_KEYS = {
    "affected_data_categories",
    "category_codes",
    "sensitive_types",
}
CATEGORY_VALUE_KEYS = {"sensitive_type", "taxonomy_code"}


def disclosure_decision(
    *, internal_only: bool, channel: DisclosureChannel, authorised_restricted_access: bool = False
) -> RestrictedPolicyDecision:
    if not internal_only:
        return RestrictedPolicyDecision(
            allowed=True, channel=channel, internal_only=False, reason_code="ordinary_category"
        )
    if channel in EXTERNAL_CHANNELS:
        return RestrictedPolicyDecision(
            allowed=False,
            channel=channel,
            internal_only=True,
            reason_code="restricted_external_disclosure_prohibited",
        )
    if channel == "restricted_api" and authorised_restricted_access:
        return RestrictedPolicyDecision(
            allowed=True,
            channel=channel,
            internal_only=True,
            reason_code="authorised_minimum_access",
        )
    return RestrictedPolicyDecision(
        allowed=False,
        channel=channel,
        internal_only=True,
        replacement_code=RESTRICTED_REPLACEMENT_CODE,
        reason_code="restricted_access_required",
    )


def _drop_forbidden_values(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in FORBIDDEN_VALUE_KEYS}


def filter_records(
    records: list[dict[str, Any]],
    *,
    channel: DisclosureChannel,
    authorised_restricted_access: bool = False,
) -> tuple[list[dict[str, Any]], bool]:
    output: list[dict[str, Any]] = []
    restricted_present = False
    replacement_added = False
    for source in records:
        record = _drop_forbidden_values(dict(source))
        category_code = record.get("taxonomy_code") or record.get("sensitive_type")
        internal_only = bool(record.get("internal_only")) or is_restricted_category(
            str(category_code or ""), channel=channel
        )
        decision = disclosure_decision(
            internal_only=internal_only,
            channel=channel,
            authorised_restricted_access=authorised_restricted_access,
        )
        if not internal_only:
            output.append(record)
            continue
        restricted_present = True
        if decision.allowed:
            record.pop("masked_value", None)
            output.append(record)
        elif decision.replacement_code and channel == "ordinary_api" and not replacement_added:
            output.append(
                {
                    "taxonomy_code": decision.replacement_code,
                    "internal_only": True,
                    "restricted": True,
                }
            )
            replacement_added = True
    return output, restricted_present


def policy_summary() -> RestrictedPolicySummary:
    return RestrictedPolicySummary(
        policy_version=POLICY_VERSION,
        auditable_actions=[
            "restricted_data_access",
            "restricted_data_filtered",
            "customer_notification_content_filtered",
        ],
    )

RESTRICTED_AML_FALLBACK_CODES = {
    "suspicious_activity_flag", "str_sar_status", "str_sar_reference",
    "aml_investigation_note", "fiu_submission_reference", "law_enforcement_request",
    "watchlist_match", "sanctions_screening_result",
}
AML_NAMING_HEURISTIC_TOKENS = (
    "aml", "str_", "sar", "fiu", "sanctions", "watchlist", "law_enforcement",
)


def _matches_aml_naming_heuristic(normalised_code: str) -> bool:
    if not normalised_code:
        return False
    return any(token in normalised_code for token in AML_NAMING_HEURISTIC_TOKENS)


def is_restricted_category(code: str, *, channel: DisclosureChannel | None = None) -> bool:
    """Return whether a taxonomy code must be treated as restricted/internal-only.

    Fails closed: unknown codes that resemble AML/STR/SAR/FIU/sanctions/watchlist/
    law-enforcement naming are always treated as restricted, and a taxonomy load
    failure is treated as restricted whenever the disclosure channel is external
    (or unspecified, since the caller's channel context is then unknown).
    """
    normalised = str(code or "").strip().lower()
    if not normalised:
        # No category was supplied at all (e.g. a record that carries no
        # taxonomy/sensitive-type classification). There is nothing to fail
        # closed on here; treating "no category" as restricted would corrupt
        # unrelated, uncategorised records whenever taxonomy loading hiccups.
        return False
    if normalised in RESTRICTED_AML_FALLBACK_CODES or _matches_aml_naming_heuristic(normalised):
        return True
    try:
        from app.services.taxonomy_registry_service import load_taxonomy
        return bool(load_taxonomy().category(normalised).get("internal_only"))
    except KeyError:
        return False
    except ValueError:
        return channel is None or channel in EXTERNAL_CHANNELS


def _restricted_terms() -> set[str]:
    terms = set(RESTRICTED_AML_FALLBACK_CODES)
    try:
        from app.services.taxonomy_registry_service import load_taxonomy

        for category in load_taxonomy().enabled_categories():
            if category.get("internal_only"):
                terms.add(str(category.get("code") or ""))
                terms.add(str(category.get("display_name") or ""))
    except ValueError:
        pass
    return {term for term in terms if term}


def sanitize_text(text: str, *, channel: DisclosureChannel) -> tuple[str, bool]:
    restricted_present = False
    replacement = (
        RESTRICTED_REPLACEMENT_CODE.replace("_", " ")
        if channel == "ordinary_api"
        else ""
    )
    for term in sorted(_restricted_terms(), key=len, reverse=True):
        variants = {term, term.replace("_", " ")}
        for variant in variants:
            updated, count = re.subn(
                re.escape(variant),
                replacement,
                text,
                flags=re.IGNORECASE,
            )
            if count:
                restricted_present = True
                text = updated
    return re.sub(r"\s{2,}", " ", text).strip(), restricted_present


def filter_category_codes(codes: list[str], *, channel: DisclosureChannel) -> tuple[list[str], bool]:
    safe: list[str] = []
    restricted_present = False
    for code in codes:
        if is_restricted_category(code, channel=channel):
            restricted_present = True
            continue
        safe.append(str(code))
    return list(dict.fromkeys(safe)), restricted_present


def _safe_category_codes(codes: list[Any], channel: DisclosureChannel) -> tuple[list[str], bool]:
    safe, restricted = filter_category_codes([str(code) for code in codes], channel=channel)
    if restricted and channel == "ordinary_api":
        safe.append(RESTRICTED_REPLACEMENT_CODE)
    return list(dict.fromkeys(safe)), restricted


def sanitize_payload(
    value: Any,
    *,
    channel: DisclosureChannel,
    authorised_restricted_access: bool = False,
) -> tuple[Any, bool]:
    """Remove restricted categories and forbidden values at an outbound boundary."""

    if isinstance(value, list):
        list_output: list[Any] = []
        restricted_present = False
        for item in value:
            safe_item, restricted = sanitize_payload(
                item,
                channel=channel,
                authorised_restricted_access=authorised_restricted_access,
            )
            restricted_present = restricted_present or restricted
            if safe_item is not None:
                list_output.append(safe_item)
        return list_output, restricted_present

    if isinstance(value, str):
        return sanitize_text(value, channel=channel)
    if not isinstance(value, dict):
        return value, False

    record = _drop_forbidden_values(dict(value))
    category_code = record.get("taxonomy_code") or record.get("sensitive_type")
    internal_only = bool(record.get("internal_only")) or is_restricted_category(
        str(category_code or ""), channel=channel
    )
    if internal_only:
        decision = disclosure_decision(
            internal_only=True,
            channel=channel,
            authorised_restricted_access=authorised_restricted_access,
        )
        if not decision.allowed:
            if channel == "ordinary_api" and decision.replacement_code:
                return {
                    "taxonomy_code": decision.replacement_code,
                    "internal_only": True,
                    "restricted": True,
                }, True
            return None, True
        record.pop("masked_value", None)

    dict_output: dict[str, Any] = {}
    restricted_present = internal_only
    for key, item in record.items():
        if key in CATEGORY_VALUE_KEYS and is_restricted_category(str(item or ""), channel=channel):
            restricted_present = True
            if channel == "ordinary_api":
                dict_output[key] = RESTRICTED_REPLACEMENT_CODE
            continue
        if key in CATEGORY_KEYS and isinstance(item, list):
            dict_output[key], restricted = _safe_category_codes(item, channel)
        else:
            safe_item, restricted = sanitize_payload(
                item,
                channel=channel,
                authorised_restricted_access=authorised_restricted_access,
            )
            if safe_item is not None:
                dict_output[key] = safe_item
        restricted_present = restricted_present or restricted
    return dict_output, restricted_present
