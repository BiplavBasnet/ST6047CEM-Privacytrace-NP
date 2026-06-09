from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from app.schemas.contextual_detection_schema import ContextualDetectionResult
from app.services import taxonomy_registry_service, taxonomy_validator_service


def _normalise_label(value: str) -> str:
    return re.sub(r"[^\w\u0900-\u097f]+", "_", value.casefold()).strip("_")


def _flatten_fields(value: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    if depth > 3:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_fields(item, name, depth + 1)
        return
    if isinstance(value, list):
        for index, item in enumerate(value[:20]):
            yield from _flatten_fields(item, f"{prefix}[{index}]", depth + 1)
        return
    yield prefix, value


def _aliases(category: dict[str, Any]) -> dict[str, str]:
    values = (
        list(category.get("field_aliases") or [])
        + list(category.get("nepali_aliases") or [])
        + list(category.get("romanised_aliases") or [])
    )
    return {_normalise_label(str(item)): str(item) for item in values}


def _safe_context_label(value: str | None) -> str | None:
    label = (value or "").strip()
    if not label:
        return None
    return label if re.fullmatch(r"[A-Za-z0-9 _./:@-]{1,64}", label) else "unclassified"


def _trusted_source(source_context: dict[str, str]) -> bool:
    return any(
        str(source_context.get(key) or "").strip()
        for key in ("endpoint", "upload_endpoint", "document_type", "scanner_label", "source_service")
    )


def _result_for(
    category: dict[str, Any],
    *,
    alias: str,
    value: Any,
    source_context: dict[str, str],
    hmac_key: str,
) -> ContextualDetectionResult:
    validation = taxonomy_validator_service.validate_value(
        value, list(category.get("validator_ids") or []), source_context
    )
    trusted = _trusted_source(source_context)
    context_score = 0.8 if trusted else 0.65
    limitations = list(category.get("known_limitations") or [])
    if validation == "invalid":
        confidence = "rejected"
        context_score = min(context_score, 0.35)
    elif category.get("group") == "kyc_document" or category.get("internal_only"):
        confidence = "requires_human_review"
    elif validation == "valid" and trusted:
        confidence = "validated"
    elif validation == "valid":
        confidence = "probable"
    else:
        confidence = "possible"
    fingerprint = None
    strategy = str(category.get("fingerprint_strategy") or "none")
    if strategy == "hmac_sha256_v1":
        if hmac_key:
            fingerprint = taxonomy_validator_service.hmac_fingerprint(value, category["code"], hmac_key)
        else:
            limitations.append("Stable fingerprint omitted because DETECTION_HMAC_KEY is unavailable.")
            confidence = "requires_human_review"
    credential_status = None
    if category.get("group") == "authentication_credential":
        credential_status = str(source_context.get("credential_status") or "unknown")
    return ContextualDetectionResult(
        taxonomy_code=category["code"],
        taxonomy_version=category["taxonomy_version"],
        category_group=category["group"],
        detection_method="structured_field_alias",
        matched_alias=alias,
        context_score=context_score,
        format_validation_status=validation,
        source_context_status="trusted" if trusted else "limited",
        credential_status=credential_status,
        document_type=_safe_context_label(source_context.get("document_type")),
        masked_value=taxonomy_validator_service.mask_value(value, category["masking_strategy"]),
        value_fingerprint=fingerprint,
        fingerprint_strategy=strategy,
        confidence_label=confidence,
        internal_only=bool(category.get("internal_only")),
        customer_notification_allowed=category.get("customer_notification_policy") != "prohibited",
        restricted_roles=list(category.get("restricted_roles") or []),
        limitations=list(dict.fromkeys(limitations)),
    )


def classify_structured_fields(
    fields: dict[str, Any],
    *,
    source_context: dict[str, str] | None = None,
    hmac_key: str = "",
    registry: taxonomy_registry_service.TaxonomyRegistry | None = None,
) -> list[ContextualDetectionResult]:
    registry = registry or taxonomy_registry_service.load_taxonomy()
    source_context = source_context or {}
    flattened = list(_flatten_fields(fields))
    results: list[ContextualDetectionResult] = []
    seen: set[tuple[str, str, str | None]] = set()
    source_text = " ".join(str(value) for value in source_context.values()).casefold()
    for category in registry.enabled_categories():
        aliases = _aliases(category)
        negative = [str(item).casefold() for item in category.get("negative_context_terms") or []]
        for field_name, value in flattened:
            normalised = _normalise_label(field_name.rsplit(".", 1)[-1].split("[", 1)[0])
            alias = aliases.get(normalised)
            if alias is None:
                continue
            combined_context = f"{field_name} {source_text}".casefold()
            if any(term and term in combined_context for term in negative):
                continue
            result = _result_for(
                category,
                alias=alias,
                value=value,
                source_context=source_context,
                hmac_key=hmac_key,
            )
            key = (result.taxonomy_code, field_name, result.value_fingerprint)
            if key not in seen:
                results.append(result)
                seen.add(key)
    return results

