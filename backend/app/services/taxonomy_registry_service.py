from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import resolve_rules_dir
from app.schemas.taxonomy_schema import (
    TaxonomyCategoryRead,
    TaxonomyValidationResponse,
    TaxonomyVersionResponse,
)


class TaxonomyRegistryError(ValueError):
    pass


REQUIRED_CATEGORY_FIELDS = {
    "code",
    "display_name",
    "group",
    "description",
    "field_aliases",
    "nepali_aliases",
    "romanised_aliases",
    "context_terms",
    "negative_context_terms",
    "pattern_ids",
    "validator_ids",
    "masking_strategy",
    "fingerprint_strategy",
    "default_severity",
    "default_harm_categories",
    "default_alert_type",
    "containment_recommendations",
    "customer_notification_policy",
    "restricted_roles",
    "internal_only",
    "enabled",
}


@dataclass(frozen=True)
class TaxonomyRegistry:
    version: str
    policy_version: str
    categories: tuple[dict[str, Any], ...]
    registry_hash: str

    def category(self, code: str) -> dict[str, Any]:
        for item in self.categories:
            if item["code"] == code:
                return item
        raise KeyError(code)

    def enabled_categories(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self.categories if item.get("enabled", True))


def _default_path() -> Path:
    return resolve_rules_dir() / "nepal_financial_data_taxonomy.yaml"


def _canonical_hash(data: dict[str, Any]) -> str:
    blob = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def validate_taxonomy_data(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["Taxonomy root must be a mapping."]
    if not str(data.get("taxonomy_version") or "").strip():
        errors.append("taxonomy_version is required.")
    categories = data.get("categories")
    if not isinstance(categories, list) or not categories:
        errors.append("categories must be a non-empty list.")
        return errors
    seen: set[str] = set()
    for index, item in enumerate(categories):
        label = f"categories[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be a mapping.")
            continue
        missing = sorted(REQUIRED_CATEGORY_FIELDS - set(item))
        if missing:
            errors.append(f"{label} is missing: {', '.join(missing)}.")
        code = str(item.get("code") or "").strip()
        if not code:
            errors.append(f"{label}.code is required.")
        elif code in seen:
            errors.append(f"Duplicate taxonomy code: {code}.")
        seen.add(code)
        if item.get("internal_only") and item.get("customer_notification_policy") != "prohibited":
            errors.append(f"{code or label} must prohibit customer notification when internal_only is true.")
        if item.get("fingerprint_strategy") not in {"none", "hmac_sha256_v1"}:
            errors.append(f"{code or label} has an unsupported fingerprint_strategy.")
    return errors


@lru_cache(maxsize=8)
def _load_cached(path_text: str) -> TaxonomyRegistry:
    path = Path(path_text)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TaxonomyRegistryError(f"Taxonomy could not be loaded: {path.name}") from exc
    errors = validate_taxonomy_data(data)
    if errors:
        raise TaxonomyRegistryError(" ".join(errors))
    version = str(data["taxonomy_version"])
    categories = tuple(
        {**item, "taxonomy_version": version}
        for item in data["categories"]
    )
    return TaxonomyRegistry(
        version=version,
        policy_version=str(data.get("policy_version") or version),
        categories=categories,
        registry_hash=_canonical_hash(data),
    )


def load_taxonomy(path: str | Path | None = None) -> TaxonomyRegistry:
    resolved = Path(path) if path is not None else _default_path()
    return _load_cached(str(resolved.resolve()))


def reset_taxonomy_cache() -> None:
    _load_cached.cache_clear()


def category_to_read(item: dict[str, Any]) -> TaxonomyCategoryRead:
    return TaxonomyCategoryRead(
        code=item["code"],
        display_name=item["display_name"],
        group=item["group"],
        description=item["description"],
        detection_methods=list(item.get("pattern_ids") or []),
        masking_strategy=item["masking_strategy"],
        fingerprint_strategy=item["fingerprint_strategy"],
        default_severity=item["default_severity"],
        internal_only=bool(item.get("internal_only")),
        customer_notification_allowed=item.get("customer_notification_policy") != "prohibited",
        enabled=bool(item.get("enabled", True)),
        taxonomy_version=item["taxonomy_version"],
        known_limitations=list(item.get("known_limitations") or []),
    )


def version_response(registry: TaxonomyRegistry | None = None) -> TaxonomyVersionResponse:
    registry = registry or load_taxonomy()
    return TaxonomyVersionResponse(
        taxonomy_version=registry.version,
        category_count=len(registry.categories),
        enabled_category_count=len(registry.enabled_categories()),
        registry_hash=registry.registry_hash,
    )


def validate_taxonomy_file(path: str | Path | None = None) -> TaxonomyValidationResponse:
    resolved = Path(path) if path is not None else _default_path()
    try:
        data = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return TaxonomyValidationResponse(valid=False, errors=["Taxonomy file is unavailable or invalid YAML."])
    errors = validate_taxonomy_data(data)
    return TaxonomyValidationResponse(
        valid=not errors,
        taxonomy_version=str(data.get("taxonomy_version")) if isinstance(data, dict) and data.get("taxonomy_version") else None,
        errors=errors,
        warnings=["Taxonomy matching identifies possible exposure; it does not prove a breach."],
    )
