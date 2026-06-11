"""Canonical sensitive-data taxonomy mapping for PrivacyTrace-NP.

Maps legacy detector names onto one category / type / sensitivity model.
Does not replace Nepal taxonomy YAML; bridges regex + contextual codes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache


class SensitiveDataCategory(str, Enum):
    PERSONAL = "PERSONAL"
    FINANCIAL = "FINANCIAL"
    AUTHENTICATION_SECRET = "AUTHENTICATION_SECRET"
    KYC = "KYC"
    UNKNOWN = "UNKNOWN"


class SensitivityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"


TAXONOMY_VERSION = "canonical_v1"


@dataclass(frozen=True)
class CanonicalType:
    taxonomy_type: str
    category: SensitiveDataCategory
    sensitivity: SensitivityLevel
    legacy_aliases: tuple[str, ...]


# Primary types + legacy detector aliases used across Live Monitor / Evidence.
_CANONICAL_TYPES: tuple[CanonicalType, ...] = (
    CanonicalType("phone_number", SensitiveDataCategory.PERSONAL, SensitivityLevel.HIGH, ("nepal_phone", "phone", "customer_phone", "mobile")),
    CanonicalType("email_address", SensitiveDataCategory.PERSONAL, SensitivityLevel.MODERATE, ("email",)),
    CanonicalType("full_name", SensitiveDataCategory.PERSONAL, SensitivityLevel.MODERATE, ("name", "customer_name")),
    CanonicalType("citizenship_number", SensitiveDataCategory.PERSONAL, SensitivityLevel.HIGH, ("citizenship", "national_id")),
    CanonicalType("wallet_identifier", SensitiveDataCategory.FINANCIAL, SensitivityLevel.HIGH, ("wallet_id", "wallet")),
    CanonicalType("transaction_reference", SensitiveDataCategory.FINANCIAL, SensitivityLevel.HIGH, ("transaction_ref", "transaction_id", "txn_ref")),
    CanonicalType("payment_card_number", SensitiveDataCategory.FINANCIAL, SensitivityLevel.CRITICAL, ("card_number", "pan", "payment_card")),
    CanonicalType("bank_account_number", SensitiveDataCategory.FINANCIAL, SensitivityLevel.HIGH, ("bank_account", "account_number")),
    CanonicalType("jwt", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ("jwt_token",)),
    CanonicalType("bearer_token", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ("authorization_header",)),
    CanonicalType("access_token", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ()),
    CanonicalType("refresh_token", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ()),
    CanonicalType("session_token", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ()),
    CanonicalType("api_key", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ("merchant_api_key", "payment_gateway_key")),
    CanonicalType("password", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ("plaintext_password",)),
    CanonicalType("pin", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.HIGH, ()),
    CanonicalType("otp", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.HIGH, ()),
    CanonicalType("private_key", SensitiveDataCategory.AUTHENTICATION_SECRET, SensitivityLevel.CRITICAL, ()),
    CanonicalType("kyc_document_reference", SensitiveDataCategory.KYC, SensitivityLevel.HIGH, ("kyc_document",)),
    CanonicalType("identity_document_number", SensitiveDataCategory.KYC, SensitivityLevel.HIGH, ()),
)


@lru_cache(maxsize=1)
def _alias_index() -> dict[str, CanonicalType]:
    index: dict[str, CanonicalType] = {}
    for item in _CANONICAL_TYPES:
        index[item.taxonomy_type.casefold()] = item
        for alias in item.legacy_aliases:
            index[alias.casefold()] = item
    return index


def resolve_taxonomy_type(raw_type_hint: str | None) -> CanonicalType | None:
    if not raw_type_hint:
        return None
    return _alias_index().get(str(raw_type_hint).strip().casefold())


def canonical_type_name(raw_type_hint: str | None) -> str:
    resolved = resolve_taxonomy_type(raw_type_hint)
    if resolved:
        return resolved.taxonomy_type
    text = str(raw_type_hint or "unknown").strip()
    return text or "unknown"


def category_for(raw_type_hint: str | None) -> SensitiveDataCategory:
    resolved = resolve_taxonomy_type(raw_type_hint)
    return resolved.category if resolved else SensitiveDataCategory.UNKNOWN


def sensitivity_for(raw_type_hint: str | None) -> SensitivityLevel:
    resolved = resolve_taxonomy_type(raw_type_hint)
    return resolved.sensitivity if resolved else SensitivityLevel.MODERATE


def list_canonical_types() -> list[dict[str, str]]:
    return [
        {
            "taxonomy_type": item.taxonomy_type,
            "category": item.category.value,
            "sensitivity_level": item.sensitivity.value,
            "legacy_aliases": ",".join(item.legacy_aliases),
            "taxonomy_version": TAXONOMY_VERSION,
        }
        for item in _CANONICAL_TYPES
    ]
