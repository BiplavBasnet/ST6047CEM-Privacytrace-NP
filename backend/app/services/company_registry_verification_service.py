"""Nepal company registry verification adapters (no HTML scraping)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.config import resolve_company_verification_mode


class MatchStatus:
    MATCHED = "matched"
    MISMATCH = "mismatch"
    NOT_VERIFIED = "not_verified"
    VERIFICATION_SERVICE_UNAVAILABLE = "verification_service_unavailable"


@dataclass(frozen=True)
class RegistryVerificationResult:
    source: str
    registration_number: str
    submitted_name: str
    registry_name: str | None
    match_status: str
    checked_at: datetime
    verification_method: str
    reference_safe: str | None


class CompanyRegistryAdapter(Protocol):
    def verify(self, *, legal_name: str, registration_number: str) -> RegistryVerificationResult: ...


class ManualOfficialReferenceAdapter:
    """Records an authorised OCR official-reference review result (no live scrape)."""

    source = "NEPAL_OCR"
    method = "OFFICIAL_REFERENCE_MANUAL"

    def verify(
        self,
        *,
        legal_name: str,
        registration_number: str,
        registry_name: str | None = None,
        match_status: str = MatchStatus.MATCHED,
        reference_safe: str | None = None,
    ) -> RegistryVerificationResult:
        if match_status not in {
            MatchStatus.MATCHED,
            MatchStatus.MISMATCH,
            MatchStatus.NOT_VERIFIED,
            MatchStatus.VERIFICATION_SERVICE_UNAVAILABLE,
        }:
            match_status = MatchStatus.NOT_VERIFIED
        return RegistryVerificationResult(
            source=self.source,
            registration_number=registration_number.strip(),
            submitted_name=legal_name.strip(),
            registry_name=(registry_name or "").strip() or None,
            match_status=match_status,
            checked_at=datetime.now(UTC),
            verification_method=self.method,
            reference_safe=(reference_safe or "").strip() or None,
        )


class DemoRegistryAdapter:
    """Synthetic registry for thesis/demo only — never labelled as OCR Verified."""

    source = "DEMO_SIMULATED"
    method = "DEMO_SIMULATED"

    def verify(self, *, legal_name: str, registration_number: str) -> RegistryVerificationResult:
        name = legal_name.strip()
        reg = registration_number.strip()
        if not name or not reg:
            status = MatchStatus.NOT_VERIFIED
            registry_name = None
        elif reg.upper().endswith("X"):
            status = MatchStatus.MISMATCH
            registry_name = f"Other Entity ({reg})"
        elif reg.upper().endswith("U"):
            status = MatchStatus.VERIFICATION_SERVICE_UNAVAILABLE
            registry_name = None
        else:
            status = MatchStatus.MATCHED
            registry_name = name
        return RegistryVerificationResult(
            source=self.source,
            registration_number=reg,
            submitted_name=name,
            registry_name=registry_name,
            match_status=status,
            checked_at=datetime.now(UTC),
            verification_method=self.method,
            reference_safe="demo-registry-simulated",
        )


def get_registry_adapter() -> CompanyRegistryAdapter:
    if resolve_company_verification_mode() == "demo":
        return DemoRegistryAdapter()
    return ManualOfficialReferenceAdapter()


def verify_company_registration(
    *,
    legal_name: str,
    registration_number: str,
    registry_name: str | None = None,
    match_status: str | None = None,
    reference_safe: str | None = None,
    adapter: CompanyRegistryAdapter | None = None,
) -> RegistryVerificationResult:
    adapter = adapter or get_registry_adapter()
    if isinstance(adapter, ManualOfficialReferenceAdapter):
        return adapter.verify(
            legal_name=legal_name,
            registration_number=registration_number,
            registry_name=registry_name,
            match_status=match_status or MatchStatus.MATCHED,
            reference_safe=reference_safe,
        )
    return adapter.verify(legal_name=legal_name, registration_number=registration_number)
