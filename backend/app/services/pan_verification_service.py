"""Optional Nepal PAN (IRD) verification adapters — no fragile page scraping."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.config import get_settings, resolve_company_verification_mode


class PanMatchStatus:
    MATCHED = "matched"
    NOT_VERIFIED = "not_verified"
    VERIFICATION_SERVICE_UNAVAILABLE = "verification_service_unavailable"
    SKIPPED_OPTIONAL = "skipped_optional"


@dataclass(frozen=True)
class PanVerificationResult:
    pan: str
    match_status: str
    checked_at: datetime
    verification_method: str
    reference_safe: str | None
    message_safe: str


class PanVerificationAdapter(Protocol):
    def verify(self, *, pan: str) -> PanVerificationResult: ...


class ManualIrdReferenceAdapter:
    source = "NEPAL_IRD"
    method = "OFFICIAL_REFERENCE_MANUAL"

    def verify(
        self,
        *,
        pan: str,
        match_status: str = PanMatchStatus.MATCHED,
        reference_safe: str | None = None,
    ) -> PanVerificationResult:
        status = match_status
        if status not in {
            PanMatchStatus.MATCHED,
            PanMatchStatus.NOT_VERIFIED,
            PanMatchStatus.VERIFICATION_SERVICE_UNAVAILABLE,
        }:
            status = PanMatchStatus.NOT_VERIFIED
        if status == PanMatchStatus.MATCHED:
            msg = "PAN verification recorded via official IRD reference."
        elif status == PanMatchStatus.VERIFICATION_SERVICE_UNAVAILABLE:
            msg = "PAN verification unsuccessful / unavailable."
        else:
            msg = "PAN verification unsuccessful / unavailable."
        return PanVerificationResult(
            pan=pan.strip().upper(),
            match_status=status,
            checked_at=datetime.now(UTC),
            verification_method=self.method,
            reference_safe=(reference_safe or "").strip() or None,
            message_safe=msg,
        )


class DemoPanAdapter:
    method = "DEMO_SIMULATED"

    def verify(self, *, pan: str) -> PanVerificationResult:
        value = pan.strip().upper()
        if value.endswith("U"):
            status = PanMatchStatus.VERIFICATION_SERVICE_UNAVAILABLE
            msg = "PAN verification unsuccessful / unavailable."
        elif value.endswith("X"):
            status = PanMatchStatus.NOT_VERIFIED
            msg = "PAN verification unsuccessful / unavailable."
        else:
            status = PanMatchStatus.MATCHED
            msg = "Demo PAN verification simulated (not IRD Verified)."
        return PanVerificationResult(
            pan=value,
            match_status=status,
            checked_at=datetime.now(UTC),
            verification_method=self.method,
            reference_safe="demo-pan-simulated",
            message_safe=msg,
        )


def pan_verification_required() -> bool:
    return bool(get_settings().pan_verification_required)


def get_pan_adapter() -> PanVerificationAdapter:
    if resolve_company_verification_mode() == "demo":
        return DemoPanAdapter()
    return ManualIrdReferenceAdapter()


def verify_pan(
    *,
    pan: str,
    match_status: str | None = None,
    reference_safe: str | None = None,
    adapter: PanVerificationAdapter | None = None,
) -> PanVerificationResult:
    adapter = adapter or get_pan_adapter()
    if isinstance(adapter, ManualIrdReferenceAdapter):
        return adapter.verify(
            pan=pan,
            match_status=match_status or PanMatchStatus.MATCHED,
            reference_safe=reference_safe,
        )
    return adapter.verify(pan=pan)
