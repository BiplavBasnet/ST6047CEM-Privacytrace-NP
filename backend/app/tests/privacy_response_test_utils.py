"""Synthetic fixtures shared by privacy-response tests."""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.detection import Detection
from app.models.enums import IncidentStatus, Severity, UserRole
from app.models.incident import Incident
from app.models.user import User


def seed_privacy_response_case(db, *, credential_type: str | None = None):
    users = {
        role: User(
            name=f"Synthetic {role.value}",
            email=f"privacy-{role.value}@example.test",
            role=role,
            is_active=True,
        )
        for role in (
            UserRole.SECURITY_ANALYST,
            UserRole.ADMIN,
            UserRole.DEVSECOPS_ENGINEER,
            UserRole.AUDITOR,
            UserRole.DEVELOPER,
        )
    }
    incident = Incident(
        incident_id="INC-PRIVACY-RESPONSE-001",
        title="Possible privacy exposure in synthetic-api /profile",
        affected_service="synthetic-api",
        affected_endpoint="/profile",
        status=IncidentStatus.UNDER_REVIEW,
        severity=Severity.HIGH,
        first_seen=datetime(2026, 7, 16, 3, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 7, 16, 3, 5, tzinfo=timezone.utc),
        summary="Masked synthetic evidence requires human review.",
    )
    detections = [
        Detection(
            detection_id="DET-PRIVACY-CONTACT",
            incident_id=incident.incident_id,
            sensitive_type="nepal_phone",
            raw_value_hash="sha256:synthetic-only",
            masked_value="984****567",
            confidence=0.96,
            severity=Severity.HIGH,
            detector_name="synthetic-test-detector",
        )
    ]
    if credential_type:
        detections.append(
            Detection(
                detection_id="DET-PRIVACY-CREDENTIAL",
                incident_id=incident.incident_id,
                sensitive_type=credential_type,
                raw_value_hash="sha256:synthetic-credential-only",
                masked_value="credential_[masked]",
                confidence=0.98,
                severity=Severity.CRITICAL,
                detector_name="synthetic-test-detector",
            )
        )
    db.add_all([*users.values(), incident, *detections])
    db.flush()
    return {"users": users, "incident": incident, "detections": detections}
