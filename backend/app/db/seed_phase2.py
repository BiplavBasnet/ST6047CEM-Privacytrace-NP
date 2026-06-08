"""Phase 2 seed: synthetic users, one incident, two linked evidence files."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import EvidenceFile, Incident, User
from app.models.enums import EvidenceType, IncidentStatus, ParsingStatus, Severity, UserRole

SEED_INCIDENT_ID = "INC-SEED-001"


def seed_phase2(db: Session | None = None) -> None:
    owns_session = db is None
    if owns_session:
        db = SessionLocal()
    try:
        existing = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        if existing:
            print(f"Seed skipped: incident {SEED_INCIDENT_ID} already exists.")
            return

        admin = User(
            name="Admin User",
            email="admin@example.com",
            role=UserRole.ADMIN,
        )
        developer = User(
            name="Developer User",
            email="developer@example.com",
            role=UserRole.DEVELOPER,
        )
        analyst = User(
            name="Security Analyst",
            email="analyst@example.com",
            role=UserRole.SECURITY_ANALYST,
        )
        db.add_all([admin, developer, analyst])
        db.flush()
        from app.services import organisation_access_service as org_access

        org = org_access.attach_demo_memberships(db, [admin, developer, analyst])

        incident = Incident(
            incident_id=SEED_INCIDENT_ID,
            organisation_id=org.id if org else None,
            title="Sample sensitive data exposure in wallet API logs",
            affected_endpoint="/api/v1/wallet/transfer",
            affected_service="wallet-service",
            status=IncidentStatus.NEW,
            severity=Severity.HIGH,
            summary=(
                "Synthetic seed incident for Phase 2 database verification. "
                "No real customer data."
            ),
        )
        db.add(incident)
        db.flush()

        evidence_api = EvidenceFile(
            evidence_id="EVD-SEED-API-001",
            file_name="wallet_api.log",
            evidence_type=EvidenceType.API_LOG,
            source_system="wallet-service",
            file_hash="sha256:seed_api_log_placeholder",
            uploaded_by=admin.id,
            parsing_status=ParsingStatus.PARSED,
            linked_incident_id=SEED_INCIDENT_ID,
        )
        evidence_sast = EvidenceFile(
            evidence_id="EVD-SEED-SAST-001",
            file_name="semgrep_report.json",
            evidence_type=EvidenceType.SEMGREP_REPORT,
            source_system="ci-pipeline",
            file_hash="sha256:seed_semgrep_placeholder",
            uploaded_by=admin.id,
            parsing_status=ParsingStatus.PARSED,
            linked_incident_id=SEED_INCIDENT_ID,
        )
        db.add_all([evidence_api, evidence_sast])
        if owns_session:
            db.commit()
        else:
            db.flush()

        print("Phase 2 seed completed:")
        print(f"  - 3 users (admin, developer, security_analyst)")
        print(f"  - 1 incident ({SEED_INCIDENT_ID})")
        print("  - 2 evidence files linked to incident")
    except Exception:
        if owns_session:
            db.rollback()
        raise
    finally:
        if owns_session:
            db.close()


if __name__ == "__main__":
    seed_phase2()
