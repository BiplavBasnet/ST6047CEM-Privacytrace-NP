"""Phase 8 hardening force-check (no Phase 9). Run from backend with DB up."""
from __future__ import annotations

import json
import sys

from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.database import SessionLocal, check_database_connection
from app.db.seed_phase2 import seed_phase2
from app.main import app
from app.models import AuditLog, Incident, ReviewDecision
from app.models.enums import IncidentStatus
from app.services import fix_verification_gate_service

SEED_INCIDENT_ID = "INC-SEED-001"
RAW = ("9841234567", "WALLET-NP-88291", "pk_test_np_fake_12345")
OVERCLAIM = ("developer fault", "proven cause", "confirmed blame", "guaranteed cause")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"PASS: {msg}")


def pipeline(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


def clear_reviews(incident_id: str) -> None:
    """Reset review history so gate checks reflect the current scenario only."""
    db = SessionLocal()
    try:
        db.execute(
            delete(ReviewDecision).where(ReviewDecision.incident_id == incident_id)
        )
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == incident_id)
        )
        if incident:
            incident.status = IncidentStatus.UNDER_REVIEW
        db.commit()
    finally:
        db.close()


def gate_allowed(client: TestClient) -> bool:
    db = SessionLocal()
    try:
        return fix_verification_gate_service.can_start_fix_verification(db, SEED_INCIDENT_ID)
    finally:
        db.close()


def main() -> None:
    if not check_database_connection():
        fail("PostgreSQL not reachable; start docker compose up -d")

    seed_phase2()
    client = TestClient(app)

    # 8. No Phase 9 routes
    paths = [getattr(r, "path", "") for r in app.routes]
    if any("/verify-fix" in p for p in paths):
        fail("Phase 9 route /verify-fix exists")
    ok("No /verify-fix route registered")

    # 7. Fix verification gate (run before decision-mapping loop on this DB)
    pipeline(client)
    clear_reviews(SEED_INCIDENT_ID)
    if gate_allowed(client):
        fail("gate allowed with no review")
    ok("Gate blocked: no review")

    pipeline(client)
    clear_reviews(SEED_INCIDENT_ID)
    if gate_allowed(client):
        fail("gate allowed with root-cause only")
    ok("Gate blocked: root-cause only")

    pipeline(client)
    clear_reviews(SEED_INCIDENT_ID)
    ex = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
    if ex.status_code != 200:
        fail(f"explain failed: {ex.text}")
    if gate_allowed(client):
        fail("gate allowed with LLM only")
    ok("Gate blocked: LLM explanation only")

    for decision in ("rejected", "inconclusive", "request_more_evidence"):
        pipeline(client)
        client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": decision, "reviewer_id": 1},
        )
        if gate_allowed(client):
            fail(f"gate allowed after {decision}")
        ok(f"Gate blocked: {decision} review")

    pipeline(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={"decision": "approved", "reviewer_id": 1},
    )
    if not gate_allowed(client):
        fail("gate should allow approved + confirmed_incident")
    ok("Gate allowed: approved + confirmed_incident")

    # Decision mapping (1-4)
    expected = {
        "approved": "confirmed_incident",
        "rejected": "false_positive",
        "inconclusive": "under_review",
        "request_more_evidence": "needs_more_evidence",
    }
    for decision, status in expected.items():
        pipeline(client)
        r = client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": decision, "reviewer_id": 1},
        )
        if r.status_code != 200:
            fail(f"{decision} review -> {r.status_code}: {r.text}")
        if r.json()["incident_status"] != status:
            fail(f"{decision} expected status {status}, got {r.json()['incident_status']}")
        ok(f"Review {decision} -> incident status {status}")

    # 5. Invalid decision
    pipeline(client)
    db = SessionLocal()
    try:
        before_audits = db.scalar(select(func.count()).select_from(AuditLog))
        inc = db.scalar(select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID))
        status_before = inc.status.value if inc else None
    finally:
        db.close()

    bad = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={"decision": "totally_invalid", "reviewer_id": 1},
    )
    if bad.status_code not in (400, 422):
        fail(f"invalid decision expected 400/422, got {bad.status_code}")
    db = SessionLocal()
    try:
        after_audits = db.scalar(select(func.count()).select_from(AuditLog))
        inc = db.scalar(select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID))
        if after_audits != before_audits:
            fail("invalid decision created audit log")
        if inc.status.value != status_before:
            fail("invalid decision changed incident status")
    finally:
        db.close()
    ok("Invalid decision rejected; status and audit count unchanged")

    # 6. Comment safety
    pipeline(client)
    sensitive_comment = (
        "phone 9841234567 wallet WALLET-NP-88291 key pk_test_np_fake_12345"
    )
    r = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={"decision": "approved", "reviewer_id": 1, "comment": sensitive_comment},
    )
    if r.status_code != 200:
        fail(f"sensitive comment (maskable) rejected unexpectedly: {r.text}")
    audit = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
    blob = json.dumps(audit.json())
    for s in RAW:
        if s in blob:
            fail(f"GET /audit-logs returned raw value: {s}")
    ok("Sensitive values masked; not in audit log response")

    for phrase in ("developer fault", "proven cause"):
        pipeline(client)
        oc = client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": "approved", "reviewer_id": 1, "comment": phrase},
        )
        if oc.status_code != 422:
            fail(f"overclaim '{phrase}' should be 422, got {oc.status_code}")
        audit = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
        ablob = json.dumps(audit.json()).lower()
        if phrase in ablob:
            fail(f"overclaim '{phrase}' in audit logs")
    ok("Overclaim phrases rejected; not in audit logs")

    print("\nPHASE 8 HARDENING FORCE-CHECK: ALL MANUAL CHECKS PASSED")


if __name__ == "__main__":
    main()
