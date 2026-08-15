"""Phase 9 force-check — evidence-based fix verification (no Phase 10)."""
from __future__ import annotations

import json
import sys
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.config import resolve_sample_data_dir
from app.database import SessionLocal, check_database_connection
from app.db.seed_phase2 import seed_phase2
from app.main import app
from app.models import Incident, ReviewDecision
from app.models.enums import IncidentStatus
from app.services import fix_verification_gate_service

SEED_INCIDENT_ID = "INC-SEED-001"
SAFE_RETEST_BYTES = (
    resolve_sample_data_dir() / "retest_evidence" / "wallet_transfer_retest.log"
).read_bytes()

RAW_LEAKS = (
    "9841234567",
    "WALLET-NP-88291",
    "pk_test_np_fake_12345",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "Bearer eyJ",
)

OVERCLAIM = (
    "guaranteed fixed",
    "definitely fixed",
    "proven fixed",
    "incident closed automatically",
    "developer fault",
    "confirmed blame",
    "guaranteed fix",
)

JWT_LEAK = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

passed = 0
failed = 0


def step(num: int, label: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    line = f"[{tag}] {num}. {label}"
    if detail:
        line += f" — {detail}"
    print(line)
    if not ok:
        sys.exit(1)


def clear_reviews() -> None:
    db = SessionLocal()
    try:
        db.execute(
            delete(ReviewDecision).where(ReviewDecision.incident_id == SEED_INCIDENT_ID)
        )
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        if incident:
            incident.status = IncidentStatus.UNDER_REVIEW
        db.commit()
    finally:
        db.close()


def pipeline(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


def gate_allowed() -> bool:
    db = SessionLocal()
    try:
        return fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()


def verify_blocked(client: TestClient) -> tuple[bool, str]:
    r = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"requested_by": 1},
    )
    blocked = r.status_code == 422
    return blocked, f"status={r.status_code} body={r.text[:200]}"


def submit_review(client: TestClient, decision: str) -> dict:
    r = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={"decision": decision, "reviewer_id": 1},
    )
    assert r.status_code == 200, r.text
    return r.json()


def upload_retest(client: TestClient, content: bytes) -> str:
    name = f"force_retest_{uuid.uuid4().hex[:8]}.log"
    r = client.post(
        "/evidence/upload",
        files={"file": (name, content, "text/plain")},
        data={
            "evidence_type": "fixed_log",
            "linked_incident_id": SEED_INCIDENT_ID,
            "source_system": "wallet-service",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["evidence"]["evidence_id"]


def blob_has_raw(blob: str) -> list[str]:
    found = [p for p in RAW_LEAKS if p in blob]
    if 'authorization: Bearer eyJ' in blob.lower():
        found.append("authorization bearer")
    return found


def blob_has_overclaim(blob: str) -> list[str]:
    lower = blob.lower()
    return [p for p in OVERCLAIM if p.lower() in lower]


def main() -> None:
    if not check_database_connection():
        print("FAIL: PostgreSQL not reachable (docker compose up -d)")
        sys.exit(1)

    seed_phase2()
    client = TestClient(app)

    # Risk 1 — scope creep: Phase 9 routes exist; Phase 10 routes absent
    paths = [getattr(r, "path", "") for r in app.routes]
    has_verify = any("/verify-fix" in p for p in paths)
    has_list = any("/fix-verifications" in p for p in paths)
    step(
        12,
        "No Phase 10 report/metrics/dashboard endpoints",
        not any(x in "".join(paths) for x in ("/report/json", "/report/html", "/metrics", "/dashboard")),
        f"routes checked; verify-fix present={has_verify}",
    )
    step(
        0,
        "Phase 9 endpoints registered (scope: verification only)",
        has_verify and has_list,
        "POST verify-fix, GET fix-verifications",
    )

    pipeline(client)

    # 1. No review
    clear_reviews()
    blocked, detail = verify_blocked(client)
    step(1, "Fix verification with no review blocked", blocked and not gate_allowed(), detail)

    # 2. LLM only
    clear_reviews()
    client.post(f"/incidents/{SEED_INCIDENT_ID}/explain", json={"provider": "template"})
    blocked, detail = verify_blocked(client)
    step(2, "Fix verification after LLM-only blocked", blocked and not gate_allowed(), detail)

    # 3. Root-cause / analyse only
    clear_reviews()
    pipeline(client)
    blocked, detail = verify_blocked(client)
    step(3, "Fix verification after analyse-only blocked", blocked and not gate_allowed(), detail)

    # 4–6. Rejected / inconclusive / request_more_evidence
    for num, decision in (
        (4, "rejected"),
        (5, "inconclusive"),
        (6, "request_more_evidence"),
    ):
        clear_reviews()
        pipeline(client)
        submit_review(client, decision)
        blocked, detail = verify_blocked(client)
        step(num, f"Fix verification after {decision} review blocked", blocked, detail)

    # 7. Approved review -> confirmed_incident
    clear_reviews()
    pipeline(client)
    body = submit_review(client, "approved")
    step(
        7,
        "Approved review sets confirmed_incident",
        body.get("incident_status") == "confirmed_incident",
        f"status={body.get('incident_status')}",
    )

    # 8. Clean retest -> passed (or inconclusive if incomplete)
    safe_id = upload_retest(
        client, SAFE_RETEST_BYTES + f"\n# force {uuid.uuid4().hex}\n".encode()
    )
    r = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    ok8 = r.status_code == 200 and r.json().get("verification_status") in (
        "passed",
        "inconclusive",
    )
    step(
        8,
        "Clean retest evidence verification",
        ok8,
        f"status={r.json().get('verification_status') if r.status_code == 200 else r.text[:120]}",
    )
    if r.status_code == 200:
        resp_blob = json.dumps(r.json())
        raw_found = blob_has_raw(resp_blob)
        step(
            81,
            "Clean verify response has no raw sensitive values",
            not raw_found,
            str(raw_found) if raw_found else "none",
        )

    # 9. Unsafe retest -> failed, no echo of raw values
    unsafe_cases = [
        ('{"message":"phone 9841234567 still logged"}\n', "phone"),
        ('{"wallet_id":"WALLET-NP-88291"}\n', "wallet"),
        ('{"api_key":"pk_test_np_fake_12345"}\n', "api_key"),
        (f'{{"token":"{JWT_LEAK}"}}\n', "jwt"),
    ]
    for leak_bytes, label in unsafe_cases:
        clear_reviews()
        pipeline(client)
        submit_review(client, "approved")
        bad_id = upload_retest(client, leak_bytes)
        r = client.post(
            f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
            json={"retest_evidence_ids": [bad_id], "requested_by": 1},
        )
        body = r.json() if r.status_code == 200 else {}
        blob = json.dumps(body)
        step(
            9,
            f"Unsafe retest ({label}) -> failed, no raw echo",
            r.status_code == 200
            and body.get("verification_status") == "failed"
            and not blob_has_raw(blob),
            f"verification_status={body.get('verification_status')} raw_in_response={blob_has_raw(blob)}",
        )

    # 10. GET fix-verifications metadata
    clear_reviews()
    pipeline(client)
    submit_review(client, "approved")
    safe_id = upload_retest(
        client, SAFE_RETEST_BYTES + f"\n# list {uuid.uuid4().hex}\n".encode()
    )
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    lr = client.get(f"/incidents/{SEED_INCIDENT_ID}/fix-verifications")
    list_ok = lr.status_code == 200 and len(lr.json().get("verifications", [])) > 0
    list_blob = json.dumps(lr.json())
    raw_in_list = blob_has_raw(list_blob)
    over_in_list = blob_has_overclaim(list_blob)
    has_evd = "EVD-" in list_blob or "evidence_used" in list_blob
    step(
        10,
        "GET fix-verifications safe metadata",
        list_ok and not raw_in_list and not over_in_list and has_evd,
        f"count={len(lr.json().get('verifications', []))} raw={raw_in_list} overclaim={over_in_list}",
    )

    # 11. Not auto-closed
    db = SessionLocal()
    try:
        inc = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        not_closed = inc is not None and inc.status != IncidentStatus.CLOSED
    finally:
        db.close()
    step(
        11,
        "Incident not automatically closed",
        not_closed,
        f"incident.status={inc.status.value if inc else 'missing'}",
    )

    # Risk 2 — verification is evidence-based (not manual mark-fixed)
    # Risk 3 — state transitions respect gate (covered by steps 1–7)
    print()
    print(f"Phase 9 force-check complete: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
