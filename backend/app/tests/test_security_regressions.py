from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings, synthetic_demo_actions_allowed
from app.core.request_body_limit import RequestBodyLimitMiddleware
from app.schemas.final_report_schema import (
    FinalInvestigationReport,
    FinalReportEvidenceItem,
    FinalReportExecutiveSummary,
    FinalReportFixVerification,
    FinalReportGuardedExplanation,
    FinalReportHumanReview,
    FinalReportIncidentSection,
    FinalReportMetadata,
)
from app.schemas.metric_schema import RunEvaluationRequest
from app.schemas.report_schema import GenerateReportRequest
from app.schemas.review_schema import SubmitReviewRequest
from app.schemas.verification_schema import VerifyFixRequest
from app.services import final_report_service


def test_authenticated_actor_fields_are_not_client_controlled():
    assert "requested_by" not in GenerateReportRequest.model_fields
    assert "requested_by" not in VerifyFixRequest.model_fields
    assert "requested_by" not in RunEvaluationRequest.model_fields
    assert "reviewer_id" not in SubmitReviewRequest.model_fields


def test_request_body_limit_rejects_oversized_content_before_endpoint():
    test_app = FastAPI()
    test_app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16)

    @test_app.post("/echo")
    async def echo():
        return {"ok": True}

    response = TestClient(test_app).post(
        "/echo",
        content=b"x" * 17,
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code == 413
    assert "x" * 17 not in response.text


def test_request_body_limit_rejects_negative_content_length():
    test_app = FastAPI()
    test_app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16)

    @test_app.post("/echo")
    async def echo():
        return {"ok": True}

    with TestClient(test_app) as test_client:
        response = test_client.post("/echo", headers={"content-length": "-1"})

    assert response.status_code == 413


def test_synthetic_evidence_actions_are_disabled_in_production():
    assert synthetic_demo_actions_allowed(Settings(app_env="development")) is True
    assert synthetic_demo_actions_allowed(Settings(app_env="production")) is False


def test_csv_export_neutralizes_spreadsheet_formula_cells():
    report = FinalInvestigationReport(
        metadata=FinalReportMetadata(
            incident_id="INC-TEST",
            generated_at=datetime.now(timezone.utc),
            report_format="csv",
        ),
        executive_summary=FinalReportExecutiveSummary(
            human_review_status="pending",
            fix_verification_status="not completed",
        ),
        incident=FinalReportIncidentSection(
            incident_id="INC-TEST",
            title="Test",
            status="open",
        ),
        evidence_chain=[
            FinalReportEvidenceItem(
                evidence_id="EVD-TEST",
                file_name="=1+1",
                evidence_type="api_log",
                source_system="+cmd|' /C calc'!A0",
                parsing_status="parsed",
                role_in_investigation="supporting",
            )
        ],
        guarded_explanation=FinalReportGuardedExplanation(),
        human_review=FinalReportHumanReview(),
        fix_verification=FinalReportFixVerification(),
    )
    rows = list(csv.reader(io.StringIO(final_report_service.build_evidence_summary_csv(report))))
    assert rows[1][2].startswith("'+")
    assert rows[1][3].startswith("'=")
