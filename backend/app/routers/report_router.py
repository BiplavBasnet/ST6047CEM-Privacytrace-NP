from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.report_schema import (
    GenerateReportRequest,
    GenerateReportResponse,
    IncidentReportListResponse,
    IncidentReportSummary,
)
from app.services import (
    audit_service,
    final_report_bundle_service,
    final_report_pdf_service,
    final_report_service,
    integrity_ledger_service,
    organisation_access_service as org_access,
    report_service,
)
from app.services.report_safety_service import ReportSafetyError

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post(
    "/incidents/{incident_id}/generate",
    response_model=GenerateReportResponse,
)
def generate_incident_report(
    incident_id: str,
    body: GenerateReportRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        org_access.assert_incident_visible(db, current_user, incident_id)
        integrity_ledger_service.assert_export_allowed(
            db, scope_type="incident", scope_id=incident_id, executed_by=current_user.id
        )
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
    except integrity_ledger_service.IntegrityExportBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    try:
        result = report_service.generate_report(
            db,
            incident_id,
            report_type=body.report_type,
            requested_by=current_user.id,
        )
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except report_service.ReportServiceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return GenerateReportResponse(
        report_id=result.report.id,
        incident_id=incident_id,
        report_type=result.report_type,
        created_at=result.report.created_at,
        content=result.content,
        html_document=result.html_document,
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentReportListResponse,
)
def list_incident_reports(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        org_access.assert_incident_visible(db, _user, incident_id)
        rows = report_service.list_incident_reports(db, incident_id)
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    summaries: list[IncidentReportSummary] = []
    statuses = report_service.report_history_statuses(db, incident_id, rows)
    for row in rows:
        safe = report_service.report_to_safe_response(row)
        status = statuses[row.id]
        summaries.append(
            IncidentReportSummary(
                report_id=safe["report_id"],
                incident_id=safe["incident_id"],
                report_type=safe["report_type"],
                created_at=safe["created_at"],
                content=safe["content"],
                html_document=safe.get("html_document"),
                report_version=row.report_version,
                history_status=status["history_status"],
                current_chain_match_at_export=status["current_chain_match_at_export"],
            )
        )

    return IncidentReportListResponse(
        incident_id=incident_id,
        reports=summaries,
        total=len(summaries),
    )


def _actor_label(user: User | None) -> str | None:
    if user is None:
        return None
    return user.email


def _guard_final_export(db: Session, incident_id: str, user: User) -> None:
    try:
        org_access.assert_incident_visible(db, user, incident_id)
        integrity_ledger_service.assert_export_allowed(
            db, scope_type="incident", scope_id=incident_id, executed_by=user.id
        )
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
    except integrity_ledger_service.IntegrityExportBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _log_final_export(
    db: Session,
    *,
    incident_id: str,
    export_format: str,
    user: User,
    report,
) -> None:
    final_report_service.persist_final_report_export(db, report)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_REPORT_EXPORTED,
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value if hasattr(user.role, "value") else str(user.role),
        target_type="incident",
        target_id=incident_id,
        details={"export_kind": "final_investigation_report", "format": export_format},
    )
    db.commit()


@router.get("/incidents/{incident_id}/final-report.json")
def export_final_report_json(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    _guard_final_export(db, incident_id, current_user)
    try:
        report = final_report_service.build_final_investigation_report(
            db,
            incident_id,
            report_format="json",
            generated_by=_actor_label(current_user),
        )
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _log_final_export(db, incident_id=incident_id, export_format="json", user=current_user, report=report)
    return report.model_dump(mode="json")


@router.get("/incidents/{incident_id}/final-report.html")
def export_final_report_html(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    _guard_final_export(db, incident_id, current_user)
    try:
        report = final_report_service.build_final_investigation_report(
            db,
            incident_id,
            report_format="html",
            generated_by=_actor_label(current_user),
        )
        html_doc = final_report_service.render_final_report_html(report)
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _log_final_export(db, incident_id=incident_id, export_format="html", user=current_user, report=report)
    return Response(content=html_doc, media_type="text/html; charset=utf-8")


@router.get("/incidents/{incident_id}/final-report.pdf")
def export_final_report_pdf(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    _guard_final_export(db, incident_id, current_user)
    try:
        report = final_report_service.build_final_investigation_report(
            db,
            incident_id,
            report_format="pdf",
            generated_by=_actor_label(current_user),
        )
        pdf_bytes = final_report_pdf_service.render_final_report_pdf(report)
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _log_final_export(db, incident_id=incident_id, export_format="pdf", user=current_user, report=report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="final-report-{incident_id}.pdf"'
        },
    )


@router.get("/incidents/{incident_id}/evidence-summary.csv")
def export_evidence_summary_csv(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    _guard_final_export(db, incident_id, current_user)
    try:
        report = final_report_service.build_final_investigation_report(
            db,
            incident_id,
            report_format="csv",
            generated_by=_actor_label(current_user),
        )
        csv_text = final_report_service.build_evidence_summary_csv(report)
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _log_final_export(db, incident_id=incident_id, export_format="csv", user=current_user, report=report)
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-summary-{incident_id}.csv"'
        },
    )


@router.get("/incidents/{incident_id}/final-report-bundle.zip")
def export_final_report_bundle(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_REPORT_GENERATE))
    ],
    db: Session = Depends(get_db_session),
):
    _guard_final_export(db, incident_id, current_user)
    try:
        report = final_report_service.build_final_investigation_report(
            db,
            incident_id,
            report_format="zip",
            generated_by=_actor_label(current_user),
        )
        zip_bytes = final_report_bundle_service.build_final_report_bundle(report)
    except report_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ReportSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _log_final_export(db, incident_id=incident_id, export_format="zip", user=current_user, report=report)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="final-report-bundle-{incident_id}.zip"'
        },
    )
