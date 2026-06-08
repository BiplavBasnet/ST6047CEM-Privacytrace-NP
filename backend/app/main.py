import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings, validate_runtime_configuration
from app.database import check_database_connection
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.request_body_limit import RequestBodyLimitMiddleware
from app.routers import (
    ai_remediation_router,
    alert_operations_router,
    breach_decision_router,
    counterfactual_router,
    evidence_provenance_router,
    exposure_profile_router,
    incident_timeline_router,
    integrity_router,
    preventive_control_router,
    sensitive_taxonomy_router,
    audit_router,
    auth_router,
    cicd_evidence_router,
    connector_router,
    evidence_router,
    explanation_router,
    fix_verification_router,
    health_router,
    incident_router,
    incident_workflow_router,
    integration_router,
    integration_gateway_router,
    live_monitor_router,
    scanner_bridge_router,
    metrics_router,
    remediation_action_router,
    remediation_lifecycle_router,
    privacy_impact_router,
    privacy_response_router,
    report_router,
    review_router,
    security_router,
    user_router,
    organisation_setup_router,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    validate_runtime_configuration(settings)
    if settings.nepal_financial_taxonomy_enabled:
        from app.services import exposure_profile_service, taxonomy_registry_service
        taxonomy_registry_service.load_taxonomy(settings.nepal_financial_taxonomy_path)
        if settings.combined_exposure_rules_enabled:
            exposure_profile_service.load_rules(settings.combined_exposure_rules_path)
    if check_database_connection():
        logger.info("PrivacyTrace-NP started; database connection OK.")
        try:
            from app.database import SessionLocal
            from app.services import controlled_rollback_service

            with SessionLocal() as db:
                recovered = controlled_rollback_service.recover_incomplete_patches(db)
            if recovered:
                logger.info(
                    "Controlled patch recovery scanned %s incomplete workspace(s).",
                    len(recovered),
                )
        except Exception:
            logger.exception("Controlled patch startup recovery skipped due to error.")
    else:
        logger.warning(
            "PrivacyTrace-NP started; database is not reachable at %s",
            settings.database_url.split("@")[-1],
        )
    yield


app = FastAPI(
    title="PrivacyTrace-NP",
    description=(
        "Privacy-preserving incident traceability framework for "
        "Nepalese digital financial service API environments."
    ),
    version=get_settings().api_version,
    lifespan=lifespan,
)

@app.exception_handler(RequestValidationError)
async def safe_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return validation errors without echoing raw request input.

    FastAPI's default handler includes the submitted value in each error's
    ``input``/``ctx`` fields. If a malformed request carries a raw sensitive
    value, that value would be echoed back in the 422 response. This handler
    keeps the useful location/message fields and drops the raw input echo.
    """
    safe_errors = [
        {
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": safe_errors})


# Phase 11: allow local Vite dashboard (http://127.0.0.1:5173) to call this API.
# No business-logic change â€” browser same-origin policy only.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type"],
)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_bytes=get_settings().max_request_body_bytes,
)

app.include_router(health_router.router)
app.include_router(auth_router.router)
app.include_router(organisation_setup_router.router)
app.include_router(cicd_evidence_router.router)
app.include_router(ai_remediation_router.router)
app.include_router(user_router.router)
app.include_router(evidence_router.router)
app.include_router(incident_router.router)
app.include_router(incident_workflow_router.router)
app.include_router(explanation_router.router)
app.include_router(review_router.router)
app.include_router(remediation_action_router.router)
app.include_router(remediation_lifecycle_router.router)
app.include_router(privacy_impact_router.router)
app.include_router(privacy_response_router.router)
app.include_router(breach_decision_router.router)
app.include_router(evidence_provenance_router.router)
app.include_router(integrity_router.router)
app.include_router(counterfactual_router.router)
app.include_router(alert_operations_router.router)
app.include_router(incident_timeline_router.router)
app.include_router(preventive_control_router.router)
app.include_router(sensitive_taxonomy_router.router)
app.include_router(exposure_profile_router.router)
app.include_router(audit_router.router)
app.include_router(fix_verification_router.router)
app.include_router(report_router.router)
app.include_router(metrics_router.router)
app.include_router(security_router.router)
app.include_router(integration_gateway_router.router)
app.include_router(connector_router.router)
app.include_router(integration_router.router)
app.include_router(live_monitor_router.router)
app.include_router(scanner_bridge_router.router)
