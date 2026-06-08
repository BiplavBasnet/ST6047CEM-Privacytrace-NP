from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.contextual_detection_schema import (
    SensitiveDataClassificationListResponse,
    SyntheticDetectionPreviewRequest,
    SyntheticDetectionPreviewResponse,
)
from app.schemas.restricted_data_policy_schema import RestrictedPolicySummary
from app.schemas.taxonomy_schema import TaxonomyCategoryRead, TaxonomyListResponse, TaxonomyValidationResponse, TaxonomyVersionResponse
from app.services import (
    contextual_detection_service,
    permission_service,
    restricted_data_policy_service,
    sensitive_data_classification_service,
    taxonomy_registry_service,
)


router = APIRouter(tags=["sensitive-data-taxonomy"])


def _restricted_access(db: Session, user: User) -> bool:
    return permission_service.restricted_detection_authorised(db, user)


@router.get("/taxonomy/categories", response_model=TaxonomyListResponse)
@router.get("/sensitive-data-taxonomy", response_model=TaxonomyListResponse)
def list_taxonomy_categories(
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
    db: Session = Depends(get_db_session),
):
    registry = taxonomy_registry_service.load_taxonomy()
    authorised = _restricted_access(db, user)
    categories = [taxonomy_registry_service.category_to_read(item) for item in registry.enabled_categories() if authorised or not item.get("internal_only")]
    return TaxonomyListResponse(taxonomy_version=registry.version, categories=categories, total=len(categories))


@router.get("/taxonomy/version", response_model=TaxonomyVersionResponse)
@router.get("/sensitive-data-taxonomy/version", response_model=TaxonomyVersionResponse)
def taxonomy_version(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
):
    return taxonomy_registry_service.version_response()


@router.get("/sensitive-data-taxonomy/{taxonomy_code}", response_model=TaxonomyCategoryRead)
def taxonomy_category(
    taxonomy_code: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
    db: Session = Depends(get_db_session),
):
    try:
        item = taxonomy_registry_service.load_taxonomy().category(taxonomy_code)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Taxonomy category was not found.") from exc
    if item.get("internal_only") and not _restricted_access(db, user):
        raise HTTPException(status_code=404, detail="Taxonomy category was not found.")
    return taxonomy_registry_service.category_to_read(item)

@router.post("/taxonomy/validate", response_model=TaxonomyValidationResponse)
@router.post("/sensitive-data-taxonomy/validate", response_model=TaxonomyValidationResponse)
def validate_taxonomy(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_VALIDATE))],
):
    return taxonomy_registry_service.validate_taxonomy_file()


@router.get("/taxonomy/restricted-policy", response_model=RestrictedPolicySummary)
def restricted_policy(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
):
    return restricted_data_policy_service.policy_summary()


@router.post("/taxonomy/contextual-preview", response_model=SyntheticDetectionPreviewResponse)
def preview_contextual_detection(
    body: SyntheticDetectionPreviewRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
    db: Session = Depends(get_db_session),
):
    settings = get_settings()
    if not getattr(settings, "detector_preview_enabled", False):
        raise HTTPException(status_code=404, detail="Synthetic detector preview is disabled.")
    results = contextual_detection_service.classify_structured_fields(body.fields, source_context=body.source_context, hmac_key=getattr(settings, "detection_hmac_key", ""))
    if not _restricted_access(db, user):
        results = [item for item in results if not item.internal_only]
    return SyntheticDetectionPreviewResponse(results=results, total=len(results))


@router.get("/incidents/{incident_id}/sensitive-classifications", response_model=SensitiveDataClassificationListResponse)
def list_sensitive_classifications(
    incident_id: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
    db: Session = Depends(get_db_session),
):
    authorised = _restricted_access(db, user)
    records, restricted_present = sensitive_data_classification_service.list_classifications(db, incident_id, authorised_restricted_access=authorised)
    return SensitiveDataClassificationListResponse(
        incident_id=incident_id,
        classifications=records,
        total=len(records),
        restricted_information_present=restricted_present,
        restricted_message="Restricted compliance information is present and requires authorised access." if restricted_present and not authorised else None,
    )

@router.get("/incidents/{incident_id}/restricted-detections", response_model=SensitiveDataClassificationListResponse)
def list_restricted_detections(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_RESTRICTED_DETECTION_READ))],
    db: Session = Depends(get_db_session),
):
    records, restricted_present = sensitive_data_classification_service.list_classifications(db, incident_id, authorised_restricted_access=True)
    restricted_records = [item for item in records if item.get("internal_only")]
    return SensitiveDataClassificationListResponse(
        incident_id=incident_id,
        classifications=restricted_records,
        total=len(restricted_records),
        restricted_information_present=restricted_present,
    )
