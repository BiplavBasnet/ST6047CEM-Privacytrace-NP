from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from functools import lru_cache

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings, resolve_rules_dir
from app.models.detection import Detection
from app.models.exposure_profile import ExposureProfile
from app.models.incident import Incident
from app.models.privacy_impact import PrivacyHarm, PrivacyImpactAssessment, PrivacyImpactFactor
from app.models.sensitive_data_classification import SensitiveDataClassification
from app.schemas.privacy_impact_schema import PrivacyImpactAssessRequest, PrivacyImpactResponse, PrivacyImpactReviewRequest
from app.services import audit_safety_service, audit_service


class PrivacyImpactError(Exception):
    pass


class PrivacyImpactNotFoundError(PrivacyImpactError):
    pass


class PrivacyImpactStateError(PrivacyImpactError):
    pass


PRIVACY_IMPACT_METHOD_VERSION = "privacy-impact-v1"

# Legacy detector types → ENISA-inspired privacy-impact categories.
_TYPE_TO_CATEGORY = {
    "nepal_phone": "contact_data", "wallet_id": "financial_data", "transaction_ref": "financial_data",
    "authorization_header": "authentication_data", "jwt_token": "authentication_data", "bearer_token": "authentication_data",
    "api_key": "authentication_data", "password": "authentication_data", "password_hash": "authentication_data",
    "access_token": "authentication_data", "session_token": "authentication_data", "private_key": "authentication_data",
    "credential_username": "authentication_data",
}

# Nepal taxonomy groups → ENISA-inspired privacy-impact categories.
_TAXONOMY_GROUP_TO_CATEGORY = {
    "identity": "government_identifier",
    "kyc_document": "government_identifier",
    "financial_account": "financial_data",
    "payment_card": "financial_data",
    "transaction": "financial_data",
    "merchant_kyc": "financial_data",
    "authentication_credential": "authentication_data",
    "restricted_aml": "sensitive_personal_data",
}


def configured_credential_types() -> set[str]:
    configured = {
        value.strip().lower()
        for value in get_settings().breach_credential_categories.split(",")
        if value.strip()
    }
    # Always treat password hashes / credential usernames as credential material.
    configured.update({"password_hash", "credential_username", "password"})
    return configured


def _category_for_taxonomy_code(code: str, group: str | None = None) -> str:
    if group and group in _TAXONOMY_GROUP_TO_CATEGORY:
        return _TAXONOMY_GROUP_TO_CATEGORY[group]
    try:
        from app.services.taxonomy_registry_service import load_taxonomy

        item = load_taxonomy().category(code)
        mapped = _TAXONOMY_GROUP_TO_CATEGORY.get(str(item.get("group") or ""))
        if mapped:
            return mapped
    except (KeyError, ValueError):
        pass
    return _TYPE_TO_CATEGORY.get(code, "simple_personal_data")

@lru_cache
def load_privacy_impact_rules() -> dict:
    with (resolve_rules_dir() / "privacy_impact_rules.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def breach_severity_level(score: float) -> str:
    settings = get_settings()
    if score < settings.breach_severity_medium_threshold:
        return "low"
    if score < settings.breach_severity_high_threshold:
        return "medium"
    if score < settings.breach_severity_very_high_threshold:
        return "high"
    return "very_high"


def privacy_harm_level(score: int) -> str:
    settings = get_settings()
    if score < settings.privacy_harm_medium_threshold:
        return "low"
    if score < settings.privacy_harm_high_threshold:
        return "medium"
    if score < settings.privacy_harm_critical_threshold:
        return "high"
    return "critical"


def _safe_text(value: str) -> str:
    return audit_safety_service.mask_sensitive_text(value.strip())


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def _fingerprint(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_approver_separation(
    *, created_by: int | None, reviewed_by: int | None, actor_id: int
) -> None:
    if actor_id in {created_by, reviewed_by}:
        raise PrivacyImpactStateError("The assessment approver must be independent of its creator and reviewer.")


def _default_harm(categories: set[str], credential: bool, evidence_ids: list[str]) -> dict:
    if credential:
        return {"harm_category": "account_takeover", "likelihood": 2, "magnitude": 3, "evidence_ids": evidence_ids, "explanation": "Exposed authentication material may enable account misuse if it remains active.", "uncertainty": "Credential validity and access scope require verification.", "recommended_mitigation": "Validate credential status and complete approved containment."}
    if "financial_data" in categories:
        return {"harm_category": "financial_fraud", "likelihood": 2, "magnitude": 3, "evidence_ids": evidence_ids, "explanation": "Financial data exposure may increase fraud risk.", "uncertainty": "External access and affected-subject scope are not yet confirmed.", "recommended_mitigation": "Confirm exposure scope and monitor affected accounts."}
    if "contact_data" in categories:
        return {"harm_category": "phishing", "likelihood": 2, "magnitude": 2, "evidence_ids": evidence_ids, "explanation": "Contact data exposure may increase targeted phishing risk.", "uncertainty": "External access is not yet confirmed.", "recommended_mitigation": "Review exposure scope and prepare protective guidance."}
    return {"harm_category": "unwanted_disclosure", "likelihood": 1, "magnitude": 2, "evidence_ids": evidence_ids, "explanation": "Detected personal data may have been disclosed unexpectedly.", "uncertainty": "The detector result requires human verification.", "recommended_mitigation": "Verify the context and reduce further disclosure."}


def _resolve_assessment_inputs(
    db: Session,
    incident_id: str,
    request: PrivacyImpactAssessRequest,
    detections: list[Detection],
) -> tuple[set[str], list[str], bool, dict[str, list[str]], str | None, str | None]:
    """Merge legacy detections, taxonomy classifications, and exposure profiles."""
    detection_ids = [item.detection_id for item in detections]
    categories: set[str] = {
        _TYPE_TO_CATEGORY.get(item.sensitive_type, "simple_personal_data") for item in detections
    }
    category_detection_map: dict[str, list[str]] = {}
    for item in detections:
        code = _TYPE_TO_CATEGORY.get(item.sensitive_type, "simple_personal_data")
        category_detection_map.setdefault(code, []).append(item.detection_id)

    classifications = list(
        db.scalars(
            select(SensitiveDataClassification)
            .where(SensitiveDataClassification.incident_id == incident_id)
            .order_by(SensitiveDataClassification.id)
        ).all()
    )
    taxonomy_version = None
    for row in classifications:
        if row.evidence_role == "retest":
            continue
        taxonomy_version = taxonomy_version or row.taxonomy_version
        impact_category = _category_for_taxonomy_code(row.taxonomy_code, row.category_group)
        categories.add(impact_category)
        if row.detection_id:
            category_detection_map.setdefault(impact_category, []).append(row.detection_id)

    profiles = list(
        db.scalars(
            select(ExposureProfile).where(
                ExposureProfile.incident_id == incident_id,
                ExposureProfile.is_current.is_(True),
            )
        ).all()
    )
    combination_version = None
    for profile in profiles:
        combination_version = combination_version or profile.combination_ruleset_version
        taxonomy_version = taxonomy_version or profile.taxonomy_version
        # Full KYC / account-takeover style profiles raise context toward higher categories.
        if "kyc" in profile.profile_type or "identity" in profile.profile_type:
            categories.add("government_identifier")
        if "account_takeover" in profile.profile_type or "credential" in profile.profile_type:
            categories.add("authentication_data")
        if "merchant" in profile.profile_type or "financial" in profile.profile_type:
            categories.add("financial_data")
        for detection_id in profile.supporting_detection_ids or []:
            detection_ids.append(str(detection_id))

    categories |= set(request.data_categories)
    detection_ids = list(dict.fromkeys(detection_ids))

    credential_types = {
        item.sensitive_type
        for item in detections
        if item.sensitive_type.lower() in configured_credential_types()
    }
    taxonomy_credentials = {
        row.taxonomy_code
        for row in classifications
        if row.category_group == "authentication_credential"
        or row.taxonomy_code.lower() in configured_credential_types()
        or (row.credential_status or "").lower() in {"active", "possible_active", "unknown"}
    }
    credential_present = (
        request.credential_exposure_present
        or bool(credential_types)
        or bool(taxonomy_credentials)
        or any("account_takeover" in (p.profile_type or "") for p in profiles)
    )
    # Stash supporting map on request-local attribute via returned structure.
    return (
        categories,
        detection_ids,
        credential_present,
        category_detection_map,
        taxonomy_version,
        combination_version,
    )


def assess_incident(
    db: Session,
    incident_id: str,
    request: PrivacyImpactAssessRequest,
    *,
    actor_id: int | None,
    commit: bool = True,
) -> tuple[PrivacyImpactAssessment, bool]:
    settings = get_settings()
    incident = db.scalar(
        select(Incident).where(Incident.incident_id == incident_id).with_for_update()
    )
    if incident is None:
        raise PrivacyImpactNotFoundError(f"Incident not found: {incident_id}")

    detections = list(db.scalars(select(Detection).where(Detection.incident_id == incident_id).order_by(Detection.id)).all())
    (
        categories,
        evidence_ids,
        credential_present,
        category_detection_map,
        taxonomy_version,
        combination_version,
    ) = _resolve_assessment_inputs(db, incident_id, request, detections)
    if not categories:
        raise PrivacyImpactStateError("At least one detected or reviewed data category is required.")

    rules = load_privacy_impact_rules()
    category_rules = rules["data_categories"]
    scores = {
        code: float(category_rules[code]["score"])
        for code in categories
        if code in category_rules
    }
    if not scores:
        raise PrivacyImpactStateError("No recognised data categories were available for scoring.")
    if "authentication_data" in scores and request.credential_access_impact != "unknown":
        scores["authentication_data"] = max(scores["authentication_data"], float(rules["credential_access_impact"][request.credential_access_impact]))
    dpc = max(scores.values())
    circumstances_score = round(sum(float(rules["circumstances"][item.code]["score"]) for item in request.circumstances), 2)
    severity_score = round(dpc * request.ease_of_identification_score + circumstances_score, 2)

    harm_inputs = [item.model_dump() for item in request.likely_harms]
    if not harm_inputs:
        harm_inputs = [_default_harm(categories, credential_present, evidence_ids)]
    top_harm = max(harm_inputs, key=lambda item: (item["likelihood"] * item["magnitude"], item["magnitude"], item["harm_category"]))
    harm_score = int(top_harm["likelihood"] * top_harm["magnitude"])
    resolved_taxonomy_version = taxonomy_version or settings.nepal_financial_taxonomy_version
    resolved_combination_version = (
        combination_version or settings.combined_exposure_ruleset_version
    )
    payload = {
        "detections": evidence_ids, "categories": sorted(categories), "eoi": request.ease_of_identification_score,
        "circumstances": [item.model_dump() for item in request.circumstances], "harms": harm_inputs,
        "subject_count": request.affected_subject_count, "credential": credential_present,
        "credential_active": request.credential_active, "public": request.public_exposure_present,
        "external": request.external_access_confirmed, "malicious": request.malicious_intent_status,
        "encrypted": request.encrypted_or_unintelligible, "idempotency_key": request.idempotency_key,
        "taxonomy_version": resolved_taxonomy_version,
        "combination_ruleset_version": resolved_combination_version,
    }
    input_fingerprint = _fingerprint(payload)
    existing = db.scalar(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.incident_id == incident_id, PrivacyImpactAssessment.input_fingerprint == input_fingerprint))
    if existing is not None:
        from app.services import privacy_breach_alert_service

        privacy_breach_alert_service.evaluate_assessment(db, existing, actor_id=actor_id)
        if commit:
            db.commit()
            db.refresh(existing)
        return existing, False

    version = int(db.scalar(select(func.coalesce(func.max(PrivacyImpactAssessment.assessment_version), 0)).where(PrivacyImpactAssessment.incident_id == incident_id)) or 0) + 1
    confidence = "high" if request.external_access_confirmed and request.circumstances else "medium" if request.circumstances or request.likely_harms else "low"
    assessment = PrivacyImpactAssessment(
        assessment_id=_new_id("PIA"), incident_id=incident_id, assessment_version=version, status="draft",
        data_processing_context_score=dpc, ease_of_identification_score=request.ease_of_identification_score,
        circumstances_score=circumstances_score, breach_severity_score=severity_score,
        breach_severity_level=breach_severity_level(severity_score), harm_likelihood=top_harm["likelihood"],
        harm_magnitude=top_harm["magnitude"], privacy_harm_score=harm_score, privacy_harm_level=privacy_harm_level(harm_score),
        affected_subject_count=request.affected_subject_count, affected_subject_count_status=request.affected_subject_count_status,
        credential_exposure_present=credential_present, public_exposure_present=request.public_exposure_present,
        external_access_confirmed=request.external_access_confirmed, malicious_intent_status=request.malicious_intent_status,
        encrypted_or_unintelligible=request.encrypted_or_unintelligible, assessment_confidence=confidence,
        limitations=[_safe_text(item) for item in request.limitations], data_categories=sorted(categories),
        input_fingerprint=input_fingerprint, taxonomy_version=resolved_taxonomy_version,
        combination_ruleset_version=resolved_combination_version, created_by=actor_id,
    )
    db.add(assessment)
    db.flush()
    for code in sorted(scores):
        supporting = list(dict.fromkeys(category_detection_map.get(code, [])))
        db.add(PrivacyImpactFactor(assessment_id=assessment.assessment_id, factor_type="data_processing_context", factor_code=code,
            factor_label=category_rules[code]["label"], score_contribution=scores[code], evidence_ids=supporting,
            reason=f"Configured {category_rules[code]['label'].lower()} score; the highest applicable category sets the context score.", source="configured_rule", method_version=PRIVACY_IMPACT_METHOD_VERSION, is_system_generated=True))
    db.add(PrivacyImpactFactor(assessment_id=assessment.assessment_id, factor_type="ease_of_identification", factor_code=f"eoi_{request.ease_of_identification_score}", factor_label="Ease of identification", score_contribution=request.ease_of_identification_score, evidence_ids=evidence_ids, reason="Ease of identification selected for the available subject-linking evidence.", source="review_input" if actor_id else "system_default", method_version=PRIVACY_IMPACT_METHOD_VERSION, is_system_generated=actor_id is None))
    for item in request.circumstances:
        rule = rules["circumstances"][item.code]
        db.add(PrivacyImpactFactor(assessment_id=assessment.assessment_id, factor_type="circumstance", factor_code=item.code,
            factor_label=rule["label"], score_contribution=float(rule["score"]), evidence_ids=item.evidence_ids,
            reason=_safe_text(item.reason), source="review_input", method_version=PRIVACY_IMPACT_METHOD_VERSION, is_system_generated=False))
    for item in harm_inputs:
        db.add(PrivacyHarm(harm_id=_new_id("HRM"), assessment_id=assessment.assessment_id, harm_category=item["harm_category"],
            likelihood=item["likelihood"], magnitude=item["magnitude"], harm_score=item["likelihood"] * item["magnitude"],
            evidence_ids=item["evidence_ids"], explanation=_safe_text(item["explanation"]), uncertainty=_safe_text(item["uncertainty"]),
            recommended_mitigation=_safe_text(item["recommended_mitigation"])))
    db.flush()
    created_factors = list(db.scalars(select(PrivacyImpactFactor).where(
        PrivacyImpactFactor.assessment_id == assessment.assessment_id
    )).all())
    for factor in created_factors:
        audit_service.log_action(
            db,
            action="privacy_impact_factor_added",
            actor_id=actor_id,
            target_type="privacy_impact_factor",
            target_id=str(factor.id),
            details={
                "incident_id": incident_id,
                "assessment_id": assessment.assessment_id,
                "factor_type": factor.factor_type,
                "factor_code": factor.factor_code,
                "score_contribution": factor.score_contribution,
                "source": factor.source,
                "evidence_ids": factor.evidence_ids,
            },
        )
    audit_service.log_action(db, action="privacy_impact_assessment_generated", actor_id=actor_id, target_type="privacy_impact_assessment", target_id=assessment.assessment_id,
        details={"incident_id": incident_id, "assessment_version": version, "breach_severity_level": assessment.breach_severity_level,
                 "privacy_harm_level": assessment.privacy_harm_level, "credential_exposure_present": credential_present, "evidence_ids": evidence_ids})
    if actor_id is not None and (request.data_categories or request.circumstances or request.likely_harms):
        audit_service.log_action(db, action="privacy_impact_human_override", actor_id=actor_id, target_type="privacy_impact_assessment", target_id=assessment.assessment_id,
            details={"incident_id": incident_id, "reason_code": "reviewed_context_supplied"})
    from app.services import privacy_breach_alert_service
    privacy_breach_alert_service.evaluate_assessment(db, assessment, actor_id=actor_id)
    if commit:
        db.commit()
        db.refresh(assessment)
    else:
        db.flush()
    return assessment, True


def get_latest_assessment(db: Session, incident_id: str) -> PrivacyImpactAssessment | None:
    return db.scalar(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.incident_id == incident_id).order_by(PrivacyImpactAssessment.assessment_version.desc()).limit(1))


def get_assessment(db: Session, assessment_id: str) -> PrivacyImpactAssessment:
    item = db.scalar(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.assessment_id == assessment_id))
    if item is None:
        raise PrivacyImpactNotFoundError(f"Privacy impact assessment not found: {assessment_id}")
    return item


def build_response(db: Session, incident_id: str) -> PrivacyImpactResponse:
    history = list(db.scalars(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.incident_id == incident_id).order_by(PrivacyImpactAssessment.assessment_version.desc())).all())
    latest = history[0] if history else None
    factors = list(db.scalars(select(PrivacyImpactFactor).where(PrivacyImpactFactor.assessment_id == latest.assessment_id).order_by(PrivacyImpactFactor.id)).all()) if latest else []
    harms = list(db.scalars(select(PrivacyHarm).where(PrivacyHarm.assessment_id == latest.assessment_id).order_by(PrivacyHarm.harm_score.desc())).all()) if latest else []
    return PrivacyImpactResponse(assessment=latest, factors=factors, harms=harms, history=history)


def review_assessment(
    db: Session,
    assessment_id: str,
    request: PrivacyImpactReviewRequest,
    *,
    actor_id: int,
    commit: bool = True,
) -> PrivacyImpactAssessment:
    assessment = get_assessment(db, assessment_id)
    if assessment.status not in {"draft", "changes_required"}:
        raise PrivacyImpactStateError("Only a draft assessment can be reviewed.")
    factors = list(db.scalars(select(PrivacyImpactFactor).where(PrivacyImpactFactor.assessment_id == assessment_id)).all())
    accepted = set(request.accepted_factor_ids) or {item.id for item in factors}
    for factor in factors:
        factor.review_status = "accepted" if factor.id in accepted else "changes_required"
    assessment.status = "reviewed" if request.decision == "accepted" and all(item.id in accepted for item in factors) else "changes_required"
    assessment.reviewed_by = actor_id
    assessment.reviewed_at = datetime.now(timezone.utc)
    if request.limitations is not None:
        assessment.limitations = [_safe_text(item) for item in request.limitations]
    audit_service.log_action(db, action="privacy_impact_assessment_reviewed", actor_id=actor_id, target_type="privacy_impact_assessment", target_id=assessment_id,
        details={"incident_id": assessment.incident_id, "decision": request.decision, "reason": _safe_text(request.reason), "accepted_factor_count": len(accepted)})
    if commit:
        db.commit()
        db.refresh(assessment)
    else:
        db.flush()
    return assessment


def approve_assessment(
    db: Session,
    assessment_id: str,
    *,
    actor_id: int,
    reason: str,
    commit: bool = True,
) -> PrivacyImpactAssessment:
    assessment = get_assessment(db, assessment_id)
    if assessment.status != "reviewed":
        raise PrivacyImpactStateError("Assessment must be reviewed before approval.")
    validate_approver_separation(
        created_by=assessment.created_by,
        reviewed_by=assessment.reviewed_by,
        actor_id=actor_id,
    )
    assessment.status = "approved"
    assessment.approved_by = actor_id
    assessment.approved_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="privacy_impact_assessment_approved", actor_id=actor_id, target_type="privacy_impact_assessment", target_id=assessment_id,
        details={"incident_id": assessment.incident_id, "reason": _safe_text(reason), "breach_severity_level": assessment.breach_severity_level, "privacy_harm_level": assessment.privacy_harm_level})
    from app.services import privacy_breach_alert_service
    privacy_breach_alert_service.evaluate_assessment(db, assessment, actor_id=actor_id)
    if commit:
        db.commit()
        db.refresh(assessment)
    else:
        db.flush()
    return assessment

