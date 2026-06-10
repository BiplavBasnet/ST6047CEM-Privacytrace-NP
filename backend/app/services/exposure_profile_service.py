from __future__ import annotations

from datetime import datetime, timezone

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import resolve_rules_dir
from app.models.exposure_profile import ExposureProfile, ExposureProfileFactor
from app.models.incident import Incident
from app.models.sensitive_data_classification import SensitiveDataClassification
from app.schemas.exposure_profile_schema import ClassificationFact, ExposureProfileCandidate
from app.services import audit_safety_service, audit_service


class ExposureProfileError(ValueError):
    pass


@dataclass(frozen=True)
class ExposureRuleset:
    version: str
    rules: tuple[dict[str, Any], ...]


@lru_cache(maxsize=4)
def _load_rules(path_text: str) -> ExposureRuleset:
    try:
        data = yaml.safe_load(Path(path_text).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ExposureProfileError("Exposure-combination rules are unavailable.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ExposureProfileError("Exposure-combination rules are invalid.")
    version = str(data.get("ruleset_version") or "").strip()
    if not version:
        raise ExposureProfileError("Exposure-combination rules require a version.")
    seen: set[str] = set()
    for rule in data["rules"]:
        rule_id = str(rule.get("rule_id") or "")
        if not rule_id or rule_id in seen:
            raise ExposureProfileError("Exposure-combination rule identifiers must be unique.")
        seen.add(rule_id)
    return ExposureRuleset(version=version, rules=tuple(data["rules"]))


def load_rules(path: str | Path | None = None) -> ExposureRuleset:
    resolved = Path(path) if path else resolve_rules_dir() / "nepal_exposure_combination_rules.yaml"
    return _load_rules(str(resolved.resolve()))


def _group_key(fact: ClassificationFact) -> tuple[str, str, str]:
    if fact.affected_subject_reference_id:
        return "subject_reference", "high", fact.affected_subject_reference_id
    if fact.normalized_event_id:
        return "normalized_event", "medium", fact.normalized_event_id
    if fact.evidence_id:
        return "evidence", "medium", fact.evidence_id
    if fact.detection_id:
        return "detection", "low", fact.detection_id
    return "classification", "low", fact.classification_id


def _matches(rule: dict[str, Any], facts: list[ClassificationFact]) -> bool:
    categories = {fact.taxonomy_code for fact in facts if fact.confidence_label != "rejected"}
    groups = {fact.category_group for fact in facts if fact.confidence_label != "rejected"}
    if not set(rule.get("required_all") or []).issubset(categories):
        return False
    required_any = set(rule.get("required_any") or [])
    if required_any and not required_any.intersection(categories):
        return False
    if not set(rule.get("required_groups") or []).issubset(groups):
        return False
    if set(rule.get("excluded_categories") or []).intersection(categories):
        return False
    if len(categories) < int(rule.get("minimum_distinct_categories") or 1):
        return False
    required_statuses = set(rule.get("credential_status_requirements") or [])
    if required_statuses:
        credential_facts = [fact for fact in facts if fact.category_group == "authentication_credential"]
        if not credential_facts or not any((fact.credential_status or "unknown") in required_statuses for fact in credential_facts):
            return False
    return True


def evaluate_exposure_profiles(facts: list[ClassificationFact], *, ruleset: ExposureRuleset | None = None) -> list[ExposureProfileCandidate]:
    ruleset = ruleset or load_rules()
    grouped: dict[tuple[str, str, str], list[ClassificationFact]] = {}
    for fact in facts:
        grouped.setdefault(_group_key(fact), []).append(fact)
    candidates: list[ExposureProfileCandidate] = []
    for (method, confidence, grouping_key), group_facts in grouped.items():
        for rule in ruleset.rules:
            if not rule.get("enabled", True) or not _matches(rule, group_facts):
                continue
            matched = [fact for fact in group_facts if fact.confidence_label != "rejected"]
            candidates.append(ExposureProfileCandidate(
                profile_type=str(rule["profile_type"]),
                rule_id=str(rule["rule_id"]),
                rule_version=str(rule.get("version") or ruleset.version),
                severity=str(rule["severity"]),
                privacy_harm_level=str(rule.get("privacy_harm_level") or "unknown"),
                internal_only=bool(rule.get("internal_only")),
                customer_notification_allowed=rule.get("notification_policy") != "prohibited",
                grouping_method=method,
                grouping_confidence=confidence,
                grouping_key=grouping_key,
                supporting_classification_ids=sorted({fact.classification_id for fact in matched}),
                supporting_detection_ids=sorted({fact.detection_id for fact in matched if fact.detection_id}),
                supporting_evidence_ids=sorted({fact.evidence_id for fact in matched if fact.evidence_id}),
                matched_category_codes=sorted({fact.taxonomy_code for fact in matched}),
                possible_harms=list(rule.get("harm_categories") or []),
                containment_recommendations=list(rule.get("containment_recommendations") or []),
                missing_information=["Human review is required before treating this profile as verified."],
                limitations=["Contextual matches indicate possible combined exposure and do not prove misuse."],
                explanation=str(rule.get("explanation_template") or "Combination rule matched."),
            ))
    return candidates


def _profile_key(incident_id: str, candidate: ExposureProfileCandidate, ruleset_version: str) -> str:
    payload = {
        "incident_id": incident_id,
        "rule_id": candidate.rule_id,
        "grouping_method": candidate.grouping_method,
        "grouping_key": candidate.grouping_key,
        "classification_ids": candidate.supporting_classification_ids,
        "ruleset_version": ruleset_version,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _classification_facts(rows: list[SensitiveDataClassification]) -> list[ClassificationFact]:
    return [ClassificationFact(
        classification_id=row.classification_id,
        taxonomy_code=row.taxonomy_code,
        taxonomy_version=row.taxonomy_version,
        category_group=row.category_group,
        detection_id=row.detection_id,
        evidence_id=row.evidence_id,
        normalized_event_id=row.normalized_event_id,
        affected_subject_reference_id=row.affected_subject_reference_id,
        credential_status=row.credential_status,
        confidence_label=row.confidence_label,
        internal_only=row.internal_only,
        evidence_role=row.evidence_role,
    ) for row in rows]


def _stored_grouping_key(
    db: Session,
    profile: ExposureProfile,
) -> str | None:
    if getattr(profile, "grouping_key", None):
        return profile.grouping_key
    if profile.grouping_method == "subject_reference":
        return profile.affected_subject_reference_id
    classification_ids = list(
        db.scalars(
            select(ExposureProfileFactor.classification_id).where(
                ExposureProfileFactor.exposure_profile_id == profile.profile_id
            )
        ).all()
    )
    if not classification_ids:
        return None
    rows = list(
        db.scalars(
            select(SensitiveDataClassification).where(
                SensitiveDataClassification.classification_id.in_(classification_ids)
            )
        ).all()
    )
    keys = {
        _group_key(fact)[2]
        for fact in _classification_facts(rows)
        if _group_key(fact)[0] == profile.grouping_method
    }
    return next(iter(keys)) if len(keys) == 1 else None


def _logical_profile_key(
    profile_type: str,
    rule_id: str,
    grouping_method: str,
    grouping_key: str,
) -> tuple[str, str, str, str]:
    return profile_type, rule_id, grouping_method, grouping_key


def profiles_without_active_candidate(
    current_by_logical: dict[tuple[str, str, str, str], list[ExposureProfile]],
    active_logical_keys: set[tuple[str, str, str, str]],
) -> list[ExposureProfile]:
    return [
        profile
        for logical_key, profiles in current_by_logical.items()
        if logical_key not in active_logical_keys
        for profile in profiles
    ]


def recalculate_profiles(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None,
    commit: bool = True,
) -> list[ExposureProfile]:
    if db.scalar(select(Incident.id).where(Incident.incident_id == incident_id).with_for_update()) is None:
        raise ExposureProfileError("Incident was not found.")
    classifications = list(db.scalars(select(SensitiveDataClassification).where(SensitiveDataClassification.incident_id == incident_id)).all())
    ruleset = load_rules()
    candidates = evaluate_exposure_profiles(_classification_facts(classifications), ruleset=ruleset)
    by_id = {item.classification_id: item for item in classifications}
    current_profiles = list(
        db.scalars(
            select(ExposureProfile).where(
                ExposureProfile.incident_id == incident_id,
                ExposureProfile.is_current.is_(True),
            )
        ).all()
    )
    current_by_logical: dict[
        tuple[str, str, str, str], list[ExposureProfile]
    ] = {}
    for profile in current_profiles:
        grouping_key = _stored_grouping_key(db, profile)
        rule_id = profile.rule_id or next(iter(profile.matched_rule_ids or []), None)
        if grouping_key and rule_id:
            logical_key = _logical_profile_key(
                profile.profile_type,
                str(rule_id),
                profile.grouping_method,
                grouping_key,
            )
            current_by_logical.setdefault(logical_key, []).append(profile)
    output: list[ExposureProfile] = []
    active_logical_keys: set[tuple[str, str, str, str]] = set()
    for candidate in candidates:
        logical_key = _logical_profile_key(
            candidate.profile_type,
            candidate.rule_id,
            candidate.grouping_method,
            candidate.grouping_key,
        )
        active_logical_keys.add(logical_key)
        key = _profile_key(incident_id, candidate, ruleset.version)
        existing = db.scalar(select(ExposureProfile).where(ExposureProfile.profile_key == key))
        if existing:
            for previous in current_by_logical.get(logical_key, []):
                if previous.profile_id != existing.profile_id:
                    previous.is_current = False
                    previous.superseded_by_profile_id = existing.profile_id
            db.flush()
            existing.is_current = True
            existing.superseded_by_profile_id = None
            db.flush()
            output.append(existing)
            continue
        taxonomy_versions = sorted({by_id[item].taxonomy_version for item in candidate.supporting_classification_ids})
        subject_ids = {by_id[item].affected_subject_reference_id for item in candidate.supporting_classification_ids if by_id[item].affected_subject_reference_id}
        profile = ExposureProfile(
            profile_id=f"EXP-{uuid4().hex[:20].upper()}",
            profile_key=key,
            incident_id=incident_id,
            profile_type=candidate.profile_type,
            rule_id=candidate.rule_id,
            taxonomy_version=taxonomy_versions[-1] if taxonomy_versions else "unknown",
            combination_ruleset_version=ruleset.version,
            severity=candidate.severity,
            privacy_harm_level=candidate.privacy_harm_level,
            internal_only=candidate.internal_only,
            customer_notification_allowed=candidate.customer_notification_allowed,
            grouping_method=candidate.grouping_method,
            grouping_confidence=candidate.grouping_confidence,
            grouping_key=candidate.grouping_key,
            affected_subject_reference_id=next(iter(subject_ids)) if len(subject_ids) == 1 else None,
            supporting_detection_ids=candidate.supporting_detection_ids,
            supporting_evidence_ids=candidate.supporting_evidence_ids,
            matched_rule_ids=[candidate.rule_id],
            possible_harms=candidate.possible_harms,
            containment_recommendations=candidate.containment_recommendations,
            missing_information=candidate.missing_information,
            limitations=candidate.limitations,
            is_current=False,
        )
        db.add(profile)
        db.flush()
        for previous in current_by_logical.get(logical_key, []):
            previous.is_current = False
            previous.superseded_by_profile_id = profile.profile_id
        db.flush()
        profile.is_current = True
        db.flush()
        for classification_id in candidate.supporting_classification_ids:
            row = by_id[classification_id]
            db.add(ExposureProfileFactor(
                exposure_profile_id=profile.profile_id,
                classification_id=classification_id,
                taxonomy_code=row.taxonomy_code,
                detection_id=row.detection_id,
                factor_role="supporting",
                reason=candidate.explanation,
            ))
        output.append(profile)
    for profile in profiles_without_active_candidate(
        current_by_logical,
        active_logical_keys,
    ):
        profile.is_current = False
        profile.superseded_by_profile_id = None
    audit_service.log_action(db, action="exposure_profiles_recalculated", actor_id=actor_id, target_type="incident", target_id=incident_id, details={"incident_id": incident_id, "profile_ids": [item.profile_id for item in output], "ruleset_version": ruleset.version})
    if commit:
        db.commit()
        for item in output:
            db.refresh(item)
    else:
        db.flush()
    return output


def list_profiles(db: Session, incident_id: str, *, authorised_restricted_access: bool = False) -> tuple[list[ExposureProfile], bool]:
    rows = list(db.scalars(select(ExposureProfile).where(ExposureProfile.incident_id == incident_id, ExposureProfile.is_current.is_(True)).order_by(ExposureProfile.created_at.desc())).all())
    restricted_present = any(item.internal_only for item in rows)
    if authorised_restricted_access:
        return rows, restricted_present
    return [item for item in rows if not item.internal_only], restricted_present


def get_profile(db: Session, profile_id: str, *, authorised_restricted_access: bool = False) -> ExposureProfile:
    item = db.scalar(select(ExposureProfile).where(ExposureProfile.profile_id == profile_id))
    if item is None or (item.internal_only and not authorised_restricted_access):
        raise ExposureProfileError("Exposure profile was not found.")
    return item

def review_profile(db: Session, profile_id: str, *, actor_id: int, decision: str, reason: str) -> ExposureProfile:
    item = db.scalar(select(ExposureProfile).where(ExposureProfile.profile_id == profile_id).with_for_update())
    if item is None:
        raise ExposureProfileError("Exposure profile was not found.")
    if item.review_status != "pending":
        raise ExposureProfileError("Exposure profile has already been reviewed.")
    safe_reason = audit_safety_service.prepare_review_comment(reason)
    if not safe_reason:
        raise ExposureProfileError("A review reason is required.")
    item.review_status = decision
    item.reviewed_by = actor_id
    item.reviewed_at = datetime.now(timezone.utc)
    item.rejection_reason = safe_reason if decision == "rejected" else None
    audit_service.log_action(db, action="exposure_profile_reviewed", actor_id=actor_id, target_type="exposure_profile", target_id=profile_id, details={"incident_id": item.incident_id, "decision": decision, "reason": safe_reason})
    db.commit()
    db.refresh(item)
    return item


def combination_rules() -> list[dict[str, Any]]:
    ruleset = load_rules()
    return [
        {
            "rule_id": str(rule["rule_id"]),
            "version": str(rule.get("version") or ruleset.version),
            "profile_type": str(rule["profile_type"]),
            "severity": str(rule["severity"]),
            "internal_only": bool(rule.get("internal_only")),
            "explanation_template": str(rule.get("explanation_template") or "Combination rule matched."),
        }
        for rule in ruleset.rules
    ]


