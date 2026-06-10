from __future__ import annotations

import re
import uuid
from collections import defaultdict, deque
from collections.abc import Hashable, Sequence
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.breach_decision import BreachDecisionRecord
from app.models.evidence_file import EvidenceFile
from app.models.evidence_provenance import EvidenceProvenance, ProvenanceRelationship
from app.schemas.evidence_provenance_schema import EvidenceProvenanceUpsertRequest, ProvenanceRelationshipCreate
from app.services import audit_safety_service, audit_service

ALLOWED_ENTITY_TYPES = {"incident", "evidence", "provenance", "normalized_event", "detection", "decision", "decision_factor", "root_cause", "report", "retest"}
HASH_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")


class ProvenanceError(Exception):
    pass


class ProvenanceNotFoundError(ProvenanceError):
    pass


class ProvenanceValidationError(ProvenanceError):
    pass


def normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    match = HASH_RE.fullmatch(value.strip())
    if not match:
        raise ProvenanceValidationError("Content hashes must be SHA-256 values.")
    return f"sha256:{match.group(1).lower()}"


def _safe_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    masked = audit_safety_service.mask_sensitive_text(stripped)
    if masked != stripped:
        raise ProvenanceValidationError("Provenance references must not contain raw sensitive values.")
    return stripped


def upsert_provenance(
    db: Session,
    evidence_id: str,
    body: EvidenceProvenanceUpsertRequest,
    *,
    actor_id: int | None,
    commit: bool = False,
) -> EvidenceProvenance:
    evidence = db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id))
    if evidence is None:
        raise ProvenanceNotFoundError(f"Evidence not found: {evidence_id}")
    record = db.scalar(select(EvidenceProvenance).where(EvidenceProvenance.evidence_id == evidence_id))
    if record is None:
        record = EvidenceProvenance(provenance_id=f"PRV-{uuid.uuid4().hex[:20].upper()}", evidence_id=evidence_id)
        db.add(record)
    values = body.model_dump()
    for field in (
        "source_system", "source_event_id", "source_format", "collector_name", "collector_version",
        "parser_name", "parser_version", "normalisation_version", "service_name", "service_version",
        "deployment_environment", "host_reference", "container_reference", "trace_id", "span_id",
        "parent_span_id", "commit_sha", "configuration_hash", "parent_evidence_id",
    ):
        values[field] = _safe_optional(values[field])
    parent_id = values.get("parent_evidence_id")
    if parent_id == evidence_id:
        raise ProvenanceValidationError("An evidence record cannot be its own parent.")
    if parent_id:
        parent_exists = (
            db.scalar(select(EvidenceFile.id).where(EvidenceFile.evidence_id == parent_id)) is not None
        )
        if not parent_exists:
            raise ProvenanceValidationError(f"Parent evidence not found: {parent_id}")
        parent_rows = list(
            db.scalars(
                select(EvidenceProvenance).where(EvidenceProvenance.parent_evidence_id.is_not(None))
            ).all()
        )
        parent_edges = [
            (row.evidence_id, row.parent_evidence_id)
            for row in parent_rows
            if row.parent_evidence_id and row.evidence_id != evidence_id
        ]
        parent_edges.append((evidence_id, parent_id))
        if node_has_cycle(parent_edges, evidence_id):
            raise ProvenanceValidationError("The parent relationship would create circular provenance.")
    values["content_sha256"] = normalize_sha256(values["content_sha256"] or evidence.file_hash)
    for field, value in values.items():
        setattr(record, field, value)
    record.provenance_status = "unverified"
    db.flush()
    audit_service.log_action(db, action="evidence_provenance_recorded", actor_id=actor_id, target_type="evidence", target_id=evidence_id,
                             details={"provenance_id": record.provenance_id, "source_system": record.source_system})
    if commit:
        db.commit()
        db.refresh(record)
    return record


def get_provenance(db: Session, evidence_id: str) -> EvidenceProvenance:
    record = db.scalar(select(EvidenceProvenance).where(EvidenceProvenance.evidence_id == evidence_id))
    if record is None:
        raise ProvenanceNotFoundError(f"Provenance not found for evidence: {evidence_id}")
    return record


def relationship_has_cycle(
    edges: list[tuple[Hashable, Hashable]] | Sequence[tuple[Hashable, Hashable]],
    candidate: tuple[Hashable, Hashable] | None = None,
) -> bool:
    adjacency: dict[Hashable, set[Hashable]] = defaultdict(set)
    for source, target in edges + ([candidate] if candidate else []):
        adjacency[source].add(target)
    visiting: set[Hashable] = set()
    visited: set[Hashable] = set()

    def visit(node: Hashable) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(child) for child in adjacency.get(node, set())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in list(adjacency))


def node_has_cycle(
    edges: list[tuple[Hashable, Hashable]], node: Hashable
) -> bool:
    adjacency: dict[Hashable, set[Hashable]] = defaultdict(set)
    for source, target in edges:
        adjacency[source].add(target)

    def visit(current: Hashable, path: set[Hashable]) -> bool:
        if current in path:
            return True
        return any(visit(child, path | {current}) for child in adjacency.get(current, set()))

    return visit(node, set())


def create_relationship(
    db: Session,
    body: ProvenanceRelationshipCreate,
    *,
    actor_id: int | None,
    commit: bool = False,
) -> ProvenanceRelationship:
    if body.source_entity_type not in ALLOWED_ENTITY_TYPES or body.target_entity_type not in ALLOWED_ENTITY_TYPES:
        raise ProvenanceValidationError("Unsupported provenance entity type.")
    if body.source_entity_type == body.target_entity_type and body.source_entity_id == body.target_entity_id:
        raise ProvenanceValidationError("A provenance relationship cannot reference itself.")
    reason = audit_safety_service.prepare_review_comment(body.reason)
    if body.relationship_type == "was_derived_from":
        existing = list(db.execute(select(
            ProvenanceRelationship.source_entity_type,
            ProvenanceRelationship.source_entity_id,
            ProvenanceRelationship.target_entity_type,
            ProvenanceRelationship.target_entity_id,
        ).where(ProvenanceRelationship.relationship_type == "was_derived_from")).all())
        edges = [
            ((str(source_type), str(source_id)), (str(target_type), str(target_id)))
            for source_type, source_id, target_type, target_id in existing
        ]
        candidate = (
            (body.source_entity_type, body.source_entity_id),
            (body.target_entity_type, body.target_entity_id),
        )
        if relationship_has_cycle(edges, candidate):
            raise ProvenanceValidationError("The relationship would create circular provenance.")
    duplicate = db.scalar(select(ProvenanceRelationship).where(
        ProvenanceRelationship.source_entity_type == body.source_entity_type,
        ProvenanceRelationship.source_entity_id == body.source_entity_id,
        ProvenanceRelationship.target_entity_type == body.target_entity_type,
        ProvenanceRelationship.target_entity_id == body.target_entity_id,
        ProvenanceRelationship.relationship_type == body.relationship_type,
    ))
    if duplicate is not None:
        return duplicate
    record = ProvenanceRelationship(
        relationship_id=f"PRR-{uuid.uuid4().hex[:20].upper()}", validation_status="unverified",
        created_by=actor_id, **body.model_dump(exclude={"reason"}), reason=reason,
    )
    db.add(record)
    db.flush()
    audit_service.log_action(db, action="provenance_relationship_created", actor_id=actor_id, target_type="provenance_relationship", target_id=record.relationship_id,
                             details={"relationship_type": record.relationship_type, "source_entity_id": record.source_entity_id, "target_entity_id": record.target_entity_id})
    if commit:
        db.commit()
        db.refresh(record)
    return record


def validate_values(
    *, source_system: str | None, source_timestamp: datetime | None, collection_timestamp: datetime | None,
    ingestion_timestamp: datetime, parser_name: str | None, parser_version: str | None,
    content_sha256: str | None, evidence_file_hash: str | None,
    parent_evidence_id: str | None, evidence_id: str, parent_exists: bool = True, circular: bool = False,
) -> tuple[str, list[dict]]:
    issues: list[dict] = []
    for missing, code in ((not source_system, "missing_source_system"), (source_timestamp is None, "missing_source_timestamp"),
                          (not parser_name, "missing_parser_name"), (not parser_version, "missing_parser_version")):
        if missing:
            issues.append({"code": code, "severity": "partial"})
    if parent_evidence_id == evidence_id or (parent_evidence_id and not parent_exists):
        issues.append({"code": "invalid_parent_evidence", "severity": "invalid"})
    if circular:
        issues.append({"code": "circular_provenance", "severity": "invalid"})
    if source_timestamp and collection_timestamp and source_timestamp > collection_timestamp:
        issues.append({"code": "source_after_collection", "severity": "invalid"})
    if collection_timestamp and collection_timestamp > ingestion_timestamp:
        issues.append({"code": "collection_after_ingestion", "severity": "invalid"})
    try:
        recorded_hash, current_hash = normalize_sha256(content_sha256), normalize_sha256(evidence_file_hash)
    except ProvenanceValidationError:
        issues.append({"code": "invalid_content_hash", "severity": "invalid"})
    else:
        if recorded_hash and current_hash and recorded_hash != current_hash:
            issues.append({"code": "content_hash_mismatch", "severity": "invalid"})
        if not recorded_hash:
            issues.append({"code": "missing_content_hash", "severity": "partial"})
    if any(issue["severity"] == "invalid" for issue in issues):
        return "invalid", issues
    if issues:
        return "partial", issues
    return "complete", issues


def validate_provenance(
    db: Session,
    evidence_id: str,
    *,
    actor_id: int | None,
    commit: bool = False,
) -> tuple[EvidenceProvenance, list[dict]]:
    record = get_provenance(db, evidence_id)
    evidence = db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id))
    parent_exists = not record.parent_evidence_id or db.scalar(select(EvidenceFile.id).where(EvidenceFile.evidence_id == record.parent_evidence_id)) is not None
    parent_rows = list(db.scalars(select(EvidenceProvenance).where(EvidenceProvenance.parent_evidence_id.is_not(None))).all())
    parent_edges = [
        (row.evidence_id, row.parent_evidence_id)
        for row in parent_rows
        if row.parent_evidence_id
    ]
    circular = node_has_cycle(parent_edges, evidence_id)
    status, issues = validate_values(
        source_system=record.source_system, source_timestamp=record.source_timestamp,
        collection_timestamp=record.collection_timestamp, ingestion_timestamp=record.ingestion_timestamp,
        parser_name=record.parser_name, parser_version=record.parser_version,
        content_sha256=record.content_sha256, evidence_file_hash=evidence.file_hash if evidence else None,
        parent_evidence_id=record.parent_evidence_id, evidence_id=record.evidence_id,
        parent_exists=parent_exists, circular=circular,
    )
    record.provenance_status = status
    audit_service.log_action(db, action="provenance_validated", actor_id=actor_id, target_type="evidence", target_id=evidence_id,
                             details={"provenance_status": status, "issue_codes": [item["code"] for item in issues]})
    if commit:
        db.commit()
        db.refresh(record)
    return record, issues


def append_evidence_integrity_record(db: Session, evidence_id: str) -> None:
    """Append an integrity ledger entry for evidence. Caller owns the transaction."""
    from app.config import get_settings
    from app.services import integrity_ledger_service

    if not get_settings().integrity_ledger_enabled:
        return
    evidence = db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id))
    if evidence is None:
        return
    integrity_ledger_service.append_record(
        db,
        record_type="evidence",
        record_id=evidence.evidence_id,
        canonical_content={
            "evidence_id": evidence.evidence_id,
            "source_system": evidence.source_system,
            "file_hash": evidence.file_hash,
            "upload_timestamp": evidence.upload_timestamp,
            "is_encrypted": evidence.is_encrypted,
        },
        scope_type="incident" if evidence.linked_incident_id else "global",
        scope_id=evidence.linked_incident_id,
    )


def record_system_provenance(
    db: Session,
    evidence_id: str,
    *,
    source_system: str | None,
    source_format: str | None,
    collector_name: str,
    parser_name: str | None = None,
    source_timestamp: datetime | None = None,
    collection_timestamp: datetime | None = None,
    parser_version: str | None = None,
    collector_version: str | None = None,
    source_event_id: str | None = None,
    trace_id: str | None = None,
    commit_sha: str | None = None,
    service_name: str | None = None,
    deployment_environment: str | None = None,
    commit: bool = False,
    append_integrity: bool = False,
) -> EvidenceProvenance:
    """Record system provenance. Does not append integrity unless append_integrity=True.

    Callers that need both provenance and integrity should either pass
    append_integrity=True or call append_evidence_integrity_record explicitly
    after a successful provenance write. Caller owns the transaction.
    """
    record = upsert_provenance(
        db, evidence_id, EvidenceProvenanceUpsertRequest(
            source_system=source_system,
            source_format=source_format,
            source_event_id=source_event_id,
            collector_name=collector_name,
            collector_version=collector_version or "1",
            parser_name=parser_name,
            parser_version=parser_version,
            source_timestamp=source_timestamp,
            collection_timestamp=collection_timestamp,
            trace_id=trace_id,
            commit_sha=commit_sha,
            service_name=service_name,
            deployment_environment=deployment_environment,
        ), actor_id=None, commit=False,
    )
    if append_integrity:
        append_evidence_integrity_record(db, evidence_id)
    if commit:
        db.commit()
        db.refresh(record)
    return record


def list_incident_provenance(db: Session, incident_id: str) -> tuple[list[EvidenceProvenance], list[ProvenanceRelationship]]:
    evidence_ids = list(db.scalars(select(EvidenceFile.evidence_id).where(EvidenceFile.linked_incident_id == incident_id)).all())
    records = list(db.scalars(select(EvidenceProvenance).where(EvidenceProvenance.evidence_id.in_(evidence_ids)).order_by(EvidenceProvenance.created_at)).all()) if evidence_ids else []
    entity_ids = set(evidence_ids) | {incident_id}
    decisions = list(db.scalars(select(BreachDecisionRecord.decision_id).where(BreachDecisionRecord.incident_id == incident_id)).all())
    entity_ids.update(decisions)
    relationships = list(db.scalars(select(ProvenanceRelationship).where(or_(
        ProvenanceRelationship.source_entity_id.in_(entity_ids), ProvenanceRelationship.target_entity_id.in_(entity_ids)
    )).order_by(ProvenanceRelationship.created_at)).all()) if entity_ids else []
    return records, relationships


def incident_validation_summary(
    db: Session, incident_id: str
) -> tuple[str, list[dict]]:
    records, relationships = list_incident_provenance(db, incident_id)
    evidence_rows = list(
        db.scalars(
            select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)
        ).all()
    )
    evidence_by_id = {row.evidence_id: row for row in evidence_rows}
    provenance_by_id = {row.evidence_id: row for row in records}
    # Include all known parent edges so write-time cycles spanning outside the
    # incident map are still detectable per node.
    all_parent_rows = list(
        db.scalars(
            select(EvidenceProvenance).where(EvidenceProvenance.parent_evidence_id.is_not(None))
        ).all()
    )
    parent_edges = [
        (row.evidence_id, row.parent_evidence_id)
        for row in all_parent_rows
        if row.parent_evidence_id
    ]
    issues: list[dict] = []

    for evidence_id, evidence in evidence_by_id.items():
        record = provenance_by_id.get(evidence_id)
        if record is None:
            issues.append(
                {
                    "code": "missing_provenance",
                    "severity": "partial",
                    "evidence_id": evidence_id,
                }
            )
            continue
        parent_exists = (
            not record.parent_evidence_id
            or db.scalar(
                select(EvidenceFile.id).where(
                    EvidenceFile.evidence_id == record.parent_evidence_id
                )
            )
            is not None
        )
        _, record_issues = validate_values(
            source_system=record.source_system,
            source_timestamp=record.source_timestamp,
            collection_timestamp=record.collection_timestamp,
            ingestion_timestamp=record.ingestion_timestamp,
            parser_name=record.parser_name,
            parser_version=record.parser_version,
            content_sha256=record.content_sha256,
            evidence_file_hash=evidence.file_hash,
            parent_evidence_id=record.parent_evidence_id,
            evidence_id=record.evidence_id,
            parent_exists=parent_exists,
            circular=node_has_cycle(parent_edges, evidence_id),
        )
        issues.extend({**issue, "evidence_id": evidence_id} for issue in record_issues)

    available_evidence_ids = set(evidence_by_id)
    decisions = list(
        db.scalars(
            select(BreachDecisionRecord).where(
                BreachDecisionRecord.incident_id == incident_id
            )
        ).all()
    )
    for decision in decisions:
        for evidence_id in decision.input_evidence_ids or []:
            if evidence_id not in available_evidence_ids:
                issues.append(
                    {
                        "code": "decision_evidence_unavailable",
                        "severity": "invalid",
                        "decision_id": decision.decision_id,
                        "evidence_id": evidence_id,
                    }
                )

    relationship_edges = [
        (
            (row.source_entity_type, row.source_entity_id),
            (row.target_entity_type, row.target_entity_id),
        )
        for row in relationships
        if row.relationship_type == "was_derived_from"
    ]
    if relationship_has_cycle(relationship_edges):
        issues.append({"code": "circular_provenance", "severity": "invalid"})

    if any(issue["severity"] == "invalid" for issue in issues):
        return "invalid", issues
    if issues:
        return "partial", issues
    return ("complete" if records else "unverified"), issues


def build_paths_from_relationships(
    rows: list[ProvenanceRelationship],
    *,
    entity_type: str,
    entity_id: str,
    max_depth: int = 12,
    max_paths: int = 100,
) -> list[list[dict]]:
    adjacency: dict[tuple[str, str], list[tuple[tuple[str, str], ProvenanceRelationship]]] = defaultdict(list)
    for row in rows:
        source, target = (row.source_entity_type, row.source_entity_id), (row.target_entity_type, row.target_entity_id)
        adjacency[source].append((target, row))
        adjacency[target].append((source, row))
    start = (entity_type, entity_id)
    queue: deque[
        tuple[tuple[str, str], list[dict], set[tuple[str, str]]]
    ] = deque([(start, [], {start})])
    paths: list[list[dict]] = []
    while queue and len(paths) < max_paths:
        node, path, visited = queue.popleft()
        if path and node[0] in {"evidence", "provenance"}:
            paths.append(path)
        if len(path) >= max_depth:
            continue
        for neighbour, edge in adjacency.get(node, []):
            if neighbour in visited:
                continue
            step = {"from_type": node[0], "from_id": node[1], "relationship_type": edge.relationship_type,
                    "reason": edge.reason, "to_type": neighbour[0], "to_id": neighbour[1]}
            queue.append((neighbour, path + [step], visited | {neighbour}))
    return paths


def build_paths(db: Session, *, entity_type: str, entity_id: str, max_depth: int = 12) -> list[list[dict]]:
    rows = list(db.scalars(select(ProvenanceRelationship)).all())
    return build_paths_from_relationships(
        rows,
        entity_type=entity_type,
        entity_id=entity_id,
        max_depth=max_depth,
    )


def safe_export(db: Session, incident_id: str) -> dict:
    records, relationships = list_incident_provenance(db, incident_id)
    return {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence": [{
            "evidence_id": row.evidence_id, "source_system": row.source_system,
            "source_timestamp": row.source_timestamp.isoformat() if row.source_timestamp else None,
            "collection_timestamp": row.collection_timestamp.isoformat() if row.collection_timestamp else None,
            "parser_name": row.parser_name, "parser_version": row.parser_version,
            "service_name": row.service_name, "service_version": row.service_version,
            "content_sha256": row.content_sha256, "parent_evidence_id": row.parent_evidence_id,
            "provenance_status": row.provenance_status,
        } for row in records],
        "relationships": [{
            "source_entity_type": row.source_entity_type, "source_entity_id": row.source_entity_id,
            "target_entity_type": row.target_entity_type, "target_entity_id": row.target_entity_id,
            "relationship_type": row.relationship_type, "reason": row.reason,
            "validation_status": row.validation_status,
        } for row in relationships],
        "notice": "This export contains safe provenance metadata only; raw evidence content is excluded.",
    }
