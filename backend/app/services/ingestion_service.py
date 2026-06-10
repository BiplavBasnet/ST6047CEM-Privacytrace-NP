"""Evidence ingestion: hashing, file storage, metadata persistence (Phase 3)."""

from __future__ import annotations

import hashlib
import re
import shutil
import uuid
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import resolve_sample_data_dir, resolve_upload_dir
from app.models import EvidenceFile
from app.models.enums import EvidenceType, ParsingStatus
from app.services import field_encryption_service, file_encryption_service

ALLOWED_EXTENSIONS = {".txt", ".json", ".csv", ".log"}


def compute_file_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def compute_file_hash_from_path(path: Path) -> str:
    return compute_file_hash(path.read_bytes())


def generate_evidence_id() -> str:
    return f"EVD-{uuid.uuid4().hex[:12]}"


def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)[:200]


def _ensure_upload_dir() -> Path:
    upload_dir = resolve_upload_dir()
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def hash_exists(db: Session, file_hash: str) -> bool:
    return (
        db.scalar(select(EvidenceFile.id).where(EvidenceFile.file_hash == file_hash).limit(1))
        is not None
    )


def evidence_id_exists(db: Session, evidence_id: str) -> bool:
    return (
        db.scalar(
            select(EvidenceFile.id).where(EvidenceFile.evidence_id == evidence_id).limit(1)
        )
        is not None
    )


def ingest_file(
    db: Session,
    *,
    content: bytes,
    file_name: str,
    evidence_type: EvidenceType,
    source_system: str | None = None,
    linked_incident_id: str | None = None,
    uploaded_by: int | None = None,
    evidence_id: str | None = None,
) -> EvidenceFile:
    file_hash = compute_file_hash(content)
    if hash_exists(db, file_hash):
        raise ValueError(f"Duplicate file hash already ingested: {file_hash}")

    eid = evidence_id or generate_evidence_id()
    if evidence_id_exists(db, eid):
        raise ValueError(f"Evidence ID already exists: {eid}")

    record = EvidenceFile(
        evidence_id=eid,
        file_name=file_name,
        evidence_type=evidence_type,
        source_system=source_system,
        file_hash=file_hash,
        uploaded_by=uploaded_by,
        parsing_status=ParsingStatus.PENDING,
        linked_incident_id=linked_incident_id,
    )
    stored_path: Path | None = None
    if field_encryption_service.encryption_enabled():
        rel_path, payload = file_encryption_service.store_encrypted_evidence(
            evidence_id=eid,
            file_name=file_name,
            content=content,
        )
        record.encrypted_file_path = rel_path
        record.file_crypto_metadata = {"kid": payload.get("kid"), "version": payload.get("version")}
        record.is_encrypted = True
        stored_path = file_encryption_service.resolve_encrypted_upload_dir() / f"{eid}.enc"
    else:
        upload_dir = _ensure_upload_dir()
        stored_name = f"{eid}_{_safe_filename(file_name)}"
        stored_path = upload_dir / stored_name
        stored_path.write_bytes(content)
        record.is_encrypted = False
    try:
        db.add(record)
        db.flush()
        from app.services import evidence_provenance_service

        evidence_provenance_service.record_system_provenance(
            db,
            eid,
            source_system=source_system,
            source_format=evidence_type.value,
            collector_name="file_ingestion",
            parser_name="file_ingestion",
            parser_version="1",
            commit=False,
            append_integrity=True,
        )
        db.commit()
    except Exception:
        db.rollback()
        if stored_path is not None:
            stored_path.unlink(missing_ok=True)
        raise
    db.refresh(record)
    return record


def ingest_from_path(
    db: Session,
    source_path: Path,
    *,
    file_name: str | None = None,
    evidence_type: EvidenceType,
    source_system: str | None = None,
    linked_incident_id: str | None = None,
    uploaded_by: int | None = None,
    evidence_id: str | None = None,
    copy_to_upload: bool = True,
) -> EvidenceFile:
    content = source_path.read_bytes()
    name = file_name or source_path.name
    file_hash = compute_file_hash(content)

    if hash_exists(db, file_hash):
        raise ValueError(f"duplicate_hash:{file_hash}")

    eid = evidence_id or generate_evidence_id()
    if evidence_id_exists(db, eid):
        raise ValueError(f"duplicate_id:{eid}")

    record = EvidenceFile(
        evidence_id=eid,
        file_name=name,
        evidence_type=evidence_type,
        source_system=source_system,
        file_hash=file_hash,
        uploaded_by=uploaded_by,
        parsing_status=ParsingStatus.PENDING,
        linked_incident_id=linked_incident_id,
    )
    stored_path: Path | None = None
    if field_encryption_service.encryption_enabled():
        rel_path, payload = file_encryption_service.store_encrypted_evidence(
            evidence_id=eid,
            file_name=name,
            content=content,
        )
        record.encrypted_file_path = rel_path
        record.file_crypto_metadata = {"kid": payload.get("kid"), "version": payload.get("version")}
        record.is_encrypted = True
        stored_path = file_encryption_service.resolve_encrypted_upload_dir() / f"{eid}.enc"
    elif copy_to_upload:
        upload_dir = _ensure_upload_dir()
        stored_path = upload_dir / f"{eid}_{_safe_filename(name)}"
        shutil.copy2(source_path, stored_path)
        record.is_encrypted = False
    try:
        db.add(record)
        db.flush()
        from app.services import evidence_provenance_service

        evidence_provenance_service.record_system_provenance(
            db,
            eid,
            source_system=source_system,
            source_format=evidence_type.value,
            collector_name="file_ingestion",
            parser_name="file_ingestion",
            parser_version="1",
            commit=False,
            append_integrity=True,
        )
        db.commit()
    except Exception:
        db.rollback()
        if stored_path is not None:
            stored_path.unlink(missing_ok=True)
        raise
    db.refresh(record)
    return record


def load_manifest() -> dict:
    manifest_path = resolve_sample_data_dir() / "manifest.yaml"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with manifest_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_sample_scenario(
    db: Session,
    scenario: str = "scenario_1",
    *,
    uploaded_by: int | None = None,
) -> dict[str, list[str]]:
    data = load_manifest()
    scenarios = data.get("scenarios") or {}
    if scenario not in scenarios:
        raise KeyError(f"Unknown scenario: {scenario}")

    spec = scenarios[scenario]
    linked_incident_id = spec.get("linked_incident_id")
    sample_root = resolve_sample_data_dir()
    loaded: list[str] = []
    skipped: list[str] = []
    evidence_ids: list[str] = []

    for entry in spec.get("files") or []:
        rel_path = entry["path"]
        source_path = sample_root / rel_path
        if not source_path.is_file():
            skipped.append(f"{rel_path}:file_not_found")
            continue

        eid = entry.get("evidence_id")
        file_hash = compute_file_hash_from_path(source_path)

        if eid and evidence_id_exists(db, eid):
            skipped.append(f"{rel_path}:evidence_id_exists")
            continue
        if hash_exists(db, file_hash):
            skipped.append(f"{rel_path}:duplicate_hash")
            continue

        try:
            record = ingest_from_path(
                db,
                source_path,
                file_name=entry.get("file_name", source_path.name),
                evidence_type=EvidenceType(entry["evidence_type"]),
                source_system=entry.get("source_system"),
                linked_incident_id=linked_incident_id,
                uploaded_by=uploaded_by,
                evidence_id=eid,
            )
            loaded.append(rel_path)
            evidence_ids.append(record.evidence_id)
        except ValueError as exc:
            skipped.append(f"{rel_path}:{exc}")

    return {"loaded": loaded, "skipped": skipped, "evidence_ids": evidence_ids}


def list_evidence(
    db: Session,
    *,
    linked_incident_id: str | None = None,
) -> list[EvidenceFile]:
    stmt = select(EvidenceFile).order_by(EvidenceFile.id)
    if linked_incident_id:
        stmt = stmt.where(EvidenceFile.linked_incident_id == linked_incident_id)
    return list(db.scalars(stmt).all())


def get_evidence(db: Session, evidence_id: str) -> EvidenceFile | None:
    return db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id))


def validate_upload_extension(filename: str) -> None:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{suffix}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
