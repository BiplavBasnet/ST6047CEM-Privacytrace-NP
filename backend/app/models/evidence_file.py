from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import EvidenceType, ParsingStatus

if TYPE_CHECKING:
    from app.models.access_event import AccessEvent
    from app.models.dependency_risk import DependencyRisk
    from app.models.deployment_event import DeploymentEvent
    from app.models.incident import Incident
    from app.models.normalized_event import NormalizedEvent
    from app.models.sast_finding import SastFinding
    from app.models.secret_finding import SecretFinding
    from app.models.user import User


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    file_name: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType, name="evidence_type", native_enum=False),
        nullable=False,
    )
    source_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    uploaded_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    upload_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    parsing_status: Mapped[ParsingStatus] = mapped_column(
        Enum(ParsingStatus, name="parsing_status", native_enum=False),
        nullable=False,
        default=ParsingStatus.PENDING,
    )
    linked_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    encrypted_file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_crypto_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    uploader: Mapped["User | None"] = relationship(
        "User",
        back_populates="uploaded_evidence",
        foreign_keys=[uploaded_by],
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        back_populates="evidence_files",
        foreign_keys=[linked_incident_id],
    )
    normalized_events: Mapped[list["NormalizedEvent"]] = relationship(
        "NormalizedEvent",
        back_populates="evidence_file",
    )
    sast_findings: Mapped[list["SastFinding"]] = relationship(
        "SastFinding",
        back_populates="evidence_file",
    )
    secret_findings: Mapped[list["SecretFinding"]] = relationship(
        "SecretFinding",
        back_populates="evidence_file",
    )
    deployment_events: Mapped[list["DeploymentEvent"]] = relationship(
        "DeploymentEvent",
        back_populates="evidence_file",
    )
    access_events: Mapped[list["AccessEvent"]] = relationship(
        "AccessEvent",
        back_populates="evidence_file",
    )
    dependency_risks: Mapped[list["DependencyRisk"]] = relationship(
        "DependencyRisk",
        back_populates="evidence_file",
    )
