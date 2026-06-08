from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import IncidentStatus, Severity

if TYPE_CHECKING:
    from app.models.cicd_evidence import CicdEvidence
    from app.models.detection import Detection
    from app.models.evidence_file import EvidenceFile
    from app.models.fix_verification import FixVerification
    from app.models.llm_report import LlmReport
    from app.models.normalized_event import NormalizedEvent
    from app.models.remediation_action import RemediationAction
    from app.models.report import Report
    from app.models.review_decision import ReviewDecision
    from app.models.review_draft import ReviewDraft
    from app.models.root_cause_score import RootCauseScore


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("organisations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    affected_endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    affected_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status", native_enum=False),
        nullable=False,
        default=IncidentStatus.NEW,
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity", native_enum=False),
        nullable=False,
        default=Severity.MEDIUM,
    )
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    evidence_files: Mapped[list["EvidenceFile"]] = relationship(
        "EvidenceFile",
        back_populates="incident",
        foreign_keys="EvidenceFile.linked_incident_id",
    )
    normalized_events: Mapped[list["NormalizedEvent"]] = relationship(
        "NormalizedEvent",
        back_populates="incident",
        foreign_keys="NormalizedEvent.linked_incident_id",
    )
    detections: Mapped[list["Detection"]] = relationship(
        "Detection",
        back_populates="incident",
    )
    root_cause_scores: Mapped[list["RootCauseScore"]] = relationship(
        "RootCauseScore",
        back_populates="incident",
    )
    review_decisions: Mapped[list["ReviewDecision"]] = relationship(
        "ReviewDecision",
        back_populates="incident",
    )
    review_draft: Mapped["ReviewDraft | None"] = relationship(
        "ReviewDraft",
        back_populates="incident",
        uselist=False,
        cascade="all, delete-orphan",
    )
    remediation_actions: Mapped[list["RemediationAction"]] = relationship(
        "RemediationAction",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    cicd_evidence: Mapped[list["CicdEvidence"]] = relationship(
        "CicdEvidence",
        back_populates="incident",
    )
    fix_verifications: Mapped[list["FixVerification"]] = relationship(
        "FixVerification",
        back_populates="incident",
    )
    reports: Mapped[list["Report"]] = relationship(
        "Report",
        back_populates="incident",
    )
    llm_reports: Mapped[list["LlmReport"]] = relationship(
        "LlmReport",
        back_populates="incident",
    )
