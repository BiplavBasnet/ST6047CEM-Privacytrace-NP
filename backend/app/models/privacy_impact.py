from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PrivacyImpactAssessment(Base):
    __tablename__ = "privacy_impact_assessments"
    __table_args__ = (
        UniqueConstraint("incident_id", "assessment_version", name="uq_privacy_impact_incident_version"),
        UniqueConstraint("incident_id", "input_fingerprint", name="uq_privacy_impact_incident_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    assessment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    data_processing_context_score: Mapped[float] = mapped_column(Float, nullable=False)
    ease_of_identification_score: Mapped[float] = mapped_column(Float, nullable=False)
    circumstances_score: Mapped[float] = mapped_column(Float, nullable=False)
    breach_severity_score: Mapped[float] = mapped_column(Float, nullable=False)
    breach_severity_level: Mapped[str] = mapped_column(String(32), nullable=False)
    harm_likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    harm_magnitude: Mapped[int] = mapped_column(Integer, nullable=False)
    privacy_harm_score: Mapped[int] = mapped_column(Integer, nullable=False)
    privacy_harm_level: Mapped[str] = mapped_column(String(32), nullable=False)
    affected_subject_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    affected_subject_count_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    credential_exposure_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    public_exposure_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_access_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    malicious_intent_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    encrypted_or_unintelligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assessment_confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    data_categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    input_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    taxonomy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    combination_ruleset_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    factors: Mapped[list["PrivacyImpactFactor"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    harms: Mapped[list["PrivacyHarm"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")


class PrivacyImpactFactor(Base):
    __tablename__ = "privacy_impact_factors"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("privacy_impact_assessments.assessment_id", ondelete="CASCADE"), index=True, nullable=False)
    factor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    factor_code: Mapped[str] = mapped_column(String(128), nullable=False)
    factor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    score_contribution: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    method_version: Mapped[str] = mapped_column(String(64), nullable=False, default="privacy-impact-v1")
    is_system_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    assessment: Mapped["PrivacyImpactAssessment"] = relationship(back_populates="factors")


class PrivacyHarm(Base):
    __tablename__ = "privacy_harms"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    harm_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("privacy_impact_assessments.assessment_id", ondelete="CASCADE"), index=True, nullable=False)
    harm_category: Mapped[str] = mapped_column(String(64), nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    magnitude: Mapped[int] = mapped_column(Integer, nullable=False)
    harm_score: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    uncertainty: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_mitigation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    assessment: Mapped["PrivacyImpactAssessment"] = relationship(back_populates="harms")
