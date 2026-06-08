from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ExposureProfile(Base):
    __tablename__ = "exposure_profiles"
    __table_args__ = (
        UniqueConstraint("profile_id", name="uq_exposure_profile_profile_id"),
        Index(
            "uq_exposure_profile_current_group",
            "incident_id",
            "rule_id",
            "grouping_method",
            "grouping_key",
            unique=True,
            postgresql_where=text("is_current"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    profile_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    profile_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    profile_type: Mapped[str] = mapped_column(String(96), index=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    combination_ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    privacy_harm_level: Mapped[str] = mapped_column(String(32), nullable=False)
    internal_only: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)
    customer_notification_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    grouping_method: Mapped[str] = mapped_column(String(64), nullable=False)
    grouping_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    grouping_key: Mapped[str] = mapped_column(String(160), nullable=False)
    affected_subject_reference_id: Mapped[str | None] = mapped_column(
        ForeignKey("affected_subject_references.subject_reference_id", ondelete="RESTRICT"),
        index=True,
        nullable=True,
    )
    supporting_detection_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    supporting_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    matched_rule_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    possible_harms: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    containment_recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    missing_information: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    review_status: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False, default="pending"
    )
    is_current: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=True)
    superseded_by_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("exposure_profiles.profile_id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class ExposureProfileFactor(Base):
    __tablename__ = "exposure_profile_factors"
    __table_args__ = (
        UniqueConstraint(
            "exposure_profile_id", "classification_id", "factor_role", name="uq_profile_classification_role"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    exposure_profile_id: Mapped[str] = mapped_column(
        ForeignKey("exposure_profiles.profile_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    classification_id: Mapped[str] = mapped_column(
        ForeignKey("sensitive_data_classifications.classification_id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    taxonomy_code: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    detection_id: Mapped[str | None] = mapped_column(
        ForeignKey("detections.detection_id", ondelete="RESTRICT"), nullable=True
    )
    factor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
