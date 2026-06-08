"""Nepal financial taxonomy classifications and exposure profiles.

Revision ID: 017_nepal_taxonomy_exposure
Revises: 016_counterfactual_alert_prevention
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "017_nepal_taxonomy_exposure"
down_revision: Union[str, None] = "016_counterfactual_alert_prevention"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _column_names(table_name: str) -> set[str]:
    if context.is_offline_mode():
        return set()
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _table_names() -> set[str]:
    if context.is_offline_mode():
        return set()
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    subject_columns = _column_names("affected_subject_references")
    if "subject_type" not in subject_columns:
        op.add_column("affected_subject_references", sa.Column("subject_type", sa.String(48), server_default="unknown_subject_type", nullable=False))
        op.create_index("ix_affected_subject_type", "affected_subject_references", ["subject_type"])
    assessment_columns = _column_names("privacy_impact_assessments")
    if "taxonomy_version" not in assessment_columns:
        op.add_column("privacy_impact_assessments", sa.Column("taxonomy_version", sa.String(64), nullable=True))
    if "combination_ruleset_version" not in assessment_columns:
        op.add_column("privacy_impact_assessments", sa.Column("combination_ruleset_version", sa.String(64), nullable=True))
    decision_columns = _column_names("breach_decision_records")
    if "taxonomy_version" not in decision_columns:
        op.add_column("breach_decision_records", sa.Column("taxonomy_version", sa.String(64), nullable=True))
    if "combination_ruleset_version" not in decision_columns:
        op.add_column("breach_decision_records", sa.Column("combination_ruleset_version", sa.String(64), nullable=True))
    if "exposure_profile_ids" not in decision_columns:
        op.add_column("breach_decision_records", sa.Column("exposure_profile_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    if "internal_only_restrictions" not in decision_columns:
        op.add_column("breach_decision_records", sa.Column("internal_only_restrictions", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.create_table(
        "sensitive_data_classifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("classification_id", sa.String(64), nullable=False),
        sa.Column("classification_key", sa.String(128), nullable=False),
        sa.Column("detection_id", sa.String(64), nullable=True),
        sa.Column("privacy_alert_id", sa.String(64), nullable=True),
        sa.Column("incident_id", sa.String(64), nullable=True),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("normalized_event_id", sa.String(64), nullable=True),
        sa.Column("affected_subject_reference_id", sa.String(64), nullable=True),
        sa.Column("taxonomy_code", sa.String(128), nullable=False),
        sa.Column("taxonomy_version", sa.String(64), nullable=False),
        sa.Column("category_group", sa.String(64), nullable=False),
        sa.Column("detection_method", sa.String(64), nullable=False),
        sa.Column("matched_alias", sa.String(255), nullable=True),
        sa.Column("context_score", sa.Float(), server_default="0", nullable=False),
        sa.Column("format_validation_status", sa.String(32), nullable=False),
        sa.Column("source_context_status", sa.String(32), nullable=False),
        sa.Column("credential_status", sa.String(32), nullable=True),
        sa.Column("document_type", sa.String(64), nullable=True),
        sa.Column("masked_value", sa.String(512), nullable=False),
        sa.Column("value_fingerprint", sa.String(160), nullable=True),
        sa.Column("fingerprint_strategy", sa.String(48), nullable=False),
        sa.Column("confidence_label", sa.String(32), nullable=False),
        sa.Column("review_status", sa.String(32), server_default="pending", nullable=False),
        sa.Column("internal_only", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("customer_notification_allowed", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("restricted_roles", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_role", sa.String(32), server_default="original", nullable=False),
        sa.Column("limitations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.detection_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["privacy_alert_id"], ["privacy_alerts.alert_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_files.evidence_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["normalized_event_id"], ["normalized_events.event_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["affected_subject_reference_id"], ["affected_subject_references.subject_reference_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("classification_id"), sa.UniqueConstraint("classification_key"),
    )
    op.create_index("ix_sensitive_classification_id", "sensitive_data_classifications", ["classification_id"], unique=True)
    op.create_index("ix_sensitive_classification_key", "sensitive_data_classifications", ["classification_key"], unique=True)
    for name, columns in (
        ("ix_sensitive_classification_detection", ["detection_id"]), ("ix_sensitive_classification_alert", ["privacy_alert_id"]),
        ("ix_sensitive_classification_incident", ["incident_id"]), ("ix_sensitive_classification_evidence", ["evidence_id"]),
        ("ix_sensitive_classification_event", ["normalized_event_id"]), ("ix_sensitive_classification_subject", ["affected_subject_reference_id"]),
        ("ix_sensitive_classification_taxonomy", ["taxonomy_code"]), ("ix_sensitive_classification_group", ["category_group"]),
        ("ix_sensitive_classification_confidence", ["confidence_label"]), ("ix_sensitive_classification_review", ["review_status"]),
        ("ix_sensitive_classification_internal", ["internal_only"]),
    ):
        op.create_index(name, "sensitive_data_classifications", columns)

    op.create_table(
        "exposure_profiles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("profile_id", sa.String(64), nullable=False), sa.Column("profile_key", sa.String(128), nullable=False),
        sa.Column("incident_id", sa.String(64), nullable=False), sa.Column("profile_type", sa.String(96), nullable=False),
        sa.Column("taxonomy_version", sa.String(64), nullable=False), sa.Column("combination_ruleset_version", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False), sa.Column("privacy_harm_level", sa.String(32), nullable=False),
        sa.Column("internal_only", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("customer_notification_allowed", sa.Boolean(), nullable=False),
        sa.Column("grouping_method", sa.String(64), nullable=False), sa.Column("grouping_confidence", sa.String(32), nullable=False),
        sa.Column("affected_subject_reference_id", sa.String(64), nullable=True),
        sa.Column("supporting_detection_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("supporting_evidence_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("matched_rule_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("possible_harms", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("containment_recommendations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("missing_information", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("review_status", sa.String(32), server_default="pending", nullable=False),
        sa.Column("is_current", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("superseded_by_profile_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["affected_subject_reference_id"], ["affected_subject_references.subject_reference_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["superseded_by_profile_id"], ["exposure_profiles.profile_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("profile_id"), sa.UniqueConstraint("profile_key"),
    )
    op.create_index("ix_exposure_profile_id", "exposure_profiles", ["profile_id"], unique=True)
    op.create_index("ix_exposure_profile_key", "exposure_profiles", ["profile_key"], unique=True)
    for name, columns in (
        ("ix_exposure_profile_incident", ["incident_id"]), ("ix_exposure_profile_type", ["profile_type"]),
        ("ix_exposure_profile_severity", ["severity"]), ("ix_exposure_profile_internal", ["internal_only"]),
        ("ix_exposure_profile_subject", ["affected_subject_reference_id"]), ("ix_exposure_profile_review", ["review_status"]),
        ("ix_exposure_profile_current", ["is_current"]),
    ):
        op.create_index(name, "exposure_profiles", columns)

    op.create_table(
        "exposure_profile_factors",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("exposure_profile_id", sa.String(64), nullable=False), sa.Column("classification_id", sa.String(64), nullable=False),
        sa.Column("taxonomy_code", sa.String(128), nullable=False), sa.Column("detection_id", sa.String(64), nullable=True),
        sa.Column("factor_role", sa.String(32), nullable=False), sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["exposure_profile_id"], ["exposure_profiles.profile_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["classification_id"], ["sensitive_data_classifications.classification_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.detection_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("exposure_profile_id", "classification_id", "factor_role", name="uq_profile_classification_role"),
    )
    op.create_index("ix_exposure_profile_factor_profile", "exposure_profile_factors", ["exposure_profile_id"])
    op.create_index("ix_exposure_profile_factor_classification", "exposure_profile_factors", ["classification_id"])
    op.create_index("ix_exposure_profile_factor_taxonomy", "exposure_profile_factors", ["taxonomy_code"])

    # Existing plain SHA-256 detection hashes remain untouched and are not reused as new grouping fingerprints.
    op.execute("""
        INSERT INTO sensitive_data_classifications (
          classification_id, classification_key, detection_id, incident_id, evidence_id,
          normalized_event_id, taxonomy_code, taxonomy_version, category_group,
          detection_method, context_score, format_validation_status, source_context_status,
          masked_value, value_fingerprint, fingerprint_strategy, confidence_label,
          review_status, internal_only, customer_notification_allowed, restricted_roles,
          evidence_role, limitations
        )
        SELECT
          'CLS-LEGACY-' || upper(substr(md5(detection_id), 1, 20)),
          'legacy:' || detection_id,
          detection_id, incident_id, evidence_id, normalized_event_id,
          'legacy_unmapped', 'legacy-unversioned', 'legacy_unmapped',
          COALESCE(detector_name, 'legacy_detector'), COALESCE(confidence, 0),
          'legacy_unverified', 'legacy_unverified', masked_value, NULL,
          'legacy_sha256_not_reused',
          CASE WHEN COALESCE(confidence, 0) >= 0.8 THEN 'medium' ELSE 'low' END,
          'pending', false, true, '[]'::jsonb, 'original',
          '["Legacy detection; contextual taxonomy review required."]'::jsonb
        FROM detections
        ON CONFLICT (classification_key) DO NOTHING
    """)


def downgrade() -> None:
    offline = context.is_offline_mode()
    tables = _table_names()
    for table in ("exposure_profile_factors", "exposure_profiles", "sensitive_data_classifications"):
        if offline or table in tables:
            op.drop_table(table)
    decision_columns = _column_names("breach_decision_records")
    for name in ("internal_only_restrictions", "exposure_profile_ids", "combination_ruleset_version", "taxonomy_version"):
        if offline or name in decision_columns:
            op.drop_column("breach_decision_records", name)
    assessment_columns = _column_names("privacy_impact_assessments")
    for name in ("combination_ruleset_version", "taxonomy_version"):
        if offline or name in assessment_columns:
            op.drop_column("privacy_impact_assessments", name)
    subject_columns = _column_names("affected_subject_references")
    if offline or "subject_type" in subject_columns:
        index_names = set() if offline else {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("affected_subject_references")}
        if offline or "ix_affected_subject_type" in index_names:
            op.drop_index("ix_affected_subject_type", table_name="affected_subject_references")
        op.drop_column("affected_subject_references", "subject_type")
