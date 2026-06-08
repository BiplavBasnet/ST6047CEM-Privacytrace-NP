"""Privacy harm, breach alert, containment, and notification records.

Revision ID: 014_privacy_harm_response
Revises: 013_workflow_integrity
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "014_privacy_harm_response"
down_revision: Union[str, None] = "013_workflow_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names() -> set[str] | None:
    if context.is_offline_mode():
        return None
    return set(sa.inspect(op.get_bind()).get_table_names())


def _should_create(table_name: str) -> bool:
    tables = _table_names()
    return tables is None or table_name not in tables


def _should_drop(table_name: str) -> bool:
    tables = _table_names()
    return tables is None or table_name in tables


def upgrade() -> None:
    if _should_create("privacy_impact_assessments"):
        op.create_table(
            "privacy_impact_assessments",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("assessment_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("assessment_version", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("data_processing_context_score", sa.Float(), nullable=False),
            sa.Column("ease_of_identification_score", sa.Float(), nullable=False),
            sa.Column("circumstances_score", sa.Float(), nullable=False),
            sa.Column("breach_severity_score", sa.Float(), nullable=False),
            sa.Column("breach_severity_level", sa.String(32), nullable=False),
            sa.Column("harm_likelihood", sa.Integer(), nullable=False),
            sa.Column("harm_magnitude", sa.Integer(), nullable=False),
            sa.Column("privacy_harm_score", sa.Integer(), nullable=False),
            sa.Column("privacy_harm_level", sa.String(32), nullable=False),
            sa.Column("affected_subject_count", sa.Integer(), nullable=True),
            sa.Column("affected_subject_count_status", sa.String(32), nullable=False),
            sa.Column("credential_exposure_present", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("public_exposure_present", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("external_access_confirmed", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("malicious_intent_status", sa.String(32), nullable=False),
            sa.Column("encrypted_or_unintelligible", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("assessment_confidence", sa.String(32), nullable=False),
            sa.Column("limitations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("data_categories", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("input_fingerprint", sa.String(128), nullable=False),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column("reviewed_by", sa.Integer(), nullable=True),
            sa.Column("approved_by", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("assessment_id"),
            sa.UniqueConstraint("incident_id", "assessment_version", name="uq_privacy_impact_incident_version"),
            sa.UniqueConstraint("incident_id", "input_fingerprint", name="uq_privacy_impact_incident_fingerprint"),
        )
        op.create_index("ix_privacy_impact_assessment_id", "privacy_impact_assessments", ["assessment_id"], unique=True)
        op.create_index("ix_privacy_impact_incident", "privacy_impact_assessments", ["incident_id"])
        op.create_index("ix_privacy_impact_status", "privacy_impact_assessments", ["status"])

    if _should_create("privacy_impact_factors"):
        op.create_table(
            "privacy_impact_factors",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("assessment_id", sa.String(64), nullable=False),
            sa.Column("factor_type", sa.String(64), nullable=False),
            sa.Column("factor_code", sa.String(128), nullable=False),
            sa.Column("factor_label", sa.String(255), nullable=False),
            sa.Column("score_contribution", sa.Float(), nullable=False),
            sa.Column("evidence_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("source", sa.String(64), nullable=False),
            sa.Column("is_system_generated", sa.Boolean(), server_default="true", nullable=False),
            sa.Column("review_status", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["assessment_id"], ["privacy_impact_assessments.assessment_id"], ondelete="CASCADE"),
        )
        op.create_index("ix_privacy_impact_factor_assessment", "privacy_impact_factors", ["assessment_id"])

    if _should_create("privacy_harms"):
        op.create_table(
            "privacy_harms",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("harm_id", sa.String(64), nullable=False),
            sa.Column("assessment_id", sa.String(64), nullable=False),
            sa.Column("harm_category", sa.String(64), nullable=False),
            sa.Column("likelihood", sa.Integer(), nullable=False),
            sa.Column("magnitude", sa.Integer(), nullable=False),
            sa.Column("harm_score", sa.Integer(), nullable=False),
            sa.Column("evidence_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("explanation", sa.Text(), nullable=False),
            sa.Column("uncertainty", sa.Text(), nullable=False),
            sa.Column("recommended_mitigation", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["assessment_id"], ["privacy_impact_assessments.assessment_id"], ondelete="CASCADE"),
            sa.UniqueConstraint("harm_id"),
        )
        op.create_index("ix_privacy_harm_id", "privacy_harms", ["harm_id"], unique=True)
        op.create_index("ix_privacy_harm_assessment", "privacy_harms", ["assessment_id"])

    if _should_create("affected_subject_references"):
        op.create_table(
            "affected_subject_references",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("subject_reference_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("subject_reference", sa.String(96), nullable=False),
            sa.Column("reference_method", sa.String(32), nullable=False),
            sa.Column("resolution_status", sa.String(32), nullable=False),
            sa.Column("affected_data_categories", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
            sa.Column("credential_types", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("notification_eligibility", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.UniqueConstraint("subject_reference_id"),
            sa.UniqueConstraint("incident_id", "subject_reference", name="uq_affected_subject_incident_reference"),
        )
        op.create_index("ix_affected_subject_reference_id", "affected_subject_references", ["subject_reference_id"], unique=True)
        op.create_index("ix_affected_subject_incident", "affected_subject_references", ["incident_id"])
        op.create_index("ix_affected_subject_status", "affected_subject_references", ["resolution_status"])

    if _should_create("breach_alerts"):
        op.create_table(
            "breach_alerts",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("alert_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("assessment_id", sa.String(64), nullable=False),
            sa.Column("alert_type", sa.String(64), nullable=False),
            sa.Column("severity", sa.String(32), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("reason_codes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("affected_subject_count", sa.Integer(), nullable=True),
            sa.Column("credential_exposure_present", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("requires_acknowledgement", sa.Boolean(), server_default="true", nullable=False),
            sa.Column("deduplication_key", sa.String(128), nullable=False),
            sa.Column("triggered_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acknowledged_by", sa.Integer(), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by", sa.Integer(), nullable=True),
            sa.Column("resolution_reason", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["assessment_id"], ["privacy_impact_assessments.assessment_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["resolved_by"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("alert_id"), sa.UniqueConstraint("deduplication_key"),
        )
        for name, columns, unique in (("ix_breach_alert_id", ["alert_id"], True), ("ix_breach_alert_incident", ["incident_id"], False),
                                      ("ix_breach_alert_assessment", ["assessment_id"], False), ("ix_breach_alert_status", ["status"], False),
                                      ("ix_breach_alert_severity", ["severity"], False), ("ix_breach_alert_dedupe", ["deduplication_key"], True)):
            op.create_index(name, "breach_alerts", columns, unique=unique)

    if _should_create("containment_actions"):
        op.create_table(
            "containment_actions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("containment_action_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("affected_subject_reference_id", sa.String(64), nullable=True),
            sa.Column("action_type", sa.String(64), nullable=False),
            sa.Column("credential_type", sa.String(64), nullable=True),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("requires_approval", sa.Boolean(), server_default="true", nullable=False),
            sa.Column("approved_by", sa.Integer(), nullable=True), sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("executed_by", sa.Integer(), nullable=True), sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("execution_reference", sa.String(255), nullable=True), sa.Column("result_summary", sa.Text(), nullable=True),
            sa.Column("failure_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["affected_subject_reference_id"], ["affected_subject_references.subject_reference_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("containment_action_id"),
        )
        op.create_index("ix_containment_action_id", "containment_actions", ["containment_action_id"], unique=True)
        op.create_index("ix_containment_incident", "containment_actions", ["incident_id"])
        op.create_index("ix_containment_subject", "containment_actions", ["affected_subject_reference_id"])
        op.create_index("ix_containment_status", "containment_actions", ["status"])

    if _should_create("customer_notification_decisions"):
        op.create_table(
            "customer_notification_decisions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("notification_id", sa.String(64), nullable=False), sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("assessment_id", sa.String(64), nullable=False), sa.Column("affected_subject_reference_id", sa.String(64), nullable=False),
            sa.Column("recommendation", sa.String(48), nullable=False),
            sa.Column("reason_codes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
            sa.Column("decision_rationale", sa.Text(), nullable=False), sa.Column("status", sa.String(32), nullable=False),
            sa.Column("draft_message", sa.Text(), nullable=False), sa.Column("message_locale", sa.String(16), nullable=False),
            sa.Column("created_by", sa.Integer(), nullable=True), sa.Column("approved_by", sa.Integer(), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True), sa.Column("rejected_by", sa.Integer(), nullable=True),
            sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True), sa.Column("rejection_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["assessment_id"], ["privacy_impact_assessments.assessment_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["affected_subject_reference_id"], ["affected_subject_references.subject_reference_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["rejected_by"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("notification_id"),
            sa.UniqueConstraint("incident_id", "affected_subject_reference_id", "assessment_id", name="uq_notification_subject_assessment"),
        )
        op.create_index("ix_customer_notification_id", "customer_notification_decisions", ["notification_id"], unique=True)
        op.create_index("ix_customer_notification_incident", "customer_notification_decisions", ["incident_id"])
        op.create_index("ix_customer_notification_status", "customer_notification_decisions", ["status"])

    if _should_create("notification_outbox"):
        op.create_table(
            "notification_outbox",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("outbox_id", sa.String(64), nullable=False), sa.Column("notification_id", sa.String(64), nullable=False),
            sa.Column("channel", sa.String(32), nullable=False), sa.Column("idempotency_key", sa.String(128), nullable=False),
            sa.Column("destination_reference", sa.String(96), nullable=False), sa.Column("status", sa.String(32), nullable=False),
            sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False), sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_category", sa.String(64), nullable=True), sa.Column("provider_message_reference", sa.String(255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["notification_id"], ["customer_notification_decisions.notification_id"], ondelete="RESTRICT"),
            sa.UniqueConstraint("outbox_id"), sa.UniqueConstraint("idempotency_key"),
            sa.UniqueConstraint("notification_id", "channel", name="uq_outbox_notification_channel"),
        )
        op.create_index("ix_notification_outbox_id", "notification_outbox", ["outbox_id"], unique=True)
        op.create_index("ix_notification_outbox_notification", "notification_outbox", ["notification_id"])
        op.create_index("ix_notification_outbox_status", "notification_outbox", ["status"])
        op.create_index("ix_notification_outbox_idempotency", "notification_outbox", ["idempotency_key"], unique=True)

    if _should_create("delivery_attempts"):
        op.create_table(
            "delivery_attempts",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("delivery_attempt_id", sa.String(64), nullable=False), sa.Column("outbox_id", sa.String(64), nullable=False),
            sa.Column("attempt_number", sa.Integer(), nullable=False), sa.Column("status", sa.String(32), nullable=False),
            sa.Column("error_category", sa.String(64), nullable=True), sa.Column("provider_message_reference", sa.String(255), nullable=True),
            sa.Column("attempted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["outbox_id"], ["notification_outbox.outbox_id"], ondelete="RESTRICT"),
            sa.UniqueConstraint("delivery_attempt_id"), sa.UniqueConstraint("outbox_id", "attempt_number", name="uq_delivery_attempt_number"),
        )
        op.create_index("ix_delivery_attempt_id", "delivery_attempts", ["delivery_attempt_id"], unique=True)
        op.create_index("ix_delivery_attempt_outbox", "delivery_attempts", ["outbox_id"])


def downgrade() -> None:
    for table in ("delivery_attempts", "notification_outbox", "customer_notification_decisions", "containment_actions",
                  "breach_alerts", "affected_subject_references", "privacy_harms", "privacy_impact_factors", "privacy_impact_assessments"):
        if _should_drop(table):
            op.drop_table(table)
