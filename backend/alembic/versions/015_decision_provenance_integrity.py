"""Decision history, evidence provenance, and tamper-evident integrity.

Revision ID: 015_decision_provenance_integrity
Revises: 014_privacy_harm_response
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "015_decision_provenance_integrity"
down_revision: Union[str, None] = "014_privacy_harm_response"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "breach_decision_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("decision_id", sa.String(64), nullable=False),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("assessment_id", sa.String(64), nullable=False),
        sa.Column("decision_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), server_default="draft", nullable=False),
        sa.Column("breach_determination", sa.String(32), server_default="insufficient_evidence", nullable=False),
        sa.Column("assessment_method_version", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("root_cause_ruleset_version", sa.String(128), nullable=False),
        sa.Column("input_evidence_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("affected_data_categories", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("affected_subject_count", sa.Integer(), nullable=True),
        sa.Column("affected_subject_count_status", sa.String(32), server_default="unknown", nullable=False),
        sa.Column("severity_inputs", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("privacy_harm_inputs", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("root_cause_summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("severity_result", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("privacy_harm_result", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("alert_recommendation", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("containment_recommendations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("customer_notification_recommendation", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("missing_information", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("uncertainties", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("human_override_present", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("human_override_reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("supersedes_record_id", sa.String(64), nullable=True),
        sa.Column("superseded_by_record_id", sa.String(64), nullable=True),
        sa.Column("integrity_record_id", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assessment_id"], ["privacy_impact_assessments.assessment_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["supersedes_record_id"], ["breach_decision_records.decision_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["superseded_by_record_id"], ["breach_decision_records.decision_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("decision_id"),
        sa.UniqueConstraint("incident_id", "decision_version", name="uq_breach_decision_incident_version"),
    )
    op.create_index("ix_breach_decision_decision_id", "breach_decision_records", ["decision_id"], unique=True)
    op.create_index("ix_breach_decision_incident_id", "breach_decision_records", ["incident_id"])
    op.create_index("ix_breach_decision_assessment_id", "breach_decision_records", ["assessment_id"])
    op.create_index("ix_breach_decision_status", "breach_decision_records", ["status"])
    op.create_index("ix_breach_decision_supersedes", "breach_decision_records", ["supersedes_record_id"])
    op.create_index("ix_breach_decision_superseded_by", "breach_decision_records", ["superseded_by_record_id"])
    op.create_index("ix_breach_decision_integrity", "breach_decision_records", ["integrity_record_id"])
    op.create_index("uq_breach_decision_latest_incident", "breach_decision_records", ["incident_id"], unique=True, postgresql_where=sa.text("superseded_by_record_id IS NULL"))

    op.create_table(
        "breach_decision_factors",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("decision_record_id", sa.String(64), nullable=False),
        sa.Column("factor_type", sa.String(64), nullable=False),
        sa.Column("factor_code", sa.String(128), nullable=False),
        sa.Column("factor_label", sa.String(255), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("score_contribution", sa.Float(), nullable=False),
        sa.Column("evidence_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("method_version", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("review_status", sa.String(32), server_default="pending", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["decision_record_id"], ["breach_decision_records.decision_id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_breach_decision_factor_record", "breach_decision_factors", ["decision_record_id"])

    op.create_table(
        "evidence_provenance",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("provenance_id", sa.String(64), nullable=False),
        sa.Column("evidence_id", sa.String(64), nullable=False),
        sa.Column("source_system", sa.String(255), nullable=True), sa.Column("source_event_id", sa.String(255), nullable=True),
        sa.Column("source_format", sa.String(64), nullable=True), sa.Column("source_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collection_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingestion_timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("collector_name", sa.String(128), nullable=True), sa.Column("collector_version", sa.String(64), nullable=True),
        sa.Column("parser_name", sa.String(128), nullable=True), sa.Column("parser_version", sa.String(64), nullable=True),
        sa.Column("normalisation_version", sa.String(64), nullable=True), sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_version", sa.String(64), nullable=True), sa.Column("deployment_environment", sa.String(64), nullable=True),
        sa.Column("host_reference", sa.String(255), nullable=True), sa.Column("container_reference", sa.String(255), nullable=True),
        sa.Column("trace_id", sa.String(128), nullable=True), sa.Column("span_id", sa.String(128), nullable=True),
        sa.Column("parent_span_id", sa.String(128), nullable=True), sa.Column("commit_sha", sa.String(128), nullable=True),
        sa.Column("configuration_hash", sa.String(128), nullable=True), sa.Column("content_sha256", sa.String(128), nullable=True),
        sa.Column("parent_evidence_id", sa.String(64), nullable=True),
        sa.Column("provenance_status", sa.String(32), server_default="unverified", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_files.evidence_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["parent_evidence_id"], ["evidence_files.evidence_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("provenance_id"), sa.UniqueConstraint("evidence_id", name="uq_evidence_provenance_evidence"),
    )
    op.create_index("ix_evidence_provenance_id", "evidence_provenance", ["provenance_id"], unique=True)
    op.create_index("ix_evidence_provenance_evidence", "evidence_provenance", ["evidence_id"])
    op.create_index("ix_evidence_provenance_parent", "evidence_provenance", ["parent_evidence_id"])
    op.create_index("ix_evidence_provenance_status", "evidence_provenance", ["provenance_status"])

    op.create_table(
        "provenance_relationships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("relationship_id", sa.String(64), nullable=False),
        sa.Column("source_entity_type", sa.String(64), nullable=False), sa.Column("source_entity_id", sa.String(128), nullable=False),
        sa.Column("target_entity_type", sa.String(64), nullable=False), sa.Column("target_entity_id", sa.String(128), nullable=False),
        sa.Column("relationship_type", sa.String(64), nullable=False), sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("confidence_type", sa.String(32), server_default="unverified", nullable=False),
        sa.Column("validation_status", sa.String(32), server_default="unverified", nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("relationship_id"),
        sa.UniqueConstraint("source_entity_type", "source_entity_id", "target_entity_type", "target_entity_id", "relationship_type", name="uq_provenance_relationship_edge"),
    )
    op.create_index("ix_provenance_relationship_id", "provenance_relationships", ["relationship_id"], unique=True)
    op.create_index("ix_provenance_relationship_source", "provenance_relationships", ["source_entity_type", "source_entity_id"])
    op.create_index("ix_provenance_relationship_target", "provenance_relationships", ["target_entity_type", "target_entity_id"])

    op.create_table(
        "integrity_ledger_head",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_sequence_number", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_record_hash", sa.String(128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_integrity_ledger_head_singleton"),
    )
    op.bulk_insert(sa.table("integrity_ledger_head", sa.column("id", sa.Integer()), sa.column("last_sequence_number", sa.Integer())), [{"id": 1, "last_sequence_number": 0}])

    op.create_table(
        "integrity_ledger_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("integrity_record_id", sa.String(64), nullable=False), sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("record_type", sa.String(64), nullable=False), sa.Column("record_id", sa.String(128), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=True), sa.Column("scope_id", sa.String(128), nullable=True),
        sa.Column("content_hash", sa.String(128), nullable=False), sa.Column("previous_record_hash", sa.String(128), nullable=True),
        sa.Column("record_hash", sa.String(128), nullable=False), sa.Column("integrity_schema_version", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verification_status", sa.String(32), server_default="not_yet_verified", nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("integrity_record_id"), sa.UniqueConstraint("sequence_number", name="uq_integrity_ledger_sequence"),
        sa.UniqueConstraint("record_hash", name="uq_integrity_ledger_record_hash"),
        sa.UniqueConstraint("record_type", "record_id", "content_hash", name="uq_integrity_ledger_content"),
    )
    op.create_index("ix_integrity_ledger_integrity_record_id", "integrity_ledger_records", ["integrity_record_id"], unique=True)
    op.create_index("ix_integrity_ledger_record", "integrity_ledger_records", ["record_type", "record_id"])
    op.create_index("ix_integrity_ledger_scope", "integrity_ledger_records", ["scope_type", "scope_id"])
    op.create_index("ix_integrity_ledger_verification", "integrity_ledger_records", ["verification_status"])

    op.create_table(
        "integrity_verification_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("verification_run_id", sa.String(64), nullable=False), sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("scope_id", sa.String(128), nullable=True), sa.Column("records_checked", sa.Integer(), server_default="0", nullable=False),
        sa.Column("chain_valid", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("content_mismatch_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("missing_sequence_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("invalid_link_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("first_invalid_sequence", sa.Integer(), nullable=True), sa.Column("result_summary", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("executed_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="SET NULL"), sa.UniqueConstraint("verification_run_id"),
    )
    op.create_index("ix_integrity_verification_run_id", "integrity_verification_runs", ["verification_run_id"], unique=True)
    op.create_index("ix_integrity_verification_scope_type", "integrity_verification_runs", ["scope_type"])
    op.create_index("ix_integrity_verification_scope_id", "integrity_verification_runs", ["scope_id"])

    op.execute("""
        CREATE FUNCTION privacytrace_guard_approved_decision() RETURNS trigger AS $$
        BEGIN
          IF OLD.status IN ('approved', 'superseded') THEN
            IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'approved breach decisions are immutable'; END IF;
            IF NOT (OLD.status = 'approved' AND NEW.status = 'superseded'
                    AND NEW.superseded_by_record_id IS NOT NULL
                    AND (to_jsonb(NEW) - ARRAY['status','superseded_by_record_id'])
                        = (to_jsonb(OLD) - ARRAY['status','superseded_by_record_id'])) THEN
              RAISE EXCEPTION 'approved breach decisions are immutable';
            END IF;
          END IF;
          IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_guard_approved_decision BEFORE UPDATE OR DELETE ON breach_decision_records
        FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_approved_decision();
    """)
    op.execute("""
        CREATE FUNCTION privacytrace_guard_decision_factor() RETURNS trigger AS $$
        DECLARE parent_status text;
        DECLARE parent_id text;
        BEGIN
          IF TG_OP = 'DELETE' THEN parent_id := OLD.decision_record_id; ELSE parent_id := NEW.decision_record_id; END IF;
          SELECT status INTO parent_status FROM breach_decision_records WHERE decision_id = parent_id;
          IF parent_status IN ('approved', 'superseded') THEN RAISE EXCEPTION 'approved breach decision factors are immutable'; END IF;
          IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_guard_decision_factor BEFORE INSERT OR UPDATE OR DELETE ON breach_decision_factors
        FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_decision_factor();
    """)
    op.execute("""
        CREATE FUNCTION privacytrace_guard_integrity_record() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'integrity ledger records are append-only'; END IF;
          IF (to_jsonb(NEW) - ARRAY['verification_status','last_verified_at'])
             <> (to_jsonb(OLD) - ARRAY['verification_status','last_verified_at']) THEN
            RAISE EXCEPTION 'integrity ledger hash fields are immutable';
          END IF;
          RETURN NEW;
        END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_guard_integrity_record BEFORE UPDATE OR DELETE ON integrity_ledger_records
        FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_integrity_record();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_guard_integrity_record ON integrity_ledger_records")
    op.execute("DROP FUNCTION IF EXISTS privacytrace_guard_integrity_record()")
    op.execute("DROP TRIGGER IF EXISTS trg_guard_decision_factor ON breach_decision_factors")
    op.execute("DROP FUNCTION IF EXISTS privacytrace_guard_decision_factor()")
    op.execute("DROP TRIGGER IF EXISTS trg_guard_approved_decision ON breach_decision_records")
    op.execute("DROP FUNCTION IF EXISTS privacytrace_guard_approved_decision()")
    for table in (
        "integrity_verification_runs", "integrity_ledger_records", "integrity_ledger_head",
        "provenance_relationships", "evidence_provenance", "breach_decision_factors", "breach_decision_records",
    ):
        op.drop_table(table)
