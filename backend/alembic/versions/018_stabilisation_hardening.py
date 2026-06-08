"""Additive Phase 6-7 integrity and breach-alert hardening.

Revision ID: 018_stabilisation_hardening
Revises: 017_nepal_taxonomy_exposure
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "018_stabilisation_hardening"
down_revision: Union[str, None] = "017_nepal_taxonomy_exposure"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "privacy_impact_factors",
        sa.Column(
            "method_version",
            sa.String(64),
            server_default="privacy-impact-v1",
            nullable=False,
        ),
    )
    op.add_column(
        "counterfactual_analyses",
        sa.Column(
            "method_version",
            sa.String(64),
            server_default="counterfactual-removal-v2",
            nullable=False,
        ),
    )

    op.add_column("exposure_profiles", sa.Column("rule_id", sa.String(128), nullable=True))
    op.add_column("exposure_profiles", sa.Column("grouping_key", sa.String(160), nullable=True))
    op.execute(
        """
        UPDATE exposure_profiles
        SET rule_id = COALESCE(matched_rule_ids ->> 0, profile_type),
            grouping_key = COALESCE(affected_subject_reference_id, profile_key)
        WHERE rule_id IS NULL OR grouping_key IS NULL
        """
    )
    op.alter_column("exposure_profiles", "rule_id", nullable=False)
    op.alter_column("exposure_profiles", "grouping_key", nullable=False)
    op.execute(
        """
        WITH ranked AS (
          SELECT id,
                 first_value(profile_id) OVER (
                   PARTITION BY incident_id, rule_id, grouping_method, grouping_key
                   ORDER BY created_at DESC, id DESC
                 ) AS keeper_profile_id,
                 row_number() OVER (
                   PARTITION BY incident_id, rule_id, grouping_method, grouping_key
                   ORDER BY created_at DESC, id DESC
                 ) AS position
          FROM exposure_profiles
          WHERE is_current IS TRUE
        )
        UPDATE exposure_profiles AS profile
        SET is_current = FALSE,
            superseded_by_profile_id = ranked.keeper_profile_id
        FROM ranked
        WHERE profile.id = ranked.id AND ranked.position > 1
        """
    )
    op.create_index(
        "uq_exposure_profile_current_group",
        "exposure_profiles",
        ["incident_id", "rule_id", "grouping_method", "grouping_key"],
        unique=True,
        postgresql_where=sa.text("is_current IS TRUE"),
    )

    op.add_column(
        "privacy_alerts",
        sa.Column("integrity_failure_fingerprint", sa.String(128), nullable=True),
    )
    op.create_index(
        "uq_privacy_alert_integrity_failure",
        "privacy_alerts",
        ["integrity_failure_fingerprint"],
        unique=True,
        postgresql_where=sa.text("integrity_failure_fingerprint IS NOT NULL"),
    )

    op.add_column(
        "integrity_verification_runs",
        sa.Column("scope_records_checked", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "integrity_verification_runs",
        sa.Column("verified_head_sequence", sa.Integer(), nullable=True),
    )
    op.add_column(
        "integrity_verification_runs",
        sa.Column("verified_head_hash", sa.String(128), nullable=True),
    )
    op.add_column(
        "integrity_verification_runs",
        sa.Column("failure_fingerprint", sa.String(128), nullable=True),
    )
    op.add_column(
        "integrity_verification_runs",
        sa.Column("integrity_alert_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_integrity_verification_runs_failure_fingerprint",
        "integrity_verification_runs",
        ["failure_fingerprint"],
    )
    op.create_foreign_key(
        "fk_integrity_verification_run_alert",
        "integrity_verification_runs",
        "privacy_alerts",
        ["integrity_alert_id"],
        ["alert_id"],
        ondelete="SET NULL",
    )

    op.add_column(
        "breach_alerts",
        sa.Column("deduplication_signature", sa.String(128), nullable=True),
    )
    op.add_column(
        "breach_alerts",
        sa.Column("deduplication_window_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "breach_alerts",
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        """
        UPDATE breach_alerts
        SET deduplication_signature = deduplication_key,
            deduplication_window_started_at = COALESCE(last_observed_at, triggered_at)
        WHERE deduplication_signature IS NULL
           OR deduplication_window_started_at IS NULL
        """
    )
    op.alter_column("breach_alerts", "deduplication_signature", nullable=False)
    op.alter_column("breach_alerts", "deduplication_window_started_at", nullable=False)
    op.create_index(
        "ix_breach_alert_deduplication_signature",
        "breach_alerts",
        ["deduplication_signature"],
    )
    op.create_check_constraint(
        "ck_breach_alert_occurrence_positive",
        "breach_alerts",
        "occurrence_count >= 1",
    )
    op.create_check_constraint(
        "ck_breach_alert_duplicate_nonnegative",
        "breach_alerts",
        "duplicate_count >= 0",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION privacytrace_guard_integrity_head()
        RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'integrity ledger head cannot be deleted';
          END IF;
          IF NEW.id <> OLD.id
             OR NEW.last_sequence_number <> OLD.last_sequence_number + 1
             OR NOT EXISTS (
               SELECT 1
               FROM integrity_ledger_records AS record
               WHERE record.sequence_number = NEW.last_sequence_number
                 AND record.record_hash = NEW.last_record_hash
             ) THEN
            RAISE EXCEPTION 'integrity ledger head may only advance to the next appended record';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_guard_integrity_head
        BEFORE UPDATE OR DELETE ON integrity_ledger_head
        FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_integrity_head();
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION privacytrace_guard_approved_decision()
        RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.status IN ('approved', 'superseded') THEN
              RAISE EXCEPTION 'approved breach decisions are immutable';
            END IF;
            RETURN OLD;
          END IF;

          IF OLD.status = 'superseded' THEN
            RAISE EXCEPTION 'superseded breach decisions are immutable';
          END IF;

          IF OLD.status = 'approved' THEN
            IF OLD.integrity_record_id IS NULL
               AND NEW.integrity_record_id IS NOT NULL
               AND (to_jsonb(NEW) - 'integrity_record_id')
                   = (to_jsonb(OLD) - 'integrity_record_id') THEN
              RETURN NEW;
            END IF;
            IF NEW.status = 'superseded'
               AND NEW.superseded_by_record_id IS NOT NULL
               AND (to_jsonb(NEW) - ARRAY['status', 'superseded_by_record_id'])
                   = (to_jsonb(OLD) - ARRAY['status', 'superseded_by_record_id']) THEN
              RETURN NEW;
            END IF;
            RAISE EXCEPTION 'approved breach decisions are immutable';
          END IF;

          IF NEW.status = 'approved'
             AND (to_jsonb(NEW) - ARRAY['status', 'approved_by', 'approved_at'])
                 <> (to_jsonb(OLD) - ARRAY['status', 'approved_by', 'approved_at']) THEN
            RAISE EXCEPTION 'approval may only set status and approval metadata';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "018_stabilisation_hardening is forward-only to preserve integrity and alert history."
    )
