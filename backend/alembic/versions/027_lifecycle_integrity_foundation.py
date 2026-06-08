"""Wave 2A lifecycle integrity foundation.

Revision ID: 027_lifecycle_integrity_foundation
Revises: 026_live_alert_correlation_keys
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "027_lifecycle_integrity_foundation"
down_revision: Union[str, None] = "026_live_alert_correlation_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _cols(inspector, table: str) -> set[str]:
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _add_status_columns(inspector, table: str) -> None:
    columns = _cols(inspector, table)
    if "workflow_status" not in columns:
        op.add_column(
            table,
            sa.Column(
                "workflow_status",
                sa.String(length=64),
                nullable=False,
                server_default="current",
            ),
        )
    if "invalidation_reason" not in columns:
        op.add_column(table, sa.Column("invalidation_reason", sa.Text(), nullable=True))


def _not_valid_fk(
    table: str,
    name: str,
    columns: str,
    target: str,
) -> None:
    op.execute(
        sa.text(
            f"""
            DO $$ BEGIN
              IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = '{name}'
              ) THEN
                ALTER TABLE {table}
                  ADD CONSTRAINT {name} FOREIGN KEY ({columns})
                  REFERENCES {target} ON DELETE RESTRICT NOT VALID;
              END IF;
            END $$
            """
        )
    )


def _replace_incident_fk(inspector, table: str) -> None:
    for foreign_key in inspector.get_foreign_keys(table):
        if (
            foreign_key.get("constrained_columns") == ["incident_id"]
            and foreign_key.get("referred_table") == "incidents"
        ):
            op.drop_constraint(foreign_key["name"], table, type_="foreignkey")
    op.create_foreign_key(
        f"fk_{table}_incident_restrict_027",
        table,
        "incidents",
        ["incident_id"],
        ["incident_id"],
        ondelete="RESTRICT",
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Migration 027 requires PostgreSQL.")
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    for table in (
        "remediation_actions",
        "patch_proposals",
        "remediation_test_executions",
        "verification_outcomes",
        "verified_remediation_cases",
    ):
        if table in tables:
            _add_status_columns(inspector, table)

    for table in (
        "root_cause_analyses",
        "review_decisions",
        "remediation_diagnoses",
        "remediation_actions",
        "patch_proposals",
        "remediation_test_executions",
        "verification_outcomes",
        "verified_remediation_cases",
        "fix_verifications",
    ):
        if table in tables:
            _replace_incident_fk(inspector, table)

    # Preserve every duplicate as history; detach only the non-canonical link.
    op.execute(
        sa.text(
            """
            WITH ranked AS (
              SELECT id, row_number() OVER (
                PARTITION BY diagnosis_id ORDER BY created_at, id
              ) AS ordinal
              FROM remediation_actions
              WHERE diagnosis_id IS NOT NULL
            )
            UPDATE remediation_actions ra
               SET diagnosis_id = NULL,
                   requires_revalidation = true,
                   workflow_status = 'historical',
                   invalidation_reason =
                     'Legacy duplicate action detached during migration 027.'
              FROM ranked r
             WHERE ra.id = r.id AND r.ordinal > 1
            """
        )
    )

    # If an old race produced multiple current RCAs, keep the newest identity.
    op.execute(
        sa.text(
            """
            WITH ranked AS (
              SELECT id, analysis_id,
                     first_value(analysis_id) OVER (
                       PARTITION BY incident_id
                       ORDER BY analysis_version DESC, id DESC
                     ) AS winner,
                     row_number() OVER (
                       PARTITION BY incident_id
                       ORDER BY analysis_version DESC, id DESC
                     ) AS ordinal
                FROM root_cause_analyses
               WHERE current IS TRUE
            )
            UPDATE root_cause_analyses rca
               SET current = false,
                   stale = true,
                   stale_reason = COALESCE(
                     stale_reason,
                     'Superseded during migration 027 current-RCA reconciliation.'
                   ),
                   superseded_by_analysis_id = COALESCE(
                     superseded_by_analysis_id, ranked.winner
                   )
              FROM ranked
             WHERE rca.id = ranked.id AND ranked.ordinal > 1
            """
        )
    )

    duplicate_versions = bind.scalar(
        sa.text(
            """
            SELECT count(*) FROM (
              SELECT incident_id, analysis_version
                FROM root_cause_analyses
               GROUP BY incident_id, analysis_version
              HAVING count(*) > 1
            ) duplicates
            """
        )
    )
    if duplicate_versions:
        raise RuntimeError(
            "Duplicate root-cause analysis versions require explicit reconciliation "
            "before migration 027 can continue."
        )

    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_root_cause_current_incident "
        "ON root_cause_analyses (incident_id) WHERE current IS TRUE"
    ))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_root_cause_incident_version "
        "ON root_cause_analyses (incident_id, analysis_version)"
    ))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_remediation_actions_diagnosis "
        "ON remediation_actions (diagnosis_id) WHERE diagnosis_id IS NOT NULL"
    ))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_outcomes_fix_verification "
        "ON verification_outcomes (fix_verification_id) "
        "WHERE fix_verification_id IS NOT NULL"
    ))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_verified_remediation_cases_outcome "
        "ON verified_remediation_cases (verification_outcome_id) "
        "WHERE verification_outcome_id IS NOT NULL"
    ))

    # NOT VALID preserves ambiguous legacy rows but enforces all new references.
    for args in (
        ("review_decisions", "fk_review_rca_027", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("remediation_diagnoses", "fk_diagnosis_rca_027", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("remediation_diagnoses", "fk_diagnosis_review_027", "review_decision_id", "review_decisions(id)"),
        ("remediation_actions", "fk_action_diagnosis_027", "diagnosis_id", "remediation_diagnoses(diagnosis_id)"),
        ("remediation_actions", "fk_action_rca_027", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("remediation_actions", "fk_action_review_027", "review_decision_id", "review_decisions(id)"),
        ("patch_proposals", "fk_patch_action_027", "remediation_action_id", "remediation_actions(remediation_action_id)"),
        ("patch_proposals", "fk_patch_diagnosis_027", "diagnosis_id", "remediation_diagnoses(diagnosis_id)"),
        ("patch_proposals", "fk_patch_rca_027", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("remediation_test_executions", "fk_test_action_027", "remediation_action_id", "remediation_actions(remediation_action_id)"),
        ("remediation_test_executions", "fk_test_patch_027", "patch_proposal_id", "patch_proposals(patch_proposal_id)"),
        ("verification_outcomes", "fk_outcome_rca_027", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("verification_outcomes", "fk_outcome_review_027", "review_decision_id", "review_decisions(id)"),
        ("verification_outcomes", "fk_outcome_diagnosis_027", "remediation_diagnosis_id", "remediation_diagnoses(diagnosis_id)"),
        ("verification_outcomes", "fk_outcome_action_027", "remediation_action_id", "remediation_actions(remediation_action_id)"),
        ("verification_outcomes", "fk_outcome_patch_027", "patch_proposal_id", "patch_proposals(patch_proposal_id)"),
        ("verification_outcomes", "fk_outcome_test_027", "test_execution_id", "remediation_test_executions(execution_id)"),
        ("verification_outcomes", "fk_outcome_fix_027", "fix_verification_id", "fix_verifications(id)"),
        ("verified_remediation_cases", "fk_learning_outcome_027", "verification_outcome_id", "verification_outcomes(verification_outcome_id)"),
    ):
        _not_valid_fk(*args)


def downgrade() -> None:
    # The revision preserves history and is intentionally non-destructive.
    pass
