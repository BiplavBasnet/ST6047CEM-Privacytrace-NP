"""Enforce one current remediation diagnosis branch.

Revision ID: 032_current_remediation_branch
Revises: 031_security_ownership_hardening
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "032_current_remediation_branch"
down_revision: Union[str, None] = "031_security_ownership_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Preserve an accepted/action-bearing branch when repairing legacy duplicates.
    op.execute("""
        WITH ranked AS (
          SELECT d.id, row_number() OVER (
            PARTITION BY d.incident_id, d.root_cause_analysis_id, d.review_decision_id
            ORDER BY CASE WHEN a.id IS NOT NULL AND d.status IN ('accepted','accepted_with_edits') THEN 0 ELSE 1 END,
                     d.created_at DESC, d.id DESC
          ) AS rn
          FROM remediation_diagnoses d
          LEFT JOIN remediation_actions a ON a.diagnosis_id = d.diagnosis_id
          WHERE d.workflow_status = 'current'
        )
        UPDATE remediation_diagnoses d SET workflow_status = 'superseded'
        FROM ranked r WHERE d.id = r.id AND r.rn > 1
    """)
    reason = "Legacy duplicate current diagnosis superseded by migration 032."
    op.execute(f"""
        UPDATE remediation_actions SET workflow_status='superseded', requires_revalidation=true,
          invalidation_reason='{reason}' WHERE diagnosis_id IN
          (SELECT diagnosis_id FROM remediation_diagnoses WHERE workflow_status='superseded')
    """)
    for table, diagnosis_column in (
        ("patch_proposals", "diagnosis_id"),
        ("remediation_implementation_records", "diagnosis_id"),
        ("controlled_retests", "diagnosis_id"),
        ("fix_verifications", "remediation_diagnosis_id"),
    ):
        op.execute(f"""UPDATE {table} SET workflow_status='superseded', invalidation_reason='{reason}'
          WHERE {diagnosis_column} IN (SELECT diagnosis_id FROM remediation_diagnoses WHERE workflow_status='superseded')""")
    op.execute(f"""UPDATE remediation_test_executions SET workflow_status='superseded', invalidation_reason='{reason}'
      WHERE remediation_action_id IN (SELECT remediation_action_id FROM remediation_actions WHERE workflow_status='superseded')""")
    op.execute(f"""UPDATE verification_outcomes SET workflow_status='superseded', invalidation_reason='{reason}',
      eligible_for_learning=false, eligibility_reason='{reason}' WHERE remediation_diagnosis_id IN
      (SELECT diagnosis_id FROM remediation_diagnoses WHERE workflow_status='superseded')""")
    op.execute(f"""UPDATE verified_remediation_cases SET workflow_status='superseded', invalidation_reason='{reason}',
      eligible_for_learning=false, eligibility_reason='{reason}' WHERE verification_outcome_id IN
      (SELECT verification_outcome_id FROM verification_outcomes WHERE workflow_status='superseded')""")
    op.create_index(
        "uq_remediation_diagnosis_current_branch",
        "remediation_diagnoses",
        ["incident_id", "root_cause_analysis_id", "review_decision_id"],
        unique=True,
        postgresql_where=sa.text("workflow_status = 'current'"),
    )


def downgrade() -> None:
    op.drop_index("uq_remediation_diagnosis_current_branch", table_name="remediation_diagnoses")
