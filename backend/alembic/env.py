from logging.config import fileConfig

from alembic import context
from sqlalchemy import MetaData, engine_from_config, inspect, pool, text

from app.config import get_settings
from app.database import Base

# Import all models so metadata is populated
import app.models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Revision 001 uses the live Base.metadata. On a genuinely empty database,
# temporarily present only its historical table subset so later revisions can
# create their own tables in order.
_POST_INITIAL_TABLES = frozenset(
    {
        "affected_subject_references",
        "ai_remediation_suggestions",
        "breach_alert_evidence_links",
        "breach_alerts",
        "breach_decision_factors",
        "breach_decision_records",
        "cicd_evidence",
        "containment_actions",
        "counterfactual_analyses",
        "counterfactual_test_results",
        "customer_notification_decisions",
        "delivery_attempts",
        "evidence_provenance",
        "exposure_profile_factors",
        "exposure_profiles",
        "integration_tokens",
        "integrity_ledger_head",
        "integrity_ledger_records",
        "integrity_verification_runs",
        "llm_reports",
        "notification_outbox",
        "preventive_control_evidence_links",
        "preventive_controls",
        "privacy_alerts",
        "privacy_harms",
        "privacy_impact_assessments",
        "privacy_impact_factors",
        "provenance_relationships",
        "remediation_actions",
        "remediation_diagnoses",
        "remediation_test_executions",
        "patch_proposals",
        "verified_remediation_cases",
        "remediation_playbooks",
        "review_drafts",
        "root_cause_analyses",
        "scanner_evidence_records",
        "sensitive_data_classifications",
        "exposure_verification_profiles",
        "verification_outcomes",
        "alert_trace_references",
        "controlled_retests",
        "remediation_implementation_records",
        "organisations",
        "organisation_memberships",
        "organisation_invitations",
        "deployment_setup",
    }
)


def _is_unversioned_empty_database(connection) -> bool:
    database = inspect(connection)
    return not database.has_table("alembic_version") and not database.get_table_names()


def _initial_revision_metadata() -> MetaData:
    """001-era tables/columns only — no FKs to post-001 tables.

    Live models on initial tables (reports, review_decisions, fix_verifications)
    now declare FKs to later-created tables. ``Table.to_metadata`` resolves those
    FKs at copy time and fails. Later revisions add the real constraints.
    """
    from sqlalchemy import Column, Index, Table
    from sqlalchemy.schema import CheckConstraint, UniqueConstraint

    metadata = MetaData()
    included = {name for name in target_metadata.tables if name not in _POST_INITIAL_TABLES}
    for src in target_metadata.tables.values():
        if src.name not in included:
            continue
        columns = [
            Column(
                col.name,
                col.type,
                primary_key=col.primary_key,
                nullable=col.nullable,
                server_default=col.server_default,
                autoincrement=col.autoincrement,
            )
            for col in src.columns
        ]
        extras = []
        for const in src.constraints:
            if isinstance(const, UniqueConstraint):
                extras.append(
                    UniqueConstraint(*[column.name for column in const.columns], name=const.name)
                )
            elif isinstance(const, CheckConstraint):
                extras.append(CheckConstraint(const.sqltext, name=const.name))
        Table(src.name, metadata, *columns, *extras)
        dest = metadata.tables[src.name]
        for ix in src.indexes:
            Index(
                ix.name,
                *[dest.c[column.name] for column in ix.columns],
                unique=ix.unique,
            )
    return metadata


def _ensure_alembic_version_table(connection, database_is_empty: bool) -> None:
    database = inspect(connection)
    if database_is_empty and not database.has_table("alembic_version"):
        connection.execute(
            text(
                "CREATE TABLE alembic_version ("
                "version_num VARCHAR(128) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)"
                ")"
            )
        )
        return

    if database.has_table("alembic_version"):
        connection.execute(
            text(
                "ALTER TABLE alembic_version "
                "ALTER COLUMN version_num TYPE VARCHAR(128)"
            )
        )

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.begin() as connection:
        original_metadata = Base.metadata
        migration_metadata = target_metadata
        database_is_empty = _is_unversioned_empty_database(connection)

        if database_is_empty:
            migration_metadata = _initial_revision_metadata()
            Base.metadata = migration_metadata

        try:
            context.configure(connection=connection, target_metadata=migration_metadata)

            with context.begin_transaction():
                _ensure_alembic_version_table(connection, database_is_empty)
                context.run_migrations()
        finally:
            Base.metadata = original_metadata


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
