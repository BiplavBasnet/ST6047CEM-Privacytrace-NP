"""Verify that `alembic upgrade head` succeeds against a genuinely empty
PostgreSQL database.

This is the regression check for the fresh-install path described in
docs/DATABASE_MIGRATION_STRATEGY.md: revision 001 bootstraps tables from
today's live models, and several later revisions rely on `env.py`'s
`_POST_INITIAL_TABLES` list staying in sync with which tables get an
unguarded `op.add_column` after their creation. Run this script (or its
pytest wrapper, `app/tests/test_fresh_migration.py`) after adding any new
migration, before merging, to catch a "column already exists" / "relation
already exists" regression before a real developer hits it.

Safety: this script is destructive by design (it drops and recreates the
target schema before migrating) and refuses to run unless both:
  * REQUIRE_TEST_POSTGRES=1 is set, and
  * DATABASE_URL points at a PostgreSQL database whose name ends in `_test`.

Usage (PowerShell):
    cd backend
    $env:REQUIRE_TEST_POSTGRES = "1"
    $env:DATABASE_URL = "postgresql://user:pass@localhost:5432/privacytrace_fresh_test"
    python scripts/verify_fresh_migration.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parent.parent


class UnsafeMigrationTargetError(RuntimeError):
    """Raised when the configured database is not a dedicated test database."""


def _require_dedicated_test_postgres(database_url: str) -> None:
    if os.getenv("REQUIRE_TEST_POSTGRES") != "1":
        raise UnsafeMigrationTargetError(
            "Refusing to run: set REQUIRE_TEST_POSTGRES=1 to confirm you intend "
            "to run this destructive fresh-migration check."
        )
    url = make_url(database_url)
    database_name = url.database or ""
    if not url.drivername.startswith("postgresql") or not database_name.lower().endswith("_test"):
        raise UnsafeMigrationTargetError(
            "Refusing to run: DATABASE_URL must target PostgreSQL and the "
            "database name must end with '_test'. "
            f"Got drivername={url.drivername!r}, database={database_name!r}."
        )


def _reset_to_empty(database_url: str) -> None:
    """Drop everything so the database looks genuinely unversioned/empty."""
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _assert_head_reached(database_url: str, alembic_cfg: Config) -> None:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(alembic_cfg)
    expected_head = script.get_current_head()

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    finally:
        engine.dispose()

    if row is None:
        raise AssertionError("alembic_version table has no row after upgrade head.")
    actual_head = row[0]
    if actual_head != expected_head:
        raise AssertionError(
            f"Expected alembic head {expected_head!r} after upgrade, found {actual_head!r}."
        )


def _spot_check_tables(database_url: str) -> None:
    """A few tables from across the migration history that must all exist."""
    expected_tables = {
        "users",  # 001
        "incidents",  # 001
        "privacy_alerts",  # created by an early revision, extended by 021
        "integrity_ledger_records",  # 015
        "privacy_impact_factors",  # 014, extended (unguarded) by 018
        "integrity_verification_runs",  # 015, extended (unguarded) by 020
        "live_monitor_runtime_state",  # 021 (guarded, from-scratch-safe)
        "integration_events",  # 021 (guarded, from-scratch-safe)
    }
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            inspector = inspect(connection)
            actual_tables = set(inspector.get_table_names())
            report_fk_names = {
                fk.get("name") for fk in inspector.get_foreign_keys("reports") if fk.get("name")
            }
    finally:
        engine.dispose()

    missing = expected_tables - actual_tables
    if missing:
        raise AssertionError(f"Expected tables missing after upgrade head: {sorted(missing)}")
    expected_report_fks = {
        "fk_reports_controlled_retest",
        "fk_reports_verification_outcome",
        "fk_reports_action",
    }
    missing_fks = expected_report_fks - report_fk_names
    if missing_fks:
        raise AssertionError(
            f"Expected reports FKs missing after upgrade head: {sorted(missing_fks)}"
        )


def verify_fresh_migration(database_url: str | None = None) -> None:
    database_url = database_url or os.environ["DATABASE_URL"]
    _require_dedicated_test_postgres(database_url)

    print(f"Resetting {make_url(database_url).database!r} to an empty schema...")
    _reset_to_empty(database_url)

    alembic_cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    alembic_cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))

    print("Running `alembic upgrade head` against the empty database...")
    command.upgrade(alembic_cfg, "head")

    print("Verifying the database reached the expected head revision...")
    _assert_head_reached(database_url, alembic_cfg)

    print("Spot-checking tables from across the migration history...")
    _spot_check_tables(database_url)

    print("OK: `alembic upgrade head` succeeded from an empty database.")


def main() -> int:
    try:
        verify_fresh_migration()
    except UnsafeMigrationTargetError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — top-level script failure reporting
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
