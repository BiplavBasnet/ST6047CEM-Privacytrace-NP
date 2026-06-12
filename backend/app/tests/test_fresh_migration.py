"""Regression test for the from-scratch `alembic upgrade head` path.

See docs/DATABASE_MIGRATION_STRATEGY.md. This is destructive (it drops and
recreates the target schema) and is skipped unless the caller explicitly
opts in with REQUIRE_TEST_POSTGRES=1 and a DATABASE_URL whose database name
ends in `_test` — the same fail-closed guard every other database-backed
test in this suite uses (`app/tests/conftest.py::_require_dedicated_test_postgres`).

This test intentionally does not share the `migrated_db`/`db_session`
fixtures: those assume `Base.metadata.create_all` has already been run by
`conftest.py`, whereas this test's entire point is to drive schema creation
through the real `alembic upgrade head` path instead.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy.engine import make_url

from app.config import get_settings
from scripts.verify_fresh_migration import UnsafeMigrationTargetError, verify_fresh_migration


def _dedicated_test_postgres_configured() -> bool:
    if os.getenv("REQUIRE_TEST_POSTGRES") != "1":
        return False
    url = make_url(str(get_settings().database_url))
    database_name = url.database or ""
    return url.drivername.startswith("postgresql") and database_name.lower().endswith("_test")


@pytest.mark.skipif(
    not _dedicated_test_postgres_configured(),
    reason=(
        "Set REQUIRE_TEST_POSTGRES=1 and point DATABASE_URL at a dedicated "
        "PostgreSQL database whose name ends in '_test' to run the "
        "destructive fresh-migration check."
    ),
)
def test_alembic_upgrade_head_succeeds_from_empty_database():
    database_url = str(get_settings().database_url)
    try:
        verify_fresh_migration(database_url)
    except UnsafeMigrationTargetError as exc:  # pragma: no cover - guard already checked above
        pytest.skip(str(exc))
