"""Shared pytest fixtures for PrivacyTrace-NP backend tests."""

import os
from pathlib import Path

# Dedicated PG test runs treat the process as APP_ENV=test so settings and
# safety gates match the _test database contract (see test_phase1).
if os.getenv("REQUIRE_TEST_POSTGRES") == "1":
    os.environ["APP_ENV"] = "test"
    os.environ.setdefault("PRIVACYTRACE_BOOTSTRAP_TOKEN", "test-bootstrap-token-for-ci")
    # Force off so invite/reset tests are deterministic (local .env often enables SMTP).
    os.environ["SMTP_ENABLED"] = "false"

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import Depends, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401 — register all tables for create_all

from app.database import Base, check_database_connection, engine
from app.db.seed_phase2 import seed_phase2
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import get_current_user
from app.config import get_settings
from app.main import app
from app.models.enums import UserRole
from app.models.user import User
from app.services import key_management_service
from app.tests.crypto_test_utils import write_demo_key_set

get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_settings_cache_between_tests():
    """Avoid stale Settings after monkeypatched env vars are restored."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _require_dedicated_test_postgres() -> None:
    """Fail closed before any fixture performs destructive schema operations."""
    if os.getenv("REQUIRE_TEST_POSTGRES") != "1":
        raise pytest.UsageError(
            "Database-backed tests are disabled. Set REQUIRE_TEST_POSTGRES=1 and "
            "use a dedicated PostgreSQL database whose name ends with '_test'."
        )

    database_url = make_url(str(get_settings().database_url))
    database_name = database_url.database or ""
    if not database_url.drivername.startswith("postgresql") or not database_name.lower().endswith(
        "_test"
    ):
        raise pytest.UsageError(
            "Refusing destructive test setup: DATABASE_URL must target PostgreSQL and "
            "the database name must end with '_test'."
        )


def _reset_test_schema() -> None:
    """Remove migration-owned objects from the dedicated test database.

    Each test module gets its own `migrated_db` (module-scoped) setup/teardown
    reset. A function-scoped fixture from the *previous* module occasionally
    has not fully released its connection's locks yet when the next module's
    reset starts (e.g. a `running_live_monitor` teardown session still
    finishing up), which produces a genuine Postgres deadlock between that
    leftover session and this `DROP SCHEMA ... CASCADE` (see
    docs/LIVE_ALERT_GROUPING.md's testing notes). Since this reset only ever
    runs against the dedicated `_test` database and is destructive by design,
    it is safe to forcibly terminate any other backend connected to it first
    rather than risk a deadlocked/aborted reset.
    """
    _require_dedicated_test_postgres()
    # Dispose our own pool first so `pg_terminate_backend` below only ever
    # targets genuinely foreign/leftover backends, never a connection this
    # same engine still considers "checked in" and might hand out again to
    # the `Base.metadata.create_all` call that immediately follows this reset
    # (terminating one of *those* would surface as a confusing
    # "server closed the connection unexpectedly" from unrelated DDL).
    engine.dispose()
    with engine.begin() as connection:
        # Target backends that have been sitting idle for a while (almost
        # certainly a leftover connection, not one wrapping up a fixture
        # teardown that started a moment ago), *and* any backend that is
        # blocked waiting on a lock right now. The latter case shows up as
        # `state = 'active'` (not idle) in pg_stat_activity even though it is
        # a genuinely orphaned session from a previous test's incompletely
        # torn-down request thread — e.g. a TestClient portal thread still
        # finishing a query against a table this `DROP SCHEMA ... CASCADE`
        # needs an exclusive lock on. Left alone, that backend and this reset
        # deadlock each other (see docs/LIVE_ALERT_GROUPING.md's testing
        # notes). Since this reset only ever runs against the dedicated
        # `_test` database and is destructive by design, it is safe to
        # forcibly terminate any other backend connected to it, blocked or
        # not, rather than risk that deadlock.
        connection.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid() "
                "AND ("
                "  (state IN ('idle', 'idle in transaction') "
                "   AND state_change < now() - interval '1 second')"
                "  OR wait_event_type = 'Lock'"
                ")"
            )
        )
    engine.dispose()
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))


@pytest.fixture(autouse=True)
def phase11_7_crypto_keys(request):
    """Generate ephemeral demo keys only for Phase 11.7 crypto tests."""
    if "test_phase11_7" not in str(request.node.fspath):
        yield
        return

    tmp_path_factory = request.getfixturevalue("tmp_path_factory")
    tmp_path = tmp_path_factory.mktemp("phase11_7_crypto")
    keys = write_demo_key_set(tmp_path / "keys")
    os.environ["JWT_PRIVATE_KEY_PATH"] = str(keys["jwt_private"])
    os.environ["JWT_PUBLIC_KEY_PATH"] = str(keys["jwt_public"])
    os.environ["DATA_KEY_PRIVATE_KEY_PATH"] = str(keys["data_wrap_private"])
    os.environ["DATA_KEY_PUBLIC_KEY_PATH"] = str(keys["data_wrap_public"])
    os.environ["CRYPTO_ENCRYPTION_ENABLED"] = "true"
    get_settings.cache_clear()
    key_management_service.reset_cached_keys()
    yield keys
    get_settings.cache_clear()
    key_management_service.reset_cached_keys()
    for var in (
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH",
        "DATA_KEY_PRIVATE_KEY_PATH",
        "DATA_KEY_PUBLIC_KEY_PATH",
        "CRYPTO_ENCRYPTION_ENABLED",
    ):
        os.environ.pop(var, None)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def autouse_test_admin_auth(request):
    """Authenticate all non-auth tests as the first admin user in the database."""
    if "test_phase11_6_auth_access" in str(request.node.fspath):
        yield
        return

    def override_get_current_user(db: Session = Depends(get_db_session)) -> User:
        from app.services import organisation_access_service as org_access

        user = db.scalar(select(User).where(User.role == UserRole.ADMIN))
        if user is None:
            user = db.scalar(select(User).where(User.role == UserRole.ORGANISATION_ADMIN))
        if user is None:
            raise HTTPException(status_code=401, detail="No admin user in test database")
        if org_access.get_active_membership(db, user) is None:
            org_access.attach_demo_memberships(db, [user])
        return user

    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides.pop(get_current_user, None)


# Migration 001 bootstraps a fresh database by running Base.metadata.create_all
# using the *current* models, so a real `alembic upgrade head` against an empty
# test database double-applies later additive migrations (e.g. 019/020) that
# `op.add_column` fields already present on today's models, causing
# "column already exists" failures. Base.metadata.create_all does not,
# however, create the migration-only triggers from 015/018 that guard the
# integrity ledger and approved breach decisions. Re-create those triggers
# directly (their final, post-018 definitions) so tests can rely on the same
# database-level guarantees production has, without hitting that conflict.
_INTEGRITY_TRIGGER_SQL = """
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

DROP TRIGGER IF EXISTS trg_guard_approved_decision ON breach_decision_records;
CREATE TRIGGER trg_guard_approved_decision BEFORE UPDATE OR DELETE ON breach_decision_records
FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_approved_decision();

CREATE OR REPLACE FUNCTION privacytrace_guard_decision_factor()
RETURNS trigger AS $$
DECLARE parent_status text;
DECLARE parent_id text;
BEGIN
  IF TG_OP = 'DELETE' THEN parent_id := OLD.decision_record_id; ELSE parent_id := NEW.decision_record_id; END IF;
  SELECT status INTO parent_status FROM breach_decision_records WHERE decision_id = parent_id;
  IF parent_status IN ('approved', 'superseded') THEN RAISE EXCEPTION 'approved breach decision factors are immutable'; END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_guard_decision_factor ON breach_decision_factors;
CREATE TRIGGER trg_guard_decision_factor BEFORE INSERT OR UPDATE OR DELETE ON breach_decision_factors
FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_decision_factor();

CREATE OR REPLACE FUNCTION privacytrace_guard_integrity_record()
RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'integrity ledger records are append-only'; END IF;
  IF (to_jsonb(NEW) - ARRAY['verification_status','last_verified_at'])
     <> (to_jsonb(OLD) - ARRAY['verification_status','last_verified_at']) THEN
    RAISE EXCEPTION 'integrity ledger hash fields are immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_guard_integrity_record ON integrity_ledger_records;
CREATE TRIGGER trg_guard_integrity_record BEFORE UPDATE OR DELETE ON integrity_ledger_records
FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_integrity_record();

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

DROP TRIGGER IF EXISTS trg_guard_integrity_head ON integrity_ledger_head;
CREATE TRIGGER trg_guard_integrity_head
BEFORE UPDATE OR DELETE ON integrity_ledger_head
FOR EACH ROW EXECUTE FUNCTION privacytrace_guard_integrity_head();
"""


def _apply_integrity_triggers() -> None:
    with engine.begin() as connection:
        connection.execute(text(_INTEGRITY_TRIGGER_SQL))


@pytest.fixture(scope="module")
def migrated_db():
    """Create all tables once per module (requires PostgreSQL).

    Base.metadata.create_all is used instead of `alembic upgrade head` because
    migration 001 bootstraps tables from today's live models, which makes a
    from-scratch alembic run double-apply later additive `op.add_column`
    migrations. The migration-only integrity/decision guard triggers from
    015/018 are re-applied directly afterwards so their database-level
    invariants are still exercised in tests.
    """
    _require_dedicated_test_postgres()
    if not check_database_connection():
        pytest.skip("Dedicated test PostgreSQL is not running")

    _reset_test_schema()
    Base.metadata.create_all(bind=engine)
    _apply_integrity_triggers()
    yield
    _reset_test_schema()


@pytest.fixture
def seeded_db(migrated_db, request):
    """Phase 2 seed incident. Uses the test db_session when one is requested."""
    if "db_session" in request.fixturenames:
        seed_phase2(request.getfixturevalue("db_session"))
    else:
        seed_phase2()
    yield


def _run_with_lock_timeout(session: Session, fn) -> None:
    """Run `fn(session)` with a short `lock_timeout` and swallow lock waits.

    A test's `db_session` fixture keeps one outer transaction open for the
    whole test (see below) and may itself write to the same
    `live_monitor_runtime_state` row (e.g. a live-monitor event increments
    its counters) via an overridden `get_db_session`. Without a bound, this
    fixture's start/stop against that same row on a *different* connection
    would otherwise wait indefinitely for that row lock to be released at
    the test's teardown — a real deadlock hazard now that Phase J persists
    Live Monitor control state to the database instead of an in-process
    dataclass. Failing fast here is safe: the row is reset on the next
    `start_monitor` call regardless, and test data is truncated between
    tests by `db_session`'s cleanup step.
    """
    try:
        session.execute(text("SET LOCAL lock_timeout = '2s'"))
        fn(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


@pytest.fixture
def running_live_monitor(migrated_db):
    """Start the Live Privacy Monitor for a test using its own DB session.

    `live_monitor_config_service` persists control state to
    `LiveMonitorRuntimeState` (Phase J), so this fixture needs `migrated_db`
    for the table to exist and manages its own short-lived session rather
    than reusing a test's `db_session` (whose transaction may be rolled back
    independently of this fixture's teardown).
    """
    from app.database import SessionLocal
    from app.services import live_monitor_config_service

    _run_with_lock_timeout(
        SessionLocal(),
        lambda session: live_monitor_config_service.start_monitor(
            session,
            mode="http_ingestion",
            source_name="pytest",
            environment="test",
            safe_mode=True,
        ),
    )

    yield

    _run_with_lock_timeout(
        SessionLocal(),
        lambda session: live_monitor_config_service.stop_monitor(session),
    )


@pytest.fixture
def db_session(migrated_db) -> Session:
    """Isolated SQLAlchemy session; truncates all tables after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()

    cleanup = sessionmaker(bind=engine)()
    try:
        # The integrity ledger tables are guarded by append-only/immutable
        # triggers (see migration 018) so tests that legitimately create real
        # ledger records can still be cleaned up between test runs.
        cleanup.execute(text("ALTER TABLE integrity_ledger_records DISABLE TRIGGER trg_guard_integrity_record"))
        cleanup.execute(text("ALTER TABLE integrity_ledger_head DISABLE TRIGGER trg_guard_integrity_head"))
        for table in reversed(Base.metadata.sorted_tables):
            cleanup.execute(table.delete())
        cleanup.execute(text("ALTER TABLE integrity_ledger_records ENABLE TRIGGER trg_guard_integrity_record"))
        cleanup.execute(text("ALTER TABLE integrity_ledger_head ENABLE TRIGGER trg_guard_integrity_head"))
        cleanup.commit()
    finally:
        cleanup.close()
