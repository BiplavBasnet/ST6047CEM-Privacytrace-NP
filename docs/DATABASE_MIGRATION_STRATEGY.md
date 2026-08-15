# Database Migration Strategy

PrivacyTrace-NP uses Alembic for schema management, but revision `001_initial`
does not build the schema the way a typical from-scratch Alembic history
does. This document explains why, what that means for a genuinely empty
database versus an existing developer database, and what to do in each case.

## Why revision 001 is not a normal "initial" migration

```1:29:backend/alembic/versions/001_initial_schema.py
def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)
```

`001_initial` calls `Base.metadata.create_all()` — it builds tables from
**today's live SQLAlchemy models**, not from a frozen snapshot of what the
schema looked like when revision 001 was written. Every model file merged
since (breach response, universal integration, unified exposure engine,
Nepal taxonomy, ...) is included the moment `001_initial` runs, because
`import app.models` inside that file registers all current model classes
against `Base.metadata` before `create_all()` walks it.

This was a pragmatic choice for a fast-moving academic prototype (one
"initial" revision instead of hand-writing 20+ incremental `create_table`
scripts that must be kept byte-for-byte in sync with the models), but it
creates a real hazard: revisions 002 onward were written assuming they run
against a database that only has the *original* 001-era tables/columns and
therefore use plain, unguarded `op.add_column` / `op.create_table` calls.
Run the full history from empty today, and those later revisions try to
add a column that revision 001 already created from the current model —
Postgres raises `column "..." already exists` and the migration aborts.

### The `env.py` mitigation for revision 001 itself

`backend/alembic/env.py` works around the *table-existence* half of this
problem for a genuinely empty database:

```19:70:backend/alembic/env.py
# Revision 001 uses the live Base.metadata. On a genuinely empty database,
# temporarily present only its historical table subset so later revisions can
# create their own tables in order.
_POST_INITIAL_TABLES = frozenset({...})


def _is_unversioned_empty_database(connection) -> bool:
    database = inspect(connection)
    return not database.has_table("alembic_version") and not database.get_table_names()


def _initial_revision_metadata() -> MetaData:
    metadata = MetaData()
    for table in target_metadata.tables.values():
        if table.name not in _POST_INITIAL_TABLES:
            table.to_metadata(metadata)
    return metadata
```

When `run_migrations_online()` detects a database with no tables and no
`alembic_version` row, it temporarily swaps `Base.metadata` for a copy that
excludes every table that a *later* revision is responsible for creating
(`_POST_INITIAL_TABLES`), so `001_initial` only creates the tables that
genuinely predate revision 002+. Later revisions' own `op.create_table`
calls then create the rest, in order, exactly once.

This mitigation only covers **whole tables that don't exist yet**, and it
only works *because* `_POST_INITIAL_TABLES` is kept in sync by hand. It
does **not** protect a later `op.add_column` targeting one of the tables
`001_initial` *is* allowed to create in full — that table gets every
column today's model defines, including ones a later revision's
`op.add_column` also wants to add.

### The two `op.add_column` patterns you'll find in `alembic/versions/`

**Unguarded (the older, riskier pattern)** — revisions 018 and 020:

```18:27:backend/alembic/versions/018_stabilisation_hardening.py
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
```

```18:27:backend/alembic/versions/020_integrity_verification_mode.py
def upgrade() -> None:
    op.add_column(
        "integrity_verification_runs",
        sa.Column(
            "verification_mode",
            sa.String(64),
            server_default="global_with_scope_membership",
            nullable=False,
        ),
    )
```

These two currently work from empty **only because** their target tables
(`privacy_impact_factors`, created by `014_privacy_harm_breach_response`;
`integrity_verification_runs`, created by `015_decision_provenance_
integrity`) are both listed in `env.py`'s `_POST_INITIAL_TABLES`. That
keeps `001_initial` from creating them, so they come into existence later,
via 014's/015's own `op.create_table` with the historical (pre-018/020)
column set — leaving `method_version` / `verification_mode` genuinely
absent when 018/020 run, so the unguarded `op.add_column` succeeds.

**This is fragile, not safe-by-construction.** It depends entirely on
`_POST_INITIAL_TABLES` staying perfectly in sync with which tables have a
later unguarded `add_column`. If a future contributor:

- adds a new unguarded `op.add_column` to a table and forgets it must stay
  in (or be added to) `_POST_INITIAL_TABLES`, or
- removes a table from `_POST_INITIAL_TABLES` (e.g. while refactoring
  `env.py`) without checking every migration that later `add_column`s onto
  it,

...`001_initial` silently starts creating that table with the new column
already present, and the old unguarded `op.add_column` migration breaks
with "column already exists" the next time someone runs `alembic upgrade
head` from empty. Nothing catches this except actually testing the
from-scratch path (see `scripts/verify_fresh_migration.py` below) — the
existing-database upgrade path continues to work fine, since it never hits
`001_initial`'s `create_all` at all.

**Guarded (the pattern to follow for all new migrations)** — revision 021:

```33:41:backend/alembic/versions/021_unified_exposure_engine.py
def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # --- Phase I: real alert grouping on privacy_alerts ---
    alert_columns = {column["name"] for column in inspector.get_columns("privacy_alerts")}
    if "alert_group_key" not in alert_columns:
        op.add_column("privacy_alerts", sa.Column("alert_group_key", sa.String(80), nullable=True))
```

021 inspects the live database before every `add_column`/`create_table`
call and only issues the DDL if the column/table is not already there. This
is safe to run in **both** directions: against a real database upgrading
sequentially from 020, and against a from-scratch database that got the
column for free from `001_initial`'s `create_all`. Migration 012 uses the
same inspector-guard idiom and was the first revision to adopt it; 021
follows it explicitly (see its module docstring).

**Rule for all future migrations:** always guard `op.add_column` /
`op.create_table` with an `inspector.get_columns(...)` /
`inspector.get_table_names()` check, exactly like 021. Never assume the
target column/table is absent just because the revision "logically" comes
after the one that first introduced the underlying feature — revision 001
may have already created it.

## What this means for you

### Fresh install (empty PostgreSQL database)

```bash
cd backend
# DATABASE_URL points at a brand-new, empty PostgreSQL database
alembic upgrade head
```

This is the **supported, tested** path (see
`app/tests/test_fresh_migration.py`). `001_initial` creates the pre-021
table subset from today's models (via the `env.py` mitigation above); 002
through 017 create their own tables (each is a table `_POST_INITIAL_TABLES`
excludes from 001, so it does not yet exist when its own revision runs);
018's and 020's unguarded `add_column` calls succeed today because their
two target tables are correctly listed in `_POST_INITIAL_TABLES`; 019 adds
its own columns to a table it also excludes; 021 and 022 use the guarded,
from-scratch-safe pattern and work regardless of `_POST_INITIAL_TABLES`'s
contents.

> **Caveat — this balance is hand-maintained, not structurally enforced.**
> `_POST_INITIAL_TABLES` must stay in sync with every unguarded
> `op.add_column`/`op.create_table` call added after it. Nothing in the
> codebase mechanically verifies that invariant except actually running the
> fresh-install path. **Always run `alembic upgrade head` against a scratch
> database (see `scripts/verify_fresh_migration.py` below) before merging
> any new migration** — and prefer the guarded, inspector-based pattern
> from revision 021 for all new migrations so this caveat stops applying to
> new work altogether.

### Existing developer database (already has some `alembic_version` row)

```bash
cd backend
alembic current      # see which revision you're on
alembic upgrade head # apply only the revisions after your current one
```

This is the normal Alembic path and is unaffected by the `env.py`
from-scratch special-case (`_is_unversioned_empty_database` only triggers
when there is **no** `alembic_version` table and **no** tables at all).
Each revision after your current one runs exactly once, in order, exactly
as written.

### We do not destroy your database automatically

Nothing in this codebase runs `alembic downgrade`, `DROP SCHEMA`, or
`Base.metadata.drop_all()` outside of:

- the test suite's own dedicated `_test`-suffixed PostgreSQL database
  (`backend/app/tests/conftest.py`'s `_reset_test_schema`, which refuses to
  run at all — see `_require_dedicated_test_postgres` — unless
  `REQUIRE_TEST_POSTGRES=1` **and** the target database name ends in
  `_test`), and
- `001_initial.downgrade()` / `018_stabilisation_hardening.downgrade()`
  (the latter deliberately raises `RuntimeError` and refuses to downgrade
  at all, "to preserve integrity and alert history").

`alembic upgrade head` never drops or truncates existing data. If you are
unsure which database `DATABASE_URL` points at, run `alembic current`
first — it only reads the `alembic_version` table.

## Verifying the fresh-install path stays healthy

`backend/scripts/verify_fresh_migration.py` (see also the pytest wrapper in
`backend/app/tests/test_fresh_migration.py`) runs `alembic upgrade head`
against a completely empty, dedicated PostgreSQL database and asserts it
succeeds without manual intervention. Both are skipped by default and only
run when explicitly opted in:

```bash
cd backend
$env:REQUIRE_TEST_POSTGRES = "1"
$env:DATABASE_URL = "postgresql://user:pass@localhost:5432/privacytrace_fresh_test"
python scripts/verify_fresh_migration.py
# or, as a pytest:
python -m pytest app/tests/test_fresh_migration.py -v
```

The same `_require_dedicated_test_postgres`-style guard is used here too
(the database name must end in `_test`): this script issues
`DROP SCHEMA public CASCADE` before running migrations, so it must never be
pointed at a real developer or production database.

## Summary

| Scenario | Command | Safe? |
| --- | --- | --- |
| Empty PostgreSQL, first-time setup | `alembic upgrade head` | Yes — tested path, see caveat above |
| Existing dev database on an older revision | `alembic upgrade head` | Yes — normal incremental Alembic upgrade |
| Verifying a new migration doesn't break the fresh-install path | `python scripts/verify_fresh_migration.py` against a scratch `_test` database | Yes — required before merging any new revision |
| Anything that downgrades below 018, or drops schema on a non-`_test` database | — | **Never do this automatically; there is no supported tooling for it** |
