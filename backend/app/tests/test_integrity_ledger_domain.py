from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.integrity_ledger_service import (
    INTEGRITY_SCHEMA_VERSION,
    calculate_record_hash,
    canonical_json,
    sha256_text,
    verify_chain,
)


def _record(sequence, previous_hash, record_id, content):
    created_at = datetime(2026, 7, 17, 6, sequence, tzinfo=timezone.utc)
    content_hash = sha256_text(canonical_json(content))
    record_hash = calculate_record_hash(
        record_type="synthetic",
        record_id=record_id,
        content_hash=content_hash,
        sequence_number=sequence,
        previous_record_hash=previous_hash,
        created_at=created_at,
        schema_version=INTEGRITY_SCHEMA_VERSION,
    )
    return SimpleNamespace(
        sequence_number=sequence,
        record_type="synthetic",
        record_id=record_id,
        content_hash=content_hash,
        previous_record_hash=previous_hash,
        record_hash=record_hash,
        created_at=created_at,
        integrity_schema_version=INTEGRITY_SCHEMA_VERSION,
    )


def _chain():
    first = _record(1, None, "R-1", {"value": "one"})
    second = _record(2, first.record_hash, "R-2", {"value": "two"})
    third = _record(3, second.record_hash, "R-3", {"value": "three"})
    head = SimpleNamespace(
        last_sequence_number=3,
        last_record_hash=third.record_hash,
    )
    return [first, second, third], head


def test_canonical_json_is_deterministic_and_chain_matches_locked_head():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    records, head = _chain()
    summary = verify_chain(records, expected_head=head, require_head=True)
    assert summary.chain_valid
    assert summary.records_checked == 3


def test_content_modification_is_detected_without_exposing_content():
    records, head = _chain()
    summary = verify_chain(
        records,
        lambda record: (
            {"value": "changed"}
            if record.record_id == "R-2"
            else {"value": {"R-1": "one", "R-3": "three"}[record.record_id]}
        ),
        expected_head=head,
        require_head=True,
    )
    assert not summary.chain_valid
    assert summary.content_mismatch_count == 1
    assert summary.first_invalid_sequence == 2


def test_middle_and_tail_deletion_are_detected_against_head():
    records, head = _chain()
    middle = verify_chain(
        [records[0], records[2]], expected_head=head, require_head=True
    )
    tail = verify_chain(records[:-1], expected_head=head, require_head=True)
    assert not middle.chain_valid
    assert middle.missing_sequence_count >= 1
    assert not tail.chain_valid
    assert tail.missing_sequence_count == 1


def test_sequence_rewrite_breaks_record_hash():
    records, head = _chain()
    records[0].sequence_number, records[1].sequence_number = 2, 1
    summary = verify_chain(records, expected_head=head, require_head=True)
    assert not summary.chain_valid
    assert summary.invalid_link_count > 0


import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import func, select, text

from app.models.integrity_ledger import IntegrityLedgerHead
from app.models.privacy_alert import PrivacyAlert
from app.services.integrity_ledger_service import (
    IntegrityError,
    IntegrityExportBlockedError,
    append_record,
    assert_export_allowed,
    verify_ledger,
)


def test_missing_head_fails_verification_even_for_empty_chain():
    summary = verify_chain([], expected_head=None, require_head=True)
    assert summary.chain_valid is False
    assert summary.invalid_link_count == 1


def test_latest_migration_is_the_single_alembic_head():
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)
    assert script.get_current_head() == "037_connector_client_event_id"


@pytest.mark.critical_db
def test_missing_head_with_history_blocks_append(db_session):
    append_record(
        db_session,
        record_type="synthetic",
        record_id="R-HEAD-1",
        canonical_content={"value": "one"},
        scope_type="incident",
        scope_id="INC-HEAD",
    )
    head = db_session.scalar(select(IntegrityLedgerHead).where(IntegrityLedgerHead.id == 1))
    # The migration 018 trigger blocks deleting the ledger head at the database
    # level; disable it only to simulate the missing-head scenario this test
    # exercises, then restore it immediately.
    db_session.execute(text("ALTER TABLE integrity_ledger_head DISABLE TRIGGER trg_guard_integrity_head"))
    db_session.delete(head)
    db_session.flush()
    db_session.execute(text("ALTER TABLE integrity_ledger_head ENABLE TRIGGER trg_guard_integrity_head"))

    with pytest.raises(IntegrityError, match="head is missing"):
        append_record(
            db_session,
            record_type="synthetic",
            record_id="R-HEAD-2",
            canonical_content={"value": "two"},
            scope_type="incident",
            scope_id="INC-HEAD",
        )


@pytest.mark.critical_db
def test_failed_verification_deduplicates_alert_and_blocks_export(db_session):
    record = append_record(
        db_session,
        record_type="synthetic",
        record_id="R-TAMPER",
        canonical_content={"value": "original"},
        scope_type="incident",
        scope_id="INC-TAMPER",
    )
    db_session.flush()
    # The migration 015 trigger makes record_hash immutable; disable it only to
    # simulate a tampered record for this test, then restore it immediately.
    db_session.execute(text("ALTER TABLE integrity_ledger_records DISABLE TRIGGER trg_guard_integrity_record"))
    record.record_hash = "sha256:" + ("0" * 64)
    db_session.flush()
    db_session.execute(text("ALTER TABLE integrity_ledger_records ENABLE TRIGGER trg_guard_integrity_record"))

    first = verify_ledger(
        db_session, scope_type="incident", scope_id="INC-TAMPER", executed_by=None
    )
    second = verify_ledger(
        db_session, scope_type="incident", scope_id="INC-TAMPER", executed_by=None
    )

    assert first.chain_valid is False
    assert first.records_checked == 1
    assert first.scope_records_checked == 1
    assert first.failure_fingerprint == second.failure_fingerprint
    assert first.integrity_alert_id == second.integrity_alert_id
    assert db_session.scalar(
        select(func.count(PrivacyAlert.id)).where(
            PrivacyAlert.source_type == "integrity_verification"
        )
    ) == 1
    with pytest.raises(IntegrityExportBlockedError, match="Export blocked"):
        assert_export_allowed(
            db_session,
            scope_type="incident",
            scope_id="INC-TAMPER",
            executed_by=None,
        )
