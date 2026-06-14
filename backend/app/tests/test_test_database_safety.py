"""Regression tests for the destructive PostgreSQL fixture guard."""

import pytest

from app.config import get_settings
from app.tests.conftest import _require_dedicated_test_postgres

_NON_TEST_DATABASES = (
    "privacytrace",
    "privacytrace_dev",
    "privacytrace_prod",
    "customer_database",
    "privacytrace_np",
)
_APPROVED_TEST_DATABASES = (
    "privacytrace_np_test",
    "privacytrace_regression_test",
)


def test_destructive_fixture_requires_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("REQUIRE_TEST_POSTGRES", raising=False)

    with pytest.raises(pytest.UsageError, match="REQUIRE_TEST_POSTGRES=1"):
        _require_dedicated_test_postgres()


@pytest.mark.parametrize("db_name", _NON_TEST_DATABASES)
def test_destructive_fixture_rejects_non_test_database(monkeypatch, db_name):
    monkeypatch.setenv("REQUIRE_TEST_POSTGRES", "1")
    monkeypatch.setenv(
        "DATABASE_URL",
        f"postgresql://privacytrace:privacytrace@127.0.0.1/{db_name}",
    )
    get_settings.cache_clear()
    try:
        with pytest.raises(pytest.UsageError, match="must end with '_test'"):
            _require_dedicated_test_postgres()
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize("db_name", _APPROVED_TEST_DATABASES)
def test_destructive_fixture_allows_dedicated_test_database(monkeypatch, db_name):
    monkeypatch.setenv("REQUIRE_TEST_POSTGRES", "1")
    monkeypatch.setenv(
        "DATABASE_URL",
        f"postgresql://privacytrace:privacytrace@127.0.0.1/{db_name}",
    )
    get_settings.cache_clear()
    try:
        _require_dedicated_test_postgres()
    finally:
        get_settings.cache_clear()
