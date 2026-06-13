import pytest

from app.services import confidence_service
from app.tests.test_phase10_reports_metrics import _pipeline_to_analyse
from app.tests.test_phase6 import SEED_INCIDENT_ID


def test_confidence_rules_include_time_windows():
    rules = confidence_service.load_confidence_rules()
    windows = rules.get("time_windows") or {}
    assert windows.get("deployment_strong_minutes") == 60
    assert windows.get("stale_evidence_days") == 30


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_trace_includes_summary_and_suggested_actions(client):
    _pipeline_to_analyse(client)
    response = client.get(f"/incidents/{SEED_INCIDENT_ID}/trace")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body.get("trace_summary"), dict)
    assert "safe_conclusion" in body["trace_summary"]
    assert isinstance(body.get("suggested_actions"), list)
    assert body.get("reviewer_warning")
