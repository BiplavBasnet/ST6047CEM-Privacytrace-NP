import json

import pytest

from app.tests.test_phase10_reports_metrics import RAW_LEAK_SUBSTRINGS, _full_workflow
from app.tests.test_phase6 import SEED_INCIDENT_ID


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_report_json_includes_traceability_sections(client):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json")
    assert response.status_code == 200
    body = response.json()
    assert "explainability_summary" in body
    assert "evidence_graph_summary" in body
    assert "safe_conclusion" in body


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_report_json_has_no_raw_sensitive_values(client):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json")
    blob = json.dumps(response.json())
    for raw in RAW_LEAK_SUBSTRINGS:
        assert raw not in blob
