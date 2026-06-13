import json

import pytest

from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID
from app.tests.test_phase10_reports_metrics import _pipeline_to_analyse


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_evidence_graph_endpoint_returns_nodes_edges(client):
    _pipeline_to_analyse(client)
    response = client.get(f"/incidents/{SEED_INCIDENT_ID}/evidence-graph")
    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == SEED_INCIDENT_ID
    assert isinstance(body["nodes"], list)
    assert isinstance(body["edges"], list)
    assert "likely causes" in body["disclaimer"].lower()
    node_ids = {n["id"] for n in body["nodes"]}
    for edge in body["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
    assert "confirmed blame" not in body["disclaimer"].lower()


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_evidence_graph_contains_no_raw_sensitive_values(client):
    _pipeline_to_analyse(client)
    response = client.get(f"/incidents/{SEED_INCIDENT_ID}/evidence-graph")
    blob = json.dumps(response.json())
    for raw in RAW_LEAK_SUBSTRINGS:
        assert raw not in blob
