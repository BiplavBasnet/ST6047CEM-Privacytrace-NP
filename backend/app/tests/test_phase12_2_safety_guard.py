from app.main import app
from app.services import causality_engine
from app.tests.route_test_utils import registered_routes


def test_phase12_2_no_forbidden_overclaim_words_in_rules():
    rules = causality_engine.load_root_cause_rules()
    blob = str(rules).lower()
    for forbidden in (
        "proven cause",
        "confirmed blame",
        "guaranteed cause",
        "definitely caused by",
        "developer fault",
        "guaranteed fixed",
        "confirmed bola",
        "confirmed idor",
        "attacker accessed data",
    ):
        assert forbidden not in blob


def test_existing_endpoints_still_registered():
    paths = [getattr(route, "path", "") for route in registered_routes(app)]
    assert "/health" in paths
    assert "/incidents/{incident_id}/trace" in paths
    assert "/reports/incidents/{incident_id}/generate" in paths
    assert "/reports/incidents/{incident_id}/final-report.pdf" in paths
