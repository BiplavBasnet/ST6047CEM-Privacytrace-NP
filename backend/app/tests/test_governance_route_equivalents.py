from app.routers.alert_operations_router import router as alert_router
from app.routers.exposure_profile_router import router as exposure_router
from app.routers.preventive_control_router import router as preventive_router
from app.routers.sensitive_taxonomy_router import router as taxonomy_router


def _operations(router):
    return {(method, route.path) for route in router.routes for method in route.methods}


def test_exact_alert_and_preventive_route_equivalents_exist():
    operations = _operations(alert_router) | _operations(preventive_router)
    assert {
        ("GET", "/alerts/metrics"),
        ("GET", "/alerts/overdue"),
        ("POST", "/alerts/{alert_id}/assign"),
        ("POST", "/alerts/{alert_id}/suppress"),
        ("POST", "/alerts/{alert_id}/unsuppress"),
        ("POST", "/alerts/{alert_id}/escalate"),
        ("POST", "/alerts/{alert_id}/reopen"),
        ("POST", "/preventive-controls/{control_id}/mark-implemented"),
    }.issubset(operations)


def test_taxonomy_static_version_route_precedes_dynamic_code_route():
    paths = [route.path for route in taxonomy_router.routes]
    assert paths.index("/sensitive-data-taxonomy/version") < paths.index("/sensitive-data-taxonomy/{taxonomy_code}")
    assert {
        ("GET", "/sensitive-data-taxonomy"),
        ("GET", "/sensitive-data-taxonomy/version"),
        ("GET", "/sensitive-data-taxonomy/{taxonomy_code}"),
        ("POST", "/sensitive-data-taxonomy/validate"),
        ("GET", "/incidents/{incident_id}/restricted-detections"),
    }.issubset(_operations(taxonomy_router))


def test_all_exposure_profile_routes_exist():
    assert {
        ("GET", "/incidents/{incident_id}/exposure-profiles"),
        ("POST", "/incidents/{incident_id}/exposure-profiles/recalculate"),
        ("GET", "/exposure-profiles/{profile_id}"),
        ("POST", "/exposure-profiles/{profile_id}/review"),
        ("POST", "/exposure-profiles/{profile_id}/reject"),
        ("GET", "/exposure-combination-rules"),
    }.issubset(_operations(exposure_router))
