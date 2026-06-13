from app.services import causality_engine


def test_access_control_cause_uses_safe_wording():
    rules = causality_engine.load_root_cause_rules()
    item = next(c for c in rules["causes"] if c["likely_root_cause"] == "access_control_failure")
    assert item["display_name"] == "Possible access-control contribution"
    blob = (item.get("recommended_fix") or "").lower()
    assert "human analyst" in blob
    assert "confirmed bola" not in blob
    assert "confirmed idor" not in blob


def test_access_control_has_negative_or_contradiction_signals():
    rules = causality_engine.load_root_cause_rules()
    item = next(c for c in rules["causes"] if c["likely_root_cause"] == "access_control_failure")
    assert item.get("negative_signals")
    assert item.get("contradiction_signals")
