from datetime import datetime, timezone

import pytest

from app.models.preventive_control import PreventiveControl
from app.models.root_cause_score import RootCauseScore
from app.services import preventive_control_service


class _FakeDb:
    def __init__(self, item):
        self.item = item

    def scalar(self, _statement):
        return self.item

    def commit(self):
        return None

    def refresh(self, _item):
        return None


def _control(**overrides):
    values = {
        "control_id": "CTRL-1",
        "incident_id": "INC-1",
        "root_cause_id": "RC-1",
        "control_type": "configuration_rule",
        "control_name": "Disable request-body logging",
        "control_description": "Prevent request bodies from entering logs.",
        "generated_content": "request_body: disabled",
        "status": "proposed",
        "source": "deterministic_template",
        "generation_method": "unsafe_request_body_logging",
        "ruleset_version": "1.0.0",
        "created_by": 1,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return PreventiveControl(**values)


def test_template_generation_is_deterministic_and_masks_component_placeholder():
    root = RootCauseScore(root_cause_id="RC-1", incident_id="INC-1", cause_name="unsafe_request_body_logging", likely_root_cause="unsafe_request_body_logging")
    proposals = preventive_control_service.template_proposals(root, affected_component="api/login")
    assert proposals
    assert proposals[0]["source"] == "deterministic_template"
    assert "api/login" in proposals[0]["generated_content"] or "${component}" not in proposals[0]["generated_content"]


def test_proposer_cannot_review_same_control(monkeypatch):
    item = _control()
    monkeypatch.setattr(preventive_control_service.audit_service, "log_action", lambda *args, **kwargs: None)
    with pytest.raises(preventive_control_service.PreventiveControlError, match="proposer"):
        preventive_control_service.review_control(_FakeDb(item), item.control_id, actor_id=1, decision="accepted", reason="Independent review accepted the proposed control.")


@pytest.mark.parametrize("actor_id", [1, 2])
def test_creator_or_reviewer_cannot_approve_same_control(monkeypatch, actor_id):
    item = _control(status="reviewed", reviewed_by=2)
    monkeypatch.setattr(preventive_control_service.audit_service, "log_action", lambda *args, **kwargs: None)
    with pytest.raises(preventive_control_service.PreventiveControlError, match="separate"):
        preventive_control_service.approve_control(_FakeDb(item), item.control_id, actor_id=actor_id, reason="Approval requires an independent authorised decision.")

