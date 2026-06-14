from types import SimpleNamespace

from app.models.enums import UserRole
from app.services.permission_service import (
    PERMISSION_RESTRICTED_DETECTION_READ,
    restricted_detection_authorised,
    role_has_permission,
)
from app.services.restricted_data_policy_service import filter_records


def test_ordinary_api_replaces_restricted_aml_record_without_values():
    records, restricted = filter_records(
        [{
            "taxonomy_code": "suspicious_activity_flag",
            "internal_only": True,
            "masked_value": "[category-only]",
            "value_fingerprint": "HMAC-SHA256-V1:synthetic",
        }],
        channel="ordinary_api",
    )
    assert restricted is True
    assert records == [{"taxonomy_code": "restricted_compliance_information", "internal_only": True, "restricted": True}]


def test_external_channels_drop_restricted_aml_records():
    records, restricted = filter_records(
        [{"taxonomy_code": "str_sar_reference", "internal_only": True, "masked_value": "[category-only]"}],
        channel="customer_notification",
    )
    assert restricted is True
    assert records == []


def test_authorised_restricted_api_returns_category_without_masked_value_or_fingerprint():
    records, restricted = filter_records(
        [{"taxonomy_code": "aml_investigation_note", "internal_only": True, "masked_value": "[category-only]", "value_fingerprint": "HMAC-SHA256-V1:synthetic"}],
        channel="restricted_api",
        authorised_restricted_access=True,
    )
    assert restricted is True
    assert records == [{"taxonomy_code": "aml_investigation_note", "internal_only": True}]


def test_restricted_detection_permission_is_not_inherited_from_general_analyst_access():
    assert role_has_permission(UserRole.ADMIN, PERMISSION_RESTRICTED_DETECTION_READ)
    assert not role_has_permission(UserRole.SECURITY_ANALYST, PERMISSION_RESTRICTED_DETECTION_READ)


def test_restricted_detection_uses_membership_role_not_user_role(monkeypatch):
    from app.services import organisation_access_service as org_access

    user = SimpleNamespace(role=UserRole.ADMIN)
    monkeypatch.setattr(
        org_access,
        "require_active_membership",
        lambda _db, _user: SimpleNamespace(role=UserRole.VIEWER),
    )
    assert restricted_detection_authorised(object(), user) is False

    monkeypatch.setattr(
        org_access,
        "require_active_membership",
        lambda _db, _user: SimpleNamespace(role=UserRole.ADMIN),
    )
    user.role = UserRole.VIEWER
    assert restricted_detection_authorised(object(), user) is True

