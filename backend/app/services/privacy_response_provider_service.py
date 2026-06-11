from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from app.config import synthetic_demo_actions_allowed


class ProviderDisabledError(RuntimeError):
    pass


@dataclass(frozen=True)
class DirectoryResolution:
    active: bool
    locale: str


@dataclass(frozen=True)
class ProviderResult:
    succeeded: bool
    reference: str | None
    summary: str
    error_category: str | None = None


class CustomerDirectoryAdapter(Protocol):
    def resolve_subject(self, lookup_token: str, subject_reference: str) -> DirectoryResolution: ...
    def get_delivery_destination(self, subject_reference: str, channel: str) -> str: ...


class ContainmentProvider(Protocol):
    def execute(self, action_type: str, subject_reference: str | None, credential_type: str | None) -> ProviderResult: ...


class InApplicationAlertProvider(Protocol):
    def publish(self, *, alert_reference: str, severity: str, summary: str) -> ProviderResult: ...


class NotificationProvider(Protocol):
    def send(self, *, destination: str, message: str, idempotency_key: str) -> ProviderResult: ...


class EmailNotificationProvider(NotificationProvider, Protocol):
    pass


class WebhookNotificationProvider(NotificationProvider, Protocol):
    def sign(self, payload: bytes) -> str: ...


class SyntheticCustomerDirectoryAdapter:
    def __init__(self) -> None:
        self._destinations: dict[str, dict[str, str]] = {}

    def resolve_subject(self, lookup_token: str, subject_reference: str) -> DirectoryResolution:
        if not synthetic_demo_actions_allowed():
            raise ProviderDisabledError("Customer directory integration is disabled.")
        suffix = hashlib.sha256(lookup_token.encode("utf-8")).hexdigest()[:12]
        self._destinations[subject_reference] = {
            "email": f"synthetic-{suffix}@example.invalid",
            "webhook": f"synthetic-webhook:{suffix}",
        }
        return DirectoryResolution(active=True, locale="en")

    def get_delivery_destination(self, subject_reference: str, channel: str) -> str:
        try:
            return self._destinations[subject_reference][channel]
        except KeyError as exc:
            raise ProviderDisabledError("No approved delivery destination is available.") from exc


class DisabledCustomerDirectoryAdapter:
    def resolve_subject(self, lookup_token: str, subject_reference: str) -> DirectoryResolution:
        raise ProviderDisabledError("Customer directory integration is disabled.")

    def get_delivery_destination(self, subject_reference: str, channel: str) -> str:
        raise ProviderDisabledError("Customer directory integration is disabled.")


class DisabledContainmentProvider:
    def execute(self, action_type: str, subject_reference: str | None, credential_type: str | None) -> ProviderResult:
        return ProviderResult(False, None, "Manual execution is required; no production credential provider is configured.", "provider_disabled")


class DisabledNotificationProvider:
    def send(self, *, destination: str, message: str, idempotency_key: str) -> ProviderResult:
        raise ProviderDisabledError("External customer delivery is disabled.")


class DisabledEmailNotificationProvider(DisabledNotificationProvider):
    pass


class DisabledWebhookNotificationProvider(DisabledNotificationProvider):
    def __init__(self, signing_key: str = "") -> None:
        self.signing_key = signing_key

    def sign(self, payload: bytes) -> str:
        return sign_webhook_payload(payload, self.signing_key)


_synthetic_directory = SyntheticCustomerDirectoryAdapter()


def get_customer_directory_adapter() -> CustomerDirectoryAdapter:
    return _synthetic_directory if synthetic_demo_actions_allowed() else DisabledCustomerDirectoryAdapter()


def sign_webhook_payload(payload: bytes, signing_key: str) -> str:
    if not signing_key:
        raise ProviderDisabledError("Webhook signing key is not configured.")
    return "sha256=" + hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
