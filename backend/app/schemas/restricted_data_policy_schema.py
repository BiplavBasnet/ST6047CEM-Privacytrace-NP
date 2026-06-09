from typing import Literal

from pydantic import BaseModel, Field


DisclosureChannel = Literal[
    "ordinary_api",
    "restricted_api",
    "customer_notification",
    "external_ai",
    "external_webhook",
    "general_report",
    "search_index",
    "audit",
]


class RestrictedPolicyDecision(BaseModel):
    allowed: bool
    channel: DisclosureChannel
    internal_only: bool
    replacement_code: str | None = None
    reason_code: str


class RestrictedPolicySummary(BaseModel):
    policy_version: str
    external_channels_block_restricted: bool = True
    raw_values_allowed: bool = False
    ordinary_api_replacement: str = "restricted_compliance_information"
    auditable_actions: list[str] = Field(default_factory=list)
