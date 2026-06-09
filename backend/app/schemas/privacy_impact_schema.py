from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


DataCategory = Literal[
    "simple_personal_data", "contact_data", "behavioural_data", "location_data",
    "financial_data", "authentication_data", "government_identifier", "sensitive_personal_data",
]
HarmCategory = Literal[
    "account_takeover", "financial_fraud", "identity_theft", "phishing", "social_engineering",
    "unwanted_disclosure", "reputational_harm", "discrimination", "loss_of_service",
    "physical_safety", "emotional_distress",
]
CircumstanceCode = Literal[
    "loss_of_confidentiality", "public_exposure", "confirmed_unauthorised_access",
    "confirmed_exfiltration", "loss_of_integrity", "loss_of_availability", "malicious_intent",
    "active_credential_exposure", "long_exposure_duration", "multiple_unauthorised_recipients",
]


class CircumstanceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: CircumstanceCode
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=5, max_length=1000)


class PrivacyHarmInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    harm_category: HarmCategory
    likelihood: int = Field(ge=1, le=4)
    magnitude: int = Field(ge=1, le=4)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    explanation: str = Field(min_length=5, max_length=1000)
    uncertainty: str = Field(min_length=3, max_length=1000)
    recommended_mitigation: str = Field(min_length=3, max_length=1000)


class PrivacyImpactAssessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data_categories: list[DataCategory] = Field(default_factory=list, max_length=20)
    ease_of_identification_score: Literal[0.25, 0.5, 0.75, 1.0] = 0.25
    circumstances: list[CircumstanceInput] = Field(default_factory=list, max_length=20)
    likely_harms: list[PrivacyHarmInput] = Field(default_factory=list, max_length=20)
    affected_subject_count: int | None = Field(default=None, ge=0)
    affected_subject_count_status: Literal["unknown", "estimated", "confirmed"] = "unknown"
    credential_exposure_present: bool = False
    credential_access_impact: Literal["unknown", "limited_service", "customer_account", "financial_account", "privileged_system"] = "unknown"
    credential_active: bool = False
    public_exposure_present: bool = False
    external_access_confirmed: bool = False
    malicious_intent_status: Literal["unknown", "not_indicated", "suspected", "confirmed"] = "unknown"
    encrypted_or_unintelligible: bool = False
    limitations: list[str] = Field(default_factory=list, max_length=20)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)

    @model_validator(mode="after")
    def active_credential_requires_evidence(self):
        if self.credential_active and not any(c.code == "active_credential_exposure" for c in self.circumstances):
            raise ValueError("Active credential status requires an active_credential_exposure factor with evidence.")
        return self


class PrivacyImpactReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["accepted", "changes_required"]
    reason: str = Field(min_length=10, max_length=2000)
    accepted_factor_ids: list[int] = Field(default_factory=list, max_length=200)
    limitations: list[str] | None = Field(default=None, max_length=20)


class PrivacyImpactApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class PrivacyImpactFactorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    factor_type: str
    factor_code: str
    factor_label: str
    score_contribution: float
    evidence_ids: list[str]
    reason: str
    source: str
    method_version: str
    is_system_generated: bool
    review_status: str
    created_at: datetime


class PrivacyHarmRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    harm_id: str
    harm_category: str
    likelihood: int
    magnitude: int
    harm_score: int
    evidence_ids: list[str]
    explanation: str
    uncertainty: str
    recommended_mitigation: str


class PrivacyImpactAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    assessment_id: str
    incident_id: str
    assessment_version: int
    status: str
    data_processing_context_score: float
    ease_of_identification_score: float
    circumstances_score: float
    breach_severity_score: float
    breach_severity_level: str
    harm_likelihood: int
    harm_magnitude: int
    privacy_harm_score: int
    privacy_harm_level: str
    affected_subject_count: int | None
    affected_subject_count_status: str
    credential_exposure_present: bool
    public_exposure_present: bool
    external_access_confirmed: bool
    malicious_intent_status: str
    encrypted_or_unintelligible: bool
    assessment_confidence: str
    limitations: list[str]
    data_categories: list[str]
    taxonomy_version: str | None
    combination_ruleset_version: str | None
    created_by: int | None
    reviewed_by: int | None
    approved_by: int | None
    created_at: datetime
    reviewed_at: datetime | None
    approved_at: datetime | None


class PrivacyImpactResponse(BaseModel):
    assessment: PrivacyImpactAssessmentRead | None
    factors: list[PrivacyImpactFactorRead] = Field(default_factory=list)
    harms: list[PrivacyHarmRead] = Field(default_factory=list)
    history: list[PrivacyImpactAssessmentRead] = Field(default_factory=list)
    methodology_notice: str = "ENISA-inspired assessment support; not a legal determination."
