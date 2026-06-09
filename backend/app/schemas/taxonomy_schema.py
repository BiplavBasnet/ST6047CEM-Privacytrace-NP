from pydantic import BaseModel, Field


class TaxonomyCategoryRead(BaseModel):
    code: str
    display_name: str
    group: str
    description: str
    detection_methods: list[str] = Field(default_factory=list)
    masking_strategy: str
    fingerprint_strategy: str
    default_severity: str
    internal_only: bool
    customer_notification_allowed: bool
    enabled: bool
    taxonomy_version: str
    known_limitations: list[str] = Field(default_factory=list)


class TaxonomyListResponse(BaseModel):
    taxonomy_version: str
    categories: list[TaxonomyCategoryRead]
    total: int


class TaxonomyVersionResponse(BaseModel):
    taxonomy_version: str
    category_count: int
    enabled_category_count: int
    registry_hash: str


class TaxonomyValidationResponse(BaseModel):
    valid: bool
    taxonomy_version: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
