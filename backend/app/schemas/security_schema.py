from pydantic import BaseModel


class SecurityProfileResponse(BaseModel):
    security_profile: str
    crypto_mode_enabled: bool
    active_key_id: str
    symmetric_algorithm: str
    key_wrap_algorithm: str
    jwt_signing: str
    jwt_asymmetric_enabled: bool
    password_hash_algorithm: str
    nist_csf_functions: list[str]
    nist_sp_documents_referenced: list[str]
    compliance_note: str
    fips_aware_note: str


class SecuritySelfCheckResponse(BaseModel):
    encryption_enabled: bool
    jwt_asymmetric_signing_enabled: bool
    private_keys_not_exposed_by_api: bool
    demo_keys_directory_exists: bool
    demo_key_files_present: dict[str, bool]
    password_hashing_algorithm: str
    audit_encryption_supported: bool
    evidence_encryption_supported: bool
    report_encryption_supported: bool
    llm_report_encryption_supported: bool
    nist_profile_doc_exists: bool
    security_limitations_doc_exists: bool
    gitignore_blocks_private_keys: bool
    security_profile: str
    status: str


class SecurityKeyStatusResponse(BaseModel):
    active_key_id: str
    jwt: dict
    data_wrap: dict
    note: str
