from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_DEV_JWT_SECRET = "privacytrace-np-dev-secret-change-in-production"
_DEV_DATABASE_PASSWORD_MARKER = "privacytrace_dev"
_DEV_SUBJECT_REFERENCE_KEY = "privacytrace-dev-subject-reference-key-change-me"
_DEV_DETECTION_HMAC_KEY = "privacytrace-dev-detection-hmac-key-change-me"
_DEV_BOOTSTRAP_TOKEN = "dev-bootstrap-change-me"
_PRODUCTION_ENVS = {"prod", "production", "staging"}
_DEMO_ENVS = {"dev", "development", "test", "demo"}


class Settings(BaseSettings):
    app_env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = (
        "postgresql://privacytrace:privacytrace_dev@localhost:5432/privacytrace_np"
    )
    service_name: str = "privacytrace-np"
    api_version: str = "0.1.0"
    sample_data_dir: str = "app/sample_data"
    upload_dir: str = "data/uploads"
    encrypted_upload_dir: str = "data/uploads_encrypted"
    max_upload_bytes: int = 5 * 1024 * 1024
    max_request_body_bytes: int = 8 * 1024 * 1024
    integration_event_store_max: int = 1000
    integration_gateway_enabled: bool = True
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_default_model: str = "qwen2.5:7b-instruct"
    ollama_backup_model: str = "llama3.1:8b"
    ollama_timeout_seconds: int = 60
    llm_default_provider: str = "ollama"
    jwt_secret_key: str = _DEV_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_private_key_path: str | None = "keys/demo/jwt_private.pem"
    jwt_public_key_path: str | None = "keys/demo/jwt_public.pem"
    data_key_private_key_path: str | None = "keys/demo/data_wrap_private.pem"
    data_key_public_key_path: str | None = "keys/demo/data_wrap_public.pem"
    crypto_active_key_id: str = "demo-key-001"
    crypto_encryption_enabled: bool = True
    pbkdf2_iterations: int = 600_000
    security_profile: str = "NIST_ALIGNED_DEMO"
    access_token_expire_minutes: int = 480
    ai_assistant_enabled: bool = False
    ai_provider: str = "openai_compatible"
    ai_model: str = ""
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_backup_api_keys: str = ""
    ai_model_candidates: str = ""
    ai_timeout_seconds: int = 30
    ai_max_input_chars: int = 8000
    breach_alerts_enabled: bool = True
    customer_notification_send_enabled: bool = False
    credential_auto_containment_enabled: bool = False
    breach_severity_medium_threshold: float = 2.0
    breach_severity_high_threshold: float = 3.0
    breach_severity_very_high_threshold: float = 4.0
    privacy_harm_medium_threshold: int = 4
    privacy_harm_high_threshold: int = 8
    privacy_harm_critical_threshold: int = 12
    breach_credential_categories: str = "authorization_header,jwt_token,bearer_token,api_key,password,password_hash,credential_username,access_token,session_token,private_key"
    breach_internal_recipients: str = ""
    breach_webhook_destinations: str = ""
    notification_retry_count: int = 3
    notification_retry_delay_seconds: int = 300
    breach_alert_deduplication_window_seconds: int = 3600
    subject_reference_hmac_key: str = _DEV_SUBJECT_REFERENCE_KEY
    breach_webhook_signing_key: str = ""
    integrity_ledger_enabled: bool = True
    counterfactual_analysis_enabled: bool = True
    counterfactual_max_evidence_items: int = 25
    alert_escalation_enabled: bool = True
    alert_default_acknowledgement_minutes: int = 30
    alert_default_containment_minutes: int = 120
    preventive_control_generation_enabled: bool = True
    preventive_control_ai_generation_enabled: bool = False
    opa_validation_enabled: bool = False
    semgrep_validation_enabled: bool = False
    nepal_financial_taxonomy_enabled: bool = True
    nepal_financial_taxonomy_path: str = "app/rules/nepal_financial_data_taxonomy.yaml"
    nepal_financial_taxonomy_version: str = "np-dfs-1.0.0"
    combined_exposure_rules_enabled: bool = True
    combined_exposure_rules_path: str = "app/rules/nepal_exposure_combination_rules.yaml"
    combined_exposure_ruleset_version: str = "np-exposure-1.0.0"
    detection_hmac_key: str = _DEV_DETECTION_HMAC_KEY
    restricted_aml_handling_enabled: bool = True
    detector_preview_enabled: bool = False
    contextual_secret_entropy_enabled: bool = True
    document_metadata_classification_enabled: bool = True
    # Public self-registration (thesis demo default: enabled; disable for production-like deploys).
    self_registration_enabled: bool = True
    invite_only_registration: bool = False
    seed_demo_users: bool = True
    default_registration_role: str = "viewer"
    email_verification_required: bool = False
    company_verification_mode: str = "manual"  # manual | demo
    pan_verification_required: bool = False
    domain_challenge_ttl_minutes: int = 60
    domain_challenge_max_attempts: int = 10
    email_verification_ttl_minutes: int = 60
    email_verification_max_attempts: int = 10
    company_verification_shared_email_domains: str = (
        "gmail.com,googlemail.com,outlook.com,hotmail.com,live.com,yahoo.com,"
        "ymail.com,icloud.com,me.com,aol.com,proton.me,protonmail.com,mail.com"
    )
    # One-time deployment bootstrap secret (never log). Required for /setup and platform operator CLI.
    privacytrace_bootstrap_token: str = ""
    smtp_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@privacytrace.local"
    smtp_tls: bool = True
    smtp_timeout_seconds: int = 15
    frontend_public_url: str = "http://127.0.0.1:5173"
    password_reset_ttl_minutes: int = 60
    password_reset_max_attempts: int = 10
    dns_doh_url: str = "https://cloudflare-dns.com/dns-query"
    dns_lookup_timeout_seconds: int = 8
    dns_lookup_max_retries: int = 2
    # Comma-separated absolute paths allowed for controlled remediation code context / patches.
    remediation_repo_allowlist: str = ""
    remediation_sandbox_root: str = "data/remediation_sandbox"
    remediation_patch_max_files: int = 5
    remediation_patch_max_lines: int = 200
    remediation_max_failed_attempts: int = 3

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_backend_root() -> Path:
    return _BACKEND_ROOT


def _configured_path_exists(path_str: str | None) -> bool:
    if not path_str:
        return False
    path = Path(path_str)
    if not path.is_absolute():
        path = _BACKEND_ROOT / path
    return path.is_file()


def validate_runtime_configuration(settings: Settings | None = None) -> None:
    """Block production-like startup with demo-only secrets.

    Development defaults are intentionally convenient for the thesis demo, but
    they should never be accepted silently when APP_ENV is production-like.
    """

    settings = settings or get_settings()
    app_env = (settings.app_env or "").strip().lower()
    if app_env not in _PRODUCTION_ENVS:
        return

    problems: list[str] = []
    jwt_keys_ready = _configured_path_exists(
        settings.jwt_private_key_path
    ) and _configured_path_exists(settings.jwt_public_key_path)
    if not jwt_keys_ready and settings.jwt_secret_key == _DEV_JWT_SECRET:
        problems.append("JWT signing uses the development fallback secret")
    if _DEV_DATABASE_PASSWORD_MARKER in (settings.database_url or ""):
        problems.append("DATABASE_URL uses the development database password")
    if settings.crypto_encryption_enabled and not (
        _configured_path_exists(settings.data_key_private_key_path)
        and _configured_path_exists(settings.data_key_public_key_path)
    ):
        problems.append("encryption is enabled but data wrapping keys are missing")
    if settings.ai_assistant_enabled and (settings.ai_provider or "").lower() != "mock":
        parsed_ai_url = urlparse(settings.ai_base_url)
        if (
            parsed_ai_url.scheme != "https"
            or not parsed_ai_url.hostname
            or parsed_ai_url.username
            or parsed_ai_url.password
        ):
            problems.append(
                "AI_BASE_URL must be an HTTPS URL without embedded credentials"
            )
    if settings.breach_alerts_enabled and settings.subject_reference_hmac_key == _DEV_SUBJECT_REFERENCE_KEY:
        problems.append("SUBJECT_REFERENCE_HMAC_KEY uses the development fallback secret")
    if (
        settings.nepal_financial_taxonomy_enabled
        and settings.detection_hmac_key == _DEV_DETECTION_HMAC_KEY
    ):
        problems.append("DETECTION_HMAC_KEY uses the development fallback secret")
    if settings.customer_notification_send_enabled:
        problems.append("customer notification delivery has no production provider in this prototype")
    allowed_reg_role = (settings.default_registration_role or "").strip().lower()
    if allowed_reg_role != "viewer":
        problems.append(
            "DEFAULT_REGISTRATION_ROLE must be viewer (least-privilege public registration only)"
        )
    mode = (settings.company_verification_mode or "").strip().lower()
    if mode == "demo":
        problems.append("COMPANY_VERIFICATION_MODE=demo is not allowed in production-like environments")
    elif mode not in {"manual", "demo"}:
        problems.append("COMPANY_VERIFICATION_MODE must be manual or demo")
    if settings.seed_demo_users:
        problems.append("SEED_DEMO_USERS must be false in production-like environments")
    if not (settings.privacytrace_bootstrap_token or "").strip():
        problems.append("PRIVACYTRACE_BOOTSTRAP_TOKEN must be set in production-like environments")
    elif (settings.privacytrace_bootstrap_token or "").strip() == _DEV_BOOTSTRAP_TOKEN:
        problems.append("PRIVACYTRACE_BOOTSTRAP_TOKEN uses the development fallback secret")

    if problems:
        joined = "; ".join(problems)
        raise RuntimeError(
            f"Unsafe production configuration for PrivacyTrace-NP: {joined}. "
            "Set production secrets and key paths through environment variables."
        )


def synthetic_demo_actions_allowed(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return (settings.app_env or "").strip().lower() in _DEMO_ENVS


def resolve_company_verification_mode(settings: Settings | None = None) -> str:
    """Return effective verification mode; demo only when synthetic env allows it."""
    settings = settings or get_settings()
    mode = (settings.company_verification_mode or "manual").strip().lower()
    if mode == "demo":
        if not synthetic_demo_actions_allowed(settings):
            raise RuntimeError(
                "COMPANY_VERIFICATION_MODE=demo requires APP_ENV in {dev,development,test,demo}"
            )
        return "demo"
    return "manual"


def shared_email_domains(settings: Settings | None = None) -> frozenset[str]:
    settings = settings or get_settings()
    raw = settings.company_verification_shared_email_domains or ""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def resolve_sample_data_dir() -> Path:
    settings = get_settings()
    path = Path(settings.sample_data_dir)
    if path.is_absolute():
        return path
    return _BACKEND_ROOT / path


def resolve_upload_dir() -> Path:
    settings = get_settings()
    path = Path(settings.upload_dir)
    if path.is_absolute():
        return path
    return _BACKEND_ROOT / path


def resolve_encrypted_upload_dir() -> Path:
    settings = get_settings()
    path = Path(settings.encrypted_upload_dir)
    if path.is_absolute():
        return path
    return _BACKEND_ROOT / path


def resolve_rules_dir() -> Path:
    return _BACKEND_ROOT / "app" / "rules"


def resolve_evaluation_data_dir() -> Path:
    return _BACKEND_ROOT / "app" / "evaluation_data"

