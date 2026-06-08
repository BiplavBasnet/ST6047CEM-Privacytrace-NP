import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ORGANISATION_ADMIN = "organisation_admin"
    PLATFORM_ADMIN = "platform_admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    DEVSECOPS_ENGINEER = "devsecops_engineer"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class OrganisationStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class MembershipStatus(str, enum.Enum):
    INVITED = "invited"
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class InvitationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class OrganisationVerificationStatus(str, enum.Enum):
    UNVERIFIED = "unverified"
    PENDING_VERIFICATION = "pending_verification"
    PARTIALLY_VERIFIED = "partially_verified"
    VERIFIED = "verified"
    MANUAL_REVIEW = "manual_review"
    REJECTED = "rejected"
    SUSPENDED = "suspended"


class DomainChallengeStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"
    SUPERSEDED = "superseded"


class ManualReviewStatus(str, enum.Enum):
    OPEN = "open"
    APPROVED = "approved"
    REJECTED = "rejected"
    MORE_INFO = "more_info"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    UNDER_REVIEW = "under_review"
    CONFIRMED_INCIDENT = "confirmed_incident"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    FIXED = "fixed"
    CLOSED = "closed"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceType(str, enum.Enum):
    API_LOG = "api_log"
    RUNTIME_LOG = "runtime_log"
    SEMGREP_REPORT = "semgrep_report"
    GITLEAKS_REPORT = "gitleaks_report"
    TRIVY_REPORT = "trivy_report"
    DEPLOYMENT_LOG = "deployment_log"
    ACCESS_EVENT = "access_event"
    SIEM_ALERT = "siem_alert"
    SCANNER_BRIDGE_IMPORT = "scanner_bridge_import"
    FIXED_LOG = "fixed_log"
    FIXED_SCAN = "fixed_scan"


class ParsingStatus(str, enum.Enum):
    PENDING = "pending"
    PARSING = "parsing"
    PARSED = "parsed"
    FAILED = "failed"


class VerificationStatus(str, enum.Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class ReviewDecisionType(str, enum.Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    REJECTED_FALSE_POSITIVE = "rejected_false_positive"
    INCONCLUSIVE = "inconclusive"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"
    ESCALATED = "escalated"


class ExposureLocation(str, enum.Enum):
    """Where a sensitive-looking candidate value was physically observed.

    Distinguishes controlled/expected processing channels (e.g. an
    Authorization header being parsed) from channels that make raw values
    durable and widely readable (application logs, exports, webhooks, AI
    prompt context). Used by `sensitive_exposure_policy_service` to decide
    whether presence constitutes unsafe exposure.
    """

    APPLICATION_LOG = "application_log"
    QUERY_STRING = "query_string"
    REQUEST_HEADER_LOG = "request_header_log"
    REQUEST_HEADER_PROCESSING = "request_header_processing"
    REQUEST_BODY = "request_body"
    RESPONSE_BODY = "response_body"
    ERROR_MESSAGE = "error_message"
    DATABASE_FIELD = "database_field"
    THIRD_PARTY_LOG = "third_party_log"
    CACHE_ENTRY = "cache_entry"
    FILE_EXPORT = "file_export"
    WEBHOOK_PAYLOAD = "webhook_payload"
    AI_PROMPT_CONTEXT = "ai_prompt_context"
    UNKNOWN = "unknown"


class ExposureDecision(str, enum.Enum):
    """Policy outcome for a validated sensitive-data candidate.

    A detector match is only "presence"; this decision is the engine's
    explainable judgement on whether that presence is an unsafe exposure,
    expected processing, already mitigated, or too weak/ambiguous to act on.
    """

    UNSAFE_EXPOSURE = "unsafe_exposure"
    LEGITIMATE_PROCESSING = "legitimate_processing"
    ALREADY_SAFELY_MASKED = "already_safely_masked"
    UNCERTAIN = "uncertain"
    SUPPRESSED_FALSE_POSITIVE = "suppressed_false_positive"


class SensitivityLevelEnum(str, enum.Enum):
    """Database-facing mirror of `sensitive_data_taxonomy_service.SensitivityLevel`.

    Kept as a separate DB-oriented enum (lower-case values, consistent with
    the rest of this module) rather than reusing the taxonomy service's
    upper-case string enum directly in model columns.
    """

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
