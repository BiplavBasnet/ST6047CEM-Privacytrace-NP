"""Runtime subset of backend/app/models/enums.py. Detector rules are not copied here."""

import enum


class ExposureLocation(str, enum.Enum):
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
    UNSAFE_EXPOSURE = "unsafe_exposure"
    LEGITIMATE_PROCESSING = "legitimate_processing"
    ALREADY_SAFELY_MASKED = "already_safely_masked"
    UNCERTAIN = "uncertain"
    SUPPRESSED_FALSE_POSITIVE = "suppressed_false_positive"
