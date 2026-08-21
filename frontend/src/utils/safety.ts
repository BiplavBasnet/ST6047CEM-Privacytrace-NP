export const BLOCKED_SENSITIVE_FALLBACK = "[blocked sensitive value]";
export const BLOCKED_CLAIM_FALLBACK = "[blocked unsafe claim]";

const SENSITIVE_LITERALS = [
  "9841234567",
  "WALLET-NP-88291",
  "pk_test_np_fake_12345",
];

const OVERCLAIM_PHRASES = [
  "proven cause",
  "confirmed blame",
  "guaranteed cause",
  "definitely caused by",
  "developer fault",
  "guaranteed fixed",
  "incident closed automatically",
];

const SENSITIVE_PATTERNS: RegExp[] = [
  /\b9841234567\b/,
  /\bWALLET-NP-88291\b/,
  /\bpk_test_np_fake_12345\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /\bBearer\s+[A-Za-z0-9._-]{8,}\b/i,
  /\bAuthorization:\s*\S+/i,
  /\b(pk|sk)_(live|test)_[A-Za-z0-9]{8,}\b/i,
];

const STRIPPED_KEYS = new Set([
  "raw_value",
  "raw_log",
  "raw_content",
  "file_content",
  "body",
  "payload",
]);

/** Auth/session fields must never be passed through JWT/bearer redaction. */
const UNSANITIZED_STRING_KEYS = new Set([
  "access_token",
  "refresh_token",
  "token_type",
]);

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function sanitizeString(input: string | null | undefined): string {
  if (input == null) return "";
  let result = String(input);

  for (const literal of SENSITIVE_LITERALS) {
    const re = new RegExp(escapeRegex(literal), "gi");
    result = result.replace(re, BLOCKED_SENSITIVE_FALLBACK);
  }

  for (const pattern of SENSITIVE_PATTERNS) {
    result = result.replace(pattern, BLOCKED_SENSITIVE_FALLBACK);
  }

  for (const phrase of OVERCLAIM_PHRASES) {
    const re = new RegExp(escapeRegex(phrase), "gi");
    result = result.replace(re, BLOCKED_CLAIM_FALLBACK);
  }

  return result;
}

export function sanitizeObject<T>(value: T, parentKey?: string): T {
  if (value == null) return value;

  if (typeof value === "string") {
    if (parentKey && STRIPPED_KEYS.has(parentKey)) {
      return "" as T;
    }
    if (parentKey && UNSANITIZED_STRING_KEYS.has(parentKey)) {
      return value;
    }
    return sanitizeString(value) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeObject(item)) as T;
  }

  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (STRIPPED_KEYS.has(key)) {
        continue;
      }
      if (key === "raw_value") {
        continue;
      }
      out[key] = sanitizeObject(child, key);
    }
    return out as T;
  }

  return value;
}

export function pickMaskedDetection(det: Record<string, unknown>): Record<string, unknown> {
  return {
    detection_id: det.detection_id,
    sensitive_type: det.sensitive_type,
    masked_value: sanitizeString(String(det.masked_value ?? "")),
    severity: det.severity,
    evidence_id: det.evidence_id,
    confidence: det.confidence,
  };
}

export function extractMaskedDetectionsFromTrace(
  timeline: unknown[] | undefined,
): Record<string, unknown>[] {
  if (!timeline?.length) return [];
  const detections: Record<string, unknown>[] = [];
  for (const entry of timeline) {
    if (!entry || typeof entry !== "object") continue;
    const item = entry as Record<string, unknown>;
    const list = item.detections;
    if (!Array.isArray(list)) continue;
    for (const det of list) {
      if (!det || typeof det !== "object") continue;
      detections.push(pickMaskedDetection(det as Record<string, unknown>));
    }
  }
  return detections;
}

export function evidenceMetadataOnly(
  record: Record<string, unknown>,
): Record<string, unknown> {
  return {
    evidence_id: record.evidence_id,
    evidence_type: record.evidence_type,
    source_system: sanitizeString(String(record.source_system ?? "")),
    parsing_status: record.parsing_status,
    file_hash: record.file_hash,
    linked_incident_id: record.linked_incident_id,
  };
}
