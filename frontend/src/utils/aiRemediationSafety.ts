const REVIEW_SAFETY_PATTERNS: RegExp[] = [
  /\b98[0-9]{8}\b/,
  /\bWALLET-NP-[0-9A-Z]+\b/i,
  /\bTXN-NP-[0-9A-Z]+(?:-[0-9A-Z]+)*\b/i,
  /\beyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}\b/,
  /\bBearer\s+[^\s,;]+/i,
  /authorization\s*:\s*Bearer\s+[^\s,;]+/i,
  /\b(pk|sk)_(live|test|prod|dev|np)_[A-Za-z0-9_-]+\b/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bpassword\s*=/i,
  /\bpassword[_-]?hash\b/i,
  /\bsession[_-]?token\s*=/i,
];

const FORBIDDEN_REVIEW_PHRASES = [
  "proven cause",
  "confirmed blame",
  "guaranteed fixed",
  "ai fixed the issue",
  "ai solved the incident",
  "issue solved",
  "confirmed fix",
  "confirmed bola",
  "confirmed idor",
  "attacker accessed data",
  "developer caused this",
  "developer fault",
  "incident can be closed automatically",
  "incident closed automatically",
  "send raw logs",
  "provide raw secrets",
];

function toText(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value ?? "");
  }
}

export function findUnsafeAIRemediationText(value: unknown): string[] {
  const text = toText(value);
  const lower = text.toLowerCase();
  const matches: string[] = [];
  REVIEW_SAFETY_PATTERNS.forEach((pattern, index) => {
    if (pattern.test(text)) matches.push(`sensitive_pattern_${index + 1}`);
  });
  FORBIDDEN_REVIEW_PHRASES.forEach((phrase, index) => {
    if (lower.includes(phrase)) matches.push(`unsafe_claim_${index + 1}`);
  });
  return matches;
}

export function isAIRemediationReviewTextSafe(value: unknown): boolean {
  return findUnsafeAIRemediationText(value).length === 0;
}
