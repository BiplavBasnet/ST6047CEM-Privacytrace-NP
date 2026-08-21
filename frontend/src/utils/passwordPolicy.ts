/** Mirrors backend app.schemas.password_policy rules. */

export const PASSWORD_MIN_LENGTH = 10;

export const PASSWORD_RULES = [
  { id: "length", label: `At least ${PASSWORD_MIN_LENGTH} characters` },
  { id: "lower", label: "Contains a lowercase letter" },
  { id: "upper", label: "Contains an uppercase letter" },
  { id: "digit", label: "Contains a digit" },
  { id: "symbol", label: "Contains a symbol" },
] as const;

export type PasswordRuleId = (typeof PASSWORD_RULES)[number]["id"];

export function evaluatePassword(password: string): {
  checks: Record<PasswordRuleId, boolean>;
  passedCount: number;
  isValid: boolean;
} {
  const checks: Record<PasswordRuleId, boolean> = {
    length: password.length >= PASSWORD_MIN_LENGTH,
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    digit: /\d/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
  };
  const passedCount = Object.values(checks).filter(Boolean).length;
  return {
    checks,
    passedCount,
    isValid: passedCount === PASSWORD_RULES.length,
  };
}
