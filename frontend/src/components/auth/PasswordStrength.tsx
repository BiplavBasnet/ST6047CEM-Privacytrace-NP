import { PASSWORD_RULES, evaluatePassword } from "../../utils/passwordPolicy";

export default function PasswordStrength({ password }: { password: string }) {
  const result = evaluatePassword(password);
  const percent = Math.round((result.passedCount / PASSWORD_RULES.length) * 100);

  return (
    <div className="space-y-2" aria-live="polite">
      <div
        className="h-1.5 overflow-hidden rounded-full bg-slate-200"
        role="meter"
        aria-label="Password strength"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
      >
        <div
          className={`h-full transition-[width] duration-200 ${
            result.isValid ? "bg-accent" : percent >= 50 ? "bg-amber-500" : "bg-slate-400"
          }`}
          style={{ width: `${percent}%` }}
        />
      </div>
      <ul className="space-y-1 text-xs text-ink-muted">
        {PASSWORD_RULES.map((rule) => {
          const ok = result.checks[rule.id];
          return (
            <li key={rule.id} className={ok ? "font-medium text-accent" : undefined}>
              <span aria-hidden="true">{ok ? "✓" : "○"} </span>
              {rule.label}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
