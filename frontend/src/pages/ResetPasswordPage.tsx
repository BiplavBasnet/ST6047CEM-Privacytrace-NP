import { FormEvent, useId, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { passwordResetApi } from "../api/authClient";
import { ApiError } from "../api/client";
import AuthLayout from "../components/auth/AuthLayout";
import PasswordStrength from "../components/auth/PasswordStrength";
import { evaluatePassword } from "../utils/passwordPolicy";

export default function ResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const tokenFromQuery = params.get("token") || "";
  const [email, setEmail] = useState("");
  const [token, setToken] = useState(tokenFromQuery);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [phase, setPhase] = useState<"request" | "confirm">(tokenFromQuery ? "confirm" : "request");
  const [message, setMessage] = useState<string | null>(null);
  const [demoToken, setDemoToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const emailId = useId();
  const tokenId = useId();
  const passwordId = useId();
  const confirmId = useId();

  const canConfirm = useMemo(() => token.trim().length >= 8, [token]);

  async function onRequest(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setMessage(null);
    setDemoToken(null);
    setSubmitting(true);
    try {
      const result = await passwordResetApi.request(email.trim());
      setMessage(result.message);
      if (result.demo_reset_token) {
        setDemoToken(result.demo_reset_token);
        setToken(result.demo_reset_token);
        setPhase("confirm");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Cannot reach the API.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onConfirm(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!evaluatePassword(password).isValid) {
      setError("Choose a stronger password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await passwordResetApi.confirm(token.trim(), password, confirmPassword);
      navigate("/login", { replace: true, state: { message: "Password updated. Sign in." } });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Cannot reach the API.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout mode="login">
      <div className="pt-fade-up space-y-4">
        <h1 id="auth-heading" tabIndex={-1} className="text-2xl font-semibold tracking-tight text-navy-900">
          Reset password
        </h1>
        {phase === "request" ? (
          <form onSubmit={onRequest} className="space-y-4" noValidate>
            <p className="body-muted">Request a one-time reset link for your account email.</p>
            <div>
              <label className="field-label" htmlFor={emailId}>
                Email address
              </label>
              <input
                id={emailId}
                type="email"
                className="field-control w-full"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            {message ? (
              <p className="text-sm text-navy-900" role="status">
                {message}
              </p>
            ) : null}
            {demoToken ? (
              <p className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-950">
                Demo Organisation — Verification Simulated. Reset token ready on the next step.
              </p>
            ) : null}
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <button type="submit" className="btn-primary w-full" disabled={submitting}>
              {submitting ? "Sending…" : "Request reset"}
            </button>
            <button type="button" className="btn-secondary w-full" onClick={() => setPhase("confirm")}>
              I already have a token
            </button>
          </form>
        ) : (
          <form onSubmit={onConfirm} className="space-y-4" noValidate>
            <div>
              <label className="field-label" htmlFor={tokenId}>
                Reset token
              </label>
              <input
                id={tokenId}
                className="field-control w-full"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor={passwordId}>
                New password
              </label>
              <input
                id={passwordId}
                type="password"
                className="field-control w-full"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <div className="mt-2">
                <PasswordStrength password={password} />
              </div>
            </div>
            <div>
              <label className="field-label" htmlFor={confirmId}>
                Confirm password
              </label>
              <input
                id={confirmId}
                type="password"
                className="field-control w-full"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <button type="submit" className="btn-primary w-full" disabled={submitting || !canConfirm}>
              {submitting ? "Updating…" : "Update password"}
            </button>
          </form>
        )}
        <p className="text-sm text-ink-muted">
          <Link to="/login" className="font-semibold text-accent hover:text-teal-800">
            Back to sign in
          </Link>
        </p>
      </div>
    </AuthLayout>
  );
}
