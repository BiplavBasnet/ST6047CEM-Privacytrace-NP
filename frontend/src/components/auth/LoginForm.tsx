import { Eye, EyeOff } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { ApiError } from "../../api/client";

export default function LoginForm() {
  const { login } = useAuth();
  const location = useLocation();
  const successMessage =
    typeof location.state === "object" &&
    location.state &&
    "message" in location.state &&
    typeof (location.state as { message?: unknown }).message === "string"
      ? (location.state as { message: string }).message
      : null;

  const emailId = useId();
  const passwordId = useId();
  const errorId = useId();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("This account is inactive. Contact an administrator.");
      } else if (!(err instanceof ApiError)) {
        setError("Cannot reach the API at http://127.0.0.1:8000. Start the backend and try again.");
      } else {
        setError("We could not sign you in with those details.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="pt-fade-up">
      <h1 id="auth-heading" tabIndex={-1} className="text-2xl font-semibold tracking-tight text-navy-900">
        Welcome back
      </h1>
      <p className="body-muted mt-2">Sign in to continue.</p>

      {successMessage ? (
        <p className="mt-4 rounded-md border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-navy-800" role="status">
          {successMessage}
        </p>
      ) : null}

      <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
        <div>
          <label className="field-label" htmlFor={emailId}>
            Email address
          </label>
          <input
            id={emailId}
            name="email"
            type="email"
            autoComplete="username"
            className="field-control w-full"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? errorId : undefined}
          />
        </div>
        <div>
          <label className="field-label" htmlFor={passwordId}>
            Password
          </label>
          <div className="relative">
            <input
              id={passwordId}
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              className="field-control w-full pr-10"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
            />
            <button
              type="button"
              className="absolute inset-y-0 right-0 flex items-center px-3 text-ink-muted transition-colors hover:text-navy-900"
              onClick={() => setShowPassword((value) => !value)}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
            </button>
          </div>
        </div>

        <div aria-live="polite">
          {error ? (
            <p id={errorId} className="text-sm text-red-700" role="alert">
              {error}
            </p>
          ) : null}
        </div>

        <button type="submit" disabled={submitting} className="btn-primary w-full">
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <p className="mt-4 text-sm text-ink-muted">
        <Link to="/reset-password" className="font-semibold text-accent hover:text-teal-800">
          Forgot password?
        </Link>
      </p>

      <p className="mt-6 text-sm text-ink-muted">
        Need an account?{" "}
        <Link to="/signup" className="font-semibold text-accent hover:text-teal-800">
          Create an account
        </Link>
      </p>
    </div>
  );
}
