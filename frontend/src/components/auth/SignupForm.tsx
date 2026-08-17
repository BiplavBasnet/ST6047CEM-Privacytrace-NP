import { Eye, EyeOff } from "lucide-react";
import { useEffect, useId, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { authApi } from "../../api/authClient";
import { ApiError } from "../../api/client";
import { evaluatePassword } from "../../utils/passwordPolicy";
import PasswordStrength from "./PasswordStrength";

export default function SignupForm() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const inviteToken = searchParams.get("invite")?.trim() || "";
  const nameId = useId();
  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
  const termsId = useId();
  const errorId = useId();

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [registrationEnabled, setRegistrationEnabled] = useState<boolean | null>(null);
  const [inviteOrg, setInviteOrg] = useState<string | null>(null);
  const [inviteRole, setInviteRole] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    authApi
      .registrationStatus()
      .then((status) => {
        if (!cancelled) setRegistrationEnabled(status.enabled || Boolean(inviteToken));
      })
      .catch(() => {
        if (!cancelled) setRegistrationEnabled(true);
      });
    if (inviteToken) {
      authApi
        .invitationPreview(inviteToken)
        .then((preview) => {
          if (cancelled) return;
          setEmail(preview.email);
          setInviteOrg(preview.organisation_name);
          setInviteRole(preview.role);
        })
        .catch((err) => {
          if (!cancelled) {
            setError(err instanceof Error ? err.message : "Invitation is not valid.");
          }
        });
    }
    return () => {
      cancelled = true;
    };
  }, [inviteToken]);

  function validateClient(): boolean {
    const next: Record<string, string> = {};
    if (!fullName.trim()) next.fullName = "Enter your full name.";
    if (!email.trim() || !email.includes("@")) next.email = "Enter a valid email address.";
    const strength = evaluatePassword(password);
    if (!strength.isValid) next.password = "Choose a stronger password.";
    if (password !== confirmPassword) next.confirmPassword = "Passwords do not match.";
    if (!acceptedTerms) next.terms = "Confirm you understand this is a controlled research prototype.";
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!validateClient()) return;
    setSubmitting(true);
    try {
      await authApi.register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
        confirm_password: confirmPassword,
        ...(inviteToken ? { invite_token: inviteToken } : {}),
      });
      navigate("/login", {
        replace: true,
        state: {
          message: "Account created. Sign in with your email and password.",
        },
      });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setError("Account creation is currently unavailable.");
          setRegistrationEnabled(false);
        } else if (err.status === 409) {
          setError("An account with this email already exists.");
        } else if (err.status === 422) {
          setError("The account could not be created. Review the form and try again.");
        } else {
          setError("The account could not be created. Review the form and try again.");
        }
      } else {
        setError("Cannot reach the API at http://127.0.0.1:8000. Start the backend and try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (registrationEnabled === false) {
    return (
      <div className="pt-fade-up">
        <h1 id="auth-heading" tabIndex={-1} className="text-2xl font-semibold tracking-tight text-navy-900">
          Account creation unavailable
        </h1>
        <p className="body-muted mt-2" role="status">
          Self-registration is disabled for this deployment. Ask an administrator to create an
          account, or sign in if you already have one.
        </p>
        <div className="mt-6">
          <Link to="/login" className="btn-secondary">
            Back to sign in
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="pt-fade-up">
      <h1 id="auth-heading" tabIndex={-1} className="text-2xl font-semibold tracking-tight text-navy-900">
        Create your account
      </h1>
      <p className="body-muted mt-2">
        {inviteOrg
          ? `Join ${inviteOrg} as ${inviteRole}. Organisation and role are set by the invitation.`
          : "Create a viewer account. An organisation administrator must assign membership before company data is visible."}
      </p>

      <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
        <div>
          <label className="field-label" htmlFor={nameId}>
            Full name
          </label>
          <input
            id={nameId}
            name="full_name"
            type="text"
            autoComplete="name"
            className="field-control w-full"
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
            required
            aria-invalid={fieldErrors.fullName ? true : undefined}
            aria-describedby={fieldErrors.fullName ? `${nameId}-error` : undefined}
          />
          {fieldErrors.fullName ? (
            <p id={`${nameId}-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.fullName}
            </p>
          ) : null}
        </div>

        <div>
          <label className="field-label" htmlFor={emailId}>
            Email address
          </label>
          <input
            id={emailId}
            name="email"
            type="email"
            autoComplete="email"
            className="field-control w-full"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            readOnly={Boolean(inviteToken)}
            aria-invalid={fieldErrors.email ? true : undefined}
            aria-describedby={fieldErrors.email ? `${emailId}-error` : undefined}
          />
          {fieldErrors.email ? (
            <p id={`${emailId}-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.email}
            </p>
          ) : null}
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
              autoComplete="new-password"
              className="field-control w-full pr-10"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              aria-invalid={fieldErrors.password ? true : undefined}
              aria-describedby={`${passwordId}-strength${fieldErrors.password ? ` ${passwordId}-error` : ""}`}
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
          <div id={`${passwordId}-strength`} className="mt-2">
            <PasswordStrength password={password} />
          </div>
          {fieldErrors.password ? (
            <p id={`${passwordId}-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.password}
            </p>
          ) : null}
        </div>

        <div>
          <label className="field-label" htmlFor={confirmId}>
            Confirm password
          </label>
          <input
            id={confirmId}
            name="confirm_password"
            type={showPassword ? "text" : "password"}
            autoComplete="new-password"
            className="field-control w-full"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            required
            aria-invalid={fieldErrors.confirmPassword ? true : undefined}
            aria-describedby={fieldErrors.confirmPassword ? `${confirmId}-error` : undefined}
          />
          {fieldErrors.confirmPassword ? (
            <p id={`${confirmId}-error`} className="mt-1 text-xs text-red-700">
              {fieldErrors.confirmPassword}
            </p>
          ) : null}
        </div>

        <div className="flex items-start gap-2">
          <input
            id={termsId}
            type="checkbox"
            className="mt-1 h-4 w-4 rounded border-slate-300 text-accent focus:ring-accent"
            checked={acceptedTerms}
            onChange={(event) => setAcceptedTerms(event.target.checked)}
            aria-invalid={fieldErrors.terms ? true : undefined}
            aria-describedby={fieldErrors.terms ? `${termsId}-error` : undefined}
          />
          <label htmlFor={termsId} className="text-xs leading-relaxed text-ink-muted">
            I understand PrivacyTrace-NP is a research prototype for controlled privacy
            investigation, not a certified compliance product.
          </label>
        </div>
        {fieldErrors.terms ? (
          <p id={`${termsId}-error`} className="text-xs text-red-700">
            {fieldErrors.terms}
          </p>
        ) : null}

        <div aria-live="polite">
          {error ? (
            <p id={errorId} className="text-sm text-red-700" role="alert">
              {error}
            </p>
          ) : null}
        </div>

        <button type="submit" disabled={submitting || registrationEnabled === null} className="btn-primary w-full">
          {submitting ? "Creating account…" : "Create account"}
        </button>
      </form>

      <p className="mt-6 text-sm text-ink-muted">
        Already have an account?{" "}
        <Link to="/login" className="font-semibold text-accent hover:text-teal-800">
          Sign in
        </Link>
      </p>
    </div>
  );
}
