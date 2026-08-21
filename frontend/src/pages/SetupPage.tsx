import { FormEvent, useEffect, useId, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getAuthToken, setupApi, type VerificationStatus } from "../api/authClient";
import { ApiError } from "../api/client";
import AuthLayout from "../components/auth/AuthLayout";
import PasswordStrength from "../components/auth/PasswordStrength";
import WorkflowProgressBar, { type WizardProgressItem } from "../components/WorkflowProgressBar";
import { useAuth } from "../context/AuthContext";
import { evaluatePassword } from "../utils/passwordPolicy";
import { userFacingLabel } from "../utils/userFacing";

type StepId = "company" | "legal" | "domain" | "email" | "review" | "activated";
type Phase = "loading" | "register" | "signin" | "verify" | "locked";

function statusToStep(status: string | undefined): WizardProgressItem["status"] {
  if (status === "verified") return "complete";
  if (status === "pending_verification" || status === "partially_verified") return "ready";
  if (status === "manual_review") return "blocked";
  if (status === "rejected") return "failed";
  return "not_started";
}

function stepFromVerification(v: VerificationStatus): StepId {
  if (v.overall_verification_status === "verified") return "activated";
  if (v.legal_verification_status !== "verified") return "legal";
  if (v.domain_verification_status !== "verified") return "domain";
  if (v.admin_email_verification_status !== "verified") return "email";
  return "review";
}

export default function SetupPage() {
  const { login, refresh } = useAuth();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = useState<Phase>("loading");
  const [step, setStep] = useState<StepId>("company");
  const [organisationName, setOrganisationName] = useState("");
  const [legalName, setLegalName] = useState("");
  const [registrationNumber, setRegistrationNumber] = useState("");
  const [websiteDomain, setWebsiteDomain] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [verification, setVerification] = useState<VerificationStatus | null>(null);
  const [txtRecord, setTxtRecord] = useState<string | null>(null);
  const [emailToken, setEmailToken] = useState(searchParams.get("email_token") || "");
  const orgId = useId();
  const nameId = useId();
  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
  const bootstrapId = useId();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await setupApi.status();
        if (cancelled) return;
        const registrationOpen = status.registration_open ?? status.required;
        if (status.verification_pending && getAuthToken()) {
          const v = await setupApi.verificationStatus();
          if (cancelled) return;
          setVerification(v);
          setPhase("verify");
          setStep(stepFromVerification(v));
          return;
        }
        if (status.verification_pending) {
          setPhase("signin");
          return;
        }
        if (registrationOpen) {
          setPhase("register");
          setStep("company");
          return;
        }
        setPhase("locked");
      } catch {
        if (!cancelled) {
          setPhase("register");
          setStep("company");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const progress = useMemo<WizardProgressItem[]>(() => {
    const v = verification;
    return [
      { id: "company", label: "Company", status: phase === "register" ? "ready" : "complete" },
      { id: "legal", label: "Legal", status: statusToStep(v?.legal_verification_status) },
      { id: "domain", label: "Domain", status: statusToStep(v?.domain_verification_status) },
      { id: "email", label: "Admin email", status: statusToStep(v?.admin_email_verification_status) },
      {
        id: "review",
        label: "Review",
        status: v?.policy_satisfied ? "complete" : phase === "verify" ? "ready" : "not_started",
      },
      {
        id: "activated",
        label: "Activated",
        status: v?.overall_verification_status === "verified" ? "complete" : "not_started",
      },
    ];
  }, [phase, verification]);

  if (phase === "loading") {
    return (
      <AuthLayout mode="login">
        <p className="body-muted">Loading setup…</p>
      </AuthLayout>
    );
  }

  async function enterVerify() {
    const v = await setupApi.verificationStatus();
    setVerification(v);
    setPhase("verify");
    setStep(stepFromVerification(v));
    return v;
  }

  async function onRegister(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (evaluatePassword(password).isValid === false) {
      setError("Choose a stronger password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await setupApi.createOrganisation({
        organisation_name: organisationName.trim(),
        administrator_full_name: fullName.trim(),
        email: email.trim(),
        password,
        confirm_password: confirmPassword,
        bootstrap_token: bootstrapToken.trim(),
        legal_name: legalName.trim() || organisationName.trim(),
        registration_number: registrationNumber.trim() || undefined,
        website_domain: websiteDomain.trim() || undefined,
      });
      await login(email.trim(), password);
      await enterVerify();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Cannot reach the API.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onContinueSignIn(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      await enterVerify();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Cannot reach the API.");
    } finally {
      setSubmitting(false);
    }
  }

  async function refreshStatus() {
    const v = await setupApi.verificationStatus();
    setVerification(v);
    if (v.overall_verification_status === "verified") {
      setStep("activated");
      await refresh();
    }
    return v;
  }

  async function onLegal() {
    setSubmitting(true);
    setError(null);
    try {
      const v = await setupApi.verifyLegal({
        legal_name: legalName || verification?.legal_name || undefined,
        registration_number: registrationNumber || verification?.registration_number || undefined,
      });
      setVerification(v);
      setStep(v.domain_verification_status === "verified" ? "email" : "domain");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Legal verification failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onDomainChallenge() {
    setSubmitting(true);
    setError(null);
    try {
      const challenge = await setupApi.createDomainChallenge(websiteDomain.trim());
      setTxtRecord(challenge.txt_record);
      await refreshStatus();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create DNS challenge.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onDomainVerify() {
    setSubmitting(true);
    setError(null);
    try {
      const v = await setupApi.verifyDomain(txtRecord || undefined);
      setVerification(v);
      setStep("email");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Domain verification failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onIssueEmail() {
    setSubmitting(true);
    setError(null);
    try {
      const issued = await setupApi.issueEmailToken();
      if (issued.verify_token) setEmailToken(issued.verify_token);
      await refreshStatus();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not issue email token.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onConfirmEmail() {
    setSubmitting(true);
    setError(null);
    try {
      const v = await setupApi.confirmEmail(emailToken.trim());
      setVerification(v);
      setStep(v.overall_verification_status === "verified" ? "activated" : "review");
      if (v.overall_verification_status === "verified") await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Email verification failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout mode="login">
      <div className="pt-fade-up space-y-4">
        <h1 id="auth-heading" tabIndex={-1} className="text-2xl font-semibold tracking-tight text-navy-900">
          {phase === "register"
            ? "Register company"
            : phase === "signin"
              ? "Continue verification"
              : phase === "locked"
                ? "Setup complete"
                : "Verify organisation"}
        </h1>
        <WorkflowProgressBar steps={progress} activeStepId={step} />
        {verification?.demo_banner ? (
          <p className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-950" role="status">
            {verification.demo_banner}
          </p>
        ) : null}
        {verification ? (
          <dl className="grid grid-cols-2 gap-2 text-xs text-navy-900 sm:grid-cols-3">
            <div>
              <dt className="text-ink-muted">Legal entity</dt>
              <dd className="font-medium">{userFacingLabel(verification.legal_verification_status)}</dd>
            </div>
            <div>
              <dt className="text-ink-muted">PAN</dt>
              <dd className="font-medium">
                {verification.pan_verification_required
                  ? userFacingLabel(verification.pan_verification_status)
                  : "optional"}
              </dd>
            </div>
            <div>
              <dt className="text-ink-muted">Domain</dt>
              <dd className="font-medium">{userFacingLabel(verification.domain_verification_status)}</dd>
            </div>
            <div>
              <dt className="text-ink-muted">Admin email</dt>
              <dd className="font-medium">{userFacingLabel(verification.admin_email_verification_status)}</dd>
            </div>
            <div>
              <dt className="text-ink-muted">Overall</dt>
              <dd className="font-medium">{userFacingLabel(verification.overall_verification_status)}</dd>
            </div>
            {verification.pan_masked ? (
              <div>
                <dt className="text-ink-muted">PAN</dt>
                <dd className="font-medium">{verification.pan_masked}</dd>
              </div>
            ) : null}
            {verification.overall_verification_status === "pending_verification" ||
            verification.overall_verification_status === "partially_verified" ||
            verification.overall_verification_status === "manual_review" ? (
              <div className="col-span-2 sm:col-span-3">
                <p className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-navy-900">
                  Verification pending — invites and operational admin tools stay locked until the
                  organisation is verified
                  {verification.overall_verification_status === "manual_review"
                    ? " (Platform Operator decision required)."
                    : "."}
                </p>
              </div>
            ) : null}
          </dl>
        ) : null}

        {phase === "locked" ? (
          <div className="space-y-3">
            <p className="body-muted">
              This deployment already has a verified organisation. Sign in with an activated account.
            </p>
            <Link to="/login" className="btn-primary inline-flex w-full justify-center">
              Sign in
            </Link>
          </div>
        ) : null}

        {phase === "signin" ? (
          <form onSubmit={onContinueSignIn} className="space-y-4" noValidate>
            <p className="body-muted">
              Company registration is waiting on legal, domain, and admin-email verification. Sign in
              as the first Organisation Admin to continue.
            </p>
            <div>
              <label className="field-label" htmlFor={emailId}>
                Work email
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
            <div>
              <label className="field-label" htmlFor={passwordId}>
                Password
              </label>
              <input
                id={passwordId}
                type="password"
                className="field-control w-full"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <button type="submit" disabled={submitting} className="btn-primary w-full">
              {submitting ? "Signing in…" : "Continue verification"}
            </button>
          </form>
        ) : null}

        {phase === "register" && step === "company" ? (
          <form onSubmit={onRegister} className="space-y-4" noValidate>
            <p className="body-muted">
              Submit company details and the one-time deployment bootstrap token. Organisation Admin
              access activates only after verification.
            </p>
            <div>
              <label className="field-label" htmlFor={bootstrapId}>
                Bootstrap token
              </label>
              <input
                id={bootstrapId}
                className="field-control w-full"
                type="password"
                autoComplete="off"
                value={bootstrapToken}
                onChange={(e) => setBootstrapToken(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor={orgId}>
                Organisation name
              </label>
              <input
                id={orgId}
                className="field-control w-full"
                value={organisationName}
                onChange={(e) => setOrganisationName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor="legal-name">
                Legal company name
              </label>
              <input
                id="legal-name"
                className="field-control w-full"
                value={legalName}
                onChange={(e) => setLegalName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor="reg-number">
                Registration number
              </label>
              <input
                id="reg-number"
                className="field-control w-full"
                value={registrationNumber}
                onChange={(e) => setRegistrationNumber(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor="website-domain">
                Website domain
              </label>
              <input
                id="website-domain"
                className="field-control w-full"
                value={websiteDomain}
                onChange={(e) => setWebsiteDomain(e.target.value)}
                placeholder="abcwallet.com"
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor={nameId}>
                Administrator full name
              </label>
              <input
                id={nameId}
                className="field-control w-full"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="field-label" htmlFor={emailId}>
                Work email
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
            <div>
              <label className="field-label" htmlFor={passwordId}>
                Password
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
            <button type="submit" disabled={submitting} className="btn-primary w-full">
              {submitting ? "Submitting…" : "Submit company registration"}
            </button>
          </form>
        ) : null}

        {phase === "verify" && step === "legal" ? (
          <div className="space-y-3">
            <p className="body-muted">Confirm legal entity details against the official registry reference.</p>
            <input
              className="field-control w-full"
              placeholder="Legal name"
              value={legalName || verification?.legal_name || ""}
              onChange={(e) => setLegalName(e.target.value)}
            />
            <input
              className="field-control w-full"
              placeholder="Registration number"
              value={registrationNumber || verification?.registration_number || ""}
              onChange={(e) => setRegistrationNumber(e.target.value)}
            />
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <button type="button" className="btn-primary w-full" disabled={submitting} onClick={onLegal}>
              Run legal verification
            </button>
          </div>
        ) : null}

        {phase === "verify" && step === "domain" ? (
          <div className="space-y-3">
            <p className="body-muted">Prove domain ownership with a DNS TXT record.</p>
            <input
              className="field-control w-full"
              placeholder="company domain"
              value={websiteDomain || verification?.website_domain || ""}
              onChange={(e) => setWebsiteDomain(e.target.value)}
            />
            {txtRecord ? (
              <p className="break-all rounded bg-slate-100 p-2 font-mono text-xs" role="status">
                {txtRecord}
              </p>
            ) : null}
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <div className="flex gap-2">
              <button type="button" className="btn-secondary flex-1" disabled={submitting} onClick={onDomainChallenge}>
                Create challenge
              </button>
              <button type="button" className="btn-primary flex-1" disabled={submitting} onClick={onDomainVerify}>
                Verify DNS
              </button>
            </div>
          </div>
        ) : null}

        {phase === "verify" && step === "email" ? (
          <div className="space-y-3">
            <p className="body-muted">Verify the first administrator work email.</p>
            <input
              className="field-control w-full"
              placeholder="Email verification token"
              value={emailToken}
              onChange={(e) => setEmailToken(e.target.value)}
            />
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <div className="flex gap-2">
              <button type="button" className="btn-secondary flex-1" disabled={submitting} onClick={onIssueEmail}>
                Issue token
              </button>
              <button type="button" className="btn-primary flex-1" disabled={submitting} onClick={onConfirmEmail}>
                Confirm email
              </button>
            </div>
          </div>
        ) : null}

        {phase === "verify" && step === "review" ? (
          <div className="space-y-3">
            <p className="body-muted">Review remaining checks or request manual review if a step is blocked.</p>
            {error ? (
              <p className="text-sm text-red-700" role="alert">
                {error}
              </p>
            ) : null}
            <button
              type="button"
              className="btn-secondary w-full"
              disabled={submitting}
              onClick={async () => {
                setSubmitting(true);
                try {
                  const v = await setupApi.requestManualReview("Verification assistance requested");
                  setVerification(v);
                } catch (err) {
                  setError(err instanceof ApiError ? err.message : "Manual review request failed.");
                } finally {
                  setSubmitting(false);
                }
              }}
            >
              Request manual review
            </button>
            <button type="button" className="btn-primary w-full" disabled={submitting} onClick={() => refreshStatus()}>
              Refresh status
            </button>
          </div>
        ) : null}

        {phase === "verify" && step === "activated" ? (
          <div className="space-y-3">
            <p className="text-sm text-navy-900" role="status">
              Organisation verified. First Organisation Admin is activated. Setup is locked.
            </p>
            <Link to="/" className="btn-primary inline-flex w-full justify-center">
              Continue to PrivacyTrace
            </Link>
          </div>
        ) : null}

        <p className="mt-4 text-sm text-ink-muted">
          {phase === "locked" ? null : (
            <>
              Already have an activated account?{" "}
              <Link to="/login" className="font-semibold text-accent hover:text-teal-800">
                Sign in
              </Link>
            </>
          )}
        </p>
      </div>
    </AuthLayout>
  );
}
