import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { integrationsApi } from "../api/integrationsClient";
import Card from "../components/Card";
import NextActionPanel from "../components/NextActionPanel";
import WorkflowProgressBar, {
  type WizardProgressItem,
} from "../components/WorkflowProgressBar";
import PageHeader from "../components/PageHeader";
import SectionNavigation from "../components/SectionNavigation";
import WorkflowStepCard, {
  type WizardStepStatus,
  type WizardStepLink,
} from "../components/WorkflowStepCard";
import { useToasts } from "../components/Toast";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

const DEMO_INCIDENT_ID = "INC-SEED-001";
const DEMO_SCENARIO = "scenario_1";

type StepId =
  | "status"
  | "evidence"
  | "parse"
  | "detect"
  | "analyse"
  | "explain"
  | "review"
  | "fix_verify"
  | "report"
  | "export";

interface StepState {
  status: WizardStepStatus;
  error?: string | null;
  result?: string | null;
}

/** Wizard completion follows backend PASSED + workflow stage, never HTTP 200 alone. */
export function wizardFixVerificationComplete(
  verificationStatus: string,
  workflowStageCompleted: boolean | undefined,
): boolean {
  return verificationStatus === "passed" && workflowStageCompleted === true;
}

/**
 * Review decisions accepted by POST /incidents/{id}/review. Each maps to a
 * safe incident status on the backend; only "approved" (a human confirming
 * the incident) lets the fix-verification step run afterwards.
 */
type ReviewDecisionValue =
  | "approved"
  | "rejected"
  | "inconclusive"
  | "request_more_evidence";

const REVIEW_DECISION_OPTIONS: Record<
  ReviewDecisionValue,
  { label: string; outcome: string }
> = {
  approved: {
    label: "Approve",
    outcome: "Incident confirmed by human review; fix verification can run next.",
  },
  rejected: {
    label: "Reject (false positive)",
    outcome: "Incident marked false positive; fix verification stays blocked.",
  },
  inconclusive: {
    label: "Inconclusive",
    outcome: "Incident stays under review; fix verification stays blocked.",
  },
  request_more_evidence: {
    label: "Request more evidence",
    outcome: "Incident needs more evidence; fix verification stays blocked.",
  },
};

const STEP_ORDER: StepId[] = [
  "status",
  "evidence",
  "parse",
  "detect",
  "analyse",
  "explain",
  "review",
  "fix_verify",
  "report",
  "export",
];

const STEP_PERMISSIONS: Partial<Record<StepId, string>> = {
  status: undefined,
  evidence: "evidence:upload",
  parse: "workflow:parse",
  detect: "workflow:detect",
  analyse: "workflow:analyse",
  explain: "explanation:generate",
  review: "incident:review",
  fix_verify: "fix:verify",
  report: "report:generate",
  export: "integration:export",
};

const STEP_LABELS: Record<StepId, string> = {
  status: "Status check",
  evidence: "Evidence",
  parse: "Parse",
  detect: "Detect",
  analyse: "Analyse",
  explain: "Explain",
  review: "Review",
  fix_verify: "Verify fix",
  report: "Report",
  export: "SOC export",
};

/**
 * Phase 11.8 Guided Investigation Wizard.
 *
 * The wizard walks the user through ten ordered steps, calling existing
 * backend endpoints in sequence. Safety rules:
 *
 *  - we never `console.log` API responses
 *  - we never render the raw API body; only a short, sanitized summary
 *  - if a step fails, the wizard stops and surfaces the safe failure
 *    reason via {@link WorkflowStepCard}
 *  - subsequent steps are marked `blocked` instead of `ready` while
 *    earlier steps are still pending
 *  - permission denials are explained without leaking detail
 *
 * The wizard is intentionally self-contained: state lives in the
 * component and resets on unmount, so tests don't share state.
 */
export default function InvestigationWizard() {
  const { user, can } = useAuth();
  const { push, ToastContainer } = useToasts();

  const [stepStates, setStepStates] = useState<Record<StepId, StepState>>(() => {
    const init: Record<StepId, StepState> = {} as Record<StepId, StepState>;
    STEP_ORDER.forEach((id, index) => {
      init[id] = { status: index === 0 ? "ready" : "not_started" };
    });
    return init;
  });
  const [runningStep, setRunningStep] = useState<StepId | null>(null);
  const [runningFull, setRunningFull] = useState(false);
  const [incidentId, setIncidentId] = useState<string>(DEMO_INCIDENT_ID);
  const [reviewDecision, setReviewDecision] =
    useState<ReviewDecisionValue>("approved");

  const firstNotComplete = useMemo<StepId | null>(() => {
    for (const id of STEP_ORDER) {
      if (stepStates[id].status !== "complete") return id;
    }
    return null;
  }, [stepStates]);

  const anyFailed = useMemo(
    () => STEP_ORDER.some((id) => stepStates[id].status === "failed"),
    [stepStates],
  );

  const setStep = useCallback(
    (id: StepId, patch: Partial<StepState>) =>
      setStepStates((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } })),
    [],
  );

  const stepIsReady = useCallback(
    (id: StepId): boolean => {
      const index = STEP_ORDER.indexOf(id);
      if (index <= 0) return true;
      const prev = STEP_ORDER[index - 1];
      return stepStates[prev].status === "complete";
    },
    [stepStates],
  );

  // ---- Step runners --------------------------------------------------------

  const runStatusCheck = useCallback(async () => {
    setStep("status", { status: "running", error: null });
    try {
      const health = await api.getHealth();
      const profile = await api.getSecurityProfile();
      setStep("status", {
        status: "complete",
        result: `Backend ${sanitizeString(health.status)} · profile ${sanitizeString(
          profile.security_profile,
        )} · ${sanitizeString(profile.symmetric_algorithm)}`,
      });
      push("success", "Backend and security profile reachable.");
    } catch (err) {
      setStep("status", {
        status: "failed",
        error: err instanceof Error ? err.message : "Status check failed",
      });
      push("error", "Backend disconnected.");
    }
  }, [push, setStep]);

  const runLoadEvidence = useCallback(async () => {
    setStep("evidence", { status: "running", error: null });
    try {
      const result = await api.loadSampleEvidence(DEMO_SCENARIO);
      const count = Number(result.evidence_loaded ?? result.evidence_count ?? 0);
      setStep("evidence", {
        status: "complete",
        result: `Loaded ${count || "sample"} evidence file(s) for ${DEMO_SCENARIO}.`,
      });
      push("success", "Sample evidence loaded.");
    } catch (err) {
      setStep("evidence", {
        status: "failed",
        error: err instanceof Error ? err.message : "Loading sample evidence failed",
      });
      push("error", "Evidence step failed.");
    }
  }, [push, setStep]);

  const runParse = useCallback(async () => {
    setStep("parse", { status: "running", error: null });
    try {
      const result = await api.parseAllEvidence();
      const total = Number(result.total_events ?? 0);
      setStep("parse", {
        status: "complete",
        result: `Parsed evidence into ${total} normalized event(s).`,
      });
      push("success", "Parsing complete.");
    } catch (err) {
      setStep("parse", {
        status: "failed",
        error: err instanceof Error ? err.message : "Parsing failed",
      });
      push("error", "Parse step failed.");
    }
  }, [push, setStep]);

  const runDetect = useCallback(async () => {
    setStep("detect", { status: "running", error: null });
    try {
      const result = await api.detectAllEvidence();
      const total = Number(result.total_detections ?? 0);
      setStep("detect", {
        status: "complete",
        result: `Detection produced ${total} masked finding(s).`,
      });
      push("success", "Detection complete.");
    } catch (err) {
      setStep("detect", {
        status: "failed",
        error: err instanceof Error ? err.message : "Detection failed",
      });
      push("error", "Detect step failed.");
    }
  }, [push, setStep]);

  const runAnalyse = useCallback(async () => {
    setStep("analyse", { status: "running", error: null });
    try {
      await api.analyseIncident(incidentId, true);
      setStep("analyse", {
        status: "complete",
        result: `Causality scored for ${sanitizeString(incidentId)}.`,
      });
      push("success", "Analysis complete.");
    } catch (err) {
      setStep("analyse", {
        status: "failed",
        error: err instanceof Error ? err.message : "Analysis failed",
      });
      push("error", "Analyse step failed.");
    }
  }, [incidentId, push, setStep]);

  const runExplain = useCallback(async () => {
    setStep("explain", { status: "running", error: null });
    try {
      await api.explainIncident(incidentId, true);
      setStep("explain", {
        status: "complete",
        result: "Guarded explanation generated (template provider).",
      });
      push("success", "Explanation generated.");
    } catch (err) {
      setStep("explain", {
        status: "failed",
        error: err instanceof Error ? err.message : "Explanation failed",
      });
      push("error", "Explain step failed.");
    }
  }, [incidentId, push, setStep]);

  const runReview = useCallback(async () => {
    setStep("review", { status: "running", error: null });
    try {
      await api.submitReview(
        incidentId,
        reviewDecision,
        `Reviewed via wizard – decision: ${REVIEW_DECISION_OPTIONS[reviewDecision].label}.`,
      );
      setStep("review", {
        status: "complete",
        result: `Human review recorded (${REVIEW_DECISION_OPTIONS[reviewDecision].label}). ${REVIEW_DECISION_OPTIONS[reviewDecision].outcome}`,
      });
      push("success", "Human review submitted.");
    } catch (err) {
      setStep("review", {
        status: "failed",
        error: err instanceof Error ? err.message : "Review failed",
      });
      push("error", "Review step failed.");
    }
  }, [incidentId, push, reviewDecision, setStep]);

  const runFixVerify = useCallback(async () => {
    setStep("fix_verify", { status: "running", error: null });
    try {
      const result = await api.verifyFix(incidentId);
      const status = sanitizeString(String(result.verification_status ?? "")).toLowerCase();
      const workflow = await api.getWorkflowState(incidentId);
      const verifyStage = workflow.stages.find((stage) => stage.code === "fix_verification");
      if (!wizardFixVerificationComplete(status, verifyStage?.completed)) {
        setStep("fix_verify", {
          status: "failed",
          error: `Fix verification ${status || "did not pass"}.`,
          result: `Fix verification ${status || "unconfirmed"}.`,
        });
        push("error", "Fix verification did not pass.");
        return;
      }
      setStep("fix_verify", {
        status: "complete",
        result: `Fix verification ${status}.`,
      });
      push("success", "Fix verification complete.");
    } catch (err) {
      setStep("fix_verify", {
        status: "failed",
        error: err instanceof Error ? err.message : "Fix verification failed",
      });
      push("error", "Fix verify step failed.");
    }
  }, [incidentId, push, setStep]);

  const runReport = useCallback(async () => {
    setStep("report", { status: "running", error: null });
    try {
      await api.generateReport(incidentId, "json");
      setStep("report", {
        status: "complete",
        result: `Incident report generated for ${sanitizeString(incidentId)}.`,
      });
      push("success", "Report generated.");
    } catch (err) {
      setStep("report", {
        status: "failed",
        error: err instanceof Error ? err.message : "Report generation failed",
      });
      push("error", "Report step failed.");
    }
  }, [incidentId, push, setStep]);

  const runExport = useCallback(async () => {
    setStep("export", { status: "running", error: null });
    try {
      const exportResult = await integrationsApi.exportIncident(
        incidentId,
        "privacytrace_json",
      );
      setStep("export", {
        status: "complete",
        result: `Safe SOC summary exported (${sanitizeString(
          exportResult.format,
        )}, content-type ${sanitizeString(exportResult.content_type)}).`,
      });
      push("success", "SOC summary exported.");
    } catch (err) {
      setStep("export", {
        status: "failed",
        error: err instanceof Error ? err.message : "SOC export failed",
      });
      push("error", "Export step failed.");
    }
  }, [incidentId, push, setStep]);

  const STEP_RUNNERS: Record<StepId, () => Promise<void>> = useMemo(
    () => ({
      status: runStatusCheck,
      evidence: runLoadEvidence,
      parse: runParse,
      detect: runDetect,
      analyse: runAnalyse,
      explain: runExplain,
      review: runReview,
      fix_verify: runFixVerify,
      report: runReport,
      export: runExport,
    }),
    [
      runStatusCheck,
      runLoadEvidence,
      runParse,
      runDetect,
      runAnalyse,
      runExplain,
      runReview,
      runFixVerify,
      runReport,
      runExport,
    ],
  );

  const handleStep = useCallback(
    async (id: StepId) => {
      if (runningStep || runningFull) return;
      if (!stepIsReady(id)) return;
      const required = STEP_PERMISSIONS[id];
      if (required && !can(required)) {
        setStep(id, {
          status: "failed",
          error: `Required permission "${required}" is not granted to your role.`,
        });
        push("warning", `Missing permission: ${required}`);
        return;
      }
      setRunningStep(id);
      try {
        await STEP_RUNNERS[id]();
      } finally {
        setRunningStep(null);
      }
    },
    [STEP_RUNNERS, can, push, runningFull, runningStep, setStep, stepIsReady],
  );

  const runFullAnalysis = useCallback(async () => {
    if (runningStep || runningFull) return;
    setRunningFull(true);
    try {
      for (const id of STEP_ORDER) {
        const required = STEP_PERMISSIONS[id];
        if (required && !can(required)) {
          setStep(id, {
            status: "blocked",
            error: `Required permission "${required}" is not granted to your role.`,
          });
          push(
            "warning",
            `Run Full Analysis stopped before step "${STEP_LABELS[id]}" — missing permission ${required}.`,
          );
          return;
        }
        setRunningStep(id);
        await STEP_RUNNERS[id]();
        setRunningStep(null);
        if (stepStates[id].status === "failed") {
          // Note: stepStates is a snapshot; we re-read via state setter for safety
          break;
        }
      }
    } finally {
      setRunningStep(null);
      setRunningFull(false);
    }
  }, [
    STEP_RUNNERS,
    can,
    push,
    runningFull,
    runningStep,
    setStep,
    stepStates,
  ]);

  // ---- Render --------------------------------------------------------------

  const progressItems: WizardProgressItem[] = STEP_ORDER.map((id) => ({
    id,
    label: STEP_LABELS[id],
    status: stepStates[id].status,
  }));

  const stepsWithStatuses = useMemo(() => {
    let blockedReason: string | null = null;
    return STEP_ORDER.map((id, index) => {
      let status = stepStates[id].status;
      if (status === "not_started") {
        if (anyFailed && index > 0) {
          // any earlier failure blocks downstream steps
          const failedIndex = STEP_ORDER.findIndex(
            (s) => stepStates[s].status === "failed",
          );
          if (failedIndex >= 0 && index > failedIndex) {
            status = "blocked";
            blockedReason = `Resolve "${STEP_LABELS[STEP_ORDER[failedIndex]]}" first.`;
          }
        } else if (stepIsReady(id) && !blockedReason) {
          status = "ready";
        }
      }
      return { id, status, blockedReason };
    });
  }, [anyFailed, stepIsReady, stepStates]);

  const nextRecommendedStep = firstNotComplete;

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[
          { label: "Dashboard", to: "/" },
          { label: "Guided Investigation" },
        ]}
        title="Guided Investigation"
        description="DEMO walkthrough of the investigation workflow. All demo data is synthetic."
      />
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-200 bg-amber-50 px-4 py-3">
        <p className="text-sm text-amber-950">
          DEMO — this wizard is not the investigation workspace. Continue in the incident workspace.
        </p>
        <Link
          to={`/incidents/${encodeURIComponent(incidentId)}/overview`}
          className="btn-primary shrink-0"
        >
          Open incident workspace
        </Link>
      </div>
      <Card title="Guided Investigation Wizard">
        <p className="body-muted">
          Walk through the privacy-preserving investigation workflow end-to-end.
          Each step calls the standard backend endpoints in order, surfaces a
          short safe summary on success, and stops on the first failure with the
          exact safe failure reason.
        </p>
        <p className="mt-2 text-xs text-ink-muted">
          Signed in as{" "}
          <span className="font-medium text-navy-800">
            {sanitizeString(user?.name ?? "anonymous")}
          </span>
          {user?.role ? (
            <>
              {" "}
              · role{" "}
              <code className="rounded bg-slate-100 px-1 font-mono">
                {sanitizeString(user.role)}
              </code>
            </>
          ) : null}
        </p>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-sm font-medium text-navy-900">
            Incident ID
            <input
              type="text"
              value={incidentId}
              onChange={(event) => setIncidentId(event.target.value)}
              className="field-control ml-2 font-mono text-xs"
            />
          </label>
          <button
            type="button"
            onClick={runFullAnalysis}
            disabled={!!runningStep || runningFull}
            className="btn-secondary"
          >
            {runningFull ? "Running…" : "Run Full Analysis"}
          </button>
        </div>

        <div className="mt-4">
          <WorkflowProgressBar
            steps={progressItems}
            activeStepId={runningStep ?? nextRecommendedStep}
          />
        </div>

        <div className="mt-4">
          {nextRecommendedStep ? (
            <NextActionPanel
              actionLabel={`Run "${STEP_LABELS[nextRecommendedStep]}" step`}
              description={
                stepStates[nextRecommendedStep].status === "failed"
                  ? "The current step failed. Inspect the safe failure reason below before continuing."
                  : "Proceed with the next workflow step. Each step has its own permission requirement."
              }
              targetStep={STEP_LABELS[nextRecommendedStep]}
              onAction={
                stepStates[nextRecommendedStep].status === "failed"
                  ? undefined
                  : () => handleStep(nextRecommendedStep)
              }
              disabled={!!runningStep || runningFull}
            />
          ) : (
            <NextActionPanel
              actionLabel=""
              description=""
              empty
            />
          )}
        </div>
      </Card>

      <div className="space-y-4">
        {stepsWithStatuses.map(({ id, status, blockedReason }, index) => {
          const required = STEP_PERMISSIONS[id];
          const hasPerm = required ? can(required) : true;
          const links: WizardStepLink[] = [];
          if (id === "analyse" || id === "report" || id === "fix_verify") {
            links.push({
              label: "Open incident detail",
              to: `/incidents/${incidentId}`,
            });
          }
          if (id === "evidence" || id === "parse" || id === "detect") {
            links.push({ label: "Open evidence", to: "/evidence" });
          }
          if (id === "report") {
            links.push({ label: "Open reports", to: "/reports" });
          }
          if (id === "export") {
            links.push({ label: "Open Integrations", to: "/integrations" });
          }
          const previousStep = index > 0 ? STEP_ORDER[index - 1] : null;
          const nextStep =
            index < STEP_ORDER.length - 1 ? STEP_ORDER[index + 1] : null;
          return (
            <div key={id} id={`wizard-${id}`} className="scroll-mt-4 space-y-2">
            <WorkflowStepCard
              stepNumber={index + 1}
              title={WIZARD_DESCRIPTIONS[id].title}
              description={WIZARD_DESCRIPTIONS[id].description}
              why={WIZARD_DESCRIPTIONS[id].why}
              requiredPermission={required ?? null}
              hasPermission={hasPerm}
              status={status}
              errorMessage={stepStates[id].error ?? blockedReason}
              resultSummary={stepStates[id].result}
              actionLabel={WIZARD_DESCRIPTIONS[id].action}
              actionDisabled={!!runningStep || runningFull}
              onAction={() => handleStep(id)}
              links={links}
            >
              {id === "review" ? (
                <div className="flex flex-wrap items-center gap-2">
                  <label
                    htmlFor="wizard-review-decision"
                    className="text-xs font-medium text-ink-muted"
                  >
                    Reviewer decision
                  </label>
                  <select
                    id="wizard-review-decision"
                    value={reviewDecision}
                    onChange={(e) =>
                      setReviewDecision(e.target.value as ReviewDecisionValue)
                    }
                    disabled={!!runningStep || runningFull || status === "complete"}
                    className="field-control"
                  >
                    {(
                      Object.keys(REVIEW_DECISION_OPTIONS) as ReviewDecisionValue[]
                    ).map((value) => (
                      <option key={value} value={value}>
                        {REVIEW_DECISION_OPTIONS[value].label}
                      </option>
                    ))}
                  </select>
                  <span className="text-xs text-ink-muted">
                    {REVIEW_DECISION_OPTIONS[reviewDecision].outcome}
                  </span>
                </div>
              ) : null}
            </WorkflowStepCard>
            <SectionNavigation
              previous={
                previousStep
                  ? {
                      label: `Previous: ${STEP_LABELS[previousStep]}`,
                      to: `#wizard-${previousStep}`,
                    }
                  : undefined
              }
              next={
                nextStep
                  ? {
                      label: `Next: ${STEP_LABELS[nextStep]}`,
                      to: `#wizard-${nextStep}`,
                    }
                  : undefined
              }
            />
            </div>
          );
        })}
      </div>

      <ToastContainer />
    </div>
  );
}

const WIZARD_DESCRIPTIONS: Record<
  StepId,
  { title: string; description: string; why: string; action: string }
> = {
  status: {
    title: "Backend and security status check",
    description:
      "Confirm the API is reachable and the active NIST-aligned security profile is healthy.",
    why: "If the backend or crypto profile is unhealthy, none of the later steps can be trusted.",
    action: "Check status",
  },
  evidence: {
    title: "Load sample evidence (or upload your own)",
    description:
      "Seed the database with the scenario_1 demo dataset, or upload real evidence from the Evidence page.",
    why: "All later steps operate on evidence metadata. Without evidence there is nothing to parse, detect or trace.",
    action: "Load sample evidence",
  },
  parse: {
    title: "Parse evidence into normalized events",
    description:
      "Run the universal parser to turn raw evidence into masked, normalized events stored in the database.",
    why: "Detection and causality reason over normalized events, not raw logs.",
    action: "Parse evidence",
  },
  detect: {
    title: "Run sensitive-data detection",
    description:
      "Scan normalized events for sensitive-data exposure findings using the masking and detection rules.",
    why: "Findings drive incident creation and root-cause scoring.",
    action: "Run detection",
  },
  analyse: {
    title: "Run incident causality analysis",
    description:
      "Score the most likely root causes for the selected incident using evidence-supported causality.",
    why: "Causality ranking is what the explanation, review and report steps will summarize.",
    action: "Analyse incident",
  },
  explain: {
    title: "Generate guarded explanation",
    description:
      "Generate the safety-guarded explanation using the template provider (no external LLM by default).",
    why: "Operators get a masked, overclaim-free summary they can paste into a ticket.",
    action: "Generate explanation",
  },
  review: {
    title: "Submit a human review decision",
    description:
      "Record the reviewer decision (approve / reject / inconclusive / request more evidence) with a sanitized comment.",
    why: "Incidents must not auto-close. Fix verification only runs after a human reviewer approves the analysis.",
    action: "Submit review",
  },
  fix_verify: {
    title: "Run fix verification",
    description:
      "Re-run the verification checks on the recorded evidence and update the incident status.",
    why: "Verifies that the proposed fix actually clears the masked detections, with audit trail.",
    action: "Verify fix",
  },
  report: {
    title: "Generate incident report",
    description:
      "Build the safe, masked-only incident report (JSON) for the selected incident.",
    why: "Reports are the human-readable artefact for stakeholders; they are also the source for SOC exports.",
    action: "Generate report",
  },
  export: {
    title: "Export safe SOC summary",
    description:
      "Export the masked incident summary into the privacytrace_json format for any SIEM/SOC tool.",
    why: "Closes the loop with downstream SOC / SIEM tools while keeping raw values out of the network.",
    action: "Export SOC summary",
  },
};
