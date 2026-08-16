import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import CausalTimelinePanel from "../components/differentiation/CausalTimelinePanel";
import EvidenceCompletenessPanel from "../components/differentiation/EvidenceCompletenessPanel";
import FixVerificationComparisonPanel from "../components/differentiation/FixVerificationComparisonPanel";
import ScannerComparisonPanel from "../components/differentiation/ScannerComparisonPanel";
import WhyThisCausePanel from "../components/differentiation/WhyThisCausePanel";
import { buildCausalTimeline } from "../utils/causalTimeline";
import { computeEvidenceCompleteness } from "../utils/evidenceCompleteness";
import {
  BLOCKED_CLAIM_FALLBACK,
  BLOCKED_SENSITIVE_FALLBACK,
  sanitizeString,
} from "../utils/safety";

const incident = {
  incident_id: "INC-SEED-001",
  title: "Seed",
  affected_endpoint: "/api/v1/wallet/transfer",
  affected_service: "wallet-service",
  status: "fixed",
  severity: "high",
  summary: "Masked leak",
  root_cause_scores: [],
};

describe("Differentiation panels", () => {
  it("renders causal timeline investigation stages", () => {
    const stages = buildCausalTimeline({
      evidenceFiles: [
        {
          evidence_id: "EVD-1",
          evidence_type: "api_log",
          source_system: "gw",
          parsing_status: "parsed",
          file_hash: "h1",
          linked_incident_id: "INC-SEED-001",
        },
      ],
      trace: {
        incident_id: "INC-SEED-001",
        title: "Seed",
        status: "fixed",
        affected_service: "wallet-service",
        affected_endpoint: "/api/v1/wallet/transfer",
        detection_count: 1,
        evidence_count: 1,
        timeline: [],
        likely_root_causes: [{ likely_root_cause: "unsafe_request_body_logging" }],
        missing_evidence: [],
        human_review_required: true,
        disclaimer: "Likely cause only.",
      },
      detections: [{ sensitive_type: "phone", masked_value: "98******67" }],
      rootCauseScores: [
        {
          rank: 1,
          likely_root_cause: "unsafe_request_body_logging",
          confidence_band: "high",
          confidence: 0.85,
          recommended_fix: "Redact logs",
          supporting_evidence_ids: ["EVD-1"],
          missing_evidence: [],
        },
      ],
      llmReports: [
        {
          report_id: "r1",
          incident_summary_preview: "Summary",
          top_likely_cause_preview: "Likely unsafe logging",
          provider_used: "template",
          safety_status: "ok",
          created_at: "2026-05-16T00:00:00Z",
        },
      ],
      reviews: [
        {
          decision: "approved",
          comment: "Reviewed",
          reviewer_id: 1,
          timestamp: "2026-05-16T01:00:00Z",
        },
      ],
      verifications: [
        {
          verification_status: "passed",
          checks_run: ["masked_output_check"],
          passed_checks: ["masked_output_check"],
          failed_checks: [],
          evidence_used: ["EVD-FIX-1"],
          timestamp: "2026-05-16T02:00:00Z",
        },
      ],
      reports: [
        {
          report_id: 1,
          report_type: "json",
          created_at: "2026-05-16T03:00:00Z",
          content: {},
        },
      ],
      metricsAvailable: true,
      auditLogs: [],
    });

    render(<CausalTimelinePanel stages={stages} />);

    expect(screen.getByText("Causal investigation timeline")).toBeInTheDocument();
    expect(screen.getByText("Evidence loaded")).toBeInTheDocument();
    expect(screen.getByText("Values masked")).toBeInTheDocument();
    expect(screen.getByText("Human review completed")).toBeInTheDocument();
    expect(screen.getByText("Metrics generated")).toBeInTheDocument();
  });

  it("shows evidence completeness available and missing types", () => {
    const result = computeEvidenceCompleteness(
      [
        {
          evidence_id: "EVD-1",
          evidence_type: "api_log",
          source_system: "gw",
          parsing_status: "parsed",
          file_hash: "h1",
          linked_incident_id: "INC-SEED-001",
        },
        {
          evidence_id: "EVD-2",
          evidence_type: "semgrep_report",
          source_system: "ci",
          parsing_status: "parsed",
          file_hash: "h2",
          linked_incident_id: "INC-SEED-001",
        },
      ],
      ["access_event"],
    );

    render(<EvidenceCompletenessPanel result={result} />);

    expect(
      screen.getByRole("heading", { name: "Evidence completeness" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/api_log/)).toBeInTheDocument();
    expect(screen.getByText(/semgrep_report/)).toBeInTheDocument();
    expect(screen.getByText(/access_event/)).toBeInTheDocument();
  });

  it("shows likely-cause wording in Why This Cause panel", () => {
    render(
      <WhyThisCausePanel
        topCause={{
          rank: 1,
          likely_root_cause: "unsafe_request_body_logging",
          confidence_band: "high",
          confidence: 0.85,
          recommended_fix: "Redact request bodies in logs",
          supporting_evidence_ids: ["EVD-1"],
          missing_evidence: ["access_event"],
        }}
        explanation={{
          report_id: "r1",
          incident_summary_preview: "Likely exposure in wallet API logs",
          top_likely_cause_preview: "The likely cause is unsafe request body logging",
          provider_used: "template",
          safety_status: "ok",
          created_at: "2026-05-16T00:00:00Z",
        }}
      />,
    );

    expect(screen.getByText("Why this likely cause")).toBeInTheDocument();
    expect(screen.getByText(/unsafe_request_body_logging/)).toBeInTheDocument();
    expect(screen.getByText(/Supporting evidence IDs/)).toBeInTheDocument();
    expect(
      screen.getByText(/The likely cause is unsafe request body logging/),
    ).toBeInTheDocument();
  });

  it("does not render overclaim phrases in Why This Cause panel", () => {
    render(
      <WhyThisCausePanel
        topCause={{
          rank: 1,
          likely_root_cause: "proven cause logging failure",
          confidence_band: "high",
          confidence: 1,
          recommended_fix: "developer fault patch",
          supporting_evidence_ids: [],
          missing_evidence: [],
        }}
        explanation={undefined}
      />,
    );

    expect(screen.queryByText(/proven cause/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/developer fault/i)).not.toBeInTheDocument();
    expect(screen.getAllByText(/\[blocked unsafe claim\]/).length).toBeGreaterThan(0);
  });

  it("shows before/after fix verification with masked values only", () => {
    render(
      <FixVerificationComparisonPanel
        incident={incident}
        detections={[
          { sensitive_type: "nepal_phone", masked_value: "98******67" },
          { sensitive_type: "wallet_id", masked_value: "wallet_[masked]" },
        ]}
        verification={{
          verification_status: "passed",
          checks_run: ["masked_output_check"],
          passed_checks: ["masked_output_check"],
          failed_checks: [],
          evidence_used: ["EVD-FIXED-001"],
          timestamp: "2026-05-16T02:00:00Z",
        }}
        humanReviewRequired
      />,
    );

    expect(screen.getByText("Before / after fix verification")).toBeInTheDocument();
    expect(screen.getByText(/98\*{6}67/)).toBeInTheDocument();
    expect(screen.getByText(/EVD-FIXED-001/)).toBeInTheDocument();
    expect(screen.queryByText("9841234567")).not.toBeInTheDocument();
    expect(screen.queryByText(/guaranteed fixed/i)).not.toBeInTheDocument();
  });

  it("renders Basic Scanner vs PrivacyTrace-NP comparison", () => {
    render(<ScannerComparisonPanel />);
    expect(screen.getByText("Basic scanner vs PrivacyTrace-NP")).toBeInTheDocument();
    expect(screen.getByText("Basic scanner")).toBeInTheDocument();
    expect(screen.getByText(/Verifies fix using retest evidence/)).toBeInTheDocument();
    expect(screen.getByText(/No invented performance numbers/)).toBeInTheDocument();
  });
});

describe("safety utility extended", () => {
  it("blocks raw phone number", () => {
    expect(sanitizeString("9841234567")).not.toContain("9841234567");
    expect(sanitizeString("9841234567")).toContain(BLOCKED_SENSITIVE_FALLBACK);
  });

  it("blocks raw wallet ID", () => {
    expect(sanitizeString("WALLET-NP-88291")).toContain(BLOCKED_SENSITIVE_FALLBACK);
  });

  it("blocks raw API key", () => {
    expect(sanitizeString("pk_test_np_fake_12345")).toContain(BLOCKED_SENSITIVE_FALLBACK);
  });

  it("blocks JWT and bearer token", () => {
    expect(sanitizeString("Bearer secret-token-value-12345")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
    expect(sanitizeString("Authorization: Bearer abcdef1234567890")).toContain(
      BLOCKED_SENSITIVE_FALLBACK,
    );
  });

  it("blocks overclaim phrases", () => {
    const phrases = [
      "proven cause",
      "confirmed blame",
      "guaranteed cause",
      "definitely caused by",
      "developer fault",
      "guaranteed fixed",
      "incident closed automatically",
    ];
    for (const phrase of phrases) {
      expect(sanitizeString(`unsafe ${phrase} here`)).toContain(BLOCKED_CLAIM_FALLBACK);
      expect(sanitizeString(`unsafe ${phrase} here`)).not.toMatch(
        new RegExp(phrase, "i"),
      );
    }
  });
});
