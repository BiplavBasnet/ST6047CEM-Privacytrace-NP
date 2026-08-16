import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import HumanReviewPanel from "../components/HumanReviewPanel";
import UserGuidePage from "../pages/UserGuidePage";

const submitReview = vi.fn();
const getReviewDraft = vi.fn();
const saveReviewDraft = vi.fn();
const deleteReviewDraft = vi.fn();
vi.mock("../api/client", () => ({
  api: {
    submitReview: (...args: unknown[]) => submitReview(...args),
    getReviewDraft: (...args: unknown[]) => getReviewDraft(...args),
    saveReviewDraft: (...args: unknown[]) => saveReviewDraft(...args),
    deleteReviewDraft: (...args: unknown[]) => deleteReviewDraft(...args),
  },
}));

function renderPanel() {
  return render(
    <MemoryRouter>
      <HumanReviewPanel
        incidentId="INC-SEED-001"
        topScore={{
          rank: 1,
          likely_root_cause: "Sensitive values logged by wallet middleware",
          confidence_band: "medium",
          confidence: 0.6,
          recommended_fix: "Update redaction rule",
          supporting_evidence_ids: ["EVD-1"],
          missing_evidence: [],
        }}
        detectionCount={3}
        missingEvidence={["access_logs"]}
        latestReview={null}
      />
    </MemoryRouter>,
  );
}

describe("product flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    submitReview.mockResolvedValue({});
    getReviewDraft.mockResolvedValue(null);
    saveReviewDraft.mockResolvedValue({});
    deleteReviewDraft.mockResolvedValue({});
  });

  it("human review offers the four decision options with resulting status", () => {
    renderPanel();
    const select = screen.getByLabelText("Decision");
    expect(select).toBeInTheDocument();
    const options = [...select.querySelectorAll("option")].map(
      (o) => o.textContent,
    );
    expect(options).toEqual([
      "Accept likely cause for remediation",
      "Request more evidence",
      "Decline as false positive",
      "Escalate",
    ]);
    expect(screen.getByTestId("resulting-status").textContent).toMatch(
      /Remediation becomes available/,
    );
    expect(screen.getByTestId("resulting-status")).toHaveTextContent(
      "does not verify a fix or close the incident",
    );
  });

  it("human review requires checklist and reason before submitting", async () => {
    renderPanel();
    const submit = screen.getByRole("button", {
      name: "Submit decision",
    });
    expect(submit).toBeDisabled();

    // tick every checklist item
    for (const box of screen.getAllByRole("checkbox")) {
      fireEvent.click(box);
    }
    expect(submit).toBeDisabled(); // reason still missing

    fireEvent.change(screen.getByLabelText(/Decision reason/), {
      target: { value: "Masked evidence supports the ranked cause." },
    });
    expect(submit).not.toBeDisabled();

    fireEvent.click(submit);
    await waitFor(() => expect(submitReview).toHaveBeenCalledTimes(1));
    expect(submitReview).toHaveBeenCalledWith(
      "INC-SEED-001",
      expect.objectContaining({
        decision: "approved",
        reason: "Masked evidence supports the ranked cause.",
        evidence_checklist: [
          "Live alert reviewed, if applicable",
          "Masked detection reviewed",
          "Root-cause explanation reviewed",
          "Supporting evidence reviewed",
          "Contradicting evidence reviewed, if present",
          "Missing evidence reviewed",
          "Confidence limitation acknowledged",
        ],
        missing_evidence_acknowledged: true,
      }),
    );
  });

  it("uses only the seven evidence-review checks", () => {
    renderPanel();
    const labels = screen.getAllByRole("checkbox").map((box) => box.parentElement?.textContent);
    expect(labels).toHaveLength(7);
    expect(labels.join(" ")).not.toMatch(/remediation|retest|fix verification/i);
  });

  it("saves a persistent draft without submitting a final decision", async () => {
    renderPanel();
    await waitFor(() => expect(screen.getByRole("button", { name: "Save draft" })).not.toBeDisabled());
    fireEvent.change(screen.getByLabelText(/Decision reason/), {
      target: { value: "Masked evidence needs another reviewer." },
    });
    fireEvent.click(screen.getByLabelText("Masked detection reviewed"));
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));

    await waitFor(() => expect(saveReviewDraft).toHaveBeenCalledWith(
      "INC-SEED-001",
      expect.objectContaining({
        selected_decision: "approved",
        reason: "Masked evidence needs another reviewer.",
        evidence_checklist: ["Masked detection reviewed"],
      }),
    ));
    expect(submitReview).not.toHaveBeenCalled();
    expect(await screen.findByText(/does not unlock remediation/i)).toBeInTheDocument();
  });

  it("restores a saved review draft after reload", async () => {
    getReviewDraft.mockResolvedValue({
      incident_id: "INC-SEED-001",
      selected_decision: "request_more_evidence",
      reason: "Deployment evidence is still missing.",
      evidence_checklist: ["Masked detection reviewed", "Missing evidence reviewed"],
      evidence_relied_on: ["EVD-1"],
      evidence_limitations: "No deployment metadata.",
      missing_evidence_notes: "Import deployment evidence.",
      missing_evidence_acknowledged: true,
      last_updated_by: 1,
      last_updated_at: "2026-07-15T00:00:00Z",
    });
    renderPanel();

    expect(await screen.findByText("Saved review draft restored.")).toBeInTheDocument();
    expect(screen.getByLabelText("Decision")).toHaveValue("request_more_evidence");
    expect(screen.getByLabelText(/Decision reason/)).toHaveValue("Deployment evidence is still missing.");
    expect(screen.getByLabelText("Masked detection reviewed")).toBeChecked();
    expect(screen.getByLabelText("Missing evidence reviewed")).toBeChecked();
  });

  it("human review panel shows reminder when no review exists", () => {
    renderPanel();
    expect(
      screen.getByText(/Human review has not been completed/),
    ).toBeInTheDocument();
  });

  it("human review panel never renders forbidden wording", () => {
    const { container } = renderPanel();
    for (const phrase of [
      /proven cause/i,
      /confirmed blame/i,
      /guaranteed fixed/i,
      /attacker accessed data/i,
    ]) {
      expect(container.textContent).not.toMatch(phrase);
    }
  });

  it("user guide page renders the workflow topics", () => {
    render(
      <MemoryRouter>
        <UserGuidePage />
      </MemoryRouter>,
    );
    expect(
      screen.getByRole("heading", { name: "User Guide" }),
    ).toBeInTheDocument();
    expect(screen.getByText("What PrivacyTrace-NP does")).toBeInTheDocument();
    expect(screen.getByText("What it does not do")).toBeInTheDocument();
    expect(screen.getByText("Human Review")).toBeInTheDocument();
    expect(screen.getByText("Remediation Action")).toBeInTheDocument();
    expect(screen.getByText("Fix Verification")).toBeInTheDocument();
    expect(screen.getByText("Roles and permissions")).toBeInTheDocument();
    expect(
      screen.getByText(/does not change production code/i),
    ).toBeInTheDocument();
  });

  it("user guide contains no raw sensitive values", () => {
    const { container } = render(
      <MemoryRouter>
        <UserGuidePage />
      </MemoryRouter>,
    );
    for (const raw of [
      "9841234567",
      "WALLET-NP-88291",
      "TXN-NP-2026-77881",
      "pk_test_np_fake_12345",
    ]) {
      expect(container.textContent).not.toContain(raw);
    }
  });
});
