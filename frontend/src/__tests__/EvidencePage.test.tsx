import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import EvidencePage from "../pages/EvidencePage";
import * as client from "../api/client";

describe("EvidencePage", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows metadata only and not raw file contents", async () => {
    vi.spyOn(client.api, "listEvidence").mockResolvedValue([
      {
        evidence_id: "EV-SEED-001",
        evidence_type: "api_log",
        source_system: "gateway",
        parsing_status: "parsed",
        file_hash: "deadbeef",
        linked_incident_id: "INC-SEED-001",
      },
    ]);
    vi.spyOn(client.api, "getEvidence").mockResolvedValue({
      evidence_id: "EV-SEED-001",
      evidence_type: "api_log",
      source_system: "gateway",
      parsing_status: "parsed",
      file_hash: "deadbeef",
      linked_incident_id: "INC-SEED-001",
    });

    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("EV-SEED-001")).toBeInTheDocument();
    fireEvent.click(screen.getByText("EV-SEED-001"));
    const metadata = await screen.findByTestId("evidence-metadata");
    expect(metadata).not.toHaveAttribute("open");
    expect(screen.getByText("Selected evidence metadata")).toBeInTheDocument();
    expect(screen.queryByText("9841234567")).not.toBeInTheDocument();
  });

  it("uploads historical evidence through the existing multipart endpoint", async () => {
    vi.spyOn(client.api, "listEvidence").mockResolvedValue([]);
    const upload = vi.spyOn(client.api, "uploadEvidence").mockResolvedValue({
      message: "Evidence uploaded successfully",
      evidence: {
        evidence_id: "EVD-UPLOAD-001",
        evidence_type: "api_log",
        source_system: "wallet-service",
        parsing_status: "pending",
        file_hash: "sha256:safe",
        linked_incident_id: null,
      },
    });

    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>,
    );

    const file = new File(["phone_masked=[MASKED]"], "historical.log", {
      type: "text/plain",
    });
    fireEvent.change(screen.getByLabelText("Evidence file"), {
      target: { files: [file] },
    });
    fireEvent.click(screen.getByRole("button", { name: "Validate file" }));
    fireEvent.click(screen.getByRole("button", { name: "Import Evidence" }));

    await waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
    expect(upload).toHaveBeenCalledWith(
      expect.objectContaining({ file, evidenceType: "api_log" }),
    );
    expect(await screen.findByText(/EVD-UPLOAD-001 imported/)).toBeInTheDocument();
  });
});
