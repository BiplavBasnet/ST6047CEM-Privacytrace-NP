import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import IntegrationsPage from "../pages/Integrations";
import { ANALYST_USER, VIEWER_USER, mockUseAuth } from "../test/authTestUtils";
import { CONNECTOR_V1_EVENTS_PATH } from "../api/integrationsClient";
import {
  CONNECTOR_CLI_ADD_GITHUB,
  CONNECTOR_CLI_ADD_RUNTIME,
  CONNECTOR_CLI_ADD_WAZUH,
  isVerifiedCliCommand,
} from "../components/integrations/connectorGuide";

const useAuthMock = vi.fn();

vi.mock("../context/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

const getStatus = vi.fn();
const getSchema = vi.fn();
const getSnippets = vi.fn();
const listFormats = vi.fn();
const listTokens = vi.fn();
const createToken = vi.fn();
const revokeToken = vi.fn();
const sendTestEvent = vi.fn();
const ingestConnectorV1 = vi.fn();
const exportIncident = vi.fn();
const listIncidents = vi.fn();
const listEvidence = vi.fn();

vi.mock("../api/integrationsClient", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/integrationsClient")>();
  return {
    ...actual,
    integrationsApi: {
      ...actual.integrationsApi,
      getStatus: (...args: unknown[]) => getStatus(...args),
      getSchema: (...args: unknown[]) => getSchema(...args),
      getSnippets: (...args: unknown[]) => getSnippets(...args),
      listFormats: (...args: unknown[]) => listFormats(...args),
      listTokens: (...args: unknown[]) => listTokens(...args),
      createToken: (...args: unknown[]) => createToken(...args),
      revokeToken: (...args: unknown[]) => revokeToken(...args),
      sendTestEvent: (...args: unknown[]) => sendTestEvent(...args),
      ingestConnectorV1: (...args: unknown[]) => ingestConnectorV1(...args),
      exportIncident: (...args: unknown[]) => exportIncident(...args),
    },
  };
});

vi.mock("../api/client", () => ({
  api: {
    listIncidents: (...args: unknown[]) => listIncidents(...args),
    listEvidence: (...args: unknown[]) => listEvidence(...args),
  },
  getApiBaseUrl: () => "http://localhost:8000",
}));

const MOCK_STATUS = {
  gateway_enabled: true,
  accepted_event_types: ["api_log", "custom"],
  last_event_received_at: null,
  source_name: null,
  events_received_count: 0,
  alerts_created_count: 0,
  latest_error: null,
  safety_status: "safe",
};

const MOCK_SCHEMA = {
  schema_version: "1.0",
  endpoint: "/integrations/events",
  required_fields: ["source_name", "message"],
  optional_fields: ["source_type", "service_name", "endpoint", "metadata"],
  accepted_source_types: ["api_log", "application_log", "custom"],
  accepted_source_formats: ["generic_json"],
  example: {
    source_name: "wallet-service",
    source_type: "api_log",
    message: "Synthetic integration test event",
  },
};

const MOCK_SNIPPETS = {
  curl: "curl -X POST http://localhost:8000/integrations/events -H 'Authorization: Bearer $PRIVACYTRACE_TOKEN'",
  python: "requests.post('/integrations/events', json=event)",
  node: "await fetch('/integrations/events', options)",
  docker_log_forwarder: "docker build -t privacytrace-log-forwarder tools/log-forwarder",
  generic_webhook: "POST /integrations/events",
  siem_alert_export: "source_type=siem_alert",
};

const MOCK_FORMATS = {
  inbound: [
    {
      format_id: "generic_json",
      direction: "inbound",
      title: "GENERIC JSON",
      description: "Universal event",
    },
  ],
  outbound: [
    {
      format_id: "privacytrace_json",
      direction: "outbound",
      title: "PRIVACYTRACE JSON",
      description: "Safe export",
    },
  ],
};

const MOCK_TEST_RESULT = {
  status: "accepted",
  integration_event_id: "INT-EVT-TEST",
  safety_status: "safe",
  alert_created: true,
  alert_id: "ALT-LIVE-TEST",
  missing_metadata: [],
  recommendations: [],
  event: {
    masked_values: ["984****567"],
  },
};

const PASS_CHECKS = {
  authentication: "PASS",
  schema: "PASS",
  privacy: "PASS",
  receiver: "PASS",
  accepted: "PASS",
} as const;

function renderPage(path = "/integrations") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <IntegrationsPage />
    </MemoryRouter>,
  );
}

function openTab(label: string) {
  fireEvent.click(screen.getByRole("tab", { name: label }));
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthMock.mockReturnValue(mockUseAuth(ANALYST_USER));
  getStatus.mockResolvedValue(MOCK_STATUS);
  getSchema.mockResolvedValue(MOCK_SCHEMA);
  getSnippets.mockResolvedValue(MOCK_SNIPPETS);
  listFormats.mockResolvedValue(MOCK_FORMATS);
  listTokens.mockResolvedValue({ tokens: [], total: 0 });
  listIncidents.mockResolvedValue([]);
  listEvidence.mockResolvedValue([]);
  sendTestEvent.mockResolvedValue(MOCK_TEST_RESULT);
  ingestConnectorV1.mockResolvedValue({
    httpStatus: 200,
    body: { status: "accepted", event_id: "INT-EVT-V1" },
    usedMachineToken: false,
    checks: PASS_CHECKS,
  });
});

describe("Integrations", () => {
  it("renames the hub and does not put the legacy gateway on Overview", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "Integrations" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Connectors" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Access Tokens" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Developer Setup" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Exports" })).toBeInTheDocument();
    expect(screen.queryByText("Quick Start")).not.toBeInTheDocument();
    expect(screen.queryByText("POST /integrations/events")).not.toBeInTheDocument();
    expect(getSchema).not.toHaveBeenCalled();
    expect(listFormats).not.toHaveBeenCalled();
  });

  it("lists implemented connectors with truthful setup-not-started status", async () => {
    renderPage();
    openTab("Connectors");

    expect(await screen.findByTestId("connector-row-runtime")).toHaveTextContent("PrivacyTrace Runtime Connector");
    expect(screen.getByTestId("connector-row-wazuh")).toHaveTextContent("Wazuh");
    expect(screen.getByTestId("connector-row-github")).toHaveTextContent("EXPERIMENTAL");
    expect(screen.getByTestId("connector-row-scanner")).toHaveTextContent("ScannerBridge-NP");
    expect(screen.getByTestId("connector-row-evidence")).toHaveTextContent("Evidence Import");
    expect(screen.getByTestId("connector-row-runtime")).toHaveTextContent("Available");
    expect(screen.getByTestId("connector-row-wazuh")).toHaveTextContent("Adapter available");
    expect(screen.getByTestId("connector-row-github")).toHaveTextContent("Experimental");
    expect(screen.queryByText("Credential issued")).not.toBeInTheDocument();
    expect(screen.queryByText("Setup not started")).not.toBeInTheDocument();
    expect(screen.queryByText(/^Connected$/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open ScannerBridge" })).toHaveAttribute("href", "/scanner-bridge");
    expect(screen.getByRole("link", { name: "Import evidence" })).toHaveAttribute("href", "/evidence");
  });

  it("opens Runtime setup with the V1 receiver and not the legacy gateway", async () => {
    renderPage();
    openTab("Connectors");
    fireEvent.click(within(await screen.findByTestId("connector-row-runtime")).getByRole("button", { name: "Set up" }));

    const setup = await screen.findByTestId("connector-setup-runtime");
    expect(setup).toHaveTextContent("RuntimeConnector");
    expect(setup).toHaveTextContent(CONNECTOR_V1_EVENTS_PATH);
    expect(setup).toHaveTextContent("Recommended setup");
    expect(setup).toHaveTextContent("Manual setup");
    expect(screen.getByTestId("connector-cli-command")).toHaveTextContent("file:./connectors/cli");
    expect(isVerifiedCliCommand(CONNECTOR_CLI_ADD_RUNTIME)).toBe(true);
    expect(CONNECTOR_CLI_ADD_RUNTIME.trim()).not.toBe("npx privacytrace-connect");
    expect(CONNECTOR_CLI_ADD_RUNTIME).not.toMatch(/^npx privacytrace-connect(\s|$)/);
    expect(setup).not.toHaveTextContent("POST /integrations/events");
    expect(setup).not.toHaveTextContent("pip install privacytrace-runtime");
    expect(screen.getByTestId("connector-v1-receiver")).toHaveTextContent(
      "/integrations/connector/v1/events",
    );
  });

  it("opens Wazuh and GitHub setup from actual adapter and action inputs", async () => {
    renderPage();
    openTab("Connectors");
    fireEvent.click(within(await screen.findByTestId("connector-row-wazuh")).getByRole("button", { name: "Set up" }));
    const wazuh = await screen.findByTestId("connector-setup-wazuh");
    expect(wazuh).toHaveTextContent("custom-privacytrace");
    expect(wazuh).toHaveTextContent(CONNECTOR_V1_EVENTS_PATH);
    expect(wazuh).toHaveTextContent("Recommended setup");
    expect(isVerifiedCliCommand(CONNECTOR_CLI_ADD_WAZUH)).toBe(true);
    expect(wazuh).not.toHaveTextContent("POST /integrations/events");
    fireEvent.click(screen.getByText("Manual setup"));
    fireEvent.click(screen.getByText("Full configuration notes"));
    expect(screen.getByTestId("wazuh-config-disclosure")).toBeInTheDocument();

    fireEvent.click(screen.getByText("← All connectors"));
    fireEvent.click(within(await screen.findByTestId("connector-row-github")).getByRole("button", { name: "Set up" }));
    const github = await screen.findByTestId("connector-setup-github");
    expect(github).toHaveTextContent("endpoint");
    expect(github).toHaveTextContent("PRIVACYTRACE_CONNECTOR_TOKEN");
    expect(isVerifiedCliCommand(CONNECTOR_CLI_ADD_GITHUB)).toBe(true);
    fireEvent.click(screen.getByText("Manual setup"));
    expect(screen.getByTestId("github-workflow-sample")).toHaveTextContent("contents: read");
    expect(github).toHaveTextContent(CONNECTOR_V1_EVENTS_PATH);
    expect(github).not.toHaveTextContent("POST /integrations/events");
    expect(github).toHaveTextContent("CI/CD run and commit provenance");
    expect(github).not.toHaveTextContent("build and deployment provenance");
    expect(github).toHaveTextContent("Not published to GitHub Marketplace");
    expect(github).not.toHaveTextContent("Install from Marketplace");
  });

  it("sends a Connector V1 synthetic test from Runtime setup", async () => {
    renderPage();
    openTab("Connectors");
    fireEvent.click(within(await screen.findByTestId("connector-row-runtime")).getByRole("button", { name: "Set up" }));
    fireEvent.click(await screen.findByRole("button", { name: "Send TEST PRIVACYTRACE RECEIVER event" }));

    await waitFor(() => expect(ingestConnectorV1).toHaveBeenCalledTimes(1));
    expect(sendTestEvent).not.toHaveBeenCalled();
    const result = await screen.findByTestId("connector-test-result");
    expect(result).toHaveTextContent("Authentication");
    expect(result).toHaveTextContent("PASS");
    expect(result).not.toHaveTextContent("9841234567");
  });

  it("keeps the legacy gateway under Developer Setup", async () => {
    renderPage();
    openTab("Developer Setup");
    fireEvent.click(await screen.findByText("Direct Event Gateway (legacy / compatibility)"));

    expect(screen.getByTestId("legacy-gateway")).toHaveTextContent("POST /integrations/events");
    expect(screen.getByTestId("developer-v1-endpoint")).toHaveTextContent(
      "/integrations/connector/v1/events",
    );
    expect(screen.getByTestId("developer-cli")).toHaveTextContent("NOT PUBLISHED");
    expect(screen.getByTestId("developer-cli-command")).toHaveTextContent("file:./connectors/cli");
    expect(screen.getByTestId("developer-cli")).toHaveTextContent("942dc6d5af172d9532b3e631c1a995f54fc387193b24abba37f8d6b780f1a5a5");
    fireEvent.click(screen.getByText("Event schema and code examples"));
    await waitFor(() => expect(getSchema).toHaveBeenCalled());
    expect(screen.getByRole("tab", { name: "Node.js" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Node.js" }));
    expect(screen.getByText(/await fetch/)).toBeInTheDocument();
  });

  it("sends the legacy synthetic test only from Developer Setup", async () => {
    renderPage();
    openTab("Developer Setup");
    fireEvent.click(await screen.findByText("Direct Event Gateway (legacy / compatibility)"));
    fireEvent.click(screen.getByRole("button", { name: "Send Synthetic Test Event" }));

    await waitFor(() => expect(sendTestEvent).toHaveBeenCalledTimes(1));
    const result = await screen.findByTestId("integration-test-result");
    expect(result).toHaveTextContent("Event received");
    expect(
      screen.getByRole("link", { name: "Open alert in Live Monitor" }),
    ).toHaveAttribute("href", "/live-monitor?alert=ALT-LIVE-TEST");
  });

  it("shows a generated integration token once on Access Tokens", async () => {
    const generated = {
      token_id: "ITK-TEST",
      name: "Wallet service forwarder",
      source_name: "wallet-service",
      token_prefix: "ptig_abcd...",
      created_at: "2026-07-14T00:00:00Z",
      last_used_at: null,
      is_active: true,
      token: "ptig_generated_once_for_test",
    };
    createToken.mockResolvedValue(generated);
    renderPage();
    openTab("Access Tokens");

    fireEvent.click(await screen.findByRole("button", { name: "Create access token" }));
    await waitFor(() =>
      expect(createToken).toHaveBeenCalledWith("Wallet service forwarder", "wallet-service"),
    );
    expect(await screen.findByTestId("one-time-token")).toHaveTextContent(
      "ptig_generated_once_for_test",
    );
    expect(screen.getByText("ptig_abcd...")).toBeInTheDocument();
  });

  it("enforces viewer restrictions while keeping catalogue guidance visible", async () => {
    useAuthMock.mockReturnValue(mockUseAuth(VIEWER_USER));
    renderPage();

    expect(await screen.findByRole("heading", { name: "Integrations" })).toBeInTheDocument();
    openTab("Access Tokens");
    expect(await screen.findByText("Token management is restricted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create access token" })).not.toBeInTheDocument();
    openTab("Connectors");
    fireEvent.click(within(screen.getByTestId("connector-row-runtime")).getByRole("button", { name: "Set up" }));
    expect(screen.getByText("Token management is restricted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send TEST PRIVACYTRACE RECEIVER event" })).toBeDisabled();
  });

  it("does not treat a generic token as connector configuration", async () => {
    listTokens.mockResolvedValue({
      tokens: [
        {
          token_id: "ITK-1",
          name: "Wallet",
          source_name: "wallet-api",
          token_prefix: "ptig_ab...",
          created_at: "2026-08-01T00:00:00Z",
          last_used_at: null,
          is_active: true,
        },
      ],
      total: 1,
    });
    renderPage();
    openTab("Connectors");
    expect(await screen.findByTestId("connector-row-runtime")).toHaveTextContent("Available");
    expect(screen.getByTestId("connector-row-runtime")).not.toHaveTextContent("Credential issued");
    expect(screen.getByTestId("connector-row-wazuh")).toHaveTextContent("Adapter available");
    expect(screen.getByTestId("connector-row-wazuh")).not.toHaveTextContent("Credential issued");
    expect(screen.getByTestId("connector-row-github")).toHaveTextContent("Experimental");
    expect(screen.getByTestId("connector-row-github")).not.toHaveTextContent("Credential issued");
  });

  it("does not treat legacy siem_alert or imported deployment_log as connector activity", async () => {
    listEvidence.mockResolvedValue([
      {
        evidence_id: "EV-SIEM",
        evidence_type: "siem_alert",
        source_system: "legacy-gateway",
        parsing_status: "parsed",
        file_hash: null,
        linked_incident_id: null,
        upload_timestamp: new Date().toISOString(),
      },
      {
        evidence_id: "EV-DEP",
        evidence_type: "deployment_log",
        source_system: "evidence-import",
        parsing_status: "parsed",
        file_hash: null,
        linked_incident_id: null,
        upload_timestamp: new Date().toISOString(),
      },
    ]);
    renderPage();
    openTab("Connectors");
    expect(await screen.findByTestId("connector-row-wazuh")).toHaveTextContent("Adapter available");
    expect(screen.getByTestId("connector-row-wazuh")).not.toHaveTextContent("Recent activity");
    expect(screen.getByTestId("connector-row-github")).toHaveTextContent("Experimental");
    expect(screen.getByTestId("connector-row-github")).not.toHaveTextContent("Recent activity");
  });

  it("may show recent activity only for collector-proven connector evidence", async () => {
    listEvidence.mockResolvedValue([
      {
        evidence_id: "EV-RT",
        evidence_type: "runtime_log",
        source_system: "nepalfin-runtime",
        parsing_status: "parsed",
        file_hash: null,
        linked_incident_id: null,
        upload_timestamp: new Date().toISOString(),
        collector_name: "privacytrace_runtime",
      },
    ]);
    renderPage();
    openTab("Connectors");
    expect(await screen.findByTestId("connector-row-runtime")).toHaveTextContent("Recent activity");
    expect(screen.getByTestId("connector-row-wazuh")).not.toHaveTextContent("Recent activity");
    expect(screen.getByTestId("connector-row-github")).not.toHaveTextContent("Recent activity");
  });

  it("clears one-time token plaintext when leaving the creating setup", async () => {
    const generated = {
      token_id: "ITK-ISO",
      name: "Runtime connector",
      source_name: "wallet-api",
      token_prefix: "ptig_iso...",
      created_at: "2026-08-16T00:00:00Z",
      last_used_at: null,
      is_active: true,
      token: "ptig_runtime_once_only",
    };
    createToken.mockResolvedValue(generated);
    renderPage();
    openTab("Connectors");
    fireEvent.click(within(await screen.findByTestId("connector-row-runtime")).getByRole("button", { name: "Set up" }));
    fireEvent.click(await screen.findByRole("button", { name: "Create access token" }));
    await waitFor(() => expect(createToken).toHaveBeenCalled());
    expect(await screen.findByTestId("one-time-token")).toHaveTextContent("ptig_runtime_once_only");
    fireEvent.click(screen.getByText("← All connectors"));
    fireEvent.click(within(await screen.findByTestId("connector-row-wazuh")).getByRole("button", { name: "Set up" }));
    expect(screen.queryByTestId("one-time-token")).not.toBeInTheDocument();
    expect(screen.queryByText("ptig_runtime_once_only")).not.toBeInTheDocument();
  });

  it("documents queue flush without automatic retry", async () => {
    renderPage();
    openTab("Connectors");
    fireEvent.click(within(await screen.findByTestId("connector-row-runtime")).getByRole("button", { name: "Set up" }));
    fireEvent.click(await screen.findByText("Manual setup"));
    fireEvent.click(await screen.findByText("Implementation details"));
    const setup = screen.getByTestId("connector-setup-runtime");
    expect(setup).toHaveTextContent("V1 does not run an automatic background retry worker");
    expect(setup).toHaveTextContent("flush operation");
    expect(setup).not.toHaveTextContent("events queue with a bounded retry");
  });

  it("renders no raw sensitive examples or forbidden claims", async () => {
    const { container } = renderPage();
    await screen.findByRole("heading", { name: "Integrations" });
    const text = container.textContent?.toLowerCase() ?? "";

    for (const forbidden of [
      "siem replacement",
      "works in any environment",
      "production certified",
      "proven cause",
      "confirmed breach",
      "guaranteed fixed",
      "attacker accessed data",
      "incident closed automatically",
    ]) {
      expect(text).not.toContain(forbidden);
    }
    for (const rawMarker of [
      "9841234567",
      "eyjhb",
      "-----begin rsa private key",
      "hunter2",
      "sk_test_",
    ]) {
      expect(text).not.toContain(rawMarker);
    }
  });

  it("preserves /integrations?tab=sources as the Connectors tab", async () => {
    renderPage("/integrations?tab=sources");
    expect(await screen.findByTestId("connector-row-runtime")).toBeInTheDocument();
  });
});
