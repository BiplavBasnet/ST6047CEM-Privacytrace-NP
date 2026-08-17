import type { EvidenceFile } from "../../api/client";
import {
  CONNECTOR_V1_EVENTS_PATH,
  connectorReceiverUrl,
  isLocalDevBase,
} from "../../api/integrationsClient";
import { relativeTime } from "../ui/primitives";

export const CONNECTOR_V1_PATH = CONNECTOR_V1_EVENTS_PATH;
export const RECENT_ACTIVITY_MS = 15 * 60 * 1000;

export const CONNECTOR_CLI_VERSION = "0.1.0";
export const CONNECTOR_CLI_TGZ = "privacytrace-connect-0.1.0.tgz";
export const CONNECTOR_CLI_SHA256 =
  "942dc6d5af172d9532b3e631c1a995f54fc387193b24abba37f8d6b780f1a5a5";
export const CONNECTOR_CLI_ADD_RUNTIME =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add runtime";
export const CONNECTOR_CLI_ADD_WAZUH =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add wazuh";
export const CONNECTOR_CLI_ADD_GITHUB =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add github-actions";

export function isVerifiedCliCommand(command: string): boolean {
  const trimmed = command.trim();
  if (trimmed === "npx privacytrace-connect" || trimmed.startsWith("npx privacytrace-connect ")) {
    return false;
  }
  return trimmed.includes("file:") || trimmed.includes(".tgz");
}

export const CONNECTOR_COLLECTORS: Record<SetupKind, string> = {
  runtime: "privacytrace_runtime",
  wazuh: "custom-privacytrace",
  github: "privacytrace_github_action",
};

export type SetupKind = "runtime" | "wazuh" | "github";
export type CatalogKind = SetupKind | "scanner" | "evidence";
export type StatusTone = "ok" | "warn" | "muted" | "danger";

export type ConnectorStatus = {
  label: string;
  tone: StatusTone;
  detail: string;
  caveat?: string;
};

export function latestCollectorEvidence(
  items: EvidenceFile[],
  collectorName: string,
): EvidenceFile | undefined {
  return items
    .filter((item) => item.collector_name === collectorName && item.upload_timestamp)
    .sort(
      (a, b) =>
        new Date(b.upload_timestamp ?? 0).getTime() -
        new Date(a.upload_timestamp ?? 0).getTime(),
    )[0];
}

function isRecent(iso: string | null | undefined): boolean {
  if (!iso) return false;
  const then = new Date(iso).getTime();
  return !Number.isNaN(then) && Date.now() - then < RECENT_ACTIVITY_MS;
}

export function pushConnectorStatus(opts: {
  kind: CatalogKind;
  evidence?: EvidenceFile;
  receiverPaused: boolean;
}): ConnectorStatus {
  const { kind, evidence, receiverPaused } = opts;
  if (kind === "scanner") {
    return {
      label: "Ready",
      tone: "ok",
      detail: "Use ScannerBridge-NP for Semgrep, Gitleaks and Trivy.",
    };
  }
  if (kind === "evidence") {
    return {
      label: "Available",
      tone: "muted",
      detail: "Import supporting or manual evidence. Not Controlled Retest.",
    };
  }
  if (receiverPaused) {
    return {
      label: "Receiver paused",
      tone: "warn",
      detail: "Start Live Monitor before connectors can deliver events.",
    };
  }
  if (evidence?.collector_name === CONNECTOR_COLLECTORS[kind] && isRecent(evidence.upload_timestamp)) {
    return {
      label: "Recent activity",
      tone: "ok",
      detail: `Last event ${relativeTime(evidence.upload_timestamp).toLowerCase()}`,
    };
  }
  if (kind === "github") {
    return {
      label: "Experimental",
      tone: "warn",
      detail: "Repository/local Action. Real GitHub-hosted workflow pending.",
    };
  }
  if (kind === "wazuh") {
    return {
      label: "Adapter available",
      tone: "muted",
      detail: "Local adapter included. A generic SIEM alert is not Wazuh activity.",
    };
  }
  return {
    label: "Available",
    tone: "muted",
    detail: "Create a credential on Access Tokens, then install the runtime connector.",
  };
}

export function runtimePythonExample(): string {
  return `import os
from connectors.runtime.client import RuntimeConnector

connector = RuntimeConnector(
    endpoint=os.environ["PRIVACYTRACE_CONNECTOR_URL"],
    token=os.environ["PRIVACYTRACE_CONNECTOR_TOKEN"],
    source=os.environ.get("PRIVACYTRACE_SERVICE", "wallet-api"),
)
connector.emit(
    data={
        "service": os.environ.get("PRIVACYTRACE_SERVICE", "wallet-api"),
        "environment": os.environ.get("PRIVACYTRACE_ENVIRONMENT", "production"),
        "message_summary": "Synthetic runtime event. No customer data.",
    }
)`;
}

export function runtimeEnvExample(receiverUrl: string): string {
  return `PRIVACYTRACE_CONNECTOR_URL=${receiverUrl}
PRIVACYTRACE_CONNECTOR_TOKEN=<store in a secret manager — never commit>
PRIVACYTRACE_SERVICE=wallet-api
PRIVACYTRACE_ENVIRONMENT=production`;
}

export function wazuhInstallCommands(): string {
  return `# On the Wazuh Manager — copy these commands; do not run them from this page.
cp connectors/wazuh/custom-privacytrace /var/ossec/integrations/custom-privacytrace
chown root:wazuh /var/ossec/integrations/custom-privacytrace
chmod 750 /var/ossec/integrations/custom-privacytrace`;
}

export function wazuhOssecExample(receiverUrl: string): string {
  return `<!-- EXAMPLE — adapt filters to local Wazuh rules. Do not forward every alert. -->
<ossec_config>
  <integration>
    <name>custom-privacytrace</name>
    <hook_url>${receiverUrl}</hook_url>
    <api_key>YOUR_PRIVACYTRACE_TOKEN</api_key>
    <level>10</level>
    <group>syscheck,rootcheck</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>`;
}

export function githubWorkflowExample(receiverUrl: string): string {
  return `# Repository/local Action — not published to GitHub Marketplace.
# Set Actions variable PRIVACYTRACE_CONNECTOR_URL to:
# ${receiverUrl}
permissions:
  contents: read

jobs:
  privacytrace:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: PrivacyTrace provenance
        uses: ./connectors/github-actions
        with:
          endpoint: \${{ vars.PRIVACYTRACE_CONNECTOR_URL }}
          token: \${{ secrets.PRIVACYTRACE_CONNECTOR_TOKEN }}
          repo: \${{ github.repository }}
          sha: \${{ github.sha }}
          run_id: \${{ github.run_id }}
          workflow: \${{ github.workflow }}`;
}

export function receiverCaption(base = connectorReceiverUrl()): string {
  const local = isLocalDevBase();
  return local
    ? `${base}  (LOCAL DEVELOPMENT example — replace with the organisation PrivacyTrace URL)`
    : base;
}

export { connectorReceiverUrl, isLocalDevBase };
