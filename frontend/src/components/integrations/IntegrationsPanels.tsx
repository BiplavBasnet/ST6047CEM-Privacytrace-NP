import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  integrationsApi,
  syntheticConnectorEvent,
  type ConnectorV1TestResult,
  type IntegrationToken,
} from "../../api/integrationsClient";
import { sanitizeString } from "../../utils/safety";
import CollapsibleSection from "../CollapsibleSection";
import SafeErrorMessage from "../SafeErrorMessage";
import {
  CONNECTOR_CLI_ADD_GITHUB,
  CONNECTOR_CLI_ADD_RUNTIME,
  CONNECTOR_CLI_ADD_WAZUH,
  connectorReceiverUrl,
  githubWorkflowExample,
  isLocalDevBase,
  runtimeEnvExample,
  runtimePythonExample,
  wazuhInstallCommands,
  wazuhOssecExample,
  type CatalogKind,
  type ConnectorStatus,
  type SetupKind,
  type StatusTone,
} from "./connectorGuide";

const TONE_DOT: Record<StatusTone, string> = {
  ok: "bg-teal-600",
  warn: "bg-amber-500",
  muted: "bg-slate-400",
  danger: "bg-red-600",
};

export function StatusDot({ status }: { status: ConnectorStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-navy-900">
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${TONE_DOT[status.tone]}`} aria-hidden />
      {sanitizeString(status.label)}
    </span>
  );
}

export function CopyField({
  label,
  value,
  testId,
  multiline = false,
}: {
  label: string;
  value: string;
  testId?: string;
  multiline?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const safe = sanitizeString(value);
  return (
    <div data-testid={testId} className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-ink-subtle">{label}</p>
        <button
          type="button"
          className="text-xs font-medium text-accent hover:underline"
          onClick={() => {
            void navigator.clipboard?.writeText(value).then(() => {
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            });
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre
        className={`overflow-auto rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs text-navy-900 ${
          multiline ? "max-h-64 whitespace-pre-wrap" : "break-all whitespace-pre-wrap"
        }`}
      >
        {safe}
      </pre>
    </div>
  );
}

export function TokenPanel({
  canManage,
  tokens,
  busy,
  oneTimeToken,
  defaultName,
  defaultSource,
  onCreate,
  onRevoke,
}: {
  canManage: boolean;
  tokens: IntegrationToken[];
  busy: boolean;
  oneTimeToken: string | null;
  defaultName: string;
  defaultSource: string;
  onCreate: (name: string, source: string) => void;
  onRevoke: (tokenId: string) => void;
}) {
  const [name, setName] = useState(defaultName);
  const [source, setSource] = useState(defaultSource);
  if (!canManage) {
    return (
      <SafeErrorMessage
        title="Token management is restricted"
        message="Your role cannot create or revoke integration tokens."
      />
    );
  }
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
        <label className="text-sm font-medium text-navy-900">
          Connector / application name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            className="field-control mt-1 w-full"
          />
        </label>
        <label className="text-sm font-medium text-navy-900">
          Source / service id
          <input
            value={source}
            onChange={(event) => setSource(event.target.value)}
            className="field-control mt-1 w-full"
          />
        </label>
        <button
          type="button"
          onClick={() => onCreate(name, source)}
          disabled={busy || name.trim().length < 3 || !source.trim()}
          className="btn-primary self-end"
        >
          Create access token
        </button>
      </div>
      <p className="text-xs text-ink-muted">
        Create an integration credential for this connector. The token is a shared machine
        credential — it is not bound to a connector type on the server.
      </p>
      {oneTimeToken ? (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3" data-testid="one-time-token">
          <p className="text-xs font-semibold text-amber-900">Shown once — store as a secret</p>
          <code className="mt-1 block break-all text-xs text-amber-950">{oneTimeToken}</code>
          <button
            type="button"
            onClick={() => void navigator.clipboard?.writeText(oneTimeToken)}
            className="mt-2 text-xs font-medium text-amber-900 underline"
          >
            Copy token
          </button>
        </div>
      ) : null}
      {tokens.length ? (
        <div className="-mx-1 overflow-x-auto">
          <table className="data-table text-xs">
            <thead>
              <tr>
                <th>Name</th>
                <th>Source</th>
                <th>Prefix</th>
                <th>Status</th>
                <th>Last used</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.token_id}>
                  <td className="font-medium text-navy-900">{sanitizeString(token.name)}</td>
                  <td>{sanitizeString(token.source_name)}</td>
                  <td className="mono-id">{sanitizeString(token.token_prefix)}</td>
                  <td>{token.is_active ? "Active" : "Inactive"}</td>
                  <td>{formatDate(token.last_used_at)}</td>
                  <td className="text-right">
                    {token.is_active ? (
                      <button
                        type="button"
                        onClick={() => onRevoke(token.token_id)}
                        disabled={busy}
                        className="text-xs font-medium text-red-700 underline"
                      >
                        Revoke
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-xs text-ink-muted">No access tokens yet.</p>
      )}
    </div>
  );
}

function SetupStep({
  number,
  title,
  children,
}: {
  number: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border-t border-slate-200 pt-4">
      <p className="text-xs font-semibold text-ink-subtle">Step {number}</p>
      <h3 className="mt-1 text-sm font-semibold text-navy-900">{title}</h3>
      <div className="mt-3 space-y-3">{children}</div>
    </section>
  );
}

function TestResult({ result }: { result: ConnectorV1TestResult }) {
  const rows: Array<[string, ConnectorV1TestResult["checks"][keyof ConnectorV1TestResult["checks"]]]> = [
    ["Authentication", result.checks.authentication],
    ["Schema validation", result.checks.schema],
    ["Privacy safety", result.checks.privacy],
    ["Receiver", result.checks.receiver],
    ["Event accepted", result.checks.accepted],
  ];
  return (
    <div className="grid gap-2 text-sm sm:grid-cols-2" data-testid="connector-test-result">
      {rows.map(([label, value]) => (
        <div key={label} className="flex items-center justify-between border border-slate-200 px-3 py-2">
          <span className="text-xs text-ink-muted">{label}</span>
          <span className={value === "PASS" ? "text-xs font-semibold text-teal-800" : "text-xs font-semibold text-red-700"}>
            {value}
          </span>
        </div>
      ))}
      <p className="text-xs text-ink-muted sm:col-span-2">
        {result.usedMachineToken
          ? "This test used the token shown on this page."
          : "This test used your signed-in session. It proves the receiver, not the machine token, until the source system sends an event."}
        {result.body?.status === "duplicate" ? " Duplicate of an earlier event." : ""}
      </p>
    </div>
  );
}

export function ConnectorSetupPanel({
  kind,
  status,
  canManageTokens,
  canIngest,
  tokens,
  busy,
  oneTimeToken,
  receiverPaused,
  onCreateToken,
  onRevokeToken,
  onTested,
}: {
  kind: SetupKind;
  status: ConnectorStatus;
  canManageTokens: boolean;
  canIngest: boolean;
  tokens: IntegrationToken[];
  busy: boolean;
  oneTimeToken: string | null;
  receiverPaused: boolean;
  onCreateToken: (name: string, source: string) => void;
  onRevokeToken: (tokenId: string) => void;
  onTested: (kind: SetupKind, result: ConnectorV1TestResult) => void;
}) {
  const receiver = connectorReceiverUrl();
  const [testResult, setTestResult] = useState<ConnectorV1TestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);

  async function runTest() {
    setTesting(true);
    setTestError(null);
    setTestResult(null);
    const envelope =
      kind === "wazuh"
        ? syntheticConnectorEvent(
            "np.privacytrace.wazuh.alert.v1",
            {
              rule_id: "ui-test",
              rule_level: 10,
              severity: "info",
              message_summary: "Synthetic Wazuh adapter test. No customer data.",
            },
            "/wazuh/custom-privacytrace",
          )
        : kind === "github"
          ? syntheticConnectorEvent(
              "np.privacytrace.cicd.github.run.v1",
              {
                repo: "privacytrace/ui-test",
                sha: "0000000",
                run_id: "0",
                workflow: "integrations-ui-test",
                severity: "info",
                message_summary: "Synthetic GitHub Actions test. No customer data.",
              },
              "/github/privacytrace/ui-test",
            )
          : syntheticConnectorEvent("np.privacytrace.runtime.event.v1", {
              service: "wallet-api",
              environment: "scenario-lab",
              severity: "info",
              component: "integrations-ui",
              message_summary: "Synthetic PrivacyTrace connector test. No customer data.",
            });
    try {
      const result = await integrationsApi.ingestConnectorV1(envelope, oneTimeToken ?? undefined);
      setTestResult(result);
      onTested(kind, result);
    } catch (err) {
      setTestError(err instanceof Error ? err.message : "Connector test failed");
    } finally {
      setTesting(false);
    }
  }

  const titles: Record<SetupKind, { title: string; subtitle: string; badge?: string }> = {
    runtime: {
      title: "PrivacyTrace Runtime Connector",
      subtitle: "Connect a Python application to PrivacyTrace-NP.",
    },
    wazuh: {
      title: "Wazuh",
      subtitle: "Forward selected Wazuh alerts to PrivacyTrace-NP.",
    },
    github: {
      title: "GitHub Actions",
      subtitle: "Send safe CI/CD run and commit provenance to PrivacyTrace.",
      badge: "EXPERIMENTAL",
    },
  };
  const meta = titles[kind];
  const defaults =
    kind === "runtime"
      ? { name: "Runtime connector", source: "wallet-api" }
      : kind === "wazuh"
        ? { name: "Wazuh adapter", source: "wazuh" }
        : { name: "GitHub Actions", source: "github-actions" };

  return (
    <div className="space-y-4" data-testid={`connector-setup-${kind}`}>
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-slate-200 pb-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold text-navy-900">{meta.title}</h2>
            {meta.badge ? (
              <span className="rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold tracking-wide text-amber-900">
                {meta.badge}
              </span>
            ) : null}
          </div>
          <p className="mt-1 text-xs text-ink-muted">{meta.subtitle}</p>
        </div>
        <div className="text-right">
          <StatusDot status={status} />
          <p className="mt-1 text-xs text-ink-muted">{sanitizeString(status.detail)}</p>
        </div>
      </div>

      <SetupStep number="1" title="Credential">
        <TokenPanel
          key={kind}
          canManage={canManageTokens}
          tokens={tokens}
          busy={busy}
          oneTimeToken={oneTimeToken}
          defaultName={defaults.name}
          defaultSource={defaults.source}
          onCreate={onCreateToken}
          onRevoke={onRevokeToken}
        />
      </SetupStep>

      {kind === "runtime" ? (
        <>
          <SetupStep number="2" title="Recommended setup">
            <p className="text-xs text-ink-muted">
              From the PrivacyTrace repository root, after creating the token above. Public npm
              registry distribution: NOT PUBLISHED.
            </p>
            <CopyField
              label="Verified local command"
              value={CONNECTOR_CLI_ADD_RUNTIME}
              testId="connector-cli-command"
            />
          </SetupStep>
          <CollapsibleSection summary="Manual setup" testId="runtime-manual-setup">
            <p className="text-xs text-ink-muted">
              Reference Python connector included with PrivacyTrace-NP. There is no public PyPI
              package named privacytrace-runtime. The client reads constructor arguments — wrap them
              with environment variables yourself. Do not put the token in source code.
            </p>
            <div className="mt-3 space-y-3">
              <CopyField
                label="PrivacyTrace connector receiver"
                value={receiver}
                testId="connector-v1-receiver"
              />
              {isLocalDevBase() ? (
                <p className="text-xs text-ink-subtle">LOCAL DEVELOPMENT example — replace the host for a deployed organisation.</p>
              ) : null}
              <CopyField label="Environment variables" value={runtimeEnvExample(receiver)} multiline />
              <CopyField label="Application initialisation" value={runtimePythonExample()} multiline />
              <CollapsibleSection summary="Implementation details" testId="runtime-implementation">
                <p className="text-xs text-ink-muted">
                  Source: connectors/runtime/client.py. Class RuntimeConnector(endpoint, token, source)
                  with emit(data=...). Optional logging: PrivacyTraceLogHandler. After CLI install,
                  import from privacytrace_runtime in the target application venv — never pip-install
                  that package into the PrivacyTrace server venv. Failures never raise into the host
                  application. Failed sends are stored in a bounded in-memory queue. Queued events
                  can be retried through the connector's flush operation. V1 does not run an
                  automatic background retry worker.
                </p>
              </CollapsibleSection>
              <CollapsibleSection summary="How PrivacyTrace protects connector data" testId="runtime-privacy">
                <ul className="list-disc space-y-1 pl-5 text-xs text-ink-muted">
                  <li>The connector sends structured privacy-safe evidence only.</li>
                  <li>Raw secrets should not be transmitted.</li>
                  <li>The server independently validates payload safety.</li>
                  <li>PrivacyTrace remains authoritative for detection and correlation.</li>
                </ul>
              </CollapsibleSection>
            </div>
          </CollapsibleSection>
          <SetupStep number="3" title="Test">
            <TestControls
              canIngest={canIngest}
              receiverPaused={receiverPaused}
              testing={testing || busy}
              onTest={() => void runTest()}
              testError={testError}
              testResult={testResult}
              note="TEST PRIVACYTRACE RECEIVER — synthetic data only. Live Monitor must be running. This does not verify an external Runtime Connector."
            />
          </SetupStep>
          <SetupStep number="4" title="Activity">
            <ActivityNote status={status} />
          </SetupStep>
        </>
      ) : null}

      {kind === "wazuh" ? (
        <>
          <SetupStep number="2" title="Recommended setup">
            <p className="text-xs text-ink-muted">
              Stages adapter files and prints Manager apply steps. Does not edit production
              ossec.conf, sudo, or restart. Public npm registry distribution: NOT PUBLISHED.
            </p>
            <CopyField
              label="Verified local command"
              value={CONNECTOR_CLI_ADD_WAZUH}
              testId="connector-cli-command"
            />
          </SetupStep>
          <CollapsibleSection summary="Manual setup" testId="wazuh-manual-setup">
            <p className="text-xs text-ink-muted">
              Adapter included with PrivacyTrace-NP. Not a Wazuh Marketplace package. Custom
              integration names must start with custom-.
            </p>
            <div className="mt-3 space-y-3">
              <CopyField label="Install on the Wazuh Manager" value={wazuhInstallCommands()} multiline />
              <CollapsibleSection summary="Implementation details">
                <p className="text-xs text-ink-muted">
                  Source: connectors/wazuh/custom-privacytrace. Arguments: alert file, api_key,
                  hook_url. The adapter never forwards full_log or nested data.*.
                </p>
              </CollapsibleSection>
              <CopyField
                label="PrivacyTrace connector receiver"
                value={receiver}
                testId="connector-v1-receiver"
              />
              <CopyField
                label="ossec.conf example"
                value={wazuhOssecExample(receiver)}
                multiline
                testId="wazuh-config-example"
              />
              <CollapsibleSection summary="Full configuration notes" testId="wazuh-config-disclosure">
                <ul className="list-disc space-y-1 pl-5 text-xs text-ink-muted">
                  <li>hook_url must be the Connector V1 receiver, not the legacy event gateway.</li>
                  <li>api_key is the access token created in step 1.</li>
                  <li>Filter by level and group — do not forward every Wazuh event.</li>
                  <li>Do not put the real token into screenshots, tickets, or this page after the one-time display.</li>
                </ul>
              </CollapsibleSection>
            </div>
          </CollapsibleSection>
          <SetupStep number="3" title="Verify activity">
            <p className="text-xs text-ink-muted">
              Adapter status: Available. Local adapter path verified. This page does not claim a
              real Wazuh Manager has been verified.
            </p>
            <TestControls
              canIngest={canIngest}
              receiverPaused={receiverPaused}
              testing={testing || busy}
              onTest={() => void runTest()}
              testError={testError}
              testResult={testResult}
              note="TEST PRIVACYTRACE RECEIVER — synthetic data only. This does not prove a live Wazuh Manager."
            />
            <ActivityNote status={status} />
          </SetupStep>
        </>
      ) : null}

      {kind === "github" ? (
        <>
          <SetupStep number="2" title="Recommended setup">
            <p className="text-xs text-ink-muted">
              Copies a local Action and workflow. Does not commit, push, or call the GitHub secrets
              API. Public npm registry distribution: NOT PUBLISHED.
            </p>
            <CopyField
              label="Verified local command"
              value={CONNECTOR_CLI_ADD_GITHUB}
              testId="connector-cli-command"
            />
          </SetupStep>
          <CollapsibleSection summary="Manual setup" testId="github-manual-setup">
            <p className="text-xs text-ink-muted">
              Store the token as a GitHub Actions secret named PRIVACYTRACE_CONNECTOR_TOKEN. Store
              the receiver URL as a variable named PRIVACYTRACE_CONNECTOR_URL. Never put the token
              in workflow YAML, this page after the one-time display, or logs.
            </p>
            <div className="mt-3 space-y-3">
              <CopyField
                label="PrivacyTrace connector receiver"
                value={receiver}
                testId="connector-v1-receiver"
              />
              <p className="text-xs text-ink-muted">
                Repository/local Action — Bachelor prototype. Not published to GitHub Marketplace.
                Inputs match connectors/github-actions/action.yml: endpoint, token, repo, sha, run_id,
                workflow.
              </p>
              <CopyField
                label="Workflow sample"
                value={githubWorkflowExample(receiver)}
                multiline
                testId="github-workflow-sample"
              />
              <CollapsibleSection summary="What is sent">
                <p className="text-xs text-ink-muted">
                  Safe fields only: repository, commit SHA, workflow, run ID. The Action does not send
                  GitHub secrets, commit messages, pull request titles, source code, or customer data.
                </p>
              </CollapsibleSection>
            </div>
          </CollapsibleSection>
          <SetupStep number="3" title="Verify activity">
            <p className="text-xs text-ink-muted">
              LOCAL CONTRACT VERIFIED. REAL GITHUB WORKFLOW: PENDING.
            </p>
            <TestControls
              canIngest={canIngest}
              receiverPaused={receiverPaused}
              testing={testing || busy}
              onTest={() => void runTest()}
              testError={testError}
              testResult={testResult}
              note="TEST PRIVACYTRACE RECEIVER — synthetic data only. This does not prove a hosted GitHub workflow."
            />
            <ActivityNote status={status} />
          </SetupStep>
        </>
      ) : null}
    </div>
  );
}

function TestControls({
  canIngest,
  receiverPaused,
  testing,
  onTest,
  testError,
  testResult,
  note,
}: {
  canIngest: boolean;
  receiverPaused: boolean;
  testing: boolean;
  onTest: () => void;
  testError: string | null;
  testResult: ConnectorV1TestResult | null;
  note: string;
}) {
  return (
    <>
      <p className="text-xs text-ink-muted">{note}</p>
      <button
        type="button"
        onClick={onTest}
        disabled={!canIngest || testing || receiverPaused}
        className="btn-primary"
      >
        Send TEST PRIVACYTRACE RECEIVER event
      </button>
      {receiverPaused ? (
        <Link to="/live-monitor" className="ml-3 text-sm font-medium text-accent hover:underline">
          Start Live Monitor
        </Link>
      ) : null}
      {testError ? <SafeErrorMessage title="Connector test" message={testError} /> : null}
      {testResult ? <TestResult result={testResult} /> : null}
    </>
  );
}

function ActivityNote({ status }: { status: ConnectorStatus }) {
  return (
    <div className="border border-slate-200 px-3 py-2" data-testid="connector-activity">
      <StatusDot status={status} />
      <p className="mt-1 text-xs text-ink-muted">{sanitizeString(status.detail)}</p>
      {status.caveat ? <p className="mt-1 text-xs text-ink-subtle">{sanitizeString(status.caveat)}</p> : null}
    </div>
  );
}

export function CatalogRow({
  kind,
  title,
  description,
  tools,
  status,
  badge,
  action,
}: {
  kind: CatalogKind;
  title: string;
  description: string;
  tools?: string;
  status: ConnectorStatus;
  badge?: string;
  action: ReactNode;
}) {
  return (
    <tr data-testid={`connector-row-${kind}`}>
      <td className="align-top">
        <p className="font-medium text-navy-900">{title}</p>
        {badge ? (
          <span className="mt-1 inline-block rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold tracking-wide text-amber-900">
            {badge}
          </span>
        ) : null}
        <p className="mt-1 text-xs text-ink-muted">{description}</p>
        {tools ? <p className="mt-1 text-xs text-ink-subtle">{tools}</p> : null}
      </td>
      <td className="align-top">
        <StatusDot status={status} />
        <p className="mt-1 text-xs text-ink-muted">{sanitizeString(status.detail)}</p>
      </td>
      <td className="align-top text-right">{action}</td>
    </tr>
  );
}

function formatDate(value: string | null): string {
  if (!value) return "Not yet";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" : parsed.toLocaleString();
}
