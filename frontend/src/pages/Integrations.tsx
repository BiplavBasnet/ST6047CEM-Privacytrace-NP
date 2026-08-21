import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type EvidenceFile } from "../api/client";
import {
  integrationsApi,
  LEGACY_EVENTS_PATH,
  type ConnectorV1TestResult,
  type IntegrationEventIngestResponse,
  type IntegrationFormatsResponse,
  type IntegrationGatewayStatus,
  type IntegrationSchema,
  type IntegrationSnippets,
  type IntegrationToken,
} from "../api/integrationsClient";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import CopyCurlExample from "../components/CopyCurlExample";
import PageHeader from "../components/PageHeader";
import SocExportPanel from "../components/SocExportPanel";
import { LoadingState } from "../components/LoadingError";
import SafeErrorMessage from "../components/SafeErrorMessage";
import SiemWebhookGuide from "../components/SiemWebhookGuide";
import {
  CatalogRow,
  ConnectorSetupPanel,
  CopyField,
  TokenPanel,
} from "../components/integrations/IntegrationsPanels";
import {
  CONNECTOR_CLI_ADD_RUNTIME,
  CONNECTOR_CLI_SHA256,
  CONNECTOR_CLI_TGZ,
  CONNECTOR_CLI_VERSION,
  CONNECTOR_COLLECTORS,
  CONNECTOR_V1_PATH,
  connectorReceiverUrl,
  latestCollectorEvidence,
  pushConnectorStatus,
  type CatalogKind,
  type ConnectorStatus,
  type SetupKind,
} from "../components/integrations/connectorGuide";
import { useAuth } from "../context/AuthContext";
import { SegmentedTabs } from "../components/ui/primitives";
import { sanitizeString } from "../utils/safety";

type SnippetKey = keyof IntegrationSnippets;
type TabId = "overview" | "connectors" | "tokens" | "developer" | "exports";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "connectors", label: "Connectors" },
  { id: "tokens", label: "Access Tokens" },
  { id: "developer", label: "Developer Setup" },
  { id: "exports", label: "Exports" },
];

const SNIPPET_TABS: Array<{ key: SnippetKey; label: string }> = [
  { key: "curl", label: "curl" },
  { key: "python", label: "Python" },
  { key: "node", label: "Node.js" },
  { key: "docker_log_forwarder", label: "Docker forwarder" },
  { key: "generic_webhook", label: "Webhook" },
  { key: "siem_alert_export", label: "Alert export" },
];

const SETUP_KINDS: SetupKind[] = ["runtime", "wazuh", "github"];

export default function IntegrationsPage() {
  const { can } = useAuth();
  const canIngest = can("integration:ingest");
  const canManageTokens = can("integration:token_manage");
  const canExport = can("integration:export");
  const canReadEvidence = can("evidence:read");
  const [params, setParams] = useSearchParams();
  const tab = parseTab(params.get("tab"));
  const setup = parseSetup(params.get("setup"));

  const [gatewayStatus, setGatewayStatus] = useState<IntegrationGatewayStatus | null>(null);
  const [schema, setSchema] = useState<IntegrationSchema | null>(null);
  const [snippets, setSnippets] = useState<IntegrationSnippets | null>(null);
  const [formats, setFormats] = useState<IntegrationFormatsResponse | null>(null);
  const [tokens, setTokens] = useState<IntegrationToken[]>([]);
  const [evidence, setEvidence] = useState<EvidenceFile[]>([]);
  const [activeSnippet, setActiveSnippet] = useState<SnippetKey>("curl");
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [tokenCreatedFor, setTokenCreatedFor] = useState<string | null>(null);
  const [legacyTest, setLegacyTest] = useState<IntegrationEventIngestResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [advancedLoading, setAdvancedLoading] = useState(false);
  const [advancedLoaded, setAdvancedLoaded] = useState(false);
  const [advancedError, setAdvancedError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const results = await Promise.allSettled([
      integrationsApi.getStatus(),
      canManageTokens ? integrationsApi.listTokens() : Promise.resolve({ tokens: [], total: 0 }),
      canReadEvidence ? api.listEvidence() : Promise.resolve([] as EvidenceFile[]),
    ]);
    const failures: string[] = [];
    if (results[0].status === "fulfilled") setGatewayStatus(results[0].value);
    else failures.push("receiver status");
    if (results[1].status === "fulfilled") setTokens(results[1].value.tokens);
    else failures.push("token list");
    if (results[2].status === "fulfilled") setEvidence(results[2].value);
    else failures.push("recent evidence");
    if (failures.length) {
      setError(`Some integration data is unavailable: ${failures.join(", ")}. Setup instructions remain available.`);
    }
    setLoading(false);
  }, [canManageTokens, canReadEvidence]);

  const loadAdvanced = useCallback(async () => {
    if (advancedLoaded || advancedLoading) return;
    setAdvancedLoading(true);
    setAdvancedError(null);
    const results = await Promise.allSettled([
      integrationsApi.getSchema(),
      integrationsApi.listFormats(),
      integrationsApi.getSnippets(),
    ]);
    const failures: string[] = [];
    if (results[0].status === "fulfilled") setSchema(results[0].value);
    else failures.push("schema");
    if (results[1].status === "fulfilled") setFormats(results[1].value);
    else failures.push("formats");
    if (results[2].status === "fulfilled") setSnippets(results[2].value);
    else failures.push("additional snippets");
    if (failures.length) {
      setAdvancedError(`Could not load: ${failures.join(", ")}. Other integration controls are unaffected.`);
    }
    setAdvancedLoaded(true);
    setAdvancedLoading(false);
  }, [advancedLoaded, advancedLoading]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (tab === "developer" || tab === "exports") void loadAdvanced();
  }, [tab, loadAdvanced]);

  const tokenSurface = setup ?? (tab === "tokens" ? "tokens" : null);
  useEffect(() => {
    if (tokenCreatedFor && tokenSurface !== tokenCreatedFor) {
      setOneTimeToken(null);
    }
  }, [tokenSurface, tokenCreatedFor]);

  const visibleOneTimeToken =
    tokenCreatedFor && tokenSurface === tokenCreatedFor ? oneTimeToken : null;

  function setTab(id: string) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set("tab", id);
        next.delete("setup");
        return next;
      },
      { replace: true },
    );
  }

  function openSetup(kind: SetupKind) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set("tab", "connectors");
        next.set("setup", kind);
        return next;
      },
      { replace: true },
    );
  }

  async function createToken(name: string, source: string) {
    setBusy(true);
    setError(null);
    setOneTimeToken(null);
    try {
      const created = await integrationsApi.createToken(name, source);
      setOneTimeToken(created.token);
      setTokenCreatedFor(setup ?? "tokens");
      setTokens((current) => [created, ...current]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function revokeToken(tokenId: string) {
    setBusy(true);
    setError(null);
    try {
      await integrationsApi.revokeToken(tokenId);
      setTokens((current) =>
        current.map((item) =>
          item.token_id === tokenId ? { ...item, is_active: false } : item,
        ),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token revocation failed");
    } finally {
      setBusy(false);
    }
  }

  async function sendLegacyTest() {
    setBusy(true);
    setError(null);
    setLegacyTest(null);
    try {
      const result = await integrationsApi.sendTestEvent();
      setLegacyTest(result);
      setGatewayStatus(await integrationsApi.getStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Synthetic test event failed");
    } finally {
      setBusy(false);
    }
  }

  function onConnectorTested(_kind: SetupKind, _result: ConnectorV1TestResult) {
    /* Receiver test must not mark the connector as externally verified. */
  }

  const receiverPaused = gatewayStatus ? !gatewayStatus.gateway_enabled : false;
  const statuses = useMemo(
    () => statusMap({ evidence, receiverPaused }),
    [evidence, receiverPaused],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Integrations" }]}
        title="Integrations"
        description="Connect applications, security platforms, CI/CD and supporting evidence to PrivacyTrace-NP."
      />

      {loading ? <LoadingState message="Loading integrations..." /> : null}
      {error ? <SafeErrorMessage title="Partial integration data" message={error} /> : null}

      <SegmentedTabs
        tabs={TABS}
        value={tab}
        onChange={setTab}
      />

      {tab === "overview" ? (
        <Overview
          gatewayStatus={gatewayStatus}
          statuses={statuses}
          onOpenConnectors={() => setTab("connectors")}
          onOpenSetup={openSetup}
        />
      ) : null}

      {tab === "connectors" ? (
        setup ? (
          <div className="space-y-3">
            <button
              type="button"
              className="text-sm font-medium text-accent hover:underline"
              onClick={() => setTab("connectors")}
            >
              ← All connectors
            </button>
            <ConnectorSetupPanel
              kind={setup}
              status={statuses[setup]}
              canManageTokens={canManageTokens}
              canIngest={canIngest}
              tokens={tokens}
              busy={busy}
              oneTimeToken={visibleOneTimeToken}
              receiverPaused={receiverPaused}
              onCreateToken={(name, source) => void createToken(name, source)}
              onRevokeToken={(id) => void revokeToken(id)}
              onTested={onConnectorTested}
            />
          </div>
        ) : (
          <ConnectorsCatalogue statuses={statuses} onOpenSetup={openSetup} />
        )
      ) : null}

      {tab === "tokens" ? (
        <section className="border border-slate-200 bg-white p-5">
          <h2 className="text-sm font-semibold text-navy-900">Access Tokens</h2>
          <p className="mt-1 text-xs text-ink-muted">
            Machine credentials used by application, Wazuh and CI/CD connectors. They are not human
            login tokens. Values are shown once at creation, stored hashed, and can be revoked.
          </p>
          <div className="mt-4">
            <TokenPanel
              canManage={canManageTokens}
              tokens={tokens}
              busy={busy}
              oneTimeToken={visibleOneTimeToken}
              defaultName="Wallet service forwarder"
              defaultSource="wallet-service"
              onCreate={(name, source) => void createToken(name, source)}
              onRevoke={(id) => void revokeToken(id)}
            />
          </div>
        </section>
      ) : null}

      {tab === "exports" ? (
        formats ? (
          <Card title="SOC export">
            <SocExportPanel outboundFormats={formats.outbound} canExport={canExport} />
          </Card>
        ) : advancedLoading ? (
          <LoadingState message="Loading export formats..." />
        ) : (
          <SafeErrorMessage title="Exports unavailable" message={advancedError ?? "Could not load export formats."} />
        )
      ) : null}

      {tab === "developer" ? (
        <DeveloperSetup
          snippets={snippets}
          schema={schema}
          gatewayStatus={gatewayStatus}
          formats={formats}
          canExport={canExport}
          canIngest={canIngest}
          busy={busy}
          advancedLoading={advancedLoading}
          advancedError={advancedError}
          activeSnippet={activeSnippet}
          onSnippet={setActiveSnippet}
          onLegacyTest={() => void sendLegacyTest()}
          legacyTest={legacyTest}
        />
      ) : null}
    </div>
  );
}

function Overview({
  gatewayStatus,
  statuses,
  onOpenConnectors,
  onOpenSetup,
}: {
  gatewayStatus: IntegrationGatewayStatus | null;
  statuses: Record<CatalogKind, ConnectorStatus>;
  onOpenConnectors: () => void;
  onOpenSetup: (kind: SetupKind) => void;
}) {
  return (
    <div className="space-y-6">
      <section className="border border-slate-200 bg-white">
        <div className="grid gap-px bg-slate-200 sm:grid-cols-3">
          <Metric
            label="Integration receiver"
            value={
              gatewayStatus
                ? gatewayStatus.gateway_enabled
                  ? "Running"
                  : "Paused"
                : "Unknown"
            }
          />
          <Metric
            label="Last inbound event"
            value={gatewayStatus?.last_event_received_at ? formatDate(gatewayStatus.last_event_received_at) : "None"}
          />
          <Metric label="Where to start" value="Connectors tab — create a credential, then install" />
        </div>
      </section>

      <section>
        <div className="mb-2 flex items-baseline justify-between">
          <h2 className="text-sm font-semibold text-navy-900">What can connect</h2>
          <button type="button" className="text-xs font-medium text-accent hover:underline" onClick={onOpenConnectors}>
            Open Connectors
          </button>
        </div>
        <CatalogueTable statuses={statuses} onOpenSetup={onOpenSetup} compact />
      </section>
    </div>
  );
}

function ConnectorsCatalogue({
  statuses,
  onOpenSetup,
}: {
  statuses: Record<CatalogKind, ConnectorStatus>;
  onOpenSetup: (kind: SetupKind) => void;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-muted">
        Install PrivacyTrace once. Then connect each system from this page. You do not need to
        write REST requests or learn the internal event schema.
      </p>
      <CatalogueTable statuses={statuses} onOpenSetup={onOpenSetup} />
    </div>
  );
}

function CatalogueTable({
  statuses,
  onOpenSetup,
  compact = false,
}: {
  statuses: Record<CatalogKind, ConnectorStatus>;
  onOpenSetup: (kind: SetupKind) => void;
  compact?: boolean;
}) {
  return (
    <div className="overflow-x-auto border border-slate-200 bg-white">
      <table className="data-table text-sm">
        <thead>
          <tr>
            <th>Connector</th>
            <th>Status</th>
            <th className="text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          <CategoryRow label="Applications" />
          <CatalogRow
            kind="runtime"
            title="PrivacyTrace Runtime Connector"
            description="Send privacy-relevant runtime evidence from a Python application."
            status={statuses.runtime}
            action={
              <button type="button" className="text-sm font-medium text-accent hover:underline" onClick={() => onOpenSetup("runtime")}>
                Set up
              </button>
            }
          />
          <CategoryRow label="Security monitoring" />
          <CatalogRow
            kind="wazuh"
            title="Wazuh"
            description="Forward selected Wazuh security evidence through the custom adapter."
            status={statuses.wazuh}
            action={
              <button type="button" className="text-sm font-medium text-accent hover:underline" onClick={() => onOpenSetup("wazuh")}>
                Set up
              </button>
            }
          />
          <CategoryRow label="Code & scanners" />
          <CatalogRow
            kind="scanner"
            title="ScannerBridge-NP"
            description="Scanner findings are supporting evidence, not final RCA truth."
            tools="Semgrep • Gitleaks • Trivy"
            status={statuses.scanner}
            action={
              <Link to="/scanner-bridge" className="text-sm font-medium text-accent hover:underline">
                Open ScannerBridge
              </Link>
            }
          />
          <CategoryRow label="CI/CD" />
          <CatalogRow
            kind="github"
            title="GitHub Actions"
            description="Send safe CI/CD run and commit provenance."
            badge="EXPERIMENTAL"
            status={statuses.github}
            action={
              <button type="button" className="text-sm font-medium text-accent hover:underline" onClick={() => onOpenSetup("github")}>
                Set up
              </button>
            }
          />
          <CategoryRow label="Evidence" />
          <CatalogRow
            kind="evidence"
            title="Evidence Import"
            description="Imported evidence does not replace Controlled Retest."
            status={statuses.evidence}
            action={
              <Link to="/evidence" className="text-sm font-medium text-accent hover:underline">
                Import evidence
              </Link>
            }
          />
        </tbody>
      </table>
      {compact ? null : (
        <p className="border-t border-slate-100 px-3 py-2 text-xs text-ink-subtle">
          Status uses Live Monitor and authoritative connector provenance. A generic
          access token does not mean Runtime, Wazuh or GitHub are sending events.
        </p>
      )}
    </div>
  );
}

function CategoryRow({ label }: { label: string }) {
  return (
    <tr>
      <td colSpan={3} className="bg-slate-50 text-[11px] font-semibold uppercase tracking-wide text-ink-subtle">
        {label}
      </td>
    </tr>
  );
}

function DeveloperSetup({
  snippets,
  schema,
  gatewayStatus,
  formats,
  canExport,
  canIngest,
  busy,
  advancedLoading,
  advancedError,
  activeSnippet,
  onSnippet,
  onLegacyTest,
  legacyTest,
}: {
  snippets: IntegrationSnippets | null;
  schema: IntegrationSchema | null;
  gatewayStatus: IntegrationGatewayStatus | null;
  formats: IntegrationFormatsResponse | null;
  canExport: boolean;
  canIngest: boolean;
  busy: boolean;
  advancedLoading: boolean;
  advancedError: string | null;
  activeSnippet: SnippetKey;
  onSnippet: (key: SnippetKey) => void;
  onLegacyTest: () => void;
  legacyTest: IntegrationEventIngestResponse | null;
}) {
  const v1 = connectorReceiverUrl();
  return (
    <div className="space-y-6">
      {advancedLoading ? <LoadingState message="Loading developer reference..." /> : null}
      {advancedError ? <SafeErrorMessage title="Developer reference partially unavailable" message={advancedError} /> : null}

      <section className="border border-slate-200 bg-white p-5">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-teal-800">Recommended for connectors</p>
        <h2 className="mt-1 text-sm font-semibold text-navy-900">Connector Framework V1</h2>
        <p className="mt-1 text-xs text-ink-muted">
          Runtime, Wazuh and GitHub Actions send already-safe structured events to this receiver.
          Use the Connectors tab for install steps. This section is the advanced reference.
        </p>
        <div className="mt-3">
          <code className="block break-all rounded-md bg-slate-50 px-2 py-1 font-mono text-xs" data-testid="developer-v1-endpoint">
            POST {sanitizeString(v1)}
          </code>
        </div>
        <p className="mt-2 font-mono text-xs text-ink-subtle">{CONNECTOR_V1_PATH}</p>
      </section>

      <section className="border border-slate-200 bg-white p-5" data-testid="developer-cli">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-teal-800">Connector CLI</p>
        <h2 className="mt-1 text-sm font-semibold text-navy-900">privacytrace-connect {CONNECTOR_CLI_VERSION}</h2>
        <p className="mt-1 text-xs text-ink-muted">Public npm registry distribution: NOT PUBLISHED.</p>
        <p className="mt-2 text-xs text-ink-subtle">
          Tarball {CONNECTOR_CLI_TGZ} SHA-256: {CONNECTOR_CLI_SHA256}
        </p>
        <div className="mt-3">
          <CopyField label="Verified local command" value={CONNECTOR_CLI_ADD_RUNTIME} testId="developer-cli-command" />
        </div>
      </section>

      <CollapsibleSection summary="Direct Event Gateway (legacy / compatibility)" testId="legacy-gateway">
        <p className="text-xs text-ink-muted">
          Active direct ingest for SIEM/webhooks and the in-app DEMO test. Different contract from
          Connector V1 (legacy payloads may include message/payload fields). Do not send Runtime,
          Wazuh or GitHub connector events here.
        </p>
        <p className="mt-2 font-mono text-xs text-navy-900">POST {LEGACY_EVENTS_PATH}</p>
        <div className="mt-3">
          <SiemWebhookGuide endpointPath={LEGACY_EVENTS_PATH} />
        </div>
        <div className="mt-3">
          <CopyCurlExample endpointPath={LEGACY_EVENTS_PATH} />
        </div>
        <div className="mt-4">
          <button
            type="button"
            onClick={onLegacyTest}
            disabled={!canIngest || busy || !gatewayStatus?.gateway_enabled}
            className="btn-primary"
          >
            Send Synthetic Test Event
          </button>
          {!gatewayStatus?.gateway_enabled ? (
            <Link to="/live-monitor" className="ml-3 text-sm font-medium text-accent hover:underline">
              Start Live Monitor
            </Link>
          ) : null}
          {legacyTest ? (
            <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3" data-testid="integration-test-result">
              <Metric label="Event received" value={legacyTest.status === "accepted" ? "Yes" : "No"} />
              <Metric label="Alert created" value={legacyTest.alert_created ? "Yes" : "No"} />
              <Metric label="Safety" value={legacyTest.safety_status} />
              {legacyTest.alert_id ? (
                <Link
                  to={`/live-monitor?alert=${encodeURIComponent(legacyTest.alert_id)}`}
                  className="text-sm font-medium text-accent hover:underline sm:col-span-3"
                >
                  Open alert in Live Monitor
                </Link>
              ) : null}
            </div>
          ) : null}
        </div>
        <p className="mt-3 text-xs text-ink-subtle">DEMO/TEST — labelled synthetic traffic, not production.</p>
      </CollapsibleSection>

      <CollapsibleSection summary="Event schema and code examples" testId="advanced-integration-options">
        <div className="space-y-6">
          <section>
            <h2 className="text-sm font-semibold text-navy-900">Legacy gateway examples</h2>
            <div className="mt-3 flex flex-wrap gap-1" role="tablist">
              {SNIPPET_TABS.map((snippetTab) => (
                <button
                  key={snippetTab.key}
                  type="button"
                  role="tab"
                  aria-selected={activeSnippet === snippetTab.key}
                  onClick={() => onSnippet(snippetTab.key)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium ${
                    activeSnippet === snippetTab.key
                      ? "bg-navy-700 text-white"
                      : "text-ink-muted hover:bg-slate-100"
                  }`}
                >
                  {snippetTab.label}
                </button>
              ))}
            </div>
            <pre className="mt-3 max-h-80 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-slate-100">
              {sanitizeString(snippets?.[activeSnippet] ?? "")}
            </pre>
          </section>
          {schema ? (
            <section className="border-t border-slate-100 pt-5">
              <h2 className="text-sm font-semibold text-navy-900">Legacy universal event schema</h2>
              <div className="mt-3 grid gap-4 md:grid-cols-3">
                <FieldList title="Required" fields={schema.required_fields} />
                <FieldList title="Optional" fields={schema.optional_fields} />
                <FieldList title="Source types" fields={schema.accepted_source_types} />
              </div>
            </section>
          ) : null}
          {gatewayStatus ? (
            <section className="border-t border-slate-100 pt-5">
              <h2 className="text-sm font-semibold text-navy-900">Receiver health</h2>
              <dl className="mt-3 grid gap-3 sm:grid-cols-3">
                <Metric label="Gateway" value={gatewayStatus.gateway_enabled ? "Enabled" : "Paused"} />
                <Metric label="Total events" value={String(gatewayStatus.events_received_count)} />
                <Metric label="Alerts created" value={String(gatewayStatus.alerts_created_count)} />
              </dl>
            </section>
          ) : null}
          {formats ? (
            <section className="border-t border-slate-100 pt-5">
              <h2 className="mb-3 text-sm font-semibold text-navy-900">SOC export</h2>
              <SocExportPanel outboundFormats={formats.outbound} canExport={canExport} />
            </section>
          ) : null}
        </div>
      </CollapsibleSection>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white p-3">
      <dt className="text-xs font-medium text-ink-subtle">{label}</dt>
      <dd className="mt-1 break-words text-sm font-semibold text-navy-900">{sanitizeString(value)}</dd>
    </div>
  );
}

function FieldList({ title, fields }: { title: string; fields: string[] }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">{title}</h3>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {fields.map((field) => (
          <code key={field} className="rounded bg-slate-100 px-2 py-1 text-xs text-navy-900">
            {sanitizeString(field)}
          </code>
        ))}
      </div>
    </div>
  );
}

function statusMap(opts: {
  evidence: EvidenceFile[];
  receiverPaused: boolean;
}): Record<CatalogKind, ConnectorStatus> {
  return {
    runtime: pushConnectorStatus({
      kind: "runtime",
      evidence: latestCollectorEvidence(opts.evidence, CONNECTOR_COLLECTORS.runtime),
      receiverPaused: opts.receiverPaused,
    }),
    wazuh: pushConnectorStatus({
      kind: "wazuh",
      evidence: latestCollectorEvidence(opts.evidence, CONNECTOR_COLLECTORS.wazuh),
      receiverPaused: opts.receiverPaused,
    }),
    github: pushConnectorStatus({
      kind: "github",
      evidence: latestCollectorEvidence(opts.evidence, CONNECTOR_COLLECTORS.github),
      receiverPaused: opts.receiverPaused,
    }),
    scanner: pushConnectorStatus({ kind: "scanner", receiverPaused: opts.receiverPaused }),
    evidence: pushConnectorStatus({ kind: "evidence", receiverPaused: opts.receiverPaused }),
  };
}

function parseTab(value: string | null): TabId {
  if (value === "sources") return "connectors";
  return TABS.some((tab) => tab.id === value) ? (value as TabId) : "overview";
}

function parseSetup(value: string | null): SetupKind | null {
  return SETUP_KINDS.includes(value as SetupKind) ? (value as SetupKind) : null;
}

function formatDate(value: string | null): string {
  if (!value) return "None";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" : parsed.toLocaleString();
}
