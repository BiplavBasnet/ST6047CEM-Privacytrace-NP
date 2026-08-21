import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Play, Send, Square } from "lucide-react";
import {
  liveMonitorApi,
  type LiveAlert,
  type LiveMonitorEventResponse,
  type LiveMonitorStatus,
} from "../api/liveMonitorClient";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import DetailInspector from "../components/DetailInspector";
import LiveAlertDetailPanel from "../components/LiveAlertDetailPanel";
import LiveAlertTable from "../components/LiveAlertTable";
import LiveMonitorSafetyNotice from "../components/LiveMonitorSafetyNotice";
import LiveMonitorStatusCard from "../components/LiveMonitorStatusCard";
import PageHeader from "../components/PageHeader";
import { ErrorState, LoadingState } from "../components/LoadingError";
import SafeErrorMessage from "../components/SafeErrorMessage";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

export default function LivePrivacyMonitorPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const requestedAlertId = searchParams.get("alert");
  const { can } = useAuth();
  const canRead = can("live_monitor:read");
  const canControl = can("live_monitor:control");
  const canIngest = can("live_monitor:ingest");
  const canCreateIncident = can("live_monitor:incident");
  const canDismiss = can("live_monitor:dismiss");

  const [status, setStatus] = useState<LiveMonitorStatus | null>(null);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [selected, setSelected] = useState<LiveAlert | null>(null);
  const [lastResult, setLastResult] = useState<LiveMonitorEventResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [statusData, alertData] = await Promise.all([
        liveMonitorApi.getStatus(),
        liveMonitorApi.listAlerts(),
      ]);
      setStatus(statusData);
      setAlerts(alertData.alerts);
      const targetId = selected?.alert_id ?? requestedAlertId;
      if (targetId) {
        setSelected(
          alertData.alerts.find((alert) => alert.alert_id === targetId) ?? null,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load Live Monitor");
    } finally {
      setLoading(false);
    }
  }, [canRead, requestedAlertId, selected?.alert_id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function runAction(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Live Monitor action failed");
    } finally {
      setBusy(false);
    }
  }

  function sendTestEvent() {
    void runAction(async () => {
      const result = await liveMonitorApi.sendTestEvent();
      setLastResult(result);
      if (result.alert) setSelected(result.alert);
    });
  }

  function createIncident(alert: LiveAlert) {
    void runAction(async () => {
      const result = await liveMonitorApi.createIncident(alert.alert_id);
      if (result.incident_id) {
        navigate(`/incidents/${encodeURIComponent(result.incident_id)}/overview`);
      }
    });
  }

  function dismissAlert(alert: LiveAlert) {
    void runAction(async () => {
      await liveMonitorApi.dismissAlert(alert.alert_id);
      setSelected(await liveMonitorApi.getAlert(alert.alert_id));
    });
  }

  if (!canRead) {
    return (
      <SafeErrorMessage
        title="Live Monitor is restricted"
        message="Your role cannot view live privacy alerts."
        hint="Required permission: live_monitor:read"
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[
          { label: "Dashboard", to: "/" },
          selected ? { label: "Live Monitor", to: "/live-monitor" } : { label: "Live Monitor" },
          ...(selected ? [{ label: "Alert Detail" }] : []),
        ]}
        title="Live Monitor"
        description={status?.running ? "LIVE · ingestion running" : "Paused or disconnected"}
      />
      <LiveMonitorSafetyNotice />

      <div className="sticky top-[3.75rem] z-20 -mx-1 rounded-md border border-slate-200 bg-white p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="eyebrow">Monitor controls</p>
            <p className="mt-0.5 truncate text-sm font-medium text-navy-900">
              {status?.running ? "Ingestion running" : "Monitor stopped"}
              {status?.alert_count != null ? ` · ${status.alert_count} alerts` : ""}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {canIngest ? (
              <button
                type="button"
                onClick={sendTestEvent}
                disabled={busy || status?.running !== true}
                className="btn-secondary"
              >
                <Send size={15} />
                Send Synthetic Test Event (DEMO/TEST)
              </button>
            ) : null}
            {canControl ? (
              status?.running ? (
                <button
                  type="button"
                  onClick={() => void runAction(() => liveMonitorApi.stop())}
                  disabled={busy}
                  className="btn-ghost"
                >
                  <Square size={14} />
                  Stop monitor
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => void runAction(() => liveMonitorApi.start())}
                  disabled={busy}
                  className="btn-secondary"
                >
                  <Play size={14} />
                  Start monitor
                </button>
              )
            ) : null}
          </div>
        </div>
      </div>

      <Card title="Monitor status">
        {loading ? <LoadingState message="Loading monitor status..." /> : null}
        {error ? <ErrorState message={error} /> : null}
        <LiveMonitorStatusCard status={status} />
        {lastResult ? (
          <p
            data-testid="test-event-next-action"
            className="body-muted mt-3"
          >
            {sanitizeString(lastResult.message)}
            {lastResult.alert_id ? " Open the selected alert to continue." : ""}
          </p>
        ) : null}
      </Card>

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(340px,1.35fr)]">
        <Card title="Alert queue" className="min-w-0" density="compact">
          <div className="-mx-4 -mb-4 sm:-mx-4">
            <LiveAlertTable
              alerts={alerts}
              selectedAlertId={selected?.alert_id}
              onSelect={setSelected}
            />
          </div>
        </Card>

        <DetailInspector title="Alert detail">
          <LiveAlertDetailPanel
            alert={selected}
            canCreateIncident={canCreateIncident}
            canDismiss={canDismiss}
            onCreateIncident={createIncident}
            onDismiss={dismissAlert}
          />
        </DetailInspector>
      </div>

      <CollapsibleSection summary="How to connect a live source">
        <p className="text-sm text-navy-900">
          Create a source token in Integrations, then connect Runtime, Wazuh or GitHub Actions from the Connectors tab. Synthetic events are labelled DEMO/TEST and do not represent production traffic.
        </p>
        <Link to="/integrations" className="mt-2 inline-flex text-sm font-semibold text-accent hover:underline">
          Open Integrations
        </Link>
      </CollapsibleSection>
      {error ? <SafeErrorMessage message={error} /> : null}
    </div>
  );
}
