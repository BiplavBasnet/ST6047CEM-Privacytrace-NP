import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Bell } from "lucide-react";
import { liveMonitorApi, type LiveAlert } from "../api/liveMonitorClient";
import { sanitizeString } from "../utils/safety";
import RelativeTime from "./ui/primitives";

const PREVIEW_LIMIT = 8;
const POLL_MS = 60_000;

function alertHref(alert: LiveAlert): string {
  if (alert.linked_incident_id) {
    return `/incidents/${encodeURIComponent(alert.linked_incident_id)}`;
  }
  return `/live-monitor?alert=${encodeURIComponent(alert.alert_id)}`;
}

function alertTitle(alert: LiveAlert): string {
  const summary = alert.alert_summary?.trim();
  if (summary) return summary;
  const service = alert.service_name || "Unknown service";
  const endpoint = alert.endpoint || "unknown endpoint";
  return `${service} · ${endpoint}`;
}

function severityClass(severity: string): string {
  const value = severity.toLowerCase();
  if (value === "critical" || value === "high") return "text-red-700 bg-red-50";
  if (value === "medium") return "text-amber-700 bg-amber-50";
  return "text-slate-600 bg-slate-100";
}

export default function NotificationBell() {
  const panelId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const unreadCount = alerts.filter((alert) => alert.status === "new").length;
  const preview = alerts.slice(0, PREVIEW_LIMIT);

  const refresh = async (showSpinner: boolean) => {
    if (showSpinner) setLoading(true);
    setError(null);
    try {
      const data = await liveMonitorApi.listAlerts({ limit: 20 });
      const sorted = [...data.alerts].sort((a, b) => {
        const aTime = new Date(a.first_seen || a.alert_time || a.created_at).getTime();
        const bTime = new Date(b.first_seen || b.alert_time || b.created_at).getTime();
        return bTime - aTime;
      });
      setAlerts(sorted);
      setLoaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(false);
    const timer = window.setInterval(() => {
      void refresh(false);
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!open) return;
    void refresh(true);

    const onPointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className="relative" ref={rootRef}>
      <button
        type="button"
        className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-transparent text-ink-muted transition-colors hover:border-slate-200 hover:bg-white hover:text-navy-900"
        aria-label={
          unreadCount
            ? `${unreadCount} new privacy alert${unreadCount === 1 ? "" : "s"}`
            : "Privacy alert notifications"
        }
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={panelId}
        title="Notifications"
        onClick={() => setOpen((value) => !value)}
      >
        <Bell size={16} />
        {unreadCount > 0 ? (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold leading-none text-white">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        ) : null}
      </button>

      {open ? (
        <div
          id={panelId}
          role="dialog"
          aria-label="Privacy alert notifications"
          className="absolute right-0 z-50 mt-2 w-[22rem] max-w-[calc(100vw-1.5rem)] overflow-hidden rounded-lg border border-slate-200 bg-white shadow-panel"
        >
          <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
            <div>
              <p className="text-sm font-semibold text-navy-900">Notifications</p>
              <p className="text-xs text-ink-subtle">
                {unreadCount > 0
                  ? `${unreadCount} new privacy alert${unreadCount === 1 ? "" : "s"}`
                  : "No new privacy alerts"}
              </p>
            </div>
            <Link
              to="/alerts"
              className="text-xs font-semibold text-accent hover:text-teal-800"
              onClick={() => setOpen(false)}
            >
              View all
            </Link>
          </div>

          <div className="max-h-[24rem] overflow-y-auto">
            {loading && !loaded ? (
              <p className="px-4 py-8 text-center text-sm text-ink-muted">Loading alerts...</p>
            ) : null}
            {error ? (
              <p className="px-4 py-8 text-center text-sm text-red-700">{sanitizeString(error)}</p>
            ) : null}
            {!error && loaded && preview.length === 0 ? (
              <div className="px-4 py-10 text-center">
                <p className="text-sm font-medium text-navy-900">You're all caught up</p>
                <p className="mt-1 text-xs text-ink-muted">
                  New live privacy alerts will show up here.
                </p>
              </div>
            ) : null}
            {!error && preview.length > 0 ? (
              <ul className="divide-y divide-slate-100">
                {preview.map((alert) => {
                  const isNew = alert.status === "new";
                  return (
                    <li key={alert.alert_id}>
                      <Link
                        to={alertHref(alert)}
                        onClick={() => setOpen(false)}
                        className={[
                          "flex gap-3 px-4 py-3 no-underline transition-colors hover:bg-slate-50",
                          isNew ? "bg-accent-soft/40" : "bg-white",
                        ].join(" ")}
                      >
                        <span
                          className={[
                            "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                            isNew ? "bg-accent" : "bg-transparent",
                          ].join(" ")}
                          aria-hidden="true"
                        />
                        <span className="min-w-0 flex-1">
                          <span
                            className={[
                              "block truncate text-sm text-navy-900",
                              isNew ? "font-semibold" : "font-medium",
                            ].join(" ")}
                          >
                            {sanitizeString(alertTitle(alert))}
                          </span>
                          <span className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-ink-muted">
                            <span
                              className={`rounded px-1.5 py-0.5 font-medium capitalize ${severityClass(alert.severity)}`}
                            >
                              {sanitizeString(alert.severity)}
                            </span>
                            <span aria-hidden="true">·</span>
                            <RelativeTime value={alert.first_seen || alert.alert_time} />
                            {alert.linked_incident_id ? (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="font-mono text-navy-800">
                                  {sanitizeString(alert.linked_incident_id)}
                                </span>
                              </>
                            ) : null}
                          </span>
                        </span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            ) : null}
          </div>

          <div className="border-t border-slate-100 px-4 py-2.5">
            <Link
              to="/alerts"
              className="block text-center text-xs font-semibold text-navy-800 hover:text-accent"
              onClick={() => setOpen(false)}
            >
              Open alert queue
            </Link>
          </div>
        </div>
      ) : null}
    </div>
  );
}
