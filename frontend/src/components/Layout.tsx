import { useEffect, useMemo, useState, type ComponentType } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import {
  AlertTriangle,
  BarChart3,
  Bell,
  BookOpen,
  Boxes,
  FileText,
  Info,
  LayoutDashboard,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  ScanLine,
  ScrollText,
  ShieldCheck,
  Upload,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../utils/permissions";
import { api } from "../api/client";
import { liveMonitorApi } from "../api/liveMonitorClient";
import NotificationBell from "./NotificationBell";

type IconType = ComponentType<{ size?: number | string; className?: string }>;

interface NavItem {
  to: string;
  label: string;
  icon: IconType;
  permission?: string;
  badgeKey?: "alerts" | "incidents";
}

interface NavGroup {
  heading: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    heading: "Operations",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
      {
        to: "/live-monitor",
        label: "Live Monitor",
        icon: Radio,
        permission: "live_monitor:read",
        badgeKey: "alerts",
      },
      { to: "/alerts", label: "Alerts", icon: Bell, permission: "live_monitor:read" },
      { to: "/incidents", label: "Incidents", icon: AlertTriangle, badgeKey: "incidents" },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    heading: "Data & sources",
    items: [
      { to: "/integrations", label: "Integrations", icon: Boxes },
      { to: "/evidence", label: "Evidence Import", icon: Upload, permission: "evidence:read" },
      {
        to: "/scanner-bridge",
        label: "ScannerBridge-NP",
        icon: ScanLine,
        permission: "scanner_bridge:read",
      },
    ],
  },
  {
    heading: "Management",
    items: [
      { to: "/users", label: "Users", icon: Users, permission: "user:manage" },
      { to: "/audit-logs", label: "Audit Logs", icon: ScrollText, permission: "audit:read" },
    ],
  },
  {
    heading: "Reference",
    items: [
      { to: "/security", label: "Security", icon: ShieldCheck },
      { to: "/taxonomy", label: "Taxonomy", icon: ScrollText, permission: "taxonomy:read" },
      { to: "/metrics", label: "Metrics", icon: BarChart3, permission: "metrics:read" },
    ],
  },
  {
    heading: "Help",
    items: [
      { to: "/help/guide", label: "User Guide", icon: BookOpen },
      { to: "/help/demo", label: "Demo Guide", icon: BookOpen },
      { to: "/help/about", label: "About", icon: Info },
    ],
  },
];

const CLOSED_STATUSES = new Set(["closed", "resolved"]);
const SIDEBAR_COLLAPSED_KEY = "pt-sidebar-collapsed";

function readCollapsedPreference(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

export default function Layout() {
  const { user, logout, can } = useAuth();
  const assigned = user?.membership?.status === "active";
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readCollapsedPreference);
  const [activeIncidents, setActiveIncidents] = useState<number | null>(null);
  const [openAlerts, setOpenAlerts] = useState<number | null>(null);
  const canLiveMonitor = can("live_monitor:read");

  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, sidebarCollapsed ? "1" : "0");
    } catch {
      // Preference persistence is best effort.
    }
  }, [sidebarCollapsed]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (can("incident:read")) {
        try {
          const list = await api.listIncidents();
          if (!cancelled) {
            setActiveIncidents(
              list.filter((item) => !CLOSED_STATUSES.has((item.status || "").toLowerCase())).length,
            );
          }
        } catch {
          // Workload badges are best effort.
        }
      }
      if (canLiveMonitor) {
        try {
          const data = await liveMonitorApi.listAlerts();
          if (!cancelled) setOpenAlerts(data.alerts.filter((alert) => alert.status === "new").length);
        } catch {
          // Workload badges are best effort.
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [can, canLiveMonitor]);

  const visibleGroups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          if (!assigned && item.to !== "/" && !item.to.startsWith("/help")) return false;
          return !item.permission || can(item.permission);
        }),
      })).filter((group) => group.items.length),
    [assigned, can],
  );

  const badgeFor = (item: NavItem): number | null => {
    if (!item.badgeKey) return null;
    const value = item.badgeKey === "alerts" ? openAlerts : activeIncidents;
    return value && value > 0 ? value : null;
  };

  const initials = (user?.name ?? "PT")
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const firstName = (user?.name ?? "Investigator").split(" ")[0];
  const roleLabel = user ? (ROLE_LABELS[user.role] ?? user.role) : "";
  const topbarLabel =
    firstName && roleLabel && firstName.toLowerCase() !== roleLabel.toLowerCase()
      ? `${firstName} · ${roleLabel}`
      : roleLabel || firstName || "PrivacyTrace-NP";
  // Mobile drawer is always expanded; desktop can collapse to icons.
  const compact = sidebarCollapsed && !mobileNavOpen;

  const renderNavLink = (item: NavItem) => {
    const Icon = item.icon;
    const badge = badgeFor(item);
    return (
      <li key={item.to}>
        <NavLink
          to={item.to}
          end={item.to === "/"}
          title={item.label}
          onClick={() => setMobileNavOpen(false)}
          className={({ isActive }) =>
            [
              "app-nav-link group relative flex min-h-9 items-center rounded text-sm font-medium transition-colors",
              compact ? "justify-center px-0" : "gap-2.5 px-3",
              isActive
                ? "app-nav-link-active text-white"
                : "text-navy-200 hover:bg-white/10 hover:text-white",
            ].join(" ")
          }
        >
          {({ isActive }) => (
            <>
              {isActive ? <span className="app-nav-active-bar" aria-hidden="true" /> : null}
              <span className="relative shrink-0">
                <Icon
                  size={16}
                  className={isActive ? "text-teal-300" : "text-navy-400 group-hover:text-navy-100"}
                />
                {compact && badge != null ? (
                  <span className="absolute -right-1.5 -top-1.5 h-2 w-2 rounded-full bg-teal-300" />
                ) : null}
              </span>
              {!compact ? (
                <>
                  <span className="truncate">{item.label}</span>
                  {badge != null ? (
                    <span className="ml-auto min-w-5 rounded bg-teal-400/15 px-1.5 py-0.5 text-center text-[11px] font-semibold text-teal-200">
                      {badge}
                    </span>
                  ) : null}
                </>
              ) : (
                <span className="sr-only">{item.label}</span>
              )}
            </>
          )}
        </NavLink>
      </li>
    );
  };

  return (
    <div className="app-shell flex min-h-screen bg-surface">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      {mobileNavOpen ? (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-navy-900/40 md:hidden"
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}

      <aside
        id="primary-navigation"
        data-collapsed={compact ? "true" : "false"}
        className={[
          "app-sidebar inset-y-0 left-0 z-50 flex shrink-0 flex-col transition-[width] duration-200 ease-out",
          "w-72 max-w-[86vw]",
          compact ? "md:w-[4.5rem]" : "md:w-[16.5rem]",
          "md:sticky md:top-0 md:flex md:h-screen md:max-w-none",
          mobileNavOpen ? "fixed" : "hidden md:flex",
        ].join(" ")}
      >
        <div
          className={[
            "flex items-center pb-2 pt-5",
            compact ? "flex-col gap-2 px-2" : "justify-between gap-2 px-4",
          ].join(" ")}
        >
          <Link
            to="/"
            className={[
              "inline-flex min-w-0 items-center no-underline",
              compact ? "justify-center" : "gap-3",
            ].join(" ")}
            onClick={() => setMobileNavOpen(false)}
            title="PrivacyTrace-NP"
          >
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-accent text-sm font-bold text-white">
              PT
            </span>
            {!compact ? (
              <span className="min-w-0">
                <span className="block truncate text-[15px] font-semibold tracking-tight text-white">
                  PrivacyTrace-NP
                </span>
                <span className="block text-[11px] text-navy-300">Investigation workspace</span>
              </span>
            ) : null}
          </Link>
          <button
            type="button"
            className="flex h-8 w-8 items-center justify-center rounded text-navy-300 hover:bg-white/10 hover:text-white md:hidden"
            aria-label="Close navigation"
            onClick={() => setMobileNavOpen(false)}
          >
            <X size={17} />
          </button>
          <button
            type="button"
            className="hidden h-8 w-8 shrink-0 items-center justify-center rounded text-navy-300 transition-colors hover:bg-white/10 hover:text-white md:flex"
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!sidebarCollapsed}
            aria-controls="primary-navigation"
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            onClick={() => setSidebarCollapsed((value) => !value)}
          >
            {sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </div>

        <nav
          className={["flex-1 space-y-3 overflow-y-auto pb-4", compact ? "px-2" : "px-3"].join(" ")}
          aria-label="Primary navigation"
        >
          {visibleGroups.map((group) => (
            <div key={group.heading}>
              {!compact ? <p className="app-nav-heading px-3">{group.heading}</p> : null}
              <ul className={compact ? "space-y-1" : "mt-1.5 space-y-0.5"}>
                {group.items.map(renderNavLink)}
              </ul>
            </div>
          ))}
        </nav>

        <div className={["border-t border-white/10", compact ? "p-2" : "p-3"].join(" ")}>
          <div
            className={[
              "flex",
              compact
                ? "flex-col items-center gap-1.5 py-1"
                : "items-center gap-2.5 px-1 py-1",
            ].join(" ")}
          >
            <span
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-white/10 text-xs font-semibold text-white"
              title={user?.name ?? "User"}
            >
              {initials}
            </span>
            {!compact ? (
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-white">{user?.name ?? "User"}</div>
                <div className="truncate text-[11px] text-navy-300">Signed in</div>
              </div>
            ) : null}
            <button
              type="button"
              onClick={() => logout()}
              className="flex h-8 w-8 items-center justify-center rounded text-navy-300 hover:bg-white/10 hover:text-white"
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="app-topbar sticky top-0 z-30">
          <div className="flex h-14 items-center gap-3 px-4 sm:px-6 lg:px-8">
            <button
              type="button"
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-navy-800 transition-colors hover:bg-slate-50 md:hidden"
              aria-label="Open navigation"
              aria-controls="primary-navigation"
              aria-expanded={mobileNavOpen}
              onClick={() => setMobileNavOpen(true)}
            >
              <Menu size={18} />
            </button>
            <div className="flex min-w-0 items-center gap-2.5">
              <ShieldCheck size={16} className="shrink-0 text-accent" aria-hidden="true" />
              <span className="truncate text-sm font-medium text-ink-muted">
                {topbarLabel}
              </span>
            </div>
            <div className="ml-auto flex items-center gap-2.5">
              {canLiveMonitor ? <NotificationBell /> : null}
            </div>
          </div>
        </header>

        <main id="main-content" className="app-main mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 sm:px-6 lg:px-8 lg:py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
