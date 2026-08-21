import { FormEvent, useEffect, useState } from "react";
import { request } from "../api/client";
import Card from "../components/Card";
import ConfirmDialog from "../components/ConfirmDialog";
import DetailInspector from "../components/DetailInspector";
import PageHeader from "../components/PageHeader";
import PermissionDenied from "../components/PermissionDenied";
import StatusBadge from "../components/StatusBadge";
import { ErrorState, LoadingState } from "../components/LoadingError";
import RoleGate from "../components/RoleGate";
import { ROLE_LABELS } from "../utils/permissions";

interface UserRow {
  id: number;
  name: string;
  email: string;
  role: string;
  is_active: boolean;
  membership_status?: string | null;
  membership_role?: string | null;
  created_at?: string;
  last_login_at?: string | null;
}

const ASSIGNABLE_ROLES = [
  "viewer",
  "security_analyst",
  "developer",
  "auditor",
  "devsecops_engineer",
  "organisation_admin",
];

export default function UserManagementPage() {
  return (
    <RoleGate
      permission="user:manage"
      fallback={<PermissionDenied title="User management is restricted" requiredHint="organisation admin" />}
    >
      <UserManagementInner />
    </RoleGate>
  );
}

function UserManagementInner() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [inviteDemo, setInviteDemo] = useState(false);
  const [inviteDelivery, setInviteDelivery] = useState<string | null>(null);
  const [viewUser, setViewUser] = useState<UserRow | null>(null);
  const [confirm, setConfirm] = useState<{ user: UserRow; status: "suspended" | "revoked" } | null>(null);

  async function loadUsers() {
    setLoading(true);
    setError(null);
    try {
      const data = await request<{ users: UserRow[]; total: number }>("/users");
      setUsers(data.users);
      setViewUser((current) => (current ? data.users.find((item) => item.id === current.id) ?? null : null));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function onInvite(event: FormEvent) {
    event.preventDefault();
    setInviteLink(null);
    setInviteDemo(false);
    setInviteDelivery(null);
    try {
      const created = await request<{
        invite_path?: string | null;
        domain_warning?: string | null;
        delivery?: string;
        demo_simulated?: boolean;
      }>("/users/invitations", {
        method: "POST",
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      setInviteEmail("");
      setInviteLink(created.invite_path || null);
      setInviteDemo(Boolean(created.demo_simulated));
      setInviteDelivery(created.delivery || null);
      if (created.domain_warning) setError(created.domain_warning);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to invite user");
    }
  }

  async function changeRole(user: UserRow, role: string) {
    try {
      await request(`/users/${user.id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      });
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change role");
    }
  }

  async function setMembership(user: UserRow, status: string) {
    try {
      await request(`/users/${user.id}/membership`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update membership");
    }
  }

  async function assignPending(user: UserRow, role: string) {
    try {
      await request(`/users/${user.id}/assign-membership`, {
        method: "POST",
        body: JSON.stringify({ role }),
      });
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to assign membership");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Users" }]}
        title="Users / Access Control"
        description="Invite employees and manage organisation membership. Role permissions are enforced by the backend."
      />
      <Card title="Invite user">
        <form onSubmit={onInvite} className="mb-4 grid gap-3 sm:grid-cols-2">
          <input
            className="field-control"
            placeholder="Work email"
            type="email"
            value={inviteEmail}
            onChange={(event) => setInviteEmail(event.target.value)}
            required
          />
          <select className="field-control" value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>
            {ASSIGNABLE_ROLES.map((role) => (
              <option key={role} value={role}>
                {ROLE_LABELS[role] ?? role}
              </option>
            ))}
          </select>
          <button type="submit" className="btn-primary sm:col-span-2">
            Invite User
          </button>
        </form>
        {inviteDemo ? (
          <p className="mb-2 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-950">
            Demo Organisation — Verification Simulated. Invitation token shown for operator paste.
          </p>
        ) : null}
        {inviteLink ? (
          <p className="text-sm text-navy-900">
            Invitation path: <code>{inviteLink}</code>
          </p>
        ) : inviteDelivery === "smtp" ? (
          <p className="text-sm text-navy-900">Invitation email sent.</p>
        ) : inviteDelivery ? (
          <p className="text-sm text-navy-900">
            Invitation issued. Deliver the signup link out-of-band (token not returned in this mode).
          </p>
        ) : null}
      </Card>
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(280px,20rem)]">
      <Card title="Organisation users">
        {loading ? <LoadingState /> : null}
        {error ? <ErrorState message={error} /> : null}
        <div className="overflow-x-auto">
          <table className="data-table text-sm">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last activity</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr
                  key={user.id}
                  className={`cursor-pointer ${viewUser?.id === user.id ? "is-selected" : ""}`}
                  aria-selected={viewUser?.id === user.id}
                  onClick={() => setViewUser(user)}
                >
                  <td className="font-medium text-navy-900">{user.name}</td>
                  <td>{user.email}</td>
                  <td><StatusBadge value={user.membership_role || user.role} /></td>
                  <td><StatusBadge value={user.membership_status || "pending_unassigned"} /></td>
                  <td className="text-xs text-ink-muted">
                    {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <DetailInspector title="User" onClose={viewUser ? () => setViewUser(null) : undefined}>
        {viewUser ? (
          <div className="space-y-3 text-sm">
            <p className="font-semibold text-navy-900" role="status">
              {viewUser.name} · {viewUser.email} · {viewUser.membership_status || "unassigned"} ·{" "}
              {viewUser.membership_role || viewUser.role}
            </p>
            <button type="button" className="btn-secondary" onClick={() => setViewUser(viewUser)}>
              View User
            </button>
            {viewUser.membership_status === "pending_unassigned" ? (
              <select
                className="field-control"
                defaultValue=""
                onChange={(event) => {
                  if (event.target.value) void assignPending(viewUser, event.target.value);
                }}
                aria-label={`Assign ${viewUser.email}`}
              >
                <option value="">Assign to organisation</option>
                {ASSIGNABLE_ROLES.map((role) => (
                  <option key={role} value={role}>
                    {ROLE_LABELS[role] ?? role}
                  </option>
                ))}
              </select>
            ) : (
              <select
                className="field-control"
                value={viewUser.membership_role || viewUser.role}
                onChange={(event) => void changeRole(viewUser, event.target.value)}
                aria-label={`Change role for ${viewUser.email}`}
              >
                {ASSIGNABLE_ROLES.map((role) => (
                  <option key={role} value={role}>
                    {ROLE_LABELS[role] ?? role}
                  </option>
                ))}
              </select>
            )}
            {viewUser.membership_status === "active" ? (
              <button type="button" className="btn-secondary" onClick={() => setConfirm({ user: viewUser, status: "suspended" })}>
                Suspend User
              </button>
            ) : null}
            {viewUser.membership_status === "suspended" ? (
              <button type="button" className="btn-secondary" onClick={() => void setMembership(viewUser, "active")}>
                Reactivate User
              </button>
            ) : null}
            {viewUser.membership_status && viewUser.membership_status !== "revoked" && viewUser.membership_status !== "pending_unassigned" ? (
              <button type="button" className="btn-secondary" onClick={() => setConfirm({ user: viewUser, status: "revoked" })}>
                Revoke Membership
              </button>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-ink-muted">Select a user to manage role and membership.</p>
        )}
      </DetailInspector>
      </div>
      <ConfirmDialog
        open={Boolean(confirm)}
        title={confirm?.status === "revoked" ? "Revoke membership" : "Suspend user"}
        body={confirm ? `${confirm.status === "revoked" ? "Revoke membership for" : "Suspend"} ${confirm.user.email}?` : ""}
        confirmLabel={confirm?.status === "revoked" ? "Revoke Membership" : "Suspend User"}
        danger
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          if (confirm) void setMembership(confirm.user, confirm.status);
          setConfirm(null);
        }}
      />
    </div>
  );
}
