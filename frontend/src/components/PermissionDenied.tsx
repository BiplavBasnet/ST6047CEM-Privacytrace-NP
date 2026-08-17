import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../utils/permissions";
import { sanitizeString } from "../utils/safety";

export default function PermissionDenied({
  title = "Permission required",
  requiredHint,
  stillCanDo,
  backTo = "/",
  backLabel = "Return to Dashboard",
}: {
  title?: string;
  requiredHint?: string;
  stillCanDo?: string;
  backTo?: string;
  backLabel?: string;
}) {
  const { user } = useAuth();
  const roleLabel = user ? (ROLE_LABELS[user.role] ?? user.role) : "Unknown";
  return (
    <div
      data-testid="permission-denied"
      className="rounded-md border border-amber-200 bg-amber-50 p-5"
    >
      <p className="text-sm font-semibold text-navy-900">{sanitizeString(title)}</p>
      <p className="body-muted mt-2">
        You do not have permission to perform this action with your current role.
      </p>
      <p className="mt-3 text-xs text-ink-muted">
        Current role: <span className="font-semibold text-navy-800">{sanitizeString(roleLabel)}</span>
        {requiredHint ? (
          <>
            {" · "}Required: <span className="font-semibold text-navy-800">{sanitizeString(requiredHint)}</span>
          </>
        ) : null}
      </p>
      {stillCanDo ? <p className="mt-1 text-xs text-ink-muted">{sanitizeString(stillCanDo)}</p> : null}
      <Link to={backTo} className="btn-primary mt-4">
        {sanitizeString(backLabel)}
      </Link>
    </div>
  );
}
