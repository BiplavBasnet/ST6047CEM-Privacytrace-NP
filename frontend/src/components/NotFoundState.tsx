import { Link } from "react-router-dom";
import { sanitizeString } from "../utils/safety";

/**
 * Safe not-found state for invalid incident / evidence / alert IDs and
 * unknown routes. Always offers a way back so no page is a dead end.
 */
export default function NotFoundState({
  title = "Not found",
  description = "We could not find what you were looking for.",
  backTo = "/",
  backLabel = "Return to Dashboard",
}: {
  title?: string;
  description?: string;
  backTo?: string;
  backLabel?: string;
}) {
  return (
    <div data-testid="not-found-state" className="max-w-lg py-6">
      <p className="text-sm font-semibold text-navy-900">
        {sanitizeString(title)}
      </p>
      <p className="body-muted mt-1">{sanitizeString(description)}</p>
      <Link to={backTo} className="btn-secondary mt-4">
        {sanitizeString(backLabel)}
      </Link>
    </div>
  );
}
