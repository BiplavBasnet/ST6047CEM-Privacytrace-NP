import { sanitizeString } from "../utils/safety";

/**
 * SafeErrorMessage renders backend error text after running it through
 * the project-wide safety sanitizer. This means even if a backend
 * happens to echo a sensitive literal or overclaim phrase inside an
 * error message, the UI replaces it with the safe fallback.
 *
 * Use this for backend failures, permission denials, validation errors
 * and "blocked" states. It never throws; an empty message renders an
 * empty container.
 */
export default function SafeErrorMessage({
  message,
  title = "Error",
  hint,
}: {
  message?: string | null;
  title?: string;
  hint?: string | null;
}) {
  const safeTitle = sanitizeString(title);
  const safeMessage = sanitizeString(message ?? "");
  const safeHint = hint ? sanitizeString(hint) : null;

  return (
    <div
      role="alert"
      className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
    >
      <p className="font-medium">{safeTitle}</p>
      {safeMessage ? <p className="mt-1">{safeMessage}</p> : null}
      {safeHint ? (
        <p className="mt-1 text-xs text-red-700">{safeHint}</p>
      ) : null}
    </div>
  );
}
