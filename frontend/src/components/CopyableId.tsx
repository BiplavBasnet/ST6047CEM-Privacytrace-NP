import { useCallback, useState } from "react";
import { sanitizeString } from "../utils/safety";

/**
 * Copy-to-clipboard pill. The displayed value is sanitized, and we
 * also sanitize before writing to the clipboard so that even if a
 * caller passes a tainted string, nothing sensitive ever leaves the
 * UI. Falls back silently if the Clipboard API is unavailable.
 */
export default function CopyableId({
  value,
  label,
}: {
  value: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const safe = sanitizeString(value);

  const onCopy = useCallback(async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(safe);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      }
    } catch {
      /* clipboard not available – ignore */
    }
  }, [safe]);

  return (
    <span className="inline-flex items-center gap-1.5 align-middle">
      {label ? (
        <span className="text-xs text-slate-500">{sanitizeString(label)}:</span>
      ) : null}
      <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-800">
        {safe}
      </code>
      <button
        type="button"
        onClick={onCopy}
        className="rounded border border-slate-300 px-1.5 py-0.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
        aria-label={`Copy ${safe}`}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}
