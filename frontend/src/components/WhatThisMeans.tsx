import { sanitizeString } from "../utils/safety";

/**
 * Tiny inline explanation block. Lets the dashboard show a
 * non-cyberpunk, academic explanation of what a section means without
 * adding a tooltip dependency. All copy is sanitized.
 */
export default function WhatThisMeans({
  label = "What this means",
  text,
}: {
  label?: string;
  text: string;
}) {
  return (
    <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-700">
      <span className="font-semibold text-slate-900">{sanitizeString(label)}:</span>{" "}
      {sanitizeString(text)}
    </p>
  );
}
