import { sanitizeString } from "../utils/safety";

/**
 * One-line safety notice. Use once per page instead of repeating long
 * safety paragraphs in every section.
 */
export default function CompactSafetyNotice({
  text = "Values are masked before display. Human review is required before decisions.",
  testId = "privacy-safety-notice",
}: {
  text?: string;
  testId?: string;
}) {
  return (
    <p
      data-testid={testId}
      className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-ink-muted"
    >
      {sanitizeString(text)}
    </p>
  );
}
