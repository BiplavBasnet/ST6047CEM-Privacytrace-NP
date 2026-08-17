import { useState, type ReactNode } from "react";

/**
 * Collapsed-by-default disclosure for advanced or explanatory content.
 * Hairline details — not a card — so nested disclosures do not create card-in-card.
 */
export default function CollapsibleSection({
  summary,
  children,
  testId,
  defaultOpen = false,
  onToggle,
}: {
  summary: string;
  children: ReactNode;
  testId?: string;
  defaultOpen?: boolean;
  onToggle?: (open: boolean) => void;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <details
      data-testid={testId}
      open={open}
      className="border-t border-slate-200/90 py-3"
      onToggle={(event) => {
        const next = event.currentTarget.open;
        setOpen(next);
        onToggle?.(next);
      }}
    >
      <summary className="cursor-pointer select-none text-sm font-semibold text-navy-800">
        {summary}
      </summary>
      <div className="mt-3">{children}</div>
    </details>
  );
}
