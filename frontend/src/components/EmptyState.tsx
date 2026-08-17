import type { ReactNode } from "react";
import { sanitizeString } from "../utils/safety";

export default function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="py-6 text-center">
      <p className="text-sm font-semibold text-navy-900">{sanitizeString(title)}</p>
      {description ? (
        <p className="body-muted mx-auto mt-2 max-w-md">{sanitizeString(description)}</p>
      ) : null}
      {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
    </div>
  );
}
