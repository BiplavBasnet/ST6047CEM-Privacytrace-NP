import type { ReactNode } from "react";
import { sanitizeString } from "../utils/safety";

export function LoadingState({
  message = "Loading…",
  skeleton = true,
}: {
  message?: string;
  skeleton?: boolean;
}) {
  if (!skeleton) {
    return <p className="body-muted">{sanitizeString(message)}</p>;
  }
  return (
    <div className="space-y-3" role="status" aria-live="polite" aria-label={message}>
      <div className="h-3 w-1/3 animate-pulse rounded bg-slate-200/80" />
      <div className="h-10 animate-pulse rounded-md bg-slate-100" />
      <div className="h-10 animate-pulse rounded-md bg-slate-100" />
      <div className="h-10 w-5/6 animate-pulse rounded-md bg-slate-100" />
      <p className="sr-only">{sanitizeString(message)}</p>
    </div>
  );
}

export function ErrorState({ message, action }: { message: string; action?: ReactNode }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
    >
      <p className="font-medium">{sanitizeString(message)}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
