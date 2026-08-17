import { useCallback, useEffect, useState } from "react";
import { sanitizeString } from "../utils/safety";

export type ToastTone = "info" | "success" | "warning" | "error";

export interface ToastMessage {
  id: number;
  tone: ToastTone;
  text: string;
}

const TONE_CLASS: Record<ToastTone, string> = {
  info: "border-slate-200 bg-white text-slate-800",
  success: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  error: "border-red-200 bg-red-50 text-red-900",
};

let toastCounter = 0;

/**
 * Lightweight toast stack. All messages are sanitized through the
 * project-wide safety filter so accidental leakage of sensitive
 * literals or overclaim phrases gets replaced with the safe fallback.
 *
 * `useToasts()` returns a small API: `push`, `dismiss`, and the
 * `<ToastContainer />` ready to be mounted inside any layout. The
 * stack is local to the component instance – no global state – which
 * keeps tests isolated.
 */
export function useToasts() {
  const [items, setItems] = useState<ToastMessage[]>([]);

  const push = useCallback((tone: ToastTone, text: string) => {
    toastCounter += 1;
    const id = toastCounter;
    setItems((prev) => [
      ...prev,
      { id, tone, text: sanitizeString(text) },
    ]);
    return id;
  }, []);

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const ToastContainer = useCallback(() => {
    return (
      <div
        data-testid="toast-container"
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2"
      >
        {items.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
        ))}
      </div>
    );
  }, [items, dismiss]);

  return { push, dismiss, ToastContainer, items };
}

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: ToastMessage;
  onDismiss: (id: number) => void;
}) {
  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(toast.id), 5000);
    return () => window.clearTimeout(timer);
  }, [toast.id, onDismiss]);

  return (
    <div
      role="status"
      data-testid={`toast-${toast.tone}`}
      className={`pointer-events-auto rounded-md border px-3 py-2 text-sm shadow-sm ${TONE_CLASS[toast.tone]}`}
    >
      <div className="flex items-start justify-between gap-3">
        <span>{toast.text}</span>
        <button
          type="button"
          aria-label="Dismiss"
          onClick={() => onDismiss(toast.id)}
          className="text-xs text-slate-500 hover:text-slate-900"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
