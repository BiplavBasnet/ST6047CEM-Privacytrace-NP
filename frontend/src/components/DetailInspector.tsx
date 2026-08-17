import type { ReactNode } from "react";
import { X } from "lucide-react";

export default function DetailInspector({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose?: () => void;
  children: ReactNode;
}) {
  return (
    <aside
      className="flex min-h-[16rem] min-w-0 flex-col border border-slate-200 bg-white xl:sticky xl:top-16"
      aria-label={title}
    >
      <header className="flex items-center justify-between gap-2 border-b border-slate-200 px-3 py-2">
        <h2 className="text-sm font-semibold text-navy-900">{title}</h2>
        {onClose ? (
          <button type="button" className="btn-ghost h-8 w-8 p-0" aria-label="Close inspector" onClick={onClose}>
            <X size={14} />
          </button>
        ) : null}
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto p-3">{children}</div>
    </aside>
  );
}
