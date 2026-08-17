import { useEffect, useRef } from "react";

export default function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = "Confirm",
  danger = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    try {
      if (open && !node.open) node.showModal();
      if (!open && node.open) node.close();
    } catch {
      if (open) node.setAttribute("open", "");
      else node.removeAttribute("open");
    }
  }, [open]);
  return (
    <dialog
      ref={ref}
      className="w-full max-w-md rounded-md border border-slate-200 bg-white p-4 shadow-panel"
      onCancel={onCancel}
    >
      <h2 className="text-base font-semibold text-navy-900">{title}</h2>
      <p className="body-muted mt-2">{body}</p>
      <div className="mt-4 flex justify-end gap-2">
        <button type="button" className="btn-secondary" onClick={onCancel}>
          Cancel
        </button>
        <button type="button" className={danger ? "btn-danger" : "btn-primary"} onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}
