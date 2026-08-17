import type { ReactNode } from "react";

export default function Card({
  title,
  children,
  className = "",
  actions,
  density = "default",
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
  density?: "default" | "compact";
}) {
  const pad = density === "compact" ? "p-4" : "p-5 sm:p-6";
  return (
    <section
      className={`overflow-hidden rounded-md border border-slate-200 bg-white ${className}`}
    >
      {title || actions ? (
        <div
          className={[
            "flex items-center justify-between gap-3 border-b border-slate-100",
            density === "compact" ? "min-h-11 px-4 py-2.5" : "min-h-12 px-5 py-3.5",
          ].join(" ")}
        >
          {title ? <h2 className="section-title tracking-tight">{title}</h2> : <span />}
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <div className={pad}>{children}</div>
    </section>
  );
}
