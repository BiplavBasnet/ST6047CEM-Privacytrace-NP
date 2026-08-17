import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import Breadcrumbs, { type BreadcrumbItem } from "./Breadcrumbs";
import { sanitizeString } from "../utils/safety";

/**
 * Standard page header: breadcrumbs → title → one-line description → actions.
 * Back link only when there are no breadcrumbs (otherwise it duplicates the trail).
 */
export default function PageHeader({
  breadcrumbs,
  title,
  description,
  actions,
  backTo,
  backLabel,
}: {
  breadcrumbs?: BreadcrumbItem[];
  title: string;
  description?: string;
  actions?: ReactNode;
  backTo?: string;
  backLabel?: string;
}) {
  const showBack = Boolean(backTo) && !breadcrumbs?.length;
  return (
    <header className="space-y-1.5 pb-3" data-testid="page-header">
      {breadcrumbs?.length ? <Breadcrumbs items={breadcrumbs} /> : null}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[1.375rem] font-semibold tracking-tight text-navy-900">
            {sanitizeString(title)}
          </h1>
          {description ? (
            <p className="body-muted mt-1 max-w-2xl">{sanitizeString(description)}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        ) : null}
      </div>
      {showBack ? (
        <Link
          to={backTo!}
          className="inline-flex items-center gap-1 text-sm font-semibold text-accent hover:text-teal-800"
        >
          ← {sanitizeString(backLabel ?? "Back")}
        </Link>
      ) : null}
    </header>
  );
}
