import { Link } from "react-router-dom";
import { sanitizeString } from "../utils/safety";

export interface BreadcrumbItem {
  /** Short human label. Never a raw value or technical route name. */
  label: string;
  /** Route for previous levels; omit for the current page. */
  to?: string;
}

/**
 * Consistent "Dashboard / Section / Detail" trail used across all major
 * pages. Every level except the last is clickable. Labels are sanitized as
 * defence-in-depth so raw values can never leak into the trail.
 */
export default function Breadcrumbs({ items }: { items: BreadcrumbItem[] }) {
  if (!items.length) return null;
  return (
    <nav aria-label="Breadcrumb" data-testid="breadcrumbs">
      <ol className="flex flex-wrap items-center gap-1 text-xs text-slate-500">
        {items.map((item, index) => {
          const isLast = index === items.length - 1;
          return (
            <li key={`${item.label}-${index}`} className="flex items-center gap-1">
              {item.to && !isLast ? (
                <Link
                  to={item.to}
                  className="font-medium text-accent hover:underline"
                >
                  {sanitizeString(item.label)}
                </Link>
              ) : (
                <span
                  aria-current={isLast ? "page" : undefined}
                  className={isLast ? "font-medium text-slate-700" : undefined}
                >
                  {sanitizeString(item.label)}
                </span>
              )}
              {!isLast ? <span className="text-slate-400">/</span> : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
