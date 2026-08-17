import { Link } from "react-router-dom";
import { sanitizeString } from "../utils/safety";

export interface SectionNavTarget {
  label: string;
  /** Route or in-page anchor (e.g. "#traceability"). */
  to: string;
}

function NavLink({
  target,
  prefix,
  suffix,
}: {
  target: SectionNavTarget;
  prefix?: string;
  suffix?: string;
}) {
  const text = `${prefix ?? ""}${sanitizeString(target.label)}${suffix ?? ""}`;
  if (target.to.startsWith("#")) {
    return (
      <a
        href={target.to}
        className="text-sm font-medium text-accent hover:underline"
      >
        {text}
      </a>
    );
  }
  return (
    <Link
      to={target.to}
      className="text-sm font-medium text-accent hover:underline"
    >
      {text}
    </Link>
  );
}

/**
 * Previous / Return-to-overview / Next footer used between the ordered
 * sections of detail pages and the wizard, so the user always has a clear
 * forward and backward path and never hits a dead end.
 */
export default function SectionNavigation({
  previous,
  next,
  overview,
}: {
  previous?: SectionNavTarget;
  next?: SectionNavTarget;
  overview?: SectionNavTarget;
}) {
  if (!previous && !next && !overview) return null;
  return (
    <div
      data-testid="section-navigation"
      className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2"
    >
      <div>{previous ? <NavLink target={previous} prefix="← " /> : <span />}</div>
      <div>{overview ? <NavLink target={overview} /> : null}</div>
      <div>{next ? <NavLink target={next} suffix=" →" /> : <span />}</div>
    </div>
  );
}
