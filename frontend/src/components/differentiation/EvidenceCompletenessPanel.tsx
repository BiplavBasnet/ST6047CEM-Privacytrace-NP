import type { ReactNode } from "react";
import Card from "../Card";
import type { EvidenceCompletenessResult } from "../../utils/evidenceCompleteness";
import { sanitizeString } from "../../utils/safety";

export default function EvidenceCompletenessPanel({
  result,
}: {
  result: EvidenceCompletenessResult;
}) {
  const missingDisplay =
    result.missingTypes.length === 0 && result.missingFromTrace.length === 0
      ? "none"
      : uniqueList([...result.missingTypes, ...result.missingFromTrace]).join(", ");

  return (
    <Card title="Evidence completeness">
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <DetailItem label="Completeness score">
          {result.completenessPercent}%
        </DetailItem>
        <DetailItem label="Linked evidence count">{result.linkedCount}</DetailItem>
        <DetailItem label="Available evidence">
          {result.availableTypes.length ? result.availableTypes.join(", ") : "none"}
        </DetailItem>
        <DetailItem label="Missing evidence">{sanitizeString(missingDisplay)}</DetailItem>
        <DetailItem label="Impact">confidence {result.confidenceImpact}</DetailItem>
      </dl>
    </Card>
  );
}

function DetailItem({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="font-medium text-slate-800">{children}</dd>
    </div>
  );
}

function uniqueList(values: string[]): string[] {
  return [...new Set(values)];
}
