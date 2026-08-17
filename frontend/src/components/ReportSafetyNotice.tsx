export default function ReportSafetyNotice() {
  return (
    <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
      All report exports are privacy-safe. Raw sensitive values are masked or excluded.
      Reports support investigation but do not assign blame or replace human security
      judgement.
    </p>
  );
}
