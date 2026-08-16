export default function AISafetyNotice() {
  return (
    <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
      AI Remediation Assistant is advisory. It receives masked incident summaries only, cannot approve or close incidents, and still requires human review plus retest evidence.
    </div>
  );
}
