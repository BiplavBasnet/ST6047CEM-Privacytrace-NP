export function getMissingRetestDimensions(dimensions: Record<string, string | null | undefined>) {
  return Object.entries(dimensions)
    .filter(([, value]) => !value?.trim())
    .map(([key]) => key.replaceAll("_", " "));
}

export function isExactRetestReady(
  blocked: boolean,
  retest: { status: string; workflow_status: string; dimensions_match: boolean } | null | undefined,
  test: { status: string; workflow_status?: string } | null | undefined,
) {
  return Boolean(!blocked && retest?.status === "completed" && retest.workflow_status === "current"
    && retest.dimensions_match && test?.status === "passed" && (test.workflow_status ?? "current") === "current");
}
