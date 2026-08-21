import { useEffect, useState } from "react";
import PageHeader from "../components/PageHeader";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, type EvaluationMetric } from "../api/client";
import RoleGate from "../components/RoleGate";
import Card from "../components/Card";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { sanitizeString } from "../utils/safety";
import AlertOperationsMetricsPanel from "../components/incident/AlertOperationsMetricsPanel";

export default function MetricsPage() {
  const [metrics, setMetrics] = useState<EvaluationMetric[]>([]);
  const [scenario, setScenario] = useState("scenario_1");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  async function loadMetrics() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getEvaluationMetrics(scenario);
      setMetrics(data.metrics);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load metrics");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadMetrics();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runEvaluation() {
    setRunning(true);
    setError(null);
    try {
      const data = await api.runEvaluation(scenario);
      setMetrics(data.metrics);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Evaluation run failed");
    } finally {
      setRunning(false);
    }
  }

  const chartData = metrics
    .filter((m) => m.metric_value != null)
    .map((m) => ({
      name: m.metric_name,
      value: m.metric_value as number,
    }));

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Metrics" }]}
        title="Metrics"
        description="Thesis evaluation metrics. Not a live operations time-range view."
      />
      <AlertOperationsMetricsPanel />
      <Card title="Thesis-aligned evaluation metrics">
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-ink-subtle">Scenario</span>
            <input
              className="field-control"
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
            />
          </label>
          <button
            type="button"
            onClick={() => void loadMetrics()}
            className="btn-secondary"
          >
            Refresh
          </button>
          <RoleGate permission="metrics:run" fallback={<p className="text-xs text-ink-subtle">Your role cannot run evaluation.</p>}>
            <button
              type="button"
              disabled={running}
              onClick={() => void runEvaluation()}
              className="btn-primary"
            >
              {running ? "Running…" : "Run evaluation"}
            </button>
          </RoleGate>
        </div>

        {loading ? <LoadingState /> : null}
        {error ? <ErrorState message={error} /> : null}

        {!loading && !error ? (
          <>
            <div className="-mx-5 overflow-x-auto sm:-mx-6">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Value</th>
                    <th>Thesis claim</th>
                    <th>Method</th>
                    <th>Evidence source</th>
                  </tr>
                </thead>
                <tbody>
                  {metrics.map((m) => (
                    <tr key={m.metric_name}>
                      <td className="font-medium text-navy-900">{m.metric_name}</td>
                      <td>{m.metric_value ?? "—"}</td>
                      <td className="text-ink-muted">
                        {sanitizeString(m.thesis_claim ?? "—")}
                      </td>
                      <td className="text-ink-muted">
                        {sanitizeString(m.calculation_method ?? "—")}
                      </td>
                      <td className="text-ink-muted">
                        {sanitizeString(m.evidence_source ?? "—")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {chartData.length > 0 ? (
              <div className="mt-6 h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="#334155" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : null}
          </>
        ) : null}
      </Card>
    </div>
  );
}
