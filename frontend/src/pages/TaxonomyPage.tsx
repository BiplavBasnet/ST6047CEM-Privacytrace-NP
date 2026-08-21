import { useEffect, useMemo, useState } from "react";
import { taxonomyApi, type TaxonomyCategory } from "../api/taxonomyClient";
import Card from "../components/Card";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import PermissionDenied from "../components/PermissionDenied";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

export default function TaxonomyPage() {
  const { can } = useAuth();
  const allowed = can("taxonomy:read");
  const [categories, setCategories] = useState<TaxonomyCategory[]>([]);
  const [version, setVersion] = useState("");
  const [group, setGroup] = useState("all");
  const [error, setError] = useState("");
  useEffect(() => { if (!allowed) return; taxonomyApi.list().then((result) => { setCategories(result.categories); setVersion(result.taxonomy_version); }).catch((err) => setError(err instanceof Error ? err.message : "Taxonomy could not be loaded.")); }, [allowed]);
  const groups = useMemo(() => ["all", ...Array.from(new Set(categories.map((item) => item.group)))], [categories]);
  const visible = group === "all" ? categories : categories.filter((item) => item.group === group);
  if (!allowed) return <PermissionDenied title="Taxonomy is restricted" requiredHint="security analyst, DevSecOps engineer, auditor, or admin" />;
  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Taxonomy" }]}
        title="Sensitive Data Taxonomy"
        description={`Version ${version || "not loaded"}. Contextual Nepal financial-data classification reference.`}
      />
      {error ? <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">{sanitizeString(error)}</p> : null}
      <Card title="Categories">
        <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Taxonomy group">
          {groups.map((item) => (
            <button
              key={item}
              type="button"
              aria-pressed={group === item}
              className={group === item ? "btn-secondary ring-2 ring-navy-700" : "btn-ghost"}
              onClick={() => setGroup(item)}
            >
              {item.replaceAll("_", " ")}
            </button>
          ))}
        </div>
        <div className="-mx-5 -mb-5 overflow-x-auto sm:-mx-6">
          <table className="data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Group</th>
                <th>Detection</th>
                <th>Default severity</th>
                <th>Masking</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((item) => (
                <tr key={item.code}>
                  <td>
                    <strong className="text-navy-900">{sanitizeString(item.display_name)}</strong>
                    <p className="mt-1 max-w-xl text-xs text-ink-muted">{sanitizeString(item.description)}</p>
                    {item.known_limitations.length ? (
                      <p className="mt-1 max-w-xl text-xs text-amber-700">
                        Limitations: {item.known_limitations.map(sanitizeString).join("; ")}
                      </p>
                    ) : null}
                  </td>
                  <td>{sanitizeString(item.group.replaceAll("_", " "))}</td>
                  <td>{item.detection_methods.map((method) => sanitizeString(method.replaceAll("_", " "))).join(", ")}</td>
                  <td><StatusBadge value={item.default_severity} /></td>
                  <td>{sanitizeString(item.masking_strategy.replaceAll("_", " "))}</td>
                  <td>
                    <StatusBadge value={item.enabled ? "enabled" : "disabled"} />
                    {item.internal_only ? <span className="ml-2"><StatusBadge value="internal only" /></span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <p className="body-muted text-xs">
        This taxonomy supports consistent review. It does not establish legal status, regulatory compliance, or a confirmed breach.
      </p>
    </div>
  );
}
