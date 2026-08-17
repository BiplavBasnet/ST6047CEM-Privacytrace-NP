import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function EvidenceRoleTable({
  roles,
}: {
  roles: Record<string, unknown>[];
}) {
  return (
    <Card title="Evidence roles">
      {!roles.length ? (
        <p className="text-sm text-slate-600">No evidence role entries.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500">
              <th>Evidence ID</th>
              <th>Role</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {roles.map((row, i) => (
              <tr key={i} className="border-t border-slate-100">
                <td>{sanitizeString(String(row.evidence_id ?? ""))}</td>
                <td>{sanitizeString(String(row.role ?? ""))}</td>
                <td>{sanitizeString(String(row.reason ?? ""))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
