import { sanitizeString } from "../utils/safety";

export interface FormatOption {
  id: string;
  title: string;
  description?: string;
}

/**
 * Generic format dropdown used by both inbound and outbound panels on
 * the Integrations page. Every label is sanitized; the underlying
 * `<select>` value is restricted to the format ids we receive from
 * the backend.
 */
export default function IntegrationFormatSelector({
  formats,
  value,
  onChange,
  disabled,
  label = "Format",
  testId,
}: {
  formats: FormatOption[];
  value: string;
  onChange: (next: string) => void;
  disabled?: boolean;
  label?: string;
  testId?: string;
}) {
  return (
    <label className="block text-sm font-medium text-slate-700">
      <span className="block">{sanitizeString(label)}</span>
      <select
        data-testid={testId}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        className="mt-1 w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-800 focus:border-slate-500 focus:outline-none disabled:cursor-not-allowed disabled:bg-slate-100"
      >
        {formats.map((fmt) => (
          <option key={fmt.id} value={fmt.id}>
            {sanitizeString(fmt.title)}
          </option>
        ))}
      </select>
      {formats.length === 0 ? (
        <span className="mt-1 block text-xs text-slate-500">
          No formats available.
        </span>
      ) : null}
    </label>
  );
}
