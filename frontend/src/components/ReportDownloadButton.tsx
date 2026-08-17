type ReportDownloadButtonProps = {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  /** Primary buttons (PDF / ZIP) are visually emphasised as the main outputs. */
  primary?: boolean;
};

export default function ReportDownloadButton({
  label,
  onClick,
  disabled = false,
  primary = false,
}: ReportDownloadButtonProps) {
  const styles = primary
    ? "rounded-lg bg-navy-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-navy-800"
    : "rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`${styles} disabled:cursor-not-allowed disabled:opacity-50`}
    >
      {label}
    </button>
  );
}
