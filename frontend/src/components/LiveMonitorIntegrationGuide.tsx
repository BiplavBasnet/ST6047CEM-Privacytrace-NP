import { getApiBaseUrl } from "../api/client";

export default function LiveMonitorIntegrationGuide() {
  const endpoint = `${getApiBaseUrl()}/live-monitor/events`;
  const httpExample = `curl -X POST ${endpoint} \\
  -H "Content-Type: application/json" \\
  -H "$PRIVACYTRACE_AUTH_HEADER" \\
  -d '{
    "source_type": "api_log",
    "source_name": "wallet-service",
    "source_format": "generic_json",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "environment": "demo",
    "message": "masked live event phone=984****567 wallet=WALLET-NP-****"
  }'`;
  const syslogExample = `<134>1 2026-07-13T10:00:00Z wallet-api privacy-demo - - - endpoint=/wallet/transfer phone=984****567`;
  const siemExample = `{
  "source_type": "siem_alert",
  "source_name": "synthetic-siem-export",
  "source_format": "generic_json",
  "service_name": "wallet-service",
  "endpoint": "/wallet/transfer",
  "message": "Possible exposure: wallet=WALLET-NP-****"
}`;
  const cicdExample = `Evidence type: deployment_log
Source: synthetic-ci-pipeline
Changed files: logging/redaction-config.yaml
Release: demo-release-17
No source code or secret values included.`;
  return (
    <div className="space-y-3 text-sm text-slate-700">
      <p>
        Forward copied log or event data through supported passive inputs. Configure and validate each environment before operational use. All examples below are synthetic and masked.
      </p>
      <GuideExample title="HTTP JSON event" testId="live-monitor-curl-example" value={httpExample} />
      <GuideExample title="Syslog-like event" value={syslogExample} />
      <GuideExample title="SIEM alert export" value={siemExample} />
      <GuideExample title="CI/CD evidence import" value={cicdExample} />
    </div>
  );
}

function GuideExample({
  title,
  value,
  testId,
}: {
  title: string;
  value: string;
  testId?: string;
}) {
  return (
    <div>
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </h3>
      <pre
        className="overflow-x-auto rounded-md bg-slate-950 p-3 text-xs text-slate-100"
        data-testid={testId}
      >
        {value}
      </pre>
    </div>
  );
}

