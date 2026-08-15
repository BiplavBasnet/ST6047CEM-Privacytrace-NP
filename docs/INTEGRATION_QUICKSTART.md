# Integration Quickstart

User-facing product: **Integrations** (`/integrations`). Connector Framework V1
(Runtime, Wazuh, GitHub Actions) uses `POST /integrations/connector/v1/events`.
This page documents the **Direct Event Gateway** (`POST /integrations/events`)
for SIEM/webhook compatibility.

## 1. Start the gateway

Start PostgreSQL and the backend, then open Live Privacy Monitor and select
Start monitor.

## 2. Create one token

Open Integrations at /integrations. Enter a token name and source name, then
select Create token. Store the one-time value in an environment variable:

~~~powershell
$env:PRIVACYTRACE_TOKEN = "value-shown-once"
~~~

## 3. Send a synthetic event

~~~powershell
curl.exe -sS -X POST http://127.0.0.1:8000/integrations/events ^
  -H "Authorization: Bearer %PRIVACYTRACE_TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"source_name\":\"wallet-service\",\"source_type\":\"api_log\",\"message\":\"Synthetic integration event\"}"
~~~

Python:

~~~python
import os
import requests

response = requests.post(
    "http://127.0.0.1:8000/integrations/events",
    headers={"Authorization": "Bearer " + os.environ["PRIVACYTRACE_TOKEN"]},
    json={
        "source_name": "wallet-service",
        "source_type": "api_log",
        "message": "Synthetic integration event",
    },
    timeout=15,
)
response.raise_for_status()
~~~

Node.js:

~~~javascript
const response = await fetch("http://127.0.0.1:8000/integrations/events", {
  method: "POST",
  headers: {
    Authorization: "Bearer " + process.env.PRIVACYTRACE_TOKEN,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    source_name: "wallet-service",
    source_type: "api_log",
    message: "Synthetic integration event",
  }),
});
if (!response.ok) throw new Error("Gateway request failed");
~~~

## 4. Docker log forwarder

Copy tools/log-forwarder/.env.example to .env, configure the token and mounted
log path, then:

~~~powershell
docker build -t privacytrace-log-forwarder tools/log-forwarder
docker run --rm --env-file tools/log-forwarder/.env -v C:\logs:/logs:ro privacytrace-log-forwarder
~~~

The forwarder prints only delivery status and a short hash prefix.

## 5. Review

Open Live Privacy Monitor. A safe event creates no alert. A synthetic leak
creates a masked privacy alert. Create or link an incident only after review.
Add Evidence Import, CI/CD, scanner, and retest evidence where needed.

This setup is integration-ready, not automatic for every environment. Passive
event ingestion may require local network, proxy, and source mapping changes.
