/**
 * Integrations UX interaction checks. Synthetic demo data only.
 * Usage: node docs/ux-redesign/integrations-interactions.cjs
 * Requires frontend at 127.0.0.1:5173 and a running backend with demo users.
 */
const { chromium } = require("playwright");
const { execSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "../..");
const OUT = path.join(ROOT, "docs/ux-redesign/after");
const BASE = "http://127.0.0.1:5173";
const API = "http://127.0.0.1:8000";
const ADMIN_EMAIL = "admin@privacytrace.local";
const ADMIN_PASSWORD = "AdminPass123!";
const VIEWER_EMAIL = "viewer@privacytrace.local";
const VIEWER_PASSWORD = "ViewerPass123!";
const V1 = "/integrations/connector/v1/events";

const FORBIDDEN = [
  "sk_live_",
  "sk_test_",
  "BEGIN RSA PRIVATE KEY",
  "DATABASE_URL",
  "OPENAI_API_KEY",
];

async function login(page, email, password) {
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded", timeout: 30000 });
  if (!page.url().includes("/login")) {
    await page.getByLabel("Sign out").click().catch(() => {});
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded", timeout: 30000 });
  }
  await page.getByLabel(/email/i).fill(email);
  await page.locator("#password, input[name='password'], input[type='password']").first().fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL((url) => !String(url).includes("/login"), { timeout: 20000 });
}

async function shot(page, name) {
  fs.mkdirSync(OUT, { recursive: true });
  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  console.log(file);
}

async function apiJson(pathname, { method = "GET", token, body } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${API}${pathname}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed, text };
}

async function loginApi(email, password) {
  const result = await apiJson("/auth/login", {
    method: "POST",
    body: { email, password },
  });
  if (result.status !== 200 || !result.body?.access_token) {
    throw new Error(`login failed ${result.status}: ${result.text.slice(0, 200)}`);
  }
  return result.body.access_token;
}

function assertNoLeak(text, label) {
  const lower = String(text || "");
  for (const marker of FORBIDDEN) {
    if (lower.includes(marker)) throw new Error(`${label} leaked ${marker}`);
  }
  if (lower.includes("Traceback") || lower.includes("at Object.")) {
    throw new Error(`${label} looks like a stack trace`);
  }
}

function killPort(port) {
  const script = `
    Get-CimInstance Win32_Process | Where-Object {
      $_.CommandLine -and $_.CommandLine -match 'uvicorn' -and $_.CommandLine -match 'port ${port}'
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
  `;
  try {
    execSync(`powershell -NoProfile -Command ${JSON.stringify(script)}`, { stdio: "ignore" });
  } catch {
    /* port may already be free */
  }
}

async function waitHealth(timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const result = await apiJson("/health");
      if (result.status === 200) return;
    } catch {
      /* retry */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("backend did not become healthy after restart");
}

async function restartBackend() {
  killPort(8000);
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const python = path.join(ROOT, "backend", ".venv", "Scripts", "python.exe");
  const child = spawn(
    python,
    ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
    {
      cwd: path.join(ROOT, "backend"),
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    },
  );
  child.unref();
  await waitHealth();
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1366, height: 768 } });
  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  await page.goto(`${BASE}/integrations`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Integrations" }).waitFor();
  if ((await page.getByRole("link", { name: "Integrations" }).count()) === 0) {
    throw new Error("sidebar label Integrations missing");
  }
  await shot(page, "integrations-overview-laptop");

  await page.getByRole("tab", { name: "Connectors" }).click();
  await page.getByTestId("connector-row-runtime").waitFor();
  await page.getByTestId("connector-row-wazuh").waitFor();
  await page.getByTestId("connector-row-github").waitFor();
  await page.getByRole("link", { name: "Open ScannerBridge" }).waitFor();
  await page.getByRole("link", { name: "Import evidence" }).waitFor();
  const catalogue = await page.locator("body").innerText();
  if (!catalogue.includes("PrivacyTrace Runtime Connector") || !catalogue.includes("Wazuh")) {
    throw new Error("catalogue missing Runtime or Wazuh");
  }
  if (!catalogue.includes("GitHub Actions") || !catalogue.includes("ScannerBridge")) {
    throw new Error("catalogue missing GitHub or ScannerBridge");
  }
  if (!catalogue.includes("Evidence Import")) {
    throw new Error("catalogue missing Evidence Import");
  }

  await page.getByTestId("connector-row-runtime").getByRole("button", { name: "Set up" }).click();
  await page.getByTestId("connector-setup-runtime").waitFor();
  const cliCmd = await page.getByTestId("connector-cli-command").innerText();
  if (cliCmd.trim() === "npx privacytrace-connect" || /^npx privacytrace-connect(\s|$)/.test(cliCmd.trim())) {
    throw new Error("UI shows unpublished registry npx command");
  }
  if (!cliCmd.includes("file:") && !cliCmd.includes(".tgz")) {
    throw new Error("CLI command missing file: or tarball specifier");
  }
  await page.getByTestId("connector-cli-command").getByRole("button", { name: /copy/i }).click();
  await page.getByTestId("runtime-manual-setup").locator("summary").first().click();
  const runtimeText = await page.getByTestId("connector-setup-runtime").innerText();
  if (runtimeText.includes("POST /integrations/events")) {
    throw new Error("Runtime setup still documents the legacy gateway");
  }
  if (!runtimeText.includes("/integrations/connector/v1/events")) {
    throw new Error("Runtime setup missing Connector V1 receiver");
  }
  await page.getByTestId("runtime-privacy").locator("summary").click();
  await page.getByText("Raw secrets should not be transmitted").waitFor();
  await page.getByText("Raw secrets should not be transmitted").waitFor();
  await shot(page, "integrations-runtime-setup-laptop");

  await page.getByRole("button", { name: "← All connectors" }).click();
  await page.getByTestId("connector-row-wazuh").getByRole("button", { name: "Set up" }).click();
  await page.getByTestId("connector-setup-wazuh").waitFor();
  await page.getByTestId("wazuh-manual-setup").locator("summary").first().click();
  await page.getByTestId("wazuh-config-disclosure").locator("summary").click();
  await shot(page, "integrations-wazuh-setup-laptop");

  await page.getByRole("button", { name: "← All connectors" }).click();
  await page.getByTestId("connector-row-github").getByRole("button", { name: "Set up" }).click();
  await page.getByTestId("github-manual-setup").locator("summary").first().click();
  await page.getByTestId("github-workflow-sample").waitFor();
  const githubText = await page.getByTestId("connector-setup-github").innerText();
  if (!githubText.includes("CI/CD run and commit provenance")) {
    throw new Error("GitHub setup missing run/commit provenance wording");
  }
  await shot(page, "integrations-github-setup-laptop");

  await page.getByRole("tab", { name: "Access Tokens" }).click();
  await page.getByRole("heading", { name: "Access Tokens" }).waitFor();
  const tokenName = `playwright-forwarder-${Date.now()}`;
  const nameField = page.getByLabel(/Connector \/ application name/i);
  await nameField.waitFor();
  await nameField.fill(tokenName);
  await page.getByLabel(/Source \/ service id/i).fill("playwright-source");
  await page.getByRole("button", { name: "Create access token" }).click();
  const tokenBox = page.getByTestId("one-time-token");
  await tokenBox.waitFor();
  await page.getByText(tokenName).waitFor();
  const tokenText = await tokenBox.innerText();
  const tokenMatch = tokenText.match(/ptig_[A-Za-z0-9_]+/);
  if (!tokenMatch) throw new Error("one-time ptig_ token not shown");
  const plaintext = tokenMatch[0];
  await page.getByRole("button", { name: "Copy token" }).click();
  await page.goto(`${BASE}/integrations?tab=tokens`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Access Tokens" }).waitFor();
  await page.getByText(tokenName).waitFor();
  if ((await page.getByTestId("one-time-token").count()) !== 0) {
    throw new Error("plaintext token still visible after refresh");
  }
  if ((await page.getByText(plaintext).count()) !== 0) {
    throw new Error("plaintext token echoed after refresh");
  }

  const adminToken = await loginApi(ADMIN_EMAIL, ADMIN_PASSWORD);
  const started = await apiJson("/live-monitor/start", {
    method: "POST",
    token: adminToken,
    body: {
      mode: "http_ingestion",
      source_name: "wallet-service",
      environment: "demo",
      safe_mode: true,
    },
  });
  if (started.status >= 400) {
    throw new Error(`live monitor start failed ${started.status} ${started.text}`);
  }

  await page.goto(`${BASE}/integrations?tab=connectors&setup=runtime`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("connector-setup-runtime").waitFor();
  const testButton = page.getByRole("button", { name: "Send TEST PRIVACYTRACE RECEIVER event" });
  await testButton.waitFor();
  if (await testButton.isDisabled()) {
    throw new Error("receiver test disabled after Live Monitor start");
  }
  const ingestWait = page.waitForResponse(
    (response) => response.url().includes(V1) && response.request().method() === "POST",
  );
  await testButton.click();
  const ingestResponse = await ingestWait;
  const ingestBody = await ingestResponse.json().catch(() => ({}));
  const result = page.getByTestId("connector-test-result");
  await result.waitFor();
  const resultText = await result.innerText();
  if (ingestResponse.status() !== 200 || !ingestBody.evidence_id || !resultText.includes("PASS")) {
    throw new Error(`receiver test did not pass status=${ingestResponse.status()} body=${JSON.stringify(ingestBody)} ui=${resultText}`);
  }
  if (resultText.toLowerCase().includes("externally verified")) {
    throw new Error("receiver test claimed external verification");
  }
  assertNoLeak(resultText, "receiver result");
  const evidenceId = ingestBody.evidence_id;
  if (!evidenceId) throw new Error("receiver test did not persist evidence_id");

  await page.reload({ waitUntil: "domcontentloaded" });
  const afterRefresh = await apiJson("/evidence", { token: adminToken });
  if (afterRefresh.status !== 200 || !JSON.stringify(afterRefresh.body).includes(evidenceId)) {
    throw new Error("evidence missing after refresh");
  }

  await restartBackend();
  const adminAfterRestart = await loginApi(ADMIN_EMAIL, ADMIN_PASSWORD);
  const afterRestart = await apiJson("/evidence", { token: adminAfterRestart });
  if (afterRestart.status !== 200 || !JSON.stringify(afterRestart.body).includes(evidenceId)) {
    throw new Error("evidence missing after backend restart");
  }

  await page.goto(`${BASE}/integrations?tab=tokens`, { waitUntil: "domcontentloaded" });
  const tokenRow = page.locator("tr", { hasText: tokenName });
  await tokenRow.getByRole("button", { name: "Revoke" }).click();
  await tokenRow.getByText("Inactive").waitFor();
  const revokedPost = await apiJson(V1, {
    method: "POST",
    token: plaintext,
    body: {
      specversion: "1.0",
      id: `playwright-revoked-${Date.now()}`,
      source: "/playwright/revoked",
      type: "np.privacytrace.runtime.event.v1",
      data: { message_summary: "Synthetic revoked-token probe. No customer data." },
    },
  });
  if (![401, 403].includes(revokedPost.status)) {
    throw new Error(`revoked token expected 401/403, got ${revokedPost.status}`);
  }
  if (JSON.stringify(revokedPost.body || {}).includes("event_id") && revokedPost.body?.status === "accepted") {
    throw new Error("revoked token created a new event");
  }
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "Access Tokens" }).click();
  await page.locator("tr", { hasText: tokenName }).getByText("Inactive").waitFor();

  await apiJson("/live-monitor/stop", { method: "POST", token: adminAfterRestart });
  await page.goto(`${BASE}/integrations?tab=connectors&setup=runtime`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("connector-setup-runtime").waitFor();
  await page.getByTestId("connector-setup-runtime").getByText("Receiver paused").first().waitFor();
  const pausedButton = page.getByRole("button", { name: "Send TEST PRIVACYTRACE RECEIVER event" });
  if (await pausedButton.isEnabled()) {
    throw new Error("receiver test stayed enabled while Live Monitor is paused");
  }
  const pausedText = await page.locator("body").innerText();
  assertNoLeak(pausedText, "paused receiver UI");
  if (pausedText.includes(plaintext)) throw new Error("revoked token echoed in UI");

  await page.getByRole("tab", { name: "Developer Setup" }).click();
  await page.getByTestId("developer-v1-endpoint").waitFor();
  await page.getByText("Direct Event Gateway (legacy / compatibility)").click();
  await page.getByTestId("legacy-gateway").waitFor();

  const viewerToken = await loginApi(VIEWER_EMAIL, VIEWER_PASSWORD);
  const viewerCreate = await apiJson("/integrations/tokens", {
    method: "POST",
    token: viewerToken,
    body: { name: "viewer-blocked", source_name: "viewer" },
  });
  if (viewerCreate.status !== 403) {
    throw new Error(`viewer create expected 403, got ${viewerCreate.status}`);
  }

  const viewerContext = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const viewerPage = await viewerContext.newPage();
  await login(viewerPage, VIEWER_EMAIL, VIEWER_PASSWORD);
  await viewerPage.goto(`${BASE}/integrations?tab=tokens`, { waitUntil: "domcontentloaded" });
  await viewerPage.getByText("Token management is restricted").waitFor();
  if ((await viewerPage.getByRole("button", { name: "Create access token" }).count()) !== 0) {
    throw new Error("viewer can see create token");
  }
  if ((await viewerPage.getByRole("button", { name: "Revoke" }).count()) !== 0) {
    throw new Error("viewer can see revoke");
  }
  await viewerContext.close();

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${BASE}/integrations?tab=connectors&setup=runtime`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("connector-setup-runtime").waitFor();
  await page.getByTestId("connector-cli-command").waitFor();
  await page.getByTestId("runtime-manual-setup").waitFor();
  await shot(page, "integrations-runtime-setup-desktop");

  const body = await page.locator("body").innerText();
  assertNoLeak(body, "DOM");
  if (body.toLowerCase().includes("real wazuh manager verified")) {
    throw new Error("UI claimed live Wazuh Manager");
  }

  await browser.close();
  console.log("integrations interactions ok");
  console.log("EXTERNAL CONNECTORS PENDING: NepalFin runtime, Wazuh Manager, hosted GitHub Actions");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
