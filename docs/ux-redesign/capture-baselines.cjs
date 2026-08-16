/**
 * UX screenshots. Synthetic demo data only.
 * Usage: node docs/ux-redesign/capture-baselines.cjs [before|after]
 * Never uses INC-SEED-001 unless that ID actually loads.
 */
const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "../..");
const PHASE = process.argv[2] === "after" ? "after" : "before";
const OUT = path.join(ROOT, "docs/ux-redesign", PHASE);
const BASE = "http://127.0.0.1:5173";
const EMAIL = "admin@privacytrace.local";
const PASSWORD = "AdminPass123!";

const VIEWPORTS = [{ name: "desktop", width: 1440, height: 900 }];
if (process.argv.includes("--laptop")) VIEWPORTS.push({ name: "laptop", width: 1366, height: 768 });
if (process.argv.includes("--wide")) VIEWPORTS.push({ name: "wide", width: 1920, height: 1080 });

const PUBLIC = [
  ["login", "/login"],
  ["setup", "/setup"],
];

const AUTHED = [
  ["dashboard", "/"],
  ["live-monitor", "/live-monitor"],
  ["alerts", "/alerts"],
  ["incidents", "/incidents"],
  ["integrations", "/integrations"],
  ["evidence", "/evidence"],
  ["scanner-bridge", "/scanner-bridge"],
  ["reports", "/reports"],
  ["users", "/users"],
  ["audit-logs", "/audit-logs"],
  ["user-guide", "/help/guide"],
  ["metrics", "/metrics"],
  ["security", "/security"],
  ["taxonomy", "/taxonomy"],
];

const STAGES = [
  ["incident-overview", "overview"],
  ["root-cause", "root-cause"],
  ["review", "review"],
  ["remediation", "remediation"],
  ["verification", "verification"],
  ["final-report", "report"],
];

async function shot(page, name, viewport) {
  const file = path.join(OUT, `${name}-${viewport}.png`);
  await page.screenshot({ path: file, fullPage: true });
  console.log(file);
}

async function gotoReady(page, route) {
  await page.goto(`${BASE}${route}`, { waitUntil: "domcontentloaded", timeout: 30000 });
  if (route.includes("/incidents/")) {
    await page.waitForSelector('[data-testid="workflow-stage-panel"], [data-testid="page-header"]', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(1200);
    return;
  }
  await page.waitForTimeout(900);
}

async function login(page) {
  await gotoReady(page, "/login");
  if (!page.url().includes("/login")) return;
  await page.getByLabel(/email/i).fill(EMAIL);
  await page.locator("#password, input[name='password'], input[type='password']").first().fill(PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL((url) => !String(url).includes("/login"), { timeout: 20000 });
}

async function ensureValidIncident(page) {
  await gotoReady(page, "/live-monitor");
  const start = page.getByRole("button", { name: /start monitor/i });
  if (await start.isVisible().catch(() => false)) {
    await start.click();
    await page.waitForTimeout(800);
  }
  const send = page.getByRole("button", { name: /synthetic test event/i });
  if (await send.isEnabled().catch(() => false)) {
    await send.click();
    await page.waitForTimeout(1200);
  }
  const openAlert = page.getByRole("button", { name: /open alert/i }).first();
  if (await openAlert.isVisible().catch(() => false)) {
    await openAlert.click();
    await page.waitForTimeout(400);
  }
  const create = page.getByRole("button", { name: /create incident/i });
  if (await create.isVisible().catch(() => false)) {
    await create.click();
    await page.waitForURL(/\/incidents\/.+/, { timeout: 20000 });
    const match = page.url().match(/\/incidents\/([^/]+)/);
    if (match) return decodeURIComponent(match[1]);
  }
  await gotoReady(page, "/incidents");
  const link = page.locator("a[href*='/incidents/INC-']").first();
  if (await link.count()) {
    const href = await link.getAttribute("href");
    const match = href && href.match(/\/incidents\/([^/]+)/);
    if (match) return decodeURIComponent(match[1]);
  }
  throw new Error("Could not create or find a valid incident for screenshots");
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  fs.mkdirSync(OUT, { recursive: true });
  let incidentId = null;
  for (const vp of VIEWPORTS) {
    const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
    const page = await context.newPage();
    for (const [name, route] of PUBLIC) {
      await gotoReady(page, route);
      await shot(page, name, vp.name);
    }
    await login(page);
    if (!incidentId) incidentId = await ensureValidIncident(page);
    console.log("valid incident", incidentId);
    for (const [name, route] of AUTHED) {
      await gotoReady(page, route);
      await shot(page, name, vp.name);
    }
    for (const [name, stage] of STAGES) {
      await gotoReady(page, `/incidents/${encodeURIComponent(incidentId)}/${stage}`);
      const body = await page.locator("body").innerText();
      if (/incident not found/i.test(body)) {
        throw new Error(`Incident ${incidentId} not found on ${stage}`);
      }
      await shot(page, name, vp.name);
    }
    await context.close();
  }
  await browser.close();
  fs.writeFileSync(path.join(OUT, "valid-incident.txt"), String(incidentId || ""));
  console.log(`Captured ${PHASE} screenshots into ${OUT}`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
