"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { receiverTest } = require("../src/add-runtime");
const BIN = path.join(__dirname, "..", "bin", "privacytrace-connect.js");
const ROOT = path.join(__dirname, "..", "..", "..");

function runCli(args, extra = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    windowsHide: true,
    cwd: extra.cwd || ROOT,
    env: { ...process.env, ...(extra.env || {}) },
    input: extra.input,
  });
}

function startMockProcess() {
  const file = path.join(os.tmpdir(), `pt-mock-${Date.now()}.js`);
  fs.writeFileSync(
    file,
    `
const http = require("http");
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    let status = 200;
    if (req.url.includes("401")) status = 401;
    else if (req.url.includes("403")) status = 403;
    else if (req.url.includes("409")) status = 409;
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: status === 200 ? "accepted" : "error" }));
  });
});
server.listen(0, "127.0.0.1", () => process.stdout.write(String(server.address().port)));
`,
  );
  const { spawn } = require("node:child_process");
  const child = spawn(process.execPath, [file], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("mock server did not start")), 5000);
    child.stdout.once("data", (data) => {
      clearTimeout(timer);
      const port = Number(String(data).trim());
      resolve({
        child,
        url: `http://127.0.0.1:${port}/integrations/connector/v1/events`,
        stop: () => child.kill(),
      });
    });
    child.once("error", reject);
  });
}

describe("wazuh staging", () => {
  it("stages adapter files and does not write a fake manager tree", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-wazuh-"));
    const fake = path.join(dir, "ossec");
    fs.mkdirSync(path.join(fake, "etc"), { recursive: true });
    fs.mkdirSync(path.join(fake, "integrations"), { recursive: true });
    const ossec = path.join(fake, "etc", "ossec.conf");
    fs.writeFileSync(ossec, "<ossec_config></ossec_config>\n");
    const before = fs.readFileSync(ossec, "utf8");
    const result = runCli(["add", "wazuh"], {
      cwd: dir,
      env: {
        PRIVACYTRACE_HOME: ROOT,
        PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        PRIVACYTRACE_CONNECTOR_TOKEN: "ptig_wazuh_secret_token",
        PRIVACYTRACE_CONFIRM: "y",
        PRIVACYTRACE_WAZUH_ROOT: fake,
      },
    });
    assert.equal(result.status, 0, result.stderr + result.stdout);
    assert.match(result.stdout, /CONFIGURED|STAGED|REAL PLATFORM PENDING/);
    assert.doesNotMatch(result.stdout + result.stderr, /CONNECTED/);
    assert.doesNotMatch(result.stdout + result.stderr, /ptig_wazuh_secret_token/);
    assert.ok(fs.existsSync(path.join(dir, ".privacytrace", "wazuh", "custom-privacytrace")));
    const stagedConf = fs.readFileSync(path.join(dir, ".privacytrace", "wazuh", "ossec.conf.example"), "utf8");
    assert.match(stagedConf, /YOUR_PRIVACYTRACE_TOKEN/);
    assert.doesNotMatch(stagedConf, /ptig_/);
    assert.equal(fs.readFileSync(ossec, "utf8"), before);
    assert.ok(!fs.existsSync(path.join(fake, "integrations", "custom-privacytrace")));
    const manifest = fs.readFileSync(path.join(dir, ".privacytrace", "install-manifest.json"), "utf8");
    assert.doesNotMatch(manifest, /ptig_/);
  });
});

describe("github-actions local install", () => {
  it("copies the local action and does not commit", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-gh-"));
    const git = spawnSync("git", ["init"], { cwd: dir, encoding: "utf8", windowsHide: true });
    assert.equal(git.status, 0, git.stderr);
    const result = runCli(["add", "github-actions"], {
      cwd: dir,
      env: {
        PRIVACYTRACE_HOME: ROOT,
        PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        PRIVACYTRACE_CONNECTOR_TOKEN: "ptig_github_secret_token",
        PRIVACYTRACE_CONFIRM: "y",
      },
    });
    assert.equal(result.status, 0, result.stderr + result.stdout);
    assert.match(result.stdout, /LOCAL ACTION INSTALLATION VERIFIED/);
    assert.match(result.stdout, /HOSTED GITHUB WORKFLOW PENDING/);
    assert.doesNotMatch(result.stdout, /CONNECTED/);
    assert.doesNotMatch(result.stdout + result.stderr, /ptig_github_secret_token/);
    const wf = fs.readFileSync(path.join(dir, ".github", "workflows", "privacytrace.yml"), "utf8");
    assert.match(wf, /secrets\.PRIVACYTRACE_CONNECTOR_TOKEN/);
    assert.match(wf, /contents: read/);
    assert.doesNotMatch(wf, /ptig_/);
    assert.ok(fs.existsSync(path.join(dir, ".github", "actions", "privacytrace", "action.yml")));
    assert.ok(fs.existsSync(path.join(dir, ".github", "actions", "privacytrace", "index.js")));
    const status = spawnSync("git", ["status", "--porcelain"], { cwd: dir, encoding: "utf8", windowsHide: true });
    assert.equal(status.status, 0);
    assert.ok(!status.stdout.includes("A  "));
    const log = spawnSync("git", ["log"], { cwd: dir, encoding: "utf8", windowsHide: true });
    assert.notEqual(log.status, 0);
  });
});

describe("doctor", () => {
  it("prints version and does not send payloads", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-doc-"));
    const result = runCli(["doctor"], {
      cwd: dir,
      env: {
        PRIVACYTRACE_HOME: ROOT,
        PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        PRIVACYTRACE_CONNECTOR_TOKEN: "ptig_doctor_secret_token",
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /CLI version: 0.1.0/);
    assert.match(result.stdout, /NOT PUBLISHED/);
    assert.match(result.stdout, /does not send payloads/);
    assert.doesNotMatch(result.stdout + result.stderr, /ptig_doctor_secret_token/);
  });
});

function venvPython(dir) {
  return path.join(dir, "venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
}

function installRuntime(dir) {
  const venvPy = venvPython(dir);
  const venv = spawnSync("python", ["-m", "venv", path.join(dir, "venv")], { encoding: "utf8", windowsHide: true });
  assert.equal(venv.status, 0, venv.stderr);
  const runtimePath = path.join(ROOT, "connectors", "runtime");
  const bundle = spawnSync(venvPy, [path.join(runtimePath, "_bundle_privacy.py")], {
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(bundle.status, 0, bundle.stderr + bundle.stdout);
  const pip = spawnSync(venvPy, ["-m", "pip", "install", "--no-cache-dir", runtimePath], {
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(pip.status, 0, pip.stderr + pip.stdout);
  return venvPy;
}

const NAMESPACE_PROBE = "import json,inspect,sys; from pathlib import Path; from privacytrace_runtime import RuntimeConnector; import privacytrace_runtime, privacytrace_runtime.client as client; root=Path(privacytrace_runtime.__file__).resolve().parents[1]; src=inspect.getsource(client); print(json.dumps({'ok': RuntimeConnector.__name__=='RuntimeConnector', 'backend': any('Privacytrace-NP' in p.replace(chr(92),'/') and p.replace(chr(92),'/').rstrip('/').endswith('backend') for p in sys.path), 'app_dir': (root/'app').is_dir(), 'ingest': (Path(privacytrace_runtime.__file__).resolve().parent/'services'/'connector_ingest_service.py').exists(), 'from_app': ('from app.' in src) or ('import app.' in src)}))";

describe("runtime namespace collision", { timeout: 180000 }, () => {
  it("imports from a target with app.py and does not use backend PYTHONPATH", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-ns-apppy-"));
    fs.writeFileSync(path.join(dir, "app.py"), "HOST = 'target-app-module'\n");
    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const venvPy = installRuntime(dir);
    const probe = spawnSync(venvPy, ["-c", NAMESPACE_PROBE], {
      cwd: dir,
      encoding: "utf8",
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: "" },
    });
    assert.equal(probe.status, 0, probe.stderr + probe.stdout);
    const info = JSON.parse(probe.stdout.trim().split(/\r?\n/).pop());
    assert.equal(info.ok, true);
    assert.equal(info.backend, false);
    assert.equal(info.app_dir, false);
    assert.equal(info.ingest, false);
    assert.equal(info.from_app, false);
    const host = spawnSync(venvPy, ["-c", "import app; print(app.HOST)"], {
      cwd: dir,
      encoding: "utf8",
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: "" },
    });
    assert.equal(host.status, 0, host.stderr);
    assert.equal(host.stdout.trim(), "target-app-module");
  });

  it("imports from a target with an app package", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-ns-apppkg-"));
    fs.mkdirSync(path.join(dir, "app"));
    fs.writeFileSync(path.join(dir, "app", "__init__.py"), "");
    fs.writeFileSync(path.join(dir, "app", "main.py"), "VALUE = 1\n");
    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const venvPy = installRuntime(dir);
    const probe = spawnSync(venvPy, ["-c", NAMESPACE_PROBE], {
      cwd: dir,
      encoding: "utf8",
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: "" },
    });
    assert.equal(probe.status, 0, probe.stderr + probe.stdout);
    const info = JSON.parse(probe.stdout.trim().split(/\r?\n/).pop());
    assert.equal(info.ok, true);
    assert.equal(info.backend, false);
    assert.equal(info.from_app, false);
    const host = spawnSync(venvPy, ["-c", "import app.main; print(app.main.VALUE)"], {
      cwd: dir,
      encoding: "utf8",
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: "" },
    });
    assert.equal(host.status, 0, host.stderr);
    assert.equal(host.stdout.trim(), "1");
  });

  it("runs the generated example and CLI receiver from a target with app.py", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-ns-example-"));
    fs.writeFileSync(path.join(dir, "app.py"), "HOST = 'target-app-module'\n");
    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const venvPy = installRuntime(dir);
    const token = "ptig_ns_secret_token";
    const mock = await startMockProcess();
    try {
      const applied = runCli(["add", "runtime"], {
        cwd: dir,
        env: {
          PRIVACYTRACE_HOME: ROOT,
          PRIVACYTRACE_CONNECTOR_URL: mock.url,
          PRIVACYTRACE_CONNECTOR_TOKEN: token,
          PRIVACYTRACE_CONFIRM: "y",
          PRIVACYTRACE_SERVICE: "wallet-api",
          PRIVACYTRACE_ENVIRONMENT: "test",
          PYTHONPATH: "",
        },
      });
      assert.equal(applied.status, 0, applied.stderr + applied.stdout);
      assert.match(applied.stdout, /INSTALLED/);
      assert.match(applied.stdout, /RECEIVER VERIFIED/);
      assert.ok(fs.existsSync(path.join(dir, "privacytrace-example.py")));
      const example = spawnSync(
        venvPy,
        [path.join(dir, "privacytrace-example.py")],
        {
          cwd: dir,
          encoding: "utf8",
          windowsHide: true,
          env: {
            ...process.env,
            PYTHONPATH: "",
            PRIVACYTRACE_CONNECTOR_URL: mock.url,
            PRIVACYTRACE_CONNECTOR_TOKEN: token,
            PRIVACYTRACE_SERVICE: "wallet-api",
            PRIVACYTRACE_ENVIRONMENT: "test",
          },
        },
      );
      assert.equal(example.status, 0, example.stderr + example.stdout);
      assert.match(example.stdout, /emit accepted|emit did not complete/);
      assert.doesNotMatch(example.stdout + example.stderr, /ptig_ns_secret_token/);
    } finally {
      mock.stop();
    }
  });
});

describe("installed runtime receiver codes", { timeout: 120000 }, () => {
  it("classifies 401, 403, 409, timeout, and malformed emit without leaking the token", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-http-"));
    const venvPy = installRuntime(dir);
    const probe = spawnSync(
      venvPy,
      [
        "-c",
        "import sys, json; from privacytrace_runtime import RuntimeConnector; print(json.dumps({'backend': any('Privacytrace-NP' in p and p.endswith('backend') for p in sys.path), 'sqlalchemy': 'sqlalchemy' in sys.modules}))",
      ],
      { encoding: "utf8", windowsHide: true },
    );
    assert.equal(probe.status, 0, probe.stderr);
    const info = JSON.parse(probe.stdout.trim());
    assert.equal(info.backend, false);
    assert.equal(info.sqlalchemy, false);

    const token = "ptig_http_secret_token";
    const mock = await startMockProcess();
    try {
      const ok = receiverTest(venvPy, mock.url, token, "wallet-api", "test");
      assert.equal(ok.ok, true, ok.output);
      assert.doesNotMatch(ok.output, /ptig_http_secret_token/);

      const unauth = receiverTest(venvPy, mock.url.replace("/integrations", "/401/integrations"), token, "wallet-api", "test");
      assert.equal(unauth.ok, false);
      assert.equal(unauth.reason, "http_401");
      assert.doesNotMatch(unauth.output, /ptig_http_secret_token/);

      const forbidden = receiverTest(venvPy, mock.url.replace("/integrations", "/403/integrations"), token, "wallet-api", "test");
      assert.equal(forbidden.ok, false);
      assert.equal(forbidden.reason, "http_403");

      const conflict = receiverTest(venvPy, mock.url.replace("/integrations", "/409/integrations"), token, "wallet-api", "test");
      assert.equal(conflict.ok, false);
      assert.equal(conflict.reason, "http_409");
    } finally {
      mock.stop();
    }

    const timed = receiverTest(venvPy, "http://127.0.0.1:1/integrations/connector/v1/events", token, "wallet-api", "test");
    assert.equal(timed.ok, false);
    assert.ok(["timeout", "transport_error"].includes(timed.reason), timed.reason);

    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const applyMock = await startMockProcess();
    try {
      const applied = runCli(["add", "runtime"], {
        cwd: dir,
        env: {
          PRIVACYTRACE_HOME: ROOT,
          PRIVACYTRACE_CONNECTOR_URL: applyMock.url,
          PRIVACYTRACE_CONNECTOR_TOKEN: token,
          PRIVACYTRACE_CONFIRM: "y",
          PRIVACYTRACE_SERVICE: "wallet-api",
          PRIVACYTRACE_ENVIRONMENT: "test",
        },
      });
      assert.equal(applied.status, 0, applied.stderr + applied.stdout);
      assert.match(applied.stdout, /INSTALLED/);
      assert.match(applied.stdout, /RECEIVER VERIFIED/);
      assert.doesNotMatch(applied.stdout + applied.stderr, /ptig_http_secret_token/);
      assert.doesNotMatch(applied.stdout, /\bCONNECTED\b/);
      assert.ok(fs.existsSync(path.join(dir, ".env.privacytrace.example")));
      assert.ok(fs.existsSync(path.join(dir, "privacytrace-example.py")));
      const manifest = fs.readFileSync(path.join(dir, ".privacytrace", "install-manifest.json"), "utf8");
      assert.doesNotMatch(manifest, /ptig_/);
      assert.doesNotMatch(fs.readFileSync(path.join(dir, ".env.privacytrace.example"), "utf8"), /ptig_/);
    } finally {
      applyMock.stop();
    }

    const malformed = spawnSync(
      venvPy,
      [
        "-c",
        "from privacytrace_runtime import RuntimeConnector; c=RuntimeConnector('http://127.0.0.1:1/x','tok','src'); print(c.emit(data={'not_a_field': 'nope'})); print(c.health()['last_failure_reason'])",
      ],
      { encoding: "utf8", windowsHide: true },
    );
    assert.equal(malformed.status, 0, malformed.stderr);
    assert.match(malformed.stdout, /False/);
    assert.match(malformed.stdout, /emit_error|privacy_drop/);

    await assertLiveReceiver(venvPy);
  });
});

async function assertLiveReceiver(venvPy) {
  let health;
  try {
    const res = await fetch("http://127.0.0.1:8000/health");
    health = await res.json();
  } catch {
    return;
  }
  if (!health || health.status !== "healthy") return;

  const login = await fetch("http://127.0.0.1:8000/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "admin@privacytrace.local", password: "AdminPass123!" }),
  });
  if (login.status !== 200) return;
  const { access_token } = await login.json();
  const headers = { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" };
  await fetch("http://127.0.0.1:8000/live-monitor/start", {
    method: "POST",
    headers,
    body: JSON.stringify({
      mode: "http_ingestion",
      source_name: "wallet-service",
      environment: "demo",
      safe_mode: true,
    }),
  });
  const created = await fetch("http://127.0.0.1:8000/integrations/tokens", {
    method: "POST",
    headers,
    body: JSON.stringify({ name: `cli-runtime-${Date.now()}`, source_name: "cli-runtime-proof" }),
  });
  const createdText = await created.text();
  assert.equal(created.status, 200, createdText);
  const tokenBody = JSON.parse(createdText);
  const token = tokenBody.token;
  assert.ok(token && token.startsWith("ptig_"));
  const live = receiverTest(
    venvPy,
    "http://127.0.0.1:8000/integrations/connector/v1/events",
    token,
    "cli-runtime-proof",
    "test",
  );
  assert.doesNotMatch(live.output, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  if (!live.ok) {
    assert.equal(live.reason, "http_409", `live receiver failed: ${live.reason} ${live.output}`);
    return;
  }
  const evidence = await fetch("http://127.0.0.1:8000/evidence", { headers: { Authorization: `Bearer ${access_token}` } });
  assert.equal(evidence.status, 200);
  const payload = await evidence.text();
  assert.match(payload, /cli-runtime-proof|privacytrace_runtime|SYNTHETIC SETUP TEST/);
}
