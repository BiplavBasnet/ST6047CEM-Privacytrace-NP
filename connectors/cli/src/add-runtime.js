"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { VERSION, MANIFEST_REL } = require("./constants");
const {
  detectPythonProject,
  findTargetPython,
  isPrivacyTraceTree,
  print,
  resolveUnderRoot,
  writeTracked,
  writeManifest,
  sha256Text,
  needsOverwriteConfirm,
  confirmContinue,
  redact,
} = require("./shared");

const EXAMPLE_PY = `import os
from privacytrace_runtime import RuntimeConnector

connector = RuntimeConnector(
    endpoint=os.environ["PRIVACYTRACE_CONNECTOR_URL"],
    token=os.environ["PRIVACYTRACE_CONNECTOR_TOKEN"],
    source=os.environ.get("PRIVACYTRACE_SERVICE", "wallet-api"),
)
ok = connector.emit(
    data={
        "service": os.environ.get("PRIVACYTRACE_SERVICE", "wallet-api"),
        "environment": os.environ.get("PRIVACYTRACE_ENVIRONMENT", "production"),
        "message_summary": "Synthetic runtime event. No customer data.",
    }
)
print("emit accepted" if ok else "emit did not complete")
`;

function envExample(url, service, environment) {
  return `PRIVACYTRACE_CONNECTOR_URL=${url}
PRIVACYTRACE_CONNECTOR_TOKEN=<store in a secret manager — never commit>
PRIVACYTRACE_SERVICE=${service}
PRIVACYTRACE_ENVIRONMENT=${environment}
`;
}

function pipInstall(python, runtimePath) {
  const bundle = spawnSync(python, [path.join(runtimePath, "_bundle_privacy.py")], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (bundle.status !== 0) {
    const err = redact(bundle.stderr || bundle.stdout || "runtime bundle failed");
    throw new Error(`privacytrace-runtime bundle failed: ${err}`);
  }
  const result = spawnSync(python, ["-m", "pip", "install", "--no-cache-dir", runtimePath], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) {
    const err = redact(result.stderr || result.stdout || "pip install failed");
    throw new Error(`pip install privacytrace-runtime failed: ${err}`);
  }
}

function receiverTest(python, endpoint, token, service, environment) {
  const script = [
    "import json, os, sys",
    "from privacytrace_runtime import RuntimeConnector",
    "c = RuntimeConnector(os.environ['PT_URL'], os.environ['PT_TOKEN'], os.environ.get('PT_SERVICE','wallet-api'))",
    "ok = c.emit(data={'service': os.environ.get('PT_SERVICE','wallet-api'), 'environment': os.environ.get('PT_ENV','production'), 'message_summary': 'SYNTHETIC SETUP TEST. No customer data.', 'severity': 'info'})",
    "print(json.dumps({'ok': bool(ok), 'health': c.health()}))",
    "sys.exit(0 if ok else 2)",
  ].join("; ");
  const result = spawnSync(python, ["-c", script], {
    encoding: "utf8",
    windowsHide: true,
    env: {
      ...process.env,
      PT_URL: endpoint,
      PT_TOKEN: token,
      PT_SERVICE: service,
      PT_ENV: environment,
    },
  });
  const combined = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (combined.includes("ptig_")) {
    throw new Error("Receiver test leaked a token to process output.");
  }
  let parsed = null;
  try {
    const line = (result.stdout || "").trim().split(/\r?\n/).pop();
    parsed = JSON.parse(line);
  } catch {
    parsed = null;
  }
  const reason = parsed && parsed.health && parsed.health.last_failure_reason;
  return {
    ok: result.status === 0,
    reason: reason || (result.status === 0 ? null : "receiver_test_failed"),
    output: redact(combined),
  };
}

async function addRuntime(ctx) {
  const { cwd, sourceRoot, endpoint, token, service, environment, flags, stdout, stdin, env, tracker } = ctx;
  if (isPrivacyTraceTree(cwd)) {
    throw new Error(
      "Refusing to install privacytrace-runtime into the PrivacyTrace tree. Run this command from the target application directory.",
    );
  }
  const markers = detectPythonProject(cwd);
  if (!markers.length) {
    print(stdout, "UNSUPPORTED TARGET");
    print(
      stdout,
      "No pyproject.toml, requirements.txt, Pipfile, or poetry.lock in this directory. Create a Python project, then re-run, or install manually:",
    );
    print(stdout, `  python -m pip install "${path.join(sourceRoot, "connectors", "runtime")}"`);
    return {
      unsupported: true,
      plan: ["UNSUPPORTED TARGET — no Python project markers"],
      summary: [
        ["Runtime package", "NOT INSTALLED"],
        ["Target", "UNSUPPORTED TARGET"],
      ],
      apply: async () => ({
        code: 1,
        summary: [
          ["Runtime package", "NOT INSTALLED"],
          ["Target", "UNSUPPORTED TARGET"],
        ],
      }),
    };
  }

  const python = findTargetPython(cwd);
  const runtimePath = path.join(sourceRoot, "connectors", "runtime");
  const envRel = ".env.privacytrace.example";
  const pyRel = "privacytrace-example.py";
  const envPath = resolveUnderRoot(cwd, envRel);
  const pyPath = resolveUnderRoot(cwd, pyRel);
  const envBody = envExample(endpoint, service, environment);
  const plan = [
    `Target Python project (${markers.join(", ")})`,
    `pip install ${runtimePath} into ${python}`,
    `Write ${envRel} (no token)`,
    `Write ${pyRel}`,
    `Write ${MANIFEST_REL} (no token)`,
    flags.dryRun ? "Dry-run: no pip, no files, no receiver call" : "Optional receiver test via installed RuntimeConnector.emit",
  ];

  return {
    plan,
    summary: [
      ["Runtime package", "PLANNED"],
      ["Receiver", "NOT CONTACTED"],
    ],
    apply: async () => {
      for (const [filePath, body] of [
        [envPath, envBody],
        [pyPath, EXAMPLE_PY],
      ]) {
        if (needsOverwriteConfirm(filePath, sha256Text(body))) {
          print(stdout, `File exists with different content: ${filePath}`);
          const overwrite = await confirmContinue({ stdin, stdout, env });
          if (!overwrite) throw new Error("Overwrite declined.");
        }
      }
      pipInstall(python, runtimePath);
      writeTracked(tracker, envPath, envBody);
      writeTracked(tracker, pyPath, EXAMPLE_PY);
      writeManifest(
        cwd,
        {
          version: VERSION,
          connector: "runtime",
          timestamp: new Date().toISOString(),
          paths: [envRel, pyRel],
          hashes: {
            [envRel]: sha256Text(envBody),
            [pyRel]: sha256Text(EXAMPLE_PY),
          },
          url: endpoint,
          service,
          environment,
        },
        tracker,
      );

      const test = receiverTest(python, endpoint, token, service, environment);
      const installed = "INSTALLED";
      let receiver = "RECEIVER TEST FAILED";
      if (test.ok) receiver = "RECEIVER VERIFIED";
      print(stdout, test.ok ? "Receiver test: HTTP accepted or duplicate." : `Receiver test failed (${test.reason}).`);
      if (test.reason === "http_409") {
        print(stdout, "Live Monitor returned 409. Connector files are installed; start Live Monitor and re-test.");
      }
      return {
        code: 0,
        summary: [
          ["Runtime package", installed],
          ["Configuration files", "CONFIGURED"],
          ["PrivacyTrace receiver", receiver],
          ["Host application wiring", "REAL PLATFORM PENDING"],
        ],
      };
    },
  };
}

module.exports = { addRuntime, envExample, receiverTest, pipInstall };
