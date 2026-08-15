"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  parseArgs,
  parseEndpoint,
  resolveUnderRoot,
  redact,
  writeManifest,
  readManifest,
  sha256Text,
  confirmContinue,
  rollbackCreated,
  writeTracked,
} = require("../src/shared");
const { parseActionInputs, workflowYaml } = require("../src/add-github");
const { CLI_ADD_RUNTIME, VERSION } = require("../src/constants");

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

describe("parse and help", () => {
  it("prints help and version", () => {
    const help = runCli(["--help"]);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /privacytrace-connect/);
    assert.match(help.stdout, /file:\.\/connectors\/cli/);
    const version = runCli(["--version"]);
    assert.equal(version.status, 0);
    assert.equal(version.stdout.trim(), VERSION);
  });

  it("lists installable and built-in connectors", () => {
    const result = runCli(["list"]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /runtime/);
    assert.match(result.stdout, /wazuh/);
    assert.match(result.stdout, /github-actions/);
    assert.match(result.stdout, /scannerbridge/);
    assert.match(result.stdout, /evidence-import/);
    assert.match(result.stdout, /not installable/);
  });

  it("rejects unknown connector and unknown command", () => {
    const unknown = runCli(["add", "splunk"]);
    assert.notEqual(unknown.status, 0);
    assert.match(unknown.stderr, /unknown connector/);
    const cmd = runCli(["explode"]);
    assert.notEqual(cmd.status, 0);
    assert.match(cmd.stderr, /unknown command/);
  });

  it("rejects --token", () => {
    assert.throws(() => parseArgs(["add", "runtime", "--token=ptig_secret"]), /command line/);
    const result = runCli(["add", "runtime", "--token", "ptig_secretvalue"]);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stderr, /ptig_secretvalue/);
    assert.match(result.stderr, /ptig_\[redacted\]|command line|hidden prompt/);
  });
});

describe("url path manifest redaction", () => {
  it("parses URLs and warns on non-local HTTP", () => {
    const ok = parseEndpoint("http://127.0.0.1:8000/integrations/connector/v1/events");
    assert.equal(ok.local, true);
    assert.equal(ok.warnings.length, 0);
    const remote = parseEndpoint("http://example.invalid/integrations/connector/v1/events");
    assert.ok(remote.warnings.some((w) => /HTTP/i.test(w)));
    assert.throws(() => parseEndpoint("not a url"), /valid URL/);
    assert.throws(() => parseEndpoint("ftp://127.0.0.1/x"), /http or https/);
  });

  it("jails paths and rejects traversal", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "pt-jail-"));
    const inside = resolveUnderRoot(root, ".privacytrace/wazuh/custom-privacytrace");
    assert.ok(inside.startsWith(path.resolve(root)));
    assert.throws(() => resolveUnderRoot(root, "../secret"), /\.\./);
    assert.throws(() => resolveUnderRoot(root, "foo/../../etc/passwd"), /\.\./);
  });

  it("redacts ptig_ tokens", () => {
    const token = "ptig_abcdefghijklmnopqrstuvwxyz";
    assert.equal(redact(`using ${token} now`), "using ptig_[redacted] now");
    assert.doesNotMatch(redact(token), /ptig_abcdefghijklmnopqrstuvwxyz/);
  });

  it("writes a manifest without a token and refuses token fields", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "pt-man-"));
    const tracker = [];
    writeManifest(
      root,
      {
        version: VERSION,
        connector: "runtime",
        timestamp: "2026-08-17T00:00:00Z",
        paths: [".env.privacytrace.example"],
        hashes: { ".env.privacytrace.example": "abc" },
        url: "http://127.0.0.1:8000/integrations/connector/v1/events",
        service: "wallet-api",
        environment: "test",
      },
      tracker,
    );
    const parsed = readManifest(root);
    assert.equal(parsed.connector, "runtime");
    assert.equal(parsed.token, undefined);
    const blob = fs.readFileSync(path.join(root, ".privacytrace/install-manifest.json"), "utf8");
    assert.doesNotMatch(blob, /ptig_/);
    assert.throws(
      () => writeManifest(root, { token: "ptig_nope", connector: "runtime" }, []),
      /must not contain a token/,
    );
  });
});

describe("dry-run confirm overwrite", () => {
  it("dry-run add runtime from a temp dir does not write files", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-dry-"));
    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const result = runCli(["add", "runtime", "--dry-run"], {
      cwd: dir,
      env: {
        PRIVACYTRACE_HOME: ROOT,
        PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        PRIVACYTRACE_CONNECTOR_TOKEN: "ptig_should_not_appear",
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Dry-run/);
    assert.doesNotMatch(result.stdout + result.stderr, /ptig_should_not_appear/);
    assert.ok(!fs.existsSync(path.join(dir, ".env.privacytrace.example")));
    assert.ok(!fs.existsSync(path.join(dir, ".privacytrace")));
  });

  it("declined confirm writes nothing", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-no-"));
    fs.writeFileSync(path.join(dir, "requirements.txt"), "pydantic\n");
    const result = runCli(["add", "runtime"], {
      cwd: dir,
      env: {
        PRIVACYTRACE_HOME: ROOT,
        PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        PRIVACYTRACE_CONNECTOR_TOKEN: "ptig_hidden_token_value",
        PRIVACYTRACE_CONFIRM: "n",
      },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /Declined/);
    assert.doesNotMatch(result.stdout + result.stderr, /ptig_hidden_token_value/);
    assert.ok(!fs.existsSync(path.join(dir, "privacytrace-example.py")));
  });

  it("confirmContinue defaults to N", async () => {
    const stdout = { write() {} };
    const stdin = {
      isTTY: false,
      resume() {},
      pause() {},
      setEncoding() {},
      once() {},
    };
    const ok = await confirmContinue({ stdin, stdout, env: {} });
    assert.equal(ok, false);
  });

  it("rollback deletes only matching created files", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pt-rb-"));
    const tracker = [];
    const file = path.join(dir, "created.txt");
    writeTracked(tracker, file, "hello\n");
    rollbackCreated(tracker);
    assert.ok(!fs.existsSync(file));
  });
});

describe("github workflow generation", () => {
  it("uses action.yml inputs and never inlines a token", () => {
    const yml = fs.readFileSync(path.join(ROOT, "connectors", "github-actions", "action.yml"), "utf8");
    const inputs = parseActionInputs(yml);
    assert.deepEqual(inputs, ["endpoint", "token", "repo", "sha", "run_id", "workflow"]);
    const wf = workflowYaml(inputs);
    assert.match(wf, /secrets\.PRIVACYTRACE_CONNECTOR_TOKEN/);
    assert.match(wf, /contents: read/);
    assert.match(wf, /\.\/\.github\/actions\/privacytrace/);
    assert.doesNotMatch(wf, /ptig_/);
    assert.doesNotMatch(wf, /token: [A-Za-z0-9_]+/);
  });
});

describe("verified command constant", () => {
  it("is not a bare registry npx invocation", () => {
    assert.notEqual(CLI_ADD_RUNTIME.trim(), "npx privacytrace-connect");
    assert.ok(CLI_ADD_RUNTIME.includes("file:") || CLI_ADD_RUNTIME.includes(".tgz"));
    assert.match(CLI_ADD_RUNTIME, /privacytrace-connect add runtime/);
  });
});

describe("hash helper", () => {
  it("is stable", () => {
    assert.equal(sha256Text("abc"), sha256Text("abc"));
    assert.notEqual(sha256Text("abc"), sha256Text("abd"));
  });
});
