"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { CLI_ADD_RUNTIME, NPX_PACKAGE_FILE } = require("../src/constants");

const ROOT = path.join(__dirname, "..", "..", "..");
const CLI = path.join(ROOT, "connectors", "cli");
function runNpx(args, extra = {}) {
  const parts = args.map((arg) => {
    if (arg.startsWith("--package=") && /\s/.test(arg)) {
      return `--package="${arg.slice("--package=".length)}"`;
    }
    if (/\s/.test(arg)) return `"${arg.replace(/"/g, '\\"')}"`;
    return arg;
  });
  return spawnSync(["npx", ...parts].join(" "), {
    encoding: "utf8",
    windowsHide: true,
    shell: true,
    ...extra,
  });
}

describe("npm pack and npx", { timeout: 120000 }, () => {
  it("packs private package members and runs the verified npx file: command", () => {
    const inspect = spawnSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: CLI,
      encoding: "utf8",
      windowsHide: true,
      shell: true,
    });
    assert.equal(inspect.status, 0, inspect.stderr);
    const packed = JSON.parse(inspect.stdout);
    const entry = Array.isArray(packed) ? packed[0] : packed;
    const files = (entry.files || []).map((f) => f.path || f);
    const joined = files.join("\n");
    assert.match(joined, /bin\/privacytrace-connect\.js|bin\\privacytrace-connect\.js/);
    assert.match(joined, /src\/main\.js|src\\main\.js/);
    assert.match(joined, /README\.md/);
    assert.doesNotMatch(joined, /tests[\\/]/);
    assert.doesNotMatch(joined, /\.env/);

    const pack = spawnSync("npm", ["pack"], {
      cwd: CLI,
      encoding: "utf8",
      windowsHide: true,
      shell: true,
    });
    assert.equal(pack.status, 0, pack.stderr);
    const tgzName = pack.stdout.trim().split(/\r?\n/).pop();
    assert.equal(tgzName, "privacytrace-connect-0.1.0.tgz");
    const tgzPath = path.join(CLI, tgzName);
    assert.ok(fs.existsSync(tgzPath));
    const sha = crypto.createHash("sha256").update(fs.readFileSync(tgzPath)).digest("hex");
    fs.writeFileSync(path.join(CLI, "tarball.sha256"), `${sha}  ${tgzName}\n`);

    const scanScript = path.join(os.tmpdir(), `pt-scan-${Date.now()}.py`);
    fs.writeFileSync(
      scanScript,
      [
        "import sys, tarfile",
        "from pathlib import Path",
        `sys.path.insert(0, ${JSON.stringify(path.join(ROOT, "scripts"))})`,
        "from check_tracked_secrets import scan_text",
        `tf = tarfile.open(${JSON.stringify(tgzPath)})`,
        "hits = []",
        "for member in tf.getmembers():",
        "    if not member.isfile():",
        "        continue",
        "    name = member.name.lower()",
        "    if not name.endswith(('.js', '.md', '.json')):",
        "        continue",
        "    text = tf.extractfile(member).read().decode('utf-8', 'ignore')",
        "    hits.extend(scan_text(member.name, text))",
        "print('\\n'.join(hits))",
        "raise SystemExit(1 if hits else 0)",
        "",
      ].join("\n"),
    );
    const scan = spawnSync("python", [scanScript], { encoding: "utf8", windowsHide: true, cwd: ROOT });
    assert.equal(scan.status, 0, scan.stdout + scan.stderr);

    const npxHelp = runNpx(["--yes", `--package=${NPX_PACKAGE_FILE}`, "privacytrace-connect", "--help"], {
      cwd: ROOT,
    });
    assert.equal(npxHelp.status, 0, npxHelp.stderr + npxHelp.stdout);
    assert.match(npxHelp.stdout, /privacytrace-connect/);
    assert.match(npxHelp.stdout, /file:\.\/connectors\/cli/);

    const npxList = runNpx(["--yes", `--package=${NPX_PACKAGE_FILE}`, "privacytrace-connect", "list"], {
      cwd: ROOT,
    });
    assert.equal(npxList.status, 0, npxList.stderr);
    assert.match(npxList.stdout, /runtime/);

    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "pt-npx-dry-"));
    fs.writeFileSync(path.join(temp, "requirements.txt"), "pydantic\n");
    const npxDry = runNpx(
      ["--yes", `--package=file:${CLI}`, "privacytrace-connect", "add", "runtime", "--dry-run"],
      {
        cwd: temp,
        env: {
          ...process.env,
          PRIVACYTRACE_HOME: ROOT,
          PRIVACYTRACE_CONNECTOR_URL: "http://127.0.0.1:8000/integrations/connector/v1/events",
        },
      },
    );
    assert.equal(npxDry.status, 0, npxDry.stderr + npxDry.stdout);
    assert.match(npxDry.stdout, /Dry-run/);
    assert.ok(!fs.existsSync(path.join(temp, ".env.privacytrace.example")));

    const clean = fs.mkdtempSync(path.join(os.tmpdir(), "pt-npx-"));
    fs.copyFileSync(tgzPath, path.join(clean, tgzName));
    const cleanNpx = runNpx(["--yes", `--package=file:./${tgzName}`, "privacytrace-connect", "--help"], {
      cwd: clean,
    });
    assert.equal(cleanNpx.status, 0, cleanNpx.stderr + cleanNpx.stdout);
    assert.match(cleanNpx.stdout, /privacytrace-connect/);

    assert.ok(CLI_ADD_RUNTIME.includes("file:./connectors/cli"));
    assert.notEqual(CLI_ADD_RUNTIME.trim(), "npx privacytrace-connect");
  });
});
