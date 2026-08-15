"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { RECEIVER_PATH, TOKEN_ENV } = require("./constants");

const TOKEN_RE = /ptig_[A-Za-z0-9_]+/g;

function redact(value) {
  return String(value ?? "").replace(TOKEN_RE, "ptig_[redacted]");
}

function formatError(err) {
  const message = err && err.message ? err.message : String(err);
  return `privacytrace-connect: ${redact(message)}`;
}

function parseArgs(argv) {
  const flags = {
    help: false,
    version: false,
    dryRun: false,
    labApply: false,
    checkAuth: false,
  };
  const positionals = [];
  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") flags.help = true;
    else if (arg === "--version" || arg === "-V") flags.version = true;
    else if (arg === "--dry-run") flags.dryRun = true;
    else if (arg === "--lab-apply") flags.labApply = true;
    else if (arg === "--check-auth") flags.checkAuth = true;
    else if (arg === "--token" || arg.startsWith("--token=")) {
      throw new Error("Do not pass the token on the command line. Use the hidden prompt or PRIVACYTRACE_CONNECTOR_TOKEN.");
    }
    else if (arg.startsWith("-") && arg !== "-") {
      throw new Error(`Unknown flag: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals };
}

function parseEndpoint(raw) {
  if (!raw || !String(raw).trim()) {
    throw new Error("Connector URL is required.");
  }
  let parsed;
  try {
    parsed = new URL(String(raw).trim());
  } catch {
    throw new Error("Connector URL is not a valid URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Connector URL must be http or https.");
  }
  const warnings = [];
  const host = parsed.hostname.toLowerCase();
  const local = host === "localhost" || host === "127.0.0.1" || host === "::1";
  if (parsed.protocol === "http:" && !local) {
    warnings.push("URL uses HTTP on a non-local host. Prefer HTTPS.");
  }
  if (!parsed.pathname.includes(RECEIVER_PATH)) {
    warnings.push(`URL path does not include ${RECEIVER_PATH}.`);
  }
  return { href: parsed.href, warnings, local };
}

function assertNoTraversal(rel) {
  const normalized = String(rel).replace(/\\/g, "/");
  if (normalized.split("/").includes("..")) {
    throw new Error("Path must not contain '..'.");
  }
}

function resolveUnderRoot(root, rel) {
  assertNoTraversal(rel);
  const rootResolved = path.resolve(root);
  const resolved = path.resolve(rootResolved, rel);
  const prefix = rootResolved.endsWith(path.sep) ? rootResolved : rootResolved + path.sep;
  if (resolved !== rootResolved && !resolved.startsWith(prefix)) {
    throw new Error("Path escapes the project root.");
  }
  return resolved;
}

function rejectUnexpectedSymlink(targetPath, { allowMissing = false } = {}) {
  let stat;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (err) {
    if (allowMissing && err && err.code === "ENOENT") return;
    throw err;
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`Refusing to follow unexpected symlink: ${targetPath}`);
  }
}

function sha256Text(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function readManifest(projectRoot) {
  const file = resolveUnderRoot(projectRoot, ".privacytrace/install-manifest.json");
  if (!fs.existsSync(file)) return null;
  rejectUnexpectedSymlink(file);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (parsed && parsed.token) {
    throw new Error("Install manifest must not contain a token.");
  }
  return parsed;
}

function writeManifest(projectRoot, data, tracker) {
  if (data.token) throw new Error("Install manifest must not contain a token.");
  const dir = resolveUnderRoot(projectRoot, ".privacytrace");
  fs.mkdirSync(dir, { recursive: true });
  const file = resolveUnderRoot(projectRoot, ".privacytrace/install-manifest.json");
  const body = `${JSON.stringify(data, null, 2)}\n`;
  writeTracked(tracker, file, body);
}

function writeTracked(tracker, filePath, content, { mode } = {}) {
  rejectUnexpectedSymlink(filePath, { allowMissing: true });
  const existed = fs.existsSync(filePath);
  let previousHash = null;
  if (existed) previousHash = sha256File(filePath);
  const payload = typeof content === "string" ? content : String(content);
  const nextHash = sha256Text(payload);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, payload, { encoding: "utf8", ...(mode ? { mode } : {}) });
  tracker.push({
    path: filePath,
    hash: nextHash,
    created: !existed,
    previousHash,
  });
  return nextHash;
}

function copyTracked(tracker, fromPath, toPath, { mode } = {}) {
  rejectUnexpectedSymlink(fromPath);
  const content = fs.readFileSync(fromPath);
  rejectUnexpectedSymlink(toPath, { allowMissing: true });
  const existed = fs.existsSync(toPath);
  let previousHash = null;
  if (existed) previousHash = sha256File(toPath);
  fs.mkdirSync(path.dirname(toPath), { recursive: true });
  fs.writeFileSync(toPath, content, mode ? { mode } : undefined);
  const hash = crypto.createHash("sha256").update(content).digest("hex");
  tracker.push({ path: toPath, hash, created: !existed, previousHash });
  return hash;
}

function rollbackCreated(tracker) {
  for (const item of [...tracker].reverse()) {
    if (!item.created) continue;
    if (!fs.existsSync(item.path)) continue;
    try {
      if (sha256File(item.path) === item.hash) fs.unlinkSync(item.path);
    } catch {
      /* best-effort */
    }
  }
}

function needsOverwriteConfirm(filePath, incomingHash) {
  if (!fs.existsSync(filePath)) return false;
  rejectUnexpectedSymlink(filePath);
  return sha256File(filePath) !== incomingHash;
}

function print(stream, text) {
  stream.write(`${redact(text)}\n`);
}

function isYes(value) {
  return String(value || "").trim().toLowerCase() === "y" || String(value || "").trim().toLowerCase() === "yes";
}

function readLine(stdin) {
  return new Promise((resolve) => {
    const onData = (chunk) => {
      stdin.pause();
      stdin.removeListener("data", onData);
      resolve(String(chunk).replace(/\r?\n$/, ""));
    };
    stdin.resume();
    stdin.setEncoding("utf8");
    stdin.once("data", onData);
  });
}

async function promptLine(question, { stdin = process.stdin, stdout = process.stdout, envValue } = {}) {
  if (envValue != null && String(envValue).length) return String(envValue);
  if (!stdin.isTTY) {
    throw new Error(`${question} (non-interactive: set the matching environment variable)`);
  }
  stdout.write(redact(question));
  return readLine(stdin);
}

async function promptHidden(label, { stdin = process.stdin, stdout = process.stdout, env = process.env } = {}) {
  if (env[TOKEN_ENV]) return String(env[TOKEN_ENV]);
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new Error(`Provide ${TOKEN_ENV} for non-interactive use. The token is never accepted as --token.`);
  }
  stdout.write(label);
  return new Promise((resolve, reject) => {
    const previous = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    const finish = (value) => {
      stdin.setRawMode(Boolean(previous));
      stdin.pause();
      stdin.removeListener("data", onData);
      stdout.write("\n");
      resolve(value);
    };
    const onData = (ch) => {
      if (ch === "\n" || ch === "\r" || ch === "\u0004") {
        finish(buf);
        return;
      }
      if (ch === "\u0003") {
        stdin.setRawMode(Boolean(previous));
        reject(new Error("cancelled"));
        return;
      }
      if (ch === "\u007f" || ch === "\b") {
        buf = buf.slice(0, -1);
        return;
      }
      buf += ch;
      stdout.write("*");
    };
    stdin.on("data", onData);
  });
}

async function confirmContinue({ stdin = process.stdin, stdout = process.stdout, env = process.env } = {}) {
  const preset = env.PRIVACYTRACE_CONFIRM;
  if (preset != null && String(preset).length) return isYes(preset);
  stdout.write("Continue? [y/N] ");
  if (!stdin.isTTY) {
    stdout.write("n\n");
    return false;
  }
  const answer = await readLine(stdin);
  return isYes(answer);
}

function findPrivacyTraceRoot({ cwd = process.cwd(), fromFile = __dirname, env = process.env } = {}) {
  const markers = (root) =>
    fs.existsSync(path.join(root, "connectors", "runtime", "client.py")) &&
    fs.existsSync(path.join(root, "connectors", "wazuh", "custom-privacytrace"));

  const candidates = [];
  if (env.PRIVACYTRACE_HOME) candidates.push(path.resolve(env.PRIVACYTRACE_HOME));
  if (env.INIT_CWD) {
    candidates.push(path.resolve(env.INIT_CWD));
    const pkg = env.npm_config_package;
    if (pkg && String(pkg).startsWith("file:")) {
      const loc = path.resolve(env.INIT_CWD, String(pkg).slice("file:".length));
      candidates.push(path.resolve(loc, "..", ".."));
      candidates.push(path.resolve(loc, ".."));
    }
  }
  let dir = path.resolve(cwd);
  for (let i = 0; i < 8; i += 1) {
    candidates.push(dir);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  dir = path.resolve(fromFile);
  for (let i = 0; i < 8; i += 1) {
    candidates.push(dir);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  for (const candidate of candidates) {
    if (markers(candidate)) return candidate;
  }
  return null;
}

function isPrivacyTraceTree(dir) {
  return (
    fs.existsSync(path.join(dir, "backend", "app", "main.py")) &&
    fs.existsSync(path.join(dir, "connectors", "runtime", "client.py"))
  );
}

function detectPythonProject(dir) {
  const names = ["pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"];
  return names.filter((name) => fs.existsSync(path.join(dir, name)));
}

function findTargetPython(dir) {
  const windows = process.platform === "win32";
  const rels = windows
    ? [".venv/Scripts/python.exe", "venv/Scripts/python.exe"]
    : [".venv/bin/python", "venv/bin/python"];
  for (const rel of rels) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
  }
  return process.env.PYTHON || (windows ? "python" : "python3");
}

module.exports = {
  redact,
  formatError,
  parseArgs,
  parseEndpoint,
  assertNoTraversal,
  resolveUnderRoot,
  rejectUnexpectedSymlink,
  sha256Text,
  sha256File,
  readManifest,
  writeManifest,
  writeTracked,
  copyTracked,
  rollbackCreated,
  needsOverwriteConfirm,
  print,
  promptLine,
  promptHidden,
  confirmContinue,
  findPrivacyTraceRoot,
  isPrivacyTraceTree,
  detectPythonProject,
  findTargetPython,
  TOKEN_RE,
};
