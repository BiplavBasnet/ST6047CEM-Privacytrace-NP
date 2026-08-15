"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { VERSION, MANIFEST_REL, URL_ENV, TOKEN_ENV } = require("./constants");
const {
  print,
  readManifest,
  sha256File,
  parseEndpoint,
  findPrivacyTraceRoot,
  detectPythonProject,
  findTargetPython,
  isPrivacyTraceTree,
} = require("./shared");

function runDoctor({ stdout, cwd, env }) {
  print(stdout, `CLI version: ${VERSION}`);
  print(stdout, "Public npm registry distribution: NOT PUBLISHED");

  const sourceRoot = findPrivacyTraceRoot({ cwd, env });
  print(stdout, `PrivacyTrace sources: ${sourceRoot || "NOT FOUND"}`);

  const manifestPath = path.join(cwd, MANIFEST_REL);
  const manifest = readManifest(cwd);
  if (!manifest) {
    print(stdout, `Manifest: missing (${MANIFEST_REL})`);
  } else {
    print(stdout, `Manifest connector: ${manifest.connector || "unknown"}`);
    print(stdout, `Manifest timestamp: ${manifest.timestamp || "unknown"}`);
    print(stdout, `Manifest URL: ${manifest.url || "unset"}`);
    const paths = Array.isArray(manifest.paths) ? manifest.paths : [];
    for (const rel of paths) {
      const abs = path.join(cwd, rel);
      if (!fs.existsSync(abs)) {
        print(stdout, `  ${rel}: MISSING`);
        continue;
      }
      const hash = sha256File(abs);
      const expected = manifest.hashes && manifest.hashes[rel];
      const match = expected ? hash === expected : "no expected hash";
      print(stdout, `  ${rel}: ${hash} ${expected ? (match === true ? "OK" : "HASH MISMATCH") : "recorded"}`);
    }
  }

  const pyMarkers = detectPythonProject(cwd);
  print(stdout, `Python project markers: ${pyMarkers.length ? pyMarkers.join(", ") : "none"}`);
  print(stdout, `Target Python: ${findTargetPython(cwd)}`);
  print(stdout, `PrivacyTrace server tree: ${isPrivacyTraceTree(cwd) ? "YES (do not pip-install runtime here)" : "no"}`);

  const wazuhRoot = env.PRIVACYTRACE_WAZUH_ROOT || "/var/ossec";
  const wazuh = fs.existsSync(path.join(wazuhRoot, "etc", "ossec.conf")) && fs.existsSync(path.join(wazuhRoot, "integrations"));
  print(stdout, `Wazuh Manager paths: ${wazuh ? "detected" : "not present"}`);
  print(stdout, `Git layout: ${fs.existsSync(path.join(cwd, ".git")) ? ".git present" : "no .git"}`);
  print(
    stdout,
    `Local GitHub Action: ${
      fs.existsSync(path.join(cwd, ".github", "actions", "privacytrace", "action.yml")) ? "present" : "not installed"
    }`,
  );

  const url = env[URL_ENV] || (manifest && manifest.url);
  if (url) {
    const parsed = parseEndpoint(url);
    print(stdout, `URL: ${parsed.href}`);
    for (const warning of parsed.warnings) print(stdout, `URL warning: ${warning}`);
  } else {
    print(stdout, "URL: unset");
  }

  if (env[TOKEN_ENV]) {
    print(stdout, "Token: supplied via environment (not printed). Doctor does not send payloads.");
  } else {
    print(stdout, "Token: not supplied. Doctor does not send payloads.");
  }
  print(stdout, "Auth validation: skipped (no payloads). Use add runtime for a synthetic receiver test.");
  return 0;
}

module.exports = { runDoctor };
