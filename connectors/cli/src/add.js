"use strict";

const { URL_ENV, TOKEN_ENV, SERVICE_ENV, ENVIRONMENT_ENV } = require("./constants");
const {
  parseEndpoint,
  promptLine,
  promptHidden,
  confirmContinue,
  findPrivacyTraceRoot,
  print,
  rollbackCreated,
} = require("./shared");
const { addRuntime } = require("./add-runtime");
const { addWazuh } = require("./add-wazuh");
const { addGithub } = require("./add-github");

async function collectCommon(opts) {
  const { flags, stdin, stdout, env, cwd } = opts;
  const sourceRoot = findPrivacyTraceRoot({ cwd, env });
  if (!sourceRoot) {
    throw new Error(
      "Cannot find the PrivacyTrace connector sources. Run from the PrivacyTrace repository, or set PRIVACYTRACE_HOME.",
    );
  }
  const urlRaw = await promptLine("Connector URL: ", {
    stdin,
    stdout,
    envValue: env[URL_ENV],
  });
  const endpoint = parseEndpoint(urlRaw);
  for (const warning of endpoint.warnings) print(stdout, `Warning: ${warning}`);

  let token = "";
  if (!flags.dryRun || flags.checkAuth) {
    token = await promptHidden("Connector token (hidden): ", { stdin, stdout, env });
    if (!token) throw new Error("A connector token is required to apply or to check auth.");
  }

  const service =
    env[SERVICE_ENV] ||
    (!stdin.isTTY
      ? "wallet-api"
      : (await promptLine("Service id [wallet-api]: ", { stdin, stdout })) || "wallet-api");
  const environment =
    env[ENVIRONMENT_ENV] ||
    (!stdin.isTTY
      ? "production"
      : (await promptLine("Environment [production]: ", { stdin, stdout })) || "production");

  return {
    sourceRoot,
    endpoint: endpoint.href,
    token,
    service,
    environment,
  };
}

function printPlan(stdout, title, lines) {
  print(stdout, title);
  for (const line of lines) print(stdout, `  ${line}`);
}

function printSummary(stdout, rows) {
  print(stdout, "Summary:");
  for (const [label, value] of rows) print(stdout, `  ${label}: ${value}`);
}

async function addConnector(connector, opts) {
  const { flags, stdout } = opts;
  const common = await collectCommon(opts);
  const ctx = { ...opts, ...common, tracker: [] };
  let result;
  try {
    if (connector === "runtime") result = await addRuntime(ctx);
    else if (connector === "wazuh") result = await addWazuh(ctx);
    else result = await addGithub(ctx);
  } catch (err) {
    rollbackCreated(ctx.tracker);
    throw err;
  }

  printPlan(stdout, "Planned changes:", result.plan);
  if (flags.dryRun) {
    print(stdout, "Dry-run: no files, git, services, or remote calls were made.");
    printSummary(stdout, result.summary);
    return 0;
  }
  if (result.unsupported) {
    printSummary(stdout, result.summary);
    return 1;
  }
  const ok = await confirmContinue({ stdin: opts.stdin, stdout, env: opts.env });
  if (!ok) {
    print(stdout, "Declined. No files were written.");
    return 1;
  }
  try {
    const applied = await result.apply();
    printSummary(stdout, applied.summary);
    return applied.code ?? 0;
  } catch (err) {
    rollbackCreated(ctx.tracker);
    throw err;
  }
}

module.exports = { addConnector, collectCommon, TOKEN_ENV };
