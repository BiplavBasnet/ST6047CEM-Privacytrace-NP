"use strict";

const {
  VERSION,
  INSTALLABLE,
  BUILTIN_NOT_INSTALLABLE,
  CLI_ADD_RUNTIME,
} = require("./constants");
const { parseArgs, formatError, print, redact } = require("./shared");
const { addConnector } = require("./add");
const { runDoctor } = require("./doctor");

const HELP = `privacytrace-connect ${VERSION}

Install and validate PrivacyTrace connectors in a target project.
Public npm registry distribution: NOT PUBLISHED.

Usage:
  privacytrace-connect list
  privacytrace-connect add <runtime|wazuh|github-actions> [--dry-run]
  privacytrace-connect doctor
  privacytrace-connect --help
  privacytrace-connect --version

Token: hidden prompt, or environment ${"PRIVACYTRACE_CONNECTOR_TOKEN"}.
Never pass --token. The install manifest never stores the token.

Verified local command (from the PrivacyTrace repository root):
  ${CLI_ADD_RUNTIME}
`;

function printList(stdout) {
  print(stdout, "Installable connectors:");
  for (const id of INSTALLABLE) print(stdout, `  ${id}`);
  print(stdout, "Built-in (not installable via this CLI):");
  for (const item of BUILTIN_NOT_INSTALLABLE) print(stdout, `  ${item.id}  ${item.note}`);
}

async function main(argv, io = {}) {
  const stdin = io.stdin || process.stdin;
  const stdout = io.stdout || process.stdout;
  const stderr = io.stderr || process.stderr;
  const env = io.env || process.env;
  const cwd = io.cwd || process.cwd();

  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    print(stderr, formatError(err));
    return 1;
  }
  const { flags, positionals } = parsed;
  if (flags.help || positionals[0] === "help") {
    stdout.write(`${HELP}\n`);
    return 0;
  }
  if (flags.version || positionals[0] === "version") {
    print(stdout, VERSION);
    return 0;
  }
  const command = positionals[0];
  if (!command) {
    stdout.write(`${HELP}\n`);
    return 0;
  }
  try {
    if (command === "list") {
      printList(stdout);
      return 0;
    }
    if (command === "add") {
      const connector = positionals[1];
      if (!connector) {
        print(stderr, "privacytrace-connect: missing connector. Try: runtime, wazuh, github-actions");
        return 1;
      }
      if (!INSTALLABLE.includes(connector)) {
        print(stderr, `privacytrace-connect: unknown connector '${redact(connector)}'. Try: ${INSTALLABLE.join(", ")}`);
        return 1;
      }
      return await addConnector(connector, {
        flags,
        stdin,
        stdout,
        stderr,
        env,
        cwd,
      });
    }
    if (command === "doctor") {
      return runDoctor({ flags, stdin, stdout, stderr, env, cwd });
    }
    print(stderr, `privacytrace-connect: unknown command '${redact(command)}'`);
    return 1;
  } catch (err) {
    print(stderr, formatError(err));
    return 1;
  }
}

module.exports = { main, HELP };
