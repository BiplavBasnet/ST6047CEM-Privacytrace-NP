"use strict";

const VERSION = "0.1.0";

/** Verified local specifier. Not a public npm package. */
const NPX_PACKAGE_FILE = "file:./connectors/cli";
const NPX_PACKAGE_TGZ = "file:./privacytrace-connect-0.1.0.tgz";

const CLI_ADD_RUNTIME =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add runtime";
const CLI_ADD_WAZUH =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add wazuh";
const CLI_ADD_GITHUB =
  "npx --yes --package=file:./connectors/cli privacytrace-connect add github-actions";

const INSTALLABLE = ["runtime", "wazuh", "github-actions"];
const BUILTIN_NOT_INSTALLABLE = [
  { id: "scannerbridge", note: "built-in ScannerBridge-NP (not installable via this CLI)" },
  { id: "evidence-import", note: "built-in Evidence Import (not installable via this CLI)" },
];

const RECEIVER_PATH = "/integrations/connector/v1/events";
const TOKEN_ENV = "PRIVACYTRACE_CONNECTOR_TOKEN";
const URL_ENV = "PRIVACYTRACE_CONNECTOR_URL";
const SERVICE_ENV = "PRIVACYTRACE_SERVICE";
const ENVIRONMENT_ENV = "PRIVACYTRACE_ENVIRONMENT";
const MANIFEST_REL = ".privacytrace/install-manifest.json";

module.exports = {
  VERSION,
  NPX_PACKAGE_FILE,
  NPX_PACKAGE_TGZ,
  CLI_ADD_RUNTIME,
  CLI_ADD_WAZUH,
  CLI_ADD_GITHUB,
  INSTALLABLE,
  BUILTIN_NOT_INSTALLABLE,
  RECEIVER_PATH,
  TOKEN_ENV,
  URL_ENV,
  SERVICE_ENV,
  ENVIRONMENT_ENV,
  MANIFEST_REL,
};
