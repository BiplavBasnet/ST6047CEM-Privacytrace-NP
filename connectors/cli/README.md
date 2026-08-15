# privacytrace-connect

Installer CLI for PrivacyTrace Runtime, Wazuh, and GitHub Actions connectors.

Public npm registry distribution: **NOT PUBLISHED**. There is no `npx privacytrace-connect` package on the public registry.

## Commands

```text
privacytrace-connect list
privacytrace-connect add runtime [--dry-run]
privacytrace-connect add wazuh [--dry-run]
privacytrace-connect add github-actions [--dry-run]
privacytrace-connect doctor
privacytrace-connect --help
privacytrace-connect --version
```

Token: hidden prompt, or `PRIVACYTRACE_CONNECTOR_TOKEN`. Never `--token`. The install manifest never stores the token.

## Verified local commands

From the PrivacyTrace repository root:

```text
npx --yes --package=file:./connectors/cli privacytrace-connect add runtime
```

After `npm pack` in `connectors/cli/`:

```text
npx --yes --package=file:./privacytrace-connect-0.1.0.tgz privacytrace-connect add runtime
```

Always-works in this repository:

```text
node connectors/cli/bin/privacytrace-connect.js --help
```

## Status language

The CLI reports **INSTALLED**, **CONFIGURED**, **RECEIVER VERIFIED**, or **REAL PLATFORM PENDING**. It does not print a catch-all CONNECTED.

Wazuh V1 stages files and prints Manager apply steps. It does not edit production `ossec.conf`, sudo, or restart.

GitHub V1 copies a local Action and workflow. It does not commit, push, open a PR, or call the GitHub secrets API.
