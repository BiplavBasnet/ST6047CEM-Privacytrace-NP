"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { VERSION, MANIFEST_REL } = require("./constants");
const {
  copyTracked,
  writeTracked,
  writeManifest,
  resolveUnderRoot,
  sha256Text,
  print,
  confirmContinue,
} = require("./shared");

function ossecSnippet(url) {
  return `<!-- EXAMPLE — adapt filters to local Wazuh rules. Do not forward every alert. -->
<!-- Staged by privacytrace-connect. Apply on the Wazuh Manager; this CLI does not edit production ossec.conf. -->
<ossec_conf>
  <integration>
    <name>custom-privacytrace</name>
    <hook_url>${url}</hook_url>
    <api_key>YOUR_PRIVACYTRACE_TOKEN</api_key>
    <level>10</level>
    <group>syscheck,rootcheck</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_conf>
`;
}

function managerPresent() {
  const root = process.env.PRIVACYTRACE_WAZUH_ROOT || "/var/ossec";
  return fs.existsSync(path.join(root, "etc", "ossec.conf")) && fs.existsSync(path.join(root, "integrations"));
}

function applySteps(stagedScript, stagedConf) {
  return [
    "On the Wazuh Manager — copy these commands; this CLI does not sudo or restart:",
    `cp ${stagedScript} /var/ossec/integrations/custom-privacytrace`,
    "chown root:wazuh /var/ossec/integrations/custom-privacytrace",
    "chmod 750 /var/ossec/integrations/custom-privacytrace",
    `Merge ${stagedConf} into /var/ossec/etc/ossec.conf (do not replace the whole file).`,
    "Restart the Wazuh manager to apply.",
  ];
}

async function addWazuh(ctx) {
  const { cwd, sourceRoot, endpoint, flags, stdout, stdin, env, tracker, token } = ctx;
  const srcScript = path.join(sourceRoot, "connectors", "wazuh", "custom-privacytrace");
  const destScriptRel = ".privacytrace/wazuh/custom-privacytrace";
  const destConfRel = ".privacytrace/wazuh/ossec.conf.example";
  const destScript = resolveUnderRoot(cwd, destScriptRel);
  const destConf = resolveUnderRoot(cwd, destConfRel);
  const confBody = ossecSnippet(endpoint);
  const detected = managerPresent();
  const plan = [
    detected
      ? "Wazuh Manager paths detected. V1 still stages files locally and does not edit production ossec.conf."
      : "Wazuh Manager not detected. Staging adapter files under .privacytrace/wazuh/.",
    `Copy connectors/wazuh/custom-privacytrace → ${destScriptRel}`,
    `Write ${destConfRel} with placeholder api_key (not the real token)`,
    `Write ${MANIFEST_REL} (no token)`,
    "Print copy/chown/chmod/restart steps. No sudo, no restart.",
  ];
  if (flags.labApply) {
    plan.push("Lab apply requested — requires PRIVACYTRACE_WAZUH_LAB=1 and confirmation.");
  }

  return {
    plan,
    summary: [
      ["Wazuh adapter", "STAGED"],
      ["Wazuh Manager", detected ? "PATHS DETECTED — PRODUCTION WRITE SKIPPED" : "REAL PLATFORM PENDING"],
    ],
    apply: async () => {
      copyTracked(tracker, srcScript, destScript);
      writeTracked(tracker, destConf, confBody);
      writeManifest(
        cwd,
        {
          version: VERSION,
          connector: "wazuh",
          timestamp: new Date().toISOString(),
          paths: [destScriptRel, destConfRel],
          hashes: {
            [destScriptRel]: require("./shared").sha256File(destScript),
            [destConfRel]: sha256Text(confBody),
          },
          url: endpoint,
          service: ctx.service,
          environment: ctx.environment,
        },
        tracker,
      );
      for (const line of applySteps(destScript, destConf)) print(stdout, line);

      if (flags.labApply) {
        if (env.PRIVACYTRACE_WAZUH_LAB !== "1") {
          print(stdout, "Lab apply ignored: set PRIVACYTRACE_WAZUH_LAB=1 to enable.");
        } else {
          print(stdout, "Lab apply would write /var/ossec (still requires a second confirmation).");
          const ok = await confirmContinue({ stdin, stdout, env });
          if (ok && detected) {
            print(stdout, "Lab apply is not implemented for production ossec.conf in V1. Files remain staged.");
          }
        }
      }

      if (token && env.PRIVACYTRACE_WRITE_WAZUH_KEY === "1") {
        print(stdout, "Writing a local api_key file is sensitive. Confirm to create .privacytrace/wazuh/api_key with mode 0600.");
        const ok = await confirmContinue({ stdin, stdout, env });
        if (ok) {
          const keyPath = resolveUnderRoot(cwd, ".privacytrace/wazuh/api_key");
          writeTracked(tracker, keyPath, `${token}\n`, { mode: 0o600 });
          const gitignore = resolveUnderRoot(cwd, ".privacytrace/wazuh/.gitignore");
          writeTracked(tracker, gitignore, "api_key\n");
          print(stdout, "Sensitive local api_key written (0600). Do not commit it.");
        }
      }

      return {
        code: 0,
        summary: [
          ["Wazuh adapter files", "CONFIGURED"],
          ["PrivacyTrace receiver", "NOT CONTACTED FROM MANAGER"],
          ["Wazuh Manager", "REAL PLATFORM PENDING"],
        ],
      };
    },
  };
}

module.exports = { addWazuh, ossecSnippet };
