"use strict";

/**
 * PrivacyTrace GitHub Actions connector (JavaScript action).
 * Inputs are read from INPUT_* env vars (GitHub Actions convention) so
 * untrusted context is never shell-interpolated.
 * The token is used only as an Authorization header and is never placed
 * on the event body or written to stdout/stderr.
 */

const EVENT_TYPE = "np.privacytrace.cicd.github.run.v1";

function input(name) {
  const key = `INPUT_${String(name).toUpperCase().replace(/ /g, "_")}`;
  const value = process.env[key];
  if (value == null) return "";
  return String(value).trim();
}

function buildEvent(fields) {
  const repo = fields.repo || "";
  const sha = fields.sha || "";
  const runId = fields.run_id || "";
  const workflow = fields.workflow || "";
  const data = {};
  if (repo) data.repo = repo.slice(0, 255);
  if (sha) data.sha = sha.slice(0, 64);
  if (runId) data.run_id = String(runId).slice(0, 64);
  if (workflow) data.workflow = workflow.slice(0, 255);
  data.severity = "info";
  data.message_summary = `GitHub Actions run ${data.run_id || "unknown"}`;
  const idParts = [data.repo || "repo", data.run_id || "run", data.sha || "sha"];
  return {
    specversion: "1.0",
    id: idParts.join(":").slice(0, 128),
    source: data.repo ? `/github/${data.repo}` : "/github/actions",
    type: EVENT_TYPE,
    time: new Date().toISOString(),
    datacontenttype: "application/json",
    data,
  };
}

function assertNoSecret(envelope, token) {
  const dumped = JSON.stringify(envelope);
  if (token && dumped.includes(token)) {
    throw new Error("refusing to send event that embeds the integration token");
  }
}

async function postEvent(endpoint, token, envelope) {
  assertNoSecret(envelope, token);
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(envelope),
  });
  if (!response.ok && response.status !== 409) {
    throw new Error(`privacytrace_http_${response.status}`);
  }
}

async function main() {
  const endpoint = input("endpoint");
  const token = input("token");
  if (!endpoint || !token) {
    throw new Error("endpoint and token inputs are required");
  }
  const envelope = buildEvent({
    repo: input("repo"),
    sha: input("sha"),
    run_id: input("run_id"),
    workflow: input("workflow"),
  });
  await postEvent(endpoint, token, envelope);
}

module.exports = { buildEvent, assertNoSecret, postEvent, main };

if (require.main === module) {
  main().catch((err) => {
    const message = err && err.message ? String(err.message) : "connector_failed";
    if (message.includes("ptig_")) {
      console.error("privacytrace connector failed");
    } else {
      console.error(message);
    }
    process.exit(1);
  });
}
