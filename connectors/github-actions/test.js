"use strict";

const assert = require("node:assert/strict");
const { buildEvent, assertNoSecret } = require("./index.js");

const token = "ptig_super_secret_token_value";
const envelope = buildEvent({
  repo: "acme/payments",
  sha: "abc123def456",
  run_id: "42",
  workflow: "ci",
});

assert.equal(envelope.specversion, "1.0");
assert.equal(envelope.type, "np.privacytrace.cicd.github.run.v1");
assert.equal(envelope.data.repo, "acme/payments");
assert.equal(envelope.data.sha, "abc123def456");
assert.equal(envelope.data.run_id, "42");
assert.equal(envelope.data.workflow, "ci");
assert.ok(!("pull_request_title" in envelope.data));
assert.ok(!("commit_message" in envelope.data));
assert.ok(!JSON.stringify(envelope).includes(token));
assert.doesNotThrow(() => assertNoSecret(envelope, token));

const leaked = { ...envelope, data: { ...envelope.data, note: token } };
assert.throws(() => assertNoSecret(leaked, token));

console.log("github-actions contract ok");
