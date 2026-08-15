#!/usr/bin/env node
"use strict";

const { main } = require("../src/main");

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code ?? 0;
  },
  (err) => {
    const { formatError } = require("../src/shared");
    process.stderr.write(`${formatError(err)}\n`);
    process.exitCode = 1;
  },
);
