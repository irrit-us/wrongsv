#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const explicitBin = process.env.WRONGSV_BIN;
const debugBin = path.join(repoRoot, "target", "debug", "wrongsv");
const releaseBin = path.join(repoRoot, "target", "release", "wrongsv");
const subcommand = "generate-main-config";
const args = process.argv.slice(2);

let command;
let commandArgs;
if (explicitBin) {
  command = explicitBin;
  commandArgs = [subcommand, ...args];
} else if (fs.existsSync(debugBin)) {
  command = debugBin;
  commandArgs = [subcommand, ...args];
} else if (fs.existsSync(releaseBin)) {
  command = releaseBin;
  commandArgs = [subcommand, ...args];
} else {
  command = "cargo";
  commandArgs = ["run", "--quiet", "-p", "wrongsv", "--", subcommand, ...args];
}

const result = spawnSync(command, commandArgs, {
  cwd: repoRoot,
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
