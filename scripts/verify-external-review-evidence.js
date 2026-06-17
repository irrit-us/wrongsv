#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const defaultExternalRoot = path.resolve(repoRoot, "..", "wrongsv-external-tests");

function parseArgs(argv) {
  const opts = {
    externalRoot: defaultExternalRoot,
    passthrough: [],
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--":
        opts.passthrough.push(...argv.slice(i + 1));
        return opts;
      case "--external-tests-root":
        opts.externalRoot = path.resolve(next);
        i++;
        break;
      case "-h":
      case "--help":
        printHelp();
        process.exit(0);
      default:
        opts.passthrough.push(arg);
        break;
    }
  }

  return opts;
}

function printHelp() {
  console.log(`verify-external-review-evidence.js

Usage:
  node scripts/verify-external-review-evidence.js [options] [-- <verify-review-evidence args>]

Options:
  --external-tests-root <path>   path to sibling wrongsv-external-tests repo
  --help                         show this help

All remaining arguments are passed to:
  node scripts/verify-review-evidence.js
inside wrongsv-external-tests.
`);
}

function emitWrapperError(reasonCode, fields) {
  console.error(
    JSON.stringify(
      {
        reasonCode,
        ...fields,
      },
      null,
      2
    )
  );
}

function isDryRun(passthrough) {
  return passthrough.includes("--dry-run");
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const externalScript = path.join(
    opts.externalRoot,
    "scripts",
    "verify-review-evidence.js"
  );

  if (!fs.existsSync(externalScript)) {
    if (isDryRun(opts.passthrough)) {
      console.log(
        JSON.stringify(
          {
            dryRun: true,
            externalRoot: opts.externalRoot,
            externalScriptPresent: false,
            delegatedCommand: `node scripts/verify-review-evidence.js ${opts.passthrough.join(" ")}`.trim(),
          },
          null,
          2
        )
      );
      return;
    }
    emitWrapperError("external_review_helper_missing", {
      externalRoot: opts.externalRoot,
      expectedScript: externalScript,
      message:
        "verify-review-evidence.js not found; pass --external-tests-root or check out wrongsv-external-tests next to wrongsv",
    });
    process.exit(1);
  }

  const result = spawnSync(process.execPath, [externalScript, ...opts.passthrough], {
    cwd: opts.externalRoot,
    stdio: "inherit",
  });

  if (result.error) {
    emitWrapperError("external_review_helper_spawn_failed", {
      externalRoot: opts.externalRoot,
      expectedScript: externalScript,
      message: result.error.message,
    });
    process.exit(1);
  }

  process.exit(result.status ?? 1);
}

main();
