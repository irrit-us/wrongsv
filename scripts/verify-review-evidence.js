#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const opts = {
    wrongsvBin: null,
    externalRoot: path.resolve(repoRoot, "..", "wrongsv-external-tests"),
    skipExternal: false,
    standingOnly: null,
    outputRoot: null,
    outputFile: null,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--wrongsv-bin":
        opts.wrongsvBin = path.resolve(next);
        i++;
        break;
      case "--external-tests-root":
        opts.externalRoot = path.resolve(next);
        i++;
        break;
      case "--skip-external":
        opts.skipExternal = true;
        break;
      case "--standing-only":
        opts.standingOnly = next;
        i++;
        break;
      case "--output-root":
        opts.outputRoot = path.resolve(next);
        i++;
        break;
      case "--output-file":
        opts.outputFile = path.resolve(next);
        i++;
        break;
      case "--dry-run":
        opts.dryRun = true;
        break;
      case "-h":
      case "--help":
        printHelp();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return opts;
}

function printHelp() {
  console.log(`verify-review-evidence.js

Usage:
  node scripts/verify-review-evidence.js [options]

Options:
  --wrongsv-bin <path>          path to wrongsv binary (defaults to target/debug or target/release)
  --external-tests-root <path>  path to sibling wrongsv-external-tests repo
  --skip-external               run only the local client-generation self-test
  --standing-only <csv>         pass through to external standing-limitations checks
  --output-root <path>          pass through output root to the external standing review helper
  --output-file <path>          write the combined JSON summary to this file
  --dry-run                     print the planned commands without executing them
  --help                        show this help
`);
}

function resolveWrongsvBin(explicitPath) {
  if (explicitPath) return explicitPath;
  const debugBin = path.join(repoRoot, "target", "debug", "wrongsv");
  const releaseBin = path.join(repoRoot, "target", "release", "wrongsv");
  if (fs.existsSync(debugBin)) return debugBin;
  if (fs.existsSync(releaseBin)) return releaseBin;
  return null;
}

function maybeParseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function runNode(cwd, args) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    ok: result.status === 0,
    status: result.status ?? 1,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

function buildLocalCommand(wrongsvBin, externalRoot) {
  return buildLocalCommandWithMode({
    wrongsvBin,
    externalRoot,
    localOnly: false,
  });
}

function buildLocalCommandWithMode({ wrongsvBin, externalRoot, localOnly }) {
  const args = [
    "scripts/generate-client-configs.js",
    "--self-test",
    "--json",
    "--wrongsv-bin",
    wrongsvBin,
  ];
  if (localOnly) {
    args.push("--local-only");
  }
  if (externalRoot && fs.existsSync(externalRoot)) {
    args.push("--external-tests-root", externalRoot);
  }
  return args;
}

function buildExternalCommand(opts) {
  const args = ["scripts/verify-external-review-evidence.js"];
  if (opts.externalRoot) {
    args.push("--external-tests-root", opts.externalRoot);
  }
  if (opts.standingOnly) {
    args.push("--standing-only", opts.standingOnly);
  }
  if (opts.outputRoot) {
    args.push("--output-root", opts.outputRoot);
  }
  return args;
}

function defaultOutputFile(opts) {
  if (opts.outputFile) return opts.outputFile;
  if (opts.outputRoot) {
    return path.join(opts.outputRoot, "wrongsv-review-evidence-summary.json");
  }
  return null;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const wrongsvBin = resolveWrongsvBin(opts.wrongsvBin);
  const localArgs = buildLocalCommandWithMode({
    wrongsvBin: wrongsvBin || "<missing>",
    externalRoot: opts.externalRoot,
    localOnly: opts.skipExternal,
  });
  const externalArgs = buildExternalCommand(opts);
  const outputFile = defaultOutputFile(opts);

  if (opts.dryRun) {
    console.log(
      JSON.stringify(
        {
          outputFile,
          commands: {
            local: `node ${localArgs.join(" ")}`,
            external: opts.skipExternal ? null : `node ${externalArgs.join(" ")}`,
          },
        },
        null,
        2
      )
    );
    return;
  }

  if (!wrongsvBin) {
    console.error(
      JSON.stringify(
        {
          reasonCode: "wrongsv_binary_missing",
          repoRoot,
          message:
            "No wrongsv binary found at target/debug/wrongsv or target/release/wrongsv; build wrongsv or pass --wrongsv-bin",
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  const localRun = runNode(repoRoot, localArgs);
  const localSummary = {
    ok: localRun.ok,
    command: `node ${localArgs.join(" ")}`,
    stdout: maybeParseJson(localRun.stdout) || localRun.stdout.trim(),
    stderr: maybeParseJson(localRun.stderr) || localRun.stderr.trim(),
  };

  let externalSummary = {
    skipped: opts.skipExternal,
  };
  if (!opts.skipExternal) {
    const externalRun = runNode(repoRoot, externalArgs);
    externalSummary = {
      ok: externalRun.ok,
      command: `node ${externalArgs.join(" ")}`,
      stdout: maybeParseJson(externalRun.stdout) || externalRun.stdout.trim(),
      stderr: maybeParseJson(externalRun.stderr) || externalRun.stderr.trim(),
    };
  }

  const summary = {
    wrongsvBin,
    localSelfTest: localSummary,
    externalReview: externalSummary,
  };

  if (outputFile) {
    fs.mkdirSync(path.dirname(outputFile), { recursive: true });
    fs.writeFileSync(outputFile, JSON.stringify(summary, null, 2) + "\n", "utf8");
  }

  console.log(JSON.stringify(summary, null, 2));

  if (!localSummary.ok || (!opts.skipExternal && externalSummary.ok === false)) {
    process.exit(1);
  }
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
