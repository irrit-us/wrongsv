#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const DEFAULT_EXTERNAL_TESTS_ROOT = path.resolve(REPO_ROOT, "..", "wrongsv-external-tests");

function parseArgs(argv) {
  const opts = {
    clients: "all",
    clientName: "wrongsv",
    serverName: "localhost",
    selfTest: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--wrongsv-bin":
        opts.wrongsvBin = path.resolve(next);
        i++;
        break;
      case "--config":
        opts.config = path.resolve(next);
        i++;
        break;
      case "--external-tests-root":
        opts.externalTestsRoot = path.resolve(next);
        i++;
        break;
      case "--output-dir":
        opts.outputDir = path.resolve(next);
        i++;
        break;
      case "--server-host":
        opts.serverHost = next;
        i++;
        break;
      case "--servername":
        opts.serverName = next;
        i++;
        break;
      case "--client-name":
        opts.clientName = next;
        i++;
        break;
      case "--clients":
        opts.clients = next;
        i++;
        break;
      case "--self-test":
        opts.selfTest = true;
        break;
      case "-h":
      case "--help":
        printHelp();
        process.exit(0);
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (opts.selfTest) {
    opts.externalTestsRoot = opts.externalTestsRoot || DEFAULT_EXTERNAL_TESTS_ROOT;
    return opts;
  }

  for (const key of ["wrongsvBin", "config", "externalTestsRoot", "outputDir", "serverHost"]) {
    if (!opts[key]) {
      throw new Error(`missing required ${key}`);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`generate-client-configs.js

Usage:
  node scripts/generate-client-configs.js \\
    --wrongsv-bin target/.../wrongsv \\
    --config configs/reality-vision.toml \\
    --external-tests-root ../wrongsv-external-tests \\
    --output-dir ./client-configs \\
    --server-host 203.0.113.10 \\
    --servername www.microsoft.com

Options:
  --clients <csv|all>     default: all clients known to wrongsv-external-tests
  --client-name <name>    default: wrongsv
  --self-test             validate scenario mapping and external capability assumptions
`);
}

function runWrongsvJson(opts, args) {
  const output = execFileSync(opts.wrongsvBin, args, {
    cwd: path.dirname(opts.wrongsvBin),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(output);
}

function writePrivateFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, { encoding: "utf8", mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, 0o600);
  }
}

function loadHarness(root) {
  const capabilities = require(path.join(root, "e2e-harness", "capabilities"));
  const scenarios = require(path.join(root, "e2e-harness", "scenarios"));
  const builders = require(path.join(root, "e2e-harness", "config-builders"));
  return { capabilities, scenarios, builders };
}

function includes(bucket, value) {
  return Array.isArray(bucket) && bucket.includes(value);
}

function scenarioIdForDiagnostics(diagnostics) {
  const r = diagnostics.resolved;
  const c = r.active_components || {};
  const camouflage = c.camouflage || [];
  const performance = c.performance || [];

  switch (r.protocol) {
    case "vless":
      if (includes(camouflage, "anytls")) return "anytls_tcp";
      if (includes(camouflage, "shadowtls")) return "shadowtls_tcp";
      if (r.transport === "websocket") return "vless_ws_tcp";
      if (r.transport === "httpupgrade") return "vless_httpupgrade";
      if (r.transport === "grpc") return "vless_grpc";
      if (r.transport === "xhttp") return "vless_xhttp";
      if (r.transport === "quic") return "vless_quic";
      if (r.transport === "kcp") return "vless_kcp";
      if (r.outer_security === "reality") return "vless_reality_vision";
      if (r.outer_security === "tls") {
        return includes(performance, "vision") ? "vless_tls_vision" : "vless_tls_tcp";
      }
      return "vless_raw_tcp";
    case "vmess":
      return "vmess_standard";
    case "shadowsocks":
      return r.protocol_internal_security === "shadowsocks_2022"
        ? "shadowsocks_2022"
        : "shadowsocks_aead";
    case "trojan":
      return "trojan_tls";
    case "hysteria2":
      return "hysteria2_tcp";
    case "tuic":
      return "tuic_tcp";
    case "wireguard":
      return "wireguard_tunnel_http";
    default:
      return null;
  }
}

function shellConfig(proxy, builders) {
  const proxyName = proxy.name || proxy.tag || "wrongsv";
  return builders.toYaml({
    "mixed-port": 7890,
    "allow-lan": false,
    "bind-address": "127.0.0.1",
    mode: "rule",
    "log-level": "info",
    ipv6: false,
    proxies: [proxy],
    "proxy-groups": [
      {
        name: "PROXY",
        type: "select",
        proxies: [proxyName],
      },
    ],
    rules: ["MATCH,PROXY"],
  });
}

function xrayRuntime(raw, client, clientName) {
  if (!Array.isArray(raw.outbounds) || raw.outbounds.length === 0) {
    throw new Error(`${client} raw xray config did not contain outbounds`);
  }
  const socksPort = client === "v2ray" ? 10818 : 10808;
  const primaryTag = raw.outbounds[0].tag || clientName;
  return JSON.stringify(
    {
      log: {
        loglevel: "warning",
      },
      inbounds: [
        {
          tag: "socks-in",
          listen: "127.0.0.1",
          port: socksPort,
          protocol: "socks",
          settings: {
            udp: true,
          },
        },
      ],
      outbounds: [
        ...raw.outbounds,
        {
          protocol: "freedom",
          tag: "direct",
        },
      ],
      routing: {
        domainStrategy: "AsIs",
        rules: [
          {
            type: "field",
            inboundTag: ["socks-in"],
            outboundTag: primaryTag,
          },
        ],
      },
    },
    null,
    2
  );
}

function validateRawForScenario(raw, client) {
  if (client === "flclash" || client === "clash-verge-rev") {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(`${client} raw config must be a single mihomo proxy object`);
    }
    if (!raw.name || !raw.type || !raw.server || !raw.port) {
      throw new Error(`${client} proxy object is missing name/type/server/port`);
    }
  }
  if (client === "sing-box") {
    if (!Array.isArray(raw.inbounds) || !Array.isArray(raw.outbounds)) {
      throw new Error("sing-box config must contain inbounds and outbounds");
    }
  }
  if (client === "hiddify") {
    if (!Array.isArray(raw.configs) && !Array.isArray(raw.outbounds)) {
      throw new Error("hiddify config must contain configs or sing-box outbounds");
    }
  }
  if (client === "xray-core" || client === "v2ray") {
    if (!Array.isArray(raw.outbounds) || raw.outbounds.length === 0) {
      throw new Error(`${client} config must contain outbounds`);
    }
  }
}

function runtimeContent(raw, client, builders, clientName) {
  switch (client) {
    case "flclash":
    case "clash-verge-rev":
      return { extension: ".yaml", content: shellConfig(raw, builders) };
    case "sing-box":
    case "hiddify":
      return { extension: ".json", content: JSON.stringify(raw, null, 2) };
    case "xray-core":
    case "v2ray":
      return { extension: ".json", content: xrayRuntime(raw, client, clientName) };
    default:
      throw new Error(`unsupported client ${client}`);
  }
}

function assertSelf(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function diagnosticsFor({
  protocol,
  transport = null,
  outerSecurity = null,
  protocolInternalSecurity = null,
  camouflage = [],
  performance = [],
}) {
  return {
    resolved: {
      protocol,
      transport,
      outer_security: outerSecurity,
      protocol_internal_security: protocolInternalSecurity,
      active_components: {
        camouflage,
        performance,
      },
    },
  };
}

function runSelfTest(externalTestsRoot) {
  const { capabilities, scenarios, builders } = loadHarness(externalTestsRoot);
  const wrongsvRepo = path.resolve(externalTestsRoot, "..", "wrongsv");
  const scenarioCatalog = scenarios.buildScenarios(wrongsvRepo);

  const mappingCases = [
    [diagnosticsFor({ protocol: "vless", camouflage: ["anytls"] }), "anytls_tcp"],
    [diagnosticsFor({ protocol: "vless", outerSecurity: "reality" }), "vless_reality_vision"],
    [
      diagnosticsFor({
        protocol: "vless",
        outerSecurity: "tls",
        performance: ["vision"],
      }),
      "vless_tls_vision",
    ],
    [diagnosticsFor({ protocol: "vless", transport: "grpc" }), "vless_grpc"],
    [diagnosticsFor({ protocol: "vless", transport: "xhttp" }), "vless_xhttp"],
    [diagnosticsFor({ protocol: "vless" }), "vless_raw_tcp"],
    [
      diagnosticsFor({
        protocol: "shadowsocks",
        protocolInternalSecurity: "shadowsocks_2022",
      }),
      "shadowsocks_2022",
    ],
    [diagnosticsFor({ protocol: "shadowsocks" }), "shadowsocks_aead"],
    [diagnosticsFor({ protocol: "trojan" }), "trojan_tls"],
    [diagnosticsFor({ protocol: "hysteria2" }), "hysteria2_tcp"],
    [diagnosticsFor({ protocol: "tuic" }), "tuic_tcp"],
    [diagnosticsFor({ protocol: "vmess" }), "vmess_standard"],
  ];

  for (const [diagnostics, expected] of mappingCases) {
    const actual = scenarioIdForDiagnostics(diagnostics);
    assertSelf(actual === expected, `expected ${expected}, got ${actual}`);
    assertSelf(scenarioCatalog[actual]?.id === actual, `missing external scenario ${actual}`);
  }

  const anytlsScenario = scenarioCatalog.anytls_tcp;
  const realityScenario = scenarioCatalog.vless_reality_vision;
  assertSelf(anytlsScenario, "missing external anytls_tcp scenario");
  assertSelf(realityScenario, "missing external vless_reality_vision scenario");

  assertSelf(
    builders.rawConfigFormat("flclash", anytlsScenario) === "mihomo",
    "FlClash AnyTLS must use mihomo raw config format"
  );
  assertSelf(
    builders.rawConfigFormat("clash-verge-rev", anytlsScenario) === "mihomo",
    "clash-verge-rev AnyTLS must use mihomo raw config format"
  );
  assertSelf(
    builders.rawConfigFormat("sing-box", anytlsScenario) === "sing-box",
    "sing-box AnyTLS must use sing-box raw config format"
  );
  assertSelf(
    builders.rawConfigFormat("xray-core", realityScenario) === "xray",
    "xray-core REALITY must use xray raw config format"
  );

  const runnable = (client, scenario) =>
    capabilities.CLIENT_CAPABILITIES[client]?.runnableScenarios?.includes(scenario) === true;
  const gap = (client, scenario) =>
    capabilities.CLIENT_CAPABILITIES[client]?.harnessGaps?.includes(scenario) === true;

  assertSelf(runnable("flclash", "anytls_tcp"), "FlClash must declare anytls_tcp runnable");
  assertSelf(
    runnable("clash-verge-rev", "anytls_tcp"),
    "clash-verge-rev/Mihomo must declare anytls_tcp runnable"
  );
  assertSelf(runnable("sing-box", "anytls_tcp"), "sing-box must declare anytls_tcp runnable");
  assertSelf(!gap("flclash", "anytls_tcp"), "FlClash anytls_tcp must not be a harness gap");
  assertSelf(!runnable("xray-core", "anytls_tcp"), "xray-core must not advertise AnyTLS");
  assertSelf(!runnable("v2ray", "anytls_tcp"), "v2ray must not advertise AnyTLS");
  assertSelf(
    !runnable("hiddify", "anytls_tcp"),
    "Hiddify AnyTLS must stay gated until direct GUI E2E passes"
  );
  assertSelf(gap("hiddify", "anytls_tcp"), "Hiddify AnyTLS must be documented as a harness gap");

  console.log("generate-client-configs self-test OK");
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.selfTest) {
    runSelfTest(opts.externalTestsRoot);
    return;
  }

  const { capabilities, scenarios, builders } = loadHarness(opts.externalTestsRoot);
  const wrongsvRepo = path.resolve(opts.externalTestsRoot, "..", "wrongsv");
  const scenarioCatalog = scenarios.buildScenarios(wrongsvRepo);
  const diagnostics = runWrongsvJson(opts, [
    "--config",
    opts.config,
    "--print-endpoint-diagnostics",
    "--server-host",
    opts.serverHost,
    "--servername",
    opts.serverName,
  ]);
  const scenarioId = scenarioIdForDiagnostics(diagnostics);
  const scenario = scenarioId ? scenarioCatalog[scenarioId] || { id: scenarioId } : null;
  const clients =
    opts.clients === "all"
      ? Object.keys(capabilities.CLIENT_CAPABILITIES)
      : opts.clients.split(",").map((item) => item.trim()).filter(Boolean);

  fs.mkdirSync(opts.outputDir, { recursive: true });
  fs.mkdirSync(path.join(opts.outputDir, "raw"), { recursive: true });

  const manifest = {
    generatedAt: new Date().toISOString(),
    config: opts.config,
    serverHost: opts.serverHost,
    serverName: opts.serverName,
    scenarioId,
    diagnostics,
    generated: [],
    skipped: [],
    failed: [],
  };

  for (const client of clients) {
    const capability = capabilities.CLIENT_CAPABILITIES[client];
    if (!capability) {
      manifest.failed.push({ client, error: "unknown client in wrongsv-external-tests" });
      continue;
    }
    if (!scenarioId || !capability.runnableScenarios.includes(scenarioId)) {
      manifest.skipped.push({
        client,
        scenarioId,
        reason: "scenario not declared runnable for client",
      });
      continue;
    }
    if ((capability.harnessGaps || []).includes(scenarioId)) {
      manifest.skipped.push({ client, scenarioId, reason: "scenario is a harness gap" });
      continue;
    }

    try {
      const format = builders.rawConfigFormat(client, scenario);
      const rawText = execFileSync(
        opts.wrongsvBin,
        [
          "--config",
          opts.config,
          "--print-client-config",
          "--format",
          format,
          "--server-host",
          opts.serverHost,
          "--servername",
          opts.serverName,
          "--client-name",
          `${opts.clientName}-${client}`,
        ],
        {
          cwd: path.dirname(opts.wrongsvBin),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }
      );
      const raw = JSON.parse(rawText);
      validateRawForScenario(raw, client);
      const rawPath = path.join(opts.outputDir, "raw", `${client}-${format}.json`);
      writePrivateFile(rawPath, JSON.stringify(raw, null, 2) + "\n");

      const runtime = runtimeContent(raw, client, builders, `${opts.clientName}-${client}`);
      const filePath = path.join(opts.outputDir, `${client}${runtime.extension}`);
      writePrivateFile(filePath, runtime.content.trimEnd() + "\n");
      manifest.generated.push({
        client,
        scenarioId,
        format,
        path: filePath,
        rawPath,
      });
    } catch (error) {
      manifest.failed.push({ client, scenarioId, error: error.message });
    }
  }

  writePrivateFile(
    path.join(opts.outputDir, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n"
  );
  const lines = [
    `# wrongsv client configs`,
    ``,
    `- Scenario: ${scenarioId || "unsupported"}`,
    `- Server: ${opts.serverHost}`,
    `- Server name: ${opts.serverName}`,
    ``,
    `## Generated`,
    ...manifest.generated.map((item) => `- ${item.client}: ${path.basename(item.path)}`),
    ``,
    `## Skipped`,
    ...manifest.skipped.map((item) => `- ${item.client}: ${item.reason}`),
    ``,
    `## Failed`,
    ...manifest.failed.map((item) => `- ${item.client}: ${item.error}`),
    ``,
  ];
  writePrivateFile(path.join(opts.outputDir, "manifest.md"), lines.join("\n"));

  if (manifest.failed.length > 0) {
    console.error(JSON.stringify(manifest.failed, null, 2));
    process.exit(1);
  }
  if (manifest.generated.length === 0) {
    console.error("no compatible client configs were generated");
    process.exit(1);
  }

  console.log(JSON.stringify({
    scenarioId,
    outputDir: opts.outputDir,
    generated: manifest.generated.map((item) => item.client),
    skipped: manifest.skipped.length,
  }, null, 2));
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = {
  scenarioIdForDiagnostics,
  validateRawForScenario,
  runtimeContent,
  runSelfTest,
  writePrivateFile,
};
