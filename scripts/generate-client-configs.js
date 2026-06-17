#!/usr/bin/env node

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const DEFAULT_EXTERNAL_TESTS_ROOT = path.resolve(REPO_ROOT, "..", "wrongsv-external-tests");
const VLESS_TRANSPORT_SCENARIOS = {
  websocket: "vless_ws_tcp",
  httpupgrade: "vless_httpupgrade",
  grpc: "vless_grpc",
  xhttp: "vless_xhttp",
  meek: "vless_meek",
  gdocsviewer: "vless_gdocsviewer",
  webtransport: "vless_webtransport",
  quic: "vless_quic",
  kcp: "vless_kcp",
};

function parseArgs(argv) {
  const opts = {
    clients: "all",
    clientName: "wrongsv",
    serverName: "localhost",
    noManifest: false,
    json: false,
    localOnly: false,
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
      case "--no-manifest":
        opts.noManifest = true;
        break;
      case "--self-test":
        opts.selfTest = true;
        break;
      case "--json":
        opts.json = true;
        break;
      case "--local-only":
        opts.localOnly = true;
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
  --no-manifest           skip manifest.json and manifest.md in the output dir
  --json                  when used with --self-test, emit a machine-readable JSON summary
  --local-only            when used with --self-test, skip external capability checks even if the sibling repo exists
  --self-test             validate scenario mapping and external capability assumptions
                          pass --wrongsv-bin to also verify representative real configs;
                          when wrongsv-external-tests is unavailable, only the
                          internal mapping/config checks run
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

function hasHarnessRoot(root) {
  if (!root) return false;
  return fs.existsSync(path.join(root, "e2e-harness", "capabilities.js"));
}

function clientFamilyFormat(client) {
  switch (client) {
    case "flclash":
    case "clash-verge-rev":
      return "mihomo";
    case "sing-box":
      return "sing-box";
    case "hiddify":
      return "hiddify";
    case "xray-core":
    case "v2ray":
      return "xray";
    default:
      throw new Error(`Unknown client family format mapping for ${client}`);
  }
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
      if (r.transport && VLESS_TRANSPORT_SCENARIOS[r.transport]) {
        return VLESS_TRANSPORT_SCENARIOS[r.transport];
      }
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

function scenarioIdForDiagnosticsWithHarness(diagnostics, scenariosModule = null) {
  if (scenariosModule && typeof scenariosModule.scenarioIdFromResolvedDiagnostics === "function") {
    return scenariosModule.scenarioIdFromResolvedDiagnostics(diagnostics);
  }
  return scenarioIdForDiagnostics(diagnostics);
}

function intentionallyUntrackedScenario(capabilities, scenarioId) {
  return capabilities?.INTENTIONALLY_UNTRACKED_SCENARIOS?.[scenarioId] || null;
}

function skipDecisionForClient({
  capability,
  scenarioId,
  scenarioKnownToHarness,
  intentionallyUntracked,
}) {
  if ((capability.harnessGaps || []).includes(scenarioId)) {
    return {
      reasonCode: "harness_gap",
      reason:
        capability.harnessGapReasons?.[scenarioId] || "scenario is a harness gap",
    };
  }
  if (!scenarioId) {
    return {
      reasonCode: "scenario_unrecognized",
      reason: "scenario could not be derived from endpoint diagnostics",
    };
  }
  if (!scenarioKnownToHarness || intentionallyUntracked) {
    return {
      reasonCode: "scenario_untracked",
      reason:
        intentionallyUntracked?.reason ||
        "scenario is not yet represented in external capability metadata",
    };
  }
  if (!capability.runnableScenarios.includes(scenarioId)) {
    return {
      reasonCode: "client_not_runnable_for_scenario",
      reason: "scenario not declared runnable for client",
    };
  }
  return null;
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

function verifyMappedScenario(scenarioCatalog, scenarioId, message, untrackedScenarios = {}) {
  if (untrackedScenarios[scenarioId]) {
    assertSelf(
      scenarioCatalog[scenarioId]?.id === scenarioId,
      `${message}: intentionally untracked scenario ${scenarioId} should still exist in the external scenario catalog`
    );
    return;
  }
  assertSelf(scenarioCatalog[scenarioId]?.id === scenarioId, `${message}: missing external scenario ${scenarioId}`);
}

function verifyConfigMapping(wrongsvBin, configPath, expectedScenario) {
  const diagnostics = runWrongsvJson(
    { wrongsvBin },
    [
      "--config",
      configPath,
      "--print-endpoint-diagnostics",
      "--server-host",
      "127.0.0.1",
      "--servername",
      "localhost",
    ]
  );
  const actual = scenarioIdForDiagnostics(diagnostics);
  assertSelf(
    actual === expectedScenario,
    `expected ${expectedScenario} for ${path.basename(configPath)}, got ${actual}`
  );
}

function verifyExportDiagnostics(
  wrongsvBin,
  configPath,
  format,
  { supported, errorCode = null, errorContains = null }
) {
  const diagnostics = runWrongsvJson(
    { wrongsvBin },
    [
      "--config",
      configPath,
      "--print-endpoint-diagnostics",
      "--format",
      format,
      "--server-host",
      "127.0.0.1",
      "--servername",
      "localhost",
    ]
  );
  assertSelf(
    diagnostics.export?.supported === supported,
    `expected export.supported=${supported} for ${path.basename(configPath)} (${format})`
  );
  if (errorCode) {
    assertSelf(
      diagnostics.export?.error_code === errorCode,
      `expected ${path.basename(configPath)} (${format}) export.error_code=${errorCode}`
    );
  }
  if (errorContains) {
    assertSelf(
      (diagnostics.export?.error || "").includes(errorContains),
      `expected ${path.basename(configPath)} (${format}) export error to contain: ${errorContains}`
    );
  }
}

function verifyClientConfigFailure(wrongsvBin, configPath, format, errorContains) {
  try {
    execFileSync(
      wrongsvBin,
      [
        "--config",
        configPath,
        "--print-client-config",
        "--format",
        format,
        "--server-host",
        "127.0.0.1",
        "--servername",
        "localhost",
      ],
      {
        cwd: path.dirname(wrongsvBin),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    throw new Error(
      `expected ${path.basename(configPath)} (${format}) client export to fail`
    );
  } catch (error) {
    const stderr = error.stderr?.toString?.() || error.stderr || "";
    const stdout = error.stdout?.toString?.() || error.stdout || "";
    const combined = `${stdout}\n${stderr}\n${error.message || ""}`;
    assertSelf(
      combined.includes(errorContains),
      `expected ${path.basename(configPath)} (${format}) failure to contain: ${errorContains}`
    );
  }
}

function buildExportDiagnosticsArgs(opts, format) {
  return [
    "--config",
    opts.config,
    "--print-endpoint-diagnostics",
    "--format",
    format,
    "--server-host",
    opts.serverHost,
    "--servername",
    opts.serverName,
  ];
}

function classifyClientExportFailure(opts, format, error) {
  const stderr = error?.stderr?.toString?.() || error?.stderr || "";
  const stdout = error?.stdout?.toString?.() || error?.stdout || "";
  const fallbackError = stderr.trim() || stdout.trim() || error?.message || "client export failed";
  try {
    const diagnostics = runWrongsvJson(opts, buildExportDiagnosticsArgs(opts, format));
    const exportInfo = diagnostics.export || {};
    if (exportInfo.error_code || exportInfo.error) {
      return {
        reasonCode: exportInfo.error_code || "client_export_failed",
        error: exportInfo.error || fallbackError,
      };
    }
  } catch (_) {}
  return {
    reasonCode: "client_export_failed",
    error: fallbackError,
  };
}

function preflightClientFamilyExportSupport(opts, client) {
  const format = clientFamilyFormat(client);
  const diagnostics = runWrongsvJson(opts, buildExportDiagnosticsArgs(opts, format));
  const exportInfo = diagnostics.export || {};
  if (exportInfo.supported === false) {
    return {
      format,
      supported: false,
      reasonCode: exportInfo.error_code || "client_family_export_unsupported",
      error:
        exportInfo.error ||
        `client family export is unsupported for ${client} (${format})`,
    };
  }
  return {
    format,
    supported: true,
    reasonCode: null,
    error: null,
  };
}

function buildExportPreflightSummary(opts, clients) {
  const byFormat = {};
  for (const client of clients) {
    let format;
    try {
      format = clientFamilyFormat(client);
    } catch {
      continue;
    }
    if (!byFormat[format]) {
      const support = preflightClientFamilyExportSupport(opts, client);
      byFormat[format] = {
        clients: [client],
        supported: support.supported,
        reasonCode: support.reasonCode,
        error: support.error,
      };
    } else if (!byFormat[format].clients.includes(client)) {
      byFormat[format].clients.push(client);
    }
  }
  return byFormat;
}

function runGenerationCommand(args, cwd = REPO_ROOT) {
  try {
    const stdout = execFileSync(process.execPath, [__filename, ...args], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout?.toString?.() || error.stdout || "",
      stderr: error.stderr?.toString?.() || error.stderr || "",
    };
  }
}

function readManifest(outputDir) {
  return JSON.parse(fs.readFileSync(path.join(outputDir, "manifest.json"), "utf8"));
}

function writeFailureSummary(manifest, reasonCode) {
  console.error(
    JSON.stringify(
      {
        reasonCode,
        scenarioId: manifest.scenarioId,
        generatedCount: manifest.generated.length,
        exportPreflight: manifest.exportPreflight,
        skipped: manifest.skipped,
        failed: manifest.failed,
      },
      null,
      2
    )
  );
}

function createDriftedHarnessRoot(sourceRoot) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "wrongsv-harness-drift-"));
  fs.mkdirSync(path.join(tempRoot, "e2e-harness"), { recursive: true });
  for (const file of ["capabilities.js", "scenarios.js", "config-builders.js"]) {
    fs.copyFileSync(
      path.join(sourceRoot, "e2e-harness", file),
      path.join(tempRoot, "e2e-harness", file)
    );
  }
  const capabilitiesPath = path.join(tempRoot, "e2e-harness", "capabilities.js");
  let text = fs.readFileSync(capabilitiesPath, "utf8");
  text = text.replace(
    '      "tuic_tcp",\n      "shadowtls_tcp",',
    '      "tuic_tcp",\n      "anytls_tcp",\n      "shadowtls_tcp",'
  );
  text = text.replace('    harnessGaps: ["anytls_tcp"],', "    harnessGaps: [],");
  text = text.replace(/\s+harnessGapReasons:\s*\{[\s\S]*?\},\n/, "    harnessGapReasons: {},\n");
  fs.writeFileSync(capabilitiesPath, text, "utf8");
  return tempRoot;
}

function runSelfTest(externalTestsRoot, wrongsvBin = null, options = {}) {
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
    [diagnosticsFor({ protocol: "vless", transport: "meek", outerSecurity: "tls" }), "vless_meek"],
    [
      diagnosticsFor({ protocol: "vless", transport: "gdocsviewer" }),
      "vless_gdocsviewer",
    ],
    [
      diagnosticsFor({ protocol: "vless", transport: "webtransport", outerSecurity: "tls" }),
      "vless_webtransport",
    ],
    [diagnosticsFor({ protocol: "vless", transport: "quic", outerSecurity: "tls" }), "vless_quic"],
    [diagnosticsFor({ protocol: "vless", transport: "kcp" }), "vless_kcp"],
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

  let harness = null;
  let wrongsvRepo = REPO_ROOT;
  let scenarioCatalog = null;
  let untrackedScenarios = {};
  let scenariosModule = null;
  if (!options.localOnly && hasHarnessRoot(externalTestsRoot)) {
    harness = loadHarness(externalTestsRoot);
    scenariosModule = harness.scenarios;
    wrongsvRepo = path.resolve(externalTestsRoot, "..", "wrongsv");
    scenarioCatalog = harness.scenarios.buildScenarios(wrongsvRepo);
    untrackedScenarios = harness.capabilities.INTENTIONALLY_UNTRACKED_SCENARIOS || {};
  }
  const summary = {
    status: "ok",
    usedHarness: Boolean(harness),
    usedWrongsvBin: Boolean(wrongsvBin),
    syntheticMappingCases: mappingCases.length,
    configBackedCases: 0,
    notes: [],
  };

  for (const [diagnostics, expected] of mappingCases) {
    const actual = scenarioIdForDiagnostics(diagnostics);
    assertSelf(actual === expected, `expected ${expected}, got ${actual}`);
    if (scenariosModule?.scenarioIdFromResolvedDiagnostics) {
      const externalActual = scenarioIdForDiagnosticsWithHarness(diagnostics, scenariosModule);
      assertSelf(
        externalActual === actual,
        `external scenario mapper drifted for ${expected}: expected ${actual}, got ${externalActual}`
      );
    }
    if (scenarioCatalog) {
      verifyMappedScenario(scenarioCatalog, actual, "synthetic mapping", untrackedScenarios);
    }
  }

  if (harness && scenarioCatalog) {
    const { capabilities, builders } = harness;
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
    const gapReason = (client, scenario) =>
      capabilities.CLIENT_CAPABILITIES[client]?.harnessGapReasons?.[scenario] || "";

    assertSelf(runnable("flclash", "anytls_tcp"), "FlClash must declare anytls_tcp runnable");
    assertSelf(
      runnable("clash-verge-rev", "anytls_tcp"),
      "clash-verge-rev/Mihomo must declare anytls_tcp runnable"
    );
    assertSelf(runnable("sing-box", "anytls_tcp"), "sing-box must declare anytls_tcp runnable");
    assertSelf(!gap("flclash", "anytls_tcp"), "FlClash anytls_tcp must not be a harness gap");
    assertSelf(!runnable("xray-core", "anytls_tcp"), "xray-core must not advertise AnyTLS");
    assertSelf(!runnable("v2ray", "anytls_tcp"), "v2ray must not advertise AnyTLS");
    assertSelf(runnable("v2ray", "vless_meek"), "v2ray must declare vless_meek runnable");
    assertSelf(
      runnable("v2ray", "vless_gdocsviewer"),
      "v2ray must declare vless_gdocsviewer runnable"
    );
    for (const capability of Object.values(capabilities.CLIENT_CAPABILITIES)) {
      assertSelf(
        !includes(capability.runnableScenarios, "vless_webtransport"),
        "WebTransport should stay untracked until wrongsv-external-tests adds explicit capability metadata"
      );
      assertSelf(
        !includes(capability.harnessGaps, "vless_webtransport"),
        "WebTransport should stay absent from harness gaps until the external matrix defines that scenario"
      );
    }
    assertSelf(
      !runnable("hiddify", "anytls_tcp"),
      "Hiddify AnyTLS must stay gated until direct GUI E2E passes"
    );
    assertSelf(gap("hiddify", "anytls_tcp"), "Hiddify AnyTLS must be documented as a harness gap");
    assertSelf(
      /generated AnyTLS outbound/.test(gapReason("hiddify", "anytls_tcp")),
      "Hiddify AnyTLS gap reason must explain the packaged-core AnyTLS outbound rejection"
    );

    const hiddifyAnytlsSkip = skipDecisionForClient({
      capability: capabilities.CLIENT_CAPABILITIES.hiddify,
      scenarioId: "anytls_tcp",
      scenarioKnownToHarness: true,
    });
    assertSelf(
      hiddifyAnytlsSkip?.reasonCode === "harness_gap",
      "Hiddify AnyTLS skip decision must remain a harness gap"
    );
    assertSelf(
      /generated AnyTLS outbound/.test(hiddifyAnytlsSkip?.reason || ""),
      "Hiddify AnyTLS skip reason must include the packaged-core AnyTLS outbound rejection"
    );

    const webtransportSkip = skipDecisionForClient({
      capability: capabilities.CLIENT_CAPABILITIES.flclash,
      scenarioId: "vless_webtransport",
      scenarioKnownToHarness: true,
      intentionallyUntracked: intentionallyUntrackedScenario(
        capabilities,
        "vless_webtransport"
      ),
    });
    assertSelf(
      webtransportSkip?.reasonCode === "scenario_untracked",
      "WebTransport skip decision must stay distinct from generic non-runnable scenarios"
    );
    assertSelf(
      /intentionally untracked/.test(webtransportSkip?.reason || ""),
      "WebTransport skip decision should carry the explicit intentionally untracked metadata reason"
    );

    const xrayAnytlsSkip = skipDecisionForClient({
      capability: capabilities.CLIENT_CAPABILITIES["xray-core"],
      scenarioId: "anytls_tcp",
      scenarioKnownToHarness: true,
    });
    assertSelf(
      xrayAnytlsSkip?.reasonCode === "client_not_runnable_for_scenario",
      "xray-core AnyTLS skip decision must stay a non-runnable capability, not a harness gap"
    );
    summary.notes.push("external capability metadata checks passed");
  }

  if (wrongsvBin) {
    const configCases = [
      ["configs/basic-tcp.toml", "vless_raw_tcp"],
      ["configs/tls-tcp.toml", "vless_tls_tcp"],
      ["configs/tls-vision.toml", "vless_tls_vision"],
      ["configs/reality-vision.toml", "vless_reality_vision"],
      ["configs/ws-tcp.toml", "vless_ws_tcp"],
      ["configs/httpupgrade.toml", "vless_httpupgrade"],
      ["configs/grpc.toml", "vless_grpc"],
      ["configs/xhttp.toml", "vless_xhttp"],
      ["configs/meek.toml", "vless_meek"],
      ["configs/gdocsviewer.toml", "vless_gdocsviewer"],
      ["configs/quic.toml", "vless_quic"],
      ["configs/kcp.toml", "vless_kcp"],
      ["configs/webtransport.toml", "vless_webtransport"],
      ["configs/anytls-tcp.toml", "anytls_tcp"],
      ["configs/shadowtls.toml", "shadowtls_tcp"],
      ["configs/shadowsocks-aead.toml", "shadowsocks_aead"],
      ["configs/shadowsocks-2022.toml", "shadowsocks_2022"],
      ["configs/trojan-tls.toml", "trojan_tls"],
      ["configs/hysteria2.toml", "hysteria2_tcp"],
      ["configs/tuic.toml", "tuic_tcp"],
      ["configs/vmess.toml", "vmess_standard"],
      ["configs/wireguard.toml", "wireguard_tunnel_http"],
    ];
    summary.configBackedCases = configCases.length;
    for (const [relativeConfigPath, expectedScenario] of configCases) {
      const configPath = path.join(wrongsvRepo, relativeConfigPath);
      verifyConfigMapping(wrongsvBin, configPath, expectedScenario);
      if (scenarioCatalog) {
        verifyMappedScenario(
          scenarioCatalog,
          expectedScenario,
          `config-backed mapping for ${relativeConfigPath}`,
          untrackedScenarios
        );
      }
    }

    const webtransportConfigPath = path.join(wrongsvRepo, "configs/webtransport.toml");
    verifyExportDiagnostics(wrongsvBin, webtransportConfigPath, "xray", {
      supported: false,
      errorCode: "webtransport_xray_family_export_disabled",
      errorContains: "WebTransport export is disabled",
    });
    verifyClientConfigFailure(
      wrongsvBin,
      webtransportConfigPath,
      "xray",
      "WebTransport export is disabled"
    );

    const anytlsConfigPath = path.join(wrongsvRepo, "configs/anytls-vision.toml");
    verifyExportDiagnostics(wrongsvBin, anytlsConfigPath, "hiddify", {
      supported: false,
      errorCode: "hiddify_anytls_packaged_core_gap",
      errorContains:
        "packaged Hiddify core rejected the generated AnyTLS outbound and never exposed the local mixed proxy port",
    });
    verifyClientConfigFailure(
      wrongsvBin,
      anytlsConfigPath,
      "hiddify",
      "packaged Hiddify core rejected the generated AnyTLS outbound and never exposed the local mixed proxy port"
    );

    const classifiedWebtransportFailure = classifyClientExportFailure(
      {
        wrongsvBin,
        config: webtransportConfigPath,
        serverHost: "127.0.0.1",
        serverName: "localhost",
      },
      "xray",
      new Error("synthetic export failure")
    );
    assertSelf(
      classifiedWebtransportFailure.reasonCode === "webtransport_xray_family_export_disabled",
      "WebTransport export failure classification must reuse the diagnostics error_code"
    );

    const classifiedHiddifyAnytlsFailure = classifyClientExportFailure(
      {
        wrongsvBin,
        config: anytlsConfigPath,
        serverHost: "127.0.0.1",
        serverName: "localhost",
      },
      "hiddify",
      new Error("synthetic export failure")
    );
    assertSelf(
      classifiedHiddifyAnytlsFailure.reasonCode === "hiddify_anytls_packaged_core_gap",
      "Hiddify AnyTLS export failure classification must reuse the diagnostics error_code"
    );

    const hiddifyPreflight = preflightClientFamilyExportSupport(
      {
        wrongsvBin,
        config: anytlsConfigPath,
        serverHost: "127.0.0.1",
        serverName: "localhost",
      },
      "hiddify"
    );
    assertSelf(
      hiddifyPreflight.reasonCode === "hiddify_anytls_packaged_core_gap",
      "Hiddify AnyTLS preflight must fail with the packaged-core export error_code"
    );

    const webtransportPreflight = preflightClientFamilyExportSupport(
      {
        wrongsvBin,
        config: webtransportConfigPath,
        serverHost: "127.0.0.1",
        serverName: "localhost",
      },
      "xray-core"
    );
    assertSelf(
      webtransportPreflight.reasonCode === "webtransport_xray_family_export_disabled",
      "WebTransport xray preflight must fail with the xray-family export error_code"
    );

    if (harness && scenarioCatalog) {
      const webtransportOutputDir = fs.mkdtempSync(
        path.join(os.tmpdir(), "wrongsv-webtransport-manifest-")
      );
      const webtransportRun = runGenerationCommand([
        "--wrongsv-bin",
        wrongsvBin,
        "--config",
        webtransportConfigPath,
        "--external-tests-root",
        externalTestsRoot,
        "--output-dir",
        webtransportOutputDir,
        "--server-host",
        "127.0.0.1",
        "--servername",
        "localhost",
        "--clients",
        "xray-core",
      ]);
      assertSelf(
        !webtransportRun.ok,
        "WebTransport generation should fail because no compatible client artifacts are produced"
      );
      const webtransportManifest = readManifest(webtransportOutputDir);
      assertSelf(
        webtransportManifest.skipped[0]?.reasonCode === "scenario_untracked",
        "WebTransport manifest skip should use reasonCode=scenario_untracked"
      );
      assertSelf(
        webtransportManifest.exportPreflight?.xray?.reasonCode ===
          "webtransport_xray_family_export_disabled",
        "WebTransport manifest should record the xray-family export preflight failure"
      );
      assertSelf(
        /"reasonCode": "no_compatible_client_configs_generated"/.test(
          webtransportRun.stderr
        ) &&
          /"reasonCode": "scenario_untracked"/.test(webtransportRun.stderr) &&
          /"exportPreflight"/.test(webtransportRun.stderr),
        "WebTransport no-compatible failure output should include the summary reasonCode and scenario_untracked details"
      );

      const anytlsSkipOutputDir = fs.mkdtempSync(
        path.join(os.tmpdir(), "wrongsv-anytls-skip-manifest-")
      );
      const anytlsSkipRun = runGenerationCommand([
        "--wrongsv-bin",
        wrongsvBin,
        "--config",
        anytlsConfigPath,
        "--external-tests-root",
        externalTestsRoot,
        "--output-dir",
        anytlsSkipOutputDir,
        "--server-host",
        "127.0.0.1",
        "--servername",
        "localhost",
        "--clients",
        "hiddify",
      ]);
      assertSelf(
        !anytlsSkipRun.ok,
        "Hiddify AnyTLS generation should fail because the client remains a harness gap"
      );
      const anytlsSkipManifest = readManifest(anytlsSkipOutputDir);
      assertSelf(
        anytlsSkipManifest.skipped[0]?.reasonCode === "harness_gap",
        "Hiddify AnyTLS manifest skip should use reasonCode=harness_gap"
      );
      assertSelf(
        anytlsSkipManifest.exportPreflight?.hiddify?.reasonCode ===
          "hiddify_anytls_packaged_core_gap",
        "Hiddify AnyTLS manifest should record the hiddify export preflight failure"
      );
      assertSelf(
        /"reasonCode": "no_compatible_client_configs_generated"/.test(
          anytlsSkipRun.stderr
        ) &&
          /"reasonCode": "harness_gap"/.test(anytlsSkipRun.stderr) &&
          /"exportPreflight"/.test(anytlsSkipRun.stderr),
        "Hiddify AnyTLS no-compatible failure output should include the summary reasonCode and harness_gap details"
      );

      const driftedHarnessRoot = createDriftedHarnessRoot(externalTestsRoot);
      const anytlsFailedOutputDir = fs.mkdtempSync(
        path.join(os.tmpdir(), "wrongsv-anytls-failed-manifest-")
      );
      const anytlsFailedRun = runGenerationCommand([
        "--wrongsv-bin",
        wrongsvBin,
        "--config",
        anytlsConfigPath,
        "--external-tests-root",
        driftedHarnessRoot,
        "--output-dir",
        anytlsFailedOutputDir,
        "--server-host",
        "127.0.0.1",
        "--servername",
        "localhost",
        "--clients",
        "hiddify",
      ]);
      assertSelf(
        !anytlsFailedRun.ok,
        "Drifted Hiddify AnyTLS generation should fail through the family export preflight"
      );
      const anytlsFailedManifest = readManifest(anytlsFailedOutputDir);
      assertSelf(
        anytlsFailedManifest.failed[0]?.reasonCode === "hiddify_anytls_packaged_core_gap",
        "Hiddify AnyTLS manifest failure should reuse the packaged-core error_code"
      );
      assertSelf(
        anytlsFailedManifest.exportPreflight?.hiddify?.reasonCode ===
          "hiddify_anytls_packaged_core_gap",
        "Drifted Hiddify AnyTLS manifest should keep the hiddify export preflight failure"
      );
      assertSelf(
        /"reasonCode": "client_generation_failed"/.test(anytlsFailedRun.stderr) &&
          /"reasonCode": "hiddify_anytls_packaged_core_gap"/.test(anytlsFailedRun.stderr) &&
          /"exportPreflight"/.test(anytlsFailedRun.stderr),
        "Drifted Hiddify AnyTLS failure output should include both the summary reasonCode and the packaged-core error_code"
      );

      const meekOutputDir = fs.mkdtempSync(path.join(os.tmpdir(), "wrongsv-meek-success-"));
      const meekRun = runGenerationCommand([
        "--wrongsv-bin",
        wrongsvBin,
        "--config",
        path.join(wrongsvRepo, "configs/meek.toml"),
        "--external-tests-root",
        externalTestsRoot,
        "--output-dir",
        meekOutputDir,
        "--server-host",
        "127.0.0.1",
        "--servername",
        "localhost",
        "--clients",
        "v2ray",
        "--no-manifest",
      ]);
      assertSelf(meekRun.ok, "Meek generation should succeed for v2ray");
      const meekSummary = JSON.parse(meekRun.stdout);
      assertSelf(
        meekSummary.exportPreflight?.xray?.supported === true &&
          meekSummary.generatedCount === 1 &&
          Array.isArray(meekSummary.skippedDetails) &&
          meekSummary.skippedDetails.length === 0,
        "Successful generation output should include exportPreflight, generatedCount, and skippedDetails"
      );
      summary.notes.push("manifest/stdout/stderr probe checks passed");
    }
  }

  if (!harness) {
    summary.notes.push(
      options.localOnly
        ? "external capability checks skipped by --local-only"
        : "external capability checks skipped because wrongsv-external-tests was unavailable"
    );
    if (!options.json) {
      console.log(
        options.localOnly
          ? "generate-client-configs self-test skipped external capability checks (--local-only)"
          : "generate-client-configs self-test skipped external capability checks (wrongsv-external-tests unavailable)"
      );
    }
  }
  if (options.json) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.log("generate-client-configs self-test OK");
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.selfTest) {
    runSelfTest(opts.externalTestsRoot, opts.wrongsvBin, {
      json: opts.json,
      localOnly: opts.localOnly,
    });
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
  const scenarioId = scenarioIdForDiagnosticsWithHarness(diagnostics, scenarios);
  const scenarioKnownToHarness = Boolean(scenarioId && scenarioCatalog[scenarioId]);
  const scenarioUntracked = intentionallyUntrackedScenario(capabilities, scenarioId);
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
    exportPreflight: buildExportPreflightSummary(opts, clients),
    generated: [],
    skipped: [],
    failed: [],
  };

  for (const client of clients) {
    const capability = capabilities.CLIENT_CAPABILITIES[client];
    if (!capability) {
      manifest.failed.push({
        client,
        error: "unknown client in wrongsv-external-tests",
        reasonCode: "unknown_client",
      });
      continue;
    }
    const skipDecision = skipDecisionForClient({
      capability,
      scenarioId,
      scenarioKnownToHarness,
      intentionallyUntracked: scenarioUntracked,
    });
    if (skipDecision) {
      manifest.skipped.push({
        client,
        scenarioId,
        reasonCode: skipDecision.reasonCode,
        reason: skipDecision.reason,
      });
      continue;
    }

    let familyExport;
    try {
      familyExport = preflightClientFamilyExportSupport(opts, client);
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        reasonCode: "client_family_export_preflight_failed",
        error: error.message,
      });
      continue;
    }
    if (!familyExport.supported) {
      manifest.failed.push({
        client,
        scenarioId,
        format: familyExport.format,
        reasonCode: familyExport.reasonCode,
        error: familyExport.error,
      });
      continue;
    }

    let format;
    try {
      format = builders.rawConfigFormat(client, scenario);
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        reasonCode: "raw_format_mapping_failed",
        error: error.message,
      });
      continue;
    }

    let rawText;
    try {
      rawText = execFileSync(
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
    } catch (error) {
      const failure = classifyClientExportFailure(opts, format, error);
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: failure.reasonCode,
        error: failure.error,
      });
      continue;
    }

    let raw;
    try {
      raw = JSON.parse(rawText);
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: "raw_config_invalid_json",
        error: error.message,
      });
      continue;
    }

    try {
      validateRawForScenario(raw, client);
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: "raw_config_shape_invalid",
        error: error.message,
      });
      continue;
    }

    const rawPath = path.join(opts.outputDir, "raw", `${client}-${format}.json`);
    try {
      writePrivateFile(rawPath, JSON.stringify(raw, null, 2) + "\n");
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: "output_write_failed",
        error: error.message,
      });
      continue;
    }

    let runtime;
    try {
      runtime = runtimeContent(raw, client, builders, `${opts.clientName}-${client}`);
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: "runtime_artifact_generation_failed",
        error: error.message,
      });
      continue;
    }

    const filePath = path.join(opts.outputDir, `${client}${runtime.extension}`);
    try {
      writePrivateFile(filePath, runtime.content.trimEnd() + "\n");
    } catch (error) {
      manifest.failed.push({
        client,
        scenarioId,
        format,
        reasonCode: "output_write_failed",
        error: error.message,
      });
      continue;
    }

    manifest.generated.push({
      client,
      scenarioId,
      format,
      path: filePath,
      rawPath,
    });
  }

  if (!opts.noManifest) {
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
      `## Export preflight`,
      ...Object.entries(manifest.exportPreflight).map(
        ([format, info]) =>
          `- ${format} [${info.supported ? "supported" : info.reasonCode || "unsupported"}]: clients=${info.clients.join(", ")}${info.error ? ` — ${info.error}` : ""}`
      ),
      ``,
      `## Generated`,
      ...manifest.generated.map((item) => `- ${item.client}: ${path.basename(item.path)}`),
      ``,
      `## Skipped`,
      ...manifest.skipped.map((item) => `- ${item.client} [${item.reasonCode}]: ${item.reason}`),
      ``,
      `## Failed`,
      ...manifest.failed.map((item) => `- ${item.client} [${item.reasonCode || "unknown"}]: ${item.error}`),
      ``,
    ];
    writePrivateFile(path.join(opts.outputDir, "manifest.md"), lines.join("\n"));
  }

  if (manifest.failed.length > 0) {
    writeFailureSummary(manifest, "client_generation_failed");
    process.exit(1);
  }
  if (manifest.generated.length === 0) {
    writeFailureSummary(manifest, "no_compatible_client_configs_generated");
    process.exit(1);
  }

  console.log(JSON.stringify({
    scenarioId,
    outputDir: opts.outputDir,
    exportPreflight: manifest.exportPreflight,
    generated: manifest.generated.map((item) => item.client),
    generatedCount: manifest.generated.length,
    skipped: manifest.skipped.length,
    skippedDetails: manifest.skipped,
    manifestWritten: !opts.noManifest,
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
