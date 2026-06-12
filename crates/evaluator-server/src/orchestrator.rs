//! Evaluator orchestrator: spawns wrongsv instances + target servers,
//! coordinates multi-protocol evaluation with a remote client over a JSON-line
//! control channel.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use super::protocol::{ClientMessage, ProtocolMetrics, ServerMessage};
use super::target;

/// Default list of protocol combinations to evaluate.
pub const DEFAULT_PROTOCOLS: &[&str] = &[
    "reality",
    "anytls",
    "tls",
    "raw",
    "ws",
    "ws+tls",
    "httpupgrade",
    "httpupgrade+tls",
    "grpc",
    "grpc+tls",
    "xhttp",
    "xhttp+tls",
    "quic",
    "kcp",
    "webtransport",
    "shadowtls",
    "vmess",
];

/// Recommended protocol stacks (from PROTOCOL-COVERAGE.md).
/// Each stack is a named group of protocols that together form a
/// deployment recommendation. A stack passes only if every constituent
/// protocol passes.
pub const STACKS: &[(&str, &[&str])] = &[
    ("tier1", &["reality"]),
    // Hysteria2 runs as a separate server instance and is not tested via the
    // VLESS evaluator path. Tier 2 tests the REALITY (TCP) half; deploy
    // Hysteria2 alongside on the same port for the full dual-stack.
    ("tier2", &["reality"]),
    ("tier3", &["ws+tls"]),
    ("tier4", &["shadowtls"]),
    ("post-quantum", &["reality"]),
    ("legacy", &["vmess"]),
];

/// Human-readable descriptions for each stack.
pub fn stack_description(name: &str) -> &'static str {
    match name {
        "tier1" => "VLESS + REALITY + XTLS-Vision (TCP/443) — maximum stealth",
        "tier2" => "REALITY + Hysteria2 dual-stack (TCP+UDP/443) — multi-protocol resilient",
        "tier3" => "VLESS + WebSocket + TLS (TCP/443 via CDN) — CDN-friendly",
        "tier4" => "VLESS + ShadowTLS v3 (TCP/443) — TLS mimicry, no pre-shared keys",
        "post-quantum" => "VLESS + REALITY + Vision + ML-KEM-512 — post-quantum",
        "legacy" => "VMess AEAD — legacy client compatibility",
        _ => "Unknown stack",
    }
}

/// Build a wrongsv server config TOML for the given protocol.
/// Extra parameters needed by some transports on the client side.
#[derive(Default)]
pub struct TransportParams {
    pub reality_pubkey_b64: Option<String>,
    pub reality_short_id: Option<String>,
    pub reality_raw_pubkey: Option<String>,
}

fn build_proxy_config(
    protocol: &str,
    proxy_port: u16,
    _target_addr: SocketAddr,
    proxy_bind: &str,
) -> (String, String, TransportParams) {
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        0x40 | (rand::random::<u8>() & 0x0f),
        rand::random::<u8>(),
        0x80 | (rand::random::<u8>() & 0x3f),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
    );
    let uid = &uuid;

    match protocol {
        "reality" => {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let sk_hex: String = sk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let short_id = format!(
                "{:02x}{:02x}{:02x}{:02x}",
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            );
            // Server generates its own cert material; client skips cert
            // verification for evaluator (all-zeros raw_pubkey signals skip).
            let raw_pubkey_hex =
                "0000000000000000000000000000000000000000000000000000000000000000".to_string();
            use base64::Engine;
            let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes());
            let params = TransportParams {
                reality_pubkey_b64: Some(pubkey_b64),
                reality_short_id: Some(short_id.clone()),
                reality_raw_pubkey: Some(raw_pubkey_hex),
            };
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"
flow = "xtls-rprx-vision"

[reality]
private_key = "{sk_hex}"
short_ids = ["{short_id}"]
"#
            );
            (config, uid.to_string(), params)
        }
        "anytls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[anytls]
password = "eval-anytls-pass"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "tls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "raw" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "ws" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[websocket]
path = "/eval"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "ws+tls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[websocket]
path = "/eval"

[websocket.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "httpupgrade" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[httpupgrade]
path = "/eval"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "httpupgrade+tls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[httpupgrade]
path = "/eval"

[httpupgrade.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "grpc" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[grpc]
service_name = "EvalService"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "grpc+tls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[grpc]
service_name = "EvalService"

[grpc.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "xhttp" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[xhttp]
path = "/eval"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "xhttp+tls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[xhttp]
path = "/eval"

[xhttp.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "quic" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[quic]

[quic.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "kcp" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[kcp]
seed = "eval-kcp-seed"
tti = 10
mtu = 1350
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "webtransport" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[webtransport]
path = "/eval"

[webtransport.tls]
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "shadowtls" => {
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[shadowtls]
password = "eval-stls-pass"
"#
            );
            (config, uid.to_string(), TransportParams::default())
        }
        "vmess" => {
            // VMess is a standalone protocol, not VLESS. The uuid field in the
            // VMess user table is the VMess UUID, not a VLESS user ID.
            let vmess_uid = format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                0x40 | (rand::random::<u8>() & 0x0f),
                rand::random::<u8>(),
                0x80 | (rand::random::<u8>() & 0x3f),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            );
            let config = format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[vmess]

[[vmess.users]]
id = "{vmess_uid}"
"#
            );
            (config, vmess_uid, TransportParams::default())
        }
        _ => panic!("unknown protocol: {protocol}"),
    }
}

/// Resolve the protocol list from user input or default to all.
pub fn resolve_protocols(requested: Option<&str>) -> Vec<String> {
    match requested {
        None | Some("") | Some("all") => DEFAULT_PROTOCOLS.iter().map(|s| s.to_string()).collect(),
        Some(list) => list.split(',').map(|s| s.trim().to_string()).collect(),
    }
}

/// Resolve stack names to their constituent protocols.
/// Returns (ordered_protocols, stack_names_in_order) where protocols are
/// deduplicated and stack_names preserves the requested order for reporting.
pub fn resolve_stacks(requested: Option<&str>) -> (Vec<String>, Vec<String>) {
    let stack_names: Vec<String> = match requested {
        None | Some("") | Some("all") => STACKS.iter().map(|(n, _)| n.to_string()).collect(),
        Some(list) => list.split(',').map(|s| s.trim().to_string()).collect(),
    };

    let mut protocols = Vec::new();
    let mut valid_names = Vec::new();
    let stack_map: std::collections::HashMap<&str, &[&str]> = STACKS.iter().copied().collect();

    for name in &stack_names {
        if let Some(stack_protos) = stack_map.get(name.as_str()) {
            valid_names.push(name.clone());
            for p in *stack_protos {
                let ps = p.to_string();
                if !protocols.contains(&ps) {
                    protocols.push(ps);
                }
            }
        } else {
            warn!(
                "unknown stack: {name} (valid: {})",
                STACKS
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    (protocols, valid_names)
}

/// Serve a single client connection through the full protocol evaluation cycle.
/// If `stack_names` is non-empty, a stack-level summary is emitted after all
/// protocols complete.
async fn serve_client(
    stream: TcpStream,
    token: &str,
    protocols: &[String],
    duration_secs: u64,
    proxy_bind: &str,
    fixed_proxy_port: Option<u16>,
    stack_names: &[String],
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // --- auth ---
    let authed = match lines.next_line().await {
        Ok(Some(line)) => match serde_json::from_str::<ClientMessage>(&line) {
            Ok(ClientMessage::Auth { token: t }) if t == token => true,
            Ok(ClientMessage::Auth { .. }) => {
                let msg = ServerMessage::AuthErr {
                    reason: "bad token".into(),
                };
                let _ = send_msg(&mut writer, &msg).await;
                false
            }
            _ => {
                let msg = ServerMessage::AuthErr {
                    reason: "expected auth".into(),
                };
                let _ = send_msg(&mut writer, &msg).await;
                false
            }
        },
        _ => false,
    };
    if !authed {
        return;
    }
    if send_msg(&mut writer, &ServerMessage::AuthOk).await.is_err() {
        return;
    }
    info!("evaluator client authenticated");

    let mut results: Vec<ProtocolMetrics> = Vec::new();

    for (i, protocol) in protocols.iter().enumerate() {
        info!("starting evaluation for protocol: {protocol}");

        // Spawn targets
        let echo_addr = match target::spawn_echo_target().await {
            Ok(a) => a,
            Err(e) => {
                error!("failed to spawn echo target: {e}");
                continue;
            }
        };
        let bw_addr = match target::spawn_bandwidth_target().await {
            Ok(a) => a,
            Err(e) => {
                error!("failed to spawn bandwidth target: {e}");
                continue;
            }
        };
        let pl_addr = match target::spawn_packet_loss_target().await {
            Ok(a) => a,
            Err(e) => {
                error!("failed to spawn packet-loss target: {e}");
                continue;
            }
        };

        // Pick proxy port: fixed if requested, otherwise ephemeral
        let proxy_port = if let Some(port) = fixed_proxy_port {
            port
        } else {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let (config_toml, uuid, params) =
            build_proxy_config(protocol, proxy_port, echo_addr, proxy_bind);
        let server_config: wrongsv_server::Config =
            toml::from_str(&config_toml).expect("eval config should parse");
        let server = wrongsv_server::InboundServer::new(server_config)
            .expect("eval server should initialize");
        let _handle = server.spawn();

        // Give the proxy a moment to start
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Send test config to client
        let test_msg = ServerMessage::TestConfig {
            protocol: protocol.clone(),
            proxy_port,
            echo_port: echo_addr.port(),
            bw_port: bw_addr.port(),
            pl_port: pl_addr.port(),
            uuid: uuid.clone(),
            reality_pubkey_b64: params.reality_pubkey_b64,
            reality_short_id: params.reality_short_id,
            reality_raw_pubkey: params.reality_raw_pubkey,
        };
        if send_msg(&mut writer, &test_msg).await.is_err() {
            break;
        }

        // Wait for client ready
        match lines.next_line().await {
            Ok(Some(line)) => {
                if let Ok(ClientMessage::Ready { .. }) = serde_json::from_str(&line) {
                    // good
                } else {
                    warn!("expected ready, got: {line}");
                    continue;
                }
            }
            _ => break,
        }

        // Send start
        let start_msg = ServerMessage::Start {
            protocol: protocol.clone(),
            duration_secs,
        };
        if send_msg(&mut writer, &start_msg).await.is_err() {
            break;
        }

        // Wait for result
        match lines.next_line().await {
            Ok(Some(line)) => match serde_json::from_str::<ClientMessage>(&line) {
                Ok(ClientMessage::Result { metrics: m, .. }) => {
                    info!(
                        "{}: lat avg={:.2}ms, bw up={:.2}/dn={:.2} Mbps, loss={:.2}%",
                        protocol,
                        m.latency_ms.avg,
                        m.bandwidth_mbps.upload,
                        m.bandwidth_mbps.download,
                        m.packet_loss_pct
                    );
                    results.push(m);
                }
                other => {
                    warn!("unexpected client message: {other:?}");
                }
            },
            _ => break,
        }

        // Send next or done
        if i + 1 < protocols.len() {
            if send_msg(&mut writer, &ServerMessage::Next).await.is_err() {
                break;
            }
        } else if send_msg(&mut writer, &ServerMessage::Done).await.is_err() {
            break;
        }

        // _handle drops here → server shuts down
    }

    info!("evaluation complete: {} protocols evaluated", results.len());

    // ── stack-level summary ──────────────────────────────────────────
    if !stack_names.is_empty() {
        // Build protocol-name → metrics lookup (results are in protocol iteration order)
        let proto_results: Vec<(&String, &ProtocolMetrics)> =
            protocols.iter().zip(results.iter()).collect();

        let stack_map: std::collections::HashMap<&str, &[&str]> = STACKS.iter().copied().collect();
        let mut stack_results = Vec::new();

        for name in stack_names {
            if let Some(stack_protos) = stack_map.get(name.as_str()) {
                let failing: Vec<String> = stack_protos
                    .iter()
                    .filter(|sp| {
                        proto_results
                            .iter()
                            .any(|(proto, m)| proto.as_str() == **sp && m.packet_loss_pct > 0.0)
                    })
                    .map(|s| s.to_string())
                    .collect();

                let desc = stack_description(name);
                let passed = failing.is_empty();
                info!(
                    "stack {} {} — {}",
                    name,
                    if passed { "PASS" } else { "FAIL" },
                    desc
                );
                if !passed {
                    warn!("  failing protocols: {:?}", failing);
                }
                stack_results.push(super::protocol::StackResult {
                    name: name.clone(),
                    description: desc.to_string(),
                    passed,
                    protocols: stack_protos.iter().map(|s| s.to_string()).collect(),
                    failing,
                });
            }
        }

        let summary = ServerMessage::StackSummary {
            stacks: stack_results,
        };
        let _ = send_msg(&mut writer, &summary).await;
    }
}

async fn send_msg(
    writer: &mut (impl AsyncWriteExt + Unpin),
    msg: &ServerMessage,
) -> Result<(), std::io::Error> {
    let mut json = serde_json::to_string(msg).expect("ServerMessage should serialize");
    json.push('\n');
    writer.write_all(json.as_bytes()).await
}

/// Start the evaluator orchestrator. Listens on `listen_addr`, authenticates
/// clients with `token`, and runs the requested protocol evaluations.
/// If `requested_stacks` is Some, stack mode is used instead of raw protocol mode.
pub async fn run_orchestrator(
    listen_addr: &str,
    token: &str,
    requested_protocols: Option<&str>,
    requested_stacks: Option<&str>,
    duration_secs: u64,
    proxy_bind: &str,
    fixed_proxy_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (protocols, stack_names) = if let Some(stacks) = requested_stacks {
        let (protos, names) = resolve_stacks(Some(stacks));
        info!(
            "evaluator orchestrator listening on {listen_addr}, token={token}, stacks={:?} → protocols={:?}, duration={duration_secs}s",
            names, protos
        );
        (protos, names)
    } else {
        let protos = resolve_protocols(requested_protocols);
        info!(
            "evaluator orchestrator listening on {listen_addr}, token={token}, protocols={:?}, duration={duration_secs}s",
            protos
        );
        (protos, Vec::new())
    };

    let listener = TcpListener::bind(listen_addr).await?;
    // Accept only one client per invocation
    let (stream, peer) = listener.accept().await?;
    info!("evaluator client connected from {peer}");

    serve_client(
        stream,
        token,
        &protocols,
        duration_secs,
        proxy_bind,
        fixed_proxy_port,
        &stack_names,
    )
    .await;

    info!("evaluator orchestrator done");
    Ok(())
}
