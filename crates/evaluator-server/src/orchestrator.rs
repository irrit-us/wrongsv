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
];

/// Build a wrongsv server config TOML for the given protocol.
fn build_proxy_config(
    protocol: &str,
    proxy_port: u16,
    _target_addr: SocketAddr,
    proxy_bind: &str,
) -> (String, String) {
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

    let config_toml = match protocol {
        "reality" => {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let sk_hex: String = sk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let short_id = format!(
                "{:02x}{:02x}{:02x}{:02x}",
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            );
            format!(
                r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"
flow = "xtls-rprx-vision"

[reality]
private_key = "{sk_hex}"
short_ids = ["{short_id}"]
"#
            )
        }
        "anytls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[anytls]
password = "eval-anytls-pass"
"#
        ),
        "tls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[tls]
"#
        ),
        "raw" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"
"#
        ),
        "ws" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[websocket]
path = "/eval"
"#
        ),
        "ws+tls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[websocket]
path = "/eval"

[websocket.tls]
"#
        ),
        "httpupgrade" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[httpupgrade]
path = "/eval"
"#
        ),
        "httpupgrade+tls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[httpupgrade]
path = "/eval"

[httpupgrade.tls]
"#
        ),
        "grpc" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[grpc]
service_name = "EvalService"
"#
        ),
        "grpc+tls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[grpc]
service_name = "EvalService"

[grpc.tls]
"#
        ),
        "xhttp" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[xhttp]
path = "/eval"
"#
        ),
        "xhttp+tls" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[xhttp]
path = "/eval"

[xhttp.tls]
"#
        ),
        "quic" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[quic]

[quic.tls]
"#
        ),
        "kcp" => format!(
            r#"
listen = "{proxy_bind}:{proxy_port}"

[[users]]
id = "{uid}"

[kcp]
seed = "eval-kcp-seed"
tti = 20
mtu = 1350
"#
        ),
        _ => panic!("unknown protocol: {protocol}"),
    };

    (config_toml, uid.to_string())
}

/// Resolve the protocol list from user input or default to all.
pub fn resolve_protocols(requested: Option<&str>) -> Vec<String> {
    match requested {
        None | Some("") | Some("all") => DEFAULT_PROTOCOLS.iter().map(|s| s.to_string()).collect(),
        Some(list) => list.split(',').map(|s| s.trim().to_string()).collect(),
    }
}

/// Serve a single client connection through the full protocol evaluation cycle.
async fn serve_client(
    stream: TcpStream,
    token: &str,
    protocols: &[String],
    duration_secs: u64,
    proxy_bind: &str,
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

        // Pick an ephemeral proxy port
        let proxy_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let (config_toml, uuid) = build_proxy_config(protocol, proxy_port, echo_addr, proxy_bind);
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
pub async fn run_orchestrator(
    listen_addr: &str,
    token: &str,
    requested_protocols: Option<&str>,
    duration_secs: u64,
    proxy_bind: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let protocols = resolve_protocols(requested_protocols);
    info!(
        "evaluator orchestrator listening on {listen_addr}, token={token}, protocols={:?}, duration={duration_secs}s",
        protocols
    );

    let listener = TcpListener::bind(listen_addr).await?;
    // Accept only one client per invocation
    let (stream, peer) = listener.accept().await?;
    info!("evaluator client connected from {peer}");

    serve_client(stream, token, &protocols, duration_secs, proxy_bind).await;

    info!("evaluator orchestrator done");
    Ok(())
}
