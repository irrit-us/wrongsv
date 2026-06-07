//! Xray lifecycle integration tests.
//!
//! These tests verify the full proxy lifecycle using a real xray client:
//! deploy → REALITY/VLESS, Shadowsocks 2022, or Trojan → relay → response → cleanup.
//!
//! Requires xray binary. Set `XRAY_BIN` env var or place at
//! `test-deploy/xray`. Tests are skipped if xray is not available.

mod common;

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use common::{
    TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_SHORT_ID, TEST_SNI, TEST_SS_2022_AES_128_PASSWORD,
    TEST_SS_2022_AES_256_PASSWORD, TEST_SS_AEAD_PASSWORD, TEST_TROJAN_PASSWORD, TEST_UUID,
    init_logging, lifecycle_test_lock, local_http_url, pick_ports, socks5_get, socks5_tcp_echo,
    socks5_udp_echo, spawn_http_echo_target, spawn_multi_user_server, spawn_server,
    spawn_shadowsocks_server, spawn_tcp_echo_target, spawn_trojan_server_with_pinned_cert,
    spawn_udp_echo_target, spawn_ws_server,
};

fn xray_bin() -> Option<String> {
    if let Ok(path) = std::env::var("XRAY_BIN")
        && std::path::Path::new(&path).exists()
    {
        return Some(path);
    }
    for candidate in &["xray", "./test-deploy/xray", "../test-deploy/xray"] {
        if Command::new(candidate).arg("version").output().is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

struct XrayGuard {
    child: Child,
    #[allow(dead_code)]
    socks_port: u16,
}

impl Drop for XrayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write an xray JSON config for a VLESS+REALITY client.
#[allow(clippy::too_many_arguments)]
fn write_xray_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    flow: &str,
    server_name: &str,
    public_key: &str,
    short_id: &str,
) {
    let flow_field = if flow.is_empty() {
        String::new()
    } else {
        format!(r#","flow": "{}""#, flow)
    };
    let json = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "port": {socks_port},
      "protocol": "socks",
      "listen": "127.0.0.1",
      "tag": "socks-in"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "vless",
      "tag": "proxy",
      "settings": {{
        "vnext": [
          {{
            "address": "127.0.0.1",
            "port": {server_port},
            "users": [
              {{
                "id": "{uuid}"{flow_field},
                "encryption": "none"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "serverName": "{server_name}",
          "publicKey": "{public_key}",
          "shortId": "{short_id}",
          "fingerprint": "chrome"
        }}
      }}
    }}
  ],
  "routing": {{
    "rules": [
      {{
        "type": "field",
        "inboundTag": ["socks-in"],
        "outboundTag": "proxy"
      }}
    ]
  }}
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn write_xray_shadowsocks_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    method: &str,
    password: &str,
) {
    let json = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "port": {socks_port},
      "protocol": "socks",
      "listen": "127.0.0.1",
      "tag": "socks-in",
      "settings": {{
        "udp": true
      }}
    }}
  ],
  "outbounds": [
    {{
      "protocol": "shadowsocks",
      "tag": "proxy",
      "settings": {{
        "address": "127.0.0.1",
        "port": {server_port},
        "method": "{method}",
        "password": "{password}"
      }}
    }}
  ],
  "routing": {{
    "rules": [
      {{
        "type": "field",
        "inboundTag": ["socks-in"],
        "outboundTag": "proxy"
      }}
    ]
  }}
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn write_xray_trojan_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    password: &str,
    cert_hash: &str,
) {
    let json = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "port": {socks_port},
      "protocol": "socks",
      "listen": "127.0.0.1",
      "tag": "socks-in",
      "settings": {{
        "udp": true
      }}
    }}
  ],
  "outbounds": [
    {{
      "protocol": "trojan",
      "tag": "proxy",
      "settings": {{
        "address": "127.0.0.1",
        "port": {server_port},
        "password": "{password}"
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{
          "serverName": "www.cloudfront.net",
          "pinnedPeerCertSha256": "{cert_hash}"
        }}
      }}
    }}
  ],
  "routing": {{
    "rules": [
      {{
        "type": "field",
        "inboundTag": ["socks-in"],
        "outboundTag": "proxy"
      }}
    ]
  }}
}}"#
    );
    std::fs::write(path, json).unwrap();
}

/// Write an xray JSON config for VLESS+WebSocket client.
fn write_xray_ws_config(path: &str, socks_port: u16, server_port: u16, uuid: &str, ws_path: &str) {
    let json = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "port": {socks_port},
      "protocol": "socks",
      "listen": "127.0.0.1",
      "tag": "socks-in"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "vless",
      "tag": "proxy",
      "settings": {{
        "vnext": [
          {{
            "address": "127.0.0.1",
            "port": {server_port},
            "users": [
              {{
                "id": "{uuid}",
                "encryption": "none"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "ws",
        "security": "none",
        "wsSettings": {{
          "path": "{ws_path}"
        }}
      }}
    }}
  ],
  "routing": {{
    "rules": [
      {{
        "type": "field",
        "inboundTag": ["socks-in"],
        "outboundTag": "proxy"
      }}
    ]
  }}
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn start_xray(config_path: &str, socks_port: u16) -> XrayGuard {
    let bin = xray_bin().expect("xray not found");
    let child = Command::new(&bin)
        .args(["run", "-c", config_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start xray");

    // Xray takes a moment to load config and bind the inbound.
    let addr = format!("127.0.0.1:{socks_port}");
    for _ in 0..30 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            return XrayGuard { child, socks_port };
        }
        thread::sleep(Duration::from_millis(200));
    }
    XrayGuard { child, socks_port }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_xray_lifecycle_vision_http() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found (set XRAY_BIN or build with 'go build ./main/')");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_server(
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_PRIVATE_KEY,
        &[TEST_SHORT_ID],
        None,
    );

    let cfg = format!("/tmp/xray-test-vision-{server_port}.json");
    write_xray_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _x = start_xray(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");

    let body2 = socks5_get(socks_port, &local_http_url(http_addr, "/get?test=lc")).unwrap();
    assert!(
        body2.contains("test") && body2.contains("lc"),
        "unexpected: {body2}"
    );
}

#[test]
fn test_xray_lifecycle_raw_http() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_server(
        server_port,
        TEST_UUID,
        "",
        TEST_PRIVATE_KEY,
        &[TEST_SHORT_ID],
        None,
    );

    let cfg = format!("/tmp/xray-test-raw-{server_port}.json");
    write_xray_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _x = start_xray(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected: {body}");
}

#[test]
fn test_xray_lifecycle_multi_request() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_server(
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_PRIVATE_KEY,
        &[TEST_SHORT_ID],
        None,
    );

    let cfg = format!("/tmp/xray-test-multi-{server_port}.json");
    write_xray_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _x = start_xray(&cfg, socks_port);

    for i in 0..5 {
        let body = socks5_get(
            socks_port,
            &local_http_url(http_addr, &format!("/get?n={i}")),
        )
        .unwrap();
        assert!(
            body.contains(&format!("n={i}")),
            "request {i} failed: {body}"
        );
    }
}

#[test]
fn test_xray_lifecycle_multi_user() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(3);
    let server_port = ports[0];
    let socks1 = ports[1];
    let socks2 = ports[2];
    let http_addr = spawn_http_echo_target();
    let user1 = (
        "11111111-1111-1111-1111-111111111111".to_string(),
        "xtls-rprx-vision".to_string(),
    );
    let user2 = (
        "22222222-2222-2222-2222-222222222222".to_string(),
        "".to_string(),
    );

    let _server = spawn_multi_user_server(
        server_port,
        &[user1.clone(), user2.clone()],
        TEST_PRIVATE_KEY,
        &[TEST_SHORT_ID],
    );

    let cfg1 = format!("/tmp/xray-mu1-{server_port}.json");
    write_xray_config(
        &cfg1,
        socks1,
        server_port,
        &user1.0,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _x1 = start_xray(&cfg1, socks1);

    let cfg2 = format!("/tmp/xray-mu2-{server_port}.json");
    write_xray_config(
        &cfg2,
        socks2,
        server_port,
        &user2.0,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _x2 = start_xray(&cfg2, socks2);

    let body1 = socks5_get(socks1, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body1.contains("origin"), "user1 Vision failed: {body1}");

    let body2 = socks5_get(socks2, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body2.contains("origin"), "user2 raw failed: {body2}");
}

#[test]
fn test_xray_lifecycle_restart() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    {
        let _server = spawn_server(
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_PRIVATE_KEY,
            &[TEST_SHORT_ID],
            None,
        );
        let cfg = format!("/tmp/xray-restart-{server_port}.json");
        write_xray_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _x = start_xray(&cfg, socks_port);
        let body = socks5_get(socks_port, &local_http_url(http_addr, "/get?run=1")).unwrap();
        assert!(body.contains("run=1"), "first run failed: {body}");
    }

    thread::sleep(Duration::from_millis(500));

    {
        let _server = spawn_server(
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_PRIVATE_KEY,
            &[TEST_SHORT_ID],
            None,
        );
        let cfg = format!("/tmp/xray-restart-{server_port}.json");
        write_xray_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _x = start_xray(&cfg, socks_port);
        let body = socks5_get(socks_port, &local_http_url(http_addr, "/get?run=2")).unwrap();
        assert!(body.contains("run=2"), "restart failed: {body}");
    }
}

#[test]
fn test_xray_lifecycle_wrong_credential_rejected() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_server(
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_PRIVATE_KEY,
        &["ababa486"],
        Some("127.0.0.1:1"),
    );

    let cfg = format!("/tmp/xray-wrong-{server_port}.json");
    write_xray_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        "deadbeef",
    );

    let _x = start_xray(&cfg, socks_port);

    let result = socks5_get(socks_port, &local_http_url(http_addr, "/ip"));
    assert!(
        result.is_err(),
        "wrong short_id should be rejected, got: {result:?}"
    );
}

#[test]
fn test_xray_shadowsocks_aead_tcp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_tcp_echo_target();
    let _server =
        spawn_shadowsocks_server(server_port, "chacha20-ietf-poly1305", TEST_SS_AEAD_PASSWORD);

    let cfg = format!("/tmp/xray-ss-aead-tcp-{server_port}.json");
    write_xray_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"xray ss aead tcp").unwrap();
    assert_eq!(response, b"xray ss aead tcp");
}

#[test]
fn test_xray_shadowsocks_aead_udp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();
    let _server =
        spawn_shadowsocks_server(server_port, "chacha20-ietf-poly1305", TEST_SS_AEAD_PASSWORD);

    let cfg = format!("/tmp/xray-ss-aead-udp-{server_port}.json");
    write_xray_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"xray ss aead udp").unwrap();
    assert_eq!(response, b"xray ss aead udp");
}

#[test]
fn test_xray_shadowsocks_2022_tcp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_tcp_echo_target();
    let _server = spawn_shadowsocks_server(
        server_port,
        "2022-blake3-aes-128-gcm",
        TEST_SS_2022_AES_128_PASSWORD,
    );

    let cfg = format!("/tmp/xray-ss2022-tcp-{server_port}.json");
    write_xray_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-128-gcm",
        TEST_SS_2022_AES_128_PASSWORD,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"xray ss2022 tcp").unwrap();
    assert_eq!(response, b"xray ss2022 tcp");
}

#[test]
fn test_xray_shadowsocks_2022_udp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();
    let _server = spawn_shadowsocks_server(
        server_port,
        "2022-blake3-aes-256-gcm",
        TEST_SS_2022_AES_256_PASSWORD,
    );

    let cfg = format!("/tmp/xray-ss2022-udp-{server_port}.json");
    write_xray_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-256-gcm",
        TEST_SS_2022_AES_256_PASSWORD,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"xray ss2022 udp").unwrap();
    assert_eq!(response, b"xray ss2022 udp");
}

#[test]
fn test_xray_trojan_tcp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_tcp_echo_target();
    let (_server, cert_hash) =
        spawn_trojan_server_with_pinned_cert(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/xray-trojan-tcp-{server_port}.json");
    write_xray_trojan_config(
        &cfg,
        socks_port,
        server_port,
        TEST_TROJAN_PASSWORD,
        &cert_hash,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"xray trojan tcp").unwrap();
    assert_eq!(response, b"xray trojan tcp");
}

#[test]
fn test_xray_trojan_udp_echo() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();
    let (_server, cert_hash) =
        spawn_trojan_server_with_pinned_cert(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/xray-trojan-udp-{server_port}.json");
    write_xray_trojan_config(
        &cfg,
        socks_port,
        server_port,
        TEST_TROJAN_PASSWORD,
        &cert_hash,
    );
    let _x = start_xray(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"xray trojan udp").unwrap();
    assert_eq!(response, b"xray trojan udp");
}

// ── WebSocket transport tests ──────────────────────────────────────────────

#[test]
fn test_xray_lifecycle_ws_tcp_http() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_ws_server(server_port, TEST_UUID, "", "/ws");

    let cfg = format!("/tmp/xray-ws-{server_port}.json");
    write_xray_ws_config(&cfg, socks_port, server_port, TEST_UUID, "/ws");
    let _x = start_xray(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");
}
