//! Sing-box lifecycle integration tests.
//!
//! These tests verify the full proxy lifecycle using a real sing-box client:
//! deploy → REALITY/VLESS, Shadowsocks 2022, or Trojan → relay → response → cleanup.
//!
//! Requires sing-box binary. Set `SINGBOX_BIN` env var or place it on PATH.
//! Tests are skipped if sing-box is not available.

mod common;

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use common::{
    TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_SHORT_ID, TEST_SNI, TEST_SS_2022_AES_128_PASSWORD,
    TEST_SS_2022_AES_256_PASSWORD, TEST_SS_AEAD_PASSWORD, TEST_TROJAN_PASSWORD, TEST_UUID,
    init_logging, lifecycle_test_lock, local_http_url, pick_ports, socks5_get, socks5_tcp_echo,
    socks5_udp_echo, spawn_http_echo_target, spawn_multi_user_server, spawn_server,
    spawn_shadowsocks_server, spawn_tcp_echo_target, spawn_trojan_server, spawn_udp_echo_target,
    spawn_ws_server,
};

/// Path to sing-box binary.
fn singbox_bin() -> Option<String> {
    if let Ok(path) = std::env::var("SINGBOX_BIN")
        && std::path::Path::new(&path).exists()
    {
        return Some(path);
    }
    for candidate in &[
        "sing-box",
        "./test-deploy/sing-box",
        "../test-deploy/sing-box",
    ] {
        if Command::new(candidate).arg("version").output().is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

struct SingBoxGuard {
    child: Child,
    #[allow(dead_code)]
    socks_port: u16,
}

impl Drop for SingBoxGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write a sing-box config JSON for a VLESS+REALITY client.
#[allow(clippy::too_many_arguments)]
fn write_singbox_config(
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
        r#""flow": """#
    } else {
        r#""flow": "xtls-rprx-vision""#
    };
    let json = format!(
        r#"{{
  "log": {{ "level": "warn", "timestamp": true }},
  "inbounds": [
    {{
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": {socks_port}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": {server_port},
      "uuid": "{uuid}",
      {flow_field},
      "tls": {{
        "enabled": true,
        "server_name": "{server_name}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{public_key}",
          "short_id": "{short_id}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ]
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn write_singbox_shadowsocks_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    method: &str,
    password: &str,
) {
    let json = format!(
        r#"{{
  "log": {{ "level": "warn", "timestamp": true }},
  "inbounds": [
    {{
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": {socks_port}
    }}
  ],
  "outbounds": [
    {{
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": {server_port},
      "method": "{method}",
      "password": "{password}"
    }}
  ]
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn write_singbox_trojan_config(path: &str, socks_port: u16, server_port: u16, password: &str) {
    let json = format!(
        r#"{{
  "log": {{ "level": "warn", "timestamp": true }},
  "inbounds": [
    {{
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": {socks_port}
    }}
  ],
  "outbounds": [
    {{
      "type": "trojan",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": {server_port},
      "password": "{password}",
      "tls": {{
        "enabled": true,
        "server_name": "localhost",
        "insecure": true
      }}
    }}
  ]
}}"#
    );
    std::fs::write(path, json).unwrap();
}

/// Start sing-box with the given config.
/// Write a sing-box config JSON for VLESS+WebSocket client.
fn write_singbox_ws_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    ws_path: &str,
) {
    let json = format!(
        r#"{{
  "log": {{ "level": "warn", "timestamp": true }},
  "inbounds": [
    {{
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": {socks_port}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": {server_port},
      "uuid": "{uuid}",
      "flow": "",
      "transport": {{
        "type": "ws",
        "path": "{ws_path}"
      }}
    }},
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{
    "rules": [
      {{
        "inbound": ["mixed-in"],
        "outbound": "direct"
      }},
      {{
        "domain": ["*"],
        "outbound": "proxy"
      }}
    ]
  }}
}}"#
    );
    std::fs::write(path, json).unwrap();
}

fn start_singbox(config_path: &str, socks_port: u16) -> SingBoxGuard {
    let bin = singbox_bin().expect("sing-box not found");
    let child = Command::new(&bin)
        .args(["run", "-c", config_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start sing-box");
    thread::sleep(Duration::from_secs(1));
    SingBoxGuard { child, socks_port }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_singbox_lifecycle_vision_http() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found (set SINGBOX_BIN or place on PATH)");
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

    let cfg = format!("/tmp/singbox-test-vision-{server_port}.json");
    write_singbox_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _sbox = start_singbox(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");

    let body2 = socks5_get(socks_port, &local_http_url(http_addr, "/get?test=lc")).unwrap();
    assert!(
        body2.contains("test") && body2.contains("lc"),
        "unexpected: {body2}"
    );
}

#[test]
fn test_singbox_lifecycle_raw_http() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-test-raw-{server_port}.json");
    write_singbox_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _sbox = start_singbox(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected: {body}");
}

#[test]
fn test_singbox_lifecycle_multi_request() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-test-multi-{server_port}.json");
    write_singbox_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _sbox = start_singbox(&cfg, socks_port);

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
fn test_singbox_lifecycle_multi_user() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg1 = format!("/tmp/singbox-mu1-{server_port}.json");
    write_singbox_config(
        &cfg1,
        socks1,
        server_port,
        &user1.0,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _sbox1 = start_singbox(&cfg1, socks1);

    let cfg2 = format!("/tmp/singbox-mu2-{server_port}.json");
    write_singbox_config(
        &cfg2,
        socks2,
        server_port,
        &user2.0,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _sbox2 = start_singbox(&cfg2, socks2);

    let body1 = socks5_get(socks1, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body1.contains("origin"), "user1 Vision failed: {body1}");

    let body2 = socks5_get(socks2, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body2.contains("origin"), "user2 raw failed: {body2}");
}

#[test]
fn test_singbox_lifecycle_restart() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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
        let cfg = format!("/tmp/singbox-restart-{server_port}.json");
        write_singbox_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _sbox = start_singbox(&cfg, socks_port);
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
        let cfg = format!("/tmp/singbox-restart-{server_port}.json");
        write_singbox_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _sbox = start_singbox(&cfg, socks_port);
        let body = socks5_get(socks_port, &local_http_url(http_addr, "/get?run=2")).unwrap();
        assert!(body.contains("run=2"), "restart failed: {body}");
    }
}

#[test]
fn test_singbox_lifecycle_wrong_credential_rejected() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-wrong-{server_port}.json");
    write_singbox_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        "deadbeef",
    );

    let _sbox = start_singbox(&cfg, socks_port);

    let result = socks5_get(socks_port, &local_http_url(http_addr, "/ip"));
    assert!(
        result.is_err(),
        "wrong short_id should be rejected, got: {result:?}"
    );
}

#[test]
fn test_singbox_shadowsocks_aead_tcp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-ss-aead-tcp-{server_port}.json");
    write_singbox_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _sb = start_singbox(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"sing-box ss aead tcp").unwrap();
    assert_eq!(response, b"sing-box ss aead tcp");
}

#[test]
fn test_singbox_shadowsocks_aead_udp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-ss-aead-udp-{server_port}.json");
    write_singbox_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _sb = start_singbox(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"sing-box ss aead udp").unwrap();
    assert_eq!(response, b"sing-box ss aead udp");
}

#[test]
fn test_singbox_shadowsocks_2022_tcp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-ss2022-tcp-{server_port}.json");
    write_singbox_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-128-gcm",
        TEST_SS_2022_AES_128_PASSWORD,
    );
    let _sbox = start_singbox(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"sing-box ss2022 tcp").unwrap();
    assert_eq!(response, b"sing-box ss2022 tcp");
}

#[test]
fn test_singbox_shadowsocks_2022_udp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
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

    let cfg = format!("/tmp/singbox-ss2022-udp-{server_port}.json");
    write_singbox_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-256-gcm",
        TEST_SS_2022_AES_256_PASSWORD,
    );
    let _sbox = start_singbox(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"sing-box ss2022 udp").unwrap();
    assert_eq!(response, b"sing-box ss2022 udp");
}

#[test]
fn test_singbox_trojan_tcp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_tcp_echo_target();
    let _server = spawn_trojan_server(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/singbox-trojan-tcp-{server_port}.json");
    write_singbox_trojan_config(&cfg, socks_port, server_port, TEST_TROJAN_PASSWORD);
    let _sb = start_singbox(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"sing-box trojan tcp").unwrap();
    assert_eq!(response, b"sing-box trojan tcp");
}

#[test]
fn test_singbox_trojan_udp_echo() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();
    let _server = spawn_trojan_server(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/singbox-trojan-udp-{server_port}.json");
    write_singbox_trojan_config(&cfg, socks_port, server_port, TEST_TROJAN_PASSWORD);
    let _sb = start_singbox(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"sing-box trojan udp").unwrap();
    assert_eq!(response, b"sing-box trojan udp");
}

// ── WebSocket transport tests ──────────────────────────────────────────────

#[test]
fn test_singbox_lifecycle_ws_tcp_http() {
    if singbox_bin().is_none() {
        eprintln!("SKIP: sing-box not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_ws_server(server_port, TEST_UUID, "", "/ws");

    let cfg = format!("/tmp/singbox-ws-{server_port}.json");
    write_singbox_ws_config(&cfg, socks_port, server_port, TEST_UUID, "/ws");
    let _sb = start_singbox(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");
}
