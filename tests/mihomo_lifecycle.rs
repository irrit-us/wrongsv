//! Mihomo (ClashMeta) lifecycle integration tests.
//!
//! These tests verify the full proxy lifecycle using mihomo:
//! deploy → REALITY/VLESS, Shadowsocks 2022, or Trojan → relay → response → cleanup.
//!
//! Requires mihomo binary. Set `MIHOMO_BIN` env var or place at
//! `test-deploy/mihomo`. Tests are skipped if mihomo is not available.

mod common;

use std::net::TcpStream;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use common::{
    TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_SHORT_ID, TEST_SNI, TEST_SS_2022_AES_128_PASSWORD,
    TEST_SS_2022_AES_256_PASSWORD, TEST_SS_AEAD_PASSWORD, TEST_TROJAN_PASSWORD, TEST_UUID,
    init_logging, lifecycle_test_lock, local_http_url, pick_ports, socks5_get, socks5_tcp_echo,
    socks5_udp_echo, spawn_http_echo_target, spawn_httpupgrade_server, spawn_multi_user_server,
    spawn_server, spawn_shadowsocks_server, spawn_tcp_echo_target, spawn_trojan_server,
    spawn_udp_echo_target, spawn_ws_server,
};

fn mihomo_bin() -> Option<String> {
    if let Ok(path) = std::env::var("MIHOMO_BIN")
        && std::path::Path::new(&path).exists()
    {
        return Some(path);
    }
    for candidate in &["mihomo", "./test-deploy/mihomo", "../test-deploy/mihomo"] {
        if Command::new(candidate).arg("-v").output().is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

struct MihomoGuard {
    child: Child,
    #[allow(dead_code)]
    socks_port: u16,
}

impl Drop for MihomoGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write a mihomo YAML config for a VLESS+REALITY outbound.
#[allow(clippy::too_many_arguments)]
fn write_mihomo_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    flow: &str,
    server_name: &str,
    public_key: &str,
    short_id: &str,
) {
    let (flow_line, sni_indent) = if flow.is_empty() {
        (String::new(), "")
    } else {
        (format!("flow: \"{}\"\n", flow), "    ")
    };
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: vless
    server: "127.0.0.1"
    port: {server_port}
    uuid: "{uuid}"
    tls: true
    udp: true
    {flow_line}{sni_indent}servername: "{server_name}"
    reality-opts:
      public-key: "{public_key}"
      short-id: "{short_id}"
    client-fingerprint: "chrome"
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

fn write_mihomo_packetaddr_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    server_name: &str,
    public_key: &str,
    short_id: &str,
) {
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: vless
    server: "127.0.0.1"
    port: {server_port}
    uuid: "{uuid}"
    tls: true
    udp: true
    packet-encoding: packetaddr
    servername: "{server_name}"
    reality-opts:
      public-key: "{public_key}"
      short-id: "{short_id}"
    client-fingerprint: "chrome"
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

fn write_mihomo_shadowsocks_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    method: &str,
    password: &str,
) {
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: ss
    server: "127.0.0.1"
    port: {server_port}
    cipher: "{method}"
    password: "{password}"
    udp: true
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

fn write_mihomo_trojan_config(path: &str, socks_port: u16, server_port: u16, password: &str) {
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: trojan
    server: "127.0.0.1"
    port: {server_port}
    password: "{password}"
    udp: true
    sni: "localhost"
    skip-cert-verify: true
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

/// Write a mihomo YAML config for VLESS+WebSocket client.
fn write_mihomo_ws_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    ws_path: &str,
) {
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: vless
    server: "127.0.0.1"
    port: {server_port}
    uuid: "{uuid}"
    udp: true
    packet-encoding: ""
    network: "ws"
    ws-opts:
      path: "{ws_path}"
    smux:
      enabled: false
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

fn write_mihomo_httpupgrade_config(
    path: &str,
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    upgrade_path: &str,
) {
    let yaml = format!(
        r#"socks-port: {socks_port}
log-level: error
proxies:
  - name: "proxy"
    type: vless
    server: "127.0.0.1"
    port: {server_port}
    uuid: "{uuid}"
    udp: true
    packet-encoding: ""
    network: "ws"
    ws-opts:
      path: "{upgrade_path}"
      v2ray-http-upgrade: true
    smux:
      enabled: false
rules:
  - MATCH, proxy
"#
    );
    std::fs::write(path, yaml).unwrap();
}

fn start_mihomo(config_path: &str, socks_port: u16) -> MihomoGuard {
    let bin = mihomo_bin().expect("mihomo not found");
    // Each mihomo gets its own working directory so cache.db locks don't collide
    // when multiple instances run in parallel (multi-user test).
    let work_dir = format!("/tmp/mihomo-d-{socks_port}");
    let _ = std::fs::create_dir_all(&work_dir);
    let child = Command::new(&bin)
        .args(["-d", &work_dir, "-f", config_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start mihomo");

    // Mihomo takes longer to start than sing-box — poll until SOCKS port is ready.
    let addr = format!("127.0.0.1:{socks_port}");
    for _ in 0..30 {
        if TcpStream::connect(&addr).is_ok() {
            return MihomoGuard { child, socks_port };
        }
        thread::sleep(Duration::from_millis(200));
    }
    // Last attempt
    MihomoGuard { child, socks_port }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_mihomo_lifecycle_vision_http() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found (set MIHOMO_BIN or place at test-deploy/mihomo)");
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

    let cfg = format!("/tmp/mihomo-test-vision-{server_port}.yaml");
    write_mihomo_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _m = start_mihomo(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");

    let body2 = socks5_get(socks_port, &local_http_url(http_addr, "/get?test=lc")).unwrap();
    assert!(
        body2.contains("test") && body2.contains("lc"),
        "unexpected: {body2}"
    );
}

#[test]
fn test_mihomo_lifecycle_raw_http() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-test-raw-{server_port}.yaml");
    write_mihomo_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _m = start_mihomo(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected: {body}");
}

#[test]
fn test_mihomo_lifecycle_packetaddr_udp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();

    let _server = spawn_server(
        server_port,
        TEST_UUID,
        "",
        TEST_PRIVATE_KEY,
        &[TEST_SHORT_ID],
        None,
    );

    let cfg = format!("/tmp/mihomo-packetaddr-udp-{server_port}.yaml");
    write_mihomo_packetaddr_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"mihomo packetaddr udp").unwrap();
    assert_eq!(response, b"mihomo packetaddr udp");
}

#[test]
fn test_mihomo_lifecycle_multi_request() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-test-multi-{server_port}.yaml");
    write_mihomo_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );

    let _m = start_mihomo(&cfg, socks_port);

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
fn test_mihomo_lifecycle_multi_user() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg1 = format!("/tmp/mihomo-mu1-{server_port}.yaml");
    write_mihomo_config(
        &cfg1,
        socks1,
        server_port,
        &user1.0,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _m1 = start_mihomo(&cfg1, socks1);

    let cfg2 = format!("/tmp/mihomo-mu2-{server_port}.yaml");
    write_mihomo_config(
        &cfg2,
        socks2,
        server_port,
        &user2.0,
        "",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        TEST_SHORT_ID,
    );
    let _m2 = start_mihomo(&cfg2, socks2);

    let body1 = socks5_get(socks1, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body1.contains("origin"), "user1 Vision failed: {body1}");

    let body2 = socks5_get(socks2, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body2.contains("origin"), "user2 raw failed: {body2}");
}

#[test]
fn test_mihomo_lifecycle_restart() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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
        let cfg = format!("/tmp/mihomo-restart-{server_port}.yaml");
        write_mihomo_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _m = start_mihomo(&cfg, socks_port);
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
        let cfg = format!("/tmp/mihomo-restart-{server_port}.yaml");
        write_mihomo_config(
            &cfg,
            socks_port,
            server_port,
            TEST_UUID,
            "xtls-rprx-vision",
            TEST_SNI,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
        );
        let _m = start_mihomo(&cfg, socks_port);
        let body = socks5_get(socks_port, &local_http_url(http_addr, "/get?run=2")).unwrap();
        assert!(body.contains("run=2"), "restart failed: {body}");
    }
}

#[test]
fn test_mihomo_lifecycle_wrong_credential_rejected() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-wrong-{server_port}.yaml");
    write_mihomo_config(
        &cfg,
        socks_port,
        server_port,
        TEST_UUID,
        "xtls-rprx-vision",
        TEST_SNI,
        TEST_PUBLIC_KEY,
        "deadbeef",
    );

    let _m = start_mihomo(&cfg, socks_port);

    let result = socks5_get(socks_port, &local_http_url(http_addr, "/ip"));
    assert!(
        result.is_err(),
        "wrong short_id should be rejected, got: {result:?}"
    );
}

#[test]
fn test_mihomo_shadowsocks_aead_tcp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-ss-aead-tcp-{server_port}.yaml");
    write_mihomo_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"mihomo ss aead tcp").unwrap();
    assert_eq!(response, b"mihomo ss aead tcp");
}

#[test]
fn test_mihomo_shadowsocks_aead_udp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-ss-aead-udp-{server_port}.yaml");
    write_mihomo_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "chacha20-ietf-poly1305",
        TEST_SS_AEAD_PASSWORD,
    );
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"mihomo ss aead udp").unwrap();
    assert_eq!(response, b"mihomo ss aead udp");
}

#[test]
fn test_mihomo_shadowsocks_2022_tcp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-ss2022-tcp-{server_port}.yaml");
    write_mihomo_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-128-gcm",
        TEST_SS_2022_AES_128_PASSWORD,
    );
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"mihomo ss2022 tcp").unwrap();
    assert_eq!(response, b"mihomo ss2022 tcp");
}

#[test]
fn test_mihomo_shadowsocks_2022_udp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
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

    let cfg = format!("/tmp/mihomo-ss2022-udp-{server_port}.yaml");
    write_mihomo_shadowsocks_config(
        &cfg,
        socks_port,
        server_port,
        "2022-blake3-aes-256-gcm",
        TEST_SS_2022_AES_256_PASSWORD,
    );
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"mihomo ss2022 udp").unwrap();
    assert_eq!(response, b"mihomo ss2022 udp");
}

#[test]
fn test_mihomo_trojan_tcp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_tcp_echo_target();
    let _server = spawn_trojan_server(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/mihomo-trojan-tcp-{server_port}.yaml");
    write_mihomo_trojan_config(&cfg, socks_port, server_port, TEST_TROJAN_PASSWORD);
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_tcp_echo(socks_port, echo_addr, b"mihomo trojan tcp").unwrap();
    assert_eq!(response, b"mihomo trojan tcp");
}

#[test]
fn test_mihomo_trojan_udp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();
    let _server = spawn_trojan_server(server_port, TEST_TROJAN_PASSWORD);

    let cfg = format!("/tmp/mihomo-trojan-udp-{server_port}.yaml");
    write_mihomo_trojan_config(&cfg, socks_port, server_port, TEST_TROJAN_PASSWORD);
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"mihomo trojan udp").unwrap();
    assert_eq!(response, b"mihomo trojan udp");
}

// ── WebSocket transport tests ──────────────────────────────────────────────

#[test]
fn test_mihomo_lifecycle_ws_tcp_http() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_ws_server(server_port, TEST_UUID, "", "/ws");

    let cfg = format!("/tmp/mihomo-ws-{server_port}.yaml");
    write_mihomo_ws_config(&cfg, socks_port, server_port, TEST_UUID, "/ws");
    let _m = start_mihomo(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");
}

#[test]
fn test_mihomo_lifecycle_ws_udp_echo() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let echo_addr = spawn_udp_echo_target();

    let _server = spawn_ws_server(server_port, TEST_UUID, "", "/ws");

    let cfg = format!("/tmp/mihomo-ws-udp-{server_port}.yaml");
    write_mihomo_ws_config(&cfg, socks_port, server_port, TEST_UUID, "/ws");
    let _m = start_mihomo(&cfg, socks_port);

    let response = socks5_udp_echo(socks_port, echo_addr, b"mihomo ws udp").unwrap();
    assert_eq!(response, b"mihomo ws udp");
}

// ── HTTPUpgrade transport tests ────────────────────────────────────────────

#[test]
fn test_mihomo_lifecycle_httpupgrade_tcp_http() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    let _guard = lifecycle_test_lock();
    init_logging();

    let ports = pick_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];
    let http_addr = spawn_http_echo_target();

    let _server = spawn_httpupgrade_server(server_port, TEST_UUID, "", "/up");

    let cfg = format!("/tmp/mihomo-httpupgrade-{server_port}.yaml");
    write_mihomo_httpupgrade_config(&cfg, socks_port, server_port, TEST_UUID, "/up");
    let _m = start_mihomo(&cfg, socks_port);

    let body = socks5_get(socks_port, &local_http_url(http_addr, "/ip")).unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");
}
