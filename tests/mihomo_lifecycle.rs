//! Mihomo (ClashMeta) lifecycle integration tests.
//!
//! These tests verify the full proxy lifecycle using mihomo:
//! deploy → REALITY handshake → VLESS relay → HTTP response → cleanup.
//!
//! Requires mihomo binary. Set `MIHOMO_BIN` env var or place at
//! `test-deploy/mihomo`. Tests are skipped if mihomo is not available.

mod common;

use std::net::TcpStream;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use common::{
    TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_SHORT_ID, TEST_SNI, TEST_UUID, init_logging, pick_port,
    socks5_get, spawn_multi_user_server, spawn_server,
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
        r#"mixed-port: {socks_port}
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

fn start_mihomo(config_path: &str, socks_port: u16) -> MihomoGuard {
    let bin = mihomo_bin().expect("mihomo not found");
    let child = Command::new(&bin)
        .args(["-f", config_path])
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
    init_logging();

    let server_port = pick_port();
    let socks_port = server_port + 1000;

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

    let body = socks5_get(socks_port, "http://httpbin.org/ip").unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");

    let body2 = socks5_get(socks_port, "http://httpbin.org/get?test=lc").unwrap();
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
    init_logging();

    let server_port = pick_port();
    let socks_port = server_port + 1000;

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

    let body = socks5_get(socks_port, "http://httpbin.org/ip").unwrap();
    assert!(body.contains("origin"), "unexpected: {body}");
}

#[test]
fn test_mihomo_lifecycle_multi_request() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    init_logging();

    let server_port = pick_port();
    let socks_port = server_port + 1000;

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
        let body = socks5_get(socks_port, &format!("http://httpbin.org/get?n={i}")).unwrap();
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
    init_logging();

    let server_port = pick_port();
    let socks1 = server_port + 1000;
    let socks2 = server_port + 1001;
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

    let body1 = socks5_get(socks1, "http://httpbin.org/ip").unwrap();
    assert!(body1.contains("origin"), "user1 Vision failed: {body1}");

    let body2 = socks5_get(socks2, "http://httpbin.org/ip").unwrap();
    assert!(body2.contains("origin"), "user2 raw failed: {body2}");
}

#[test]
fn test_mihomo_lifecycle_restart() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    init_logging();

    let server_port = pick_port();
    let socks_port = server_port + 1000;

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
        let body = socks5_get(socks_port, "http://httpbin.org/get?run=1").unwrap();
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
        let body = socks5_get(socks_port, "http://httpbin.org/get?run=2").unwrap();
        assert!(body.contains("run=2"), "restart failed: {body}");
    }
}

#[test]
fn test_mihomo_lifecycle_wrong_credential_rejected() {
    if mihomo_bin().is_none() {
        eprintln!("SKIP: mihomo not found");
        return;
    }
    init_logging();

    let server_port = pick_port();
    let socks_port = server_port + 1000;

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

    let result = socks5_get(socks_port, "http://httpbin.org/ip");
    assert!(
        result.is_err(),
        "wrong short_id should be rejected, got: {result:?}"
    );
}
