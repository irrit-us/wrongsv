//! Xray lifecycle integration tests.
//!
//! These tests verify the full proxy lifecycle using a real xray client:
//! deploy → REALITY handshake → VLESS relay → HTTP response → cleanup.
//!
//! Requires xray binary. Set `XRAY_BIN` env var or place at
//! `test-deploy/xray`. Tests are skipped if xray is not available.

mod common;

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use common::{
    TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, TEST_SHORT_ID, TEST_SNI, TEST_UUID, init_logging, pick_port,
    socks5_get, spawn_multi_user_server, spawn_server,
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

    let body = socks5_get(socks_port, "http://httpbin.org/ip").unwrap();
    assert!(body.contains("origin"), "unexpected response: {body}");

    let body2 = socks5_get(socks_port, "http://httpbin.org/get?test=lc").unwrap();
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

    let body = socks5_get(socks_port, "http://httpbin.org/ip").unwrap();
    assert!(body.contains("origin"), "unexpected: {body}");
}

#[test]
fn test_xray_lifecycle_multi_request() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
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
        let body = socks5_get(socks_port, &format!("http://httpbin.org/get?n={i}")).unwrap();
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

    let body1 = socks5_get(socks1, "http://httpbin.org/ip").unwrap();
    assert!(body1.contains("origin"), "user1 Vision failed: {body1}");

    let body2 = socks5_get(socks2, "http://httpbin.org/ip").unwrap();
    assert!(body2.contains("origin"), "user2 raw failed: {body2}");
}

#[test]
fn test_xray_lifecycle_restart() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
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
        let body = socks5_get(socks_port, "http://httpbin.org/get?run=2").unwrap();
        assert!(body.contains("run=2"), "restart failed: {body}");
    }
}

#[test]
fn test_xray_lifecycle_wrong_credential_rejected() {
    if xray_bin().is_none() {
        eprintln!("SKIP: xray not found");
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

    let result = socks5_get(socks_port, "http://httpbin.org/ip");
    assert!(
        result.is_err(),
        "wrong short_id should be rejected, got: {result:?}"
    );
}
