//! Integration tests for the metrics HTTP endpoint exposed by `InboundServer`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn reserve_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn http_get(addr: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn metrics_disabled_by_default() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let config_toml = format!(
        r#"
listen = "{listen}"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "no-metrics-test"
udp = false
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(100));

    let result = TcpStream::connect_timeout(
        &metrics_addr.parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        result.is_err(),
        "expected no metrics listener; got connection on {metrics_addr}"
    );
}

#[test]
fn metrics_endpoint_serves_prometheus_dump() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let config_toml = format!(
        r#"
listen = "{listen}"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "metrics-test"
udp = false

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    assert!(
        response.contains("wrongsv_uptime_seconds"),
        "missing uptime metric: {response}"
    );

    let healthz = http_get(&metrics_addr, "/healthz");
    assert!(healthz.contains("200 OK"), "got: {healthz}");
}
