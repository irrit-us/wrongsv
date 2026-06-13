//! Integration tests for the metrics HTTP endpoint exposed by `InboundServer`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

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

fn spawn_echo_target() -> std::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn build_vless_request(
    user_uuid: Uuid,
    email: &str,
    target_port: u16,
    flow: &str,
) -> (RequestHeader, Vec<u8>) {
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(user_uuid),
            flow: flow.into(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: email.into(),
        level: 0,
    };

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(target_port),
        user,
    };
    let addons = Addons {
        flow: flow.into(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();
    (request, buf.to_vec())
}

fn vless_connect(server_addr: &str, user_uuid: Uuid, email: &str, target_port: u16) -> TcpStream {
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(user_uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: email.into(),
        level: 0,
    };
    validator.add(user).unwrap();
    let (request, encoded) = build_vless_request(user_uuid, email, target_port, "");

    let mut stream = TcpStream::connect(server_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&encoded).unwrap();

    // Read the server's response header so the caller can read raw bytes.
    let mut cursor_buf = [0u8; 256];
    let n = stream.read(&mut cursor_buf).unwrap();
    let mut cursor = std::io::Cursor::new(&cursor_buf[..n]);
    encoding::decode_response_header(&mut cursor, &request).unwrap();

    stream
}

fn write_http1_chunk(stream: &mut TcpStream, payload: &[u8]) {
    write!(stream, "{:X}\r\n", payload.len()).unwrap();
    stream.write_all(payload).unwrap();
    stream.write_all(b"\r\n").unwrap();
    stream.flush().unwrap();
}

fn finish_http1_chunks(stream: &mut TcpStream) {
    stream.write_all(b"0\r\n\r\n").unwrap();
    stream.flush().unwrap();
}

fn read_http1_response_headers(reader: &mut std::io::BufReader<TcpStream>) -> u16 {
    use std::io::BufRead;

    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let mut parts = status_line.split_whitespace();
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    let status = parts.next().unwrap().parse::<u16>().unwrap();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    status
}

fn read_http1_chunk(reader: &mut std::io::BufReader<TcpStream>) -> Option<Vec<u8>> {
    use std::io::BufRead;

    let mut len_line = String::new();
    reader.read_line(&mut len_line).unwrap();
    assert!(!len_line.is_empty(), "unexpected EOF while reading HTTP/1.1 chunk");
    let chunk_len = usize::from_str_radix(
        len_line.trim().split(';').next().unwrap_or_default(),
        16,
    )
    .unwrap();
    if chunk_len == 0 {
        loop {
            let mut trailer = String::new();
            reader.read_line(&mut trailer).unwrap();
            if trailer == "\r\n" || trailer.is_empty() {
                break;
            }
        }
        return None;
    }
    let mut data = vec![0u8; chunk_len];
    reader.read_exact(&mut data).unwrap();
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).unwrap();
    assert_eq!(&crlf, b"\r\n");
    Some(data)
}

async fn read_grpc_frame(
    body: &mut h2::RecvStream,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut buf = bytes::BytesMut::new();

    loop {
        match body.data().await {
            Some(Ok(data)) => {
                buf.extend_from_slice(&data);
                if let Some(payload) = wrongsv_grpc::decode_hunk_frame(&mut buf)? {
                    return Ok(Some(payload));
                }
            }
            Some(Err(e)) => return Err(format!("h2 stream error: {e}").into()),
            None => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return wrongsv_grpc::decode_hunk_frame(&mut buf)
                    .map_err(|e| format!("decode trailing grpc frame: {e}").into());
            }
        }
    }
}

#[test]
fn metrics_count_bytes_per_user_through_vless_relay() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "alice@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(150));

    let echo_addr = spawn_echo_target();
    let mut conn = vless_connect(&listen, user_uuid, email, echo_addr.port());

    let payload = b"metrics-roundtrip-test-payload";
    conn.write_all(payload).unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload, "echo mismatch");

    // Give the relay threads a beat to flush counters.
    thread::sleep(Duration::from_millis(150));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload.len());
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload.len()
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}

#[test]
fn metrics_count_bytes_per_user_through_xhttp_http1_relay() {
    use std::io::BufReader;

    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "xhttp-user@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[xhttp]
path = "/xhttp"

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();
    let (_request, encoded) = build_vless_request(user_uuid, email, echo_addr.port(), "");

    let mut writer = TcpStream::connect(&listen).unwrap();
    writer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let reader_stream = writer.try_clone().unwrap();
    let mut reader = BufReader::new(reader_stream);

    writer
        .write_all(
            b"POST /xhttp HTTP/1.1\r\n\
Host: localhost\r\n\
Transfer-Encoding: chunked\r\n\
Content-Type: application/grpc\r\n\
\r\n",
        )
        .unwrap();
    write_http1_chunk(&mut writer, &encoded);

    assert_eq!(read_http1_response_headers(&mut reader), 200);
    let response_header = read_http1_chunk(&mut reader).expect("expected VLESS response");
    assert!(!response_header.is_empty(), "expected non-empty VLESS response header");

    let payload = b"xhttp-metrics-roundtrip-payload";
    write_http1_chunk(&mut writer, payload);
    let echoed = read_http1_chunk(&mut reader).expect("expected echoed payload");
    assert_eq!(&echoed[..], payload, "echo mismatch");

    finish_http1_chunks(&mut writer);
    assert!(read_http1_chunk(&mut reader).is_none());

    thread::sleep(Duration::from_millis(200));
    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload.len());
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload.len()
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}

#[test]
fn metrics_count_bytes_per_user_through_grpc_relay() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "grpc-user@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[grpc]
service_name = "GunService"

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();
    let (_request, encoded) = build_vless_request(user_uuid, email, echo_addr.port(), "");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(&listen).await.unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://grpc.local/GunService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut body = response.into_body();
        send_stream
            .send_data(wrongsv_grpc::encode_hunk_frame(&encoded), false)
            .unwrap();

        let response_header = read_grpc_frame(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response frame");
        assert!(!response_header.is_empty(), "expected non-empty VLESS response frame");

        let payload = b"grpc-metrics-roundtrip-payload";
        send_stream
            .send_data(wrongsv_grpc::encode_hunk_frame(payload), false)
            .unwrap();
        let echoed = read_grpc_frame(&mut body)
            .await
            .unwrap()
            .expect("expected echoed gRPC payload frame");
        assert_eq!(&echoed[..], payload, "echo mismatch");

        send_stream.send_data(bytes::Bytes::new(), true).unwrap();
    });

    thread::sleep(Duration::from_millis(200));
    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let payload_len = b"grpc-metrics-roundtrip-payload".len();
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload_len);
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload_len
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}

#[test]
fn metrics_count_bytes_per_user_through_reality_relay() {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "test@reality.test";

    // Generate REALITY X25519 keypair; configure server with the private key,
    // hand the client the base64-encoded public key.
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    let sk_hex = hex::encode(sk.as_bytes());
    let pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes());
    let short_id = "01234567";

    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[reality]
private_key = "{sk_hex}"
short_ids = ["{short_id}"]
max_time_diff = 300

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let raw_pubkey_hex = server
        .reality_raw_pubkey_hex()
        .expect("REALITY config should expose raw_pubkey");
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();

    // Use the server's actual raw_pubkey so the client-side cert HMAC
    // verification path is exercised end-to-end (not bypassed).
    let proxy_host = listen.split(':').next().unwrap();
    let proxy_port: u16 = listen.split(':').next_back().unwrap().parse().unwrap();
    let mut conn = wrongsv_evaluator_client::transport::connect_for_protocol(
        "reality",
        proxy_host,
        proxy_port,
        echo_addr.port(),
        &user_uuid.to_string(),
        "",
        Some(&pk_b64),
        Some(short_id),
        Some(&raw_pubkey_hex),
    )
    .expect("REALITY handshake should succeed");

    let payload = b"reality-metrics-roundtrip-payload";
    conn.write_all(payload).unwrap();
    conn.flush().unwrap();

    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < payload.len() {
        match conn.read(&mut got[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => panic!("REALITY read error: {e}"),
        }
    }
    assert_eq!(&got[..filled], payload, "echo mismatch");

    drop(conn);
    thread::sleep(Duration::from_millis(200));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload.len());
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload.len()
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}

#[test]
fn metrics_count_bytes_per_user_through_vmess_relay() {
    use wrongsv_server::vmess::{
        self, VmessBodyReader, VmessBodyWriter, VmessCommand, VmessRequest,
    };

    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "vmess-user@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[vmess]

[[vmess.users]]
id = "{user_uuid}"
email = "{email}"

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();

    let uuid_bytes: [u8; 16] = *user_uuid.as_bytes();
    let cmd_key = vmess::derive_cmd_key(&uuid_bytes);
    let (_plain, eaudid) = vmess::generate_eaudid(&cmd_key);

    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut body_key);
    rand::rngs::OsRng.fill_bytes(&mut body_iv);

    let request = VmessRequest {
        command: VmessCommand::Tcp,
        address: "127.0.0.1".into(),
        port: echo_addr.port(),
        option: vmess::DEFAULT_REQUEST_OPTIONS,
        security: vmess::DEFAULT_SECURITY,
        response_header: vmess::DEFAULT_RESPONSE_HEADER,
    };
    let (_header_len, header_payload) =
        vmess::build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request).unwrap();

    let mut conn = TcpStream::connect(&listen).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&eaudid).unwrap();
    conn.write_all(&header_payload).unwrap();

    vmess::read_response(&body_key, &body_iv, request.response_header, &mut conn).unwrap();

    let payload = b"vmess-metrics-roundtrip-payload";
    let mut writer = VmessBodyWriter::new_with_options(
        &body_key,
        &body_iv,
        &body_key,
        &body_iv,
        request.option,
        request.security,
    )
    .unwrap();
    writer.write_chunk(&mut conn, payload).unwrap();

    let response_body_key = vmess::derive_response_body_key(&body_key);
    let response_body_iv = vmess::derive_response_body_iv(&body_iv);
    let mut reader = VmessBodyReader::new_with_options(
        &response_body_key,
        &response_body_iv,
        &body_key,
        &body_iv,
        request.option,
        request.security,
    )
    .unwrap();
    let mut plaintext = Vec::with_capacity(payload.len());
    let got_chunk = reader.read_chunk(&mut conn, &mut plaintext).unwrap();
    assert!(got_chunk, "expected echoed VMess body chunk");
    assert_eq!(&plaintext[..], payload, "echo mismatch");

    // Cleanly close to flush counters before scrape.
    let _ = writer.write_eof(&mut conn);
    let _ = conn.shutdown(std::net::Shutdown::Write);
    thread::sleep(Duration::from_millis(200));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload.len());
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload.len()
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}
