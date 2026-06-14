//! XHTTP (SplitHTTP) carrier integration tests.
//!
//! These tests verify both HTTP/2 and raw HTTP/1.1 stream-one behavior plus
//! VLESS relay semantics without external client binaries. XHTTP uses no
//! protobuf framing — just raw bytes over the HTTP body stream.

use bytes::Bytes;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use wrongsv_protocol::RequestCommand;

mod common;
use common::{init_logging, pick_port, spawn_tcp_echo_target, spawn_xhttp_server};

const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";
const XRV: &str = "xtls-rprx-vision";

// ── helpers ────────────────────────────────────────────────────────────

/// Encode a VLESS request header into a byte buffer.
fn encode_vless_request(
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    command: RequestCommand,
    flow: &str,
) -> Vec<u8> {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestHeader};
    use wrongsv_uuid::Uuid;
    use wrongsv_vless_encoding::Addons;

    let uid = Uuid::parse_string(uuid).unwrap();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uid),
            flow: flow.into(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@xhttp.test".into(),
        level: 0,
    };

    let request = RequestHeader {
        version: 0,
        command,
        address: Address::parse(target_addr),
        port: Port(target_port),
        user,
    };

    let mut buf = bytes::BytesMut::new();
    wrongsv_vless_encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons { flow: flow.into() },
    )
    .unwrap();
    buf.to_vec()
}

/// Read raw bytes from an h2 response body stream (XHTTP has no framing).
async fn read_xhttp_data(
    body: &mut h2::RecvStream,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    match body.data().await {
        Some(Ok(data)) => Ok(Some(data.to_vec())),
        Some(Err(e)) => Err(format!("h2 stream error: {e}").into()),
        None => Ok(None),
    }
}

fn write_http1_chunk(
    stream: &mut TcpStream,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    write!(stream, "{:X}\r\n", payload.len())?;
    stream.write_all(payload)?;
    stream.write_all(b"\r\n")?;
    stream.flush()?;
    Ok(())
}

fn finish_http1_chunks(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

fn read_http1_response_status(
    reader: &mut BufReader<TcpStream>,
) -> Result<u16, Box<dyn std::error::Error>> {
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or("missing HTTP version")?;
    assert_eq!(version, "HTTP/1.1");
    let status = parts.next().ok_or("missing HTTP status")?.parse::<u16>()?;

    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }

    Ok(status)
}

fn read_http1_chunk(
    reader: &mut BufReader<TcpStream>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut len_line = String::new();
    reader.read_line(&mut len_line)?;
    if len_line.is_empty() {
        return Err("unexpected EOF while reading chunk size".into());
    }

    let chunk_len = len_line
        .trim()
        .split(';')
        .next()
        .ok_or("missing chunk length")?;
    let chunk_len = usize::from_str_radix(chunk_len, 16)?;
    if chunk_len == 0 {
        loop {
            let mut trailer = String::new();
            reader.read_line(&mut trailer)?;
            if trailer == "\r\n" || trailer.is_empty() {
                break;
            }
        }
        return Ok(None);
    }

    let mut data = vec![0u8; chunk_len];
    reader.read_exact(&mut data)?;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf)?;
    assert_eq!(&crlf, b"\r\n");
    Ok(Some(data))
}

// ── tests ──────────────────────────────────────────────────────────────

/// Verify the server completes HTTP/2 handshake and returns 200 for a
/// valid XHTTP path. Close the stream before sending VLESS data to
/// exercise clean shutdown.
#[test]
fn test_xhttp_handshake_and_path() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/xhttp")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), http::StatusCode::OK, "expected 200 OK");
    });
}

/// Verify the server accepts a sub-path under the configured prefix.
#[test]
fn test_xhttp_path_prefix() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        // XHTTP uses path prefix matching, so /xhttp/anything should work
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/xhttp/sub/path")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "path prefix should match"
        );
    });
}

/// Verify rejection for wrong path prefix.
#[test]
fn test_xhttp_rejects_wrong_path() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/wrong")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(
            response.status(),
            http::StatusCode::NOT_FOUND,
            "expected 404 for wrong path"
        );
    });
}

/// Verify a non-POST method is rejected.
#[test]
fn test_xhttp_rejects_get() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://xhttp.local/xhttp")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert!(
            response.status() != http::StatusCode::OK,
            "expected non-200 for GET method, got {}",
            response.status()
        );
    });
}

/// Verify a custom path is accepted.
#[test]
fn test_xhttp_custom_path() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/custom-path");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/custom-path")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "custom path should be accepted"
        );
    });
}

/// Verify a VLESS TCP request over XHTTP yields a valid VLESS response
/// (header round-trip without full relay).
#[test]
fn test_xhttp_vless_response() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");
    let echo_addr = spawn_tcp_echo_target();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/xhttp")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut body = response.into_body();

        // Send VLESS TCP request to the echo target (raw bytes, no framing).
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "",
        );
        send_stream.send_data(vless_header.into(), true).unwrap();
        drop(send_stream);

        tokio::task::yield_now().await;

        // Read VLESS response — raw bytes from the response body.
        let vless_resp = read_xhttp_data(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(!vless_resp.is_empty(), "VLESS response should not be empty");
    });
}

/// Full TCP echo through the XHTTP relay.
#[test]
fn test_xhttp_tcp_echo() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");
    let echo_addr = spawn_tcp_echo_target();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/xhttp")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut body = response.into_body();

        // Send VLESS TCP request to the echo target.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "",
        );
        send_stream.send_data(vless_header.into(), false).unwrap();

        // Read VLESS response header.
        let vless_resp = read_xhttp_data(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(!vless_resp.is_empty(), "VLESS response should not be empty");

        // Do TCP echo through the relay.
        let payload = b"hello XHTTP echo test payload";
        send_stream
            .send_data(payload.to_vec().into(), false)
            .unwrap();

        let echoed = read_xhttp_data(&mut body).await.unwrap();
        assert_eq!(
            echoed.as_deref(),
            Some(payload.as_ref()),
            "echo payload should match"
        );

        // End the stream.
        send_stream.send_data(Bytes::new(), true).unwrap();
    });
}

/// Full TCP echo through the HTTP/1.1 stream-one XHTTP path used by xray-core.
#[test]
fn test_xhttp_http1_chunked_tcp_echo() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, XRV, "/xhttp");
    let echo_addr = spawn_tcp_echo_target();

    let mut writer = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    writer.set_nodelay(true).unwrap();
    let reader_stream = writer.try_clone().unwrap();
    let mut reader = BufReader::new(reader_stream);

    writer
        .write_all(
            b"POST /xhttp HTTP/1.1\r\n\
Host: xhttp.local\r\n\
Transfer-Encoding: chunked\r\n\
Content-Type: application/grpc\r\n\
\r\n",
        )
        .unwrap();

    let vless_header = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        echo_addr.port(),
        RequestCommand::Tcp,
        "",
    );
    write_http1_chunk(&mut writer, &vless_header).unwrap();

    let status = read_http1_response_status(&mut reader).unwrap();
    assert_eq!(status, http::StatusCode::OK.as_u16());

    let vless_resp = read_http1_chunk(&mut reader)
        .unwrap()
        .expect("expected VLESS response");
    assert!(!vless_resp.is_empty(), "VLESS response should not be empty");

    let payload = b"hello XHTTP HTTP/1.1 chunked echo";
    write_http1_chunk(&mut writer, payload).unwrap();

    let echoed = read_http1_chunk(&mut reader)
        .unwrap()
        .expect("expected echoed payload");
    assert_eq!(echoed, payload);

    finish_http1_chunks(&mut writer).unwrap();
    assert!(
        read_http1_chunk(&mut reader).unwrap().is_none(),
        "response should terminate with a zero chunk"
    );
}

/// Verify host validation rejects mismatched hosts.
#[test]
fn test_xhttp_rejects_wrong_host() {
    init_logging();
    let port = pick_port();
    // Spawn server with host validation enabled
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[[users]]
id = "{TEST_UUID}"
email = "test@xhttp.test"
flow = "{XRV}"

[xhttp]
path = "/xhttp"
host = "allowed.example.com"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _guard = common::ServerGuard { handle };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        // Send with wrong host — should be rejected.
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://evil.example.com/xhttp")
            .header("host", "evil.example.com")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(
            response.status(),
            http::StatusCode::NOT_FOUND,
            "expected 404 for wrong host"
        );
    });
}

/// Verify XHTTP with Vision flow completes a VLESS response round-trip.
#[test]
fn test_xhttp_vision_vless_response() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_xhttp_server(port, TEST_UUID, "xtls-rprx-vision", "/xhttp");
    let echo_addr = spawn_tcp_echo_target();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();

        let (client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://xhttp.local/xhttp")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut body = response.into_body();

        // Send VLESS TCP request with xtls-rprx-vision flow.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "xtls-rprx-vision",
        );
        send_stream.send_data(vless_header.into(), true).unwrap();
        drop(send_stream);

        tokio::task::yield_now().await;

        // Read Vision-encoded VLESS response.
        let vless_resp = read_xhttp_data(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(
            !vless_resp.is_empty(),
            "Vision VLESS response should not be empty"
        );
    });
}
