//! XHTTP (SplitHTTP) carrier integration tests.
//!
//! These tests verify HTTP/2 handshake + raw byte streaming + VLESS relay
//! without external client binaries, by using the h2 crate as an HTTP/2
//! client. XHTTP uses no protobuf framing — just raw bytes over HTTP/2.

use bytes::Bytes;
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
        &Addons {
            flow: flow.into(),
            ..Default::default()
        },
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
