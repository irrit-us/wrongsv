//! gRPC carrier integration tests.
//!
//! These tests verify HTTP/2 handshake + gRPC stream + VLESS relay
//! without external client binaries, by using the h2 crate as an
//! HTTP/2 client.

use bytes::Bytes;
use wrongsv_protocol::RequestCommand;

mod common;
use common::{init_logging, pick_port, spawn_grpc_server, spawn_tcp_echo_target};

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
        email: "test@grpc.test".into(),
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

/// Read one gRPC frame from an h2 response body stream.
async fn read_grpc_frame(
    body: &mut h2::RecvStream,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    use bytes::BytesMut;
    let mut buf = BytesMut::new();
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
                // Try to decode any remaining data
                return wrongsv_grpc::decode_hunk_frame(&mut buf)
                    .map_err(|e| format!("gRPC decode: {e}").into());
            }
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────

/// Verify the server completes HTTP/2 handshake and returns 200 for a
/// valid gRPC service path. Close the stream before sending VLESS data
/// to exercise clean shutdown.
#[test]
fn test_grpc_handshake_and_path() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");

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

        // Drive the connection in a background task.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Wait for the connection to be ready.
        let mut client = client.ready().await.unwrap();

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://grpc.local/GunService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("grpc-accept-encoding", "identity")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), http::StatusCode::OK, "expected 200 OK");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap()),
            Some("application/grpc")
        );
    });
}

/// Verify that sending a VLESS TCP request over gRPC yields a valid
/// VLESS response (header round-trip without full relay).
#[test]
fn test_grpc_vless_response() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");
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

        // Send VLESS TCP request to the echo target.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "",
        );
        let hdr_frame = wrongsv_grpc::encode_hunk_frame(&vless_header);
        send_stream.send_data(hdr_frame, true).unwrap();
        drop(send_stream);

        // Yield to let the connection driver flush the DATA frame.
        tokio::task::yield_now().await;

        // Read VLESS response header — should arrive as a gRPC frame.
        let vless_resp = read_grpc_frame(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(!vless_resp.is_empty(), "VLESS response should not be empty");
    });
}

/// Full TCP echo through the gRPC relay.
#[test]
fn test_grpc_tcp_echo() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");
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

        // Send VLESS TCP request to the echo target.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "",
        );
        let hdr_frame = wrongsv_grpc::encode_hunk_frame(&vless_header);
        send_stream.send_data(hdr_frame, false).unwrap();

        // Read VLESS response header.
        let vless_resp = read_grpc_frame(&mut body)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(!vless_resp.is_empty(), "VLESS response should not be empty");

        // Do TCP echo through the relay.
        let payload = b"hello gRPC echo test payload";
        let echo_frame = wrongsv_grpc::encode_hunk_frame(payload);
        send_stream.send_data(echo_frame, false).unwrap();

        let echoed = read_grpc_frame(&mut body).await.unwrap();
        assert_eq!(echoed.as_deref(), Some(payload.as_ref()));

        // End the stream.
        send_stream.send_data(Bytes::new(), true).unwrap();
    });
}

/// A single HTTP/2 gRPC connection should be able to carry more than one
/// request stream. Real clients (mihomo/xray/v2ray) reuse the same h2
/// connection for sequential proxy requests, so rejecting every stream after
/// the first breaks compatibility even when the first request succeeds.
#[test]
fn test_grpc_multiple_streams_same_h2_connection() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");
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

        for payload in [b"grpc-stream-one".as_slice(), b"grpc-stream-two".as_slice()] {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://grpc.local/GunService/Tun")
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .header("grpc-accept-encoding", "identity")
                .body(())
                .unwrap();

            let mut client_ready = client.clone().ready().await.unwrap();
            let (response, mut send_stream) = client_ready.send_request(request, false).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();

            let vless_header = encode_vless_request(
                TEST_UUID,
                "127.0.0.1",
                echo_addr.port(),
                RequestCommand::Tcp,
                "",
            );
            send_stream
                .send_data(wrongsv_grpc::encode_hunk_frame(&vless_header), false)
                .unwrap();

            let vless_resp = read_grpc_frame(&mut body)
                .await
                .unwrap()
                .expect("expected VLESS response");
            assert!(!vless_resp.is_empty(), "VLESS response should not be empty");

            send_stream
                .send_data(wrongsv_grpc::encode_hunk_frame(payload), false)
                .unwrap();
            let echoed = read_grpc_frame(&mut body).await.unwrap();
            assert_eq!(echoed.as_deref(), Some(payload));

            send_stream.send_data(Bytes::new(), true).unwrap();
            while let Some(frame) = body.data().await {
                let _ = frame.unwrap();
            }
            let _ = body.trailers().await.unwrap();
        }
    });
}

/// Verify the server rejects a request to the wrong service path.
#[test]
fn test_grpc_rejects_wrong_path() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");

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
            .uri("https://grpc.local/WrongService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
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
fn test_grpc_rejects_get() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "GunService");

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
            .uri("https://grpc.local/GunService/Tun")
            .header("content-type", "application/grpc")
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

/// Verify custom service names are supported.
#[test]
fn test_grpc_custom_service_name() {
    init_logging();
    let port = pick_port();
    let _guard = spawn_grpc_server(port, TEST_UUID, XRV, "MyService");

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
            .uri("https://grpc.local/MyService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();

        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "custom service name should be accepted"
        );
    });
}
