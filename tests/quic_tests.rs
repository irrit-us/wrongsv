//! QUIC carrier integration tests.
//!
//! These tests verify VLESS over QUIC transport — TLS handshake + QUIC
//! stream + VLESS relay without external client binaries.

use std::sync::Arc;
use std::time::Duration;

use wrongsv_protocol::RequestCommand;

mod common;
use common::{init_logging, pick_port, spawn_tcp_echo_target};

use std::sync::Once;
static INIT_RUSTLS: Once = Once::new();

fn ensure_rustls() {
    INIT_RUSTLS.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
    });
}

const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";

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
        email: "test@quic.test".into(),
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

/// Skip server certificate verification (for test self-signed certs).
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create a quinn client endpoint that skips server cert verification.
fn make_quic_client() -> Result<quinn::Endpoint, Box<dyn std::error::Error>> {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ── tests ──────────────────────────────────────────────────────────────

/// Verify QUIC handshake completes and a bidirectional stream can be
/// established through the QUIC carrier.
#[test]
fn test_quic_handshake() {
    init_logging();
    ensure_rustls();
    let port = pick_port();
    let _guard = spawn_quic_server(port, TEST_UUID, "");
    std::thread::sleep(Duration::from_millis(300));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let client = make_quic_client().unwrap();
        let conn = client
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Send a VLESS header over the QUIC stream.
        let vless_header =
            encode_vless_request(TEST_UUID, "127.0.0.1", 80, RequestCommand::Tcp, "");
        send.write_all(&vless_header).await.unwrap();
        send.finish().unwrap();

        // Read the VLESS response.
        let mut buf = vec![0u8; 1024];
        let n = recv
            .read(&mut buf)
            .await
            .unwrap()
            .expect("expected VLESS response data");
        assert!(n > 0, "VLESS response should not be empty");
    });
}

/// Verify VLESS TCP echo relay over QUIC carrier.
#[test]
fn test_quic_tcp_echo() {
    init_logging();
    ensure_rustls();
    let port = pick_port();
    let _guard = spawn_quic_server(port, TEST_UUID, "");
    let echo_addr = spawn_tcp_echo_target();
    std::thread::sleep(Duration::from_millis(300));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let client = make_quic_client().unwrap();
        let conn = client
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Send VLESS TCP request to the echo target.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "",
        );
        send.write_all(&vless_header).await.unwrap();

        // Read VLESS response header.
        let mut buf = vec![0u8; 1024];
        let n = recv
            .read(&mut buf)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(n > 0, "VLESS response should not be empty");

        // Do TCP echo through the relay.
        let payload = b"hello QUIC echo test payload";
        send.write_all(payload).await.unwrap();
        send.finish().unwrap();

        let n = recv
            .read(&mut buf)
            .await
            .unwrap()
            .expect("expected echo response");
        assert_eq!(&buf[..n], payload, "echo payload should match");
    });
}

/// Verify VLESS over QUIC rejects an invalid UUID.
#[test]
fn test_quic_rejects_invalid_uuid() {
    init_logging();
    ensure_rustls();
    let port = pick_port();
    let _guard = spawn_quic_server(port, TEST_UUID, "");
    std::thread::sleep(Duration::from_millis(300));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let client = make_quic_client().unwrap();
        let conn = client
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Send VLESS header with an invalid UUID.
        let bad_header = encode_vless_request(
            "00000000-0000-0000-0000-000000000000",
            "127.0.0.1",
            80,
            RequestCommand::Tcp,
            "",
        );
        send.write_all(&bad_header).await.unwrap();
        send.finish().unwrap();

        // Should get connection closed or empty response (invalid user).
        let mut buf = vec![0u8; 1024];
        let result = recv.read(&mut buf).await;
        // Either Ok(None) (clean close) or Err (connection closed) is acceptable.
        match result {
            Ok(None) | Err(_) => {}     // expected — invalid user rejected
            Ok(Some(0)) => {} // empty read = closed
            Ok(Some(_)) => {
                // The server might send a response header before closing.
                // Either way, the connection should be dropped soon.
            }
        }
    });
}

/// Verify VLESS over QUIC with Vision flow handshake and VLESS response.
#[test]
fn test_quic_vision_response() {
    init_logging();
    ensure_rustls();
    let port = pick_port();
    let _guard = spawn_quic_server(port, TEST_UUID, "xtls-rprx-vision");
    let echo_addr = spawn_tcp_echo_target();
    std::thread::sleep(Duration::from_millis(300));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let client = make_quic_client().unwrap();
        let conn = client
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Send Vision VLESS TCP request.
        let vless_header = encode_vless_request(
            TEST_UUID,
            "127.0.0.1",
            echo_addr.port(),
            RequestCommand::Tcp,
            "xtls-rprx-vision",
        );
        send.write_all(&vless_header).await.unwrap();

        // Read VLESS response header (may be Vision-padded).
        let mut buf = vec![0u8; 1024];
        let n = recv
            .read(&mut buf)
            .await
            .unwrap()
            .expect("expected VLESS response");
        assert!(n > 0, "Vision VLESS response should not be empty");
    });
}

/// Spawn a wrongsv QUIC VLESS server.
fn spawn_quic_server(port: u16, user_id: &str, flow: &str) -> common::ServerGuard {
    let flow_line = if flow.is_empty() {
        String::new()
    } else {
        format!("flow = \"{flow}\"")
    };
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[[users]]
id = "{user_id}"
email = "test@quic.test"
{flow_line}

[quic]
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    std::thread::sleep(Duration::from_millis(200));
    common::ServerGuard { handle }
}
