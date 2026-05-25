//! Minimal REALITY client — TLS 1.3 + VLESS, tests HTTPS relay.
//!
//! Usage:
//!   cargo run --example reality-client -- \
//!     --server 127.0.0.1:8443 \
//!     --server-pk <base64-x25519-pk> \
//!     --short-id <hex-8-chars> \
//!     --raw-pubkey <hex-64-chars> \
//!     --target www.microsoft.com:443
//!
//! The server prints its raw_pubkey on startup when REALITY is enabled.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use clap::Parser;
use hkdf::Hkdf;
use hmac::Mac;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
struct Cli {
    /// wrongsv server address
    #[arg(long, default_value = "127.0.0.1:8443")]
    server: String,

    /// Server X25519 public key (base64, url-safe no pad)
    #[arg(long)]
    server_pk: String,

    /// REALITY short ID (hex, 8 chars = 4 bytes)
    #[arg(long)]
    short_id: String,

    /// Server Ed25519 raw pubkey (hex, 64 chars) for cert HMAC verification
    #[arg(long)]
    raw_pubkey: String,

    /// Target host:port to connect to through the proxy
    #[arg(long, default_value = "www.microsoft.com:443")]
    target: String,

    /// VLESS user UUID
    #[arg(long, default_value = "00000000-0000-4000-8000-000000000000")]
    uuid: String,

    /// SNI for the REALITY ClientHello
    #[arg(long, default_value = "www.microsoft.com")]
    sni: String,

    /// Use plain HTTP (no TLS) to the target. Good for testing.
    #[arg(long)]
    http: bool,

    /// HTTP path to request from the target
    #[arg(long, default_value = "/")]
    path: String,

    /// Skip REALITY cert verification (for testing)
    #[arg(long)]
    insecure: bool,

    /// Path to server KEYLOG file (env WRONGSV_KEYLOG_FILE).
    /// Client reads this file mid-handshake to extract correct TLS secrets
    /// if its own key schedule doesn't match the server's.
    #[arg(long)]
    keylog_file: Option<String>,

    /// Skip target TLS certificate verification (for testing with IP targets).
    #[arg(long)]
    insecure_target: bool,

    /// Override server handshake traffic secret (hex, 64 chars) from server KEYLOG.
    /// Bypasses client-side key schedule computation for debugging.
    #[arg(long)]
    keylog_server_hs: Option<String>,

    /// Override client handshake traffic secret (hex, 64 chars) from server KEYLOG.
    #[arg(long)]
    keylog_client_hs: Option<String>,

    /// Override server app traffic secret (hex, 64 chars) from server KEYLOG.
    #[arg(long)]
    keylog_server_app: Option<String>,

    /// Override client app traffic secret (hex, 64 chars) from server KEYLOG.
    #[arg(long)]
    keylog_client_app: Option<String>,
}

// ---------------------------------------------------------------------------
// No-op TLS certificate verifier (for --insecure-target)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
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

// ---------------------------------------------------------------------------
// TLS 1.3 key schedule helpers (RFC 8446 §7.1)
// ---------------------------------------------------------------------------

/// HKDF-Extract: HMAC-Hash(salt, ikm)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(salt)
        .expect("HMAC key len");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("valid prk");
    let mut out = vec![0u8; length];

    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hkdf.expand(&info, &mut out).expect("expand ok");
    out
}

// ---------------------------------------------------------------------------
// TLS 1.3 AEAD record layer
// ---------------------------------------------------------------------------

/// Sequence-number-based nonce for TLS 1.3: write_iv XOR seq_num (big-endian)
fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(iv);
    let be = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= be[i];
    }
    n
}

/// Read one TLS record, returning (content_type, payload, record_header_aad).
/// The AAD is the 5-byte record header needed for TLS 1.3 AEAD.
fn read_tls_record(stream: &mut TcpStream) -> Result<(u8, Vec<u8>, [u8; 5]), String> {
    // Set a read timeout so we don't hang forever if the server dies mid-stream.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| format!("read record hdr: {e}"))?;
    let ct = hdr[0];
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("read record payload ({len} bytes): {e}"))?;
    Ok((ct, payload, hdr))
}

struct TlsCipher {
    cipher: Aes128Gcm,
    _write_key: Vec<u8>,
    write_iv: [u8; 12],
    read_key: Vec<u8>,
    read_iv: [u8; 12],
    write_seq: u64,
    read_seq: u64,
}

impl TlsCipher {
    fn new(
        client_write_key: &[u8],
        client_write_iv: &[u8; 12],
        server_write_key: &[u8],
        server_write_iv: &[u8; 12],
    ) -> Self {
        let mut cwiv = [0u8; 12];
        cwiv.copy_from_slice(client_write_iv);
        let mut criv = [0u8; 12];
        criv.copy_from_slice(server_write_iv);
        TlsCipher {
            cipher: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(client_write_key)),
            _write_key: client_write_key.to_vec(),
            write_iv: cwiv,
            read_key: server_write_key.to_vec(),
            read_iv: criv,
            write_seq: 0,
            read_seq: 0,
        }
    }

    /// Encrypt and write application data.
    fn encrypt_write(&mut self, stream: &mut TcpStream, plaintext: &[u8]) -> Result<(), String> {
        let nonce_arr = tls13_nonce(&self.write_iv, self.write_seq);
        let nonce = Nonce::from_slice(&nonce_arr);

        // Build inner plaintext with content type byte
        let mut inner = plaintext.to_vec();
        inner.push(0x17); // inner content type = application_data

        // Build the record header that will wrap the ciphertext (use it as AAD).
        // Tag is 16 bytes for AES-GCM.
        let record_len = inner.len() + 16;
        let hdr: [u8; 5] = [
            0x17, // application_data
            0x03, 0x03, // TLS 1.2 compat version
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        let ct = self
            .cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &inner,
                    aad: &hdr,
                },
            )
            .map_err(|e| format!("encrypt: {e}"))?;
        self.write_seq += 1;

        // Write TLS record: header + ciphertext+tag (no separate inner_ct byte)
        stream
            .write_all(&hdr)
            .map_err(|e| format!("write hdr: {e}"))?;
        stream
            .write_all(&ct)
            .map_err(|e| format!("write ct: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Read and decrypt one application data record.
    /// Returns the inner plaintext with padding and content_type byte stripped.
    fn decrypt_read(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.read_key));
        let (payload, aad) = loop {
            let (ct, payload, hdr) = read_tls_record(stream)?;
            if ct == 0x15 {
                return Err("TLS alert received".into());
            }
            if ct == 0x17 {
                break (payload, hdr);
            }
        };
        let nonce_arr = tls13_nonce(&self.read_iv, self.read_seq);
        let nonce = Nonce::from_slice(&nonce_arr);
        let mut pt = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: payload.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|e| format!("decrypt: {e}"))?;
        self.read_seq += 1;

        // Strip TLS 1.3 inner content type (last byte) and any zero padding
        while pt.last() == Some(&0) {
            pt.pop();
        }
        let _inner_ct = pt.pop().ok_or("empty decrypted record")?;
        Ok(pt)
    }
}

// ---------------------------------------------------------------------------
// REALITY ClientHello
// ---------------------------------------------------------------------------

fn build_reality_client_hello(
    random: [u8; 32],
    session_id: [u8; 32],
    key_share: [u8; 32],
    sni: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01); // handshake: client_hello
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 compat
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    // cipher_suites: TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut extensions = Vec::new();

    // supported_versions: TLS 1.3
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&[0x03, 0x04]);

    // signature_algorithms: ed25519, ecdsa_secp256r1_sha256
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    extensions.extend_from_slice(&6u16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&0x0807u16.to_be_bytes());
    extensions.extend_from_slice(&0x0403u16.to_be_bytes());

    // supported_groups: X25519
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.extend_from_slice(&0x001Du16.to_be_bytes());

    // key_share: X25519
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&38u16.to_be_bytes());
    extensions.extend_from_slice(&36u16.to_be_bytes());
    extensions.extend_from_slice(&0x001Du16.to_be_bytes());
    extensions.extend_from_slice(&32u16.to_be_bytes());
    extensions.extend_from_slice(&key_share);

    // server_name: SNI
    let host = sni.as_bytes();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    let sn_len = 5 + host.len() as u16;
    extensions.extend_from_slice(&sn_len.to_be_bytes());
    extensions.extend_from_slice(&(3 + host.len() as u16).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // Fill handshake length
    let hs_len = (body.len() - 4) as u32;
    body[1] = (hs_len >> 16) as u8;
    body[2] = (hs_len >> 8) as u8;
    body[3] = hs_len as u8;

    // TLS record
    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

// ---------------------------------------------------------------------------
// TLS 1.3 handshake state
// ---------------------------------------------------------------------------

struct HandshakeState {
    _client_random: [u8; 32],
    _server_random: [u8; 32],
    transcript: Vec<u8>,
    client_handshake_key: Vec<u8>,
    client_handshake_iv: [u8; 12],
    server_handshake_key: Vec<u8>,
    server_handshake_iv: [u8; 12],
    master_secret: [u8; 32],
    client_app_key: Vec<u8>,
    client_app_iv: [u8; 12],
    server_app_key: Vec<u8>,
    server_app_iv: [u8; 12],
}

impl HandshakeState {
    fn new(
        client_random: [u8; 32],
        server_random: [u8; 32],
        client_hello_raw: &[u8],
        server_hello_raw: &[u8],
        shared_secret: &[u8],
    ) -> Self {
        let empty_hash = Sha256::digest([]);

        // early_secret = HKDF-Extract(salt=zeros(32), ikm="")
        let early_secret = hkdf_extract(&[0u8; 32], &[0u8; 32]);

        // handshake_secret = HKDF-Extract(derived, shared_secret)
        let derived = hkdf_expand_label(&early_secret, "derived", &empty_hash, 32);
        let handshake_secret = hkdf_extract(&derived, shared_secret);

        // Transcript: SHA256(ClientHello || ServerHello)
        let mut transcript = Vec::new();
        transcript.extend_from_slice(client_hello_raw);
        transcript.extend_from_slice(server_hello_raw);
        let transcript_hash = Sha256::digest(&transcript);

        // Handshake traffic secrets
        let client_hs_ts =
            hkdf_expand_label(&handshake_secret, "c hs traffic", &transcript_hash, 32);
        let server_hs_ts =
            hkdf_expand_label(&handshake_secret, "s hs traffic", &transcript_hash, 32);

        let client_hs_key = hkdf_expand_label(&client_hs_ts, "key", b"", 16);
        let client_hs_iv = hkdf_expand_label(&client_hs_ts, "iv", b"", 12);
        let server_hs_key = hkdf_expand_label(&server_hs_ts, "key", b"", 16);
        let server_hs_iv = hkdf_expand_label(&server_hs_ts, "iv", b"", 12);

        let mut c_hs_iv_arr = [0u8; 12];
        c_hs_iv_arr.copy_from_slice(&client_hs_iv);
        let mut s_hs_iv_arr = [0u8; 12];
        s_hs_iv_arr.copy_from_slice(&server_hs_iv);

        // Master secret = HKDF-Extract(derived, zeros(32))
        let derived = hkdf_expand_label(&handshake_secret, "derived", &empty_hash, 32);
        let master_secret = hkdf_extract(&derived, &[0u8; 32]);

        // Placeholder app keys (updated with real transcript later)
        let client_app_ts =
            hkdf_expand_label(&master_secret, "c ap traffic", &empty_hash, 32);
        let server_app_ts =
            hkdf_expand_label(&master_secret, "s ap traffic", &empty_hash, 32);

        let client_app_key = hkdf_expand_label(&client_app_ts, "key", b"", 16);
        let client_app_iv = hkdf_expand_label(&client_app_ts, "iv", b"", 12);
        let server_app_key = hkdf_expand_label(&server_app_ts, "key", b"", 16);
        let server_app_iv = hkdf_expand_label(&server_app_ts, "iv", b"", 12);

        let mut c_app_iv_arr = [0u8; 12];
        c_app_iv_arr.copy_from_slice(&client_app_iv);
        let mut s_app_iv_arr = [0u8; 12];
        s_app_iv_arr.copy_from_slice(&server_app_iv);

        HandshakeState {
            _client_random: client_random,
            _server_random: server_random,
            transcript,
            client_handshake_key: client_hs_key,
            client_handshake_iv: c_hs_iv_arr,
            server_handshake_key: server_hs_key,
            server_handshake_iv: s_hs_iv_arr,
            master_secret,
            client_app_key,
            client_app_iv: c_app_iv_arr,
            server_app_key,
            server_app_iv: s_app_iv_arr,
        }
    }

    /// Update application traffic secrets with the final transcript hash.
    fn update_app_keys(&mut self, full_transcript_hash: &[u8]) {
        let client_app_ts =
            hkdf_expand_label(&self.master_secret, "c ap traffic", full_transcript_hash, 32);
        let server_app_ts =
            hkdf_expand_label(&self.master_secret, "s ap traffic", full_transcript_hash, 32);

        self.client_app_key = hkdf_expand_label(&client_app_ts, "key", b"", 16);
        self.server_app_key = hkdf_expand_label(&server_app_ts, "key", b"", 16);
        let c_iv = hkdf_expand_label(&client_app_ts, "iv", b"", 12);
        let s_iv = hkdf_expand_label(&server_app_ts, "iv", b"", 12);
        self.client_app_iv.copy_from_slice(&c_iv);
        self.server_app_iv.copy_from_slice(&s_iv);
    }
}

// ---------------------------------------------------------------------------
// ServerHello parser
// ---------------------------------------------------------------------------

fn parse_server_hello(
    payload: &[u8],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    // TLS handshake header: type(1) + len(3)
    if payload.len() < 4 || payload[0] != 0x02 {
        return Err(format!("expected ServerHello (0x02), got 0x{:02x}", payload[0]));
    }
    let _hs_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;

    let body = &payload[4..];
    if body.len() < 34 {
        return Err("ServerHello too short".into());
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&body[2..34]);

    let session_id_len = body[34] as usize;
    let mut pos = 35 + session_id_len;
    if pos + 3 > body.len() {
        return Err("ServerHello truncated at cipher_suite".into());
    }
    let _cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3; // cipher_suite(2) + compression(1)

    if pos + 2 > body.len() {
        return Err("ServerHello truncated at extensions".into());
    }
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_data = &body[pos..pos + ext_len];

    // Find key_share extension (0x0033)
    let mut ext_pos = 0;
    let mut server_key_share = None;
    while ext_pos + 4 <= ext_data.len() {
        let ext_type = u16::from_be_bytes([ext_data[ext_pos], ext_data[ext_pos + 1]]);
        let ext_size =
            u16::from_be_bytes([ext_data[ext_pos + 2], ext_data[ext_pos + 3]]) as usize;
        ext_pos += 4;
        if ext_pos + ext_size > ext_data.len() {
            break;
        }
        if ext_type == 0x0033 {
            // ServerHello key_share: KeyShareEntry = group(2) + key_len(2) + key_data
            if ext_size >= 4 {
                let group = u16::from_be_bytes([ext_data[ext_pos], ext_data[ext_pos + 1]]);
                let key_len =
                    u16::from_be_bytes([ext_data[ext_pos + 2], ext_data[ext_pos + 3]]) as usize;
                if group == 0x001D && key_len == 32 && ext_size >= 4 + key_len {
                    let mut ks = [0u8; 32];
                    ks.copy_from_slice(&ext_data[ext_pos + 4..ext_pos + 4 + 32]);
                    server_key_share = Some(ks);
                }
            }
        }
        ext_pos += ext_size;
    }

    let server_key_share =
        server_key_share.ok_or("key_share extension not found in ServerHello")?;

    Ok((server_random, server_key_share, [0u8; 32])) // TODO: proper cipher suite
}

// ---------------------------------------------------------------------------
// REALITY auth key derivation (client side)
// ---------------------------------------------------------------------------

fn derive_auth_key(
    client_random: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();
    auth_key
}

/// Verify the server's cert: last 64 bytes must equal HMAC-SHA512(auth_key, raw_pubkey).
fn verify_reality_cert(
    auth_key: &[u8; 32],
    raw_pubkey: &[u8; 32],
    cert_der: &[u8],
) -> Result<(), String> {
    if cert_der.len() < 64 {
        return Err("cert too short".into());
    }
    let sig = &cert_der[cert_der.len() - 64..];
    let mut mac = <hmac::Hmac<Sha512> as Mac>::new_from_slice(auth_key)
        .map_err(|e| format!("hmac: {e}"))?;
    mac.update(raw_pubkey);
    let expected = mac.finalize().into_bytes();
    if sig == expected.as_slice() {
        Ok(())
    } else {
        Err("cert HMAC mismatch".into())
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Parse server public key (base64 url-safe no pad)
    let server_pk_bytes: [u8; 32] = {
        use base64::Engine;
        let mut b64 = cli.server_pk.clone();
        // Add padding if needed
        while b64.len() % 4 != 0 {
            b64.push('=');
        }
        let bytes = base64::engine::general_purpose::URL_SAFE
            .decode(&b64)
            .map_err(|e| format!("server-pk base64 decode: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "server-pk must be 32 bytes")?
    };

    // Parse short ID
    let short_id: [u8; 8] = {
        let mut sid = [0u8; 8];
        let hex = &cli.short_id;
        if hex.len() != 16 {
            return Err("short-id must be 16 hex chars (8 bytes)".into());
        }
        for i in 0..8 {
            sid[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("short-id hex: {e}"))?;
        }
        sid
    };

    // Parse raw pubkey (for cert verification)
    let raw_pubkey: [u8; 32] = if cli.insecure {
        [0u8; 32]
    } else {
        let hex = &cli.raw_pubkey;
        if hex.len() != 64 {
            return Err("raw-pubkey must be 64 hex chars (32 bytes)".into());
        }
        let mut pk = [0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("raw-pubkey hex: {e}"))?;
        }
        pk
    };

    // Parse target
    let (target_host, target_port) = cli
        .target
        .rsplit_once(':')
        .ok_or("target must be host:port")?;
    let target_port: u16 = target_port.parse()?;

    // Parse UUID
    let user_uuid = Uuid::parse_string(&cli.uuid)?;

    // ------------------------------------------------------------------
    // Step 1: TCP connect + REALITY ClientHello
    // ------------------------------------------------------------------
    let server_addr: std::net::SocketAddr = cli.server.parse()?;
    let mut stream = TcpStream::connect_timeout(&server_addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Generate ephemeral X25519 keypair
    let client_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pk = PublicKey::from(&client_sk);
    let server_pk = PublicKey::from(server_pk_bytes);
    let reality_shared = client_sk.diffie_hellman(&server_pk);

    // Generate client random (for REALITY + TLS)
    let mut client_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_random);

    // Derive REALITY auth key
    let auth_key = derive_auth_key(&client_random, reality_shared.as_bytes());

    // Build REALITY auth plaintext
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let mut plaintext = [0u8; 16];
    plaintext[0..3].copy_from_slice(&[1, 2, 3]);
    plaintext[3] = 0;
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..16].copy_from_slice(&short_id);

    // Build ClientHello with zeroed session_id, compute AAD
    let temp_hello =
        build_reality_client_hello(client_random, [0u8; 32], *client_pk.as_bytes(), &cli.sni);
    let aad = &temp_hello[5..]; // strip TLS record header

    // Encrypt session_id
    let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&auth_key);
    let cipher = aes_gcm::Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&client_random[20..32]);
    let ct = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|e| format!("AES-GCM encrypt: {e}"))?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&ct);

    let client_hello =
        build_reality_client_hello(client_random, session_id, *client_pk.as_bytes(), &cli.sni);

    // Extract the ClientHello handshake body (without TLS record header) for transcript
    let client_hello_body = &client_hello[5..];

    stream.write_all(&client_hello)?;
    tracing::info!("sent REALITY ClientHello ({} bytes)", client_hello.len());

    // ------------------------------------------------------------------
    // Step 2: Read ServerHello
    // ------------------------------------------------------------------
    let (ct, server_hello_payload, _sh_hdr) = read_tls_record(&mut stream)?;
    if ct != 0x16 {
        return Err(format!("expected handshake (0x16), got 0x{ct:02x}").into());
    }
    let (server_random, server_key_share, _cs) = parse_server_hello(&server_hello_payload)?;
    tracing::info!("received ServerHello");

    // ServerHello raw bytes for transcript (re-wrap as TLS record)
    let mut server_hello_record = Vec::new();
    server_hello_record.push(0x16);
    server_hello_record.extend_from_slice(&[0x03, 0x03]);
    server_hello_record
        .extend_from_slice(&(server_hello_payload.len() as u16).to_be_bytes());
    server_hello_record.extend_from_slice(&server_hello_payload);

    // ------------------------------------------------------------------
    // Step 3: TLS 1.3 ECDH + derive handshake keys
    // ------------------------------------------------------------------
    let server_ks_pk = PublicKey::from(server_key_share);
    let tls_shared = client_sk.diffie_hellman(&server_ks_pk);

    let mut state = HandshakeState::new(
        client_random,
        server_random,
        client_hello_body,
        &server_hello_payload,
        tls_shared.as_bytes(),
    );

    // If --keylog-file is provided, read server KEYLOG and extract secrets
    // matching our client_random. This bypasses our own key schedule entirely.
    let mut keylog_server_hs_ts: Option<Vec<u8>> = None;
    let mut keylog_client_hs_ts: Option<Vec<u8>> = None;
    let mut keylog_server_app_ts: Option<Vec<u8>> = None;
    let mut keylog_client_app_ts: Option<Vec<u8>> = None;

    if let Some(ref keylog_path) = cli.keylog_file {
        let cr_hex = client_random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match std::fs::read_to_string(keylog_path) {
            Ok(contents) => {
                for line in contents.lines() {
                    if let Some(rest) = line.strip_prefix("KEYLOG ") {
                        let parts: Vec<&str> = rest.split_whitespace().collect();
                        if parts.len() >= 3 && parts[1] == cr_hex {
                            let secret = match hex::decode(parts[2]) {
                                Ok(s) => s,
                                Err(_) => continue,
                            };
                            match parts[0] {
                                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => keylog_server_hs_ts = Some(secret),
                                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => keylog_client_hs_ts = Some(secret),
                                "SERVER_TRAFFIC_SECRET_0" => keylog_server_app_ts = Some(secret),
                                "CLIENT_TRAFFIC_SECRET_0" => keylog_client_app_ts = Some(secret),
                                _ => {}
                            }
                        }
                    }
                }
                if keylog_server_hs_ts.is_some() && keylog_client_hs_ts.is_some() {
                    tracing::info!("loaded KEYLOG secrets from {keylog_path}");
                } else {
                    tracing::warn!("KEYLOG file {keylog_path} found but no matching secrets for client_random={cr_hex}");
                }
            }
            Err(e) => {
                tracing::warn!("cannot read KEYLOG file {keylog_path}: {e}");
            }
        }
    }

    // Allow KEYLOG-based override for debugging key schedule mismatch.
    // Priority: --keylog-file (auto) > --keylog-server-hs/--keylog-client-hs (manual)
    let hs_server_ts_override: Option<Vec<u8>> = keylog_server_hs_ts.or_else(|| {
        cli.keylog_server_hs.as_ref().and_then(|h| hex::decode(h).ok())
    });
    let hs_client_ts_override: Option<Vec<u8>> = keylog_client_hs_ts.or_else(|| {
        cli.keylog_client_hs.as_ref().and_then(|h| hex::decode(h).ok())
    });
    let (server_hs_key_used, server_hs_iv_used, client_hs_key_used, client_hs_iv_used) =
        if let (Some(server_hs_ts), Some(client_hs_ts)) = (&hs_server_ts_override, &hs_client_ts_override)
        {
            if server_hs_ts.len() != 32 || client_hs_ts.len() != 32 {
                return Err("handshake traffic secrets must be 32 bytes".into());
            }
            let s_key = hkdf_expand_label(server_hs_ts, "key", b"", 16);
            let s_iv = hkdf_expand_label(server_hs_ts, "iv", b"", 12);
            let c_key = hkdf_expand_label(client_hs_ts, "key", b"", 16);
            let c_iv = hkdf_expand_label(client_hs_ts, "iv", b"", 12);
            let mut s_iv_arr = [0u8; 12];
            s_iv_arr.copy_from_slice(&s_iv);
            let mut c_iv_arr = [0u8; 12];
            c_iv_arr.copy_from_slice(&c_iv);
            tracing::info!("using KEYLOG override for handshake keys");
            (s_key, s_iv_arr, c_key, c_iv_arr)
        } else {
            (
                state.server_handshake_key.clone(),
                state.server_handshake_iv,
                state.client_handshake_key.clone(),
                state.client_handshake_iv,
            )
        };

    // Handshake cipher for decrypting server messages
    let mut hs_cipher = TlsCipher::new(
        &client_hs_key_used,
        &client_hs_iv_used,
        &server_hs_key_used,
        &server_hs_iv_used,
    );

    // Step 4: Read rest of server handshake (encrypted)
    let mut handshake_data = Vec::new();
    let mut cert_der = Vec::new();
    let mut got_finished = false;

    while !got_finished {
        let (ct, payload, hdr) = read_tls_record(&mut stream)?;
        match ct {
            0x14 => continue,
            0x17 => {
                let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(
                    &hs_cipher.read_key,
                ));
                let nonce_arr = tls13_nonce(&hs_cipher.read_iv, hs_cipher.read_seq);
                let nonce = Nonce::from_slice(&nonce_arr);
                let pt = cipher
                    .decrypt(
                        nonce,
                        aes_gcm::aead::Payload {
                            msg: payload.as_slice(),
                            aad: &hdr,
                        },
                    )
                    .map_err(|e| format!("hs decrypt: {e}"))?;
                hs_cipher.read_seq += 1;

                // Inner plaintext: content || zeros(padding) || inner_content_type
                // Strip trailing zeros then the content type byte
                let mut pt = pt; // make mutable
                while pt.last() == Some(&0) {
                    pt.pop();
                }
                let inner_ct = pt.pop().ok_or("empty decrypted record")?;

                if inner_ct != 0x16 {
                    continue;
                }

                // Parse handshake messages from decrypted data
                let mut pos = 0;
                while pos + 4 <= pt.len() {
                    let msg_type = pt[pos];
                    let msg_len =
                        u32::from_be_bytes([0, pt[pos + 1], pt[pos + 2], pt[pos + 3]]) as usize;
                    pos += 4;
                    if pos + msg_len > pt.len() {
                        break;
                    }
                    let msg = &pt[pos..pos + msg_len];
                    pos += msg_len;

                    handshake_data.extend_from_slice(&pt[pos - 4 - msg_len..pos]);

                    match msg_type {
                        0x08 => {
                            // EncryptedExtensions — just consume
                        }
                        0x0b => {
                            // Certificate
                            if msg.len() < 4 {
                                return Err("cert too short".into());
                            }
                            let cert_req_ctx_len = msg[0] as usize;
                            let cert_list_len_offset = 1 + cert_req_ctx_len;
                            if msg.len() < cert_list_len_offset + 3 {
                                return Err("cert list too short".into());
                            }
                            let _cert_list_len = u32::from_be_bytes([
                                0,
                                msg[cert_list_len_offset],
                                msg[cert_list_len_offset + 1],
                                msg[cert_list_len_offset + 2],
                            ]) as usize;
                            let cert_start = cert_list_len_offset + 3;
                            if msg.len() < cert_start + 3 {
                                return Err("cert entry too short".into());
                            }
                            let cert_len = u32::from_be_bytes([
                                0,
                                msg[cert_start],
                                msg[cert_start + 1],
                                msg[cert_start + 2],
                            ]) as usize;
                            let cert_bytes = &msg[cert_start + 3..cert_start + 3 + cert_len];
                            cert_der = cert_bytes.to_vec();
                        }
                        0x0f => {
                            // CertificateVerify — skip (we verify via HMAC instead)
                        }
                        0x14 => {
                            // Finished
                            got_finished = true;
                        }
                        _ => {}
                    }
                }
            }
            0x15 => {
                return Err("server sent alert during handshake".into());
            }
            _ => {}
        }
    }

    tracing::info!(
        "handshake complete, cert {} bytes",
        cert_der.len()
    );

    // Verify cert HMAC
    if !cli.insecure {
        verify_reality_cert(&auth_key, &raw_pubkey, &cert_der)?;
        tracing::info!("REALITY cert HMAC verified OK");
    }

    // Update transcript with all handshake data and re-derive application keys
    state.transcript.extend_from_slice(&handshake_data);
    state.update_app_keys(&state.transcript.clone());

    // ------------------------------------------------------------------
    // Step 5: Send client Finished
    // ------------------------------------------------------------------
    // Derive finished_key for HMAC-based Finished message verification.
    // Use KEYLOG override if available, otherwise compute from our own schedule.
    let client_hs_ts_for_finished = hs_client_ts_override.unwrap_or_else(|| {
        let empty_hash = Sha256::digest([]);
        let early_secret = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        let derived = hkdf_expand_label(&early_secret, "derived", &empty_hash, 32);
        let handshake_secret = hkdf_extract(&derived, tls_shared.as_bytes());
        let mut ch_sh = Vec::new();
        ch_sh.extend_from_slice(client_hello_body);
        ch_sh.extend_from_slice(&server_hello_payload);
        let ch_sh_hash = Sha256::digest(&ch_sh);
        hkdf_expand_label(&handshake_secret, "c hs traffic", &ch_sh_hash, 32)
    });
    let finished_key = hkdf_expand_label(&client_hs_ts_for_finished, "finished", b"", 32);

    let transcript_hash = Sha256::digest(&state.transcript);

    let mut hmac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&finished_key)
        .map_err(|e| format!("hmac: {e}"))?;
    hmac.update(&transcript_hash);
    let verify_data = hmac.finalize().into_bytes();

    // Build Finished message
    let mut finished_msg = vec![0x14]; // Finished
    finished_msg.extend_from_slice(&(verify_data.len() as u32).to_be_bytes()[1..]);
    finished_msg.extend_from_slice(&verify_data);

    // Encrypt and send with TLS 1.3 AAD
    let hs_cipher_send = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(
        &client_hs_key_used,
    ));
    let send_nonce_arr = tls13_nonce(&client_hs_iv_used, 0);
    let send_nonce = Nonce::from_slice(&send_nonce_arr);

    // Inner plaintext = Finished message + inner content type
    let mut inner = finished_msg;
    inner.push(0x16); // inner content type = handshake

    // Record header as AAD
    let record_len = inner.len() + 16; // +16 for AES-GCM tag
    let hdr: [u8; 5] = [
        0x17, 0x03, 0x03,
        (record_len >> 8) as u8,
        record_len as u8,
    ];

    let finished_ct = hs_cipher_send
        .encrypt(
            send_nonce,
            aes_gcm::aead::Payload {
                msg: &inner,
                aad: &hdr,
            },
        )
        .map_err(|e| format!("encrypt finished: {e}"))?;

    stream.write_all(&hdr)?;
    stream.write_all(&finished_ct)?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    tracing::info!("sent client Finished");

    // ------------------------------------------------------------------
    // Step 6: Derive application traffic keys + build app cipher
    // transcript for app traffic = SHA256(all handshake msgs through server Finished)
    // Client Finished is NOT included in the app traffic transcript (RFC 8446 §7.1).
    // ------------------------------------------------------------------
    let app_transcript_hash = Sha256::digest(&state.transcript);
    state.update_app_keys(&app_transcript_hash);

    // Allow KEYLOG-based override for app traffic keys
    let server_app_ts: Option<Vec<u8>> = keylog_server_app_ts.or_else(|| {
        cli.keylog_server_app.as_ref().and_then(|h| hex::decode(h).ok())
    });
    let client_app_ts: Option<Vec<u8>> = keylog_client_app_ts.or_else(|| {
        cli.keylog_client_app.as_ref().and_then(|h| hex::decode(h).ok())
    });
    let (client_app_key_used, client_app_iv_used, server_app_key_used, server_app_iv_used) =
        if let (Some(client_app_ts), Some(server_app_ts)) = (client_app_ts, server_app_ts) {
            if server_app_ts.len() != 32 || client_app_ts.len() != 32 {
                return Err("app traffic secrets must be 32 bytes".into());
            }
            let c_key = hkdf_expand_label(&client_app_ts, "key", b"", 16);
            let c_iv = hkdf_expand_label(&client_app_ts, "iv", b"", 12);
            let s_key = hkdf_expand_label(&server_app_ts, "key", b"", 16);
            let s_iv = hkdf_expand_label(&server_app_ts, "iv", b"", 12);
            let mut c_iv_arr = [0u8; 12];
            c_iv_arr.copy_from_slice(&c_iv);
            let mut s_iv_arr = [0u8; 12];
            s_iv_arr.copy_from_slice(&s_iv);
            tracing::info!("using KEYLOG override for app traffic keys");
            (c_key, c_iv_arr, s_key, s_iv_arr)
        } else {
            (
                state.client_app_key.clone(),
                state.client_app_iv,
                state.server_app_key.clone(),
                state.server_app_iv,
            )
        };

    let mut app_cipher = TlsCipher::new(
        &client_app_key_used,
        &client_app_iv_used,
        &server_app_key_used,
        &server_app_iv_used,
    );
    // App traffic keys are separate from handshake keys, so sequence numbers
    // are independent per RFC 8446 §5.3. Start fresh at seq=0.
    app_cipher.write_seq = 0;

    // ------------------------------------------------------------------
    // Step 7: Send VLESS TCP header
    // ------------------------------------------------------------------
    let validator = {
        let v = std::sync::Arc::new(MemoryValidator::new());
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
            email: "client@test".into(),
            level: 0,
        };
        v.add(user)?;
        v
    };

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse(target_host),
        port: wrongsv_net_types::Port(target_port),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };
    let addons = Addons::default();
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons)?;

    app_cipher.encrypt_write(&mut stream, &req_buf)?;

    // Read VLESS response header
    let resp = app_cipher.decrypt_read(&mut stream)?;
    if resp.is_empty() {
        return Err("empty VLESS response".into());
    }
    tracing::info!("VLESS response: version={}", resp[0]);

    // ------------------------------------------------------------------
    // Step 8: Request through the tunnel
    // ------------------------------------------------------------------
    if cli.http {
        tracing::info!("sending plain HTTP request to {target_host}:{target_port}{}", cli.path);

        let http_req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wrongsv-reality-client\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            cli.path, target_host
        );
        app_cipher.encrypt_write(&mut stream, http_req.as_bytes())?;

        // Read response
        let mut total = 0;
        loop {
            match app_cipher.decrypt_read(&mut stream) {
                Ok(data) => {
                    total += data.len();
                    print!("{}", String::from_utf8_lossy(&data));
                }
                Err(e) => {
                    if total > 0 {
                        tracing::info!("tunnel closed after {total} bytes");
                        break;
                    }
                    return Err(e.into());
                }
            }
        }
        tracing::info!("done — received {total} bytes");
    } else {
        tracing::info!("connecting to https://{target_host}:{target_port}{}", cli.path);

        // TLS handshake with target (use real web PKI via webpki-roots)
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls_config = if cli.insecure_target {
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let server_name = rustls::pki_types::ServerName::try_from(target_host.to_string())
            .map_err(|e| format!("invalid server name: {e}"))?;
        let mut tls_conn = rustls::ClientConnection::new(std::sync::Arc::new(tls_config), server_name)
            .map_err(|e| format!("TLS client: {e}"))?;

        // Drive TLS handshake over the encrypted tunnel.
        loop {
            if tls_conn.wants_write() {
                let mut write_buf = Vec::new();
                tls_conn.write_tls(&mut write_buf).map_err(|e| format!("TLS write: {e}"))?;
                if !write_buf.is_empty() {
                    app_cipher.encrypt_write(&mut stream, &write_buf)?;
                }
            }
            if tls_conn.wants_read() {
                let server_data = app_cipher.decrypt_read(&mut stream)?;
                let mut cursor = std::io::Cursor::new(server_data);
                let n = tls_conn.read_tls(&mut cursor).map_err(|e| format!("TLS read hs: {e}"))?;
                if n == 0 {
                    return Err("TLS target closed during handshake".into());
                }
                tls_conn.process_new_packets().map_err(|e| format!("TLS process hs: {e}"))?;
            }
            if !tls_conn.is_handshaking() && !tls_conn.wants_write() {
                break;
            }
        }
        tracing::info!("TLS to target established");

        // Send HTTP request
        let http_req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wrongsv-reality-client\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            cli.path, target_host
        );
        tls_conn.writer().write_all(http_req.as_bytes())?;
        let mut write_buf = Vec::new();
        tls_conn.write_tls(&mut write_buf).map_err(|e| format!("TLS write req: {e}"))?;
        if !write_buf.is_empty() {
            app_cipher.encrypt_write(&mut stream, &write_buf)?;
        }

        // Read response
        let mut total = 0;
        'outer: loop {
            let data = match app_cipher.decrypt_read(&mut stream) {
                Ok(d) => d,
                Err(e) => {
                    if total > 0 {
                        tracing::info!("tunnel closed after {total} bytes");
                        break;
                    }
                    return Err(e.into());
                }
            };
            let mut cursor = std::io::Cursor::new(&data);
            tls_conn.read_tls(&mut cursor).map_err(|e| format!("TLS read resp: {e}"))?;
            tls_conn.process_new_packets().map_err(|e| format!("TLS process resp: {e}"))?;
            let mut buf = [0u8; 4096];
            loop {
                match tls_conn.reader().read(&mut buf) {
                    Ok(0) => break 'outer,
                    Ok(n) => {
                        total += n;
                        print!("{}", String::from_utf8_lossy(&buf[..n]));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(format!("read resp: {e}").into()),
                }
            }
        }
        tracing::info!("done — received {total} bytes");
    }
    Ok(())
}
