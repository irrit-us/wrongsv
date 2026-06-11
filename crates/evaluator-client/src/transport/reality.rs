//! REALITY transport: TLS 1.3 hijacking with shortId auth + VLESS.
//!
//! Implements the full REALITY client-side handshake:
//! 1. TCP connect
//! 2. Send REALITY ClientHello with AES-encrypted session_id
//! 3. Complete TLS 1.3 handshake with custom key schedule
//! 4. Verify server cert via HMAC-SHA512
//! 5. VLESS header over application data
//!
//! This is a simplified version of `examples/reality-client.rs`,
//! optimized for sync I/O and evaluator use.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use super::BoxedIo;

// ── HKDF helpers ────────────────────────────────────────────────────────────

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC key len");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
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

fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(iv);
    let be = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= be[i];
    }
    n
}

// ── TLS record layer ────────────────────────────────────────────────────────

fn read_tls_record(stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>, [u8; 5])> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr)?;
    let ct = hdr[0];
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS record too large",
        ));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((ct, payload, hdr))
}

/// Sequence-number-based AEAD state for one direction.
struct AeadState {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl AeadState {
    fn new(key: &[u8], iv: &[u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key)),
            iv: *iv,
            seq: 0,
        }
    }

    fn decrypt(&mut self, payload: &[u8], aad: &[u8; 5]) -> io::Result<Vec<u8>> {
        let nonce_arr = tls13_nonce(&self.iv, self.seq);
        let nonce = Nonce::from_slice(&nonce_arr);
        let pt = self
            .cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: payload,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decrypt: {e}")))?;
        self.seq += 1;
        // Strip trailing zeros and inner content type byte
        let mut pt = pt;
        while pt.last() == Some(&0) {
            pt.pop();
        }
        pt.pop(); // inner content_type
        Ok(pt)
    }

    fn encrypt(&mut self, plaintext: &[u8], record_type: u8, inner_ct: u8) -> io::Result<Vec<u8>> {
        let nonce_arr = tls13_nonce(&self.iv, self.seq);
        let nonce = Nonce::from_slice(&nonce_arr);
        let mut inner = plaintext.to_vec();
        inner.push(inner_ct);
        let plaintext_len = inner.len();
        let record_len = plaintext_len + 16; // AES-GCM tag
        let hdr: [u8; 5] = [
            record_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];
        let ct = self
            .cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &inner,
                    aad: hdr.as_slice(),
                },
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encrypt: {e}")))?;
        self.seq += 1;
        let mut out = Vec::with_capacity(5 + ct.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

// ── ClientHello builder ─────────────────────────────────────────────────────

fn build_reality_client_hello(
    random: [u8; 32],
    session_id: [u8; 32],
    key_share: [u8; 32],
    sni: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01); // handshake: client_hello
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 compat version
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    // cipher_suites: only TLS_AES_128_GCM_SHA256 — our HKDF is SHA-256 only
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut extensions = Vec::new();

    // supported_versions: TLS 1.3
    extensions.extend_from_slice(&0x002bu16.to_be_bytes()); // ext type
    extensions.extend_from_slice(&3u16.to_be_bytes()); // ext len
    extensions.push(2); // versions len
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // signature_algorithms
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    extensions.extend_from_slice(&6u16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&0x0807u16.to_be_bytes()); // ed25519
    extensions.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256

    // supported_groups: X25519
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.extend_from_slice(&0x001du16.to_be_bytes());

    // key_share: X25519
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&38u16.to_be_bytes());
    extensions.extend_from_slice(&36u16.to_be_bytes());
    extensions.extend_from_slice(&0x001du16.to_be_bytes());
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

    // TLS record wrapper
    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

// ── ServerHello parser ──────────────────────────────────────────────────────

fn parse_server_hello(payload: &[u8]) -> io::Result<([u8; 32], [u8; 32])> {
    // TLS handshake header: type(1) + len(3)
    if payload.len() < 4 || payload[0] != 0x02 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected ServerHello (0x02), got 0x{:02x}", payload[0]),
        ));
    }
    let body = &payload[4..];
    if body.len() < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&body[2..34]);

    let session_id_len = body[34] as usize;
    let mut pos = 35 + session_id_len;
    if pos + 3 > body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello truncated at cipher_suite",
        ));
    }
    pos += 3; // cipher_suite(2) + compression(1)

    if pos + 2 > body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello truncated at extensions",
        ));
    }
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_data = &body[pos..pos + ext_len];

    // Find key_share extension (0x0033)
    let mut ext_pos = 0;
    let mut server_key_share = None;
    while ext_pos + 4 <= ext_data.len() {
        let ext_type = u16::from_be_bytes([ext_data[ext_pos], ext_data[ext_pos + 1]]);
        let ext_size = u16::from_be_bytes([ext_data[ext_pos + 2], ext_data[ext_pos + 3]]) as usize;
        ext_pos += 4;
        if ext_pos + ext_size > ext_data.len() {
            break;
        }
        if ext_type == 0x0033 && ext_size >= 4 {
            let group = u16::from_be_bytes([ext_data[ext_pos], ext_data[ext_pos + 1]]);
            let key_len =
                u16::from_be_bytes([ext_data[ext_pos + 2], ext_data[ext_pos + 3]]) as usize;
            if group == 0x001D && key_len == 32 && ext_size >= 4 + key_len {
                let mut ks = [0u8; 32];
                ks.copy_from_slice(&ext_data[ext_pos + 4..ext_pos + 4 + 32]);
                server_key_share = Some(ks);
            }
        }
        ext_pos += ext_size;
    }

    let server_key_share = server_key_share.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "key_share not found in ServerHello",
        )
    })?;
    Ok((server_random, server_key_share))
}

// ── REALITY auth ────────────────────────────────────────────────────────────

fn derive_auth_key(client_random: &[u8; 32], shared_secret: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();
    auth_key
}

fn verify_reality_cert(
    auth_key: &[u8; 32],
    raw_pubkey: &[u8; 32],
    cert_der: &[u8],
) -> io::Result<()> {
    if cert_der.len() < 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "cert too short"));
    }
    let sig = &cert_der[cert_der.len() - 64..];
    let mut mac = <hmac::Hmac<Sha512> as Mac>::new_from_slice(auth_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("hmac: {e}")))?;
    mac.update(raw_pubkey);
    let expected = mac.finalize().into_bytes();
    if sig == expected.as_slice() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cert HMAC mismatch",
        ))
    }
}

// ── Connection ──────────────────────────────────────────────────────────────

/// REALITY stream with TLS 1.3 AEAD encryption.
struct RealityConnection {
    sock: TcpStream,
    encrypt: AeadState,
    decrypt: AeadState,
}

impl Read for RealityConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut retries: u32 = 0;
        const MAX_RETRIES: u32 = 6;
        loop {
            match read_tls_record(&mut self.sock) {
                Ok((ct, payload, hdr)) => match ct {
                    0x17 => {
                        let pt = self.decrypt.decrypt(&payload, &hdr)?;
                        let n = pt.len().min(buf.len());
                        buf[..n].copy_from_slice(&pt[..n]);
                        return Ok(n);
                    }
                    0x15 => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "TLS alert",
                        ));
                    }
                    0x14 => {
                        continue; // change_cipher_spec — skip
                    }
                    _ => continue,
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(io::Error::new(
                            e.kind(),
                            "no application data after max retries",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for RealityConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TLS 1.3 max record plaintext is 2^14 = 16384 bytes.
        // Chunk larger writes into multiple TLS records.
        const MAX_CHUNK: usize = 16384;
        let mut written = 0;
        while written < buf.len() {
            let end = (written + MAX_CHUNK).min(buf.len());
            let chunk = &buf[written..end];
            let record = self.encrypt.encrypt(chunk, 0x17, 0x17)?;
            write_all_retry(&mut self.sock, &record)?;
            written = end;
        }
        // Flush immediately so data is on the wire before the caller tries to read
        self.sock.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// Write all bytes, retrying on WouldBlock.
fn write_all_retry(sock: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match sock.write(data) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")),
            Ok(n) => data = &data[n..],
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ── Connect ─────────────────────────────────────────────────────────────────

/// Connect via REALITY with full handshake.
#[allow(clippy::too_many_arguments)]
pub fn connect_reality(
    mut sock: TcpStream,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    server_pubkey_b64: &str,
    short_id_hex: &str,
    raw_pubkey_hex: &str,
) -> io::Result<BoxedIo> {
    let sni = "cloudflare.com";

    // Parse params
    let server_pk_bytes: [u8; 32] = {
        use base64::Engine;
        let mut b64 = server_pubkey_b64.to_string();
        while !b64.len().is_multiple_of(4) {
            b64.push('=');
        }
        let bytes = base64::engine::general_purpose::URL_SAFE
            .decode(&b64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("pubkey b64: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pubkey must be 32 bytes"))?
    };

    let short_id: [u8; 4] = {
        if short_id_hex.len() != 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "short_id must be 8 hex chars",
            ));
        }
        let mut sid = [0u8; 4];
        for i in 0..4 {
            sid[i] = u8::from_str_radix(&short_id_hex[i * 2..i * 2 + 2], 16).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("short_id hex: {e}"))
            })?;
        }
        sid
    };

    let raw_pubkey: [u8; 32] = {
        if raw_pubkey_hex.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw_pubkey must be 64 hex chars",
            ));
        }
        let mut pk = [0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&raw_pubkey_hex[i * 2..i * 2 + 2], 16).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("raw_pubkey hex: {e}"))
            })?;
        }
        pk
    };

    // Step 1: Configure TCP socket
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Step 2: Generate ephemeral X25519 keypair
    let client_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pk = PublicKey::from(&client_sk);
    let server_pk = PublicKey::from(server_pk_bytes);
    let reality_shared = client_sk.diffie_hellman(&server_pk);

    // Step 3: Build ClientHello with REALITY auth
    let mut client_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_random);

    let auth_key = derive_auth_key(&client_random, reality_shared.as_bytes());

    // REALITY auth plaintext
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| io::Error::other(format!("time: {e}")))?
        .as_secs() as u32;
    let mut plaintext = [0u8; 16];
    plaintext[0..3].copy_from_slice(&[1, 2, 3]);
    plaintext[3] = 0; // padding
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..12].copy_from_slice(&short_id);

    // Build temp ClientHello for AAD
    let temp_hello =
        build_reality_client_hello(client_random, [0u8; 32], *client_pk.as_bytes(), sni);
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
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("AES-GCM encrypt: {e}")))?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&ct);

    let client_hello =
        build_reality_client_hello(client_random, session_id, *client_pk.as_bytes(), sni);
    let client_hello_body = &client_hello[5..]; // for transcript

    sock.write_all(&client_hello)?;

    // Step 4: Read ServerHello
    let (ct_type, server_hello_payload, _sh_hdr) = read_tls_record(&mut sock)?;
    if ct_type != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected handshake, got 0x{ct_type:02x}"),
        ));
    }
    let (_server_random, server_key_share) = parse_server_hello(&server_hello_payload)?;

    // ServerHello raw bytes for transcript
    let mut server_hello_record = Vec::new();
    server_hello_record.push(0x16);
    server_hello_record.extend_from_slice(&[0x03, 0x03]);
    server_hello_record.extend_from_slice(&(server_hello_payload.len() as u16).to_be_bytes());
    server_hello_record.extend_from_slice(&server_hello_payload);

    // Step 5: ECDH + derive handshake keys
    let server_ks_pk = PublicKey::from(server_key_share);
    let tls_shared = client_sk.diffie_hellman(&server_ks_pk);

    let empty_hash = Sha256::digest([]);
    let early_secret = hkdf_extract(&[0u8; 32], &[0u8; 32]);

    // Handshake secret
    let derived = hkdf_expand_label(&early_secret, "derived", &empty_hash, 32);
    let handshake_secret = hkdf_extract(&derived, tls_shared.as_bytes());

    // Transcript hash for CH + SH
    let mut transcript = Vec::new();
    transcript.extend_from_slice(client_hello_body);
    transcript.extend_from_slice(&server_hello_payload);
    let transcript_hash = Sha256::digest(&transcript);

    let client_hs_ts = hkdf_expand_label(&handshake_secret, "c hs traffic", &transcript_hash, 32);
    let server_hs_ts = hkdf_expand_label(&handshake_secret, "s hs traffic", &transcript_hash, 32);

    let client_hs_key = hkdf_expand_label(&client_hs_ts, "key", b"", 16);
    let client_hs_iv_raw = hkdf_expand_label(&client_hs_ts, "iv", b"", 12);
    let server_hs_key = hkdf_expand_label(&server_hs_ts, "key", b"", 16);
    let server_hs_iv_raw = hkdf_expand_label(&server_hs_ts, "iv", b"", 12);

    let mut client_hs_iv = [0u8; 12];
    client_hs_iv.copy_from_slice(&client_hs_iv_raw);
    let mut server_hs_iv = [0u8; 12];
    server_hs_iv.copy_from_slice(&server_hs_iv_raw);

    let mut hs_decrypt = AeadState::new(&server_hs_key, &server_hs_iv);
    let mut hs_encrypt = AeadState::new(&client_hs_key, &client_hs_iv);

    // Step 6: Read encrypted handshake (EncryptedExtensions, Certificate, CertificateVerify, Finished)
    let mut cert_der = Vec::new();
    let mut got_finished = false;
    let mut handshake_data = Vec::new(); // track server's encrypted handshake msgs for transcript

    while !got_finished {
        let (ct, payload, hdr) = read_tls_record(&mut sock)?;
        match ct {
            0x14 => continue,
            0x17 => {
                let pt = hs_decrypt.decrypt(&payload, &hdr)?;
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
                    // Add full handshake message (type + length + body) to transcript
                    handshake_data.extend_from_slice(&pt[pos - 4..pos + msg_len]);
                    pos += msg_len;

                    if msg_type == 0x0b {
                        // Certificate
                        if msg.len() >= 4 {
                            let cert_req_ctx_len = msg[0] as usize;
                            let off = 1 + cert_req_ctx_len;
                            if msg.len() >= off + 3 {
                                let cert_len =
                                    u32::from_be_bytes([0, msg[off], msg[off + 1], msg[off + 2]])
                                        as usize;
                                if msg.len() >= off + 3 + cert_len {
                                    cert_der = msg[off + 3..off + 3 + cert_len].to_vec();
                                }
                            }
                        }
                    } else if msg_type == 0x14 {
                        got_finished = true;
                    }
                }
            }
            0x15 => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "server alert during handshake",
                ));
            }
            _ => {}
        }
    }

    // Extend transcript with server's encrypted handshake messages
    transcript.extend_from_slice(&handshake_data);

    // Step 7: Verify cert HMAC (skip if raw_pubkey is all zeros)
    if raw_pubkey != [0u8; 32] {
        verify_reality_cert(&auth_key, &raw_pubkey, &cert_der)?;
    }

    // Step 8: Send client Finished
    let finished_key = hkdf_expand_label(&client_hs_ts, "finished", b"", 32);

    // Transcript includes all handshake data through server's Finished
    let full_transcript_hash = Sha256::digest(&transcript);
    let mut hmac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&finished_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("hmac: {e}")))?;
    hmac.update(&full_transcript_hash);
    let verify_data = hmac.finalize().into_bytes();

    let mut finished_msg = vec![0x14u8];
    finished_msg.extend_from_slice(&(verify_data.len() as u32).to_be_bytes()[1..]);
    finished_msg.extend_from_slice(&verify_data);

    let finished_record = hs_encrypt.encrypt(&finished_msg, 0x17, 0x16)?;
    sock.write_all(&finished_record)?;

    // Step 9: Derive application traffic keys
    // Per RFC 8446 §7.1: transcript for app keys = all handshake msgs through server Finished
    // (NOT including client Finished)
    let app_transcript_hash = Sha256::digest(&transcript);
    let derived = hkdf_expand_label(&handshake_secret, "derived", &empty_hash, 32);
    let master_secret = hkdf_extract(&derived, &[0u8; 32]);

    let client_app_ts = hkdf_expand_label(&master_secret, "c ap traffic", &app_transcript_hash, 32);
    let server_app_ts = hkdf_expand_label(&master_secret, "s ap traffic", &app_transcript_hash, 32);

    let client_app_key = hkdf_expand_label(&client_app_ts, "key", b"", 16);
    let client_app_iv_raw = hkdf_expand_label(&client_app_ts, "iv", b"", 12);
    let server_app_key = hkdf_expand_label(&server_app_ts, "key", b"", 16);
    let server_app_iv_raw = hkdf_expand_label(&server_app_ts, "iv", b"", 12);

    let mut client_app_iv = [0u8; 12];
    client_app_iv.copy_from_slice(&client_app_iv_raw);
    let mut server_app_iv = [0u8; 12];
    server_app_iv.copy_from_slice(&server_app_iv_raw);

    let app_encrypt = AeadState::new(&client_app_key, &client_app_iv);
    let app_decrypt = AeadState::new(&server_app_key, &server_app_iv);

    let mut conn = RealityConnection {
        sock,
        encrypt: app_encrypt,
        decrypt: app_decrypt,
    };

    // Step 10: Send VLESS header
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    conn.write_all(&header)?;
    conn.flush()?;

    // Read VLESS response (handshake just completed, keep 10s timeout for this)
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp)?;

    // Use a short read timeout so WouldBlock retries don't stall data transfer
    conn.sock
        .set_read_timeout(Some(Duration::from_millis(50)))?;
    if resp[1] > 0 {
        let mut addons = vec![0u8; resp[1] as usize];
        conn.read_exact(&mut addons)?;
    }

    Ok(Box::new(conn))
}
