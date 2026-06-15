//! Per-protocol microbenchmarks for hot encode/decode/auth paths.
//!
//! Complements `throughput.rs` (which covers VLESS + XTLS Vision) by
//! exercising the encode/decode primitives of VMess, Shadowsocks-2022,
//! AnyTLS, and WebSocket.
//!
//! Each bench drives the same workload (a typical 1460-byte MTU payload)
//! through the relevant function so cross-protocol comparison is meaningful.
//!
//! Trojan's `password_hash_hex` is in a private module and is not benched here
//! to keep the public API surface unchanged.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::io::Cursor;

// ── VMess: derive command key, encode/decode header ────────────────────────
fn bench_vmess_derive_cmd_key(c: &mut Criterion) {
    let uuid: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ];
    c.bench_function("vmess_derive_cmd_key", |b| {
        b.iter(|| {
            let k = wrongsv_server::vmess::derive_cmd_key(&uuid);
            black_box(k);
        });
    });
}

fn bench_vmess_build_header(c: &mut Criterion) {
    use wrongsv_server::vmess::{VmessRequest, build_header, derive_cmd_key};
    let uuid: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ];
    let cmd_key = derive_cmd_key(&uuid);
    let auth_id = [0x55u8; 16];
    let body_key = [0x33u8; 16];
    let body_iv = [0x44u8; 16];
    let request = VmessRequest::standard_tcp("example.com", 443);

    c.bench_function("vmess_build_header", |b| {
        b.iter(|| {
            let h = build_header(&cmd_key, &auth_id, &body_key, &body_iv, &request).unwrap();
            black_box(h);
        });
    });
}

// ── AnyTLS: constant-time hash compare ─────────────────────────────────────
fn bench_anytls_verify_password(c: &mut Criterion) {
    let a = [0xAAu8; 32];
    let b_arr = [0xAAu8; 32];
    c.bench_function("anytls_verify_password_hash", |bench| {
        bench.iter(|| {
            let ok = wrongsv_anytls::verify_password_hash(black_box(a), black_box(b_arr));
            black_box(ok);
        });
    });
}

// ── Shadowsocks-2022: parse request header (addr+port) ─────────────────────
fn bench_shadowsocks_parse_request_header(c: &mut Criterion) {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_shadowsocks::{parse_request_header, write_request_header};

    let mut buf = Vec::new();
    write_request_header(&mut buf, &Address::parse("example.com"), Port(443));
    c.bench_function("shadowsocks_parse_request_header", |b| {
        b.iter(|| {
            let p = parse_request_header(black_box(&buf)).unwrap();
            black_box(p);
        });
    });
}

fn bench_shadowsocks_aead_2022_udp_encrypt(c: &mut Criterion) {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_shadowsocks::{ServerConfig, encrypt_aead_2022_udp_request};
    let cfg = ServerConfig::new("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").unwrap();
    let payload = vec![0u8; 1460];
    let session_id = [0x99u8; 8];
    let packet_id = 1u64;
    let address = Address::parse("example.com");
    let port = Port(443);
    c.bench_function("shadowsocks_aead_2022_udp_encrypt_1460", |b| {
        b.iter(|| {
            let p = encrypt_aead_2022_udp_request(
                &cfg,
                session_id,
                packet_id,
                &address,
                port,
                black_box(&payload),
            )
            .unwrap();
            black_box(p);
        });
    });
}

// ── WebSocket: encode/decode a binary frame at MTU size ────────────────────
fn bench_websocket_write_frame(c: &mut Criterion) {
    use wrongsv_websocket::{Frame, Opcode, write_frame};
    let payload = vec![0xAAu8; 1460];
    let frame = Frame {
        fin: true,
        opcode: Opcode::Binary,
        payload,
    };
    c.bench_function("websocket_write_frame_1460_unmasked", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(1500);
            write_frame(&mut buf, &frame, false).unwrap();
            black_box(buf);
        });
    });
    c.bench_function("websocket_write_frame_1460_masked", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(1500);
            write_frame(&mut buf, &frame, true).unwrap();
            black_box(buf);
        });
    });
}

fn bench_websocket_read_frame(c: &mut Criterion) {
    use wrongsv_websocket::{Frame, Opcode, read_frame, write_frame};
    let payload = vec![0xAAu8; 1460];
    let frame = Frame {
        fin: true,
        opcode: Opcode::Binary,
        payload,
    };
    let mut buf = Vec::new();
    write_frame(&mut buf, &frame, true).unwrap();
    c.bench_function("websocket_read_frame_1460_masked", |b| {
        b.iter(|| {
            let mut cur = Cursor::new(&buf[..]);
            let f = read_frame(&mut cur, true).unwrap();
            black_box(f);
        });
    });
}

// ── WebSocket: roundtrip across various payload sizes ──────────────────────
fn bench_websocket_roundtrip_sizes(c: &mut Criterion) {
    use wrongsv_websocket::{Frame, Opcode, read_frame, write_frame};
    let sizes: &[(usize, &str)] = &[(64, "64B"), (1024, "1K"), (8192, "8K"), (65536, "64K")];
    for &(size, label) in sizes {
        let payload = vec![0xAAu8; size];
        let frame = Frame {
            fin: true,
            opcode: Opcode::Binary,
            payload: payload.clone(),
        };
        c.bench_function(&format!("websocket_roundtrip_masked_{label}"), |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(size + 64);
                write_frame(&mut buf, &frame, true).unwrap();
                let mut cur = Cursor::new(&buf[..]);
                let f = read_frame(&mut cur, true).unwrap();
                black_box(f);
            });
        });
    }
}

criterion_group!(
    benches,
    bench_vmess_derive_cmd_key,
    bench_vmess_build_header,
    bench_anytls_verify_password,
    bench_shadowsocks_parse_request_header,
    bench_shadowsocks_aead_2022_udp_encrypt,
    bench_websocket_write_frame,
    bench_websocket_read_frame,
    bench_websocket_roundtrip_sizes,
);
criterion_main!(benches);
