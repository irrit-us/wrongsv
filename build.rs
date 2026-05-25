//! Compile-time random config generation.
//!
//! Generates a random UUID, listen port, X25519 keypair (for REALITY),
//! short ID, and Kyber keypair. Values are embedded via `env!("BUILD_*")`
//! so the server binary runs with zero arguments.

use base64::Engine;
use ml_kem::Kem;
use ml_kem::kem::KeyExport;
use rand::RngCore;

fn main() {
    let mut rng = rand::rngs::OsRng;

    // -- random UUID v4 --
    let mut uuid_bytes = [0u8; 16];
    rng.fill_bytes(&mut uuid_bytes);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; // version 4
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // variant 10
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid_bytes[0],
        uuid_bytes[1],
        uuid_bytes[2],
        uuid_bytes[3],
        uuid_bytes[4],
        uuid_bytes[5],
        uuid_bytes[6],
        uuid_bytes[7],
        uuid_bytes[8],
        uuid_bytes[9],
        uuid_bytes[10],
        uuid_bytes[11],
        uuid_bytes[12],
        uuid_bytes[13],
        uuid_bytes[14],
        uuid_bytes[15],
    );
    println!("cargo:rustc-env=BUILD_UUID={uuid}");
    println!("cargo:rustc-env=BUILD_UUID_SHORT={}", &uuid[..8]);

    // -- random listen port (10000-60000) --
    let mut port_buf = [0u8; 2];
    rng.fill_bytes(&mut port_buf);
    let port = 10000 + (u16::from_le_bytes(port_buf) % 50000);
    println!("cargo:rustc-env=BUILD_PORT={port}");

    // -- random short-id (8 hex chars = 4 bytes) --
    let mut sid = [0u8; 4];
    rng.fill_bytes(&mut sid);
    let short_id: String = sid.iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=BUILD_SHORT_ID={short_id}");

    // -- X25519 keypair (for REALITY) --
    let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rng);
    let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);
    let x25519_pk_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x25519_pk.as_bytes());
    let x25519_sk_hex: String = x25519_sk
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("cargo:rustc-env=BUILD_X25519_PK={x25519_pk_b64}");
    println!("cargo:rustc-env=BUILD_X25519_SK={x25519_sk_hex}");

    // -- Kyber keypair (ML-KEM-512) --
    let (dk, ek) = ml_kem::MlKem512::generate_keypair();
    let kyber_sk_seed = dk.to_seed().expect("key generated from seed");
    let kyber_sk_hex: String = kyber_sk_seed
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let kyber_pk_hex: String = ek
        .to_bytes()
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("cargo:rustc-env=BUILD_KYBER_SK_HEX={kyber_sk_hex}");
    println!("cargo:rustc-env=BUILD_KYBER_PK_HEX={kyber_pk_hex}");

    // Re-run only when build.rs itself changes
    println!("cargo:rerun-if-changed=build.rs");
}
