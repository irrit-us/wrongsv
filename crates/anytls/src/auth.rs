//! SHA-256 password verification for AnyTLS.

/// Compare two SHA-256 password hashes in constant time.
pub fn verify_password_hash(received: [u8; 32], expected: [u8; 32]) -> bool {
    // Constant-time comparison to prevent timing side channels
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= received[i] ^ expected[i];
    }
    acc == 0
}
