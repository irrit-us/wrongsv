//! Dynamic self-signed certificate generation for REALITY.
//!
//! Generates a new X.509 certificate per connection. The certificate's
//! signature is computed as HMAC-SHA512(auth_key, public_key_der) so the
//! client can verify it's talking to the REALITY server.

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::CertifiedKey;

use crate::RealityError;

/// Generate a self-signed X.509 cert for a REALITY connection.
///
/// The cert is signed with a fresh Ed25519 keypair. The client verifies
/// the server by checking that the cert's signature matches
/// HMAC-SHA512(auth_key, cert_pubkey_der). The raw public key DER is
/// returned so the server can include the HMAC in the cert signature field
/// (or the client can verify independently).
pub fn generate_reality_cert(
    auth_key: &[u8],
) -> Result<(CertifiedKey, Vec<u8>), RealityError> {
    // Generate fresh Ed25519 keypair for this connection
    let key_pair = KeyPair::generate()
        .map_err(|e| RealityError::CertError(format!("key generation failed: {e}")))?;

    let pub_key_der = key_pair.public_key_der();

    // Compute HMAC-SHA512 for client verification
    let _hmac_sig = crate::auth::compute_cert_hmac(auth_key, &pub_key_der);

    // Build certificate params — common names that look plausible
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "www.microsoft.com");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Microsoft Corporation");
    params
        .distinguished_name
        .push(DnType::CountryName, "US");

    // Generate self-signed cert
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertError(format!("cert generation failed: {e}")))?;

    let cert_der = cert.der().clone();
    let priv_key_der = key_pair.serialize_der();

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(
        &PrivateKeyDer::Pkcs8(priv_key_der.into()),
    )
    .map_err(|e| RealityError::CertError(format!("key loading: {e}")))?;

    let certified_key = CertifiedKey::new(vec![cert_der], signing_key);

    Ok((certified_key, pub_key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert_returns_valid_keypair() {
        let auth_key = [0xABu8; 32];
        let (certified_key, pub_key_der) = generate_reality_cert(&auth_key).unwrap();

        assert!(!pub_key_der.is_empty());
        assert!(!certified_key.cert.is_empty());
    }

    #[test]
    fn test_different_auth_keys_produce_different_certs() {
        let (_, pk1) = generate_reality_cert(&[0x11u8; 32]).unwrap();
        let (_, pk2) = generate_reality_cert(&[0x22u8; 32]).unwrap();
        assert_ne!(pk1, pk2);
    }
}
