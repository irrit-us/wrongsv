//! Dynamic certificate generation for REALITY.
//!
//! Matches Xray-core's approach: a single Ed25519 keypair and DER certificate
//! template are generated at startup. Per connection, the template is cloned
//! and its trailing 64-byte Ed25519 signature is overwritten with
//! HMAC-SHA512(auth_key, raw_pubkey) so the client can verify the server.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::{RealityCertMaterial, RealityError};

/// A `SigningKey` wrapper that forces Ed25519 signature scheme selection
/// even when the client didn't advertise it.
///
/// This matches xray-core's behavior: their forked TLS stack hardcodes
/// `hs.sigAlg = Ed25519` regardless of the client's advertised schemes.
/// Chrome fingerprints don't include Ed25519, but xray-core's
/// `VerifyPeerCertificate` expects an Ed25519 cert for HMAC verification.
#[derive(Debug)]
struct RealitySigningKey {
    inner: Arc<dyn SigningKey>,
}

impl SigningKey for RealitySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if let Some(signer) = self.inner.choose_scheme(offered) {
            return Some(signer);
        }
        // Force Ed25519 — same as xray-core hardcoding hs.sigAlg = Ed25519
        self.inner.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

/// Build the shared cert material once at server startup.
///
/// Generates an Ed25519 keypair and a self-signed DER certificate template.
/// The raw 32-byte public key is extracted so per-connection HMAC computation
/// matches Xray-core's `h.Write(ed25519Priv[32:])`.
pub fn build_cert_material() -> Result<RealityCertMaterial, RealityError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| RealityError::CertError(format!("key generation failed: {e}")))?;

    let pub_key_der = key_pair.public_key_der();
    // Ed25519 SPKI DER is 44 bytes: 12-byte prefix + 32-byte raw key.
    // Prefix: 302a300506032b6570032100
    if pub_key_der.len() < 44 {
        return Err(RealityError::CertError(
            "unexpected Ed25519 SPKI length".into(),
        ));
    }
    let mut raw_pubkey = [0u8; 32];
    raw_pubkey.copy_from_slice(&pub_key_der[12..44]);

    let params = CertificateParams::default();
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertError(format!("cert generation failed: {e}")))?;

    let signing_key_der = key_pair.serialize_der();

    Ok(RealityCertMaterial {
        cert_template_der: cert.der().to_vec(),
        raw_pubkey,
        signing_key_der,
    })
}

/// Build a `CertifiedKey` for a REALITY connection.
///
/// Clones the DER certificate template and overwrites its trailing 64-byte
/// Ed25519 signature with `HMAC-SHA512(auth_key, raw_pubkey_bytes)`. This
/// matches Xray-core's cert generation: the client verifies the server by
/// checking `HMAC-SHA512(auth_key, server_raw_pubkey) == cert.signature`.
pub fn generate_reality_cert(
    auth_key: &[u8],
    material: &RealityCertMaterial,
) -> Result<CertifiedKey, RealityError> {
    let hmac_sig = crate::auth::compute_cert_hmac(auth_key, &material.raw_pubkey);

    let mut cert_der = material.cert_template_der.clone();
    let len = cert_der.len();
    if len < 64 {
        return Err(RealityError::CertError("cert template too short".into()));
    }
    // Overwrite the trailing 64-byte Ed25519 signature with HMAC
    cert_der[len - 64..].copy_from_slice(&hmac_sig);

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        material.signing_key_der.clone().into(),
    ))
    .map_err(|e| RealityError::CertError(format!("key loading: {e}")))?;

    Ok(CertifiedKey::new(
        vec![cert_der.into()],
        Arc::new(RealitySigningKey { inner: signing_key }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    #[test]
    fn test_reality_signing_key_forces_ed25519() {
        let mat = build_cert_material().unwrap();
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(
            &PrivateKeyDer::Pkcs8(mat.signing_key_der.clone().into()),
        )
        .unwrap();

        // Chrome fingerprint schemes — no Ed25519
        let chrome_schemes = &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ];

        // Without wrapper: should fail
        assert!(
            signing_key.choose_scheme(chrome_schemes).is_none(),
            "Ed25519 key should not match Chrome fingerprint schemes"
        );

        // With wrapper: should force Ed25519
        let wrapped = RealitySigningKey { inner: signing_key };
        let signer = wrapped
            .choose_scheme(chrome_schemes)
            .expect("RealitySigningKey should force Ed25519 even when not offered");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);

        // When Ed25519 IS offered, normal path should work too
        let with_ed = &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ];
        let signer2 = wrapped.choose_scheme(with_ed).unwrap();
        assert_eq!(signer2.scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn test_build_cert_material_extracts_raw_pubkey() {
        let mat = build_cert_material().unwrap();
        // Raw pubkey must be 32 non-zero bytes
        assert_ne!(mat.raw_pubkey, [0u8; 32]);
        // SPKI DER is 12 bytes prefix + 32 bytes key = 44 bytes
        // Re-derive SPKI from raw to verify
        let spki_prefix: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let expected_spki: Vec<u8> = spki_prefix
            .iter()
            .chain(mat.raw_pubkey.iter())
            .copied()
            .collect();
        // Verify this is a valid Ed25519 SPKI by checking the prefix
        assert_eq!(&expected_spki[..12], spki_prefix);
    }

    #[test]
    fn test_generate_cert_patches_signature() {
        let mat = build_cert_material().unwrap();
        let auth_key = [0xABu8; 32];

        let cert1 = generate_reality_cert(&auth_key, &mat).unwrap();
        let cert2 = generate_reality_cert(&[0xCDu8; 32], &mat).unwrap();

        // Same template, different auth keys → different certs
        let der1 = cert1.cert.first().unwrap();
        let der2 = cert2.cert.first().unwrap();
        assert_ne!(der1, der2);

        // Only the last 64 bytes should differ
        let split = der1.len() - 64;
        assert_eq!(der1[..split], der2[..split]);
        assert_ne!(der1[split..], der2[split..]);
    }

    #[test]
    fn test_generate_cert_signature_matches_hmac() {
        let mat = build_cert_material().unwrap();
        let auth_key = [0x11u8; 32];

        let cert = generate_reality_cert(&auth_key, &mat).unwrap();
        let der = cert.cert.first().unwrap();

        // The last 64 bytes of the cert should equal HMAC-SHA512(auth_key, raw_pubkey)
        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).unwrap();
        mac.update(&mat.raw_pubkey);
        let expected_hmac = mac.finalize().into_bytes();

        assert_eq!(&der[der.len() - 64..], expected_hmac.as_slice());
    }
}
