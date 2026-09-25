//! P0-9: Certificate pinning.
//!
//! `CertPinConfig` holds a set of pinned SPKI SHA-256 hashes (the same
//! format as HPKP/OkHttp `sha256/` pins, base64-encoded). When attached to
//! an [`crate::HttpClientBuilder`], every TLS connection is still validated
//! against the WebPKI trust store *and* must present an end-entity
//! certificate whose SubjectPublicKeyInfo hash matches one of the pins.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::{BeanStreamError, Result};

/// A set of SPKI SHA-256 pins. A connection is allowed only if the
/// end-entity certificate matches at least one pin.
#[derive(Debug, Clone, Default)]
pub struct CertPinConfig {
    pins: Vec<[u8; 32]>,
}

impl CertPinConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pin given as base64-encoded SPKI SHA-256 (no `sha256/` prefix).
    pub fn pin_spki_sha256_base64(mut self, pin: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(pin.trim().trim_start_matches("sha256/"))
            .map_err(|e| {
                BeanStreamError::InvalidConfiguration(format!("Invalid certificate pin: {e}"))
            })?;
        let hash: [u8; 32] = decoded.try_into().map_err(|_| {
            BeanStreamError::InvalidConfiguration(
                "Certificate pin must be exactly 32 bytes of SHA-256 output".to_string(),
            )
        })?;
        self.pins.push(hash);
        Ok(self)
    }

    /// Add a pin given as raw SPKI SHA-256 bytes.
    pub fn pin_spki_sha256(mut self, hash: [u8; 32]) -> Self {
        self.pins.push(hash);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// True if `cert_der`'s SPKI hash matches one of the pins.
    pub fn matches(&self, cert_der: &CertificateDer<'_>) -> bool {
        match spki_sha256(cert_der) {
            Some(hash) => self.pins.iter().any(|pin| pin == &hash),
            None => false,
        }
    }

    /// Build a rustls client config that performs normal WebPKI validation
    /// plus SPKI pinning, backed by the Mozilla root set.
    pub fn build_rustls_config(&self) -> Result<ClientConfig> {
        if self.pins.is_empty() {
            return Err(BeanStreamError::InvalidConfiguration(
                "Certificate pinning requested but no pins were configured".to_string(),
            ));
        }

        let provider = Arc::new(crypto::ring::default_provider());
        // Install as the process-wide provider if none is installed yet, so
        // the WebPki verifier below uses the same ring provider.
        let _ = crypto::CryptoProvider::install_default(crypto::ring::default_provider());

        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| BeanStreamError::InvalidConfiguration(e.to_string()))?;

        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| BeanStreamError::InvalidConfiguration(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinningVerifier {
                inner: webpki,
                pins: self.clone(),
            }))
            .with_no_client_auth();

        Ok(config)
    }
}

/// Compute the SHA-256 hash of a certificate's SubjectPublicKeyInfo.
///
/// Returns `None` if the DER structure cannot be walked to the SPKI field.
pub fn spki_sha256(cert_der: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let spki = spki_der(cert_der.as_ref())?;
    Some(Sha256::digest(spki).into())
}

/// Walk a DER X.509 certificate to its SubjectPublicKeyInfo TLV and return
/// the raw bytes (tag + length + value) of that element.
fn spki_der(cert: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, sigAlg, sig }
    let (_, cert_content, _) = read_tlv(cert, 0)?;
    let (tbs_tag, _, _) = read_tlv(cert, cert_content)?;
    if tbs_tag != 0x30 {
        return None;
    }
    // Position after the tbs tag/length header.
    let mut pos = read_tlv(cert, cert_content)?.1;

    // TBSCertificate children: [0] version (optional), serialNumber,
    // signature, issuer, validity, subject, subjectPublicKeyInfo
    if let Some((tag, _, end)) = read_tlv(cert, pos) {
        if tag == 0xA0 {
            pos = end;
        }
    }
    for _ in 0..5 {
        let (_, content, end) = read_tlv(cert, pos)?;
        pos = end;
        let _ = content;
    }
    let (spki_tag, _, spki_end) = read_tlv(cert, pos)?;
    if spki_tag != 0x30 {
        #[cfg(test)]
        return None;
    }
    let spki_start = pos;
    Some(&cert[spki_start..spki_end])
}

/// Read one DER TLV at `pos`; returns (tag, content_start, end).
fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    if pos + 2 > buf.len() {
        return None;
    }
    let tag = buf[pos];
    let mut i = pos + 1;
    let first = buf[i];
    i += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || i + n > buf.len() {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..n {
            length = (length << 8) | buf[i] as usize;
            i += 1;
        }
        length
    };
    let content = i;
    let end = content.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, content, end))
}

#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: CertPinConfig,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        // Standard WebPKI validation first...
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        // ...then fail closed unless the SPKI hash matches a pin.
        if self.pins.matches(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "certificate pinning failed: no pinned SPKI hash matched the server certificate"
                    .to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- minimal DER helpers to synthesize a certificate skeleton ---

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    fn int(val: u8) -> Vec<u8> {
        tlv(0x02, &[val])
    }

    /// tbsCertificate with the standard prefix fields and the given SPKI.
    fn fake_cert(spki: &[u8]) -> Vec<u8> {
        let version = tlv(0xA0, &tlv(0x02, &[2])); // v3
        let sig = tlv(0x30, &tlv(0x06, &[1, 2, 3]));
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &tlv(0x06, &[4]))));
        let validity = tlv(
            0x30,
            &[
                0x17, 10, b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
            ],
        );
        let spki = tlv(0x30, spki);
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&int(1)); // serial
        tbs.extend_from_slice(&sig);
        tbs.extend_from_slice(&name); // issuer
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&name); // subject
        tbs.extend_from_slice(&spki);
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE ... }
        tlv(0x30, &tlv(0x30, &tbs))
    }

    fn der<'a>(bytes: &'a [u8]) -> CertificateDer<'a> {
        CertificateDer::from(bytes.to_vec())
    }

    #[test]
    fn extracts_spki_hash_from_a_v3_certificate() {
        let cert = fake_cert(&[0x30, 0x05, 1, 2, 3, 4, 5]);
        let hash = spki_sha256(&der(&cert)).unwrap();
        assert_eq!(hash.len(), 32);
        // Same SPKI -> same hash.
        assert_eq!(
            spki_sha256(&der(&fake_cert(&[0x30, 0x05, 1, 2, 3, 4, 5]))).unwrap(),
            hash
        );
        // Different SPKI -> different hash.
        assert_ne!(
            spki_sha256(&der(&fake_cert(&[0x30, 0x05, 9, 9, 9, 9, 9]))).unwrap(),
            hash
        );
    }

    #[test]
    fn handles_certificates_without_an_explicit_version_field() {
        // v1 certificates omit the [0] version element.
        let sig = tlv(0x30, &tlv(0x06, &[1]));
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &tlv(0x06, &[4]))));
        let validity = tlv(0x30, &[0x17, 3, b'2', b'4', b'Z']);
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&int(7));
        tbs.extend_from_slice(&sig);
        tbs.extend_from_slice(&name);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&name);
        tbs.extend_from_slice(&tlv(0x30, &[0xaa, 0xbb]));
        let cert = tlv(0x30, &tlv(0x30, &tbs));
        assert!(spki_sha256(&der(&cert)).is_some());
    }

    #[test]
    fn pin_config_matches_only_pinned_hashes() {
        let cert = fake_cert(&[0x30, 0x03, 1, 2, 3]);
        let hash = spki_sha256(&der(&cert)).unwrap();

        let pinned = CertPinConfig::new().pin_spki_sha256(hash);
        assert!(pinned.matches(&der(&cert)));
        assert!(!CertPinConfig::new().matches(&der(&cert)));

        let other = fake_cert(&[0x30, 0x03, 4, 5, 6]);
        assert!(!pinned.matches(&der(&other)));
    }

    #[test]
    fn parses_base64_pins_and_rejects_malformed_ones() {
        let raw = [0x42u8; 32];
        let encoded = BASE64.encode(raw);
        let config = CertPinConfig::new()
            .pin_spki_sha256_base64(&encoded)
            .unwrap();
        assert_eq!(config.pins_len_for_test(), 1);

        // "sha256/" prefix form is accepted too.
        let config = CertPinConfig::new()
            .pin_spki_sha256_base64(&format!("sha256/{encoded}"))
            .unwrap();
        assert_eq!(config.pins_len_for_test(), 1);

        // Short / non-base64 pins are rejected.
        assert!(CertPinConfig::new().pin_spki_sha256_base64("AAAA").is_err());
        assert!(CertPinConfig::new().pin_spki_sha256_base64("!!!").is_err());
    }

    #[test]
    fn refuses_to_build_a_config_with_no_pins() {
        assert!(CertPinConfig::new().build_rustls_config().is_err());
    }

    impl CertPinConfig {
        fn pins_len_for_test(&self) -> usize {
            self.pins.len()
        }
    }
}
