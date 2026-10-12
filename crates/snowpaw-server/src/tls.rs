//! TLS: TLS 1.3 only, aws-lc-rs provider (hybrid post-quantum key exchange preferred),
//! and a self-signed certificate that clients pin by SHA-256 fingerprint.
//!
//! Why pinning instead of a CA: this is a self-hosted, single-user server, usually on
//! loopback or a VPN address with no public DNS name. Pinning gives non-experts real
//! TLS without running a CA, and a pinned client can't be fooled by any CA-issued cert.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::fsperm;

#[derive(Debug)]
pub struct TlsError(pub String);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsError {}

/// The single crypto provider used everywhere in the server.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// `sha256:` followed by 64 lowercase hex chars of the DER certificate's SHA-256.
pub fn fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Generate a self-signed ECDSA P-256 certificate and key. Writes both with mode 0600
/// and never overwrites existing files. Returns the certificate fingerprint.
pub fn generate(cert_path: &Path, key_path: &Path) -> Result<String, TlsError> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TlsError(format!("generating TLS key: {e}")))?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| TlsError(format!("certificate params: {e}")))?;
    params.subject_alt_names.push(rcgen::SanType::IpAddress([127, 0, 0, 1].into()));
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::Ipv6Addr::LOCALHOST.into()));
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "snowpaw sync server");
    // Clients pin the fingerprint, so validity dates aren't a security control here;
    // keep them sane anyway for tools that inspect the cert.
    let year = current_year();
    params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + 10, 1, 1);

    let cert =
        params.self_signed(&key).map_err(|e| TlsError(format!("self-signing certificate: {e}")))?;

    let key_pem = zeroize::Zeroizing::new(key.serialize_pem());
    fsperm::write_new_private_file(key_path, key_pem.as_bytes())
        .map_err(|e| TlsError(format!("writing {}: {e}", key_path.display())))?;
    fsperm::write_new_private_file(cert_path, cert.pem().as_bytes())
        .map_err(|e| TlsError(format!("writing {}: {e}", cert_path.display())))?;
    Ok(fingerprint(cert.der()))
}

/// Loaded TLS material, ready to serve.
#[derive(Debug)]
pub struct TlsMaterial {
    pub config: Arc<ServerConfig>,
    pub fingerprint: String,
}

/// Load the certificate chain and key. The key file must be private to `uid`.
pub fn load(cert_path: &Path, key_path: &Path, uid: u32) -> Result<TlsMaterial, TlsError> {
    fsperm::check_private_file(key_path, uid)
        .map_err(|e| TlsError(format!("TLS key {}: {e}", key_path.display())))?;
    let certs = CertificateDer::pem_file_iter(cert_path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| TlsError(format!("reading {}: {e}", cert_path.display())))?;
    let Some(leaf) = certs.first() else {
        return Err(TlsError(format!("{}: no certificate found", cert_path.display())));
    };
    let fingerprint = fingerprint(leaf);
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| TlsError(format!("reading {}: {e}", key_path.display())))?;
    let config = server_config(certs, key)?;
    Ok(TlsMaterial { config: Arc::new(config), fingerprint })
}

pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(format!("TLS config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError(format!("TLS certificate/key: {e}")))?;
    // No 0-RTT: early data is replayable.
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Gregorian year from the system clock (Howard Hinnant's civil-from-days).
fn current_year() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    i32::try_from(year).unwrap_or(2026)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_is_plausible() {
        let y = current_year();
        assert!((2025..2200).contains(&y), "{y}");
    }

    #[test]
    fn generate_then_load() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let (c, k) = (tmp.path().join("c.pem"), tmp.path().join("k.pem"));
        let fp = generate(&c, &k).expect("generate");
        assert!(fp.starts_with("sha256:") && fp.len() == 71);
        let loaded = load(&c, &k, uid).expect("load");
        assert_eq!(loaded.fingerprint, fp);
        assert!(generate(&c, &k).is_err(), "never overwrites an existing key");
    }

    #[test]
    fn refuses_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let (c, k) = (tmp.path().join("c.pem"), tmp.path().join("k.pem"));
        generate(&c, &k).expect("generate");
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(load(&c, &k, uid).is_err());
    }
}
