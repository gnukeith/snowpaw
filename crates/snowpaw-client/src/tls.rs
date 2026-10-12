//! TLS to the sync server: TLS 1.3 only, and the server must present exactly the
//! certificate whose SHA-256 fingerprint the user pinned. Certificate authorities are
//! never consulted, so no CA-issued certificate can be used to impersonate the server.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config::ClientConfig as Settings;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config(pin: [u8; 32]) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[derive(Debug)]
pub enum ConnectError {
    /// The server's certificate isn't the pinned one. Possibly an attack.
    PinMismatch,
    Unreachable(String),
    Tls(String),
    Timeout,
}

impl ConnectError {
    pub fn user_message(&self) -> String {
        match self {
            Self::PinMismatch => {
                "The server's certificate doesn't match the fingerprint you saved. \
                 Someone may be intercepting the connection. If you re-initialized the server, \
                 update the fingerprint in Server settings."
                    .into()
            }
            Self::Unreachable(e) => format!("Can't reach the server ({e})."),
            Self::Tls(e) => format!("Secure connection failed ({e})."),
            Self::Timeout => "The server didn't respond in time.".into(),
        }
    }
}

pub async fn connect(settings: &Settings) -> Result<TlsStream<TcpStream>, ConnectError> {
    let (host, port) = settings.host_port();
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| ConnectError::Timeout)?
        .map_err(|e| ConnectError::Unreachable(e.kind().to_string()))?;
    let _ = tcp.set_nodelay(true);
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host).map_err(|e| ConnectError::Tls(e.to_string()))?,
    };
    let config = client_config(settings.pin()).map_err(|e| ConnectError::Tls(e.to_string()))?;
    let connector = TlsConnector::from(config);
    match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await {
        Err(_) => Err(ConnectError::Timeout),
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            let pin_failure = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|r| {
                    matches!(
                        r,
                        rustls::Error::InvalidCertificate(
                            CertificateError::ApplicationVerificationFailure
                        )
                    )
                });
            if pin_failure {
                Err(ConnectError::PinMismatch)
            } else {
                Err(ConnectError::Tls(e.to_string()))
            }
        }
    }
}
