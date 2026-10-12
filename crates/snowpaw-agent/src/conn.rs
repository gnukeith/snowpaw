//! The one network connection a runtime makes: TLS 1.3 to the sync server, which must
//! present exactly the pinned certificate, then the agent WebSocket.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use snowpaw_proto::SecretString;
use snowpaw_proto::agent::AGENT_WS_PATH;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::config::Config;

pub type Ws = WebSocketStream<TlsStream<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct PinnedVerifier {
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

#[derive(Debug)]
pub enum ConnectError {
    /// The token was revoked or replaced (401). Don't retry with it.
    Unauthorized,
    /// The kill switch is on (503). Retry later.
    Paused,
    /// The server presented a certificate that isn't the pinned one.
    PinMismatch,
    Other(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("the server refused this agent's token"),
            Self::Paused => f.write_str("agents are paused on the server"),
            Self::PinMismatch => f.write_str("the server's certificate doesn't match the pin"),
            Self::Other(e) => f.write_str(e),
        }
    }
}

fn other(e: impl std::fmt::Display) -> ConnectError {
    ConnectError::Other(e.to_string())
}

pub async fn connect(cfg: &Config, token: &SecretString) -> Result<Ws, ConnectError> {
    let (host, port) = cfg.host_port();
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| other("connect timed out"))?
        .map_err(other)?;
    let _ = tcp.set_nodelay(true);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin: cfg.pin, provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.clone()).map_err(other)?,
    };
    let stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(Arc::new(tls)).connect(name, tcp),
    )
    .await
    {
        Err(_) => return Err(other("TLS handshake timed out")),
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let pin =
                e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some_and(|r| {
                    matches!(
                        r,
                        rustls::Error::InvalidCertificate(
                            CertificateError::ApplicationVerificationFailure
                        )
                    )
                });
            return Err(if pin { ConnectError::PinMismatch } else { other(e) });
        }
    };
    let mut req =
        format!("wss://{}{AGENT_WS_PATH}", cfg.server).into_client_request().map_err(other)?;
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", token.expose())).map_err(other)?;
    auth.set_sensitive(true);
    req.headers_mut().insert("Authorization", auth);
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::client_async_with_config(req, stream, Some(config)),
    )
    .await
    {
        Err(_) => Err(other("WebSocket upgrade timed out")),
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            match resp.status().as_u16() {
                401 => Err(ConnectError::Unauthorized),
                503 => Err(ConnectError::Paused),
                s => Err(other(format!("upgrade refused ({s})"))),
            }
        }
        Ok(Err(e)) => Err(other(e)),
    }
}
