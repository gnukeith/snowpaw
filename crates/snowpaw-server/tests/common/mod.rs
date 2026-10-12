//! Test harness: a real server on 127.0.0.1:<random>, a pinned TLS client, raw HTTP.
#![allow(dead_code, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use snowpaw_proto::SecretString;
use snowpaw_server::clock::ManualClock;
use snowpaw_server::config::Config;
use snowpaw_server::server::Server;
use snowpaw_server::setup;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub const PASSWORD: &str = "correct horse battery staple";
pub const START_MS: i64 = 1_800_000_000_000;

pub type Ws = WebSocketStream<TlsStream<TcpStream>>;

/// Accept exactly one certificate (by DER bytes), but still verify handshake signatures.
#[derive(Debug)]
pub struct Pinned {
    pub cert: CertificateDer<'static>,
    pub provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate does not match pin".into()))
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

pub fn client_config(
    cert: CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { cert, provider }))
        .with_no_client_auth()
}

#[derive(Debug)]
pub struct RawResponse {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }

    pub fn error_code(&self) -> Option<String> {
        let v: serde_json::Value = serde_json::from_slice(&self.body).ok()?;
        v.get("error")?.as_str().map(str::to_owned)
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

pub fn parse_response(raw: &[u8]) -> Option<RawResponse> {
    // Split on bytes: bodies may be binary (e.g. pictures).
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let status = head.split(' ').nth(1)?.parse().ok()?;
    Some(RawResponse { status, head: head.to_owned(), body: raw[split + 4..].to_vec() })
}

pub struct TestServer {
    pub addr: SocketAddr,
    /// The agents-only listener, when `server.agent_listen` is set.
    pub agent_addr: Option<SocketAddr>,
    pub fingerprint: String,
    pub cert: CertificateDer<'static>,
    pub clock: Arc<ManualClock>,
    pub data_dir: PathBuf,
    pub extra_config: String,
    tmp: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl TestServer {
    pub async fn start() -> Self {
        Self::start_with("").await
    }

    /// `extra` is appended to the config (e.g. "[auth]\nmax_sessions = 2\n").
    pub async fn start_with(extra: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(START_MS));
        let data_dir = tmp.path().join("data");
        setup::init(&data_dir, clock.as_ref()).unwrap();
        let cfg = Self::config(&data_dir, extra);
        setup::set_password(&cfg, &SecretString::new(PASSWORD.into()), clock.as_ref()).unwrap();
        Self::boot(tmp, data_dir, extra.to_owned(), clock).await
    }

    pub fn config(data_dir: &std::path::Path, extra: &str) -> Config {
        Config::parse(&format!(
            "[server]\nlisten = \"127.0.0.1:0\"\ndata_dir = \"{}\"\n{extra}",
            data_dir.display()
        ))
        .unwrap()
    }

    async fn boot(
        tmp: tempfile::TempDir,
        data_dir: PathBuf,
        extra: String,
        clock: Arc<ManualClock>,
    ) -> Self {
        let cfg = Self::config(&data_dir, &extra);
        let (cert_path, _) = cfg.tls_paths();
        let server = Server::bind(cfg, clock.clone()).await.unwrap();
        let addr = server.local_addr().unwrap();
        let agent_addr = server.local_agent_addr().map(|a| a.unwrap());
        let fingerprint = server.fingerprint().to_owned();
        let cert = CertificateDer::from_pem_file(cert_path).unwrap();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.run(async {
            let _ = rx.await;
        }));
        Self {
            addr,
            agent_addr,
            fingerprint,
            cert,
            clock,
            data_dir,
            extra_config: extra,
            tmp,
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    /// Stop and start again on the same data dir (new port).
    pub async fn restart(mut self) -> Self {
        self.stop().await;
        let tmp = std::mem::replace(&mut self.tmp, tempfile::tempdir().unwrap());
        Self::boot(tmp, self.data_dir.clone(), self.extra_config.clone(), Arc::clone(&self.clock))
            .await
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("snowpaw.db")
    }

    pub async fn tls_with(&self, config: ClientConfig) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(self.addr).await?;
        let connector = TlsConnector::from(Arc::new(config));
        connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await
    }

    pub async fn tls(&self) -> TlsStream<TcpStream> {
        self.tls_with(client_config(self.cert.clone(), &[&rustls::version::TLS13])).await.unwrap()
    }

    /// Send raw bytes over TLS and read until the server closes.
    pub async fn raw(&self, request: &[u8]) -> Option<RawResponse> {
        let mut s = self.tls().await;
        s.write_all(request).await.ok()?;
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            let mut chunk = [0u8; 4096];
            loop {
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
        })
        .await;
        parse_response(&buf)
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> RawResponse {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        self.raw(req.as_bytes()).await.expect("an HTTP response")
    }

    pub async fn login_with(&self, password: &str, extra_headers: &[(&str, &str)]) -> RawResponse {
        self.login_full(password, None, extra_headers).await
    }

    pub async fn login_full(
        &self,
        password: &str,
        device_token: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> RawResponse {
        let mut body = serde_json::json!({ "password": password });
        if let Some(d) = device_token {
            body["device_token"] = d.into();
        }
        let mut headers = vec![("Content-Type", "application/json")];
        headers.extend_from_slice(extra_headers);
        self.request("POST", "/v1/login", &headers, &body.to_string()).await
    }

    pub async fn login(&self, password: &str) -> RawResponse {
        self.login_with(password, &[]).await
    }

    /// Log in with an optional device token; returns the response.
    pub async fn login_device(&self, password: &str, device_token: Option<&str>) -> RawResponse {
        self.login_full(password, device_token, &[]).await
    }

    /// Log in with the right password and return the token.
    pub async fn token(&self) -> String {
        let r = self.login(PASSWORD).await;
        assert_eq!(r.status, 200, "login failed: {r:?}");
        r.json()["token"].as_str().unwrap().to_owned()
    }

    pub async fn authed(&self, method: &str, path: &str, token: &str) -> RawResponse {
        let auth = format!("Bearer {token}");
        self.request(method, path, &[("Authorization", &auth)], "").await
    }

    pub async fn ws_with(
        &self,
        headers: &[(&str, &str)],
    ) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
        let stream = self.tls().await;
        let mut req =
            format!("wss://localhost:{}/v1/ws", self.addr.port()).into_client_request()?;
        for (k, v) in headers {
            req.headers_mut().append(http_name(k), v.parse().unwrap());
        }
        tokio_tungstenite::client_async(req, stream).await.map(|(ws, _)| ws)
    }

    pub async fn ws(&self, token: &str) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
        let auth = format!("Bearer {token}");
        self.ws_with(&[("Authorization", &auth)]).await
    }

    /// An agent runtime's socket (`/v1/agent/ws`), on the agents-only listener if
    /// there is one.
    #[allow(dead_code)]
    pub async fn agent_ws(&self, token: &str) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
        let stream = match self.agent_addr {
            Some(addr) => {
                let config = client_config(self.cert.clone(), &[&rustls::version::TLS13]);
                let tcp = TcpStream::connect(addr).await.unwrap();
                TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await
                    .unwrap()
            }
            None => self.tls().await,
        };
        let mut req =
            format!("wss://localhost:{}/v1/agent/ws", self.addr.port()).into_client_request()?;
        req.headers_mut()
            .append(http_name("Authorization"), format!("Bearer {token}").parse().unwrap());
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(16 << 20))
            .max_frame_size(Some(16 << 20));
        tokio_tungstenite::client_async_with_config(req, stream, Some(config))
            .await
            .map(|(ws, _)| ws)
    }
}

fn http_name(k: &str) -> tokio_tungstenite::tungstenite::http::HeaderName {
    tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(k.as_bytes()).unwrap()
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// HTTP status of a rejected WebSocket upgrade.
pub fn upgrade_status(e: &tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    match e {
        tokio_tungstenite::tungstenite::Error::Http(resp) => Some(resp.status().as_u16()),
        _ => None,
    }
}
