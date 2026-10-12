//! Talking to the server: login/logout over HTTPS and the WebSocket.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue, RETRY_AFTER};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use snowpaw_proto::http::{
    BLOBS_PATH, BlobUploaded, LOGIN_PATH, LOGOUT_PATH, LoginRequest, LoginResponse, PLUGINS_PATH,
    PluginInstalled, WS_PATH,
};
use snowpaw_proto::profile::{BlobHash, MAX_AVATAR_BYTES};
use snowpaw_proto::{SecretString, decode, encode};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use zeroize::Zeroizing;

use crate::config::ClientConfig as Settings;
use crate::tls::{self, ConnectError};

pub type Ws = WebSocketStream<TlsStream<TcpStream>>;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Server frames can carry a page of messages; bound what we'll buffer.
const MAX_WS_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum LoginError {
    WrongPassword,
    Locked { retry_after_secs: Option<u64> },
    Connect(ConnectError),
    Protocol(String),
    Server(u16),
}

impl LoginError {
    pub fn user_message(&self) -> String {
        match self {
            Self::WrongPassword => "Wrong password.".into(),
            Self::Locked { retry_after_secs: Some(s) } => {
                format!("Too many attempts. Try again in {}.", human_secs(*s))
            }
            Self::Locked { retry_after_secs: None } => {
                "The server is busy. Try again in a moment.".into()
            }
            Self::Connect(e) => e.user_message(),
            Self::Protocol(e) => format!("Unexpected response from the server ({e})."),
            Self::Server(code) => format!("The server returned an error ({code})."),
        }
    }
}

fn human_secs(s: u64) -> String {
    if s < 90 { format!("{s} seconds") } else { format!("{} minutes", s.div_ceil(60)) }
}

#[derive(Debug)]
pub struct LoginOk {
    pub token: SecretString,
    pub device_token: SecretString,
}

/// A request body that wipes itself when dropped (it may hold the password).
struct SecretBody(Option<Zeroizing<Vec<u8>>>);

impl Body for SecretBody {
    type Data = std::io::Cursor<Zeroizing<Vec<u8>>>;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|b| Ok(Frame::data(std::io::Cursor::new(b)))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
    }
}

async fn read_capped(mut body: Incoming, max: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Ok(data) = frame.into_data() {
            let data: Bytes = data;
            if out.len() + data.len() > max {
                return Err("response too large".into());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// A request body and its content type.
struct Payload {
    content_type: &'static str,
    bytes: Zeroizing<Vec<u8>>,
}

/// One HTTPS request on a fresh connection.
async fn request(
    settings: &Settings,
    method: Method,
    path: &str,
    token: Option<&SecretString>,
    body: Option<Payload>,
    max_response: usize,
) -> Result<(StatusCode, Option<u64>, Vec<u8>), LoginError> {
    let stream = tls::connect(settings).await.map_err(LoginError::Connect)?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, SecretBody>(TokioIo::new(stream))
            .await
            .map_err(|e| LoginError::Protocol(e.to_string()))?;
    let conn_task = tokio::spawn(conn);
    let mut builder =
        Request::builder().method(method).uri(path).header(HOST, settings.server.as_str());
    if let Some(b) = &body {
        builder = builder.header(CONTENT_TYPE, b.content_type);
    }
    if let Some(t) = token {
        let mut v = HeaderValue::from_str(&format!("Bearer {}", t.expose()))
            .map_err(|e| LoginError::Protocol(e.to_string()))?;
        v.set_sensitive(true);
        builder = builder.header(AUTHORIZATION, v);
    }
    let req = builder
        .body(SecretBody(body.map(|b| b.bytes)))
        .map_err(|e| LoginError::Protocol(e.to_string()))?;
    let result = async {
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| LoginError::Connect(ConnectError::Timeout))?
            .map_err(|e| LoginError::Protocol(e.to_string()))?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let bytes =
            tokio::time::timeout(REQUEST_TIMEOUT, read_capped(resp.into_body(), max_response))
                .await
                .map_err(|_| LoginError::Connect(ConnectError::Timeout))?
                .map_err(LoginError::Protocol)?;
        Ok((status, retry_after, bytes))
    }
    .await;
    conn_task.abort();
    result
}

pub async fn login(
    settings: &Settings,
    password: &SecretString,
    device_token: Option<&SecretString>,
) -> Result<LoginOk, LoginError> {
    let body = Zeroizing::new(
        encode(&LoginRequest { password: password.clone(), device_token: device_token.cloned() })
            .into_bytes(),
    );
    let body = Payload { content_type: "application/json", bytes: body };
    let (status, retry_after, bytes) =
        request(settings, Method::POST, LOGIN_PATH, None, Some(body), MAX_RESPONSE_BYTES).await?;
    match status {
        StatusCode::OK => {
            let resp: LoginResponse =
                decode(&bytes).map_err(|e| LoginError::Protocol(e.to_string()))?;
            let well_formed = resp.token.expose().starts_with(snowpaw_proto::SESSION_TOKEN_PREFIX)
                && resp.device_token.expose().starts_with(snowpaw_proto::DEVICE_TOKEN_PREFIX);
            if !well_formed {
                return Err(LoginError::Protocol("malformed token".into()));
            }
            Ok(LoginOk { token: resp.token, device_token: resp.device_token })
        }
        StatusCode::UNAUTHORIZED => Err(LoginError::WrongPassword),
        StatusCode::TOO_MANY_REQUESTS => Err(LoginError::Locked { retry_after_secs: retry_after }),
        other => Err(LoginError::Server(other.as_u16())),
    }
}

/// Revoke the session on the server. Best effort.
pub async fn logout(settings: &Settings, token: &SecretString) -> Result<(), LoginError> {
    let (status, _, _) =
        request(settings, Method::POST, LOGOUT_PATH, Some(token), None, MAX_RESPONSE_BYTES).await?;
    match status {
        StatusCode::NO_CONTENT | StatusCode::UNAUTHORIZED => Ok(()),
        other => Err(LoginError::Server(other.as_u16())),
    }
}

fn sha256(bytes: &[u8]) -> BlobHash {
    BlobHash::from_bytes(Sha256::digest(bytes).into())
}

/// Upload a profile picture (a normalized 256x256 PNG). The server names blobs by
/// SHA-256; the name it returns must be the one we computed.
pub async fn upload_blob(
    settings: &Settings,
    token: &SecretString,
    png: Vec<u8>,
) -> Result<BlobHash, String> {
    let expected = sha256(&png);
    let body = Payload { content_type: "image/png", bytes: Zeroizing::new(png) };
    let (status, _, bytes) =
        request(settings, Method::POST, BLOBS_PATH, Some(token), Some(body), MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| e.user_message())?;
    if status != StatusCode::OK {
        return Err(format!("The server refused the picture ({}).", status.as_u16()));
    }
    let resp: BlobUploaded = decode(&bytes).map_err(|e| e.to_string())?;
    if resp.hash != expected {
        return Err("The server stored the picture under the wrong name.".into());
    }
    Ok(resp.hash)
}

/// Install (or replace) a plugin. The server reads only its manifest; it runs only
/// in agent runtimes' sandboxes.
pub async fn upload_plugin(
    settings: &Settings,
    token: &SecretString,
    wasm: Vec<u8>,
) -> Result<snowpaw_proto::plugin::PluginView, String> {
    let expected = sha256(&wasm);
    let body = Payload { content_type: "application/wasm", bytes: Zeroizing::new(wasm) };
    let (status, _, bytes) =
        request(settings, Method::POST, PLUGINS_PATH, Some(token), Some(body), MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| e.user_message())?;
    match status {
        StatusCode::OK => {}
        StatusCode::BAD_REQUEST => return Err("The server says this isn't a valid plugin.".into()),
        StatusCode::PAYLOAD_TOO_LARGE => return Err("The plugin is too large.".into()),
        other => return Err(format!("The server refused the plugin ({}).", other.as_u16())),
    }
    let resp: PluginInstalled = decode(&bytes).map_err(|e| e.to_string())?;
    if resp.plugin.hash != expected {
        return Err("The server stored a different plugin than the one sent.".into());
    }
    Ok(resp.plugin)
}

/// Download a profile picture by hash. Whatever comes back must hash to what we
/// asked for, so neither the server nor anyone in between can swap pictures.
pub async fn fetch_blob(
    settings: &Settings,
    token: &SecretString,
    hash: BlobHash,
) -> Result<Vec<u8>, String> {
    let path = format!("{BLOBS_PATH}/{hash}");
    let (status, _, bytes) =
        request(settings, Method::GET, &path, Some(token), None, MAX_AVATAR_BYTES)
            .await
            .map_err(|e| e.user_message())?;
    if status != StatusCode::OK {
        return Err(format!("status {}", status.as_u16()));
    }
    if sha256(&bytes) != hash {
        return Err("the picture doesn't match its hash".into());
    }
    Ok(bytes)
}

/// Is a snowpaw server there, holding the key of the pinned certificate? A completed
/// TLS 1.3 handshake proves both (the pin is checked during it). Nothing else is
/// sent: no login, no request. Errors are user-facing.
pub async fn test_connection(settings: &Settings) -> Result<(), String> {
    match tls::connect(settings).await {
        Ok(mut stream) => {
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.shutdown()).await;
            Ok(())
        }
        Err(ConnectError::PinMismatch) => {
            Err("Something answered, but its certificate doesn't match your code.".into())
        }
        Err(ConnectError::Unreachable(_) | ConnectError::Timeout) => {
            Err(format!("Nothing answered at {}. Is the server running?", settings.server))
        }
        Err(ConnectError::Tls(_)) => Err(format!(
            "Something answered at {}, but it didn't start a secure snowpaw connection. \
             Check the address and port.",
            settings.server
        )),
    }
}

#[derive(Debug)]
pub enum WsConnectError {
    /// The session is no longer valid (401 on upgrade).
    Unauthorized,
    Connect(ConnectError),
    Other(String),
}

pub async fn connect_ws(settings: &Settings, token: &SecretString) -> Result<Ws, WsConnectError> {
    let stream = tls::connect(settings).await.map_err(WsConnectError::Connect)?;
    let mut req = format!("wss://{}{WS_PATH}", settings.server)
        .into_client_request()
        .map_err(|e| WsConnectError::Other(e.to_string()))?;
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
        .map_err(|e| WsConnectError::Other(e.to_string()))?;
    auth.set_sensitive(true);
    req.headers_mut().insert(AUTHORIZATION, auth);
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_FRAME_BYTES))
        .max_frame_size(Some(MAX_WS_FRAME_BYTES));
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio_tungstenite::client_async_with_config(req, stream, Some(config)),
    )
    .await
    {
        Err(_) => Err(WsConnectError::Connect(ConnectError::Timeout)),
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp)))
            if resp.status() == StatusCode::UNAUTHORIZED =>
        {
            Err(WsConnectError::Unauthorized)
        }
        Ok(Err(e)) => Err(WsConnectError::Other(e.to_string())),
    }
}
