//! Calling agents' models (OpenAI-compatible `chat/completions`) on their behalf.
//!
//! The server, not the agent runtime, makes this call, so:
//! - the API key never leaves the server (it's unsealed only for the request);
//! - token budgets, rate limits, timeouts and the kill switch are enforced here,
//!   where a compromised runtime can't skip them;
//! - the agent's container needs no network access except to this server.
//!
//! The endpoint is set by the user, never by an agent or a model. Still: TLS 1.3 only
//! (CA roots compiled in, or a pinned certificate), plain HTTP only to this machine
//! (checked again after DNS resolution), redirects are never followed, and the
//! response is size- and time-limited and parsed as untrusted data.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snowpaw_proto::Id;
use snowpaw_proto::agent::{
    AgentMsg, Endpoint, InferFailure, MAX_TOOL_CALLS, MAX_TOOL_JSON_BYTES, Reply, ToolCall,
    ToolSpec, Turn, Usage, parse_endpoint, parse_pin,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::api::AppState;
use crate::db;
use crate::secrets::Purpose;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest reply text kept from a model.
const MAX_REPLY_TEXT_BYTES: usize = 256 * 1024;

/// Run one inference for `agent`. Every limit is checked before the call.
pub async fn infer(
    st: &AppState,
    agent: Id,
    turns: Vec<Turn>,
    tools: Vec<ToolSpec>,
) -> Result<(Reply, Usage), InferFailure> {
    if !AgentMsg::validate_infer(&turns, &tools) {
        return Err(InferFailure::InvalidRequest);
    }
    let prompt_bytes: usize = turns.iter().map(turn_len).sum();
    // A cautious guess (about 3 bytes per token) until the model reports real numbers.
    let prompt_estimate = (prompt_bytes / 3) as u64 + 16;
    let now = st.clock.now_ms();
    let per_minute = i64::from(st.cfg.agents.inference_per_minute);
    let checked = st
        .db
        .call(move |c| {
            if db::agents_paused(c)? {
                return Ok(Err(InferFailure::Paused));
            }
            let Some(model) = db::agent_model(c, agent)? else {
                return Ok(Err(InferFailure::NotConfigured));
            };
            if model.settings.daily_token_limit == 0 {
                return Ok(Err(InferFailure::NotConfigured));
            }
            if db::usage_calls_since(c, agent, now - 60_000)? >= per_minute {
                return Ok(Err(InferFailure::RateLimited));
            }
            let used = db::usage_since(c, agent, now - 86_400_000)?;
            let reserve = prompt_estimate + u64::from(model.settings.max_reply_tokens);
            if used.saturating_add(reserve) > model.settings.daily_token_limit {
                return Ok(Err(InferFailure::BudgetExhausted));
            }
            // Reserve the worst case now, so the call counts against the rate limit
            // and budget while it runs; settled with real numbers afterwards.
            let row =
                db::reserve_usage(c, agent, now, prompt_estimate, model.settings.max_reply_tokens)?;
            Ok(Ok((model, row)))
        })
        .await
        .map_err(|_| InferFailure::Upstream)?;
    let (model, usage_row) = match checked {
        Ok(v) => v,
        Err(refusal) => {
            if matches!(refusal, InferFailure::BudgetExhausted | InferFailure::RateLimited) {
                st.audit_throttled(agent, "agent_model_refused", format!("{refusal:?}")).await;
            }
            return Err(refusal);
        }
    };

    let result = call(st, agent, &model, &turns, &tools).await;
    let usage = match &result {
        Ok((_, Some(u))) => *u,
        // No usage reported: charge the estimate for the prompt and the text we got.
        Ok((reply, None)) => Usage {
            prompt_tokens: prompt_estimate,
            completion_tokens: (reply.text.len() / 3) as u64 + 1,
        },
        // A failed call still charges the prompt estimate: the bytes were sent, and
        // a dead or hostile endpoint must not host free retries that dodge the
        // daily budget.
        Err(_) => Usage { prompt_tokens: prompt_estimate, completion_tokens: 0 },
    };
    let (p, cpl) = (usage.prompt_tokens, usage.completion_tokens);
    if let Err(e) = st.db.call(move |c| db::settle_usage(c, usage_row, p, cpl)).await {
        warn!(error = %e, "recording model usage failed");
    }
    result.map(|(reply, _)| (reply, usage))
}

fn turn_len(t: &Turn) -> usize {
    match t {
        Turn::System { content } | Turn::User { content } | Turn::Tool { content, .. } => {
            content.len()
        }
        Turn::Assistant { content, tool_calls } => {
            content.len() + tool_calls.iter().map(|c| c.arguments.len()).sum::<usize>()
        }
    }
}

async fn call(
    st: &AppState,
    agent: Id,
    model: &db::ModelRow,
    turns: &[Turn],
    tools: &[ToolSpec],
) -> Result<(Reply, Option<Usage>), InferFailure> {
    let endpoint =
        parse_endpoint(&model.settings.base_url).map_err(|_| InferFailure::NotConfigured)?;
    let pin = match &model.settings.tls_pin {
        Some(p) => Some(parse_pin(p).map_err(|_| InferFailure::NotConfigured)?),
        None => None,
    };
    let key = match &model.sealed_api_key {
        Some(sealed) => Some(
            st.secrets
                .open(Purpose::ModelApiKey, agent, sealed)
                .map_err(|_| InferFailure::NotConfigured)?,
        ),
        None => None,
    };
    let body = request_body(&model.settings.model, model.settings.max_reply_tokens, turns, tools);
    let timeout = Duration::from_secs(st.cfg.agents.inference_timeout_secs);
    let max = st.cfg.agents.max_inference_response_bytes;
    let path = format!("{}/chat/completions", endpoint.path);
    let started = std::time::Instant::now();
    let response = tokio::time::timeout(
        timeout,
        post_json(&endpoint, pin, &path, key.as_ref().map(|k| k.as_slice()), body, max),
    )
    .await
    .map_err(|_| InferFailure::Timeout)?;
    drop(key);
    let (status, bytes) = response.map_err(|e| {
        warn!(%agent, host = %endpoint.host, error = %e, "model call failed");
        InferFailure::Upstream
    })?;
    if status != StatusCode::OK {
        // The body may echo the prompt: log the status only.
        warn!(%agent, host = %endpoint.host, status = status.as_u16(), "model server refused");
        return Err(InferFailure::Upstream);
    }
    let parsed = parse_response(&bytes, tools).ok_or_else(|| {
        warn!(%agent, host = %endpoint.host, "model server sent an unusable response");
        InferFailure::Upstream
    })?;
    info!(%agent, ms = started.elapsed().as_millis() as u64, "model call done");
    Ok(parsed)
}

fn request_body(model: &str, max_tokens: u32, turns: &[Turn], tools: &[ToolSpec]) -> Vec<u8> {
    let messages: Vec<Value> = turns
        .iter()
        .map(|t| match t {
            Turn::System { content } => json!({ "role": "system", "content": content }),
            Turn::User { content } => json!({ "role": "user", "content": content }),
            Turn::Assistant { content, tool_calls } if tool_calls.is_empty() => {
                json!({ "role": "assistant", "content": content })
            }
            Turn::Assistant { content, tool_calls } => json!({
                "role": "assistant",
                "content": if content.is_empty() { Value::Null } else { Value::from(content.as_str()) },
                "tool_calls": tool_calls.iter().map(|c| json!({
                    "id": c.id,
                    "type": "function",
                    "function": { "name": c.name, "arguments": c.arguments },
                })).collect::<Vec<_>>(),
            }),
            Turn::Tool { tool_call_id, content } => {
                json!({ "role": "tool", "tool_call_id": tool_call_id, "content": content })
            }
        })
        .collect();
    let mut body = json!({
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": false,
    });
    if !tools.is_empty() {
        let tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                // Validated as a JSON object before we get here.
                let params: Value =
                    serde_json::from_str(&t.parameters).unwrap_or_else(|_| json!({}));
                json!({
                    "type": "function",
                    "function": { "name": t.name, "description": t.description, "parameters": params },
                })
            })
            .collect();
        body["tools"] = Value::from(tools);
    }
    serde_json::to_vec(&body).unwrap_or_default()
}

// The model server's response: read leniently (many extra fields), trusted for nothing.
#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<RespUsage>,
}

#[derive(Deserialize)]
struct Choice {
    message: RespMessage,
}

#[derive(Deserialize)]
struct RespMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<RespToolCall>>,
}

#[derive(Deserialize)]
struct RespToolCall {
    id: String,
    function: RespFunction,
}

#[derive(Deserialize)]
struct RespFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct RespUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

/// Keep the first `max` bytes of `s`, on a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_response(bytes: &[u8], offered: &[ToolSpec]) -> Option<(Reply, Option<Usage>)> {
    let resp: ChatResponse = serde_json::from_slice(bytes).ok()?;
    let msg = resp.choices.into_iter().next()?.message;
    let text = cut(&msg.content.unwrap_or_default(), MAX_REPLY_TEXT_BYTES).replace('\0', "");
    // Only well-formed calls to tools we actually offered survive.
    let tool_calls: Vec<ToolCall> = msg
        .tool_calls
        .unwrap_or_default()
        .into_iter()
        .filter(|c| {
            (1..=128).contains(&c.id.len())
                && offered.iter().any(|t| t.name == c.function.name)
                && c.function.arguments.len() <= MAX_TOOL_JSON_BYTES
                && serde_json::from_str::<serde_json::Map<String, Value>>(&c.function.arguments)
                    .is_ok()
        })
        .take(MAX_TOOL_CALLS)
        .map(|c| ToolCall { id: c.id, name: c.function.name, arguments: c.function.arguments })
        .collect();
    let usage = resp.usage.map(|u| Usage {
        prompt_tokens: u.prompt_tokens.min(100_000_000),
        completion_tokens: u.completion_tokens.min(100_000_000),
    });
    Some((Reply { text, tool_calls }, usage))
}

// ---- HTTP ----

#[derive(Debug)]
struct CallError(String);

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(e: impl std::fmt::Display) -> CallError {
    CallError(e.to_string())
}

/// A request body that wipes itself (it may carry conversation text).
struct OnceBody(Option<Zeroizing<Vec<u8>>>);

impl Body for OnceBody {
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

/// TLS 1.3 only. Public CA roots (Mozilla's, compiled in), or exactly one pinned
/// certificate.
fn tls_config(pin: Option<[u8; 32]>) -> Result<Arc<ClientConfig>, CallError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(err)?;
    let mut config = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, provider }))
            .with_no_client_auth(),
        None => {
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Resolve and connect. Plain-HTTP endpoints must resolve to loopback addresses only
/// (a name like `localhost` is checked after resolution, not trusted).
async fn connect_tcp(ep: &Endpoint) -> Result<TcpStream, CallError> {
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((ep.host.as_str(), ep.port)))
            .await
            .map_err(|_| err("DNS lookup timed out"))?
            .map_err(err)?
            .collect();
    if addrs.is_empty() {
        return Err(err("no addresses"));
    }
    if !ep.tls && !addrs.iter().all(|a| a.ip().to_canonical().is_loopback()) {
        return Err(err("plain http endpoint resolved to a non-loopback address"));
    }
    let mut last = err("unreachable");
    for addr in addrs.into_iter().take(4) {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = err(e),
            Err(_) => last = err("connect timed out"),
        }
    }
    Err(last)
}

async fn post_json(
    ep: &Endpoint,
    pin: Option<[u8; 32]>,
    path: &str,
    bearer: Option<&[u8]>,
    body: Vec<u8>,
    max_response: usize,
) -> Result<(StatusCode, Vec<u8>), CallError> {
    let tcp = connect_tcp(ep).await?;
    if ep.tls {
        let name = match ep.host.parse::<std::net::IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(ep.host.clone()).map_err(err)?,
        };
        let tls = TlsConnector::from(tls_config(pin)?).connect(name, tcp).await.map_err(err)?;
        exchange(tls, ep, path, bearer, body, max_response).await
    } else {
        exchange(tcp, ep, path, bearer, body, max_response).await
    }
}

async fn exchange<S>(
    stream: S,
    ep: &Endpoint,
    path: &str,
    bearer: Option<&[u8]>,
    body: Vec<u8>,
    max_response: usize,
) -> Result<(StatusCode, Vec<u8>), CallError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, OnceBody>(TokioIo::new(stream))
            .await
            .map_err(err)?;
    let conn_task = tokio::spawn(conn);
    let result = async {
        let path = if path.is_empty() { "/" } else { path };
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HOST, ep.authority())
            .header(CONTENT_TYPE, "application/json");
        if let Some(key) = bearer {
            let mut v = Zeroizing::new(b"Bearer ".to_vec());
            v.extend_from_slice(key);
            let mut value = HeaderValue::from_bytes(&v).map_err(err)?;
            value.set_sensitive(true);
            req = req.header(AUTHORIZATION, value);
        }
        let req = req.body(OnceBody(Some(Zeroizing::new(body)))).map_err(err)?;
        let resp = sender.send_request(req).await.map_err(err)?;
        let status = resp.status();
        // Redirects are never followed (the endpoint is exactly what the user set).
        if status.is_redirection() {
            return Err(err(format!("refusing to follow a redirect ({status})")));
        }
        let bytes = read_capped(resp.into_body(), max_response).await?;
        Ok((status, bytes))
    }
    .await;
    conn_task.abort();
    result
}

async fn read_capped(mut body: Incoming, max: usize) -> Result<Vec<u8>, CallError> {
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(err)?;
        if let Ok(data) = frame.into_data() {
            let data: Bytes = data;
            if out.len() + data.len() > max {
                return Err(err("response too large"));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> ToolSpec {
        ToolSpec { name: name.into(), description: "d".into(), parameters: "{}".into() }
    }

    #[test]
    fn responses_are_parsed_defensively() {
        let ok = br#"{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"Hi!","tool_calls":[
            {"id":"c1","type":"function","function":{"name":"message_agent","arguments":"{\"to\":\"Toki\"}"}},
            {"id":"c2","type":"function","function":{"name":"rm_rf","arguments":"{}"}},
            {"id":"c3","type":"function","function":{"name":"message_agent","arguments":"not json"}}
        ]}}],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}"#;
        let (reply, usage) = parse_response(ok, &[tool("message_agent")]).expect("parsed");
        assert_eq!(reply.text, "Hi!");
        assert_eq!(reply.tool_calls.len(), 1, "unknown tools and bad arguments are dropped");
        assert_eq!(reply.tool_calls[0].id, "c1");
        assert_eq!(usage, Some(Usage { prompt_tokens: 10, completion_tokens: 3 }));

        let null_content = br#"{"choices":[{"message":{"content":null}}]}"#;
        assert_eq!(parse_response(null_content, &[]).expect("parsed").0.text, "");
        for bad in [&b"{}"[..], b"[]", b"not json", br#"{"choices":[]}"#] {
            assert!(parse_response(bad, &[]).is_none());
        }
        let nul = br#"{"choices":[{"message":{"content":"a\u0000b"}}]}"#;
        assert_eq!(parse_response(nul, &[]).expect("parsed").0.text, "ab");
    }

    #[test]
    fn long_text_is_cut_on_a_char_boundary() {
        let s = "é".repeat(10);
        assert_eq!(cut(&s, 5), "éé");
        assert_eq!(cut("abc", 10), "abc");
    }

    #[test]
    fn request_body_shape() {
        let turns = vec![
            Turn::System { content: "be brief".into() },
            Turn::User { content: "hi".into() },
            Turn::Assistant {
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "t".into(),
                    arguments: "{}".into(),
                }],
            },
            Turn::Tool { tool_call_id: "c1".into(), content: "done".into() },
        ];
        let body: Value =
            serde_json::from_slice(&request_body("m", 100, &turns, &[tool("t")])).expect("json");
        assert_eq!(body["model"], "m");
        assert_eq!(body["max_tokens"], 100);
        assert_eq!(body["stream"], false);
        assert_eq!(body["messages"][2]["content"], Value::Null);
        assert_eq!(body["messages"][2]["tool_calls"][0]["function"]["name"], "t");
        assert_eq!(body["messages"][3]["role"], "tool");
        assert_eq!(body["tools"][0]["function"]["parameters"], json!({}));
    }
}
