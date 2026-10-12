//! Agents: the runtime's WebSocket protocol on `/v1/agent/ws`, and the settings the
//! user manages for each agent.
//!
//! An agent runtime authenticates with an agent token (`spw_a_...`) that belongs to
//! exactly one agent. It can read and post in that agent's chats, ask the server to
//! run its model, and nothing else: there is no message an agent can send to change a
//! profile, a permission, a model setting or another agent. The model's API key never
//! leaves the server; the server calls the model on the agent's behalf and enforces
//! the limits there.

use serde::{Deserialize, Serialize};

use crate::jobs::JobSpec;
use crate::plugin::{FetchFailure, GrantedPlugin};
use crate::secret::SecretString;
use crate::ws::{ChatSummary, Content, Member, MessageView, WsErrorCode};
use crate::{Id, PROTOCOL_VERSION};

pub const AGENT_WS_PATH: &str = "/v1/agent/ws";
pub const AGENT_TOKEN_PREFIX: &str = "spw_a_";

/// Most turns in one inference request.
pub const MAX_TURNS: usize = 400;
/// Most text across all turns of one inference request.
pub const MAX_PROMPT_BYTES: usize = 512 * 1024;
pub const MAX_TOOLS: usize = 32;
pub const MAX_TOOL_NAME_CHARS: usize = 64;
pub const MAX_TOOL_DESCRIPTION_CHARS: usize = 1024;
/// A tool's JSON Schema, or one call's JSON arguments.
pub const MAX_TOOL_JSON_BYTES: usize = 16 * 1024;
/// Tool calls in one turn.
pub const MAX_TOOL_CALLS: usize = 16;
/// Tool calls across all turns of one inference request. An honest runtime makes a
/// handful of calls per round.
pub const MAX_TOOL_CALLS_TOTAL: usize = 64;
pub const MAX_INSTRUCTIONS_CHARS: usize = 8000;
pub const MAX_MODEL_NAME_CHARS: usize = 128;
pub const MAX_BASE_URL_CHARS: usize = 512;
pub const MAX_REPLY_TOKENS: u32 = 32_768;
pub const MAX_CONTEXT_MESSAGES: u32 = 200;
pub const MAX_DAILY_TOKENS: u64 = 1_000_000_000;

/// The largest frame a rule-following `Infer` request can encode to. Control
/// characters are banned everywhere in a request (see `turn_text_ok`), so JSON
/// escaping at most doubles the text; the rest is envelope and per-turn structure.
/// Server configs keep `agents.max_ws_message_bytes` at or above this, so a request
/// that follows the rules always fits on the socket.
pub fn infer_frame_bound() -> usize {
    2 * MAX_PROMPT_BYTES + 128 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEnvelope {
    pub v: u16,
    pub msg: AgentMsg,
}

impl AgentEnvelope {
    pub fn new(msg: AgentMsg) -> Self {
        Self { v: PROTOCOL_VERSION, msg }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentServerEnvelope {
    pub v: u16,
    pub msg: AgentServerMsg,
}

impl AgentServerEnvelope {
    pub fn new(msg: AgentServerMsg) -> Self {
        Self { v: PROTOCOL_VERSION, msg }
    }
}

/// Runtime -> server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentMsg {
    Ping {
        nonce: u64,
    },
    ListChats {},
    Sync {
        chat_id: Id,
        after_seq: i64,
        limit: u32,
    },
    /// Post a message. `in_reply_to` is the seq of the message being answered: it is
    /// required in conversations with other agents, where it sets how deep the
    /// back-and-forth is (and so where it stops).
    Send {
        chat_id: Id,
        client_msg_id: Id,
        content: Content,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        in_reply_to: Option<i64>,
    },
    /// Run the agent's model. Answered with `Inferred` or `InferFailed`.
    Infer {
        request_id: Id,
        turns: Vec<Turn>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tools: Vec<ToolSpec>,
    },
    /// Shown to the user as "working…" on this agent.
    Working {
        chat_id: Id,
        working: bool,
    },
    /// Download a granted plugin's code. Answered with `PluginCode` and a binary frame.
    GetPlugin {
        plugin: Id,
    },
    /// Fetch a URL for a plugin. The server checks it against the hosts this agent was
    /// granted for that plugin, and that it resolves to the public internet.
    Fetch {
        request_id: Id,
        plugin: Id,
        url: String,
    },
    /// Suggest a job. It does nothing until the user approves it. Answered with
    /// `JobProposed` or `JobRefused`.
    ProposeJob {
        request_id: Id,
        title: String,
        prompt: String,
        start_in_secs: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        every_secs: Option<u32>,
    },
    /// What a job run is doing (shown on the job card).
    JobProgress {
        run_id: Id,
        text: String,
    },
    /// A job run finished.
    JobDone {
        run_id: Id,
        ok: bool,
        detail: String,
    },
}

/// Server -> runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentServerMsg {
    Welcome {
        protocol_version: u16,
        server_time_ms: i64,
        /// This agent's profile.
        you: Member,
        /// What the user told this agent to be and do.
        instructions: String,
        max_content_bytes: u32,
        /// How many recent messages to give the model as context.
        context_messages: u32,
        /// Longest allowed agent-to-agent back-and-forth.
        max_depth: u32,
        /// Largest WebSocket message the server accepts from the runtime. Inference
        /// requests must be trimmed to fit it (the server refuses larger frames).
        max_frame_bytes: u32,
        /// Plugins granted to this agent.
        plugins: Vec<GrantedPlugin>,
    },
    Pong {
        nonce: u64,
    },
    Chats {
        chats: Vec<ChatSummary>,
    },
    Messages {
        chat_id: Id,
        messages: Vec<MessageView>,
        has_more: bool,
    },
    Sent {
        client_msg_id: Id,
        id: Id,
        seq: i64,
    },
    NewMessage {
        message: MessageView,
    },
    Resync {},
    /// The user changed this agent's instructions or limits.
    Settings {
        instructions: String,
        context_messages: u32,
    },
    Inferred {
        request_id: Id,
        reply: Reply,
        usage: Usage,
    },
    InferFailed {
        request_id: Id,
        reason: InferFailure,
    },
    /// The plugins granted to this agent changed.
    Plugins {
        plugins: Vec<GrantedPlugin>,
    },
    /// Followed by a binary frame of exactly `bytes` bytes: the module.
    PluginCode {
        plugin: Id,
        bytes: u32,
    },
    Fetched {
        request_id: Id,
        fetched: crate::plugin::Fetched,
    },
    FetchFailed {
        request_id: Id,
        reason: FetchFailure,
    },
    /// Do this job now.
    JobRun {
        job: JobSpec,
    },
    /// The user cancelled a job run that's in progress: stop it.
    JobCancelled {
        run_id: Id,
    },
    JobProposed {
        request_id: Id,
        job: Id,
    },
    JobRefused {
        request_id: Id,
        reason: String,
    },
    /// A post was refused by policy. Not fatal: the runtime should stop that thread.
    SendRefused {
        client_msg_id: Id,
        reason: SendRefusal,
    },
    Error {
        code: WsErrorCode,
    },
}

/// One turn of the conversation given to the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum Turn {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    Tool {
        tool_call_id: String,
        content: String,
    },
}

/// A tool the model may call. `parameters` is a JSON Schema object, as JSON text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: String,
}

/// A tool call the model made. `arguments` is JSON text and, like everything the
/// model writes, untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferFailure {
    /// The user hasn't set up a model for this agent.
    NotConfigured,
    /// Agents are paused (the kill switch).
    Paused,
    RateLimited,
    /// The agent used up its token budget for the last 24 hours.
    BudgetExhausted,
    /// The request broke a size or format rule.
    InvalidRequest,
    /// Another request from this agent is still running.
    Busy,
    /// The model server refused, failed, or sent something we can't use.
    Upstream,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendRefusal {
    /// The agent-to-agent back-and-forth is as deep as the server allows.
    DepthLimit,
    RateLimited,
    /// The user paused this conversation between agents.
    LinkPaused,
    /// Agents are paused (the kill switch).
    Paused,
}

fn tool_name_ok(name: &str) -> bool {
    (1..=MAX_TOOL_NAME_CHARS).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A JSON object as text (not checked against any schema). Control characters are
/// banned so re-encoding can't expand the text past the frame budget via `\u` escapes.
fn json_object_ok(text: &str) -> bool {
    text.len() <= MAX_TOOL_JSON_BYTES
        && !text.chars().any(|c| c.is_control())
        && serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(text).is_ok()
}

/// Text the model sees or wrote: no control characters but newline and tab (same
/// rule as message content, and for the same reason: a turn's JSON encoding must
/// stay proportional to its size).
fn turn_text_ok(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

impl AgentMsg {
    /// Size and format rules for an inference request. `total` counts every text
    /// byte a frame will carry (content, tool text, call ids and names), so the
    /// encoded frame is bounded by `infer_frame_bound()`.
    pub fn validate_infer(turns: &[Turn], tools: &[ToolSpec]) -> bool {
        let mut total = 0usize;
        let mut calls_total = 0usize;
        let turns_ok = !turns.is_empty()
            && turns.len() <= MAX_TURNS
            && turns.iter().all(|t| match t {
                Turn::System { content } | Turn::User { content } => {
                    total += content.len();
                    turn_text_ok(content)
                }
                Turn::Assistant { content, tool_calls } => {
                    total += content.len();
                    calls_total += tool_calls.len();
                    turn_text_ok(content)
                        && calls_total <= MAX_TOOL_CALLS_TOTAL
                        && tool_calls.len() <= MAX_TOOL_CALLS
                        && tool_calls.iter().all(|c| {
                            total += c.id.len() + c.name.len() + c.arguments.len();
                            tool_name_ok(&c.name)
                                && (1..=128).contains(&c.id.len())
                                && json_object_ok(&c.arguments)
                        })
                }
                Turn::Tool { tool_call_id, content } => {
                    total += tool_call_id.len() + content.len();
                    (1..=128).contains(&tool_call_id.len()) && turn_text_ok(content)
                }
            });
        let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        let tools_ok = tools.len() <= MAX_TOOLS
            && names.len() == tools.len()
            && tools.iter().all(|t| {
                total += t.description.len() + t.parameters.len();
                tool_name_ok(&t.name)
                    && t.description.chars().count() <= MAX_TOOL_DESCRIPTION_CHARS
                    && json_object_ok(&t.parameters)
            });
        turns_ok && tools_ok && calls_total <= MAX_TOOL_CALLS_TOTAL && total <= MAX_PROMPT_BYTES
    }
}

// --- Settings the user manages -------------------------------------------------

/// Where an agent's model lives and how it may be used. Set by the user only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSettings {
    /// OpenAI-compatible API base, e.g. `https://api.example.com/v1`. Plain `http`
    /// only for this machine (`127.0.0.1`, `[::1]`, `localhost`).
    pub base_url: String,
    pub model: String,
    /// For a model server with a self-signed certificate: its SHA-256 fingerprint
    /// (`sha256:<hex>`). Without one, the certificate must chain to a public CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
    /// The agent's system prompt.
    pub instructions: String,
    pub max_reply_tokens: u32,
    pub context_messages: u32,
    /// Prompt + reply tokens allowed per rolling 24 hours. 0 = the model is off.
    pub daily_token_limit: u64,
}

/// What to do with the stored API key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApiKeyChange {
    Keep,
    Clear,
    Set { key: SecretString },
}

/// An endpoint, parsed strictly: scheme, host, port, path. No user info, query or
/// fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Lowercase; IPv6 without brackets.
    pub host: String,
    pub port: u16,
    /// Starts with `/`, no trailing `/` (may be empty).
    pub path: String,
}

impl Endpoint {
    pub fn is_loopback(&self) -> bool {
        self.host == "localhost"
            || self.host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// `host:port` for the Host header and for connecting.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    BadUrl,
    /// `http://` to anything but this machine.
    InsecureUrl,
    BadModelName,
    BadPin,
    BadInstructions,
    OutOfRange,
    BadKey,
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadUrl => "the model URL isn't valid (like https://host/v1)",
            Self::InsecureUrl => {
                "plain http is only allowed to this machine; use https (with a pinned \
                 certificate if it's self-signed)"
            }
            Self::BadModelName => "the model name is empty, too long, or has odd characters",
            Self::BadPin => "the certificate fingerprint should be sha256: and 64 hex characters",
            Self::BadInstructions => {
                "the instructions are too long or contain a forbidden character"
            }
            Self::OutOfRange => "a limit is out of range",
            Self::BadKey => "the API key is too long or contains spaces or control characters",
        })
    }
}

impl std::error::Error for SettingsError {}

pub fn parse_endpoint(url: &str) -> Result<Endpoint, SettingsError> {
    if url.len() > MAX_BASE_URL_CHARS || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(SettingsError::BadUrl);
    }
    let lower = url.to_ascii_lowercase();
    let (tls, rest) = if lower.starts_with("https://") {
        (true, &url[8..])
    } else if lower.starts_with("http://") {
        (false, &url[7..])
    } else {
        return Err(SettingsError::BadUrl);
    };
    if rest.contains(['?', '#', '@', '\\', '%']) {
        return Err(SettingsError::BadUrl);
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or(SettingsError::BadUrl)?;
        if h.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(SettingsError::BadUrl);
        }
        let port = match after {
            "" => default_port,
            p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or(SettingsError::BadUrl)?,
        };
        (h.to_ascii_lowercase(), port)
    } else {
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| SettingsError::BadUrl)?),
            None => (authority, default_port),
        };
        let host_ok = !h.is_empty()
            && h.len() <= 253
            && h.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !host_ok {
            return Err(SettingsError::BadUrl);
        }
        (h.to_ascii_lowercase(), port)
    };
    if port == 0 {
        return Err(SettingsError::BadUrl);
    }
    let path = path.trim_end_matches('/');
    let path_ok = path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        && !path.split('/').any(|seg| seg == ".." || seg == ".");
    if !path_ok {
        return Err(SettingsError::BadUrl);
    }
    let ep = Endpoint { tls, host, port, path: path.to_owned() };
    if !ep.tls && !ep.is_loopback() {
        return Err(SettingsError::InsecureUrl);
    }
    Ok(ep)
}

/// `sha256:<64 hex>` (any case) -> 32 bytes.
pub fn parse_pin(pin: &str) -> Result<[u8; 32], SettingsError> {
    let lower = pin.trim().to_ascii_lowercase();
    let hex = lower.strip_prefix("sha256:").ok_or(SettingsError::BadPin)?;
    if hex.len() != 64 {
        return Err(SettingsError::BadPin);
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| SettingsError::BadPin)?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| SettingsError::BadPin)?;
    }
    Ok(out)
}

impl ModelSettings {
    pub fn validate(&self) -> Result<Endpoint, SettingsError> {
        let ep = parse_endpoint(&self.base_url)?;
        let model_ok = (1..=MAX_MODEL_NAME_CHARS).contains(&self.model.chars().count())
            && self.model.chars().all(|c| c.is_ascii_graphic());
        if !model_ok {
            return Err(SettingsError::BadModelName);
        }
        if let Some(pin) = &self.tls_pin {
            parse_pin(pin)?;
        }
        let instructions_ok = self.instructions.chars().count() <= MAX_INSTRUCTIONS_CHARS
            && self.instructions.chars().all(|c| {
                !(c.is_control() && c != '\n' && c != '\t')
                    && !('\u{202A}'..='\u{202E}').contains(&c)
            });
        if !instructions_ok {
            return Err(SettingsError::BadInstructions);
        }
        let ranges_ok = (16..=MAX_REPLY_TOKENS).contains(&self.max_reply_tokens)
            && (1..=MAX_CONTEXT_MESSAGES).contains(&self.context_messages)
            && self.daily_token_limit <= MAX_DAILY_TOKENS;
        if !ranges_ok {
            return Err(SettingsError::OutOfRange);
        }
        Ok(ep)
    }
}

/// An API key as typed: printable ASCII, no spaces, at most 1 KiB.
pub fn check_api_key(key: &str) -> Result<(), SettingsError> {
    if (1..=1024).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(SettingsError::BadKey)
    }
}

/// Everything the user sees about one agent's setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSettingsView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelSettings>,
    pub has_api_key: bool,
    /// When the current runtime token was issued (none = no runtime can connect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_issued_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_last_used_at_ms: Option<i64>,
    pub connected: bool,
    /// Prompt + reply tokens used in the last 24 hours.
    pub tokens_used_24h: u64,
    /// Agents this agent may talk to (each has a chat between the two).
    pub links: Vec<AgentLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLink {
    pub agent: Id,
    pub chat_id: Id,
    /// Paused links keep their history but neither agent can post.
    pub allowed: bool,
}

/// One line of the audit log. Never contains secrets or message text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub seq: i64,
    pub at_ms: i64,
    /// Who did it (none = the server itself or its command line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Id>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Id>,
    pub detail: String,
}

pub const MAX_AUDIT_PAGE: u32 = 200;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let ep = parse_endpoint("https://API.example.com/v1/").expect("ok");
        assert_eq!(
            ep,
            Endpoint { tls: true, host: "api.example.com".into(), port: 443, path: "/v1".into() }
        );
        let local = parse_endpoint("http://127.0.0.1:11434/v1").expect("ok");
        assert_eq!(
            (local.tls, local.port, local.authority()),
            (false, 11434, "127.0.0.1:11434".into())
        );
        assert!(parse_endpoint("http://localhost:8080").is_ok());
        assert_eq!(
            parse_endpoint("http://[::1]:8080/v1").map(|e| e.authority()),
            Ok("[::1]:8080".into())
        );
        assert!(parse_endpoint("https://[fd00::1]/v1").is_ok());
        for (bad, why) in [
            ("http://192.168.1.10:11434/v1", SettingsError::InsecureUrl),
            ("http://models.lan/v1", SettingsError::InsecureUrl),
            ("http://127.0.0.1.evil.com/v1", SettingsError::InsecureUrl),
            ("ftp://x/v1", SettingsError::BadUrl),
            ("https://user:pw@host/v1", SettingsError::BadUrl),
            ("https://host/v1?x=1", SettingsError::BadUrl),
            ("https://host/v1#x", SettingsError::BadUrl),
            ("https://host/../admin", SettingsError::BadUrl),
            ("https://host/%2e%2e/admin", SettingsError::BadUrl),
            ("https://host:0/v1", SettingsError::BadUrl),
            ("https://host:99999/v1", SettingsError::BadUrl),
            ("https://ho st/v1", SettingsError::BadUrl),
            ("https://hοst.com/v1", SettingsError::BadUrl),
            ("https://[::1/v1", SettingsError::BadUrl),
            ("https://host\\@evil/v1", SettingsError::BadUrl),
            ("https:///v1", SettingsError::BadUrl),
        ] {
            assert_eq!(parse_endpoint(bad), Err(why), "{bad}");
        }
    }

    fn settings() -> ModelSettings {
        ModelSettings {
            base_url: "http://127.0.0.1:11434/v1".into(),
            model: "llama3.1:8b".into(),
            tls_pin: None,
            instructions: "Be brief.".into(),
            max_reply_tokens: 1024,
            context_messages: 40,
            daily_token_limit: 200_000,
        }
    }

    #[test]
    fn settings_rules() {
        assert!(settings().validate().is_ok());
        let mut s = settings();
        s.model = "two words".into();
        assert_eq!(s.validate(), Err(SettingsError::BadModelName));
        let mut s = settings();
        s.tls_pin = Some("sha256:abcd".into());
        assert_eq!(s.validate(), Err(SettingsError::BadPin));
        s.tls_pin = Some(format!("sha256:{}", "AB".repeat(32)));
        assert!(s.validate().is_ok());
        let mut s = settings();
        s.max_reply_tokens = 0;
        assert_eq!(s.validate(), Err(SettingsError::OutOfRange));
        let mut s = settings();
        s.instructions = "x\u{202E}y".into();
        assert_eq!(s.validate(), Err(SettingsError::BadInstructions));
        assert!(check_api_key("sk-abc_123").is_ok());
        assert!(check_api_key("sk abc").is_err());
        assert!(check_api_key("").is_err());
        assert!(check_api_key("sk-\n").is_err());
    }

    #[test]
    fn inference_requests_are_bounded() {
        let user = |c: &str| Turn::User { content: c.into() };
        let tool = |name: &str, params: &str| ToolSpec {
            name: name.into(),
            description: "d".into(),
            parameters: params.into(),
        };
        assert!(AgentMsg::validate_infer(&[user("hi")], &[]));
        assert!(!AgentMsg::validate_infer(&[], &[]));
        assert!(!AgentMsg::validate_infer(&[user("a\0b")], &[]));
        assert!(!AgentMsg::validate_infer(&[user(&"x".repeat(MAX_PROMPT_BYTES + 1))], &[]));
        assert!(AgentMsg::validate_infer(&[user("hi")], &[tool("message_agent", "{}")]));
        assert!(!AgentMsg::validate_infer(&[user("hi")], &[tool("bad name", "{}")]));
        assert!(
            !AgentMsg::validate_infer(&[user("hi")], &[tool("t", "[1]")]),
            "schema must be an object"
        );
        assert!(
            !AgentMsg::validate_infer(&[user("hi")], &[tool("t", "{}"), tool("t", "{}")]),
            "duplicate names"
        );
        let call = Turn::Assistant {
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "t".into(),
                arguments: "not json".into(),
            }],
        };
        assert!(!AgentMsg::validate_infer(&[user("hi"), call], &[]));
        // Control characters (other than newline and tab) are banned in all turn
        // text, and in tool JSON, so a frame can't expand past its budget in escapes.
        assert!(!AgentMsg::validate_infer(&[user("bell\u{7}")], &[]));
        assert!(AgentMsg::validate_infer(&[user("hi\n\tthere")], &[]), "newline and tab are fine");
        assert!(
            !AgentMsg::validate_infer(&[user("hi")], &[tool("t", "{\"a\":\"\u{1}\"}")]),
            "control characters inside tool JSON"
        );
        // Everything textual counts towards the budget: call ids and names included.
        let call = |id: String| Turn::Assistant {
            content: String::new(),
            tool_calls: vec![ToolCall { id, name: "t".into(), arguments: "{}".into() }],
        };
        let mut with_user = vec![user("hi")];
        with_user.extend((0..300).map(|i| call("c".repeat(64) + &i.to_string())));
        assert!(
            !AgentMsg::validate_infer(&with_user, &[]),
            "call ids alone can't blow past the budget"
        );
        // Tool descriptions and schemas count too: 32 maximal tools exceed it.
        let mut big_tools = Vec::new();
        for i in 0..MAX_TOOLS {
            big_tools.push(ToolSpec {
                name: format!("t{i}"),
                description: "d".repeat(MAX_TOOL_DESCRIPTION_CHARS),
                parameters: "x".repeat(MAX_TOOL_JSON_BYTES - 2),
            });
        }
        assert!(
            !AgentMsg::validate_infer(&[user("hi")], &big_tools),
            "tool text counts towards the budget"
        );
        // A rule-following request always fits the advertised frame bound.
        let biggest = vec![
            user(&"x".repeat(MAX_PROMPT_BYTES - 64)),
            Turn::System { content: "s".repeat(64) },
        ];
        assert!(AgentMsg::validate_infer(&biggest, &[]));
        let frame = AgentEnvelope::new(AgentMsg::Infer {
            request_id: Id::from_bytes([9; 16]),
            turns: biggest,
            tools: vec![],
        });
        assert!(crate::encode(&frame).len() <= infer_frame_bound(), "a legal request must fit");
    }

    #[test]
    fn tool_calls_are_capped_across_turns() {
        let user = |c: &str| Turn::User { content: c.into() };
        let calls = |n: usize| Turn::Assistant {
            content: String::new(),
            tool_calls: (0..n)
                .map(|i| ToolCall { id: format!("c{i}"), name: "t".into(), arguments: "{}".into() })
                .collect(),
        };
        let exact = MAX_TOOL_CALLS_TOTAL / MAX_TOOL_CALLS;
        let turns: Vec<Turn> =
            std::iter::once(user("hi")).chain((0..exact).map(|_| calls(MAX_TOOL_CALLS))).collect();
        assert!(AgentMsg::validate_infer(&turns, &[]), "exactly the total cap");
        let turns: Vec<Turn> = std::iter::once(user("hi"))
            .chain((0..exact).map(|_| calls(MAX_TOOL_CALLS)))
            .chain(std::iter::once(calls(1)))
            .collect();
        assert!(!AgentMsg::validate_infer(&turns, &[]), "one over the total cap");
    }
}
