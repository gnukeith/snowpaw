//! The authenticated WebSocket on `/v1/ws`.
//!
//! The connection is strict and short-fused: any frame that isn't valid JSON matching
//! the schema, any binary frame, any wrong protocol version, or going over the rate
//! limit gets an error frame and a close. Honest clients never trigger these, so
//! there's no reason to tolerate them. The socket also closes as soon as its session
//! ends (logout, eviction, expiry, or revocation by another process).
//!
//! Authorization: every chat request is checked against chat membership in the
//! database, "no such chat" and "not a member" are indistinguishable, and the sender
//! of a message is always the session's principal.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use snowpaw_proto::agent::{
    AGENT_TOKEN_PREFIX, AgentSettingsView, ApiKeyChange, MAX_AUDIT_PAGE, check_api_key, parse_pin,
};
use snowpaw_proto::http::ErrorCode;
use snowpaw_proto::ws::{
    ClientEnvelope, ClientMsg, MAX_SYNC_LIMIT, ServerEnvelope, ServerMsg, WsErrorCode,
};
use snowpaw_proto::{Id, PROTOCOL_VERSION, decode, encode};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};
use tracing::{debug, error};

use crate::api::{self, AppState, AuthSession, Revocation, StateEvent};
use crate::auth::{self, RandomToken};
use crate::chat_ops::{self, PostOutcome};
use crate::db;
use crate::plugins;
use crate::secrets::Purpose;
use snowpaw_proto::jobs::{JobState, MAX_OPEN_JOBS_PER_AGENT, RunOutcome, check_job};
use snowpaw_proto::profile::{check_about, check_label, check_name};

/// Most agents one server holds.
const MAX_AGENTS: i64 = 256;

/// A peer that won't read its socket can't make us buffer forever.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Close code 1008: policy violation.
pub(crate) const POLICY_VIOLATION: u16 = 1008;

pub async fn upgrade(
    State(st): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<AuthSession>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let Ok(ws) = ws else {
        return api::error_response(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let max = st.cfg.limits.max_ws_message_bytes;
    // tungstenite panics unless max_write_buffer_size > write_buffer_size, so set both.
    ws.max_message_size(max)
        .max_frame_size(max)
        .write_buffer_size(max)
        .max_write_buffer_size(4 * max)
        .on_upgrade(move |socket| run(st, session, socket))
}

/// Per-connection token bucket.
#[derive(Debug)]
pub(crate) struct Bucket {
    capacity: f64,
    tokens: f64,
    per_sec: f64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(per_sec: u32, burst: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            tokens: f64::from(burst),
            per_sec: f64::from(per_sec),
            last: Instant::now(),
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.last).as_secs_f64() * self.per_sec;
        self.tokens = (self.tokens + refill).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn send(socket: &mut WebSocket, msg: ServerMsg) -> bool {
    let text = encode(&ServerEnvelope::new(msg));
    matches!(timeout(SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await, Ok(Ok(())))
}

async fn close(mut socket: WebSocket, code: Option<WsErrorCode>) {
    if let Some(code) = code
        && !send(&mut socket, ServerMsg::Error { code }).await
    {
        return;
    }
    let frame = CloseFrame { code: POLICY_VIOLATION, reason: Utf8Bytes::from_static("") };
    let _ = timeout(SEND_TIMEOUT, socket.send(Message::Close(Some(frame)))).await;
}

async fn still_live(st: &AppState, session: &AuthSession) -> bool {
    matches!(api::authenticate(st, session.token_hash).await, Ok(Some(_)))
}

/// The result of handling one client request. Built and consumed immediately, so the
/// size of the reply variant doesn't matter.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Outcome {
    Reply(ServerMsg),
    /// Nothing to send back directly (a broadcast carries the result).
    Nothing,
    /// Send this error and close.
    Fatal(WsErrorCode),
}

fn internal(e: impl std::fmt::Display) -> Outcome {
    error!(error = %e, "websocket request failed");
    Outcome::Fatal(WsErrorCode::Internal)
}

/// Everything the user sees about one agent's setup.
pub(crate) async fn agent_settings(
    st: &AppState,
    agent: Id,
) -> Result<AgentSettingsView, db::DbError> {
    let since = st.clock.now_ms() - 86_400_000;
    let connected = st.agent_is_connected(agent);
    st.db
        .call(move |c| {
            let model = db::agent_model(c, agent)?;
            let token = db::agent_token_info(c, agent)?;
            Ok(AgentSettingsView {
                has_api_key: model.as_ref().is_some_and(|m| m.sealed_api_key.is_some()),
                model: model.map(|m| m.settings),
                token_issued_at_ms: token.map(|t| t.0),
                token_last_used_at_ms: token.and_then(|t| t.1),
                connected,
                tokens_used_24h: db::usage_since(c, agent, since)?,
                links: db::links_for(c, agent)?,
            })
        })
        .await
}

/// Reply with a job's state (and tell every window).
async fn job_reply(st: &AppState, job: Id) -> Outcome {
    match st.db.call(move |c| db::job(c, job)).await {
        Ok(Some(view)) => {
            st.publish_event(StateEvent::JobChanged(Box::new(view)));
            Outcome::Nothing
        }
        Ok(None) => Outcome::Fatal(WsErrorCode::InvalidRequest),
        Err(e) => internal(e),
    }
}

async fn plugin_list(st: &AppState) -> Outcome {
    match plugins::list(st).await {
        Ok(plugins) => Outcome::Reply(ServerMsg::Plugins { plugins }),
        Err(e) => internal(e),
    }
}

/// `agent` must be an agent (not the user, not unknown).
async fn require_agent_id(st: &AppState, agent: Id) -> Result<(), WsErrorCode> {
    match st.db.call(move |c| db::is_agent(c, agent)).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(WsErrorCode::Forbidden),
        Err(e) => {
            error!(error = %e, "agent lookup failed");
            Err(WsErrorCode::Internal)
        }
    }
}

async fn handle(st: &AppState, session: &AuthSession, msg: ClientMsg) -> Outcome {
    let me = session.principal_id;
    // Everything but chatting is the user's alone (this socket only ever carries
    // user sessions, but check anyway: deny by default).
    let user_only = !matches!(
        msg,
        ClientMsg::Ping { .. }
            | ClientMsg::ListChats {}
            | ClientMsg::Sync { .. }
            | ClientMsg::Send { .. }
    );
    if user_only && me != st.user_id {
        return Outcome::Fatal(WsErrorCode::Forbidden);
    }
    // The largest frame this socket can send: the tungstenite write buffer's cap.
    // Aggregate replies (chat lists, sync pages) are budgeted to it in chat_ops.
    let frame_budget = 4 * st.cfg.limits.max_ws_message_bytes;
    match msg {
        ClientMsg::Ping { nonce } => Outcome::Reply(ServerMsg::Pong { nonce }),
        ClientMsg::ListChats {} => match chat_ops::list_chats(st, me, frame_budget).await {
            Ok(chats) => Outcome::Reply(ServerMsg::Chats { chats }),
            Err(e) => internal(e),
        },
        ClientMsg::Sync { chat_id, after_seq, limit } => {
            if after_seq < 0 || limit == 0 || limit > MAX_SYNC_LIMIT {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            match chat_ops::sync(st, me, chat_id, after_seq, limit, frame_budget).await {
                Ok(Some((messages, has_more))) => {
                    Outcome::Reply(ServerMsg::Messages { chat_id, messages, has_more })
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::Forbidden),
                Err(e) => internal(e),
            }
        }
        ClientMsg::Send { chat_id, client_msg_id, content } => {
            let post = chat_ops::Post { chat_id, client_msg_id, content, in_reply_to: None };
            match chat_ops::post(st, me, post).await {
                PostOutcome::Sent { client_msg_id, id, seq } => {
                    Outcome::Reply(ServerMsg::Sent { client_msg_id, id, seq })
                }
                // Refusals only apply to agents.
                PostOutcome::Refused(_) => Outcome::Fatal(WsErrorCode::Forbidden),
                PostOutcome::Fatal(code) => Outcome::Fatal(code),
            }
        }
        ClientMsg::CreateAgent { name, label, about } => {
            if check_name(&name).is_err()
                || check_label(&label).is_err()
                || check_about(&about).is_err()
            {
                return Outcome::Fatal(WsErrorCode::InvalidProfile);
            }
            let (Ok(agent), Ok(chat)) = (auth::random_id(), auth::random_id()) else {
                return internal("no randomness");
            };
            let now = st.clock.now_ms();
            let result = st
                .db
                .call(move |c| {
                    let count: i64 = c.query_row(
                        "SELECT count(*) FROM principals WHERE kind = 'agent'",
                        [],
                        |r| r.get(0),
                    )?;
                    if count >= MAX_AGENTS {
                        return Ok(None);
                    }
                    let new = db::NewAgent {
                        user: me,
                        agent,
                        chat,
                        name: &name,
                        label: &label,
                        about: &about,
                    };
                    let member = db::create_agent(c, &new, now)?;
                    db::audit(c, now, Some(me), "agent_created", Some(agent), &member.name)?;
                    Ok(Some(member))
                })
                .await;
            match result {
                Ok(Some(member)) => {
                    st.publish_event(StateEvent::ChatsChanged);
                    Outcome::Reply(ServerMsg::AgentCreated { chat_id: chat, agent: member })
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => internal(e),
            }
        }
        ClientMsg::UpdateAgent { agent, name, label, about } => {
            if check_name(&name).is_err()
                || check_label(&label).is_err()
                || check_about(&about).is_err()
            {
                return Outcome::Fatal(WsErrorCode::InvalidProfile);
            }
            let now = st.clock.now_ms();
            let result = st
                .db
                .call(move |c| {
                    let member = db::update_agent(c, agent, &name, &label, &about)?;
                    if member.is_some() {
                        db::audit(c, now, Some(me), "agent_updated", Some(agent), &name)?;
                    }
                    Ok(member)
                })
                .await;
            match result {
                Ok(Some(member)) => {
                    st.publish_event(StateEvent::Profile(member.clone()));
                    Outcome::Reply(ServerMsg::ProfileChanged { member })
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::Forbidden),
                Err(e) => internal(e),
            }
        }
        ClientMsg::SetAvatar { agent, avatar } => {
            let now = st.clock.now_ms();
            let result = st
                .db
                .call(move |c| {
                    if let Some(h) = avatar
                        && !db::blob_exists(c, &h)?
                    {
                        return Ok(Err(WsErrorCode::InvalidProfile));
                    }
                    let member = db::set_avatar(c, agent, avatar)?;
                    if member.is_some() {
                        let what = if avatar.is_some() { "picture set" } else { "picture removed" };
                        db::audit(c, now, Some(me), "agent_updated", Some(agent), what)?;
                    }
                    Ok(member.ok_or(WsErrorCode::Forbidden))
                })
                .await;
            match result {
                Ok(Ok(member)) => {
                    st.publish_event(StateEvent::Profile(member.clone()));
                    Outcome::Reply(ServerMsg::ProfileChanged { member })
                }
                Ok(Err(code)) => Outcome::Fatal(code),
                Err(e) => internal(e),
            }
        }
        ClientMsg::IssueAgentToken { agent } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            let token = match RandomToken::generate() {
                Ok(t) => t,
                Err(e) => return internal(e),
            };
            let hash = token.hash();
            let now = st.clock.now_ms();
            let saved = st
                .db
                .call(move |c| {
                    db::set_agent_token(c, agent, &hash, now)?;
                    db::audit(c, now, Some(me), "agent_token_issued", Some(agent), "")
                })
                .await;
            if let Err(e) = saved {
                return internal(e);
            }
            // Whatever held the old token is cut off now.
            st.revoke(Revocation::AgentToken(agent));
            Outcome::Reply(ServerMsg::AgentToken {
                agent,
                token: token.to_wire(AGENT_TOKEN_PREFIX),
                code: st.agent_code.clone(),
            })
        }
        ClientMsg::RevokeAgentToken { agent } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    if db::delete_agent_token(c, agent)? {
                        db::audit(c, now, Some(me), "agent_token_revoked", Some(agent), "")?;
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            st.revoke(Revocation::AgentToken(agent));
            match agent_settings(st, agent).await {
                Ok(settings) => Outcome::Reply(ServerMsg::AgentSettings { agent, settings }),
                Err(e) => internal(e),
            }
        }
        ClientMsg::GetAgentSettings { agent } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            match agent_settings(st, agent).await {
                Ok(settings) => Outcome::Reply(ServerMsg::AgentSettings { agent, settings }),
                Err(e) => internal(e),
            }
        }
        ClientMsg::SetAgentModel { agent, model, api_key } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            let Ok(endpoint) = model.validate() else {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            };
            let pin = match model.tls_pin.as_deref().map(parse_pin).transpose() {
                Ok(p) => p,
                Err(_) => return Outcome::Fatal(WsErrorCode::InvalidRequest),
            };
            let (key, key_note) = match api_key {
                ApiKeyChange::Keep => (db::KeyUpdate::Keep, "key unchanged"),
                ApiKeyChange::Clear => (db::KeyUpdate::Clear, "key removed"),
                ApiKeyChange::Set { key } => {
                    if check_api_key(key.expose()).is_err() {
                        return Outcome::Fatal(WsErrorCode::InvalidRequest);
                    }
                    match st.secrets.seal(Purpose::ModelApiKey, agent, key.expose().as_bytes()) {
                        Ok(sealed) => (db::KeyUpdate::Set(sealed), "new key"),
                        Err(_) => return internal("sealing the API key failed"),
                    }
                }
            };
            let now = st.clock.now_ms();
            let detail = format!("{} at {}; {key_note}", model.model, endpoint.authority());
            let saved = st
                .db
                .call(move |c| {
                    db::set_agent_model(c, agent, &model, pin, key, now)?;
                    db::audit(c, now, Some(me), "agent_model_set", Some(agent), &detail)
                })
                .await;
            if let Err(e) = saved {
                return internal(e);
            }
            st.publish_event(StateEvent::AgentSettingsChanged(agent));
            match agent_settings(st, agent).await {
                Ok(settings) => Outcome::Reply(ServerMsg::AgentSettings { agent, settings }),
                Err(e) => internal(e),
            }
        }
        ClientMsg::SetAgentLink { a, b, allowed } => {
            if a == b {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            for x in [a, b] {
                if let Err(code) = require_agent_id(st, x).await {
                    return Outcome::Fatal(code);
                }
            }
            let new_chat = match auth::random_id() {
                Ok(id) => id,
                Err(e) => return internal(e),
            };
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    let (chat, _) = db::set_link(c, a, b, allowed, new_chat, now)?;
                    let action = if allowed { "agent_link_allowed" } else { "agent_link_paused" };
                    db::audit(c, now, Some(me), action, Some(chat), &format!("{a} and {b}"))
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            st.publish_event(StateEvent::ChatsChanged);
            Outcome::Nothing
        }
        ClientMsg::SetAgentsPaused { paused } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    db::set_agents_paused(c, paused, now)?;
                    let action = if paused { "agents_paused" } else { "agents_resumed" };
                    db::audit(c, now, Some(me), action, None, "")
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            if paused {
                st.revoke(Revocation::AgentsPaused);
            }
            st.publish_event(StateEvent::AgentsPaused(paused));
            Outcome::Nothing
        }
        ClientMsg::ListPlugins {} => plugin_list(st).await,
        ClientMsg::GrantPlugin { agent, plugin, http_hosts } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            let row = match st.db.call(move |c| db::plugin(c, plugin)).await {
                Ok(Some(row)) => row,
                Ok(None) => return Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => return internal(e),
            };
            let Some(view) = plugins::view(&row, vec![]) else {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            };
            // A grant can narrow what the plugin asks for, never widen it.
            let mut hosts = http_hosts;
            hosts.sort_unstable();
            hosts.dedup();
            if !hosts.iter().all(|h| view.http_hosts.contains(h)) {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            let now = st.clock.now_ms();
            let detail = format!(
                "{}; may fetch from: {}",
                view.name,
                if hosts.is_empty() { "nothing".into() } else { hosts.join(", ") }
            );
            let done = st
                .db
                .call(move |c| {
                    db::grant_plugin(c, agent, plugin, &hosts, now)?;
                    db::audit(c, now, Some(me), "plugin_granted", Some(agent), &detail)
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            st.publish_event(StateEvent::PluginsChanged);
            plugin_list(st).await
        }
        ClientMsg::RevokePlugin { agent, plugin } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    if db::revoke_plugin(c, agent, plugin)? {
                        db::audit(
                            c,
                            now,
                            Some(me),
                            "plugin_revoked",
                            Some(agent),
                            &plugin.to_string(),
                        )?;
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            st.publish_event(StateEvent::PluginsChanged);
            plugin_list(st).await
        }
        ClientMsg::RemovePlugin { plugin } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    if db::remove_plugin(c, plugin)? {
                        db::audit(c, now, Some(me), "plugin_removed", Some(plugin), "")?;
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = done {
                return internal(e);
            }
            st.publish_event(StateEvent::PluginsChanged);
            plugin_list(st).await
        }
        ClientMsg::ListJobs {} => match st.db.call(|c| db::jobs(c)).await {
            Ok(jobs) => Outcome::Reply(ServerMsg::Jobs { jobs }),
            Err(e) => internal(e),
        },
        ClientMsg::CreateJob { agent, title, prompt, schedule } => {
            if let Err(code) = require_agent_id(st, agent).await {
                return Outcome::Fatal(code);
            }
            let now = st.clock.now_ms();
            if check_job(&title, &prompt, &schedule, now).is_err() {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            let Ok(id) = auth::random_id() else { return internal("no randomness") };
            let user = st.user_id;
            let created = st
                .db
                .call(move |c| {
                    let (open, _) = db::open_jobs_of(c, agent)?;
                    if open >= MAX_OPEN_JOBS_PER_AGENT as i64 {
                        return Ok(false);
                    }
                    let Some(chat_id) = db::direct_chat_of(c, agent, user)? else {
                        return Ok(false);
                    };
                    let new = db::NewJob {
                        id,
                        agent,
                        chat_id,
                        title: &title,
                        prompt: &prompt,
                        schedule,
                        state: JobState::Active,
                        proposed_by_agent: false,
                    };
                    db::create_job(c, &new, now)?;
                    db::audit(c, now, Some(me), "job_created", Some(agent), &title)?;
                    Ok(true)
                })
                .await;
            match created {
                Ok(true) => job_reply(st, id).await,
                Ok(false) => Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => internal(e),
            }
        }
        ClientMsg::ApproveJob { job } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    let Some(view) = db::job(c, job)? else { return Ok(false) };
                    if view.state != JobState::Proposed {
                        return Ok(false);
                    }
                    let next = view.schedule.first_run_at_ms.max(now);
                    db::set_job_state(c, job, JobState::Active, Some(next), now)?;
                    db::audit(c, now, Some(me), "job_approved", Some(view.agent), &view.title)?;
                    Ok(true)
                })
                .await;
            match done {
                Ok(true) => job_reply(st, job).await,
                Ok(false) => Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => internal(e),
            }
        }
        ClientMsg::CancelJob { job } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    let Some(view) = db::job(c, job)? else { return Ok(None) };
                    if !view.state.is_open() {
                        return Ok(None);
                    }
                    let running = db::open_runs(c)?.into_iter().find(|(_, j, _, _)| *j == job);
                    if let Some((run, _, _, _)) = running {
                        db::finish_run(c, run, RunOutcome::Cancelled, "cancelled", false, now)?;
                    }
                    db::set_job_state(c, job, JobState::Cancelled, None, now)?;
                    let action = if view.state == JobState::Proposed {
                        "job_declined"
                    } else {
                        "job_cancelled"
                    };
                    db::audit(c, now, Some(me), action, Some(view.agent), &view.title)?;
                    Ok(Some((view.agent, running.map(|r| r.0))))
                })
                .await;
            match done {
                Ok(Some((agent, run))) => {
                    if let Some(run_id) = run {
                        st.publish_event(StateEvent::JobCancel { agent, run_id });
                    }
                    job_reply(st, job).await
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => internal(e),
            }
        }
        ClientMsg::RunJobNow { job } => {
            let now = st.clock.now_ms();
            let done = st
                .db
                .call(move |c| {
                    let Some(view) = db::job(c, job)? else { return Ok(false) };
                    if view.state != JobState::Active || view.running {
                        return Ok(false);
                    }
                    db::set_job_state(c, job, JobState::Active, Some(now), now)?;
                    Ok(true)
                })
                .await;
            match done {
                Ok(true) => job_reply(st, job).await,
                Ok(false) => Outcome::Fatal(WsErrorCode::InvalidRequest),
                Err(e) => internal(e),
            }
        }
        ClientMsg::ListAudit { before_seq, limit } => {
            if limit == 0 || limit > MAX_AUDIT_PAGE || before_seq.is_some_and(|s| s < 0) {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            match st.db.call(move |c| db::audit_page(c, before_seq, limit)).await {
                Ok((entries, has_more)) => Outcome::Reply(ServerMsg::Audit { entries, has_more }),
                Err(e) => internal(e),
            }
        }
    }
}

async fn run(st: Arc<AppState>, session: AuthSession, mut socket: WebSocket) {
    // Subscribe first, then re-check: a revocation between the HTTP auth check and
    // here would otherwise be missed.
    let mut revocations = st.subscribe_revocations();
    let mut messages = st.subscribe_messages();
    let mut events = st.subscribe_events();
    if !still_live(&st, &session).await {
        return close(socket, Some(WsErrorCode::SessionEnded)).await;
    }
    let welcome = ServerMsg::Welcome {
        protocol_version: PROTOCOL_VERSION,
        server_time_ms: st.clock.now_ms(),
        session_expires_at_ms: session.expires_at_ms,
        you: session.principal_id,
        max_content_bytes: u32::try_from(st.cfg.limits.max_message_bytes).unwrap_or(u32::MAX),
        agents_paused: st.db.call(|c| db::agents_paused(c)).await.unwrap_or(true),
    };
    if !send(&mut socket, welcome).await {
        return;
    }
    // Which agent runtimes are connected right now.
    for (agent, working_in) in st.agent_statuses() {
        if !send(&mut socket, ServerMsg::AgentStatus { agent, connected: true, working_in }).await {
            return;
        }
    }
    debug!("websocket opened");

    let limits = &st.cfg.limits;
    let mut bucket = Bucket::new(limits.ws_messages_per_sec, limits.ws_burst);
    let idle = Duration::from_secs(limits.ws_idle_timeout_secs);
    let mut last_rx = Instant::now();
    let mut keepalive = interval(idle / 3);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut recheck = interval(Duration::from_secs(limits.session_recheck_secs));
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    recheck.tick().await;

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                // None, a transport error, or a size-limit violation: the socket is done.
                let Some(Ok(msg)) = incoming else { break };
                last_rx = Instant::now();
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                // Control frames count against the rate limit too (a ping flood
                // still makes us write pongs).
                if !bucket.take() {
                    debug!("websocket rate limit exceeded");
                    return close(socket, Some(WsErrorCode::RateLimited)).await;
                }
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) | Message::Close(_) => {
                        return close(socket, Some(WsErrorCode::BadFrame)).await;
                    }
                };
                let env = match decode::<ClientEnvelope>(text.as_str().as_bytes()) {
                    Ok(env) => env,
                    Err(e) => {
                        debug!(reason = %e, "websocket frame rejected");
                        return close(socket, Some(WsErrorCode::BadFrame)).await;
                    }
                };
                if env.v != PROTOCOL_VERSION {
                    return close(socket, Some(WsErrorCode::UnsupportedVersion)).await;
                }
                match handle(&st, &session, env.msg).await {
                    Outcome::Reply(reply) => {
                        if !send(&mut socket, reply).await {
                            break;
                        }
                    }
                    Outcome::Nothing => {}
                    Outcome::Fatal(code) => return close(socket, Some(code)).await,
                }
            }
            event = events.recv() => {
                let push = match event {
                    Ok(StateEvent::Profile(member)) => Some(ServerMsg::ProfileChanged { member }),
                    Ok(StateEvent::ChatsChanged) | Err(RecvError::Lagged(_)) => Some(ServerMsg::Resync {}),
                    Ok(StateEvent::AgentStatus { agent, connected, working_in }) => {
                        Some(ServerMsg::AgentStatus { agent, connected, working_in })
                    }
                    Ok(StateEvent::AgentsPaused(paused)) => Some(ServerMsg::AgentsPaused { paused }),
                    Ok(StateEvent::JobChanged(job)) => Some(ServerMsg::JobChanged { job: *job }),
                    Ok(
                        StateEvent::AgentSettingsChanged(_)
                        | StateEvent::PluginsChanged
                        | StateEvent::JobDispatch { .. }
                        | StateEvent::JobCancel { .. },
                    ) => None,
                    Err(RecvError::Closed) => break,
                };
                if let Some(push) = push
                    && !send(&mut socket, push).await
                {
                    break;
                }
            }
            event = messages.recv() => {
                let push = match event {
                    Ok(ev) if ev.members.contains(&session.principal_id) => {
                        Some(ServerMsg::NewMessage { message: ev.message.clone() })
                    }
                    Ok(_) => None,
                    // We missed some: tell the client to sync instead of guessing.
                    Err(RecvError::Lagged(_)) => Some(ServerMsg::Resync {}),
                    Err(RecvError::Closed) => break,
                };
                if let Some(push) = push
                    && !send(&mut socket, push).await
                {
                    break;
                }
            }
            revoked = revocations.recv() => {
                let ended = match revoked {
                    Ok(Revocation::Session(h)) => h == session.token_hash,
                    Ok(Revocation::AllFor(p)) => p == session.principal_id,
                    Ok(Revocation::AgentToken(_) | Revocation::AgentReplaced { .. } | Revocation::AgentsPaused) => false,
                    // Missed some revocations: fall back to asking the database.
                    Err(RecvError::Lagged(_)) => !still_live(&st, &session).await,
                    Err(RecvError::Closed) => true,
                };
                if ended {
                    return close(socket, Some(WsErrorCode::SessionEnded)).await;
                }
            }
            _ = recheck.tick() => {
                // Catches expiry and revocations made by another process (e.g. the
                // `set-password` command), which don't go through the broadcast.
                if !still_live(&st, &session).await {
                    return close(socket, Some(WsErrorCode::SessionEnded)).await;
                }
            }
            _ = keepalive.tick() => {
                if last_rx.elapsed() >= idle {
                    debug!("websocket idle timeout");
                    return close(socket, None).await;
                }
                // Only ping a peer that has gone quiet; an active one proves it's alive.
                if last_rx.elapsed() >= idle / 3
                    && !matches!(
                        timeout(SEND_TIMEOUT, socket.send(Message::Ping(Default::default()))).await,
                        Ok(Ok(()))
                    )
                {
                    break;
                }
            }
        }
    }
    debug!("websocket closed");
}
