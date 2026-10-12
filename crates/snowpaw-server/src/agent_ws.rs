//! The agent runtime's WebSocket on `/v1/agent/ws`.
//!
//! Authenticated by a runtime token (`spw_a_...`) that belongs to exactly one agent.
//! The connection acts as that agent and nothing more: it reads and posts in that
//! agent's chats (with the agent limits in `chat_ops`), asks the server to run the
//! agent's model, and reports when it's working. It cannot touch profiles, settings,
//! tokens, links, other agents' chats or the user's session.
//!
//! It closes at once when the token is revoked or replaced, when the kill switch is
//! turned on (also checked every few seconds, to catch the command line), when a newer
//! connection for the same agent arrives, or on any protocol violation.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use snowpaw_proto::agent::{
    AGENT_TOKEN_PREFIX, AgentEnvelope, AgentMsg, AgentServerEnvelope, AgentServerMsg, InferFailure,
};
use snowpaw_proto::http::ErrorCode;
use snowpaw_proto::jobs::{
    JobSchedule, JobState, MAX_OPEN_JOBS_PER_AGENT, MAX_PROGRESS_CHARS, MAX_PROPOSALS_PER_AGENT,
    RunOutcome, check_job,
};
use snowpaw_proto::plugin::{FetchFailure, Fetched};
use snowpaw_proto::ws::{MAX_SYNC_LIMIT, WsErrorCode};
use snowpaw_proto::{Id, PROTOCOL_VERSION, decode, encode};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};
use tracing::{debug, error, info};

use crate::api::{self, AppState, Revocation, StateEvent};
use crate::chat_ops::{self, PostOutcome};
use crate::db;
use crate::inference;
use crate::ws::{Bucket, POLICY_VIOLATION, SEND_TIMEOUT};
use crate::{fetch, plugins};

/// How often a connection re-checks its token and the kill switch in the database
/// (changes made through the server are pushed instantly; this catches the CLI).
const RECHECK: Duration = Duration::from_secs(5);
/// Model context when the user hasn't configured a model yet.
const DEFAULT_CONTEXT_MESSAGES: u32 = 40;

/// The authenticated agent for this request (set by `require_agent`).
#[derive(Debug, Clone, Copy)]
pub struct AgentSession {
    pub agent: Id,
    pub token_hash: [u8; 32],
}

enum TokenState {
    Valid(Id),
    Paused,
    Invalid,
}

async fn token_state(st: &AppState, hash: [u8; 32]) -> Result<TokenState, db::DbError> {
    let now = st.clock.now_ms();
    st.db
        .call(move |c| {
            let Some(agent) = db::agent_for_token(c, &hash)? else {
                return Ok(TokenState::Invalid);
            };
            if db::agents_paused(c)? {
                return Ok(TokenState::Paused);
            }
            db::touch_agent_token(c, agent, now)?;
            Ok(TokenState::Valid(agent))
        })
        .await
}

pub async fn require_agent(
    State(st): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(hash) = api::bearer_hash_with(req.headers(), AGENT_TOKEN_PREFIX) else {
        return api::unauthorized();
    };
    match token_state(&st, hash).await {
        Ok(TokenState::Valid(agent)) => {
            req.extensions_mut().insert(AgentSession { agent, token_hash: hash });
            next.run(req).await
        }
        Ok(TokenState::Paused) => {
            api::error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::AgentsPaused)
        }
        Ok(TokenState::Invalid) => api::unauthorized(),
        Err(e) => {
            error!(error = %e, "agent token lookup failed");
            api::internal()
        }
    }
}

pub async fn upgrade(
    State(st): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<AgentSession>,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let Ok(ws) = ws else {
        return api::error_response(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let max = st.cfg.agents.max_ws_message_bytes;
    ws.max_message_size(max)
        .max_frame_size(max)
        .write_buffer_size(max)
        .max_write_buffer_size(4 * max)
        .on_upgrade(move |socket| run(st, session, socket))
}

async fn send(socket: &mut WebSocket, msg: AgentServerMsg) -> bool {
    let text = encode(&AgentServerEnvelope::new(msg));
    matches!(timeout(SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await, Ok(Ok(())))
}

async fn close(mut socket: WebSocket, code: Option<WsErrorCode>) {
    if let Some(code) = code
        && !send(&mut socket, AgentServerMsg::Error { code }).await
    {
        return;
    }
    let frame = CloseFrame { code: POLICY_VIOLATION, reason: Utf8Bytes::from_static("") };
    let _ = timeout(SEND_TIMEOUT, socket.send(Message::Close(Some(frame)))).await;
}

/// Unregisters the connection however it ends, and stops a model call in flight.
struct Presence<'a> {
    st: &'a AppState,
    agent: Id,
    conn: u64,
    inflight: Option<JoinHandle<()>>,
}

impl Drop for Presence<'_> {
    fn drop(&mut self) {
        if let Some(task) = self.inflight.take() {
            task.abort();
        }
        self.st.agent_disconnected(self.agent, self.conn);
    }
}

enum Outcome {
    Reply(AgentServerMsg),
    /// A reply followed by a binary frame.
    ReplyWithBytes(AgentServerMsg, Vec<u8>),
    Nothing,
    Fatal(WsErrorCode),
}

/// Fetches one connection may have in flight.
const MAX_FETCHES_IN_FLIGHT: usize = 2;

fn internal(e: impl std::fmt::Display) -> Outcome {
    error!(error = %e, "agent request failed");
    Outcome::Fatal(WsErrorCode::Internal)
}

async fn welcome(st: &AppState, agent: Id) -> Result<Option<AgentServerMsg>, db::DbError> {
    let found =
        st.db.call(move |c| Ok((db::member(c, agent)?, db::agent_model(c, agent)?))).await?;
    let (Some(you), model) = found else { return Ok(None) };
    let (instructions, context_messages) = model
        .map(|m| (m.settings.instructions, m.settings.context_messages))
        .unwrap_or((String::new(), DEFAULT_CONTEXT_MESSAGES));
    Ok(Some(AgentServerMsg::Welcome {
        protocol_version: PROTOCOL_VERSION,
        server_time_ms: st.clock.now_ms(),
        you,
        instructions,
        max_content_bytes: u32::try_from(st.cfg.limits.max_message_bytes).unwrap_or(u32::MAX),
        context_messages,
        max_depth: st.cfg.agents.max_depth,
        max_frame_bytes: u32::try_from(st.cfg.agents.max_ws_message_bytes).unwrap_or(u32::MAX),
        plugins: plugins::granted(st, agent).await?,
    }))
}

async fn run(st: Arc<AppState>, session: AgentSession, mut socket: WebSocket) {
    let agent = session.agent;
    // Subscribe first, then re-check, so a revocation in between isn't missed.
    let mut revocations = st.subscribe_revocations();
    let mut messages = st.subscribe_messages();
    let mut events = st.subscribe_events();
    match token_state(&st, session.token_hash).await {
        Ok(TokenState::Valid(a)) if a == agent => {}
        Ok(TokenState::Paused) => return close(socket, Some(WsErrorCode::AgentsPaused)).await,
        _ => return close(socket, Some(WsErrorCode::SessionEnded)).await,
    }
    let hello = match welcome(&st, agent).await {
        Ok(Some(w)) => w,
        Ok(None) => return close(socket, Some(WsErrorCode::SessionEnded)).await,
        Err(e) => {
            error!(error = %e, "agent welcome failed");
            return close(socket, Some(WsErrorCode::Internal)).await;
        }
    };
    let mut presence = Presence { st: &st, agent, conn: st.agent_connected(agent), inflight: None };
    if !send(&mut socket, hello).await {
        return;
    }
    info!(%agent, "agent runtime connected");
    st.audit_throttled(agent, "agent_connected", String::new()).await;

    let limits = &st.cfg.limits;
    let mut bucket = Bucket::new(limits.ws_messages_per_sec, limits.ws_burst);
    let idle = Duration::from_secs(limits.ws_idle_timeout_secs);
    let mut last_rx = Instant::now();
    let mut keepalive = interval(idle / 3);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut recheck = interval(RECHECK);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    recheck.tick().await;
    let (results_tx, mut results) = mpsc::channel::<AgentServerMsg>(4);
    let fetch_slots = Arc::new(tokio::sync::Semaphore::new(MAX_FETCHES_IN_FLIGHT));

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                last_rx = Instant::now();
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                if !bucket.take() {
                    debug!(%agent, "agent rate limit exceeded");
                    return close(socket, Some(WsErrorCode::RateLimited)).await;
                }
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) | Message::Close(_) => {
                        return close(socket, Some(WsErrorCode::BadFrame)).await;
                    }
                };
                let env = match decode::<AgentEnvelope>(text.as_str().as_bytes()) {
                    Ok(env) => env,
                    Err(e) => {
                        debug!(%agent, reason = %e, "agent frame rejected");
                        return close(socket, Some(WsErrorCode::BadFrame)).await;
                    }
                };
                if env.v != PROTOCOL_VERSION {
                    return close(socket, Some(WsErrorCode::UnsupportedVersion)).await;
                }
                let outcome = match env.msg {
                    AgentMsg::Infer { request_id, turns, tools } => {
                        if presence.inflight.as_ref().is_some_and(|t| !t.is_finished()) {
                            Outcome::Reply(AgentServerMsg::InferFailed {
                                request_id,
                                reason: InferFailure::Busy,
                            })
                        } else {
                            let (st2, tx) = (Arc::clone(&st), results_tx.clone());
                            presence.inflight = Some(tokio::spawn(async move {
                                let msg = match inference::infer(&st2, agent, turns, tools).await {
                                    Ok((reply, usage)) => {
                                        AgentServerMsg::Inferred { request_id, reply, usage }
                                    }
                                    Err(reason) => AgentServerMsg::InferFailed { request_id, reason },
                                };
                                let _ = tx.send(msg).await;
                            }));
                            Outcome::Nothing
                        }
                    }
                    AgentMsg::Fetch { request_id, plugin, url } => {
                        match Arc::clone(&fetch_slots).try_acquire_owned() {
                            Err(_) => Outcome::Reply(AgentServerMsg::FetchFailed {
                                request_id,
                                reason: FetchFailure::RateLimited,
                            }),
                            Ok(permit) => {
                                let (st2, tx) = (Arc::clone(&st), results_tx.clone());
                                tokio::spawn(async move {
                                    let msg = match fetch_for(&st2, agent, plugin, &url).await {
                                        Ok(fetched) => AgentServerMsg::Fetched { request_id, fetched },
                                        Err(reason) => AgentServerMsg::FetchFailed { request_id, reason },
                                    };
                                    drop(permit);
                                    let _ = tx.send(msg).await;
                                });
                                Outcome::Nothing
                            }
                        }
                    }
                    other => handle(&st, agent, presence.conn, other).await,
                };
                match outcome {
                    Outcome::Reply(reply) => {
                        if !send(&mut socket, reply).await {
                            break;
                        }
                    }
                    Outcome::ReplyWithBytes(reply, bytes) => {
                        let sent = send(&mut socket, reply).await
                            && matches!(
                                timeout(SEND_TIMEOUT, socket.send(Message::Binary(bytes.into()))).await,
                                Ok(Ok(()))
                            );
                        if !sent {
                            break;
                        }
                    }
                    Outcome::Nothing => {}
                    Outcome::Fatal(code) => return close(socket, Some(code)).await,
                }
            }
            Some(result) = results.recv() => {
                if !send(&mut socket, result).await {
                    break;
                }
            }
            event = messages.recv() => {
                let push = match event {
                    Ok(ev) if ev.members.contains(&agent) => {
                        Some(AgentServerMsg::NewMessage { message: ev.message.clone() })
                    }
                    Ok(_) => None,
                    Err(RecvError::Lagged(_)) => Some(AgentServerMsg::Resync {}),
                    Err(RecvError::Closed) => break,
                };
                if let Some(push) = push
                    && !send(&mut socket, push).await
                {
                    break;
                }
            }
            event = events.recv() => {
                let push = match event {
                    Ok(StateEvent::ChatsChanged | StateEvent::Profile(_)) | Err(RecvError::Lagged(_)) => {
                        Some(AgentServerMsg::Resync {})
                    }
                    Ok(StateEvent::JobDispatch { agent: a, spec }) if a == agent => {
                        Some(AgentServerMsg::JobRun { job: *spec })
                    }
                    Ok(StateEvent::JobCancel { agent: a, run_id }) if a == agent => {
                        Some(AgentServerMsg::JobCancelled { run_id })
                    }
                    Ok(StateEvent::PluginsChanged) => match plugins::granted(&st, agent).await {
                        Ok(plugins) => Some(AgentServerMsg::Plugins { plugins }),
                        Err(e) => {
                            error!(error = %e, "reading agent plugins failed");
                            None
                        }
                    },
                    Ok(StateEvent::AgentSettingsChanged(a)) if a == agent => {
                        match st.db.call(move |c| db::agent_model(c, agent)).await {
                            Ok(Some(m)) => Some(AgentServerMsg::Settings {
                                instructions: m.settings.instructions,
                                context_messages: m.settings.context_messages,
                            }),
                            Ok(None) => None,
                            Err(e) => {
                                error!(error = %e, "reading agent settings failed");
                                None
                            }
                        }
                    }
                    Ok(_) => None,
                    Err(RecvError::Closed) => break,
                };
                if let Some(push) = push
                    && !send(&mut socket, push).await
                {
                    break;
                }
            }
            revoked = revocations.recv() => {
                let code = match revoked {
                    Ok(Revocation::AgentToken(a)) if a == agent => Some(WsErrorCode::SessionEnded),
                    Ok(Revocation::AgentReplaced { agent: a, keep }) if a == agent && keep != presence.conn => {
                        Some(WsErrorCode::Replaced)
                    }
                    Ok(Revocation::AgentsPaused) => Some(WsErrorCode::AgentsPaused),
                    Ok(_) => None,
                    Err(RecvError::Lagged(_)) => match token_state(&st, session.token_hash).await {
                        Ok(TokenState::Valid(a)) if a == agent => None,
                        Ok(TokenState::Paused) => Some(WsErrorCode::AgentsPaused),
                        _ => Some(WsErrorCode::SessionEnded),
                    },
                    Err(RecvError::Closed) => Some(WsErrorCode::SessionEnded),
                };
                if let Some(code) = code {
                    info!(%agent, ?code, "agent runtime disconnected by the server");
                    return close(socket, Some(code)).await;
                }
            }
            _ = recheck.tick() => {
                let code = match token_state(&st, session.token_hash).await {
                    Ok(TokenState::Valid(a)) if a == agent => None,
                    Ok(TokenState::Paused) => Some(WsErrorCode::AgentsPaused),
                    _ => Some(WsErrorCode::SessionEnded),
                };
                if let Some(code) = code {
                    return close(socket, Some(code)).await;
                }
            }
            _ = keepalive.tick() => {
                if last_rx.elapsed() >= idle {
                    return close(socket, None).await;
                }
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
    drop(presence);
    debug!(%agent, "agent runtime connection closed");
}

async fn handle(st: &AppState, agent: Id, conn: u64, msg: AgentMsg) -> Outcome {
    // The largest frame this socket can send: the tungstenite write buffer's cap.
    let frame_budget = 4 * st.cfg.agents.max_ws_message_bytes;
    match msg {
        AgentMsg::Ping { nonce } => Outcome::Reply(AgentServerMsg::Pong { nonce }),
        AgentMsg::ListChats {} => match chat_ops::list_chats(st, agent, frame_budget).await {
            Ok(chats) => Outcome::Reply(AgentServerMsg::Chats { chats }),
            Err(e) => internal(e),
        },
        AgentMsg::Sync { chat_id, after_seq, limit } => {
            if after_seq < 0 || limit == 0 || limit > MAX_SYNC_LIMIT {
                return Outcome::Fatal(WsErrorCode::InvalidRequest);
            }
            match chat_ops::sync(st, agent, chat_id, after_seq, limit, frame_budget).await {
                Ok(Some((messages, has_more))) => {
                    Outcome::Reply(AgentServerMsg::Messages { chat_id, messages, has_more })
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::Forbidden),
                Err(e) => internal(e),
            }
        }
        AgentMsg::Send { chat_id, client_msg_id, content, in_reply_to } => {
            let post = chat_ops::Post { chat_id, client_msg_id, content, in_reply_to };
            match chat_ops::post(st, agent, post).await {
                PostOutcome::Sent { client_msg_id, id, seq } => {
                    Outcome::Reply(AgentServerMsg::Sent { client_msg_id, id, seq })
                }
                PostOutcome::Refused(reason) => {
                    st.audit_throttled(agent, "agent_post_refused", format!("{reason:?}")).await;
                    Outcome::Reply(AgentServerMsg::SendRefused { client_msg_id, reason })
                }
                PostOutcome::Fatal(code) => Outcome::Fatal(code),
            }
        }
        AgentMsg::Working { chat_id, working } => {
            match st.db.call(move |c| db::chat_if_member(c, chat_id, agent)).await {
                Ok(Some(_)) => {
                    st.agent_working(agent, conn, working.then_some(chat_id));
                    Outcome::Nothing
                }
                Ok(None) => Outcome::Fatal(WsErrorCode::Forbidden),
                Err(e) => internal(e),
            }
        }
        AgentMsg::GetPlugin { plugin } => {
            match st.db.call(move |c| db::granted_plugin_code(c, agent, plugin)).await {
                Ok(Some(code)) => match u32::try_from(code.len()) {
                    Ok(bytes) => {
                        Outcome::ReplyWithBytes(AgentServerMsg::PluginCode { plugin, bytes }, code)
                    }
                    Err(e) => internal(e),
                },
                Ok(None) => Outcome::Fatal(WsErrorCode::Forbidden),
                Err(e) => internal(e),
            }
        }
        AgentMsg::ProposeJob { request_id, title, prompt, start_in_secs, every_secs } => {
            let now = st.clock.now_ms();
            let schedule = JobSchedule {
                first_run_at_ms: now.saturating_add(i64::from(start_in_secs) * 1000),
                every_secs,
            };
            if let Err(e) = check_job(&title, &prompt, &schedule, now) {
                return Outcome::Reply(AgentServerMsg::JobRefused {
                    request_id,
                    reason: e.to_string(),
                });
            }
            let Ok(id) = crate::auth::random_id() else { return internal("no randomness") };
            let user = st.user_id;
            let created = st
                .db
                .call(move |c| {
                    if db::agents_paused(c)? {
                        return Ok(Err("agents are paused"));
                    }
                    let (open, proposals) = db::open_jobs_of(c, agent)?;
                    if open >= MAX_OPEN_JOBS_PER_AGENT as i64
                        || proposals >= MAX_PROPOSALS_PER_AGENT as i64
                    {
                        return Ok(Err("you have too many open jobs and proposals already"));
                    }
                    let Some(chat_id) = db::direct_chat_of(c, agent, user)? else {
                        return Ok(Err("you have no chat with your user"));
                    };
                    let new = db::NewJob {
                        id,
                        agent,
                        chat_id,
                        title: &title,
                        prompt: &prompt,
                        schedule,
                        state: JobState::Proposed,
                        proposed_by_agent: true,
                    };
                    db::create_job(c, &new, now)?;
                    db::audit(c, now, Some(agent), "job_proposed", Some(id), &title)?;
                    Ok(Ok(()))
                })
                .await;
            match created {
                Ok(Ok(())) => {
                    crate::jobs::changed(st, id).await;
                    Outcome::Reply(AgentServerMsg::JobProposed { request_id, job: id })
                }
                Ok(Err(reason)) => {
                    Outcome::Reply(AgentServerMsg::JobRefused { request_id, reason: reason.into() })
                }
                Err(e) => internal(e),
            }
        }
        AgentMsg::JobProgress { run_id, text } => {
            let now = st.clock.now_ms();
            let text = crate::jobs::clean(&text, MAX_PROGRESS_CHARS);
            let job = st
                .db
                .call(move |c| {
                    let job = db::open_run_of(c, run_id, agent)?;
                    if let Some(job) = job {
                        db::set_job_progress(c, job, &text, now)?;
                    }
                    Ok(job)
                })
                .await;
            match job {
                Ok(Some(job)) => {
                    crate::jobs::changed(st, job).await;
                    Outcome::Nothing
                }
                // A run that was just cancelled or timed out: nothing to update.
                Ok(None) => Outcome::Nothing,
                Err(e) => internal(e),
            }
        }
        AgentMsg::JobDone { run_id, ok, detail } => {
            let now = st.clock.now_ms();
            let detail = crate::jobs::clean(&detail, 500);
            let outcome = if ok { RunOutcome::Ok } else { RunOutcome::Failed };
            let job = st
                .db
                .call(move |c| {
                    if db::open_run_of(c, run_id, agent)?.is_none() {
                        return Ok(None);
                    }
                    db::finish_run(c, run_id, outcome, &detail, true, now)
                })
                .await;
            match job {
                Ok(Some(job)) => {
                    crate::jobs::changed(st, job).await;
                    Outcome::Nothing
                }
                Ok(None) => Outcome::Nothing,
                Err(e) => internal(e),
            }
        }
        // Handled by the caller (it runs concurrently).
        AgentMsg::Fetch { request_id, .. } => {
            Outcome::Reply(AgentServerMsg::FetchFailed { request_id, reason: FetchFailure::Failed })
        }
        // Handled by the caller (it needs the connection's state).
        AgentMsg::Infer { request_id, .. } => Outcome::Reply(AgentServerMsg::InferFailed {
            request_id,
            reason: InferFailure::InvalidRequest,
        }),
    }
}

/// A fetch for one of this agent's plugins: granted host, under the rate limit, not
/// paused, and then `fetch::get`'s own checks (HTTPS, public addresses only).
async fn fetch_for(
    st: &AppState,
    agent: Id,
    plugin: Id,
    url: &str,
) -> Result<Fetched, FetchFailure> {
    if st.db.call(|c| db::agents_paused(c)).await.unwrap_or(true) {
        return Err(FetchFailure::Paused);
    }
    let hosts = match plugins::granted_hosts(st, agent, plugin).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(FetchFailure::NotAllowed),
        Err(e) => {
            error!(error = %e, "reading plugin grants failed");
            return Err(FetchFailure::Failed);
        }
    };
    if !st.take_fetch_slot(agent) {
        return Err(FetchFailure::RateLimited);
    }
    let result = fetch::get(url, &hosts).await;
    if let Err(reason @ (FetchFailure::NotAllowed | FetchFailure::Blocked)) = result {
        st.audit_throttled(agent, "plugin_fetch_refused", format!("{reason:?}")).await;
    }
    result
}
