//! HTTP routes. Deny by default: every route except login sits behind the session
//! check, unknown paths are 404, and anything that looks like it came from a browser
//! is refused before routing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use sha2::{Digest, Sha256};
use snowpaw_proto::agent::AGENT_WS_PATH;
use snowpaw_proto::http::{BLOBS_PATH, BlobUploaded, PLUGINS_PATH, PluginInstalled};
use snowpaw_proto::http::{
    ErrorBody, ErrorCode, LOGIN_PATH, LOGOUT_ALL_PATH, LOGOUT_PATH, LoginRequest, LoginResponse,
    WS_PATH,
};
use snowpaw_proto::plugin::{MAX_PLUGIN_BYTES, Manifest, manifest_section};
use snowpaw_proto::profile::{AVATAR_SIDE, BlobHash, MAX_AVATAR_BYTES, png_dimensions};
use snowpaw_proto::{
    DEVICE_TOKEN_PREFIX, Id, MAX_PASSWORD_BYTES, SESSION_TOKEN_PREFIX, decode, encode,
};
use tokio::sync::{Semaphore, broadcast};
use tracing::{error, info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{self, RandomToken};
use crate::clock::Clock;
use crate::config::Config;
use crate::db::{self, Db, DbError, SessionRow};
use crate::secrets::Secrets;
use crate::{agent_ws, ws};

/// Don't write `last_seen` on every request; once a minute is plenty for idle expiry.
const TOUCH_INTERVAL_MS: i64 = 60_000;

/// The peer's socket address, attached by the listener.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

/// A live session that ended. Open WebSockets for it must close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    Session([u8; 32]),
    AllFor(Id),
    /// An agent's runtime token was revoked or replaced.
    AgentToken(Id),
    /// A newer runtime connection for this agent took over; others close.
    AgentReplaced {
        agent: Id,
        keep: u64,
    },
    /// The kill switch: every agent connection closes.
    AgentsPaused,
}

/// A message was stored; members' open sockets should hear about it.
#[derive(Debug)]
pub struct MessageEvent {
    pub members: Vec<Id>,
    pub message: snowpaw_proto::ws::MessageView,
}

/// Changes to shared state that open sockets should hear about.
#[derive(Debug, Clone)]
pub enum StateEvent {
    /// A profile changed.
    Profile(snowpaw_proto::ws::Member),
    /// The set of chats changed (e.g. an agent was created): clients should relist.
    ChatsChanged,
    AgentStatus {
        agent: Id,
        connected: bool,
        working_in: Option<Id>,
    },
    AgentsPaused(bool),
    /// The user changed an agent's settings: its runtime gets the new instructions.
    AgentSettingsChanged(Id),
    /// Plugins or grants changed: runtimes reload their list.
    PluginsChanged,
    JobChanged(Box<snowpaw_proto::jobs::JobView>),
    /// Hand a job run to this agent's runtime.
    JobDispatch {
        agent: Id,
        spec: Box<snowpaw_proto::jobs::JobSpec>,
    },
    /// Tell this agent's runtime to stop a run.
    JobCancel {
        agent: Id,
        run_id: Id,
    },
}

/// A connected agent runtime.
#[derive(Debug, Clone, Copy)]
struct Presence {
    conn: u64,
    working_in: Option<Id>,
}

/// The authenticated session for this request (set by `require_session`).
#[derive(Debug, Clone, Copy)]
pub struct AuthSession {
    pub token_hash: [u8; 32],
    pub principal_id: Id,
    pub expires_at_ms: i64,
}

#[derive(Debug)]
pub struct AppState {
    pub db: Db,
    pub cfg: Arc<Config>,
    pub clock: Arc<dyn Clock>,
    pub user_id: Id,
    /// One password check at a time: Argon2id costs 64 MiB, so unbounded concurrency
    /// would let anyone who can reach the port exhaust memory. Also serializes the
    /// throttle read-modify-write so parallel guesses can't race past the limit.
    login_gate: Semaphore,
    revocations: broadcast::Sender<Revocation>,
    messages: broadcast::Sender<Arc<MessageEvent>>,
    events: broadcast::Sender<StateEvent>,
    pub secrets: Secrets,
    /// The connection code agent runtimes use (shown with each new runtime token).
    pub agent_code: String,
    /// Connected agent runtimes (at most one per agent).
    presence: Mutex<HashMap<Id, Presence>>,
    next_conn: AtomicU64,
    /// When each (agent, refusal) was last written to the audit log, so a runtime
    /// hammering a limit can't flood it.
    refusals_audited: Mutex<HashMap<(Id, &'static str), i64>>,
    /// Recent fetch times per agent (a sliding one-minute window).
    fetches: Mutex<HashMap<Id, std::collections::VecDeque<i64>>>,
}

impl AppState {
    pub fn new(
        db: Db,
        cfg: Arc<Config>,
        clock: Arc<dyn Clock>,
        user_id: Id,
        secrets: Secrets,
        agent_code: String,
    ) -> Self {
        let (revocations, _) = broadcast::channel(256);
        let (messages, _) = broadcast::channel(1024);
        let (events, _) = broadcast::channel(256);
        Self {
            db,
            cfg,
            clock,
            user_id,
            login_gate: Semaphore::new(1),
            revocations,
            messages,
            events,
            secrets,
            agent_code,
            presence: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            refusals_audited: Mutex::new(HashMap::new()),
            fetches: Mutex::new(HashMap::new()),
        }
    }

    /// Count a fetch for `agent` if it's within the per-minute limit.
    pub fn take_fetch_slot(&self, agent: Id) -> bool {
        let now = self.clock.now_ms();
        let limit = self.cfg.agents.fetches_per_minute as usize;
        let mut all = self.fetches.lock().unwrap_or_else(PoisonError::into_inner);
        let times = all.entry(agent).or_default();
        while times.front().is_some_and(|t| now - t >= 60_000) {
            times.pop_front();
        }
        if times.len() >= limit {
            return false;
        }
        times.push_back(now);
        true
    }

    /// Append to the audit log. Failures are logged, never propagated: auditing
    /// must not break the action (which is also in the server log).
    pub async fn audit(
        &self,
        actor: Option<Id>,
        action: &'static str,
        target: Option<Id>,
        detail: String,
    ) {
        let now = self.clock.now_ms();
        if let Err(e) =
            self.db.call(move |c| db::audit(c, now, actor, action, target, &detail)).await
        {
            error!(error = %e, action, "writing the audit log failed");
        }
    }

    /// Audit a repeatable agent event (a refusal, a reconnect) at most once per 10
    /// minutes per agent and kind.
    pub async fn audit_throttled(&self, agent: Id, action: &'static str, detail: String) {
        let now = self.clock.now_ms();
        let due = {
            let mut seen = self.refusals_audited.lock().unwrap_or_else(PoisonError::into_inner);
            let due = seen.get(&(agent, action)).is_none_or(|t| now - t >= 600_000);
            if due {
                seen.insert((agent, action), now);
            }
            due
        };
        if due {
            self.audit(Some(agent), action, None, detail).await;
        }
    }

    /// Register a new runtime connection for `agent`. Any older one is told to close.
    pub fn agent_connected(&self, agent: Id) -> u64 {
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        self.presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(agent, Presence { conn, working_in: None });
        self.revoke(Revocation::AgentReplaced { agent, keep: conn });
        self.publish_event(StateEvent::AgentStatus { agent, connected: true, working_in: None });
        conn
    }

    pub fn agent_disconnected(&self, agent: Id, conn: u64) {
        let removed = {
            let mut p = self.presence.lock().unwrap_or_else(PoisonError::into_inner);
            let current = p.get(&agent).is_some_and(|x| x.conn == conn);
            if current {
                p.remove(&agent);
            }
            current
        };
        if removed {
            self.publish_event(StateEvent::AgentStatus {
                agent,
                connected: false,
                working_in: None,
            });
        }
    }

    pub fn agent_working(&self, agent: Id, conn: u64, working_in: Option<Id>) {
        let changed = {
            let mut p = self.presence.lock().unwrap_or_else(PoisonError::into_inner);
            match p.get_mut(&agent) {
                Some(x) if x.conn == conn && x.working_in != working_in => {
                    x.working_in = working_in;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.publish_event(StateEvent::AgentStatus { agent, connected: true, working_in });
        }
    }

    pub fn agent_is_connected(&self, agent: Id) -> bool {
        self.presence.lock().unwrap_or_else(PoisonError::into_inner).contains_key(&agent)
    }

    /// (agent, working_in) for every connected runtime.
    pub fn agent_statuses(&self) -> Vec<(Id, Option<Id>)> {
        self.presence
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(a, p)| (*a, p.working_in))
            .collect()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<StateEvent> {
        self.events.subscribe()
    }

    pub fn publish_event(&self, event: StateEvent) {
        let _ = self.events.send(event);
    }

    pub fn subscribe_messages(&self) -> broadcast::Receiver<Arc<MessageEvent>> {
        self.messages.subscribe()
    }

    pub fn publish(&self, event: MessageEvent) {
        // No receivers just means no open sockets.
        let _ = self.messages.send(Arc::new(event));
    }

    pub fn idle_timeout_ms(&self) -> i64 {
        secs_to_ms(self.cfg.auth.session_idle_timeout_secs)
    }

    pub fn subscribe_revocations(&self) -> broadcast::Receiver<Revocation> {
        self.revocations.subscribe()
    }

    pub fn revoke(&self, r: Revocation) {
        // No receivers just means no open sockets.
        let _ = self.revocations.send(r);
    }
}

fn secs_to_ms(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX)
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route(LOGOUT_PATH, post(logout))
        .route(LOGOUT_ALL_PATH, post(logout_all))
        .route(WS_PATH, get(ws::upgrade))
        .route(BLOBS_PATH, post(upload_blob))
        .route("/v1/blobs/{hash}", get(download_blob))
        .route(PLUGINS_PATH, post(install_plugin))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), require_session));
    let agents = Router::new()
        .route(AGENT_WS_PATH, get(agent_ws::upgrade))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), agent_ws::require_agent));
    Router::new()
        .route(LOGIN_PATH, post(login))
        .merge(protected)
        .merge(agents)
        .fallback(|| async { error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound) })
        .method_not_allowed_fallback(|| async {
            error_response(StatusCode::METHOD_NOT_ALLOWED, ErrorCode::MethodNotAllowed)
        })
        .layer(middleware::from_fn(browser_guard))
        .with_state(state)
}

/// The agents-only listener (`server.agent_listen`): the agent endpoint and nothing
/// else, so the agents' network can't even reach login.
pub fn agent_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(AGENT_WS_PATH, get(agent_ws::upgrade))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), agent_ws::require_agent))
        .fallback(|| async { error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound) })
        .method_not_allowed_fallback(|| async {
            error_response(StatusCode::METHOD_NOT_ALLOWED, ErrorCode::MethodNotAllowed)
        })
        .layer(middleware::from_fn(browser_guard))
        .with_state(state)
}

pub fn error_response(status: StatusCode, code: ErrorCode) -> Response {
    let mut resp = (status, encode(&ErrorBody { error: code })).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

pub fn unauthorized() -> Response {
    let mut resp = error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized);
    resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

pub fn internal() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal)
}

/// Native clients never send `Origin` or `Sec-Fetch-*`; browsers always send one or
/// the other. Refusing them means a malicious web page open in your browser can't
/// talk to this server, even on localhost.
async fn browser_guard(req: Request, next: Next) -> Response {
    let h = req.headers();
    if h.contains_key(header::ORIGIN) || h.keys().any(|k| k.as_str().starts_with("sec-fetch-")) {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::ForbiddenOrigin);
    }
    let mut resp = next.run(req).await;
    let hs = resp.headers_mut();
    hs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    hs.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

/// Exactly one `Authorization: Bearer <token>` header, token in canonical form.
/// Tokens anywhere else (query string, cookies) are ignored.
fn bearer_hash(headers: &HeaderMap) -> Option<[u8; 32]> {
    bearer_hash_with(headers, SESSION_TOKEN_PREFIX)
}

/// Same, for a token type with another prefix (agent runtime tokens).
pub fn bearer_hash_with(headers: &HeaderMap, prefix: &str) -> Option<[u8; 32]> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    auth::hash_wire_token(token, prefix)
}

/// Look up a session and check it hasn't expired. Dead sessions are deleted.
pub async fn authenticate(
    st: &AppState,
    token_hash: [u8; 32],
) -> Result<Option<AuthSession>, DbError> {
    let now = st.clock.now_ms();
    let idle = st.idle_timeout_ms();
    st.db
        .call(move |c| {
            let Some(row) = db::session(c, &token_hash)? else {
                return Ok(None);
            };
            if !row.is_live(now, idle) {
                db::delete_session(c, &token_hash)?;
                return Ok(None);
            }
            if now - row.last_seen_at_ms >= TOUCH_INTERVAL_MS {
                db::touch_session(c, &token_hash, now)?;
            }
            Ok(Some(AuthSession {
                token_hash,
                principal_id: row.principal_id,
                expires_at_ms: row.expires_at_ms,
            }))
        })
        .await
}

async fn require_session(
    State(st): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(hash) = bearer_hash(req.headers()) else {
        return unauthorized();
    };
    match authenticate(&st, hash).await {
        Ok(Some(session)) => {
            req.extensions_mut().insert(session);
            next.run(req).await
        }
        Ok(None) => unauthorized(),
        Err(e) => {
            error!(error = %e, "session lookup failed");
            internal()
        }
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
}

/// Read a request body with a size cap and a deadline (no slow-drip bodies).
///
/// The body may hold a password, so it goes into a buffer that is wiped on drop,
/// preallocated so it never reallocates (which would leave an unwiped copy behind).
/// Each frame from hyper is wiped too when we hold its only reference. Copies inside
/// the TLS and HTTP layers are outside our control.
async fn read_body(
    st: &AppState,
    headers: &HeaderMap,
    body: Body,
) -> Result<Zeroizing<Vec<u8>>, (StatusCode, ErrorCode)> {
    read_body_limited(st, headers, body, st.cfg.limits.max_http_body_bytes).await
}

async fn read_body_limited(
    st: &AppState,
    headers: &HeaderMap,
    body: Body,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, (StatusCode, ErrorCode)> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge));
    }
    let deadline = Duration::from_secs(st.cfg.limits.http_body_timeout_secs);
    match tokio::time::timeout(deadline, collect_wiped(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(())) => Err((StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge)),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, ErrorCode::BadRequest)),
    }
}

async fn collect_wiped(mut body: Body, limit: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    use axum::body::HttpBody;
    fn wipe(frame: axum::body::Bytes) {
        if let Ok(mut owned) = frame.try_into_mut() {
            owned.as_mut().zeroize();
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let Ok(data) = frame.map_err(|_| ())?.into_data() else { continue };
        if out.len() + data.len() > limit {
            wipe(data);
            return Err(());
        }
        out.extend_from_slice(&data);
        wipe(data);
    }
    Ok(out)
}

fn too_many(retry_after_ms: Option<i64>) -> Response {
    let mut resp = error_response(StatusCode::TOO_MANY_REQUESTS, ErrorCode::TooManyRequests);
    if let Some(ms) = retry_after_ms {
        let secs = (ms.max(0) + 999) / 1000;
        if let Ok(v) = HeaderValue::from_str(&secs.max(1).to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
    resp
}

/// Which login-throttle bucket an attempt counts against.
#[derive(Debug, Clone, Copy)]
enum Bucket {
    /// A device that logged in before (its device token was valid).
    Device([u8; 32]),
    /// Everyone else, shared.
    Unknown,
}

async fn login(
    State(st): State<Arc<AppState>>,
    peer: Option<axum::Extension<PeerAddr>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer = peer.map(|p| p.0.0);
    if !is_json(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, ErrorCode::UnsupportedMediaType);
    }
    let bytes = match read_body(&st, &headers, body).await {
        Ok(b) => b,
        Err((status, code)) => return error_response(status, code),
    };
    let Ok(req) = decode::<LoginRequest>(&bytes) else {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    drop(bytes);
    if req.password.expose().len() > MAX_PASSWORD_BYTES {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    }
    // A malformed, unknown, or expired device token is treated exactly like none.
    let presented_device = req
        .device_token
        .as_ref()
        .and_then(|t| auth::hash_wire_token(t.expose(), DEVICE_TOKEN_PREFIX));

    // Busy means another password check is running; don't queue (queued checks
    // would hold memory). The client can retry.
    let Ok(_permit) = st.login_gate.try_acquire() else {
        return too_many(None);
    };

    let now = st.clock.now_ms();
    let state = st
        .db
        .call(move |c| {
            let known = match presented_device {
                Some(h) => db::device_throttle(c, &h, now)?.map(|t| (Bucket::Device(h), t)),
                None => None,
            };
            let (bucket, throttle) = match known {
                Some(k) => k,
                None => (Bucket::Unknown, db::throttle(c)?),
            };
            Ok((bucket, throttle, db::password_hash(c)?))
        })
        .await;
    let (bucket, throttle, phc) = match state {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "login: reading auth state failed");
            return internal();
        }
    };
    // While locked, don't even look at the password: the response is identical
    // whether it was right or wrong, so the lock can't be used as an oracle.
    if now < throttle.locked_until_ms {
        return too_many(Some(throttle.locked_until_ms - now));
    }
    let Some(phc) = phc else {
        error!("login: no password is set");
        return unauthorized();
    };

    let password = req.password;
    let verified =
        tokio::task::spawn_blocking(move || auth::verify_password(&password, &phc)).await;
    let ok = match verified {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => {
            error!(error = %e, "login: password verification failed");
            return internal();
        }
        Err(_) => return internal(),
    };

    if !ok {
        let next = auth::after_failure(throttle, now, &st.cfg.auth);
        let saved = st
            .db
            .call(move |c| match bucket {
                Bucket::Device(h) => db::set_device_throttle(c, &h, next),
                Bucket::Unknown => db::set_throttle(c, next),
            })
            .await;
        if let Err(e) = saved {
            error!(error = %e, "login: saving throttle failed");
            return internal();
        }
        let locked_secs = (next.locked_until_ms - now).max(0) / 1000;
        let known_device = matches!(bucket, Bucket::Device(_));
        warn!(peer = ?peer, known_device, failures = next.consecutive_failures, locked_secs, "login failed");
        let from = peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into());
        let device = if known_device { "a known device" } else { "an unknown device" };
        st.audit(
            None,
            "login_failed",
            None,
            format!("from {from} ({device}); locked for {locked_secs}s"),
        )
        .await;
        return unauthorized();
    }

    // Success: fresh session and device tokens every time. A presented session or
    // device token is replaced (rotation), never reused.
    let replaced = bearer_hash(&headers);
    let (token, device) = match (RandomToken::generate(), RandomToken::generate()) {
        (Ok(t), Ok(d)) => (t, d),
        _ => {
            error!("login: token generation failed");
            return internal();
        }
    };
    let expires_at_ms = now.saturating_add(secs_to_ms(st.cfg.auth.session_max_lifetime_secs));
    let row = SessionRow {
        token_hash: token.hash(),
        principal_id: st.user_id,
        created_at_ms: now,
        last_seen_at_ms: now,
        expires_at_ms,
    };
    let device_hash = device.hash();
    let device_expires_ms = now.saturating_add(secs_to_ms(st.cfg.auth.login_device_lifetime_secs));
    let auth_cfg = st.cfg.auth.clone();
    let user_id = st.user_id;
    let idle = st.idle_timeout_ms();
    let result = st
        .db
        .call(move |c| {
            let old_device = match bucket {
                Bucket::Device(h) => Some(h),
                // Only a success from an unknown device clears the shared bucket; a
                // known device logging in must not hand an attacker fresh attempts.
                Bucket::Unknown => {
                    db::set_throttle(c, db::Throttle::default())?;
                    None
                }
            };
            db::rotate_device(
                c,
                old_device,
                device_hash,
                now,
                device_expires_ms,
                auth_cfg.max_login_devices,
            )?;
            if let Some(old) = replaced {
                // Only replace a session that belongs to this user.
                if db::session(c, &old)?.is_some_and(|s| s.principal_id == user_id) {
                    db::delete_session(c, &old)?;
                }
            }
            let evicted = db::insert_session(c, &row, auth_cfg.max_sessions)?;
            db::delete_dead_sessions(c, now, idle)?;
            Ok(evicted)
        })
        .await;
    let evicted = match result {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "login: creating session failed");
            return internal();
        }
    };
    if let Some(old) = replaced {
        st.revoke(Revocation::Session(old));
    }
    for h in evicted {
        st.revoke(Revocation::Session(h));
    }
    info!(peer = ?peer, known_device = matches!(bucket, Bucket::Device(_)), "login succeeded");
    let from = peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into());
    st.audit(Some(st.user_id), "login", None, format!("from {from}")).await;

    let body = encode(&LoginResponse {
        token: token.to_wire(SESSION_TOKEN_PREFIX),
        expires_at_ms,
        device_token: device.to_wire(DEVICE_TOKEN_PREFIX),
    });
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

async fn logout(
    State(st): State<Arc<AppState>>,
    axum::Extension(s): axum::Extension<AuthSession>,
) -> Response {
    let hash = s.token_hash;
    if let Err(e) = st.db.call(move |c| db::delete_session(c, &hash)).await {
        error!(error = %e, "logout failed");
        return internal();
    }
    st.revoke(Revocation::Session(hash));
    info!("logged out");
    StatusCode::NO_CONTENT.into_response()
}

async fn logout_all(
    State(st): State<Arc<AppState>>,
    axum::Extension(s): axum::Extension<AuthSession>,
) -> Response {
    let principal = s.principal_id;
    match st.db.call(move |c| db::delete_sessions_for(c, principal)).await {
        Ok(n) => {
            st.revoke(Revocation::AllFor(principal));
            info!(sessions = n, "logged out everywhere");
            st.audit(Some(principal), "logout_all", None, format!("{n} sessions ended")).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!(error = %e, "logout_all failed");
            internal()
        }
    }
}

fn is_png(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("image/png"))
}

/// Upload a picture. The user only; agents can't set profile pictures. The server
/// never decodes the image: it checks the PNG signature and that the header says
/// 256x256 (clients normalize pictures in their sandbox before uploading), then
/// stores it under its SHA-256.
async fn upload_blob(
    State(st): State<Arc<AppState>>,
    axum::Extension(s): axum::Extension<AuthSession>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if s.principal_id != st.user_id {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::Unauthorized);
    }
    if !is_png(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, ErrorCode::UnsupportedMediaType);
    }
    let bytes = match read_body_limited(&st, &headers, body, MAX_AVATAR_BYTES).await {
        Ok(b) => b,
        Err((status, code)) => return error_response(status, code),
    };
    if png_dimensions(&bytes) != Some((AVATAR_SIDE, AVATAR_SIDE)) {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    }
    let hash = BlobHash::from_bytes(Sha256::digest(&bytes[..]).into());
    let data = bytes.to_vec();
    let now = st.clock.now_ms();
    if let Err(e) = st.db.call(move |c| db::put_blob(c, &hash, "image/png", &data, now)).await {
        error!(error = %e, "storing blob failed");
        return internal();
    }
    let mut resp = (StatusCode::OK, encode(&BlobUploaded { hash })).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn is_wasm(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/wasm"))
}

/// Install (or replace) a plugin. The user only. The module is stored as uploaded;
/// only its manifest section is read here. It runs only in agent runtimes' sandboxes.
async fn install_plugin(
    State(st): State<Arc<AppState>>,
    axum::Extension(s): axum::Extension<AuthSession>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if s.principal_id != st.user_id {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::Unauthorized);
    }
    if !is_wasm(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, ErrorCode::UnsupportedMediaType);
    }
    let bytes = match read_body_limited(&st, &headers, body, MAX_PLUGIN_BYTES).await {
        Ok(b) => b,
        Err((status, code)) => return error_response(status, code),
    };
    let manifest_bytes = match manifest_section(&bytes) {
        Ok(m) => m.to_vec(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidPlugin),
    };
    let Ok(manifest) = Manifest::parse(&manifest_bytes) else {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidPlugin);
    };
    let hash: [u8; 32] = Sha256::digest(&bytes[..]).into();
    let Ok(id) = auth::random_id() else { return internal() };
    let wasm = bytes.to_vec();
    let now = st.clock.now_ms();
    let user = st.user_id;
    let detail = format!(
        "{} {}; may fetch from: {}",
        manifest.name,
        manifest.version,
        if manifest.capabilities.http.is_empty() {
            "nothing".into()
        } else {
            manifest.capabilities.http.join(", ")
        }
    );
    let (name, version) = (manifest.name.clone(), manifest.version.clone());
    let saved = st
        .db
        .call(move |c| {
            let new = db::NewPlugin {
                id,
                name: &name,
                version: &version,
                manifest: &manifest_bytes,
                wasm: &wasm,
                hash: &hash,
            };
            let replaced = db::install_plugin(c, &new, now)?;
            let detail = if replaced.is_some() {
                format!("{detail}; replaced the earlier version")
            } else {
                detail
            };
            db::audit(c, now, Some(user), "plugin_installed", Some(id), &detail)?;
            db::plugin(c, id)
        })
        .await;
    let row = match saved {
        Ok(Some(row)) => row,
        Ok(None) => return internal(),
        Err(e) => {
            error!(error = %e, "installing plugin failed");
            return internal();
        }
    };
    st.publish_event(StateEvent::PluginsChanged);
    let Some(plugin) = crate::plugins::view(&row, vec![]) else { return internal() };
    let mut resp = (StatusCode::OK, encode(&PluginInstalled { plugin })).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

async fn download_blob(
    State(st): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Response {
    let Some(hash) = BlobHash::parse(&hash) else {
        return error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound);
    };
    match st.db.call(move |c| db::get_blob(c, &hash)).await {
        Ok(Some((_, data))) => {
            let mut resp = (StatusCode::OK, data).into_response();
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            resp
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Err(e) => {
            error!(error = %e, "reading blob failed");
            internal()
        }
    }
}
