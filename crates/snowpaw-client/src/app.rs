//! The client's control flow: setup -> login -> live session, on a background tokio
//! runtime. The UI thread only sends `Command`s here and receives display state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use snowpaw_proto::agent::{ApiKeyChange, MAX_AUDIT_PAGE, ModelSettings};
use snowpaw_proto::jobs::{JobSchedule, check_job};
use snowpaw_proto::profile::{self, BlobHash};
use snowpaw_proto::quiz::{MAX_CHOICES, QuizAnswers};
use snowpaw_proto::render::{MAX_SOURCE_IMAGE_BYTES, RenderRequest};
use snowpaw_proto::ws::{
    ClientEnvelope, ClientMsg, Content, MAX_SYNC_LIMIT, ServerEnvelope, ServerMsg, WsErrorCode,
};
use snowpaw_proto::{Id, PROTOCOL_VERSION, SecretString, decode, encode};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::{Instant, interval, sleep_until, timeout};
use tokio_tungstenite::tungstenite::Message;

use crate::config::{self, ClientConfig};
use crate::net::{self, Ws, WsConnectError};
use crate::render::{self, RenderCache, RenderService, Rendered, RenderedImage};
use crate::store::{RenderView, Store};
use crate::timefmt::TimeFmt;
use crate::tls::ConnectError;
use crate::ui::Ui;

#[derive(Debug)]
pub enum Command {
    SaveSetup {
        server: String,
        fingerprint: String,
    },
    OpenSetup,
    CancelSetup,
    Login(SecretString),
    OpenChat(String),
    /// Already validated against the content rules on the UI thread.
    Send(Content),
    Logout,
    /// The effective theme changed (system switch or the appearance preference).
    Theme(bool),
    /// Filter the chat list.
    Search(String),
    /// Pin or unpin a chat at the top of the sidebar (at most three).
    TogglePin(String),
    /// Display preferences: font family ("" = default, "System" = OS font) and
    /// appearance ("system" | "light" | "dark").
    SetFont(String),
    SetAppearance(String),
    /// Check that a server answers with the pinned certificate, without saving or
    /// logging in. Answered with `Ui::connection_tested`.
    TestConnection {
        server: String,
        fingerprint: String,
    },
    /// Hide the first-run welcome card for good.
    DismissWelcome,
    /// Turn decorative animation off (true) or on, and remember it.
    SetReduceMotion(bool),
    /// Create an agent and open its chat. `picture` is a file the user chose (see
    /// `choose_picture`); it's processed once the agent exists.
    CreateAgent {
        name: String,
        label: String,
        about: String,
        picture: Option<PathBuf>,
    },
    UpdateAgent {
        agent: String,
        name: String,
        label: String,
        about: String,
    },
    /// Make a picture file an agent's profile picture. The file is decoded, cropped
    /// and re-encoded in the sandboxed worker, never in this process.
    SetAvatarFromFile {
        agent: String,
        path: PathBuf,
    },
    ClearAvatar {
        agent: String,
    },
    /// Submit answers to a quiz in the open chat: one entry per question, `None` =
    /// skipped. The server grades them.
    AnswerQuiz {
        message_id: String,
        answers: Vec<Option<usize>>,
    },
    /// A new runtime token for an agent (replaces the old one, which stops working).
    IssueAgentToken {
        agent: String,
    },
    RevokeAgentToken {
        agent: String,
    },
    /// Load an agent's model settings, runtime state and links.
    GetAgentSettings {
        agent: String,
    },
    SetAgentModel {
        agent: String,
        model: ModelSettings,
        api_key: ApiKeyChange,
    },
    /// Let two agents talk (creating their chat the first time), or pause them.
    SetAgentLink {
        a: String,
        b: String,
        allowed: bool,
    },
    /// The kill switch.
    SetAgentsPaused(bool),
    ListPlugins,
    /// Install a plugin file (check it first with `plugin_preview`).
    InstallPlugin {
        path: PathBuf,
    },
    /// Let an agent use a plugin, with these of the hosts it asks for (maybe none).
    GrantPlugin {
        agent: String,
        plugin: String,
        http_hosts: Vec<String>,
    },
    RevokePlugin {
        agent: String,
        plugin: String,
    },
    RemovePlugin {
        plugin: String,
    },
    /// Schedule a job for an agent: first run at `first_run_at_ms` (the UI converts
    /// from local time), repeating every `every_secs` if set.
    CreateJob {
        agent: String,
        title: String,
        prompt: String,
        first_run_at_ms: i64,
        every_secs: Option<u32>,
    },
    /// Approve a job an agent proposed.
    ApproveJob {
        job: String,
    },
    /// Cancel a job (or decline a proposal).
    CancelJob {
        job: String,
    },
    RunJobNow {
        job: String,
    },
    /// Load the newest audit entries, or (`older`) the page after those loaded.
    LoadAudit {
        older: bool,
    },
}

/// Open the native "choose a picture" dialog; `done` gets the chosen file. Call on
/// the UI thread. The extension filter is only a convenience: the worker identifies
/// pictures by content and refuses anything else.
pub fn choose_picture(done: impl FnOnce(PathBuf) + 'static) {
    let pick = rfd::AsyncFileDialog::new()
        .set_title("Choose a picture")
        .add_filter("Pictures", &["png", "jpg", "jpeg", "gif", "webp"])
        .pick_file();
    let _ = slint::spawn_local(async move {
        if let Some(file) = pick.await {
            done(file.path().to_path_buf());
        }
    });
}

/// Open the native file dialog for a plugin (`.wasm`); `done` gets the file. Call on
/// the UI thread.
pub fn choose_plugin(done: impl FnOnce(PathBuf) + 'static) {
    let pick = rfd::AsyncFileDialog::new()
        .set_title("Choose a plugin")
        .add_filter("snowpaw plugins", &["wasm"])
        .pick_file();
    let _ = slint::spawn_local(async move {
        if let Some(file) = pick.await {
            done(file.path().to_path_buf());
        }
    });
}

/// What a plugin file says it is and wants, before installing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPreview {
    pub name: String,
    pub version: String,
    pub description: String,
    /// (name as the model sees it, description)
    pub tools: Vec<(String, String)>,
    pub http_hosts: Vec<String>,
    /// `sha256:<hex>` of the file.
    pub sha256: String,
}

/// Read a plugin file's embedded manifest. Never runs the plugin: it only walks the
/// module's section headers and parses JSON. Cheap enough for the UI thread.
pub fn plugin_preview(path: &Path) -> Result<PluginPreview, String> {
    use snowpaw_proto::plugin::{MAX_PLUGIN_BYTES, Manifest, manifest_section};
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| "Couldn't open that file.".to_owned())?;
    let meta = file.metadata().map_err(|_| "Couldn't open that file.".to_owned())?;
    if !meta.is_file() || meta.len() > MAX_PLUGIN_BYTES as u64 {
        return Err("That isn't a plugin file (plugins are at most 4 MB).".into());
    }
    let mut wasm = Vec::new();
    file.take(MAX_PLUGIN_BYTES as u64 + 1)
        .read_to_end(&mut wasm)
        .map_err(|_| "Couldn't read that file.".to_owned())?;
    let manifest = manifest_section(&wasm)
        .and_then(Manifest::parse)
        .map_err(|e| format!("This isn't a snowpaw plugin: {e}."))?;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&wasm);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(PluginPreview {
        tools: manifest.tool_specs().into_iter().map(|t| (t.name, t.description)).collect(),
        name: manifest.name,
        version: manifest.version,
        description: manifest.description,
        http_hosts: manifest.capabilities.http,
        sha256: format!("sha256:{hex}"),
    })
}

/// Longest search query kept.
const MAX_SEARCH_CHARS: usize = 100;
/// Profile pictures fetched at once (each is its own HTTPS request).
const MAX_PICTURE_FETCHES: usize = 4;
/// Reading a chosen picture file must finish within this.
const PICTURE_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Results of background work (picture downloads and uploads).
#[derive(Debug)]
enum Event {
    /// A picture was fetched, hash-checked and decoded (`None`: it failed).
    Avatar(BlobHash, Option<RenderedImage>),
    /// A picture was uploaded for an agent; attach it.
    Uploaded {
        agent: Id,
        hash: BlobHash,
    },
    /// A plugin was installed; refresh the list.
    PluginInstalled,
    Notice(String),
}

/// Credentials for background requests while logged in.
#[derive(Debug)]
struct Auth {
    cfg: ClientConfig,
    token: SecretString,
}

/// Rendering state for code and math.
#[derive(Debug)]
struct Render {
    service: RenderService,
    cache: RenderCache,
    results: UnboundedReceiver<(RenderRequest, Rendered)>,
    dark: bool,
}

/// Everything the session code needs besides the store.
#[derive(Debug)]
struct Ctx<'a> {
    ui: &'a Ui,
    fmt: TimeFmt,
    render: Render,
    /// Settings folder (pins and preferences live here).
    dir: Option<PathBuf>,
    prefs: config::Prefs,
    events_tx: UnboundedSender<Event>,
    events: UnboundedReceiver<Event>,
    /// Set while a session is live.
    auth: Option<Arc<Auth>>,
    fetches: Arc<Semaphore>,
    /// A picture chosen on the "new agent" screen, attached once the agent exists.
    new_agent_picture: Option<PathBuf>,
}

impl Ctx<'_> {
    /// Apply and persist a preference change.
    fn set_pref(&mut self, font: Option<String>, appearance: Option<String>) {
        if let Some(f) = font.and_then(|f| config::Prefs::valid_font(&f)) {
            self.prefs.font = f;
        }
        if let Some(a) = appearance.and_then(|a| config::Appearance::parse(&a)) {
            self.prefs.appearance = a;
        }
        if let Some(dir) = &self.dir {
            let _ = config::save_prefs(dir, &self.prefs);
        }
        self.ui.set_prefs(self.prefs.font.clone(), self.prefs.appearance.as_str().to_owned());
    }

    fn set_reduce_motion(&mut self, on: bool) {
        self.prefs.reduce_motion = on;
        if let Some(dir) = &self.dir {
            let _ = config::save_prefs(dir, &self.prefs);
        }
        self.ui.set_reduce_motion(on);
    }

    fn dismiss_welcome(&mut self) {
        self.prefs.welcomed = true;
        if let Some(dir) = &self.dir {
            let _ = config::save_prefs(dir, &self.prefs);
        }
        self.ui.set_welcome(false);
    }

    /// Fetch pictures we don't have yet, a few at a time.
    fn fetch_avatars(&self, store: &mut Store) {
        let Some(auth) = self.auth.clone() else { return };
        for hash in store.wanted_avatars() {
            let (auth, render, tx, limit) = (
                auth.clone(),
                self.render.service.clone(),
                self.events_tx.clone(),
                self.fetches.clone(),
            );
            tokio::spawn(async move {
                let image = async {
                    let _permit = limit.acquire().await.ok()?;
                    let png = net::fetch_blob(&auth.cfg, &auth.token, hash).await.ok()?;
                    render.decode_avatar(png).await
                }
                .await;
                let _ = tx.send(Event::Avatar(hash, image));
            });
        }
    }

    /// Plugin file -> upload (the server checks it again) -> refresh the list.
    fn install_plugin(&self, path: PathBuf) {
        let Some(auth) = self.auth.clone() else { return };
        let tx = self.events_tx.clone();
        self.ui.set_notice("Installing the plugin…".into());
        tokio::spawn(async move {
            let result = async {
                plugin_preview(&path)?;
                let wasm = tokio::fs::read(&path)
                    .await
                    .map_err(|_| "Couldn't read that file.".to_owned())?;
                net::upload_plugin(&auth.cfg, &auth.token, wasm).await
            }
            .await;
            let _ = tx.send(match result {
                Ok(_) => Event::PluginInstalled,
                Err(e) => Event::Notice(e),
            });
        });
    }

    /// Picture file -> sandboxed normalize -> upload -> attach (via `Event::Uploaded`).
    fn upload_picture(&self, agent: Id, path: PathBuf) {
        let Some(auth) = self.auth.clone() else { return };
        let (render, tx) = (self.render.service.clone(), self.events_tx.clone());
        self.ui.set_notice("Preparing the picture…".into());
        tokio::spawn(async move {
            let result = async {
                let file = read_picture(&path).await?;
                let png = render.normalize_avatar(file).await.ok_or(
                    "Couldn't use that picture. Choose a PNG, JPEG, GIF or WebP image.".to_owned(),
                )?;
                let image = render.decode_avatar(png.clone()).await;
                let hash = net::upload_blob(&auth.cfg, &auth.token, png).await?;
                Ok::<_, String>((hash, image))
            }
            .await;
            match result {
                Ok((hash, image)) => {
                    let _ = tx.send(Event::Avatar(hash, image));
                    let _ = tx.send(Event::Uploaded { agent, hash });
                }
                Err(e) => {
                    let _ = tx.send(Event::Notice(e));
                }
            }
        });
    }
}

/// Read a picture the user chose, refusing anything that isn't a regular file of a
/// sane size before reading it.
async fn read_picture(path: &Path) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;
    let read = async {
        let file = tokio::fs::File::open(path).await.map_err(|_| "Couldn't open that file.")?;
        let meta = file.metadata().await.map_err(|_| "Couldn't open that file.")?;
        if !meta.is_file() {
            return Err("That isn't a picture file.".to_owned());
        }
        let too_large = format!(
            "That picture is too large (the limit is {} MB).",
            MAX_SOURCE_IMAGE_BYTES >> 20
        );
        if meta.len() > MAX_SOURCE_IMAGE_BYTES as u64 {
            return Err(too_large);
        }
        let mut data = Vec::new();
        file.take(MAX_SOURCE_IMAGE_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .await
            .map_err(|_| "Couldn't read that file.")?;
        if data.len() > MAX_SOURCE_IMAGE_BYTES {
            return Err(too_large);
        }
        if data.is_empty() {
            return Err("That file is empty.".into());
        }
        Ok(data)
    };
    timeout(PICTURE_READ_TIMEOUT, read).await.map_err(|_| "Reading the file took too long.")?
}

/// Profile text from a form: trimmed, then checked against the same rules as the
/// server (which would otherwise close the connection).
fn profile_fields(
    name: &str,
    label: &str,
    about: &str,
) -> Result<(String, String, String), String> {
    let (name, label, about) = (name.trim(), label.trim(), about.trim());
    profile::check_name(name).map_err(|e| format!("Name: {e}."))?;
    profile::check_label(label).map_err(|e| format!("Role: {e}."))?;
    profile::check_about(about).map_err(|e| format!("About: {e}."))?;
    Ok((name.to_owned(), label.to_owned(), about.to_owned()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
    LoggedOut,
    /// The server ended the session (expired, revoked, password changed).
    Expired,
    PinMismatch,
    /// The window was closed.
    Quit,
}

const DEFAULT_SERVER: &str = "127.0.0.1:7443";
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const PIN_MISMATCH: &str = "The server's certificate no longer matches the fingerprint you saved. \
    Someone may be intercepting the connection. If you re-initialized the server, update the \
    fingerprint in Server settings.";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn label(c: &ClientConfig) -> String {
    format!("Server: {}", c.server)
}

pub async fn run(dir: Option<PathBuf>, mut cmds: UnboundedReceiver<Command>, ui: Ui) {
    let (results_tx, results) = unbounded_channel();
    let service = match render::default_worker_path() {
        Some(path) => RenderService::start(path, results_tx),
        None => RenderService::disabled(),
    };
    let prefs = dir.as_deref().map(config::load_prefs).unwrap_or_default();
    // Before any screen is shown, so even setup/login use the chosen font.
    ui.set_prefs(prefs.font.clone(), prefs.appearance.as_str().to_owned());
    ui.set_welcome(!prefs.welcomed);
    ui.set_reduce_motion(prefs.reduce_motion);
    let (events_tx, events) = unbounded_channel();
    let mut ctx = Ctx {
        ui: &ui,
        fmt: TimeFmt::local(),
        render: Render { service, cache: RenderCache::default(), results, dark: false },
        dir: dir.clone(),
        prefs,
        events_tx,
        events,
        auth: None,
        fetches: Arc::new(Semaphore::new(MAX_PICTURE_FETCHES)),
        new_agent_picture: None,
    };
    let Some(dir) = dir else {
        ui.show_setup(
            DEFAULT_SERVER.into(),
            String::new(),
            "Can't find a folder for settings (HOME isn't set). Start with --settings-dir <DIR>."
                .into(),
            false,
        );
        while cmds.recv().await.is_some() {}
        return;
    };
    let mut settings = match config::load(&dir) {
        Ok(s) => s,
        Err(e) => {
            ui.show_setup(DEFAULT_SERVER.into(), String::new(), e, false);
            None
        }
    };
    if let Some(s) = &settings {
        ui.set_server_info(s.server.clone(), s.fingerprint.clone());
        ui.show_login(label(s), String::new());
    } else {
        ui.show_setup(DEFAULT_SERVER.into(), String::new(), String::new(), false);
    }

    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Command::SaveSetup { server, fingerprint } => {
                let saved = ClientConfig::new(&server, &fingerprint)
                    .and_then(|c| config::save(&dir, &c).map(|()| c));
                match saved {
                    Ok(c) => {
                        // A device token belongs to the server it came from.
                        if settings.as_ref() != Some(&c) {
                            config::forget_device_token(&dir);
                        }
                        ui.set_server_info(c.server.clone(), c.fingerprint.clone());
                        ui.show_login(label(&c), String::new());
                        settings = Some(c);
                    }
                    Err(e) => ui.show_setup(server, fingerprint, e, settings.is_some()),
                }
            }
            Command::OpenSetup => {
                let (s, f) =
                    settings.as_ref().map_or((DEFAULT_SERVER.into(), String::new()), |c| {
                        (c.server.clone(), c.fingerprint.clone())
                    });
                ui.show_setup(s, f, String::new(), settings.is_some());
            }
            Command::CancelSetup => {
                if let Some(c) = &settings {
                    ui.show_login(label(c), String::new());
                }
            }
            Command::Login(password) => {
                let Some(cfg) = settings.clone() else { continue };
                ui.login_busy(true);
                let device = config::load_device_token(&dir);
                let result = net::login(&cfg, &password, device.as_ref()).await;
                drop(password);
                match result {
                    Ok(ok) => {
                        let _ = config::save_device_token(&dir, &ok.device_token);
                        ui.show_main();
                        match session(&cfg, ok.token, &mut cmds, &mut ctx).await {
                            SessionEnd::Quit => return,
                            SessionEnd::LoggedOut => ui.show_login(label(&cfg), String::new()),
                            SessionEnd::Expired => {
                                ui.show_login(
                                    label(&cfg),
                                    "Your session ended. Please log in again.".into(),
                                );
                            }
                            SessionEnd::PinMismatch => {
                                ui.show_login(label(&cfg), PIN_MISMATCH.into())
                            }
                        }
                    }
                    Err(e) => ui.show_login(label(&cfg), e.user_message()),
                }
            }
            Command::Theme(dark) => ctx.render.dark = dark,
            Command::SetFont(f) => ctx.set_pref(Some(f), None),
            Command::SetAppearance(a) => ctx.set_pref(None, Some(a)),
            Command::DismissWelcome => ctx.dismiss_welcome(),
            Command::SetReduceMotion(on) => ctx.set_reduce_motion(on),
            Command::TestConnection { server, fingerprint } => {
                let result = match ClientConfig::new(&server, &fingerprint) {
                    Ok(c) => net::test_connection(&c).await,
                    Err(e) => Err(e),
                };
                match result {
                    Ok(()) => ui.connection_tested(true, String::new()),
                    Err(message) => ui.connection_tested(false, message),
                }
            }
            // Chat commands while logged out are ignored.
            Command::OpenChat(_)
            | Command::Send(_)
            | Command::Logout
            | Command::Search(_)
            | Command::TogglePin(_)
            | Command::CreateAgent { .. }
            | Command::UpdateAgent { .. }
            | Command::SetAvatarFromFile { .. }
            | Command::ClearAvatar { .. }
            | Command::AnswerQuiz { .. }
            | Command::IssueAgentToken { .. }
            | Command::RevokeAgentToken { .. }
            | Command::GetAgentSettings { .. }
            | Command::SetAgentModel { .. }
            | Command::SetAgentLink { .. }
            | Command::SetAgentsPaused(_)
            | Command::LoadAudit { .. }
            | Command::ListPlugins
            | Command::InstallPlugin { .. }
            | Command::GrantPlugin { .. }
            | Command::RevokePlugin { .. }
            | Command::RemovePlugin { .. }
            | Command::CreateJob { .. }
            | Command::ApproveJob { .. }
            | Command::CancelJob { .. }
            | Command::RunJobNow { .. } => {}
        }
    }
}

/// What a command or server message asks us to do next.
enum Step {
    Nothing,
    Send(Vec<ClientMsg>),
    End(SessionEnd),
    /// The connection is unusable; reconnect.
    Reconnect,
}

async fn session(
    cfg: &ClientConfig,
    token: SecretString,
    cmds: &mut UnboundedReceiver<Command>,
    ctx: &mut Ctx<'_>,
) -> SessionEnd {
    let ui = ctx.ui;
    let mut store = Store::default();
    if let Some(dir) = &ctx.dir {
        store.set_pinned(config::load_pins(dir));
    }
    ctx.auth = Some(Arc::new(Auth { cfg: cfg.clone(), token: token.clone() }));
    ctx.new_agent_picture = None;
    let mut backoff = Duration::from_secs(1);
    let end = 'outer: loop {
        ui.set_status("Connecting…".into());
        let reason = match net::connect_ws(cfg, &token).await {
            Ok(ws) => {
                backoff = Duration::from_secs(1);
                match drive(ws, &mut store, cmds, ctx).await {
                    Some(end) => break end,
                    None => "connection lost".to_owned(),
                }
            }
            Err(WsConnectError::Unauthorized) => break SessionEnd::Expired,
            Err(WsConnectError::Connect(ConnectError::PinMismatch)) => {
                break SessionEnd::PinMismatch;
            }
            Err(WsConnectError::Connect(e)) => e.user_message(),
            Err(WsConnectError::Other(e)) => e,
        };
        // Offline: wait, but keep accepting commands (messages queue as pending).
        ui.set_status(format!("Offline: {reason} Retrying in {}s…", backoff.as_secs()));
        let deadline = Instant::now() + backoff;
        loop {
            tokio::select! {
                () = sleep_until(deadline) => break,
                cmd = cmds.recv() => match on_command(cmd, &mut store, ctx) {
                    Step::End(e) => break 'outer e,
                    Step::Nothing | Step::Send(_) | Step::Reconnect => {}
                },
                Some((req, out)) = ctx.render.results.recv() => {
                    ctx.render.cache.insert(req, out);
                    render(&mut store, ctx);
                }
                Some(event) = ctx.events.recv() => {
                    if let Step::Send(_) = on_event(event, &mut store, ctx) {
                        ui.set_notice("You're offline, so the change wasn't saved. Try again \
                            once you're connected.".into());
                    }
                }
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    };
    ctx.auth = None;
    // Revoke the session on the server so it doesn't linger (best effort).
    if matches!(end, SessionEnd::LoggedOut | SessionEnd::Quit) {
        let _ = timeout(Duration::from_secs(3), net::logout(cfg, &token)).await;
    }
    ui.set_status(String::new());
    end
}

async fn send_all(ws: &mut Ws, msgs: Vec<ClientMsg>) -> bool {
    for m in msgs {
        let text = encode(&ClientEnvelope::new(m));
        if ws.send(Message::Text(text.into())).await.is_err() {
            return false;
        }
    }
    true
}

/// Next protocol message. `None`: the connection is gone. `Some(Err)`: the server sent
/// something that isn't valid protocol, which we never try to interpret.
async fn next_msg(ws: &mut Ws) -> Option<Result<ServerMsg, ()>> {
    loop {
        match ws.next().await? {
            Ok(Message::Text(t)) => {
                return Some(match decode::<ServerEnvelope>(t.as_bytes()) {
                    Ok(env) if env.v == PROTOCOL_VERSION => Ok(env.msg),
                    _ => Err(()),
                });
            }
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => continue,
            Ok(Message::Binary(_)) => return Some(Err(())),
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// Run one connection until it drops (None) or the session ends (Some).
async fn drive(
    mut ws: Ws,
    store: &mut Store,
    cmds: &mut UnboundedReceiver<Command>,
    ctx: &mut Ctx<'_>,
) -> Option<SessionEnd> {
    let ui = ctx.ui;
    match timeout(Duration::from_secs(10), next_msg(&mut ws)).await {
        Ok(Some(Ok(ServerMsg::Welcome { you, max_content_bytes, agents_paused, .. }))) => {
            store.me = Some(you);
            store.agents_paused = agents_paused;
            ui.set_agents_paused(agents_paused);
            store.max_content_bytes = max_content_bytes as usize;
            ui.set_max_bytes(max_content_bytes as usize);
        }
        _ => return None,
    }
    ui.set_status(String::new());
    // Pictures that failed while we were offline get another chance.
    store.forget_failed_avatars();
    if !send_all(&mut ws, vec![ClientMsg::ListChats {}, ClientMsg::ListJobs {}]).await {
        return None;
    }
    let mut tick = interval(Duration::from_secs(30));
    loop {
        let step = tokio::select! {
            msg = next_msg(&mut ws) => match msg {
                Some(Ok(m)) => on_server(m, store, ctx),
                Some(Err(())) | None => Step::Reconnect,
            },
            cmd = cmds.recv() => on_command(cmd, store, ctx),
            Some((req, out)) = ctx.render.results.recv() => {
                ctx.render.cache.insert(req, out);
                render(store, ctx);
                Step::Nothing
            }
            Some(event) = ctx.events.recv() => on_event(event, store, ctx),
            _ = tick.tick() => {
                render(store, ctx);
                Step::Nothing
            }
        };
        match step {
            Step::Nothing => {}
            Step::Send(msgs) => {
                if !send_all(&mut ws, msgs).await {
                    return None;
                }
            }
            Step::End(e) => {
                let _ = ws.close(None).await;
                return Some(e);
            }
            Step::Reconnect => return None,
        }
    }
}

fn render(store: &mut Store, ctx: &mut Ctx<'_>) {
    ctx.fetch_avatars(store);
    let now = now_ms();
    let fmt = &ctx.fmt;
    // The open chat counts as read.
    if let Some(chat) = store.current {
        store.mark_read(chat);
    }
    ctx.ui.set_chat_list(store.chat_rows(fmt, now), store.current.map(|c| c.to_string()));
    ctx.ui.set_conversation(store.current.and_then(|c| store.conversation(c, fmt, now)));
    let Some(chat) = store.current else {
        ctx.ui.set_timeline(vec![]);
        return;
    };
    let view = RenderView { cache: &ctx.render.cache, dark: ctx.render.dark };
    let (items, requests) = store.timeline(chat, fmt, now, &view);
    ctx.ui.set_timeline(items);
    for req in requests {
        if ctx.render.cache.want(&req) && !ctx.render.service.request(req.clone()) {
            // No renderer available: remember the plain-text fallback.
            ctx.render.cache.insert(req, Rendered::Failed);
        }
    }
}

fn on_event(event: Event, store: &mut Store, ctx: &mut Ctx<'_>) -> Step {
    match event {
        Event::Avatar(hash, image) => {
            store.set_avatar(hash, image);
            render(store, ctx);
            Step::Nothing
        }
        Event::Uploaded { agent, hash } => {
            ctx.ui.set_notice(String::new());
            Step::Send(vec![ClientMsg::SetAvatar { agent, avatar: Some(hash) }])
        }
        Event::PluginInstalled => {
            ctx.ui.set_notice(String::new());
            Step::Send(vec![ClientMsg::ListPlugins {}])
        }
        Event::Notice(n) => {
            ctx.ui.set_notice(n);
            Step::Nothing
        }
    }
}

/// An agent id from the UI, if it's an agent we know.
fn known_agent(store: &Store, id: &str) -> Option<Id> {
    Id::parse(id).ok().filter(|id| store.is_agent(*id))
}

fn sync(chat_id: Id, after_seq: i64) -> ClientMsg {
    ClientMsg::Sync { chat_id, after_seq, limit: MAX_SYNC_LIMIT }
}

fn on_command(cmd: Option<Command>, store: &mut Store, ctx: &mut Ctx<'_>) -> Step {
    let ui = ctx.ui;
    match cmd {
        None => Step::End(SessionEnd::Quit),
        Some(Command::Logout) => Step::End(SessionEnd::LoggedOut),
        Some(Command::OpenChat(id)) => {
            let Ok(id) = Id::parse(&id) else { return Step::Nothing };
            if !store.has_chat(id) {
                return Step::Nothing;
            }
            store.current = Some(id);
            ui.set_notice(String::new());
            render(store, ctx);
            let mut out = vec![sync(id, store.last_seq(id))];
            // The details panel shows the agent's setup.
            if let Some(agent) = store.conversation(id, &ctx.fmt, now_ms()).and_then(|c| c.agent) {
                out.push(ClientMsg::GetAgentSettings { agent });
            }
            Step::Send(out)
        }
        Some(Command::Send(content)) => {
            let Some(chat_id) = store.current else { return Step::Nothing };
            if store.conversation(chat_id, &ctx.fmt, now_ms()).is_some_and(|c| c.read_only) {
                ui.set_notice("This conversation is between agents. You can read along.".into());
                return Step::Nothing;
            }
            let mut b = [0u8; 16];
            if getrandom::fill(&mut b).is_err() {
                ui.set_notice("Couldn't send: no randomness available.".into());
                return Step::Nothing;
            }
            let client_msg_id = Id::from_bytes(b);
            if store.add_pending(chat_id, client_msg_id, content.clone()).is_none() {
                return Step::Nothing;
            }
            render(store, ctx);
            Step::Send(vec![ClientMsg::Send { chat_id, client_msg_id, content }])
        }
        Some(Command::Theme(dark)) => {
            ctx.render.dark = dark;
            render(store, ctx);
            Step::Nothing
        }
        Some(Command::Search(q)) => {
            store.search = q.chars().filter(|c| !c.is_control()).take(MAX_SEARCH_CHARS).collect();
            render(store, ctx);
            Step::Nothing
        }
        Some(Command::TogglePin(id)) => {
            let Ok(id) = Id::parse(&id) else { return Step::Nothing };
            if store.toggle_pin(id) {
                if let Some(dir) = &ctx.dir {
                    let _ = config::save_pins(dir, store.pinned());
                }
            } else {
                ui.set_notice(format!("You can pin up to {} chats.", crate::store::MAX_PINNED));
            }
            render(store, ctx);
            Step::Nothing
        }
        Some(Command::SetFont(f)) => {
            ctx.set_pref(Some(f), None);
            Step::Nothing
        }
        Some(Command::SetAppearance(a)) => {
            ctx.set_pref(None, Some(a));
            Step::Nothing
        }
        Some(Command::DismissWelcome) => {
            ctx.dismiss_welcome();
            Step::Nothing
        }
        Some(Command::SetReduceMotion(on)) => {
            ctx.set_reduce_motion(on);
            Step::Nothing
        }
        Some(Command::CreateAgent { name, label, about, picture }) => {
            match profile_fields(&name, &label, &about) {
                Ok((name, label, about)) => {
                    ctx.new_agent_picture = picture;
                    Step::Send(vec![ClientMsg::CreateAgent { name, label, about }])
                }
                Err(e) => {
                    ui.set_notice(e);
                    Step::Nothing
                }
            }
        }
        Some(Command::UpdateAgent { agent, name, label, about }) => {
            let Some(agent) = known_agent(store, &agent) else { return Step::Nothing };
            match profile_fields(&name, &label, &about) {
                Ok((name, label, about)) => {
                    Step::Send(vec![ClientMsg::UpdateAgent { agent, name, label, about }])
                }
                Err(e) => {
                    ui.set_notice(e);
                    Step::Nothing
                }
            }
        }
        Some(Command::SetAvatarFromFile { agent, path }) => {
            if let Some(agent) = known_agent(store, &agent) {
                ctx.upload_picture(agent, path);
            }
            Step::Nothing
        }
        Some(Command::ClearAvatar { agent }) => match known_agent(store, &agent) {
            Some(agent) => Step::Send(vec![ClientMsg::SetAvatar { agent, avatar: None }]),
            None => Step::Nothing,
        },
        Some(Command::AnswerQuiz { message_id, answers }) => {
            let (Some(chat_id), Ok(quiz_id)) = (store.current, Id::parse(&message_id)) else {
                return Step::Nothing;
            };
            let fits = store.answerable_quiz(chat_id, quiz_id) == Some(answers.len())
                && answers.iter().flatten().all(|a| *a < MAX_CHOICES);
            if !fits {
                return Step::Nothing;
            }
            let answers =
                answers.into_iter().map(|a| a.and_then(|a| u8::try_from(a).ok())).collect();
            let content =
                Content::QuizAnswers { answers: QuizAnswers { quiz_id, answers, results: vec![] } };
            on_command(Some(Command::Send(content)), store, ctx)
        }
        Some(Command::IssueAgentToken { agent }) => match known_agent(store, &agent) {
            Some(agent) => Step::Send(vec![ClientMsg::IssueAgentToken { agent }]),
            None => Step::Nothing,
        },
        Some(Command::RevokeAgentToken { agent }) => match known_agent(store, &agent) {
            Some(agent) => Step::Send(vec![ClientMsg::RevokeAgentToken { agent }]),
            None => Step::Nothing,
        },
        Some(Command::GetAgentSettings { agent }) => match known_agent(store, &agent) {
            Some(agent) => Step::Send(vec![ClientMsg::GetAgentSettings { agent }]),
            None => Step::Nothing,
        },
        Some(Command::SetAgentModel { agent, model, api_key }) => {
            let Some(agent) = known_agent(store, &agent) else { return Step::Nothing };
            let key_ok = match &api_key {
                ApiKeyChange::Set { key } => snowpaw_proto::agent::check_api_key(key.expose()),
                ApiKeyChange::Keep | ApiKeyChange::Clear => Ok(()),
            };
            match model.validate().map(|_| ()).and(key_ok) {
                Ok(()) => Step::Send(vec![ClientMsg::SetAgentModel { agent, model, api_key }]),
                Err(e) => {
                    ui.set_notice(format!("Model settings: {e}."));
                    Step::Nothing
                }
            }
        }
        Some(Command::SetAgentLink { a, b, allowed }) => {
            match (known_agent(store, &a), known_agent(store, &b)) {
                (Some(a), Some(b)) if a != b => {
                    Step::Send(vec![ClientMsg::SetAgentLink { a, b, allowed }])
                }
                _ => Step::Nothing,
            }
        }
        Some(Command::SetAgentsPaused(paused)) => {
            Step::Send(vec![ClientMsg::SetAgentsPaused { paused }])
        }
        Some(Command::ListPlugins) => Step::Send(vec![ClientMsg::ListPlugins {}]),
        Some(Command::InstallPlugin { path }) => {
            ctx.install_plugin(path);
            Step::Nothing
        }
        Some(Command::GrantPlugin { agent, plugin, http_hosts }) => {
            match (known_agent(store, &agent), Id::parse(&plugin)) {
                (Some(agent), Ok(plugin)) => {
                    Step::Send(vec![ClientMsg::GrantPlugin { agent, plugin, http_hosts }])
                }
                _ => Step::Nothing,
            }
        }
        Some(Command::RevokePlugin { agent, plugin }) => {
            match (known_agent(store, &agent), Id::parse(&plugin)) {
                (Some(agent), Ok(plugin)) => {
                    Step::Send(vec![ClientMsg::RevokePlugin { agent, plugin }])
                }
                _ => Step::Nothing,
            }
        }
        Some(Command::RemovePlugin { plugin }) => match Id::parse(&plugin) {
            Ok(plugin) => Step::Send(vec![ClientMsg::RemovePlugin { plugin }]),
            Err(_) => Step::Nothing,
        },
        Some(Command::CreateJob { agent, title, prompt, first_run_at_ms, every_secs }) => {
            let Some(agent) = known_agent(store, &agent) else { return Step::Nothing };
            let (title, prompt) = (title.trim().to_owned(), prompt.trim().to_owned());
            let schedule = JobSchedule { first_run_at_ms, every_secs };
            match check_job(&title, &prompt, &schedule, now_ms()) {
                Ok(()) => Step::Send(vec![ClientMsg::CreateJob { agent, title, prompt, schedule }]),
                Err(e) => {
                    ui.set_notice(format!("Job: {e}."));
                    Step::Nothing
                }
            }
        }
        Some(Command::ApproveJob { job }) => match Id::parse(&job) {
            Ok(job) => Step::Send(vec![ClientMsg::ApproveJob { job }]),
            Err(_) => Step::Nothing,
        },
        Some(Command::CancelJob { job }) => match Id::parse(&job) {
            Ok(job) => Step::Send(vec![ClientMsg::CancelJob { job }]),
            Err(_) => Step::Nothing,
        },
        Some(Command::RunJobNow { job }) => match Id::parse(&job) {
            Ok(job) => Step::Send(vec![ClientMsg::RunJobNow { job }]),
            Err(_) => Step::Nothing,
        },
        Some(Command::LoadAudit { older }) => {
            let before_seq = if older { store.audit_oldest() } else { None };
            if older && before_seq.is_none() {
                return Step::Nothing;
            }
            Step::Send(vec![ClientMsg::ListAudit { before_seq, limit: MAX_AUDIT_PAGE }])
        }
        Some(
            Command::SaveSetup { .. }
            | Command::OpenSetup
            | Command::CancelSetup
            | Command::Login(_)
            | Command::TestConnection { .. },
        ) => Step::Nothing,
    }
}

fn on_server(msg: ServerMsg, store: &mut Store, ctx: &mut Ctx<'_>) -> Step {
    let ui = ctx.ui;
    match msg {
        ServerMsg::Welcome { .. } => Step::Reconnect,
        ServerMsg::Pong { .. } => Step::Nothing,
        ServerMsg::Chats { chats } => {
            let single = (chats.len() == 1).then(|| chats[0].id);
            store.set_chats(chats);
            if store.current.is_none() {
                store.current = single;
            }
            render(store, ctx);
            // Catch up on every chat, then resend anything not yet confirmed (the
            // server deduplicates by client_msg_id, so this is always safe).
            let mut out: Vec<ClientMsg> =
                store.chat_ids().into_iter().map(|c| sync(c, store.last_seq(c))).collect();
            out.extend(store.all_pending().into_iter().map(|(chat_id, p)| ClientMsg::Send {
                chat_id,
                client_msg_id: p.client_msg_id,
                content: p.content,
            }));
            Step::Send(out)
        }
        ServerMsg::Messages { chat_id, messages, has_more } => {
            let last = messages.last().map(|m| m.seq);
            store.add_messages(chat_id, messages);
            render(store, ctx);
            match (has_more, last) {
                (true, Some(seq)) => Step::Send(vec![sync(chat_id, seq)]),
                _ => Step::Nothing,
            }
        }
        ServerMsg::Sent { client_msg_id, seq, .. } => {
            // Normally the message arrives as a push right after this; a retry of an
            // already-stored message doesn't get one, so fetch it explicitly.
            let chat = store.chat_ids().into_iter().find(|c| store.is_pending(*c, client_msg_id));
            match chat {
                Some(c) => {
                    Step::Send(vec![ClientMsg::Sync { chat_id: c, after_seq: seq - 1, limit: 1 }])
                }
                None => Step::Nothing,
            }
        }
        ServerMsg::NewMessage { message } => {
            let chat = message.chat_id;
            if !store.has_chat(chat) {
                // A chat we haven't seen: refresh the list.
                return Step::Send(vec![ClientMsg::ListChats {}]);
            }
            store.add_messages(chat, vec![message]);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::Resync {} => Step::Send(vec![ClientMsg::ListChats {}]),
        ServerMsg::AgentCreated { chat_id, agent } => {
            // Open the new agent's chat once the refreshed list arrives.
            store.current = Some(chat_id);
            if let Some(path) = ctx.new_agent_picture.take() {
                ctx.upload_picture(agent.id, path);
            }
            Step::Send(vec![ClientMsg::ListChats {}])
        }
        ServerMsg::ProfileChanged { member } => {
            store.update_member(&member);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::AgentToken { agent, token, code } => {
            // Shown once, with the code the runtime needs to find and trust the server.
            ui.show_agent_token(agent.to_string(), token, code);
            Step::Nothing
        }
        ServerMsg::AgentSettings { agent, settings } => {
            store.set_agent_settings(agent, settings);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::AgentStatus { agent, connected, working_in } => {
            store.set_agent_status(agent, connected, working_in);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::AgentsPaused { paused } => {
            store.agents_paused = paused;
            ui.set_agents_paused(paused);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::Jobs { jobs } => {
            store.jobs = jobs;
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::JobChanged { job } => {
            store.update_job(job);
            render(store, ctx);
            Step::Nothing
        }
        ServerMsg::Plugins { plugins } => {
            ui.set_plugins(plugins.clone());
            store.plugins = plugins;
            Step::Nothing
        }
        ServerMsg::Audit { entries, has_more } => {
            let first = store.audit.is_empty()
                || entries.first().map(|e| e.seq) > store.audit.first().map(|e| e.seq);
            store.add_audit(entries, has_more, first);
            ui.set_audit(store.audit.clone(), store.audit_more);
            Step::Nothing
        }
        ServerMsg::Error { code: WsErrorCode::SessionEnded } => Step::End(SessionEnd::Expired),
        ServerMsg::Error { code } => {
            ui.set_notice(format!("The server closed the connection ({code:?})."));
            Step::Reconnect
        }
    }
}
