//! Pushing state into the Slint UI from the network thread.
//!
//! Display data arrives as plain Rust values and is turned into Slint values inside
//! `with`, on the UI thread (models and images aren't `Send`).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use slint::{
    Color, ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString,
    StyledText, VecModel, Weak,
};
use snowpaw_proto::agent::AuditEntry;
use snowpaw_proto::jobs::{JobSchedule, JobState, JobView, RunOutcome};
use snowpaw_proto::plugin::PluginView;
use snowpaw_proto::profile::BlobHash;
use snowpaw_proto::setup_code;
use snowpaw_proto::ws::ChatKind;
use snowpaw_proto::{Id, SecretString};

use crate::render::RenderedImage;
use crate::store::{
    AgentState, Avatar, BlockData, ChatRowData, ConversationData, MessageRowData,
    Person as PersonData, PersonKind, QuizView, Section, TextKind, TimelineItem,
};
use crate::timefmt::TimeFmt;
use crate::{
    AgentLinkRow, AgentSetup, AppWindow, AuditRow, ChatRow, Conversation, HostRow, JobRow,
    MessageRow, MsgBlock, Person, PluginAgentRow, PluginPreview, PluginRow, PluginTool, Quiz,
    QuizQuestion, Theme, TimelineRow,
};

/// Most chats shown as pinned avatars at the top of the sidebar.
const MAX_PINNED: usize = 3;

thread_local! {
    /// Ids of pinned chats from the last chat list, so the open conversation can
    /// offer "Pin" or "Unpin". UI thread only.
    static PINNED: RefCell<Vec<SharedString>> = const { RefCell::new(Vec::new()) };
    /// The sidebar is showing search results (pinned chats then appear in the list).
    static SEARCHING: Cell<bool> = const { Cell::new(false) };
    /// Round profile pictures by content hash. UI thread only.
    static AVATARS: RefCell<HashMap<BlobHash, Image>> = RefCell::new(HashMap::new());
    /// Every agent in the chat list, for an agent's "can talk to" settings.
    static AGENTS: RefCell<Vec<PersonData>> = const { RefCell::new(Vec::new()) };
    /// Quizzes as last received, and the user's unsent answers, by message id.
    static QUIZ_VIEWS: RefCell<HashMap<String, QuizView>> = RefCell::new(HashMap::new());
    static QUIZ_LOCAL: RefCell<HashMap<String, QuizLocal>> = RefCell::new(HashMap::new());
    /// Installed plugins as last received. UI thread only.
    static PLUGINS: RefCell<Vec<PluginView>> = const { RefCell::new(Vec::new()) };
}

/// Most quizzes remembered (they're re-sent with every timeline).
const MAX_QUIZZES: usize = 1000;

/// Most round pictures kept (one per agent, so this is generous).
const MAX_CACHED_AVATARS: usize = 512;

/// Called on the UI thread when the search text changes, before the app filters.
pub fn note_search(text: &str) {
    SEARCHING.with(|s| s.set(!text.trim().is_empty()));
}

#[derive(Clone)]
pub struct Ui {
    weak: Weak<AppWindow>,
}

impl std::fmt::Debug for Ui {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ui")
    }
}

fn color((r, g, b): (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(r, g, b)
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

fn person(p: &PersonData) -> Person {
    Person {
        id: p.id.to_string().into(),
        name: p.name.as_str().into(),
        initials: p.initials.as_str().into(),
        tint: color(p.tint),
        kind: match p.kind {
            PersonKind::Me => "me",
            PersonKind::Agent => "agent",
            PersonKind::Note => "note",
        }
        .into(),
        working: p.working,
        label: p.label.as_str().into(),
        has_avatar: p.avatar.is_some(),
        avatar: p.avatar.as_ref().map(round_avatar).unwrap_or_default(),
    }
}

/// A profile picture cut to a circle (the software renderer can't clip to one),
/// cached by content hash. The pixels were decoded in the sandboxed worker; nothing
/// here reads image files. UI thread only.
fn round_avatar(a: &Avatar) -> Image {
    if let Some(img) = AVATARS.with(|c| c.borrow().get(&a.hash).cloned()) {
        return img;
    }
    let img = Image::from_rgba8_premultiplied(round_pixels(&a.image));
    AVATARS.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() >= MAX_CACHED_AVATARS {
            c.clear();
        }
        c.insert(a.hash, img.clone());
    });
    img
}

/// Clear everything outside the inscribed circle, with a one-pixel soft edge.
fn round_pixels(img: &RenderedImage) -> SharedPixelBuffer<Rgba8Pixel> {
    let mut px = img.pixels.clone();
    let (w, h) = (img.width as f32, img.height as f32);
    let r = w.min(h) / 2.0;
    let width = img.width.max(1) as usize;
    for (i, p) in px.make_mut_slice().iter_mut().enumerate() {
        let x = (i % width) as f32 + 0.5 - w / 2.0;
        let y = (i / width) as f32 + 0.5 - h / 2.0;
        let cover = (r - (x * x + y * y).sqrt() + 0.5).clamp(0.0, 1.0);
        if cover < 1.0 {
            // Premultiplied: every channel scales with coverage.
            let scale = |c: u8| (f32::from(c) * cover).round() as u8;
            *p = Rgba8Pixel { r: scale(p.r), g: scale(p.g), b: scale(p.b), a: scale(p.a) };
        }
    }
    px
}

fn people(ps: &[PersonData]) -> ModelRc<Person> {
    model(ps.iter().map(person).collect())
}

fn chat_row(r: &ChatRowData, section_label: &str, pinned: bool) -> ChatRow {
    ChatRow {
        id: r.id.to_string().into(),
        title: r.title.as_str().into(),
        preview: r.preview.as_str().into(),
        time: r.time.as_str().into(),
        people: people(&r.people),
        pinned,
        unread: i32::try_from(r.unread).unwrap_or(i32::MAX),
        section_label: section_label.into(),
    }
}

/// The sidebar's rows: chats first, then conversations between agents (labelled),
/// plus up to `MAX_PINNED` pinned chats for the top. Pinned chats are left out of
/// the list, except in search results (where the pinned row is hidden).
fn sidebar_rows(rows: &[ChatRowData], searching: bool) -> (Vec<ChatRow>, Vec<ChatRow>) {
    let on_top: Vec<_> = rows.iter().filter(|r| r.pinned).take(MAX_PINNED).map(|r| r.id).collect();
    let mut list = Vec::with_capacity(rows.len());
    for (section, label) in [(Section::Chats, ""), (Section::BetweenAgents, "BETWEEN AGENTS")] {
        let mut labelled = false;
        for r in rows.iter().filter(|r| r.section == section) {
            let top = on_top.contains(&r.id);
            if top && !searching {
                continue;
            }
            let label = if labelled { "" } else { label };
            labelled = true;
            list.push(chat_row(r, label, top));
        }
    }
    let pinned = rows.iter().filter(|r| on_top.contains(&r.id)).map(|r| chat_row(r, "", true));
    (list, pinned.collect())
}

fn conversation(c: ConversationData, pinned: bool) -> Conversation {
    Conversation {
        open: true,
        id: c.id.to_string().into(),
        title: c.title.into(),
        subtitle: c.subtitle.into(),
        people: people(&c.people),
        note: c.note,
        agent: c.kind == ChatKind::Direct,
        agent_id: c.agent.map(|a| a.to_string()).unwrap_or_default().into(),
        about: c.about.into(),
        read_only: c.read_only,
        placeholder: c.composer_placeholder.into(),
        pinned,
        related: model(c.related.iter().map(|r| chat_row(r, "", r.pinned)).collect()),
        setup: agent_setup(c.agent, c.agent_state.as_ref()),
        jobs: model(c.jobs.iter().map(job_row).collect()),
        has_link: c.link.is_some(),
        link_a: c.link.map(|l| l.0.to_string()).unwrap_or_default().into(),
        link_b: c.link.map(|l| l.1.to_string()).unwrap_or_default().into(),
        link_allowed: c.link.is_some_and(|l| l.2),
    }
}

/// Defaults offered for a model that hasn't been set up yet.
const DEFAULT_REPLY_TOKENS: u32 = 2048;
const DEFAULT_CONTEXT_MESSAGES: u32 = 50;
const DEFAULT_DAILY_TOKENS: u64 = 500_000;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// "1,234,567"
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// An agent's model, runtime and links, for its settings page. UI thread only.
fn agent_setup(agent: Option<Id>, state: Option<&AgentState>) -> AgentSetup {
    let Some(state) = state else { return AgentSetup::default() };
    let fmt = TimeFmt::local();
    let now = now_ms();
    let settings = state.settings.as_ref();
    let m = settings.and_then(|s| s.model.as_ref());
    let when = |t: Option<i64>| t.map(|t| fmt.bubble_time(t, now)).unwrap_or_default();
    let links: Vec<AgentLinkRow> = AGENTS.with(|all| {
        all.borrow()
            .iter()
            .filter(|p| Some(p.id) != agent)
            .map(|p| AgentLinkRow {
                agent_id: p.id.to_string().into(),
                person: person(p),
                allowed: settings
                    .and_then(|s| s.links.iter().find(|l| l.agent == p.id))
                    .is_some_and(|l| l.allowed),
            })
            .collect()
    });
    AgentSetup {
        loaded: settings.is_some(),
        connected: state.connected || settings.is_some_and(|s| s.connected),
        has_model: m.is_some(),
        base_url: m.map(|m| m.base_url.as_str()).unwrap_or_default().into(),
        model: m.map(|m| m.model.as_str()).unwrap_or_default().into(),
        tls_pin: m.and_then(|m| m.tls_pin.as_deref()).unwrap_or_default().into(),
        instructions: m.map(|m| m.instructions.as_str()).unwrap_or_default().into(),
        max_reply_tokens: m.map_or(DEFAULT_REPLY_TOKENS, |m| m.max_reply_tokens).to_string().into(),
        context_messages: m
            .map_or(DEFAULT_CONTEXT_MESSAGES, |m| m.context_messages)
            .to_string()
            .into(),
        daily_token_limit: m
            .map_or(DEFAULT_DAILY_TOKENS, |m| m.daily_token_limit)
            .to_string()
            .into(),
        has_api_key: settings.is_some_and(|s| s.has_api_key),
        token_issued: when(settings.and_then(|s| s.token_issued_at_ms)).into(),
        token_last_used: when(settings.and_then(|s| s.token_last_used_at_ms)).into(),
        usage: settings
            .filter(|s| s.tokens_used_24h > 0)
            .map(|s| format!("{} tokens used in the last 24 hours", thousands(s.tokens_used_24h)))
            .unwrap_or_default()
            .into(),
        links: model(links),
    }
}

/// The user's answers to a quiz before (or instead of) the server's grading.
#[derive(Debug, Clone, Default)]
struct QuizLocal {
    picks: Vec<Option<usize>>,
    /// Answering again after a graded submission.
    retrying: bool,
}

fn quiz_row(v: &QuizView) -> Quiz {
    let id = v.message_id.to_string();
    let local = QUIZ_LOCAL.with(|m| m.borrow().get(&id).cloned()).unwrap_or_default();
    QUIZ_VIEWS.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() >= MAX_QUIZZES {
            m.clear();
        }
        m.insert(id.clone(), v.clone());
    });
    let answering = !v.submitted || local.retrying;
    let questions: Vec<QuizQuestion> = v
        .questions
        .iter()
        .enumerate()
        .map(|(i, q)| {
            let picked = if answering { local.picks.get(i).copied().flatten() } else { q.picked };
            QuizQuestion {
                prompt: q.prompt.as_str().into(),
                choices: model(q.choices.iter().map(|c| SharedString::from(c.as_str())).collect()),
                answer: i32::try_from(q.answer).unwrap_or(-1),
                hint: q.hint.as_str().into(),
                explanation: q.explanation.as_str().into(),
                picked: picked.and_then(|p| i32::try_from(p).ok()).unwrap_or(-1),
                // Once graded, a skipped question counts as wrong so its answer shows.
                graded: if answering { -1 } else { i32::from(q.correct == Some(true)) },
            }
        })
        .collect();
    let count = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
    Quiz {
        has: true,
        message_id: id.into(),
        title: v.title.as_str().into(),
        total: count(questions.len()),
        questions: model(questions),
        submitted: !answering,
        right: count(v.score.map_or(0, |s| s.0)),
        answered: count(local.picks.iter().filter(|p| p.is_some()).count()),
        can_answer: v.can_answer,
    }
}

/// Re-show one quiz in the open timeline after a local change. UI thread only.
fn refresh_quiz(w: &AppWindow, message_id: &str) {
    let Some(view) = QUIZ_VIEWS.with(|m| m.borrow().get(message_id).cloned()) else { return };
    let timeline = w.get_timeline();
    for i in 0..timeline.row_count() {
        let Some(mut row) = timeline.row_data(i) else { continue };
        if row.msg.quiz.has && row.msg.quiz.message_id == message_id {
            row.msg.quiz = quiz_row(&view);
            timeline.set_row_data(i, row);
        }
    }
}

/// The user picked a choice in a quiz they haven't submitted. UI thread only.
pub fn quiz_pick(w: &AppWindow, message_id: &str, question: usize, choice: usize) {
    let Some(len) = QUIZ_VIEWS.with(|m| m.borrow().get(message_id).map(|v| v.questions.len()))
    else {
        return;
    };
    if question >= len {
        return;
    }
    QUIZ_LOCAL.with(|m| {
        let mut m = m.borrow_mut();
        let local = m.entry(message_id.to_owned()).or_default();
        local.picks.resize(len, None);
        local.picks[question] = Some(choice);
    });
    refresh_quiz(w, message_id);
}

/// The answers to send for a quiz, one per question (None = skipped). The quiz then
/// shows the server's grading when it arrives. UI thread only.
pub fn quiz_answers(message_id: &str) -> Option<Vec<Option<usize>>> {
    let len = QUIZ_VIEWS.with(|m| m.borrow().get(message_id).map(|v| v.questions.len()))?;
    QUIZ_LOCAL.with(|m| {
        let mut local = m.borrow_mut().remove(message_id).unwrap_or_default();
        local.picks.resize(len, None);
        local.picks.iter().any(Option::is_some).then_some(local.picks)
    })
}

/// Answer a graded quiz again. UI thread only.
pub fn quiz_retry(w: &AppWindow, message_id: &str) {
    QUIZ_LOCAL.with(|m| {
        m.borrow_mut().insert(message_id.to_owned(), QuizLocal { picks: vec![], retrying: true });
    });
    refresh_quiz(w, message_id);
}

/// One installed plugin, with every agent's access to it. UI thread only.
fn plugin_row(v: &PluginView) -> PluginRow {
    let agents: Vec<PluginAgentRow> = AGENTS.with(|all| {
        all.borrow()
            .iter()
            .map(|p| {
                let grant = v.grants.iter().find(|g| g.agent == p.id);
                PluginAgentRow {
                    agent_id: p.id.to_string().into(),
                    person: person(p),
                    granted: grant.is_some(),
                    hosts: model(
                        v.http_hosts
                            .iter()
                            .map(|h| HostRow {
                                host: h.as_str().into(),
                                allowed: grant.is_some_and(|g| g.http_hosts.contains(h)),
                            })
                            .collect(),
                    ),
                }
            })
            .collect()
    });
    PluginRow {
        id: v.id.to_string().into(),
        name: v.name.as_str().into(),
        version: v.version.as_str().into(),
        description: v.description.as_str().into(),
        hash: short_fingerprint(&format!("sha256:{}", v.hash)).into(),
        tools: model(
            v.tools
                .iter()
                .map(|t| PluginTool {
                    name: t.name.as_str().into(),
                    description: t.description.as_str().into(),
                })
                .collect(),
        ),
        hosts: model(v.http_hosts.iter().map(|h| SharedString::from(h.as_str())).collect()),
        agents: model(agents),
    }
}

/// Show the installed plugins. UI thread only (also used by the screenshot tool).
pub fn apply_plugins(w: &AppWindow, plugins: Vec<PluginView>) {
    PLUGINS.with(|p| *p.borrow_mut() = plugins);
    show_plugins(w);
}

fn show_plugins(w: &AppWindow) {
    let rows: Vec<PluginRow> = PLUGINS.with(|p| p.borrow().iter().map(plugin_row).collect());
    w.set_plugins(model(rows));
}

/// The websites an agent may let a plugin reach after switching `host` on or off,
/// or None if that agent hasn't been given the plugin. UI thread only.
pub fn plugin_hosts_toggled(agent: &str, plugin: &str, host: &str) -> Option<Vec<String>> {
    PLUGINS.with(|p| {
        let p = p.borrow();
        let v = p.iter().find(|v| v.id.to_string() == plugin)?;
        if !v.http_hosts.iter().any(|h| h == host) {
            return None;
        }
        let g = v.grants.iter().find(|g| g.agent.to_string() == agent)?;
        let mut hosts: Vec<String> = g.http_hosts.clone();
        if let Some(i) = hosts.iter().position(|h| h == host) {
            hosts.remove(i);
        } else {
            hosts.push(host.to_owned());
        }
        Some(hosts)
    })
}

/// What a plugin file says it can do, before installing it. UI thread only.
pub fn show_plugin_preview(
    w: &AppWindow,
    name: &str,
    version: &str,
    description: &str,
    tools: &[(String, String)],
    hosts: &[String],
    sha256: &str,
) {
    let replaces = PLUGINS.with(|p| p.borrow().iter().any(|v| v.name == name));
    let hash =
        if sha256.starts_with("sha256:") { sha256.to_owned() } else { format!("sha256:{sha256}") };
    w.set_plugin_preview(PluginPreview {
        open: true,
        error: SharedString::new(),
        name: name.into(),
        version: version.into(),
        description: description.into(),
        hash: short_fingerprint(&hash).into(),
        tools: model(
            tools
                .iter()
                .map(|(n, d)| PluginTool {
                    name: n.as_str().into(),
                    description: d.as_str().into(),
                })
                .collect(),
        ),
        hosts: model(hosts.iter().map(|h| SharedString::from(h.as_str())).collect()),
        replaces,
    });
}

/// A plugin file that can't be installed, and why. UI thread only.
pub fn show_plugin_error(w: &AppWindow, message: &str) {
    w.set_plugin_preview(PluginPreview { open: true, error: message.into(), ..Default::default() });
}

const DAY_MS: i64 = 86_400_000;

/// Local wall-clock words for times, from the current UTC offset.
struct Clock {
    offset: i64,
    now: i64,
}

impl Clock {
    fn local() -> Self {
        Self { offset: TimeFmt::local().offset_ms(), now: now_ms() }
    }

    fn day(&self, at: i64) -> i64 {
        (at + self.offset).div_euclid(DAY_MS)
    }

    /// "08:00"
    fn hm(&self, at: i64) -> String {
        let m = (at + self.offset).rem_euclid(DAY_MS) / 60_000;
        format!("{:02}:{:02}", m / 60, m % 60)
    }

    /// "Monday"
    fn weekday(&self, at: i64) -> &'static str {
        // 1970-01-01 was a Thursday.
        const DAYS: [&str; 7] =
            ["Thursday", "Friday", "Saturday", "Sunday", "Monday", "Tuesday", "Wednesday"];
        DAYS[usize::try_from(self.day(at).rem_euclid(7)).unwrap_or(0)]
    }

    /// "today at 08:00", "tomorrow at 08:00", "Friday at 08:00", "Oct 24 at 08:00"
    fn when(&self, at: i64) -> String {
        let days = self.day(at) - self.day(self.now);
        let day = match days {
            0 => "today".to_owned(),
            1 => "tomorrow".to_owned(),
            -1 => "yesterday".to_owned(),
            2..=6 => self.weekday(at).to_owned(),
            _ => {
                let (_, m, d) = civil(self.day(at));
                const MONTHS: [&str; 12] = [
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec",
                ];
                format!("{} {d}", MONTHS[usize::try_from(m - 1).unwrap_or(0)])
            }
        };
        format!("{day} at {}", self.hm(at))
    }

    /// UTC ms of `hh:mm` local time, `days` days from today.
    fn at(&self, days: i64, hour: i64, minute: i64) -> i64 {
        (self.day(self.now) + days) * DAY_MS + (hour * 60 + minute) * 60_000 - self.offset
    }
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// "Every day at 08:00", "Every 2 hours", "Once, tomorrow at 08:00".
fn schedule_words(c: &Clock, s: &JobSchedule) -> String {
    let first = s.first_run_at_ms;
    match s.every_secs {
        None => format!("Once, {}", c.when(first)),
        Some(3600) => "Every hour".to_owned(),
        Some(86_400) => format!("Every day at {}", c.hm(first)),
        Some(604_800) => format!("Every {} at {}", c.weekday(first), c.hm(first)),
        Some(n) if n % 86_400 == 0 => format!("Every {} days at {}", n / 86_400, c.hm(first)),
        Some(n) if n % 3600 == 0 => format!("Every {} hours", n / 3600),
        Some(n) => format!("Every {} minutes", (n / 60).max(1)),
    }
}

fn job_row(j: &JobView) -> JobRow {
    let c = Clock::local();
    let last = match &j.last_run {
        Some(r) => match (r.outcome, r.finished_at_ms) {
            (Some(RunOutcome::Ok), Some(at)) => format!("Last run finished {}", c.when(at)),
            (Some(RunOutcome::Failed), _) => format!("Last run failed: {}", r.detail),
            (Some(RunOutcome::Lost), _) => format!("Last run didn’t finish: {}", r.detail),
            (Some(RunOutcome::Cancelled), _) => "Last run was stopped.".to_owned(),
            _ => String::new(),
        },
        None => String::new(),
    };
    JobRow {
        id: j.id.to_string().into(),
        title: j.title.as_str().into(),
        prompt: j.prompt.as_str().into(),
        state: match j.state {
            JobState::Proposed => "proposed",
            JobState::Active => "active",
            JobState::Done => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
        .into(),
        schedule: schedule_words(&c, &j.schedule).into(),
        next_run: j
            .next_run_at_ms
            .map(|t| format!("Next run {}", c.when(t)))
            .unwrap_or_default()
            .into(),
        running: j.running,
        progress: j.progress.as_str().into(),
        last: last.trim_end_matches(": ").into(),
    }
}

/// When a new job should first run: now, or `hh:mm` today or tomorrow (local time).
/// `start`: 0 now, 1 today, 2 tomorrow.
pub fn job_start_ms(start: i32, time: &str) -> Result<i64, String> {
    let c = Clock::local();
    if start == 0 {
        return Ok(c.now + 2_000);
    }
    let bad = || "Write the time as hours and minutes, like 08:00 or 17:30.".to_owned();
    let t = time.trim().replace('.', ":");
    let (h, m) = match t.split_once(':') {
        Some((h, m)) => (
            h.trim().parse::<i64>().map_err(|_| bad())?,
            m.trim().parse::<i64>().map_err(|_| bad())?,
        ),
        None => (t.parse::<i64>().map_err(|_| bad())?, 0),
    };
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return Err(bad());
    }
    let at = c.at(i64::from(start == 2), h, m);
    if at <= c.now {
        return Err(format!(
            "{h:02}:{m:02} has already passed today. Choose Tomorrow or a later time."
        ));
    }
    Ok(at)
}

/// A plain name for an audit action code.
fn audit_title(action: &str) -> String {
    match action {
        "login" => "Logged in".into(),
        "login_failed" => "Failed login attempt".into(),
        "logout" => "Logged out".into(),
        "password_changed" => "Password changed".into(),
        "session_revoked" => "Session ended".into(),
        "agent_created" => "Agent created".into(),
        "agent_updated" => "Agent edited".into(),
        "agent_token_issued" => "Runtime token issued".into(),
        "agent_token_revoked" => "Runtime token revoked".into(),
        "agent_model_set" | "agent_model_changed" => "Model settings changed".into(),
        "agent_link_set" | "agent_link_changed" => "Agent permissions changed".into(),
        "agents_paused" => "All agents paused".into(),
        "agents_resumed" => "Agents resumed".into(),
        other => {
            let words = other.replace('_', " ");
            let mut c = words.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
        }
    }
}

fn styled(md: &str, plain: &str) -> StyledText {
    // Our markdown is generated and escaped, so this should always parse; if it ever
    // doesn't, show the raw text rather than nothing.
    StyledText::from_markdown(md).unwrap_or_else(|_| StyledText::from_plain_text(plain))
}

fn block(b: BlockData) -> MsgBlock {
    match b {
        BlockData::Text { md, plain, kind } => MsgBlock {
            kind: match kind {
                TextKind::Body => "text",
                TextKind::H1 => "h1",
                TextKind::H2 => "h2",
                TextKind::H3 => "h3",
                TextKind::Quote => "quote",
            }
            .into(),
            styled: styled(&md, &plain),
            ..Default::default()
        },
        BlockData::Code { md, plain } => {
            MsgBlock { kind: "code".into(), styled: styled(&md, &plain), ..Default::default() }
        }
        BlockData::Image { image, width, height, display } => MsgBlock {
            kind: if display { "display" } else { "image" }.into(),
            image: Image::from_rgba8_premultiplied(image.pixels),
            image_width: width,
            image_height: height,
            ..Default::default()
        },
        BlockData::Rule => MsgBlock { kind: "rule".into(), ..Default::default() },
    }
}

/// Must run on the UI thread (models and images aren't `Send`).
pub fn message_row(r: MessageRowData) -> MessageRow {
    let blocks: Vec<MsgBlock> = r.blocks.into_iter().map(block).collect();
    MessageRow {
        id: r.id.into(),
        blocks: model(blocks),
        outgoing: r.outgoing,
        time: r.time.into(),
        pending: r.pending,
        group_start: r.group_start,
        has_sender: r.sender.is_some(),
        sender: r.sender.as_ref().map(person).unwrap_or_default(),
        quiz: r.quiz.as_ref().map(quiz_row).unwrap_or_default(),
    }
}

/// Must run on the UI thread.
pub fn timeline_row(item: TimelineItem) -> TimelineRow {
    match item {
        TimelineItem::Separator(label) => {
            TimelineRow { kind: "separator".into(), label: label.into(), ..Default::default() }
        }
        TimelineItem::Message(m) => {
            TimelineRow { kind: "message".into(), msg: message_row(m), ..Default::default() }
        }
        TimelineItem::Activity { prefix, people: who, target } => TimelineRow {
            kind: "activity".into(),
            label: prefix.into(),
            people: people(&who),
            target: target.to_string().into(),
            ..Default::default()
        },
    }
}

/// Show the chat list. UI thread only (also used directly by the screenshot tool).
pub fn apply_chat_list(w: &AppWindow, rows: &[ChatRowData], selected: Option<String>) {
    let (list, pinned) = sidebar_rows(rows, SEARCHING.with(Cell::get));
    let pinned_ids: Vec<SharedString> =
        rows.iter().filter(|r| r.pinned).map(|r| r.id.to_string().into()).collect();
    let mut conv = w.get_conversation();
    if conv.open {
        let now = pinned_ids.contains(&conv.id);
        if conv.pinned != now {
            conv.pinned = now;
            w.set_conversation(conv);
        }
    }
    PINNED.with(|p| *p.borrow_mut() = pinned_ids);
    AGENTS.with(|a| {
        let mut agents: Vec<PersonData> = Vec::new();
        for p in rows.iter().flat_map(|r| &r.people).filter(|p| p.kind == PersonKind::Agent) {
            if !agents.iter().any(|q| q.id == p.id) {
                agents.push(p.clone());
            }
        }
        agents.sort_by_key(|p| p.name.to_lowercase());
        *a.borrow_mut() = agents;
    });
    // The agents changed, so may each plugin's list of who can use it.
    if PLUGINS.with(|p| !p.borrow().is_empty()) {
        show_plugins(w);
    }
    w.set_chats(model(list));
    w.set_pinned(model(pinned));
    w.set_selected_chat(selected.unwrap_or_default().into());
}

/// Show the open chat in the header and details panel. UI thread only.
pub fn apply_conversation(w: &AppWindow, c: Option<ConversationData>) {
    let was = w.get_conversation();
    let next = match c {
        Some(c) => {
            let id: SharedString = c.id.to_string().into();
            let pinned = PINNED.with(|p| p.borrow().contains(&id));
            conversation(c, pinned)
        }
        None => Conversation::default(),
    };
    let opened = next.open && (!was.open || was.id != next.id);
    let writable = !next.read_only;
    w.set_conversation(next);
    if opened && writable {
        w.invoke_focus_composer();
    }
}

/// Show the open chat's messages, separators and agent activity. UI thread only.
pub fn apply_timeline(w: &AppWindow, items: Vec<TimelineItem>) {
    let mut rows: Vec<TimelineRow> = Vec::with_capacity(items.len() + 1);
    if w.get_welcome() && w.get_conversation().note {
        rows.push(welcome_row());
    }
    rows.extend(items.into_iter().map(timeline_row));
    w.set_timeline(model(rows));
}

/// The first-run card, shown as the first row of Note to Self.
fn welcome_row() -> TimelineRow {
    TimelineRow { kind: "welcome".into(), ..Default::default() }
}

/// Add or remove the welcome card after `welcome` changed. UI thread only.
pub fn refresh_welcome(w: &AppWindow) {
    let timeline = w.get_timeline();
    let mut rows: Vec<TimelineRow> = timeline.iter().filter(|r| r.kind != "welcome").collect();
    if w.get_welcome() && w.get_conversation().note {
        rows.insert(0, welcome_row());
    }
    w.set_timeline(model(rows));
}

/// Read a pasted connection code as it is typed. UI thread only.
pub fn apply_setup_code(w: &AppWindow, code: &str) {
    if code.trim().is_empty() {
        w.set_code_state("empty".into());
        return;
    }
    match setup_code::parse(code) {
        Ok((server, fingerprint)) => {
            show_fingerprint(w, &fingerprint);
            w.set_setup_address(server.into());
            w.set_setup_fingerprint(fingerprint.into());
            w.set_code_state("ok".into());
        }
        Err(_) => w.set_code_state("bad".into()),
    }
}

/// The short and grouped forms of a fingerprint, for the connect and verify steps.
/// UI thread only.
pub fn show_fingerprint(w: &AppWindow, fingerprint: &str) {
    w.set_fingerprint_short(short_fingerprint(fingerprint).into());
    w.set_fingerprint_groups(fingerprint_groups(fingerprint).into());
}

/// "3f9a1c7b e24d08e6 …" in two lines of four groups, easy to compare by eye.
fn fingerprint_groups(fp: &str) -> String {
    let hex: Vec<char> = fp.strip_prefix("sha256:").unwrap_or(fp).chars().collect();
    let groups: Vec<String> = hex.chunks(8).map(|c| c.iter().collect()).collect();
    groups.chunks(4).map(|line| line.join("  ")).collect::<Vec<_>>().join("\n")
}

/// "sha256:3f9a1c…7be2": enough to recognize, short enough for a menu.
fn short_fingerprint(fp: &str) -> String {
    let chars: Vec<char> = fp.chars().collect();
    if chars.len() <= 24 {
        return fp.to_owned();
    }
    let head: String = chars[..13].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// The sidebar's connection pill, from the status line the session reports.
fn connection(status: &str) -> &'static str {
    if status.is_empty() {
        "online"
    } else if status.starts_with("Connecting") {
        "connecting"
    } else {
        "offline"
    }
}

impl Ui {
    pub fn new(window: &AppWindow) -> Self {
        Self { weak: window.as_weak() }
    }

    /// Run `f` on the UI thread. Silently does nothing once the window is gone.
    fn with(&self, f: impl FnOnce(&AppWindow) + Send + 'static) {
        let _ = self.weak.upgrade_in_event_loop(move |w| f(&w));
    }

    pub fn show_setup(
        &self,
        address: String,
        fingerprint: String,
        error: String,
        can_cancel: bool,
    ) {
        self.with(move |w| {
            // A first launch starts with the welcome; otherwise go straight to the
            // connection details (an error keeps whatever the user was typing in).
            let first = !can_cancel && fingerprint.is_empty() && error.is_empty();
            if error.is_empty() {
                w.set_setup_manual(!fingerprint.is_empty());
                w.set_setup_code(SharedString::new());
                w.set_code_state("empty".into());
            }
            show_fingerprint(w, &fingerprint);
            w.set_setup_address(address.into());
            w.set_setup_fingerprint(fingerprint.into());
            w.set_setup_error(error.into());
            w.set_setup_can_cancel(can_cancel);
            w.invoke_show_step(if first { "welcome" } else { "connect" }.into());
            w.set_page("setup".into());
        });
    }

    pub fn show_login(&self, server_label: String, error: String) {
        self.with(move |w| {
            let label = server_label.strip_prefix("Server: ").unwrap_or(&server_label);
            w.set_server_label(label.into());
            w.set_login_error(error.into());
            w.set_login_busy(false);
            w.invoke_show_step("login".into());
            w.set_page("login".into());
        });
    }

    /// The result of checking the server before saving it.
    pub fn connection_tested(&self, ok: bool, message: String) {
        self.with(move |w| {
            w.set_verify_message(message.into());
            w.set_verify_state(if ok { "ok" } else { "failed" }.into());
        });
    }

    /// Turn decorative motion (falling snow, walking paws) off or on.
    pub fn set_reduce_motion(&self, on: bool) {
        self.with(move |w| w.global::<Theme>().set_reduce_motion(on));
    }

    /// A new runtime token, shown once in a dialog. The secret goes only into that
    /// dialog's property, which is cleared when it closes.
    pub fn show_agent_token(&self, agent: String, token: SecretString, code: String) {
        self.with(move |w| {
            let name = Id::parse(&agent)
                .ok()
                .and_then(|id| {
                    AGENTS.with(|a| a.borrow().iter().find(|p| p.id == id).map(|p| p.name.clone()))
                })
                .unwrap_or_else(|| "this agent".to_owned());
            w.set_token_agent(name.into());
            w.set_token_secret(token.expose().into());
            w.set_token_code(code.into());
            w.set_token_open(true);
            drop(token);
        });
    }

    /// Installed plugins and who may use them.
    pub fn set_plugins(&self, plugins: Vec<PluginView>) {
        self.with(move |w| apply_plugins(w, plugins));
    }

    /// The kill switch: all agents paused.
    pub fn set_agents_paused(&self, paused: bool) {
        self.with(move |w| w.set_agents_paused(paused));
    }

    /// The security log, newest first.
    pub fn set_audit(&self, entries: Vec<AuditEntry>, has_more: bool) {
        self.with(move |w| {
            let fmt = TimeFmt::local();
            let now = now_ms();
            let rows: Vec<AuditRow> = entries
                .iter()
                .map(|e| AuditRow {
                    time: fmt.bubble_time(e.at_ms, now).into(),
                    title: audit_title(&e.action).into(),
                    detail: e.detail.as_str().into(),
                })
                .collect();
            w.set_audit(model(rows));
            w.set_audit_has_more(has_more);
        });
    }

    /// Whether to show the first-run welcome card in Note to Self.
    pub fn set_welcome(&self, show: bool) {
        self.with(move |w| {
            w.set_welcome(show);
            refresh_welcome(w);
        });
    }

    pub fn login_busy(&self, busy: bool) {
        self.with(move |w| {
            w.set_login_busy(busy);
            if busy {
                w.set_login_error(SharedString::new());
            }
        });
    }

    pub fn show_main(&self) {
        self.with(|w| {
            w.invoke_clear_password();
            w.invoke_reset_main();
            w.set_selected_chat(SharedString::new());
            w.set_chats(ModelRc::default());
            w.set_pinned(ModelRc::default());
            w.set_conversation(Conversation::default());
            w.set_timeline(ModelRc::default());
            w.set_notice(SharedString::new());
            w.set_page("main".into());
        });
    }

    pub fn set_status(&self, status: String) {
        self.with(move |w| {
            w.set_connection(connection(&status).into());
            w.set_status(status.into());
        });
    }

    pub fn set_notice(&self, notice: String) {
        self.with(move |w| w.set_notice(notice.into()));
    }

    pub fn set_max_bytes(&self, n: usize) {
        let n = i32::try_from(n).unwrap_or(i32::MAX);
        self.with(move |w| w.set_max_message_bytes(n));
    }

    /// The user's font and appearance ("system" | "light" | "dark").
    pub fn set_prefs(&self, font: String, appearance: String) {
        self.with(move |w| {
            let theme = w.global::<Theme>();
            theme.set_font(font.into());
            theme.set_appearance(appearance.into());
        });
    }

    pub fn set_server_info(&self, address: String, fingerprint: String) {
        self.with(move |w| {
            w.set_server_fingerprint_short(short_fingerprint(&fingerprint).into());
            w.set_server_fingerprint(fingerprint.into());
            w.set_server_address(address.into());
        });
    }

    pub fn set_chat_list(&self, rows: Vec<ChatRowData>, selected: Option<String>) {
        self.with(move |w| apply_chat_list(w, &rows, selected));
    }

    pub fn set_conversation(&self, c: Option<ConversationData>) {
        self.with(move |w| apply_conversation(w, c));
    }

    pub fn set_timeline(&self, items: Vec<TimelineItem>) {
        self.with(move |w| apply_timeline(w, items));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_shortened_in_the_middle() {
        let fp = format!("sha256:{}", "ab".repeat(32));
        let short = short_fingerprint(&fp);
        assert!(short.starts_with("sha256:ababab"));
        assert!(short.ends_with("…abab"));
        assert_eq!(short.chars().count(), 18);
        assert_eq!(short_fingerprint("sha256:abc"), "sha256:abc");
    }

    #[test]
    fn avatars_are_cut_to_a_circle() {
        let n = 8u32;
        let mut pixels = SharedPixelBuffer::<Rgba8Pixel>::new(n, n);
        pixels.make_mut_slice().fill(Rgba8Pixel { r: 255, g: 255, b: 255, a: 255 });
        let out = round_pixels(&RenderedImage { width: n, height: n, pixels });
        let px = out.as_slice();
        assert_eq!(px[0].a, 0, "corners are transparent");
        assert_eq!(px[(4 * n + 4) as usize].a, 255, "the middle stays opaque");
    }

    #[test]
    fn civil_dates_and_schedules_read_naturally() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_737), (2026, 10, 11));
        let c = Clock { offset: 0, now: 20_737 * DAY_MS + 9 * 3_600_000 };
        assert_eq!(c.when(c.now + 3_600_000), "today at 10:00");
        assert_eq!(c.when(c.now + DAY_MS), "tomorrow at 09:00");
        assert_eq!(c.weekday(c.now), "Sunday");
        let daily = JobSchedule { first_run_at_ms: c.at(1, 8, 0), every_secs: Some(86_400) };
        assert_eq!(schedule_words(&c, &daily), "Every day at 08:00");
        assert_eq!(c.at(1, 8, 0), 20_738 * DAY_MS + 8 * 3_600_000);
    }

    #[test]
    fn fingerprints_are_grouped_for_reading() {
        let fp = format!("sha256:{}", "0123456789abcdef".repeat(4));
        let g = fingerprint_groups(&fp);
        let lines: Vec<&str> = g.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "01234567  89abcdef  01234567  89abcdef");
    }

    #[test]
    fn connection_follows_the_status_line() {
        assert_eq!(connection(""), "online");
        assert_eq!(connection("Connecting…"), "connecting");
        assert_eq!(connection("Offline: connection refused. Retrying in 4s…"), "offline");
    }
}
