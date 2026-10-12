//! What the client knows: chats, messages, and messages still being sent.
//!
//! Pure logic, no I/O, so it can be tested directly. Everything here came from the
//! server and is treated as untrusted display data.

use std::collections::BTreeMap;

use snowpaw_proto::Id;
use snowpaw_proto::agent::{AgentSettingsView, AuditEntry};
use snowpaw_proto::profile::BlobHash;
use snowpaw_proto::quiz::Quiz;
use snowpaw_proto::render::{RenderRequest, Rgb, Span};

use crate::markdown::{self, Block, TextStyle};
use crate::render::{RenderCache, Rendered, RenderedImage};
use snowpaw_proto::ws::{
    ChatKind, ChatSummary, Content, MAX_TITLE_CHARS, Member, MessageView, PrincipalKind,
    truncate_chars,
};

use crate::timefmt::TimeFmt;

/// Messages from the same sender within this window are visually grouped.
const GROUP_WINDOW_MS: i64 = 5 * 60 * 1000;
const PREVIEW_CHARS: usize = 80;
/// Most messages kept per chat in memory (oldest dropped first).
const MAX_MESSAGES_PER_CHAT: usize = 5000;
/// Decoded profile pictures kept in memory (256 KiB each).
const MAX_AVATARS: usize = 512;

/// A profile picture, decoded by the render worker. Compared by hash.
#[derive(Debug, Clone)]
pub struct Avatar {
    pub hash: BlobHash,
    pub image: RenderedImage,
}

impl PartialEq for Avatar {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Avatar {}

#[derive(Debug, Clone)]
enum AvatarState {
    Loading,
    Ready(RenderedImage),
    /// Couldn't fetch, verify or decode it: initials are shown instead.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub client_msg_id: Id,
    pub content: Content,
}

#[derive(Debug, Default)]
struct ChatState {
    kind: Option<ChatKind>,
    link_allowed: Option<bool>,
    title: String,
    members: Vec<Member>,
    messages: BTreeMap<i64, MessageView>,
    /// The last message as the chat list told it: a bounded preview, not stored
    /// message data. The full body comes from a sync.
    last: Option<MessageView>,
    pending: Vec<Pending>,
}

/// One row in the chat list, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRowData {
    pub id: Id,
    pub title: String,
    pub initials: String,
    pub tint: (u8, u8, u8),
    pub note: bool,
    pub preview: String,
    pub time: String,
    /// Avatars to draw: one for Note to Self and direct chats, two for agent-to-agent.
    pub people: Vec<Person>,
    pub section: Section,
    /// Pinned to the top of the sidebar (at most `MAX_PINNED`, client-local).
    pub pinned: bool,
    /// Messages from others since the chat was last open.
    pub unread: u32,
}

/// Someone to draw: avatar initials, a stable tint, and a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: Id,
    pub name: String,
    pub initials: String,
    pub tint: (u8, u8, u8),
    pub kind: PersonKind,
    /// The agent is busy on a job (Step 7); always false until jobs exist.
    pub working: bool,
    /// Role label ("Research"); empty for none.
    pub label: String,
    /// The profile picture, once fetched and decoded; draw initials until then.
    pub avatar: Option<Avatar>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonKind {
    /// The user.
    Me,
    Agent,
    /// The Note to Self "person" (draw the note icon instead of initials).
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Note to Self and your chats with agents.
    Chats,
    /// Conversations between two agents (read-only for you).
    BetweenAgents,
}

/// The open chat, for the conversation header and the details panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationData {
    pub id: Id,
    pub kind: ChatKind,
    pub title: String,
    /// "Agent", "Only you can see this chat", "Between agents · read-only".
    pub subtitle: String,
    pub people: Vec<Person>,
    pub note: bool,
    /// Agent-to-agent chats: no composer, show that you're reading along.
    pub read_only: bool,
    /// Placeholder for the composer ("Message Mochi", "Write a note to yourself").
    pub composer_placeholder: String,
    /// For a direct chat: that agent's conversations with other agents.
    pub related: Vec<ChatRowData>,
    /// For a direct chat: the agent (for editing) and its "about" text.
    pub agent: Option<Id>,
    pub about: String,
    /// For a direct chat: the agent's runtime state and settings (once loaded).
    pub agent_state: Option<AgentState>,
    /// For a chat between agents: the two agents and whether they may talk.
    pub link: Option<(Id, Id, bool)>,
    /// Jobs that post in this chat (open ones first): for job cards.
    pub jobs: Vec<snowpaw_proto::jobs::JobView>,
}

/// One row in the conversation timeline. (Built once per render and moved straight
/// into the UI's model, so the size difference between rows doesn't matter.)
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TimelineItem {
    /// Centered time label: "Today 08:15", "Yesterday 21:14", "October 2".
    Separator(String),
    Message(MessageRowData),
    /// Agents talked to each other: "Message from" [Toki], "6 messages with" [Toki, Chika].
    /// Opening `target` shows that agent-to-agent chat.
    Activity {
        prefix: String,
        people: Vec<Person>,
        target: Id,
    },
}

/// One message bubble, ready to display.
#[derive(Debug, Clone)]
pub struct MessageRowData {
    pub id: String,
    pub blocks: Vec<BlockData>,
    pub outgoing: bool,
    pub time: String,
    pub pending: bool,
    pub group_start: bool,
    /// Who wrote it, set at the start of each group in chats with several other
    /// participants (agent-to-agent), so the UI can label it.
    pub sender: Option<Person>,
    /// A quiz message: draw the quiz card (`blocks` is empty).
    pub quiz: Option<QuizView>,
}

/// One displayable piece of a message.
#[derive(Debug, Clone)]
pub enum BlockData {
    /// Safe StyledText markdown, with a plain-text fallback.
    Text {
        md: String,
        plain: String,
        kind: TextKind,
    },
    /// Monospace StyledText markdown (colored once highlighted).
    Code {
        md: String,
        plain: String,
    },
    /// Typeset math; size in logical pixels. `display` equations are centered.
    Image {
        image: RenderedImage,
        width: f32,
        height: f32,
        display: bool,
    },
    Rule,
}

/// A quiz as the UI shows it. The answer key is included (flashcards show it, and
/// the card gives instant feedback); the server grades submitted answers itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuizView {
    /// The quiz message, for `Command::AnswerQuiz`.
    pub message_id: Id,
    pub title: String,
    pub questions: Vec<QuizQuestionView>,
    /// The user has submitted answers (the latest set is shown).
    pub submitted: bool,
    /// (right, total) from the server's grading, once submitted.
    pub score: Option<(usize, usize)>,
    /// The user can answer (it's from an agent, in a chat the user takes part in).
    pub can_answer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuizQuestionView {
    pub prompt: String,
    pub choices: Vec<String>,
    /// Index of the correct choice.
    pub answer: usize,
    pub hint: String,
    pub explanation: String,
    /// What the user picked in their latest submission.
    pub picked: Option<usize>,
    /// The server's grading of that pick.
    pub correct: Option<bool>,
}

/// What the user knows about an agent's runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentState {
    pub connected: bool,
    pub working_in: Option<Id>,
    /// Loaded on demand (`Command::GetAgentSettings`).
    pub settings: Option<AgentSettingsView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    Body,
    H1,
    H2,
    H3,
    Quote,
}

/// Render results and theme, for turning messages into blocks.
#[derive(Debug)]
pub struct RenderView<'a> {
    pub cache: &'a RenderCache,
    pub dark: bool,
}

/// Most messages shown at once for a chat (the newest).
const MAX_VISIBLE_MESSAGES: usize = 300;
/// Pinned chats allowed at the top of the sidebar.
pub const MAX_PINNED: usize = 3;
/// A new time separator after this much silence.
const SEPARATOR_GAP_MS: i64 = 60 * 60 * 1000;
/// Agent-to-agent messages further apart than this become separate activity rows.
const SESSION_GAP_MS: i64 = 30 * 60 * 1000;
/// Math is typeset at this size and pixel density.
const MATH_PT: u8 = 14;
const MATH_SCALE: u8 = 2;
const MATH_PARAGRAPH_WIDTH_PT: u16 = 440;
/// Default text color of the code themes; spans in this color need no markup.
const CODE_FG_LIGHT: Rgb = Rgb { r: 0x24, g: 0x29, b: 0x2e };
const CODE_FG_DARK: Rgb = Rgb { r: 0xe1, g: 0xe4, b: 0xe8 };

#[derive(Debug, Default)]
pub struct Store {
    pub me: Option<Id>,
    pub max_content_bytes: usize,
    /// Chat ids in server order; display order is computed from activity.
    order: Vec<Id>,
    chats: BTreeMap<Id, ChatState>,
    pub current: Option<Id>,
    /// Parsed markdown by message text (parsing is pure, so text is the key).
    parsed: std::collections::HashMap<String, std::sync::Arc<Vec<Block>>>,
    /// Sidebar search; chats whose title or preview contain it (case-insensitive).
    pub search: String,
    pinned: Vec<Id>,
    /// Highest seq the user has seen per chat. History from before this login counts
    /// as read (read state isn't synced yet).
    read_upto: std::collections::HashMap<Id, i64>,
    avatars: std::collections::HashMap<BlobHash, AvatarState>,
    agents: std::collections::HashMap<Id, AgentState>,
    /// The kill switch is on.
    pub agents_paused: bool,
    /// Installed plugins (loaded with `Command::ListPlugins`).
    pub plugins: Vec<snowpaw_proto::plugin::PluginView>,
    /// Jobs, newest first (loaded at connect, then kept current by the server).
    pub jobs: Vec<snowpaw_proto::jobs::JobView>,
    /// Audit log pages loaded so far (newest first), and whether there's more.
    pub audit: Vec<AuditEntry>,
    pub audit_more: bool,
}

impl Store {
    pub fn set_chats(&mut self, chats: Vec<ChatSummary>) {
        self.order = chats.iter().map(|c| c.id).collect();
        let keep: std::collections::BTreeSet<Id> = self.order.iter().copied().collect();
        self.chats.retain(|id, _| keep.contains(id));
        for c in chats {
            self.read_upto
                .entry(c.id)
                .or_insert_with(|| c.last_message.as_ref().map_or(0, |m| m.seq));
            let state = self.chats.entry(c.id).or_default();
            state.kind = Some(c.kind);
            state.link_allowed = c.link_allowed;
            state.title = truncate_chars(&c.title, MAX_TITLE_CHARS);
            state.members = c
                .members
                .into_iter()
                .map(|mut m| {
                    m.name = truncate_chars(&m.name, MAX_TITLE_CHARS);
                    m
                })
                .collect();
            // The summary's last message is a one-line preview from the server, for
            // the sidebar only: never filed as the message itself, so the full body
            // (which a sync delivers) is what gets stored and shown.
            state.last = c.last_message.map(|mut m| {
                m.content = Content::Markdown { text: m.content.preview(PREVIEW_CHARS) };
                m
            });
        }
        if self.current.is_some_and(|c| !self.chats.contains_key(&c)) {
            self.current = None;
        }
        self.pinned.retain(|id| keep.contains(id));
    }

    pub fn chat_ids(&self) -> Vec<Id> {
        self.order.clone()
    }

    pub fn has_chat(&self, id: Id) -> bool {
        self.chats.contains_key(&id)
    }

    /// Add messages from the server. Returns true if anything changed.
    pub fn add_messages(&mut self, chat_id: Id, messages: Vec<MessageView>) -> bool {
        let Some(state) = self.chats.get_mut(&chat_id) else { return false };
        let mut changed = false;
        for m in messages {
            // Never file a message under a chat it doesn't belong to.
            if m.chat_id != chat_id {
                continue;
            }
            if self.me == Some(m.sender_id) {
                let before = state.pending.len();
                state.pending.retain(|p| p.client_msg_id != m.client_msg_id);
                changed |= state.pending.len() != before;
            }
            changed |= Self::insert(state, m);
        }
        changed
    }

    fn insert(state: &mut ChatState, m: MessageView) -> bool {
        if state.messages.contains_key(&m.seq) {
            return false;
        }
        state.messages.insert(m.seq, m);
        while state.messages.len() > MAX_MESSAGES_PER_CHAT {
            state.messages.pop_first();
        }
        true
    }

    /// Highest seq we hold for a chat (for "sync after").
    pub fn last_seq(&self, chat_id: Id) -> i64 {
        self.chats.get(&chat_id).and_then(|c| c.messages.keys().next_back().copied()).unwrap_or(0)
    }

    pub fn add_pending(
        &mut self,
        chat_id: Id,
        client_msg_id: Id,
        content: Content,
    ) -> Option<Pending> {
        let state = self.chats.get_mut(&chat_id)?;
        let p = Pending { client_msg_id, content };
        state.pending.push(p.clone());
        Some(p)
    }

    /// Everything not yet confirmed, for resending after a reconnect (safe: the server
    /// deduplicates by client_msg_id).
    pub fn all_pending(&self) -> Vec<(Id, Pending)> {
        self.chats
            .iter()
            .flat_map(|(id, c)| c.pending.iter().map(move |p| (*id, p.clone())))
            .collect()
    }

    pub fn is_pending(&self, chat_id: Id, client_msg_id: Id) -> bool {
        self.chats
            .get(&chat_id)
            .is_some_and(|c| c.pending.iter().any(|p| p.client_msg_id == client_msg_id))
    }

    fn last_activity(&self, id: &Id) -> i64 {
        self.chats
            .get(id)
            .and_then(|c| {
                c.messages.keys().next_back().copied().or_else(|| c.last.as_ref().map(|m| m.seq))
            })
            .unwrap_or(0)
    }

    pub fn chat_rows(&self, fmt: &TimeFmt, now_ms: i64) -> Vec<ChatRowData> {
        let mut ids = self.order.clone();
        // seq is global and increasing, so it orders activity across chats. Stable
        // sort keeps the server's order for chats without messages.
        ids.sort_by_key(|id| std::cmp::Reverse(self.last_activity(id)));
        let needle = self.search.trim().to_lowercase();
        ids.into_iter()
            .filter_map(|id| self.chat_row_unfiltered(id, fmt, now_ms))
            .filter(|r| {
                needle.is_empty()
                    || r.title.to_lowercase().contains(&needle)
                    || r.preview.to_lowercase().contains(&needle)
            })
            .collect()
    }

    pub fn chat_row(&self, id: Id, fmt: &TimeFmt, now_ms: i64) -> Option<ChatRowData> {
        self.chat_row_unfiltered(id, fmt, now_ms)
    }

    fn chat_row_unfiltered(&self, id: Id, fmt: &TimeFmt, now_ms: i64) -> Option<ChatRowData> {
        let c = self.chats.get(&id)?;
        // Stored messages are the truth; the summary's preview covers a chat we
        // haven't synced yet.
        let last = c.messages.values().next_back().or(c.last.as_ref());
        let preview = match (c.pending.last(), last) {
            (Some(p), _) => p.content.preview(PREVIEW_CHARS),
            (None, Some(m)) => m.content.preview(PREVIEW_CHARS),
            (None, None) => String::new(),
        };
        let read = self.read_upto.get(&id).copied().unwrap_or(0);
        let unread =
            c.messages.range(read + 1..).filter(|(_, m)| Some(m.sender_id) != self.me).count();
        Some(ChatRowData {
            id,
            title: c.title.clone(),
            initials: initials(&c.title),
            tint: tint_for(&id),
            note: c.kind == Some(ChatKind::NoteToSelf),
            preview,
            time: last.map(|m| fmt.list_time(m.created_at_ms, now_ms)).unwrap_or_default(),
            people: self.people_of(id),
            section: if c.kind == Some(ChatKind::AgentToAgent) {
                Section::BetweenAgents
            } else {
                Section::Chats
            },
            pinned: self.pinned.contains(&id),
            unread: u32::try_from(unread).unwrap_or(u32::MAX),
        })
    }

    fn person(&self, m: &Member) -> Person {
        let me = self.me == Some(m.id) || m.kind == PrincipalKind::User;
        Person {
            id: m.id,
            name: if me { "You".to_owned() } else { m.name.clone() },
            initials: initials(&m.name),
            tint: tint_for(&m.id),
            kind: if me { PersonKind::Me } else { PersonKind::Agent },
            working: self.agents.get(&m.id).is_some_and(|a| a.working_in.is_some()),
            label: m.label.clone(),
            avatar: m.avatar.and_then(|hash| match self.avatars.get(&hash) {
                Some(AvatarState::Ready(image)) => Some(Avatar { hash, image: image.clone() }),
                _ => None,
            }),
        }
    }

    fn person_by_id(&self, chat: &ChatState, id: Id) -> Option<Person> {
        chat.members.iter().find(|m| m.id == id).map(|m| self.person(m))
    }

    /// Who to draw for a chat.
    fn people_of(&self, id: Id) -> Vec<Person> {
        let Some(c) = self.chats.get(&id) else { return vec![] };
        if c.kind == Some(ChatKind::NoteToSelf) {
            return vec![Person {
                id,
                name: c.title.clone(),
                initials: initials(&c.title),
                tint: tint_for(&id),
                kind: PersonKind::Note,
                working: false,
                label: String::new(),
                avatar: None,
            }];
        }
        c.members
            .iter()
            .filter(|m| m.kind == PrincipalKind::Agent)
            .map(|m| self.person(m))
            .collect()
    }

    /// The agent in a direct chat.
    fn direct_agent(&self, c: &ChatState) -> Option<Id> {
        (c.kind == Some(ChatKind::Direct))
            .then(|| c.members.iter().find(|m| m.kind == PrincipalKind::Agent).map(|m| m.id))
            .flatten()
    }

    /// Agent-to-agent chats that include `agent`.
    fn agent_chats_with(&self, agent: Id) -> Vec<Id> {
        self.order
            .iter()
            .copied()
            .filter(|id| {
                self.chats.get(id).is_some_and(|c| {
                    c.kind == Some(ChatKind::AgentToAgent)
                        && c.members.iter().any(|m| m.id == agent)
                })
            })
            .collect()
    }

    pub fn conversation(&self, id: Id, fmt: &TimeFmt, now_ms: i64) -> Option<ConversationData> {
        let c = self.chats.get(&id)?;
        let kind = c.kind?;
        let (subtitle, placeholder) = match kind {
            ChatKind::NoteToSelf => {
                ("Only you can see this chat".to_owned(), "Write a note to yourself".to_owned())
            }
            ChatKind::Direct => ("Agent".to_owned(), format!("Message {}", c.title)),
            ChatKind::AgentToAgent => ("Between agents · read-only".to_owned(), String::new()),
        };
        let agent = self.direct_agent(c);
        let about = agent
            .and_then(|a| c.members.iter().find(|m| m.id == a))
            .map(|m| m.about.clone())
            .unwrap_or_default();
        let related = match agent {
            Some(agent) => self
                .agent_chats_with(agent)
                .into_iter()
                .filter_map(|cid| self.chat_row_unfiltered(cid, fmt, now_ms))
                .collect(),
            None => vec![],
        };
        Some(ConversationData {
            id,
            kind,
            title: c.title.clone(),
            subtitle,
            people: self.people_of(id),
            note: kind == ChatKind::NoteToSelf,
            read_only: kind == ChatKind::AgentToAgent,
            composer_placeholder: placeholder,
            related,
            agent,
            about,
            agent_state: agent.map(|a| self.agents.get(&a).cloned().unwrap_or_default()),
            jobs: self.jobs.iter().filter(|j| j.chat_id == id).cloned().collect(),
            link: match (kind, c.link_allowed) {
                (ChatKind::AgentToAgent, Some(allowed)) => {
                    let mut agents =
                        c.members.iter().filter(|m| m.kind == PrincipalKind::Agent).map(|m| m.id);
                    agents.next().zip(agents.next()).map(|(a, b)| (a, b, allowed))
                }
                _ => None,
            },
        })
    }

    /// A job was created or changed.
    pub fn update_job(&mut self, job: snowpaw_proto::jobs::JobView) {
        match self.jobs.iter_mut().find(|j| j.id == job.id) {
            Some(existing) => *existing = job,
            None => self.jobs.insert(0, job),
        }
        self.jobs.sort_by_key(|j| !j.state.is_open());
    }

    pub fn set_agent_status(&mut self, agent: Id, connected: bool, working_in: Option<Id>) {
        let a = self.agents.entry(agent).or_default();
        a.connected = connected;
        a.working_in = working_in.filter(|_| connected);
    }

    pub fn set_agent_settings(&mut self, agent: Id, settings: AgentSettingsView) {
        let a = self.agents.entry(agent).or_default();
        a.connected = settings.connected;
        a.settings = Some(settings);
    }

    /// Add a page of audit entries (`first`: replace what's loaded).
    pub fn add_audit(&mut self, entries: Vec<AuditEntry>, has_more: bool, first: bool) {
        if first {
            self.audit.clear();
        }
        // Keep newest-first order without duplicates.
        let oldest = self.audit.last().map_or(i64::MAX, |e| e.seq);
        self.audit.extend(entries.into_iter().filter(|e| e.seq < oldest));
        self.audit_more = has_more;
    }

    /// The oldest audit entry loaded (to page further back).
    pub fn audit_oldest(&self) -> Option<i64> {
        self.audit.last().map(|e| e.seq)
    }

    /// A quiz in the current chat that the user may answer: its question count.
    pub fn answerable_quiz(&self, chat: Id, quiz_id: Id) -> Option<usize> {
        let c = self.chats.get(&chat)?;
        if c.kind == Some(ChatKind::AgentToAgent) {
            return None;
        }
        c.messages.values().find_map(|m| match &m.content {
            Content::Quiz { quiz } if m.id == quiz_id && Some(m.sender_id) != self.me => {
                Some(quiz.questions.len())
            }
            _ => None,
        })
    }

    fn quiz_view(&self, chat: Id, message_id: Id, quiz: &Quiz, outgoing: bool) -> QuizView {
        let c = self.chats.get(&chat);
        let latest = c.and_then(|c| {
            c.messages.values().rev().find_map(|m| match &m.content {
                Content::QuizAnswers { answers } if answers.quiz_id == message_id => Some(answers),
                _ => None,
            })
        });
        let questions = quiz
            .questions
            .iter()
            .enumerate()
            .map(|(i, q)| QuizQuestionView {
                prompt: q.prompt.clone(),
                choices: q.choices.clone(),
                answer: usize::from(q.answer),
                hint: q.hint.clone(),
                explanation: q.explanation.clone(),
                picked: latest.and_then(|a| a.answers.get(i).copied().flatten()).map(usize::from),
                correct: latest.and_then(|a| a.results.get(i).copied()),
            })
            .collect();
        QuizView {
            message_id,
            title: quiz.title.clone(),
            questions,
            submitted: latest.is_some(),
            score: latest.filter(|a| !a.results.is_empty()).map(|a| a.score()),
            can_answer: !outgoing && c.is_some_and(|c| c.kind != Some(ChatKind::AgentToAgent)),
        }
    }

    /// Display blocks (or a quiz card) for one message, plus render requests for
    /// code and math.
    fn content_blocks(
        &mut self,
        chat: Id,
        message_id: &str,
        content: &Content,
        outgoing: bool,
        view: &RenderView<'_>,
        requests: &mut Vec<RenderRequest>,
    ) -> (Vec<BlockData>, Option<QuizView>) {
        let text = |c: &Content| {
            let plain = c.preview(200);
            vec![BlockData::Text { md: markdown::escape(&plain), plain, kind: TextKind::Body }]
        };
        match content {
            Content::Markdown { text } => {
                let blocks = self.blocks_for(text);
                (layout(&blocks, outgoing, view, requests), None)
            }
            Content::Quiz { quiz } => match Id::parse(message_id) {
                Ok(id) => (vec![], Some(self.quiz_view(chat, id, quiz, outgoing))),
                // Still sending: no id to answer yet.
                Err(_) => (text(content), None),
            },
            Content::QuizAnswers { .. } => (text(content), None),
        }
    }

    /// Pictures that members use but we haven't fetched yet. They're marked as
    /// loading, so each is returned once.
    pub fn wanted_avatars(&mut self) -> Vec<BlobHash> {
        let mut wanted: Vec<BlobHash> = self
            .chats
            .values()
            .flat_map(|c| c.members.iter().filter_map(|m| m.avatar))
            .filter(|h| !self.avatars.contains_key(h))
            .collect();
        wanted.sort_unstable();
        wanted.dedup();
        if self.avatars.len() + wanted.len() > MAX_AVATARS {
            self.avatars.retain(|_, s| !matches!(s, AvatarState::Failed));
        }
        wanted.truncate(MAX_AVATARS.saturating_sub(self.avatars.len()));
        for h in &wanted {
            self.avatars.insert(*h, AvatarState::Loading);
        }
        wanted
    }

    /// Forget failures so those pictures are tried again (after a reconnect).
    pub fn forget_failed_avatars(&mut self) {
        self.avatars.retain(|_, s| !matches!(s, AvatarState::Failed));
    }

    /// Whether `id` is an agent in any of our chats.
    pub fn is_agent(&self, id: Id) -> bool {
        self.chats
            .values()
            .any(|c| c.members.iter().any(|m| m.id == id && m.kind == PrincipalKind::Agent))
    }

    /// A picture arrived (already hash-checked and decoded in the sandbox), or failed.
    pub fn set_avatar(&mut self, hash: BlobHash, image: Option<RenderedImage>) {
        let state = image.map_or(AvatarState::Failed, AvatarState::Ready);
        if self.avatars.len() < MAX_AVATARS || self.avatars.contains_key(&hash) {
            self.avatars.insert(hash, state);
        }
    }

    /// A profile changed: update it everywhere that person appears.
    pub fn update_member(&mut self, member: &Member) {
        let mut updated = member.clone();
        updated.name = truncate_chars(&updated.name, MAX_TITLE_CHARS);
        for chat in self.chats.values_mut() {
            for m in chat.members.iter_mut().filter(|m| m.id == updated.id) {
                *m = updated.clone();
            }
            // Direct chats are titled after the agent.
            if chat.kind == Some(ChatKind::Direct)
                && chat.members.iter().any(|m| m.id == updated.id)
            {
                chat.title = updated.name.clone();
            }
        }
    }

    /// The user has seen everything currently in this chat.
    pub fn mark_read(&mut self, id: Id) {
        let last = self.last_seq(id);
        let entry = self.read_upto.entry(id).or_insert(0);
        *entry = (*entry).max(last);
    }

    pub fn pinned(&self) -> &[Id] {
        &self.pinned
    }

    /// Replace the pinned set (e.g. loaded from settings); unknown ids are kept until
    /// the chat list arrives, extra ones beyond the limit are dropped.
    pub fn set_pinned(&mut self, ids: Vec<Id>) {
        self.pinned = ids;
        self.pinned.dedup();
        self.pinned.truncate(MAX_PINNED);
    }

    /// Pin or unpin. Returns false if pinning would exceed `MAX_PINNED`.
    pub fn toggle_pin(&mut self, id: Id) -> bool {
        if let Some(i) = self.pinned.iter().position(|p| *p == id) {
            self.pinned.remove(i);
            return true;
        }
        if self.pinned.len() >= MAX_PINNED || !self.chats.contains_key(&id) {
            return false;
        }
        self.pinned.push(id);
        true
    }

    fn blocks_for(&mut self, text: &str) -> std::sync::Arc<Vec<Block>> {
        if let Some(b) = self.parsed.get(text) {
            return b.clone();
        }
        if self.parsed.len() > 10_000 {
            self.parsed.clear();
        }
        let blocks = std::sync::Arc::new(markdown::parse(text));
        self.parsed.insert(text.to_owned(), blocks.clone());
        blocks
    }

    /// Display rows for a chat, plus render requests for anything not yet rendered.
    pub fn message_rows(
        &mut self,
        chat_id: Id,
        fmt: &TimeFmt,
        now_ms: i64,
        view: &RenderView<'_>,
    ) -> (Vec<MessageRowData>, Vec<RenderRequest>) {
        let me = self.me;
        let Some(c) = self.chats.get(&chat_id) else { return (vec![], vec![]) };
        let skip = (c.messages.len() + c.pending.len()).saturating_sub(MAX_VISIBLE_MESSAGES);
        struct Item {
            id: String,
            sender: Option<Id>,
            at: Option<i64>,
            content: Content,
            pending: bool,
        }
        let items: Vec<Item> = c
            .messages
            .values()
            .map(|m| Item {
                id: m.id.to_string(),
                sender: Some(m.sender_id),
                at: Some(m.created_at_ms),
                content: m.content.clone(),
                pending: false,
            })
            .chain(c.pending.iter().map(|p| Item {
                id: p.client_msg_id.to_string(),
                sender: me,
                at: None,
                content: p.content.clone(),
                pending: true,
            }))
            .skip(skip)
            .collect();
        let mut rows = Vec::with_capacity(items.len());
        let mut requests = Vec::new();
        let mut prev: Option<(Option<Id>, i64)> = None;
        for item in items {
            let at = item.at.unwrap_or(now_ms);
            let group_start = match prev {
                Some((sender, prev_at)) => sender != item.sender || at - prev_at > GROUP_WINDOW_MS,
                None => true,
            };
            prev = Some((item.sender, at));
            let outgoing = item.sender.is_some() && item.sender == me;
            let (blocks, quiz) = self.content_blocks(
                chat_id,
                &item.id,
                &item.content,
                outgoing,
                view,
                &mut requests,
            );
            rows.push(MessageRowData {
                id: item.id,
                blocks,
                quiz,
                outgoing,
                time: item.at.map(|t| fmt.bubble_time(t, now_ms)).unwrap_or_default(),
                pending: item.pending,
                group_start,
                sender: None,
            });
        }
        (rows, requests)
    }

    /// Activity rows for a direct chat: the agent's conversations with other agents,
    /// one row per burst of messages.
    fn activities(&self, c: &ChatState) -> Vec<(i64, TimelineItem)> {
        let Some(agent) = self.direct_agent(c) else { return vec![] };
        let mut out = vec![];
        for chat_id in self.agent_chats_with(agent) {
            let Some(other) = self.chats.get(&chat_id) else { continue };
            let mut session: Vec<&MessageView> = vec![];
            let mut flush = |session: &mut Vec<&MessageView>| {
                let Some(first) = session.first() else { return };
                let n = session.len();
                let mut senders: Vec<Id> = vec![];
                for m in session.iter() {
                    if !senders.contains(&m.sender_id) {
                        senders.push(m.sender_id);
                    }
                }
                let (prefix, ids) = if n == 1 {
                    if first.sender_id == agent {
                        // Our agent wrote to the other one.
                        let to =
                            other.members.iter().map(|m| m.id).filter(|id| *id != agent).collect();
                        ("Message to".to_owned(), to)
                    } else {
                        ("Message from".to_owned(), vec![first.sender_id])
                    }
                } else {
                    (format!("{n} messages with"), senders)
                };
                let people =
                    ids.into_iter().filter_map(|id| self.person_by_id(other, id)).collect();
                out.push((
                    first.created_at_ms,
                    TimelineItem::Activity { prefix, people, target: chat_id },
                ));
                session.clear();
            };
            for m in other.messages.values() {
                if session
                    .last()
                    .is_some_and(|prev| m.created_at_ms - prev.created_at_ms > SESSION_GAP_MS)
                {
                    flush(&mut session);
                }
                session.push(m);
            }
            flush(&mut session);
        }
        out
    }

    /// The conversation timeline: time separators, messages (grouped, with sender
    /// labels where several others talk), and agent-to-agent activity rows.
    /// Also returns render requests for code/math not yet rendered.
    pub fn timeline(
        &mut self,
        chat_id: Id,
        fmt: &TimeFmt,
        now_ms: i64,
        view: &RenderView<'_>,
    ) -> (Vec<TimelineItem>, Vec<RenderRequest>) {
        let me = self.me;
        let Some(c) = self.chats.get(&chat_id) else { return (vec![], vec![]) };
        let label_senders = c.kind == Some(ChatKind::AgentToAgent);

        #[allow(clippy::large_enum_variant)]
        enum Entry {
            Msg { id: String, sender: Option<Id>, at: i64, content: Content, pending: bool },
            Other(TimelineItem),
        }
        let skip = (c.messages.len() + c.pending.len()).saturating_sub(MAX_VISIBLE_MESSAGES);
        let mut entries: Vec<(i64, Entry)> = c
            .messages
            .values()
            .map(|m| Entry::Msg {
                id: m.id.to_string(),
                sender: Some(m.sender_id),
                at: m.created_at_ms,
                content: m.content.clone(),
                pending: false,
            })
            .chain(c.pending.iter().map(|p| Entry::Msg {
                id: p.client_msg_id.to_string(),
                sender: me,
                at: now_ms,
                content: p.content.clone(),
                pending: true,
            }))
            .skip(skip)
            .map(|e| match &e {
                Entry::Msg { at, .. } => (*at, e),
                Entry::Other(_) => (0, e),
            })
            .collect();
        let oldest = entries.first().map_or(i64::MIN, |(at, _)| *at);
        entries.extend(
            self.activities(c)
                .into_iter()
                .filter(|(at, _)| *at >= oldest)
                .map(|(at, item)| (at, Entry::Other(item))),
        );
        // Stable: equal times keep messages before activity rows.
        entries.sort_by_key(|(at, _)| *at);

        let senders: std::collections::HashMap<Id, Person> =
            c.members.iter().map(|m| (m.id, self.person(m))).collect();
        let mut items = Vec::with_capacity(entries.len() + 8);
        let mut requests = Vec::new();
        let mut prev_at: Option<i64> = None;
        let mut prev_sender: Option<Option<Id>> = None;
        for (at, entry) in entries {
            let new_section = match prev_at {
                None => true,
                Some(p) => at - p >= SEPARATOR_GAP_MS || fmt.local_day(p) != fmt.local_day(at),
            };
            if new_section {
                items.push(TimelineItem::Separator(fmt.separator(at, now_ms)));
            }
            match entry {
                Entry::Msg { id, sender, at, content, pending } => {
                    let group_start = new_section
                        || prev_sender != Some(sender)
                        || prev_at.is_some_and(|p| at - p > GROUP_WINDOW_MS);
                    let outgoing = sender.is_some() && sender == me;
                    let (blocks, quiz) =
                        self.content_blocks(chat_id, &id, &content, outgoing, view, &mut requests);
                    let shown = (label_senders && group_start)
                        .then(|| sender.and_then(|s| senders.get(&s).cloned()))
                        .flatten();
                    items.push(TimelineItem::Message(MessageRowData {
                        id,
                        blocks,
                        quiz,
                        outgoing,
                        time: if pending { String::new() } else { fmt.bubble_time(at, now_ms) },
                        pending,
                        group_start,
                        sender: shown,
                    }));
                    prev_sender = Some(sender);
                }
                Entry::Other(item) => {
                    items.push(item);
                    prev_sender = None;
                }
            }
            prev_at = Some(at);
        }
        (items, requests)
    }
}

/// Text color for math: the theme's text color (bubbles are neutral both ways; must
/// match the UI theme's text color).
fn math_color(_outgoing: bool, dark: bool) -> Rgb {
    if dark { Rgb { r: 0xe8, g: 0xee, b: 0xf6 } } else { Rgb { r: 0x0b, g: 0x1e, b: 0x3a } }
}

fn text_kind(style: TextStyle) -> TextKind {
    match style {
        TextStyle::Body => TextKind::Body,
        TextStyle::Heading(1) => TextKind::H1,
        TextStyle::Heading(2) => TextKind::H2,
        TextStyle::Heading(_) => TextKind::H3,
        TextStyle::Quote => TextKind::Quote,
    }
}

/// Code text for StyledText: escaped, with spaces kept (non-breaking) and each line
/// ending in a hard break.
fn code_text(t: &str) -> String {
    markdown::escape(&t.replace('\t', "    ")).replace(' ', "\u{a0}")
}

fn plain_code_md(code: &str) -> String {
    code.split('\n')
        .map(|l| if l.is_empty() { "\u{a0}".to_owned() } else { code_text(l) })
        .collect::<Vec<_>>()
        .join("\\\n")
}

fn highlighted_md(lines: &[Vec<Span>], default: Rgb) -> String {
    lines
        .iter()
        .map(|line| {
            let mut out = String::new();
            for span in line {
                let mut t = code_text(&span.text);
                if t.is_empty() {
                    continue;
                }
                // Emphasis markers only work when not touching whitespace.
                let trimmed = !span.text.starts_with(char::is_whitespace)
                    && !span.text.ends_with(char::is_whitespace);
                if trimmed && span.italic {
                    t = format!("*{t}*");
                }
                if trimmed && span.bold {
                    t = format!("**{t}**");
                }
                if span.color != default {
                    let Rgb { r, g, b } = span.color;
                    t = format!("<font color=\"#{r:02x}{g:02x}{b:02x}\">{t}</font>");
                }
                out.push_str(&t);
            }
            if out.is_empty() { "\u{a0}".to_owned() } else { out }
        })
        .collect::<Vec<_>>()
        .join("\\\n")
}

/// Turn parsed blocks into display blocks, using render results where available and
/// queueing requests for the rest. Anything not (yet) rendered shows as plain text.
fn layout(
    blocks: &[Block],
    outgoing: bool,
    view: &RenderView<'_>,
    requests: &mut Vec<RenderRequest>,
) -> Vec<BlockData> {
    let mut want = |req: RenderRequest| -> Option<Rendered> {
        if req.validate().is_err() {
            return Some(Rendered::Failed);
        }
        match view.cache.get(&req) {
            Some(r) => Some(r.clone()),
            None => {
                requests.push(req);
                None
            }
        }
    };
    let color = math_color(outgoing, view.dark);
    let image = |img: RenderedImage, display: bool| BlockData::Image {
        width: img.width as f32 / f32::from(MATH_SCALE),
        height: img.height as f32 / f32::from(MATH_SCALE),
        image: img,
        display,
    };
    blocks
        .iter()
        .map(|b| match b {
            Block::Text { md, plain, style } => {
                BlockData::Text { md: md.clone(), plain: plain.clone(), kind: text_kind(*style) }
            }
            Block::Code { lang, code } => {
                let req = RenderRequest::Highlight {
                    lang: lang.clone(),
                    code: code.clone(),
                    dark: view.dark,
                };
                let default = if view.dark { CODE_FG_DARK } else { CODE_FG_LIGHT };
                match want(req) {
                    Some(Rendered::Highlighted(lines)) => {
                        BlockData::Code { md: highlighted_md(&lines, default), plain: code.clone() }
                    }
                    _ => BlockData::Code { md: plain_code_md(code), plain: code.clone() },
                }
            }
            Block::Math { latex } => {
                let req = RenderRequest::Math {
                    latex: latex.clone(),
                    color,
                    size_pt: MATH_PT,
                    scale: MATH_SCALE,
                };
                match want(req) {
                    Some(Rendered::Image(img)) => image(img, true),
                    _ => {
                        let src = format!("$${latex}$$");
                        BlockData::Code { md: plain_code_md(&src), plain: src }
                    }
                }
            }
            Block::MathText { runs, md, plain, style } => {
                let req = RenderRequest::MathParagraph {
                    runs: runs.clone(),
                    color,
                    size_pt: MATH_PT,
                    width_pt: MATH_PARAGRAPH_WIDTH_PT,
                    scale: MATH_SCALE,
                };
                match want(req) {
                    Some(Rendered::Image(img)) => image(img, false),
                    _ => BlockData::Text {
                        md: md.clone(),
                        plain: plain.clone(),
                        kind: text_kind(*style),
                    },
                }
            }
            Block::Rule => BlockData::Rule,
        })
        .collect()
}

fn initials(title: &str) -> String {
    let words: Vec<&str> = title.split_whitespace().collect();
    let first =
        |w: &str| w.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
    match words.as_slice() {
        [] => "?".into(),
        [one] => first(one),
        [a, .., b] => format!("{}{}", first(a), first(b)),
    }
}

/// A stable avatar color per chat, from a small palette of readable colors.
fn tint_for(id: &Id) -> (u8, u8, u8) {
    const PALETTE: [(u8, u8, u8); 8] = [
        (0x2c, 0x6b, 0xed),
        (0xc7, 0x3f, 0x5e),
        (0x2e, 0x8b, 0x57),
        (0xb2, 0x6b, 0x00),
        (0x7d, 0x4c, 0xc8),
        (0x00, 0x83, 0x8f),
        (0xa1, 0x4d, 0x2c),
        (0x5a, 0x6b, 0x7d),
    ];
    let b = id.as_bytes();
    PALETTE[usize::from(b[0] ^ b[15]) % PALETTE.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(n: u8, kind: PrincipalKind, name: &str) -> Member {
        Member {
            id: id(n),
            kind,
            name: name.into(),
            label: String::new(),
            about: String::new(),
            avatar: None,
        }
    }

    fn rows_of(s: &mut Store, chat: Id) -> Vec<MessageRowData> {
        let cache = RenderCache::default();
        s.message_rows(chat, &TimeFmt::utc(), 0, &RenderView { cache: &cache, dark: false }).0
    }

    fn plain(r: &MessageRowData) -> String {
        r.blocks
            .iter()
            .map(|b| match b {
                BlockData::Text { plain, .. } | BlockData::Code { plain, .. } => plain.clone(),
                BlockData::Image { .. } => "[image]".into(),
                BlockData::Rule => "---".into(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn id(n: u8) -> Id {
        Id::from_bytes([n; 16])
    }

    fn md(t: &str) -> Content {
        Content::Markdown { text: t.into() }
    }

    fn msg(seq: i64, chat: Id, sender: Id, cmid: u8, text: &str, at: i64) -> MessageView {
        MessageView {
            seq,
            id: id(100 + cmid),
            chat_id: chat,
            thread_id: None,
            sender_id: sender,
            recipient_id: None,
            client_msg_id: id(cmid),
            content: md(text),
            created_at_ms: at,
        }
    }

    fn store() -> Store {
        let mut s = Store { me: Some(id(1)), max_content_bytes: 100, ..Store::default() };
        s.set_chats(vec![
            ChatSummary {
                id: id(10),
                kind: ChatKind::NoteToSelf,
                title: "Note to Self".into(),
                members: vec![member(1, PrincipalKind::User, "You")],
                last_message: None,
                link_allowed: None,
            },
            ChatSummary {
                id: id(11),
                kind: ChatKind::Direct,
                title: "Ada Lovelace".into(),
                members: vec![
                    member(1, PrincipalKind::User, "You"),
                    member(2, PrincipalKind::Agent, "Ada Lovelace"),
                ],
                last_message: None,
                link_allowed: None,
            },
        ]);
        s
    }

    #[test]
    fn messages_are_ordered_and_deduplicated() {
        let mut s = store();
        assert!(s.add_messages(
            id(10),
            vec![msg(3, id(10), id(1), 3, "c", 3), msg(1, id(10), id(1), 1, "a", 1)]
        ));
        assert!(!s.add_messages(id(10), vec![msg(1, id(10), id(1), 1, "a", 1)]), "duplicate");
        let bodies: Vec<_> = rows_of(&mut s, id(10)).iter().map(plain).collect();
        assert_eq!(bodies, vec!["a", "c"]);
        assert_eq!(s.last_seq(id(10)), 3);
    }

    #[test]
    fn messages_cannot_be_filed_under_the_wrong_chat() {
        let mut s = store();
        s.add_messages(id(10), vec![msg(1, id(11), id(1), 1, "for the other chat", 1)]);
        assert!(rows_of(&mut s, id(10)).is_empty());
        assert!(!s.add_messages(id(99), vec![msg(2, id(99), id(1), 2, "unknown chat", 1)]));
    }

    #[test]
    fn pending_messages_resolve_when_the_server_echoes_them() {
        let mut s = store();
        s.add_pending(id(10), id(5), md("hi")).expect("chat exists");
        assert!(s.is_pending(id(10), id(5)));
        let rows = rows_of(&mut s, id(10));
        assert!(rows[0].pending && rows[0].outgoing);
        assert_eq!(s.all_pending().len(), 1);
        s.add_messages(id(10), vec![msg(7, id(10), id(1), 5, "hi", 1)]);
        assert!(!s.is_pending(id(10), id(5)));
        let rows = rows_of(&mut s, id(10));
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].pending);
    }

    #[test]
    fn someone_elses_message_with_my_client_id_does_not_clear_my_pending() {
        let mut s = store();
        s.add_pending(id(11), id(5), md("mine")).expect("chat");
        s.add_messages(id(11), vec![msg(7, id(11), id(2), 5, "theirs", 1)]);
        assert!(s.is_pending(id(11), id(5)));
    }

    #[test]
    fn chat_list_orders_by_activity_and_previews() {
        let mut s = store();
        s.add_messages(id(11), vec![msg(1, id(11), id(2), 1, "older", 1)]);
        s.add_messages(id(10), vec![msg(2, id(10), id(1), 2, "newer\nsecond line", 2)]);
        let rows = s.chat_rows(&TimeFmt::utc(), 10);
        assert_eq!(rows[0].id, id(10));
        assert_eq!(rows[0].preview, "newer second line");
        assert!(rows[0].note);
        assert_eq!(rows[1].initials, "AL");
    }

    #[test]
    fn grouping() {
        let mut s = store();
        s.add_messages(
            id(11),
            vec![
                msg(1, id(11), id(2), 1, "a", 0),
                msg(2, id(11), id(2), 2, "b", 60_000),
                msg(3, id(11), id(1), 3, "c", 61_000),
                msg(4, id(11), id(1), 4, "d", 61_000 + GROUP_WINDOW_MS + 1),
            ],
        );
        let starts: Vec<bool> = rows_of(&mut s, id(11)).iter().map(|r| r.group_start).collect();
        assert_eq!(starts, vec![true, false, true, true]);
    }

    #[test]
    fn long_titles_are_truncated() {
        let mut s = Store::default();
        s.set_chats(vec![ChatSummary {
            id: id(1),
            kind: ChatKind::Direct,
            title: "x".repeat(500),
            members: vec![],
            last_message: None,
            link_allowed: None,
        }]);
        assert_eq!(s.chat_rows(&TimeFmt::utc(), 0)[0].title.chars().count(), MAX_TITLE_CHARS);
    }

    #[test]
    fn code_and_math_fall_back_until_rendered_then_use_results() {
        let mut s = store();
        s.add_messages(
            id(10),
            vec![msg(1, id(10), id(1), 1, "```rust\nlet x = 1;\n```\n\n$$\\frac{a}{b}$$", 1)],
        );
        let mut cache = RenderCache::default();
        let (r, reqs) =
            s.message_rows(id(10), &TimeFmt::utc(), 0, &RenderView { cache: &cache, dark: false });
        assert_eq!(reqs.len(), 2, "one highlight and one math request");
        assert!(matches!(&r[0].blocks[0], BlockData::Code { plain, .. } if plain == "let x = 1;"));
        assert!(matches!(&r[0].blocks[1], BlockData::Code { plain, .. } if plain.contains("frac")));
        // Results arrive.
        let span = |t: &str, r| Span {
            text: t.into(),
            color: Rgb { r, g: 0, b: 0 },
            bold: false,
            italic: false,
            underline: false,
            strike: false,
        };
        cache.insert(
            reqs[0].clone(),
            Rendered::Highlighted(vec![vec![span("let", 200), span(" x = 1;", 0x24)]]),
        );
        let img =
            RenderedImage { width: 40, height: 20, pixels: slint::SharedPixelBuffer::new(40, 20) };
        cache.insert(reqs[1].clone(), Rendered::Image(img));
        let (r, reqs) =
            s.message_rows(id(10), &TimeFmt::utc(), 0, &RenderView { cache: &cache, dark: false });
        assert!(reqs.is_empty());
        let BlockData::Code { md, .. } = &r[0].blocks[0] else { panic!() };
        assert!(md.contains("<font color=\"#c80000\">let</font>"), "{md}");
        assert!(
            matches!(&r[0].blocks[1], BlockData::Image { width, .. } if (*width - 20.0).abs() < 0.01)
        );
        assert!(slint::StyledText::from_markdown(md).is_ok());
    }

    #[test]
    fn math_color_matches_the_bubble() {
        let mut s = store();
        s.add_messages(
            id(10),
            vec![msg(1, id(10), id(1), 1, "$$x$$", 1), msg(2, id(10), id(2), 2, "$$x$$", 2)],
        );
        let cache = RenderCache::default();
        let (_, reqs) =
            s.message_rows(id(10), &TimeFmt::utc(), 0, &RenderView { cache: &cache, dark: true });
        let colors: Vec<Rgb> = reqs
            .iter()
            .filter_map(
                |r| if let RenderRequest::Math { color, .. } = r { Some(*color) } else { None },
            )
            .collect();
        let text = Rgb { r: 0xe8, g: 0xee, b: 0xf6 };
        assert_eq!(colors, vec![text, text], "neutral bubbles: theme text color both ways");
    }

    #[test]
    fn plain_code_markup_survives_slint_parsing() {
        let md = plain_code_md("fn main() {\n\n    println!(\"<b>*hi*</b> [x](y)\");\n}");
        let styled = slint::StyledText::from_markdown(&md);
        assert!(styled.is_ok(), "{md}");
    }

    // ---- timeline, activity rows, conversation data, pins, search, unread ----

    const MIN: i64 = 60_000;
    const T0: i64 = 1_791_723_900_000; // a Sunday, 13:05 UTC

    /// You (1), agents Toki (2) and Chika (3); Note to Self (10), DM with Chika (11),
    /// DM with Toki (12), and Toki<->Chika (13).
    fn world() -> Store {
        let mut s = Store { me: Some(id(1)), max_content_bytes: 1000, ..Store::default() };
        let you = member(1, PrincipalKind::User, "You");
        let toki = member(2, PrincipalKind::Agent, "Toki");
        let chika = member(3, PrincipalKind::Agent, "Chika");
        s.set_chats(vec![
            ChatSummary {
                id: id(10),
                kind: ChatKind::NoteToSelf,
                title: "Note to Self".into(),
                members: vec![you.clone()],
                last_message: None,
                link_allowed: None,
            },
            ChatSummary {
                id: id(11),
                kind: ChatKind::Direct,
                title: "Chika".into(),
                members: vec![you.clone(), chika.clone()],
                last_message: None,
                link_allowed: None,
            },
            ChatSummary {
                id: id(12),
                kind: ChatKind::Direct,
                title: "Toki".into(),
                members: vec![you, toki.clone()],
                last_message: None,
                link_allowed: None,
            },
            ChatSummary {
                id: id(13),
                kind: ChatKind::AgentToAgent,
                title: "Chika & Toki".into(),
                members: vec![chika, toki],
                last_message: None,
                link_allowed: None,
            },
        ]);
        s
    }

    fn at(seq: i64, chat: u8, sender: u8, text: &str, when: i64) -> MessageView {
        MessageView {
            seq,
            id: Id::from_bytes([seq as u8; 16]),
            chat_id: id(chat),
            thread_id: None,
            sender_id: id(sender),
            recipient_id: None,
            client_msg_id: Id::from_bytes([200 - seq as u8; 16]),
            content: md(text),
            created_at_ms: when,
        }
    }

    fn timeline(s: &mut Store, chat: u8) -> Vec<TimelineItem> {
        let cache = RenderCache::default();
        s.timeline(id(chat), &TimeFmt::utc(), T0, &RenderView { cache: &cache, dark: true }).0
    }

    fn describe(items: &[TimelineItem]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                TimelineItem::Separator(l) => format!("-- {l}"),
                TimelineItem::Message(m) => format!(
                    "{}{}{}",
                    if m.outgoing { "> " } else { "< " },
                    m.sender.as_ref().map(|p| format!("[{}] ", p.name)).unwrap_or_default(),
                    plain(m)
                ),
                TimelineItem::Activity { prefix, people, .. } => {
                    let names: Vec<_> = people.iter().map(|p| p.name.clone()).collect();
                    format!("* {prefix} {}", names.join(" and "))
                }
            })
            .collect()
    }

    #[test]
    fn timeline_has_separators_and_agent_activity() {
        let mut s = world();
        s.add_messages(
            id(11),
            vec![
                at(1, 11, 1, "Remind me about the Zimaboard", T0 - 60 * MIN),
                at(2, 11, 3, "It was the wrong machine for VMs", T0 - 59 * MIN),
            ],
        );
        // Toki and Chika talk: one message, then later a burst of three.
        s.add_messages(
            id(13),
            vec![
                at(3, 13, 2, "Chika, can you check the RAM limits?", T0 - 50 * MIN),
                at(4, 13, 3, "16 GB max", T0 - 10 * MIN),
                at(5, 13, 2, "Thanks", T0 - 9 * MIN),
                at(6, 13, 3, "np", T0 - 9 * MIN),
            ],
        );
        let items = describe(&timeline(&mut s, 11));
        assert_eq!(
            items,
            vec![
                "-- Today 12:05",
                "> Remind me about the Zimaboard",
                "< It was the wrong machine for VMs",
                "* Message from Toki",
                "* 3 messages with Chika and Toki",
            ],
            "{items:#?}"
        );
    }

    #[test]
    fn agent_to_agent_view_labels_senders_and_is_read_only() {
        let mut s = world();
        s.add_messages(
            id(13),
            vec![
                at(3, 13, 2, "hi", T0 - 3 * MIN),
                at(4, 13, 2, "still me", T0 - 2 * MIN),
                at(5, 13, 3, "hello", T0 - MIN),
            ],
        );
        let items = describe(&timeline(&mut s, 13));
        assert_eq!(
            items,
            vec!["-- Today 13:02", "< [Toki] hi", "< still me", "< [Chika] hello"],
            "{items:#?}"
        );
        let conv = s.conversation(id(13), &TimeFmt::utc(), T0).expect("conv");
        assert!(conv.read_only);
        assert!(conv.composer_placeholder.is_empty());
        assert_eq!(conv.people.len(), 2);
    }

    #[test]
    fn long_gaps_and_new_days_get_separators() {
        let mut s = world();
        s.add_messages(
            id(10),
            vec![
                at(1, 10, 1, "yesterday", T0 - 24 * 60 * MIN),
                at(2, 10, 1, "this morning", T0 - 5 * 60 * MIN),
                at(3, 10, 1, "ten minutes later", T0 - 5 * 60 * MIN + 10 * MIN),
            ],
        );
        let items = describe(&timeline(&mut s, 10));
        assert_eq!(
            items,
            vec![
                "-- Yesterday 13:05",
                "> yesterday",
                "-- Today 08:05",
                "> this morning",
                "> ten minutes later"
            ],
            "{items:#?}"
        );
    }

    #[test]
    fn conversation_data_and_related_chats() {
        let s = world();
        let chika = s.conversation(id(11), &TimeFmt::utc(), T0).expect("conv");
        assert_eq!(chika.title, "Chika");
        assert_eq!(chika.composer_placeholder, "Message Chika");
        assert_eq!(chika.related.iter().map(|r| r.id).collect::<Vec<_>>(), vec![id(13)]);
        assert_eq!(chika.people[0].kind, PersonKind::Agent);
        let note = s.conversation(id(10), &TimeFmt::utc(), T0).expect("conv");
        assert!(note.note);
        assert_eq!(note.people[0].kind, PersonKind::Note);
        assert_eq!(note.composer_placeholder, "Write a note to yourself");
        let rows = s.chat_rows(&TimeFmt::utc(), T0);
        assert_eq!(rows.iter().filter(|r| r.section == Section::BetweenAgents).count(), 1);
        assert_eq!(rows.iter().find(|r| r.id == id(13)).map(|r| r.people.len()), Some(2));
    }

    #[test]
    fn pins_are_capped_at_three() {
        let mut s = world();
        assert!(s.toggle_pin(id(10)) && s.toggle_pin(id(11)) && s.toggle_pin(id(12)));
        assert!(!s.toggle_pin(id(13)), "fourth pin refused");
        assert!(!s.toggle_pin(id(99)), "unknown chat refused");
        assert!(s.toggle_pin(id(11)), "unpin");
        assert!(s.toggle_pin(id(13)));
        assert_eq!(s.pinned(), &[id(10), id(12), id(13)]);
        assert!(
            s.chat_rows(&TimeFmt::utc(), T0)
                .iter()
                .find(|r| r.id == id(13))
                .is_some_and(|r| r.pinned)
        );
    }

    #[test]
    fn search_filters_the_chat_list() {
        let mut s = world();
        s.add_messages(id(12), vec![at(1, 12, 2, "the garlic plan is ready", T0)]);
        s.search = "GARLIC".into();
        let rows = s.chat_rows(&TimeFmt::utc(), T0);
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![id(12)]);
        s.search = "chi".into();
        let ids: Vec<Id> = s.chat_rows(&TimeFmt::utc(), T0).iter().map(|r| r.id).collect();
        assert!(ids.contains(&id(11)) && ids.contains(&id(13)) && !ids.contains(&id(10)));
    }

    #[test]
    fn unread_counts_only_new_messages_from_others() {
        let mut s = world();
        s.add_messages(id(11), vec![at(1, 11, 3, "new from Chika", T0), at(2, 11, 1, "mine", T0)]);
        let unread = |s: &Store| {
            s.chat_rows(&TimeFmt::utc(), T0).iter().find(|r| r.id == id(11)).map(|r| r.unread)
        };
        assert_eq!(unread(&s), Some(1));
        s.mark_read(id(11));
        assert_eq!(unread(&s), Some(0));
    }

    #[test]
    fn profile_changes_update_every_chat() {
        let mut s = world();
        let mut chika = member(3, PrincipalKind::Agent, "Chika");
        chika.name = "Chika 2".into();
        s.update_member(&chika);
        let rows = s.chat_rows(&TimeFmt::utc(), T0);
        assert_eq!(
            rows.iter().find(|r| r.id == id(11)).map(|r| r.title.as_str()),
            Some("Chika 2"),
            "DM retitled"
        );
        let a2a = rows.iter().find(|r| r.id == id(13)).expect("a2a");
        assert!(a2a.people.iter().any(|p| p.name == "Chika 2"));
    }

    #[test]
    fn pictures_are_fetched_once_and_shown_when_ready() {
        let mut s = world();
        assert!(s.wanted_avatars().is_empty(), "nobody has a picture yet");
        let hash = BlobHash::from_bytes([5; 32]);
        let mut chika = member(3, PrincipalKind::Agent, "Chika");
        chika.avatar = Some(hash);
        chika.label = "Garden".into();
        s.update_member(&chika);
        assert_eq!(s.wanted_avatars(), vec![hash]);
        assert!(s.wanted_avatars().is_empty(), "already loading");
        let dm = |s: &Store| {
            s.chat_rows(&TimeFmt::utc(), T0).into_iter().find(|r| r.id == id(11)).expect("dm")
        };
        let p = dm(&s).people[0].clone();
        assert_eq!((p.label.as_str(), p.avatar.is_none()), ("Garden", true), "initials meanwhile");

        let img = RenderedImage {
            width: 256,
            height: 256,
            pixels: slint::SharedPixelBuffer::new(256, 256),
        };
        s.set_avatar(hash, Some(img));
        assert_eq!(dm(&s).people[0].avatar.as_ref().map(|a| a.hash), Some(hash));

        // A failure falls back to initials and is retried after a reconnect.
        let other = BlobHash::from_bytes([6; 32]);
        chika.avatar = Some(other);
        s.update_member(&chika);
        assert_eq!(s.wanted_avatars(), vec![other]);
        s.set_avatar(other, None);
        assert!(dm(&s).people[0].avatar.is_none());
        assert!(s.wanted_avatars().is_empty());
        s.forget_failed_avatars();
        assert_eq!(s.wanted_avatars(), vec![other]);
    }

    #[test]
    fn direct_chats_expose_the_agent_for_editing() {
        let s = world();
        let c = s.conversation(id(11), &TimeFmt::utc(), T0).expect("dm");
        assert_eq!(c.agent, Some(id(3)));
        assert!(s.is_agent(id(3)));
        assert!(!s.is_agent(id(1)), "the user isn't an agent");
        assert!(!s.is_agent(id(99)), "unknown");
        let note = s.conversation(id(10), &TimeFmt::utc(), T0).expect("note");
        assert_eq!(note.agent, None);
    }
}
