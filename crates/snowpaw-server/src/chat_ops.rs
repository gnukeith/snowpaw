//! Chat operations shared by the user's socket and agent runtimes' sockets: listing
//! chats, syncing messages, and posting, with every policy check in one place.
//!
//! Who may do what:
//! - Anyone reads and posts only in chats they're a member of. The user can also
//!   read (never post in) conversations between agents.
//! - Agents' posts are rate limited, stop when the kill switch is on, and in
//!   conversations with other agents must say what they reply to: each reply is one
//!   level deeper, and past `agents.max_depth` the conversation stops. A paused link
//!   stops it too.
//! - Only the user answers quizzes, and the server grades the answers from the
//!   stored quiz.

use snowpaw_proto::Id;
use snowpaw_proto::agent::SendRefusal;
use snowpaw_proto::quiz::QuizAnswers;
use snowpaw_proto::ws::{
    ChatKind, ChatSummary, Content, MAX_TITLE_CHARS, MessageView, WsErrorCode, truncate_chars,
};
use tracing::error;

use crate::api::{AppState, MessageEvent};
use crate::auth;
use crate::db::{self, Appended, DbError, NewMessage};

/// One line of the last message in a chat summary: enough for a list row. The full
/// body always comes from a `sync`.
const LAST_MESSAGE_PREVIEW_CHARS: usize = 160;
/// Kept back from a frame budget for the JSON envelope around the payload.
const ENVELOPE_BYTES: usize = 512;

/// The chat list, sized so the reply always fits the frame budget of the socket it
/// will be sent on. Each summary carries only a preview of its last message, and
/// summaries that would push the reply past the budget are truncated from the
/// least-recently-active end (their last messages go first, then the chats
/// themselves; the full data is one `sync` away).
pub async fn list_chats(
    st: &AppState,
    me: Id,
    frame_budget: usize,
) -> Result<Vec<ChatSummary>, DbError> {
    let observer = me == st.user_id;
    let rows = st.db.call(move |c| db::chats_for(c, me, observer)).await?;
    let mut out: Vec<ChatSummary> = Vec::with_capacity(rows.len());
    let mut bytes = 0usize;
    let budget = frame_budget.saturating_sub(ENVELOPE_BYTES);
    for r in rows {
        let mut summary = ChatSummary {
            id: r.id,
            kind: r.kind,
            title: truncate_chars(&r.title, MAX_TITLE_CHARS),
            members: r
                .members
                .into_iter()
                .map(|mut m| {
                    m.name = truncate_chars(&m.name, MAX_TITLE_CHARS);
                    m
                })
                .collect(),
            last_message: None,
            link_allowed: r.link_allowed,
        };
        let bare = snowpaw_proto::encode(&summary).len();
        let with_last = r.last_message.map(|m| {
            let mut view = m.into_view();
            view.content =
                Content::Markdown { text: view.content.preview(LAST_MESSAGE_PREVIEW_CHARS) };
            summary.last_message = Some(view);
            snowpaw_proto::encode(&summary).len()
        });
        match with_last {
            Some(size) if bytes + size <= budget => bytes += size,
            _ if bytes + bare <= budget || out.is_empty() => {
                summary.last_message = None;
                bytes += bare;
            }
            _ => break,
        }
        out.push(summary);
    }
    Ok(out)
}

/// Messages after `after_seq`, if `me` may read the chat, sized so the reply always
/// fits the frame budget of the socket it will be sent on; the rest come with
/// `has_more`. `None`: no such chat or not allowed (indistinguishable on purpose).
pub async fn sync(
    st: &AppState,
    me: Id,
    chat_id: Id,
    after_seq: i64,
    limit: u32,
    frame_budget: usize,
) -> Result<Option<(Vec<MessageView>, bool)>, DbError> {
    let observer = me == st.user_id;
    let budget = frame_budget.saturating_sub(ENVELOPE_BYTES);
    st.db
        .call(move |c| {
            if db::chat_if_visible(c, chat_id, me, observer)?.is_none() {
                return Ok(None);
            }
            let msgs = db::messages_after(c, chat_id, after_seq, limit + 1)?;
            let mut has_more = msgs.len() > limit as usize;
            let mut out = Vec::with_capacity(msgs.len().min(limit as usize));
            let mut bytes = 0usize;
            for m in msgs.into_iter().take(limit as usize) {
                let view = m.into_view();
                bytes += snowpaw_proto::encode(&view).len();
                if bytes > budget && !out.is_empty() {
                    has_more = true;
                    break;
                }
                out.push(view);
            }
            Ok(Some((out, has_more)))
        })
        .await
}

#[derive(Debug, Clone)]
pub struct Post {
    pub chat_id: Id,
    pub client_msg_id: Id,
    pub content: Content,
    pub in_reply_to: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostOutcome {
    Sent {
        client_msg_id: Id,
        id: Id,
        seq: i64,
    },
    /// Policy said no; the connection stays open.
    Refused(SendRefusal),
    /// Close the connection with this code.
    Fatal(WsErrorCode),
}

enum Checked {
    Ok(Box<Appended>, Vec<Id>),
    Refused(SendRefusal),
    Fatal(WsErrorCode),
}

pub async fn post(st: &AppState, me: Id, p: Post) -> PostOutcome {
    let is_user = me == st.user_id;
    if p.content.validate_incoming(st.cfg.limits.max_message_bytes).is_err() {
        return PostOutcome::Fatal(WsErrorCode::InvalidContent);
    }
    if matches!(p.content, Content::QuizAnswers { .. }) && !is_user {
        return PostOutcome::Fatal(WsErrorCode::Forbidden);
    }
    let id = match auth::random_id() {
        Ok(id) => id,
        Err(e) => {
            error!(error = %e, "no randomness");
            return PostOutcome::Fatal(WsErrorCode::Internal);
        }
    };
    let now = st.clock.now_ms();
    let user = st.user_id;
    let limits = st.cfg.agents.clone();
    let Post { chat_id, client_msg_id, content, in_reply_to } = p;
    let result = st
        .db
        .call(move |c| {
            // A retry of something already stored is confirmed before any policy check,
            // so a rate limit can't make a client think its message was lost.
            if let Some(existing) = db::message_by_client_id(c, me, client_msg_id)? {
                let members = db::chat_if_member(c, existing.chat_id, me)?
                    .map(|(_, m)| m)
                    .unwrap_or_default();
                return Ok(Checked::Ok(Box::new(Appended::Duplicate(existing)), members));
            }
            if !is_user {
                if db::agents_paused(c)? {
                    return Ok(Checked::Refused(SendRefusal::Paused));
                }
                let recent = db::messages_sent_since(c, me, None, now - 60_000)?;
                if recent >= i64::from(limits.messages_per_minute) {
                    return Ok(Checked::Refused(SendRefusal::RateLimited));
                }
            }
            let Some((kind, members)) = db::chat_if_member(c, chat_id, me)? else {
                return Ok(Checked::Fatal(WsErrorCode::Forbidden));
            };
            let mut depth = 0u32;
            if kind == ChatKind::AgentToAgent {
                // Malformed first (fatal), then policy (a refusal).
                let Some(seq) = in_reply_to else {
                    return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
                };
                let Some((target_chat, target_sender, source_depth)) =
                    db::reply_target(c, seq, me)?
                else {
                    return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
                };
                if db::link_allowed(c, chat_id)? != Some(true) {
                    return Ok(Checked::Refused(SendRefusal::LinkPaused));
                }
                if target_chat == chat_id {
                    // The conversation itself: each reply is one level deeper.
                    depth = source_depth + 1;
                } else if target_sender == user {
                    // A cross-chat reply is how a conversation between agents starts
                    // or restarts: it must be anchored on something the user actually
                    // wrote. Agents can't cite their own or each other's messages to
                    // reset the depth clock, so an autonomous back-and-forth always
                    // grows towards the limit.
                    depth = 1;
                } else {
                    return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
                }
                if depth > limits.max_depth {
                    db::audit(
                        c,
                        now,
                        Some(me),
                        "agent_depth_limit",
                        Some(chat_id),
                        &format!("stopped at depth {depth}"),
                    )?;
                    return Ok(Checked::Refused(SendRefusal::DepthLimit));
                }
                let in_link = db::messages_sent_since(c, me, Some(chat_id), now - 3_600_000)?;
                if in_link >= i64::from(limits.link_messages_per_hour) {
                    return Ok(Checked::Refused(SendRefusal::RateLimited));
                }
            } else if let Some(seq) = in_reply_to
                && db::reply_target(c, seq, me)?.is_none()
            {
                // Must point at something the sender can see.
                return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
            }
            let content = match content {
                Content::QuizAnswers { answers } => {
                    let Some(quiz_msg) = db::message_in_chat(c, chat_id, answers.quiz_id)? else {
                        return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
                    };
                    let Content::Quiz { quiz } = quiz_msg.content else {
                        return Ok(Checked::Fatal(WsErrorCode::InvalidRequest));
                    };
                    if quiz_msg.sender_id == me || quiz.check_answers(&answers.answers).is_err() {
                        return Ok(Checked::Fatal(WsErrorCode::InvalidContent));
                    }
                    let results = quiz.grade(&answers.answers);
                    Content::QuizAnswers { answers: QuizAnswers { results, ..answers } }
                }
                other => other,
            };
            // Addressed to the other member of a direct chat; nobody otherwise.
            let recipient_id = match kind {
                ChatKind::Direct => members.iter().copied().find(|m| *m != me),
                ChatKind::NoteToSelf | ChatKind::AgentToAgent => None,
            };
            let new = NewMessage {
                id,
                chat_id,
                thread_id: None,
                sender_id: me,
                recipient_id,
                client_msg_id,
                content: &content,
                depth,
            };
            let appended = db::append_message(c, &new, now)?;
            // The user reads along in conversations between agents.
            let mut audience = members;
            if kind == ChatKind::AgentToAgent {
                audience.push(user);
            }
            Ok(Checked::Ok(Box::new(appended), audience))
        })
        .await;
    match result.map(|c| match c {
        Checked::Ok(appended, audience) => (Some((*appended, audience)), None),
        Checked::Refused(r) => (None, Some(Ok(r))),
        Checked::Fatal(code) => (None, Some(Err(code))),
    }) {
        Ok((Some((Appended::New(m), audience)), _)) => {
            let sent = PostOutcome::Sent { client_msg_id, id: m.id, seq: m.seq };
            st.publish(MessageEvent { members: audience, message: m.into_view() });
            sent
        }
        // Reusing an id for a different chat is a client bug, not a retry.
        Ok((Some((Appended::Duplicate(m), _)), _)) if m.chat_id == chat_id => {
            PostOutcome::Sent { client_msg_id, id: m.id, seq: m.seq }
        }
        Ok((Some((Appended::Duplicate(_), _)), _)) => {
            PostOutcome::Fatal(WsErrorCode::InvalidRequest)
        }
        Ok((None, Some(Ok(r)))) => PostOutcome::Refused(r),
        Ok((None, Some(Err(code)))) => PostOutcome::Fatal(code),
        Ok((None, None)) => PostOutcome::Fatal(WsErrorCode::Internal),
        Err(e) => {
            error!(error = %e, "posting failed");
            PostOutcome::Fatal(WsErrorCode::Internal)
        }
    }
}
