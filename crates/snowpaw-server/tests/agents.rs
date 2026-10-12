//! Agent runtimes: tokens, scoping, agent-to-agent limits, the kill switch, model
//! calls through the server, quizzes, and the audit log. Mostly attempts to get
//! around those controls.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{TestServer, Ws, upgrade_status};
use futures_util::{SinkExt, StreamExt};
use snowpaw_proto::agent::{
    AgentEnvelope, AgentMsg, AgentServerEnvelope, AgentServerMsg, ApiKeyChange, InferFailure,
    ModelSettings, SendRefusal, Turn,
};
use snowpaw_proto::quiz::{Question, Quiz, QuizAnswers};
use snowpaw_proto::ws::{
    ChatKind, ClientEnvelope, ClientMsg, Content, ServerEnvelope, ServerMsg, WsErrorCode,
};
use snowpaw_proto::{Id, SecretString, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

const SECRET_KEY: &str = "sk-live-SECRET-0123456789";

fn id(n: u8) -> Id {
    Id::from_bytes([n; 16])
}

fn md(t: &str) -> Content {
    Content::Markdown { text: t.into() }
}

async fn next_text(ws: &mut Ws) -> Option<String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.ok()?? {
            Ok(Message::Text(t)) => return Some(t.as_str().to_owned()),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
}

struct User {
    ws: Ws,
    you: Id,
}

impl User {
    async fn connect(s: &TestServer) -> Self {
        let token = s.token().await;
        let mut ws = s.ws(&token).await.unwrap();
        let text = next_text(&mut ws).await.unwrap();
        let you = match snowpaw_proto::decode::<ServerEnvelope>(text.as_bytes()).unwrap().msg {
            ServerMsg::Welcome { you, .. } => you,
            other => panic!("{other:?}"),
        };
        Self { ws, you }
    }

    async fn send(&mut self, msg: ClientMsg) {
        self.ws.send(Message::Text(encode(&ClientEnvelope::new(msg)).into())).await.unwrap();
    }

    async fn recv(&mut self) -> Option<ServerMsg> {
        let t = next_text(&mut self.ws).await?;
        Some(snowpaw_proto::decode::<ServerEnvelope>(t.as_bytes()).unwrap().msg)
    }

    /// The next frame matching `f`, skipping others.
    async fn expect(&mut self, f: impl Fn(&ServerMsg) -> bool) -> ServerMsg {
        loop {
            match self.recv().await {
                Some(m) if f(&m) => return m,
                Some(_) => continue,
                None => panic!("connection ended while waiting"),
            }
        }
    }

    async fn closed_with(&mut self) -> Option<WsErrorCode> {
        let mut code = None;
        while let Some(m) = self.recv().await {
            if let ServerMsg::Error { code: c } = m {
                code = Some(c);
            }
        }
        code
    }

    async fn create_agent(&mut self, name: &str) -> (Id, Id) {
        self.send(ClientMsg::CreateAgent {
            name: name.into(),
            label: String::new(),
            about: String::new(),
        })
        .await;
        match self.expect(|m| matches!(m, ServerMsg::AgentCreated { .. })).await {
            ServerMsg::AgentCreated { chat_id, agent } => (chat_id, agent.id),
            _ => unreachable!(),
        }
    }

    async fn issue_token(&mut self, agent: Id) -> String {
        self.send(ClientMsg::IssueAgentToken { agent }).await;
        match self.expect(|m| matches!(m, ServerMsg::AgentToken { .. })).await {
            ServerMsg::AgentToken { token, .. } => token.expose().to_owned(),
            _ => unreachable!(),
        }
    }

    async fn post(&mut self, chat_id: Id, n: u8, content: Content) -> i64 {
        self.send(ClientMsg::Send { chat_id, client_msg_id: id(n), content }).await;
        match self.expect(|m| matches!(m, ServerMsg::Sent { .. })).await {
            ServerMsg::Sent { seq, .. } => seq,
            _ => unreachable!(),
        }
    }

    async fn audit(&mut self) -> Vec<snowpaw_proto::agent::AuditEntry> {
        self.send(ClientMsg::ListAudit { before_seq: None, limit: 200 }).await;
        match self.expect(|m| matches!(m, ServerMsg::Audit { .. })).await {
            ServerMsg::Audit { entries, .. } => entries,
            _ => unreachable!(),
        }
    }

    async fn set_model(&mut self, agent: Id, model: ModelSettings, api_key: ApiKeyChange) {
        self.send(ClientMsg::SetAgentModel { agent, model, api_key }).await;
        self.expect(|m| matches!(m, ServerMsg::AgentSettings { .. })).await;
    }
}

struct Agent {
    ws: Ws,
}

impl Agent {
    async fn connect(s: &TestServer, token: &str) -> (Self, AgentServerMsg) {
        let mut ws = s.agent_ws(token).await.unwrap();
        let text = next_text(&mut ws).await.unwrap();
        let welcome = snowpaw_proto::decode::<AgentServerEnvelope>(text.as_bytes()).unwrap().msg;
        assert!(matches!(welcome, AgentServerMsg::Welcome { .. }), "{welcome:?}");
        (Self { ws }, welcome)
    }

    async fn send(&mut self, msg: AgentMsg) {
        self.ws.send(Message::Text(encode(&AgentEnvelope::new(msg)).into())).await.unwrap();
    }

    async fn recv(&mut self) -> Option<AgentServerMsg> {
        let t = next_text(&mut self.ws).await?;
        Some(snowpaw_proto::decode::<AgentServerEnvelope>(t.as_bytes()).unwrap().msg)
    }

    async fn expect(&mut self, f: impl Fn(&AgentServerMsg) -> bool) -> AgentServerMsg {
        loop {
            match self.recv().await {
                Some(m) if f(&m) => return m,
                Some(_) => continue,
                None => panic!("agent connection ended while waiting"),
            }
        }
    }

    async fn closed_with(&mut self) -> Option<WsErrorCode> {
        let mut code = None;
        while let Some(m) = self.recv().await {
            if let AgentServerMsg::Error { code: c } = m {
                code = Some(c);
            }
        }
        code
    }

    /// Post; returns the seq, or the refusal.
    async fn post(
        &mut self,
        chat_id: Id,
        n: u8,
        text: &str,
        in_reply_to: Option<i64>,
    ) -> Result<i64, SendRefusal> {
        self.send(AgentMsg::Send { chat_id, client_msg_id: id(n), content: md(text), in_reply_to })
            .await;
        match self
            .expect(|m| {
                matches!(m, AgentServerMsg::Sent { .. } | AgentServerMsg::SendRefused { .. })
            })
            .await
        {
            AgentServerMsg::Sent { seq, .. } => Ok(seq),
            AgentServerMsg::SendRefused { reason, .. } => Err(reason),
            _ => unreachable!(),
        }
    }

    async fn infer(&mut self, text: &str) -> Result<(String, u64), InferFailure> {
        let request_id = id(77);
        self.send(AgentMsg::Infer {
            request_id,
            turns: vec![Turn::User { content: text.into() }],
            tools: vec![],
        })
        .await;
        match self
            .expect(|m| {
                matches!(m, AgentServerMsg::Inferred { .. } | AgentServerMsg::InferFailed { .. })
            })
            .await
        {
            AgentServerMsg::Inferred { reply, usage, .. } => {
                Ok((reply.text, usage.prompt_tokens + usage.completion_tokens))
            }
            AgentServerMsg::InferFailed { reason, .. } => Err(reason),
            _ => unreachable!(),
        }
    }
}

/// A user with one agent whose runtime is connected.
async fn with_agent(s: &TestServer, name: &str) -> (User, Agent, Id, Id, String) {
    let mut user = User::connect(s).await;
    let (chat, agent) = user.create_agent(name).await;
    let token = user.issue_token(agent).await;
    let (runtime, _) = Agent::connect(s, &token).await;
    (user, runtime, chat, agent, token)
}

#[tokio::test]
async fn runtime_tokens_are_scoped_and_revocable() {
    let s = TestServer::start().await;
    let mut user = User::connect(&s).await;
    let (_, agent) = user.create_agent("Mochi").await;
    let token = user.issue_token(agent).await;
    assert!(token.starts_with("spw_a_") && token.len() == 6 + 64);
    let (mut runtime, welcome) = Agent::connect(&s, &token).await;
    match welcome {
        AgentServerMsg::Welcome { you, .. } => assert_eq!(you.id, agent),
        _ => unreachable!(),
    }

    // Each token type only opens its own door.
    let session = s.token().await;
    assert_eq!(upgrade_status(&s.ws(&token).await.unwrap_err()), Some(401));
    assert_eq!(upgrade_status(&s.agent_ws(&session).await.unwrap_err()), Some(401));
    for bad in ["spw_a_", "spw_a_zz", &format!("spw_a_{}", "0".repeat(64)), &token.to_uppercase()] {
        assert_eq!(upgrade_status(&s.agent_ws(bad).await.unwrap_err()), Some(401), "{bad}");
    }
    // An agent token is no good for HTTP routes either.
    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 401);

    // A new token cuts off whatever holds the old one, at once.
    let token2 = user.issue_token(agent).await;
    assert_eq!(runtime.closed_with().await, Some(WsErrorCode::SessionEnded));
    assert_eq!(upgrade_status(&s.agent_ws(&token).await.unwrap_err()), Some(401));
    let (mut runtime, _) = Agent::connect(&s, &token2).await;

    // Revoking does too.
    user.send(ClientMsg::RevokeAgentToken { agent }).await;
    assert_eq!(runtime.closed_with().await, Some(WsErrorCode::SessionEnded));
    assert_eq!(upgrade_status(&s.agent_ws(&token2).await.unwrap_err()), Some(401));

    let audit = user.audit().await;
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"agent_token_issued") && actions.contains(&"agent_token_revoked"));
    let all = format!("{audit:?}");
    assert!(
        !all.contains(&token[6..]) && !all.contains(&token2[6..]),
        "no tokens in the audit log"
    );
}

#[tokio::test]
async fn agents_only_reach_their_own_chats() {
    let s = TestServer::start().await;
    let (mut user, mut a, a_chat, _, _) = with_agent(&s, "Ada").await;
    let (b_chat, _) = user.create_agent("Bo").await;

    a.send(AgentMsg::ListChats {}).await;
    match a.expect(|m| matches!(m, AgentServerMsg::Chats { .. })).await {
        AgentServerMsg::Chats { chats } => {
            let ids: Vec<Id> = chats.iter().map(|c| c.id).collect();
            assert_eq!(ids, vec![a_chat], "not Note to Self, not Bo's chat");
        }
        _ => unreachable!(),
    }
    let a_id = a_agent(&mut user, a_chat).await;
    let token = user.issue_token(a_id).await;
    for attempt in [
        AgentMsg::Sync { chat_id: b_chat, after_seq: 0, limit: 10 },
        AgentMsg::Send {
            chat_id: b_chat,
            client_msg_id: id(1),
            content: md("hi"),
            in_reply_to: None,
        },
        AgentMsg::Working { chat_id: b_chat, working: true },
    ] {
        let (mut a, _) = Agent::connect(&s, &token).await;
        a.send(attempt.clone()).await;
        assert_eq!(a.closed_with().await, Some(WsErrorCode::Forbidden), "{attempt:?}");
    }
    // User-only requests don't exist on the agent socket at all.
    for frame in [
        r#"{"v":1,"msg":{"type":"create_agent","name":"x","label":"","about":""}}"#,
        r#"{"v":1,"msg":{"type":"set_agents_paused","paused":false}}"#,
        r#"{"v":1,"msg":{"type":"issue_agent_token","agent":"0101010101010101010101010101010101"}}"#,
        r#"{"v":1,"msg":{"type":"list_audit","limit":10}}"#,
    ] {
        let (mut a, _) = Agent::connect(&s, &token).await;
        a.ws.send(Message::Text(frame.into())).await.unwrap();
        assert_eq!(a.closed_with().await, Some(WsErrorCode::BadFrame), "{frame}");
    }
}

/// The agent in a direct chat (from the user's chat list).
async fn a_agent(user: &mut User, chat: Id) -> Id {
    user.send(ClientMsg::ListChats {}).await;
    match user.expect(|m| matches!(m, ServerMsg::Chats { .. })).await {
        ServerMsg::Chats { chats } => {
            let c = chats.into_iter().find(|c| c.id == chat).unwrap();
            c.members.into_iter().find(|m| m.id != user.you).unwrap().id
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn user_and_agent_talk_and_working_is_shown() {
    let s = TestServer::start().await;
    let (mut user, mut a, chat, agent, _) = with_agent(&s, "Ada").await;
    let seq = user.post(chat, 1, md("hello Ada")).await;
    match a.expect(|m| matches!(m, AgentServerMsg::NewMessage { .. })).await {
        AgentServerMsg::NewMessage { message } => assert_eq!(message.seq, seq),
        _ => unreachable!(),
    }
    a.send(AgentMsg::Working { chat_id: chat, working: true }).await;
    let status =
        user.expect(|m| matches!(m, ServerMsg::AgentStatus { working_in: Some(_), .. })).await;
    assert_eq!(status, ServerMsg::AgentStatus { agent, connected: true, working_in: Some(chat) });
    a.post(chat, 2, "hi!", Some(seq)).await.unwrap();
    match user.expect(|m| matches!(m, ServerMsg::NewMessage { .. })).await {
        ServerMsg::NewMessage { message } => {
            assert_eq!((message.sender_id, message.content), (agent, md("hi!")));
        }
        _ => unreachable!(),
    }
    // A reply must point at something the agent can see.
    a.send(AgentMsg::Send {
        chat_id: chat,
        client_msg_id: id(3),
        content: md("x"),
        in_reply_to: Some(999_999),
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));
    let status =
        user.expect(|m| matches!(m, ServerMsg::AgentStatus { connected: false, .. })).await;
    assert_eq!(status, ServerMsg::AgentStatus { agent, connected: false, working_in: None });
}

#[tokio::test]
async fn agent_to_agent_needs_a_link_and_stops_at_the_depth_limit() {
    let s = TestServer::start_with("[agents]\nmax_depth = 3\n").await;
    let (mut user, mut a, a_chat, a_id, _) = with_agent(&s, "Ada").await;
    let (b_chat, b_id) = user.create_agent("Bo").await;
    let b_token = user.issue_token(b_id).await;
    let (mut b, _) = Agent::connect(&s, &b_token).await;

    user.send(ClientMsg::SetAgentLink { a: a_id, b: b_id, allowed: true }).await;
    user.send(ClientMsg::ListChats {}).await;
    let link = loop {
        if let ServerMsg::Chats { chats } =
            user.expect(|m| matches!(m, ServerMsg::Chats { .. })).await
            && let Some(c) = chats.into_iter().find(|c| c.kind == ChatKind::AgentToAgent)
        {
            assert_eq!(c.link_allowed, Some(true));
            break c.id;
        }
        user.send(ClientMsg::ListChats {}).await;
    };

    // The user starts it (depth 0), then each reply is one level deeper.
    let start = user.post(a_chat, 1, md("ask Bo")).await;
    let d1 = a.post(link, 10, "Bo, a question", Some(start)).await.unwrap();
    // The user reads along, live.
    user.expect(|m| matches!(m, ServerMsg::NewMessage { message } if message.chat_id == link))
        .await;
    let d2 = b.post(link, 11, "an answer", Some(d1)).await.unwrap();
    let d3 = a.post(link, 12, "a follow-up", Some(d2)).await.unwrap();
    assert_eq!(b.post(link, 13, "and so on", Some(d3)).await, Err(SendRefusal::DepthLimit));
    // Replying to an older message doesn't reset the depth past the limit either.
    assert_eq!(b.post(link, 14, "again", Some(d3)).await, Err(SendRefusal::DepthLimit));

    // Pausing the link stops both.
    user.send(ClientMsg::SetAgentLink { a: a_id, b: b_id, allowed: false }).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(a.post(link, 15, "still there?", Some(d1)).await, Err(SendRefusal::LinkPaused));

    // Without saying what it replies to: refused outright.
    a.send(AgentMsg::Send {
        chat_id: link,
        client_msg_id: id(16),
        content: md("x"),
        in_reply_to: None,
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));
    // Replying "to" a message in a chat it can't see: refused.
    let b_seq = user.post(b_chat, 2, md("for Bo only")).await;
    b.send(AgentMsg::Send {
        chat_id: b_chat,
        client_msg_id: id(17),
        content: md("ok"),
        in_reply_to: Some(b_seq),
    })
    .await;
    b.expect(|m| matches!(m, AgentServerMsg::Sent { .. })).await;
    let token = user.issue_token(a_id).await;
    let (mut a, _) = Agent::connect(&s, &token).await;
    a.send(AgentMsg::Send {
        chat_id: a_chat,
        client_msg_id: id(18),
        content: md("x"),
        in_reply_to: Some(b_seq),
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));

    // The user can't post into a conversation between agents.
    user.send(ClientMsg::Send { chat_id: link, client_msg_id: id(19), content: md("hey") }).await;
    assert_eq!(user.closed_with().await, Some(WsErrorCode::Forbidden));
    let mut user = User::connect(&s).await;
    let audit = user.audit().await;
    assert!(audit.iter().any(|e| e.action == "agent_depth_limit"));
}

#[tokio::test]
async fn a_conversation_between_agents_cannot_be_restarted_by_citing_agents() {
    // The depth limit only stops runaway agent-to-agent loops if cross-chat reply
    // anchors are things the user actually wrote. An agent citing its own or
    // another agent's message from elsewhere must not reset the clock.
    let s = TestServer::start_with("[agents]\nmax_depth = 2\n").await;
    let (mut user, mut a, a_chat, a_id, a_token) = with_agent(&s, "Ada").await;
    let (_, b_id) = user.create_agent("Bo").await;
    let b_token = user.issue_token(b_id).await;
    let (mut b, _) = Agent::connect(&s, &b_token).await;
    let (_, c_id) = user.create_agent("Cy").await;
    user.send(ClientMsg::SetAgentLink { a: a_id, b: b_id, allowed: true }).await;
    user.send(ClientMsg::SetAgentLink { a: a_id, b: c_id, allowed: true }).await;
    user.send(ClientMsg::ListChats {}).await;
    let chats = match user.expect(|m| matches!(m, ServerMsg::Chats { .. })).await {
        ServerMsg::Chats { chats } => chats,
        _ => unreachable!(),
    };
    let find = |with: Id| {
        chats
            .iter()
            .find(|c| c.kind == ChatKind::AgentToAgent && c.members.iter().any(|m| m.id == with))
            .unwrap()
            .id
    };
    let link = find(b_id);
    let other_link = find(c_id);

    // Run the conversation into the depth limit.
    let start = user.post(a_chat, 1, md("ask Bo")).await;
    let d1 = a.post(link, 10, "Bo?", Some(start)).await.unwrap();
    let d2 = b.post(link, 11, "yes", Some(d1)).await.unwrap();
    assert_eq!(a.post(link, 12, "and?", Some(d2)).await, Err(SendRefusal::DepthLimit));

    // Citing its own message from another chat doesn't restart anything.
    let own = a.post(a_chat, 20, "a private note", None).await.unwrap();
    a.send(AgentMsg::Send {
        chat_id: link,
        client_msg_id: id(21),
        content: md("restart?"),
        in_reply_to: Some(own),
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));
    let (mut a, _) = Agent::connect(&s, &a_token).await;

    // Nor another agent's message from a different conversation between agents.
    let content = md("cy speaks in the other conversation");
    let db = snowpaw_server::db::Db::open(
        &s.db_path(),
        snowpaw_server::fsperm::effective_uid(&s.data_dir).unwrap(),
    )
    .unwrap();
    let cy_seq = db
        .call_blocking(|c| {
            snowpaw_server::db::append_message(
                c,
                &snowpaw_server::db::NewMessage {
                    id: id(60),
                    chat_id: other_link,
                    thread_id: None,
                    sender_id: c_id,
                    recipient_id: None,
                    client_msg_id: id(61),
                    content: &content,
                    depth: 1,
                },
                2,
            )
        })
        .unwrap();
    let cy_seq = match cy_seq {
        snowpaw_server::db::Appended::New(m) => m.seq,
        snowpaw_server::db::Appended::Duplicate(_) => panic!("seed message duplicated"),
    };
    a.send(AgentMsg::Send {
        chat_id: link,
        client_msg_id: id(22),
        content: md("restart?"),
        in_reply_to: Some(cy_seq),
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));
    let (mut a, _) = Agent::connect(&s, &a_token).await;

    // A genuinely new user message does start a fresh exchange, even at the limit.
    let fresh = user.post(a_chat, 2, md("one more thing")).await;
    assert!(a.post(link, 23, "new round", Some(fresh)).await.is_ok());
}

#[tokio::test]
async fn agent_posts_are_rate_limited() {
    let s = TestServer::start_with("[agents]\nmessages_per_minute = 3\n").await;
    let (_user, mut a, chat, _, _) = with_agent(&s, "Ada").await;
    for n in 0..3 {
        a.post(chat, n, "spam?", None).await.unwrap();
    }
    assert_eq!(a.post(chat, 3, "spam!", None).await, Err(SendRefusal::RateLimited));
    // A retry of an already-stored message is still confirmed, limit or not.
    assert!(a.post(chat, 0, "spam?", None).await.is_ok());
    s.clock.advance_secs(61);
    assert!(a.post(chat, 4, "a minute later", None).await.is_ok());
}

#[tokio::test]
async fn a_newer_runtime_replaces_the_older_one() {
    let s = TestServer::start().await;
    let (_user, mut first, _, _, token) = with_agent(&s, "Ada").await;
    let (_second, _) = Agent::connect(&s, &token).await;
    assert_eq!(first.closed_with().await, Some(WsErrorCode::Replaced));
}

#[tokio::test]
async fn the_kill_switch_stops_every_agent_and_survives_restarts() {
    let s = TestServer::start().await;
    let (mut user, mut a, _, _, token) = with_agent(&s, "Ada").await;
    user.send(ClientMsg::SetAgentsPaused { paused: true }).await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::AgentsPaused));
    user.expect(|m| matches!(m, ServerMsg::AgentsPaused { paused: true })).await;
    assert_eq!(upgrade_status(&s.agent_ws(&token).await.unwrap_err()), Some(503));

    let s = s.restart().await;
    assert_eq!(upgrade_status(&s.agent_ws(&token).await.unwrap_err()), Some(503));
    let mut user = User::connect(&s).await;
    user.send(ClientMsg::SetAgentsPaused { paused: false }).await;
    user.expect(|m| matches!(m, ServerMsg::AgentsPaused { paused: false })).await;
    let _ = Agent::connect(&s, &token).await;
    let actions: Vec<String> = user.audit().await.into_iter().map(|e| e.action).collect();
    assert!(
        actions.contains(&"agents_paused".into()) && actions.contains(&"agents_resumed".into())
    );
}

#[tokio::test]
async fn the_kill_switch_from_the_command_line_reaches_live_runtimes() {
    let s = TestServer::start().await;
    let (_user, mut a, _, _, _) = with_agent(&s, "Ada").await;
    // Another process (the CLI) flips it in the database directly.
    let db = snowpaw_server::db::Db::open(
        &s.db_path(),
        snowpaw_server::fsperm::effective_uid(&s.data_dir).unwrap(),
    )
    .unwrap();
    db.call_blocking(|c| snowpaw_server::db::set_agents_paused(c, true, 0)).unwrap();
    // Picked up by the periodic re-check (every 5 seconds).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut closed = None;
    while tokio::time::Instant::now() < deadline && closed.is_none() {
        if let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_secs(1), a.ws.next()).await
            && let Ok(env) = snowpaw_proto::decode::<AgentServerEnvelope>(t.as_bytes())
            && let AgentServerMsg::Error { code } = env.msg
        {
            closed = Some(code);
        }
    }
    assert_eq!(closed, Some(WsErrorCode::AgentsPaused));
}

fn quiz() -> Quiz {
    Quiz {
        title: "Capitals".into(),
        questions: vec![
            Question {
                prompt: "Iceland?".into(),
                choices: vec!["Reykjavík".into(), "Oslo".into()],
                answer: 0,
                hint: String::new(),
                explanation: String::new(),
            },
            Question {
                prompt: "Norway?".into(),
                choices: vec!["Bergen".into(), "Oslo".into()],
                answer: 1,
                hint: String::new(),
                explanation: String::new(),
            },
        ],
    }
}

#[tokio::test]
async fn quizzes_are_graded_by_the_server() {
    let s = TestServer::start().await;
    let (mut user, mut a, chat, _, _) = with_agent(&s, "Tutor").await;
    a.send(AgentMsg::Send {
        chat_id: chat,
        client_msg_id: id(1),
        content: Content::Quiz { quiz: quiz() },
        in_reply_to: None,
    })
    .await;
    a.expect(|m| matches!(m, AgentServerMsg::Sent { .. })).await;
    let quiz_id = match user.expect(|m| matches!(m, ServerMsg::NewMessage { .. })).await {
        ServerMsg::NewMessage { message } => message.id,
        _ => unreachable!(),
    };
    let answers = |answers: Vec<Option<u8>>, results: Vec<bool>| Content::QuizAnswers {
        answers: QuizAnswers { quiz_id, answers, results },
    };
    user.post(chat, 2, answers(vec![Some(0), Some(0)], vec![])).await;
    // The agent sees the server's grading.
    let graded = |m: &AgentServerMsg| matches!(m, AgentServerMsg::NewMessage { message } if matches!(message.content, Content::QuizAnswers { .. }));
    match a.expect(graded).await {
        AgentServerMsg::NewMessage { message } => match message.content {
            Content::QuizAnswers { answers } => assert_eq!(answers.results, vec![true, false]),
            other => panic!("{other:?}"),
        },
        _ => unreachable!(),
    }
    // Claiming results, answering a quiz that isn't there, or the wrong shape: refused.
    for (bad, code) in [
        (answers(vec![Some(1), Some(0)], vec![true, true]), WsErrorCode::InvalidContent),
        (answers(vec![Some(0)], vec![]), WsErrorCode::InvalidContent),
        (answers(vec![Some(0), Some(5)], vec![]), WsErrorCode::InvalidContent),
        (
            Content::QuizAnswers {
                answers: QuizAnswers { quiz_id: id(9), answers: vec![Some(0)], results: vec![] },
            },
            WsErrorCode::InvalidRequest,
        ),
    ] {
        let mut u = User::connect(&s).await;
        u.send(ClientMsg::Send { chat_id: chat, client_msg_id: id(50), content: bad.clone() })
            .await;
        assert_eq!(u.closed_with().await, Some(code), "{bad:?}");
    }
    // Agents don't answer quizzes.
    a.send(AgentMsg::Send {
        chat_id: chat,
        client_msg_id: id(3),
        content: answers(vec![Some(0), Some(1)], vec![]),
        in_reply_to: None,
    })
    .await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::Forbidden));
}

fn settings(base_url: &str, limit: u64) -> ModelSettings {
    ModelSettings {
        base_url: base_url.into(),
        model: "test-model".into(),
        tls_pin: None,
        instructions: "Be brief.".into(),
        max_reply_tokens: 50,
        context_messages: 20,
        daily_token_limit: limit,
    }
}

#[tokio::test]
async fn the_api_key_is_sealed_and_never_sent_back() {
    let s = TestServer::start().await;
    let mut user = User::connect(&s).await;
    let (_, agent) = user.create_agent("Ada").await;
    user.send(ClientMsg::SetAgentModel {
        agent,
        model: settings("https://api.example.com/v1", 1000),
        api_key: ApiKeyChange::Set { key: SecretString::new(SECRET_KEY.into()) },
    })
    .await;
    let reply = user.expect(|m| matches!(m, ServerMsg::AgentSettings { .. })).await;
    match &reply {
        ServerMsg::AgentSettings { settings, .. } => assert!(settings.has_api_key),
        _ => unreachable!(),
    }
    assert!(!encode(&ServerEnvelope::new(reply)).contains("SECRET"));
    // Not in the database file or its log, in any form we'd recognize.
    let mut all = std::fs::read(s.db_path()).unwrap();
    if let Ok(wal) = std::fs::read(s.db_path().with_extension("db-wal")) {
        all.extend(wal);
    }
    assert!(!all.windows(SECRET_KEY.len()).any(|w| w == SECRET_KEY.as_bytes()));
    assert!(!format!("{:?}", user.audit().await).contains("SECRET"));

    // Keep keeps it, Clear removes it.
    user.set_model(agent, settings("https://api.example.com/v1", 1000), ApiKeyChange::Keep).await;
    user.send(ClientMsg::GetAgentSettings { agent }).await;
    assert!(matches!(user.expect(|m| matches!(m, ServerMsg::AgentSettings { .. })).await,
        ServerMsg::AgentSettings { settings, .. } if settings.has_api_key));
    user.set_model(agent, settings("https://api.example.com/v1", 1000), ApiKeyChange::Clear).await;
    user.send(ClientMsg::GetAgentSettings { agent }).await;
    assert!(matches!(user.expect(|m| matches!(m, ServerMsg::AgentSettings { .. })).await,
        ServerMsg::AgentSettings { settings, .. } if !settings.has_api_key));

    // Plain http off this machine is refused even if a client skips its own checks.
    user.send(ClientMsg::SetAgentModel {
        agent,
        model: settings("http://192.168.1.20:11434/v1", 1000),
        api_key: ApiKeyChange::Keep,
    })
    .await;
    assert_eq!(user.closed_with().await, Some(WsErrorCode::InvalidRequest));
}

/// A fake OpenAI-compatible server on 127.0.0.1 that records requests and answers
/// with whatever `reply` holds.
struct FakeModel {
    url: String,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    reply: Arc<Mutex<(u16, String)>>,
}

async fn fake_model() -> FakeModel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}/v1", listener.local_addr().unwrap().port());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let reply = Arc::new(Mutex::new((200, String::new())));
    let (seen2, reply2) = (seen.clone(), reply.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let (seen, reply) = (seen2.clone(), reply2.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        while buf.len() < i + 4 + len {
                            let n = sock.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        break (
                            head,
                            String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).into_owned(),
                        );
                    }
                };
                seen.lock().unwrap().push((head, body));
                let (status, text) = reply.lock().unwrap().clone();
                let extra =
                    if status == 302 { "Location: http://169.254.169.254/\r\n" } else { "" };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    FakeModel { url, seen, reply }
}

fn completion(text: &str, prompt: u64, completion: u64) -> String {
    format!(
        r#"{{"choices":[{{"message":{{"role":"assistant","content":"{text}"}}}}],"usage":{{"prompt_tokens":{prompt},"completion_tokens":{completion}}}}}"#
    )
}

#[tokio::test]
async fn model_calls_go_through_the_server_within_limits() {
    let s = TestServer::start_with("[agents]\ninference_per_minute = 3\n").await;
    let model = fake_model().await;
    let (mut user, mut a, _, agent, _) = with_agent(&s, "Ada").await;

    assert_eq!(a.infer("hi").await, Err(InferFailure::NotConfigured));
    user.set_model(
        agent,
        settings(&model.url, 200),
        ApiKeyChange::Set { key: SecretString::new(SECRET_KEY.into()) },
    )
    .await;
    // The runtime is told the new instructions.
    a.expect(|m| matches!(m, AgentServerMsg::Settings { instructions, .. } if instructions == "Be brief.")).await;

    *model.reply.lock().unwrap() = (200, completion("Hello!", 12, 3));
    assert_eq!(a.infer("hi").await, Ok(("Hello!".into(), 15)));
    {
        let seen = model.seen.lock().unwrap();
        let (head, body) = &seen[0];
        assert!(head.starts_with("POST /v1/chat/completions HTTP/1.1"), "{head}");
        assert!(
            head.contains(&format!("authorization: Bearer {SECRET_KEY}")),
            "the key goes only here"
        );
        assert!(body.contains(r#""model":"test-model""#) && body.contains(r#""max_tokens":50"#));
    }

    // Redirects aren't followed, errors and oversized or broken replies are refused.
    for (status, text) in [
        (302, String::new()),
        (500, r#"{"error":"boom"}"#.to_owned()),
        (200, "not json".to_owned()),
        (200, format!(r#"{{"choices":[{{"message":{{"content":"{}"}}}}]}}"#, "x".repeat(5 << 20))),
    ] {
        s.clock.advance_secs(61);
        *model.reply.lock().unwrap() = (status, text);
        assert_eq!(a.infer("hi").await, Err(InferFailure::Upstream), "{status}");
    }
    assert_eq!(model.seen.lock().unwrap().len(), 5, "the redirect target was never fetched");

    // Failed calls charge their prompt estimate, so a hostile or dead endpoint
    // can't host free retries that dodge the daily budget. ("hi" estimates to 16
    // tokens; the one success before this settled 12 + 3.)
    user.send(ClientMsg::GetAgentSettings { agent }).await;
    let used = match user.expect(|m| matches!(m, ServerMsg::AgentSettings { .. })).await {
        ServerMsg::AgentSettings { settings, .. } => settings.tokens_used_24h,
        _ => unreachable!(),
    };
    assert!(used >= 15 + 4 * 16, "failures were charged: {used}");

    // Rate limit: 3 calls a minute (failures count too).
    s.clock.advance_secs(61);
    *model.reply.lock().unwrap() = (200, completion("ok", 5, 1));
    for _ in 0..3 {
        assert!(a.infer("hi").await.is_ok());
    }
    assert_eq!(a.infer("hi").await, Err(InferFailure::RateLimited));

    // Budget: 200 tokens a day, each call reserves its worst case up front (and
    // failures are no longer free, so it may take a few more calls to get there).
    s.clock.advance_secs(61);
    *model.reply.lock().unwrap() = (200, completion("ok", 40, 50));
    let mut refused = false;
    for _ in 0..6 {
        match a.infer("hi").await {
            Ok(_) => {}
            Err(InferFailure::BudgetExhausted) => {
                refused = true;
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
        s.clock.advance_secs(61);
    }
    assert!(refused, "the daily budget stops calls");
    // ...until the window passes.
    s.clock.advance_secs(86_400);
    assert!(a.infer("hi").await.is_ok());

    // Paused: refused before any call is made.
    let before = model.seen.lock().unwrap().len();
    let db = snowpaw_server::db::Db::open(
        &s.db_path(),
        snowpaw_server::fsperm::effective_uid(&s.data_dir).unwrap(),
    )
    .unwrap();
    db.call_blocking(|c| snowpaw_server::db::set_agents_paused(c, true, 0)).unwrap();
    s.clock.advance_secs(61);
    let r = a.infer("hi").await;
    assert!(matches!(r, Err(InferFailure::Paused)), "{r:?}");
    assert_eq!(model.seen.lock().unwrap().len(), before);
}

#[tokio::test]
async fn the_audit_log_is_paged_and_append_only() {
    let s = TestServer::start().await;
    let mut user = User::connect(&s).await;
    for name in ["A", "B", "C"] {
        user.create_agent(name).await;
    }
    user.send(ClientMsg::ListAudit { before_seq: None, limit: 2 }).await;
    let (page, more) = match user.expect(|m| matches!(m, ServerMsg::Audit { .. })).await {
        ServerMsg::Audit { entries, has_more } => (entries, has_more),
        _ => unreachable!(),
    };
    assert!(more);
    assert_eq!(page.len(), 2);
    assert!(page[0].seq > page[1].seq, "newest first");
    assert_eq!(page[0].action, "agent_created");
    user.send(ClientMsg::ListAudit { before_seq: Some(page[1].seq), limit: 200 }).await;
    match user.expect(|m| matches!(m, ServerMsg::Audit { .. })).await {
        ServerMsg::Audit { entries, has_more } => {
            assert!(!has_more);
            assert!(entries.iter().all(|e| e.seq < page[1].seq));
            assert!(entries.iter().any(|e| e.action == "login"));
        }
        _ => unreachable!(),
    }
    for bad in [0, 201] {
        let mut u = User::connect(&s).await;
        u.send(ClientMsg::ListAudit { before_seq: None, limit: bad }).await;
        assert_eq!(u.closed_with().await, Some(WsErrorCode::InvalidRequest));
    }
    let db = snowpaw_server::db::Db::open(
        &s.db_path(),
        snowpaw_server::fsperm::effective_uid(&s.data_dir).unwrap(),
    )
    .unwrap();
    for sql in ["UPDATE audit SET detail = 'x'", "DELETE FROM audit"] {
        assert!(db.call_blocking(|c| Ok(c.execute(sql, [])?)).is_err(), "{sql}");
    }
}

#[tokio::test]
async fn the_agents_only_listener_serves_nothing_else() {
    let s = TestServer::start_with("agent_listen = \"127.0.0.1:0\"\n").await;
    let agent_addr = s.agent_addr.expect("agent listener");
    assert_ne!(agent_addr, s.addr);
    let (_user, _runtime, _, _, _) = with_agent(&s, "Ada").await;
    // Login and the user's API don't exist on the agents' port.
    let tls = common::client_config(s.cert.clone(), &[&rustls::version::TLS13]);
    for path in ["/v1/login", "/v1/ws", "/v1/blobs", "/v1/plugins", "/v1/logout"] {
        let tcp = tokio::net::TcpStream::connect(agent_addr).await.unwrap();
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls.clone()))
            .connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out).await;
        let r = common::parse_response(&out).expect("response");
        assert_eq!(r.status, 404, "{path}");
    }
}

// ---- jobs ----

use snowpaw_proto::jobs::{JobSchedule, JobState, JobView};

/// The next JobChanged for `job` that satisfies `f`.
async fn job_until(user: &mut User, f: impl Fn(&JobView) -> bool) -> JobView {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), user.recv()).await {
            Ok(Some(ServerMsg::JobChanged { job })) if f(&job) => return job,
            Ok(Some(_)) => continue,
            other => panic!("waiting for a job change: {other:?}"),
        }
    }
}

async fn next_run(a: &mut Agent) -> snowpaw_proto::jobs::JobSpec {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), a.recv()).await {
            Ok(Some(AgentServerMsg::JobRun { job })) => return job,
            Ok(Some(_)) => continue,
            other => panic!("waiting for a job run: {other:?}"),
        }
    }
}

#[tokio::test]
async fn jobs_run_report_progress_and_repeat() {
    let s = TestServer::start().await;
    let (mut user, mut a, chat, agent, _) = with_agent(&s, "Ada").await;
    let now = common::START_MS;
    user.send(ClientMsg::CreateJob {
        agent,
        title: "Briefing".into(),
        prompt: "Summarize the day.".into(),
        schedule: JobSchedule { first_run_at_ms: now, every_secs: Some(3600) },
    })
    .await;
    let created = job_until(&mut user, |j| j.state == JobState::Active).await;
    assert_eq!((created.chat_id, created.proposed_by_agent), (chat, false));

    let run = next_run(&mut a).await;
    assert_eq!((run.job, run.chat_id, run.attempt), (created.id, chat, 1));
    a.send(AgentMsg::JobProgress { run_id: run.run_id, text: "Reading\u{202E} the news\n".into() })
        .await;
    let j = job_until(&mut user, |j| !j.progress.is_empty()).await;
    assert_eq!(j.progress, "Reading the news", "cleaned to one plain line");
    assert!(j.running);
    a.send(AgentMsg::JobDone { run_id: run.run_id, ok: true, detail: "posted 1".into() }).await;
    let j = job_until(&mut user, |j| !j.running).await;
    assert_eq!(j.state, JobState::Active);
    assert_eq!(j.next_run_at_ms, Some(now + 3_600_000), "the next slot on its schedule");
    // Reporting on a finished run changes nothing.
    a.send(AgentMsg::JobDone { run_id: run.run_id, ok: false, detail: "x".into() }).await;
    s.clock.advance_secs(3600);
    let run2 = next_run(&mut a).await;
    assert_ne!(run2.run_id, run.run_id);
}

#[tokio::test]
async fn a_lost_run_is_retried_with_backoff_then_given_up() {
    let s = TestServer::start().await;
    let (mut user, a, _, agent, token) = with_agent(&s, "Ada").await;
    let now = common::START_MS;
    user.send(ClientMsg::CreateJob {
        agent,
        title: "Once".into(),
        prompt: "Do it.".into(),
        schedule: JobSchedule { first_run_at_ms: now, every_secs: None },
    })
    .await;
    let mut a = a;
    for attempt in 1..=3u32 {
        let run = next_run(&mut a).await;
        assert_eq!(run.attempt, attempt);
        // The runtime goes away mid-run.
        drop(a);
        let j = job_until(&mut user, |j| !j.running && j.attempts >= attempt.min(3)).await;
        if attempt < 3 {
            assert_eq!(j.state, JobState::Active);
            assert!(
                j.next_run_at_ms.unwrap() > snowpaw_server::clock::Clock::now_ms(s.clock.as_ref()),
                "backs off"
            );
            s.clock.advance_secs(3600);
        } else {
            assert_eq!(j.state, JobState::Failed, "a one-off gives up after 3 tries");
        }
        a = Agent::connect(&s, &token).await.0;
    }
}

#[tokio::test]
async fn agents_can_only_propose_jobs_and_proposals_wait_for_approval() {
    let s = TestServer::start().await;
    let (mut user, mut a, _, _, _) = with_agent(&s, "Ada").await;
    a.send(AgentMsg::ProposeJob {
        request_id: id(1),
        title: "Daily digest".into(),
        prompt: "Summarize my mail.".into(),
        start_in_secs: 0,
        every_secs: Some(86_400),
    })
    .await;
    let job = match a
        .expect(|m| {
            matches!(m, AgentServerMsg::JobProposed { .. } | AgentServerMsg::JobRefused { .. })
        })
        .await
    {
        AgentServerMsg::JobProposed { job, .. } => job,
        other => panic!("{other:?}"),
    };
    let j = job_until(&mut user, |j| j.id == job).await;
    assert_eq!((j.state, j.proposed_by_agent), (JobState::Proposed, true));
    // Not run while proposed.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(500),
            a.expect(|m| matches!(m, AgentServerMsg::JobRun { .. }))
        )
        .await
        .is_err(),
        "a proposal never runs on its own"
    );
    // Bad proposals and too many proposals are refused.
    for (n, every) in [(2u8, Some(10u32)), (3, Some(400_000_000))] {
        a.send(AgentMsg::ProposeJob {
            request_id: id(n),
            title: "x".into(),
            prompt: "y".into(),
            start_in_secs: 0,
            every_secs: every,
        })
        .await;
        assert!(matches!(
            a.expect(|m| matches!(
                m,
                AgentServerMsg::JobRefused { .. } | AgentServerMsg::JobProposed { .. }
            ))
            .await,
            AgentServerMsg::JobRefused { .. }
        ));
    }
    for n in 0..4u8 {
        a.send(AgentMsg::ProposeJob {
            request_id: id(10 + n),
            title: format!("p{n}"),
            prompt: "y".into(),
            start_in_secs: 0,
            every_secs: None,
        })
        .await;
        assert!(matches!(
            a.expect(|m| matches!(
                m,
                AgentServerMsg::JobRefused { .. } | AgentServerMsg::JobProposed { .. }
            ))
            .await,
            AgentServerMsg::JobProposed { .. }
        ));
    }
    a.send(AgentMsg::ProposeJob {
        request_id: id(20),
        title: "sixth".into(),
        prompt: "y".into(),
        start_in_secs: 0,
        every_secs: None,
    })
    .await;
    assert!(
        matches!(
            a.expect(|m| matches!(
                m,
                AgentServerMsg::JobRefused { .. } | AgentServerMsg::JobProposed { .. }
            ))
            .await,
            AgentServerMsg::JobRefused { .. }
        ),
        "at most 5 proposals"
    );
    // Agents have no way to approve: the request doesn't exist on their socket.
    a.ws.send(Message::Text(
        format!(r#"{{"v":1,"msg":{{"type":"approve_job","job":"{job}"}}}}"#).into(),
    ))
    .await
    .unwrap();
    assert_eq!(a.closed_with().await, Some(WsErrorCode::BadFrame));

    // The user approves: now it runs.
    let mut user2 = User::connect(&s).await;
    let token = user2.issue_token(j.agent).await;
    let (mut a, _) = Agent::connect(&s, &token).await;
    user.send(ClientMsg::ApproveJob { job }).await;
    job_until(&mut user, |j| j.id == job && j.state == JobState::Active).await;
    let run = next_run(&mut a).await;
    assert_eq!(run.job, job);
    let audit = user2.audit().await;
    assert!(
        audit.iter().any(|e| e.action == "job_proposed")
            && audit.iter().any(|e| e.action == "job_approved")
    );
}

#[tokio::test]
async fn cancelling_stops_a_run_and_the_kill_switch_holds_jobs() {
    let s = TestServer::start().await;
    let (mut user, mut a, _, agent, _) = with_agent(&s, "Ada").await;
    let schedule = JobSchedule { first_run_at_ms: common::START_MS, every_secs: Some(600) };
    user.send(ClientMsg::CreateJob { agent, title: "Loop".into(), prompt: "x".into(), schedule })
        .await;
    let run = next_run(&mut a).await;
    user.send(ClientMsg::CancelJob { job: run.job }).await;
    match a.expect(|m| matches!(m, AgentServerMsg::JobCancelled { .. })).await {
        AgentServerMsg::JobCancelled { run_id } => assert_eq!(run_id, run.run_id),
        _ => unreachable!(),
    }
    let j = job_until(&mut user, |j| j.state == JobState::Cancelled).await;
    assert_eq!(j.next_run_at_ms, None);

    // Paused: nothing is dispatched (and the runtime is disconnected anyway).
    user.send(ClientMsg::CreateJob { agent, title: "Held".into(), prompt: "x".into(), schedule })
        .await;
    user.send(ClientMsg::SetAgentsPaused { paused: true }).await;
    let held = job_until(&mut user, |j| j.title == "Held").await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut user = User::connect(&s).await;
    user.send(ClientMsg::ListJobs {}).await;
    match user.expect(|m| matches!(m, ServerMsg::Jobs { .. })).await {
        ServerMsg::Jobs { jobs } => {
            let j = jobs.into_iter().find(|j| j.id == held.id).unwrap();
            assert!(!j.running && j.last_run.as_ref().is_none_or(|r| r.outcome.is_some()));
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn runtimes_cannot_report_on_other_agents_runs() {
    let s = TestServer::start().await;
    let (mut user, mut a, _, agent_a, _) = with_agent(&s, "Ada").await;
    let (_, b_id) = user.create_agent("Bo").await;
    let b_token = user.issue_token(b_id).await;
    let (mut b, _) = Agent::connect(&s, &b_token).await;
    let schedule = JobSchedule { first_run_at_ms: common::START_MS, every_secs: None };
    user.send(ClientMsg::CreateJob {
        agent: agent_a,
        title: "A's".into(),
        prompt: "x".into(),
        schedule,
    })
    .await;
    let run = next_run(&mut a).await;
    b.send(AgentMsg::JobDone { run_id: run.run_id, ok: true, detail: "not mine".into() }).await;
    b.send(AgentMsg::JobProgress { run_id: run.run_id, text: "hijacked".into() }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    user.send(ClientMsg::ListJobs {}).await;
    match user.expect(|m| matches!(m, ServerMsg::Jobs { .. })).await {
        ServerMsg::Jobs { jobs } => {
            let j = jobs.into_iter().find(|j| j.id == run.job).unwrap();
            assert!(j.running, "still A's run, untouched");
            assert_eq!(j.progress, "");
        }
        _ => unreachable!(),
    }
    // Bad schedules from the user are refused too.
    user.send(ClientMsg::CreateJob {
        agent: agent_a,
        title: "x".into(),
        prompt: "y".into(),
        schedule: JobSchedule { first_run_at_ms: common::START_MS, every_secs: Some(1) },
    })
    .await;
    assert_eq!(user.closed_with().await, Some(WsErrorCode::InvalidRequest));
}
