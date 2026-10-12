//! Chats and the message log over the WebSocket, and attempts to get around
//! membership, sender identity, and content rules.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{TestServer, Ws};
use futures_util::{SinkExt, StreamExt};
use snowpaw_proto::ws::{
    ChatKind, ClientEnvelope, ClientMsg, Content, MessageView, ServerEnvelope, ServerMsg,
    WsErrorCode,
};
use snowpaw_proto::{Id, encode};
use snowpaw_server::db::{self, Db};
use tokio_tungstenite::tungstenite::Message;

struct Client {
    ws: Ws,
    you: Id,
    max: u32,
}

impl Client {
    async fn connect(s: &TestServer) -> Self {
        let token = s.token().await;
        let mut ws = s.ws(&token).await.unwrap();
        match recv(&mut ws).await {
            Some(ServerMsg::Welcome { you, max_content_bytes, .. }) => {
                Self { ws, you, max: max_content_bytes }
            }
            other => panic!("expected welcome, got {other:?}"),
        }
    }

    async fn send(&mut self, msg: ClientMsg) {
        self.ws.send(Message::Text(encode(&ClientEnvelope::new(msg)).into())).await.unwrap();
    }

    async fn send_raw(&mut self, text: &str) {
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    async fn recv(&mut self) -> Option<ServerMsg> {
        recv(&mut self.ws).await
    }

    async fn chats(&mut self) -> Vec<snowpaw_proto::ws::ChatSummary> {
        self.send(ClientMsg::ListChats {}).await;
        match self.recv().await {
            Some(ServerMsg::Chats { chats }) => chats,
            other => panic!("expected chats, got {other:?}"),
        }
    }

    async fn note_to_self(&mut self) -> Id {
        self.chats().await.iter().find(|c| c.kind == ChatKind::NoteToSelf).unwrap().id
    }

    async fn post(&mut self, chat_id: Id, client_msg_id: Id, text: &str) {
        self.send(ClientMsg::Send { chat_id, client_msg_id, content: md(text) }).await;
    }

    async fn sync(&mut self, chat_id: Id, after_seq: i64, limit: u32) -> (Vec<MessageView>, bool) {
        self.send(ClientMsg::Sync { chat_id, after_seq, limit }).await;
        loop {
            match self.recv().await {
                Some(ServerMsg::Messages { messages, has_more, .. }) => {
                    return (messages, has_more);
                }
                Some(ServerMsg::NewMessage { .. } | ServerMsg::Sent { .. }) => continue,
                other => panic!("expected messages, got {other:?}"),
            }
        }
    }

    /// Drain until the server closes; return the error code it sent.
    async fn closed_with(&mut self) -> Option<WsErrorCode> {
        let mut code = None;
        let done = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = self.ws.next().await {
                match frame {
                    Ok(Message::Text(t)) => {
                        if let Ok(ServerEnvelope { msg: ServerMsg::Error { code: c }, .. }) =
                            snowpaw_proto::decode(t.as_bytes())
                        {
                            code = Some(c);
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(done.is_ok(), "socket stayed open");
        code
    }
}

async fn recv(ws: &mut Ws) -> Option<ServerMsg> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.ok()?? {
            Ok(Message::Text(t)) => {
                return Some(snowpaw_proto::decode::<ServerEnvelope>(t.as_bytes()).unwrap().msg);
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
}

fn md(text: &str) -> Content {
    Content::Markdown { text: text.to_owned() }
}

fn id(n: u8) -> Id {
    Id::from_bytes([n; 16])
}

fn open_db(s: &TestServer) -> Db {
    let uid = snowpaw_server::fsperm::effective_uid(&s.data_dir).unwrap();
    Db::open(&s.db_path(), uid).unwrap()
}

/// Two agents, a direct chat (user + agent A), and a chat the user is NOT in (A + B).
fn seed_agents(s: &TestServer, user: Id) -> (Id, Id) {
    let db = open_db(s);
    db.call_blocking(|c| {
        for (n, name) in [(1u8, "Ada"), (2, "Brook")] {
            c.execute(
                "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'agent', ?2, 0)",
                rusqlite_params(id(n), name),
            )?;
        }
        db::create_chat(c, id(10), ChatKind::Direct, &[user, id(1)], 0)?;
        db::create_chat(c, id(11), ChatKind::AgentToAgent, &[id(1), id(2)], 0)?;
        Ok(())
    })
    .unwrap();
    (id(10), id(11))
}

fn rusqlite_params(i: Id, name: &str) -> [String; 2] {
    [i.to_string(), name.to_owned()]
}

#[tokio::test]
async fn welcome_says_who_you_are() {
    let s = TestServer::start().await;
    let c = Client::connect(&s).await;
    let user = open_db(&s).call_blocking(|c| db::user_id(c)).unwrap().unwrap();
    assert_eq!(c.you, user);
    assert_eq!(c.max, 16 * 1024);
}

#[tokio::test]
async fn note_to_self_exists_from_the_start() {
    let s = TestServer::start().await;
    let mut c = Client::connect(&s).await;
    let chats = c.chats().await;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].kind, ChatKind::NoteToSelf);
    assert_eq!(chats[0].title, "Note to Self");
    assert!(chats[0].last_message.is_none());
}

#[tokio::test]
async fn sending_stores_and_pushes_live_to_every_open_window() {
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let mut b = Client::connect(&s).await;
    let chat = a.note_to_self().await;

    a.post(chat, id(100), "hello from window A").await;
    let (sent_id, sent_seq) = match a.recv().await {
        Some(ServerMsg::Sent { client_msg_id, id: sent_id, seq }) => {
            assert_eq!(client_msg_id, id(100));
            (sent_id, seq)
        }
        other => panic!("expected sent, got {other:?}"),
    };
    for client in [&mut a, &mut b] {
        match client.recv().await {
            Some(ServerMsg::NewMessage { message }) => {
                assert_eq!(message.id, sent_id);
                assert_eq!(message.seq, sent_seq);
                assert_eq!(message.chat_id, chat);
                assert_eq!(message.sender_id, client.you, "sender comes from the session");
                assert_eq!(message.created_at_ms, common::START_MS, "server clock, not client");
                assert_eq!(message.content, md("hello from window A"));
                assert_eq!(message.recipient_id, None);
            }
            other => panic!("expected push, got {other:?}"),
        }
    }
    let (msgs, more) = b.sync(chat, 0, 50).await;
    assert_eq!(msgs.len(), 1);
    assert!(!more);
    let chats = b.chats().await;
    assert_eq!(chats[0].last_message.as_ref().map(|m| m.id), Some(sent_id));
}

#[tokio::test]
async fn retries_never_duplicate() {
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let mut b = Client::connect(&s).await;
    let chat = a.note_to_self().await;
    a.post(chat, id(100), "once").await;
    let first = a.recv().await;
    let _push = a.recv().await;
    assert!(matches!(b.recv().await, Some(ServerMsg::NewMessage { .. })));
    // Same client_msg_id again (e.g. after a reconnect), even with different text.
    a.post(chat, id(100), "once (retry)").await;
    let second = a.recv().await;
    assert_eq!(first, second, "a retry confirms the original");
    let (msgs, _) = b.sync(chat, 0, 50).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].content, md("once"));
    // B was not told about a second message.
    b.send(ClientMsg::Ping { nonce: 1 }).await;
    assert_eq!(b.recv().await, Some(ServerMsg::Pong { nonce: 1 }));
}

#[tokio::test]
async fn reusing_a_client_msg_id_in_another_chat_is_refused() {
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let (direct, _) = seed_agents(&s, a.you);
    let note = a.note_to_self().await;
    a.post(note, id(100), "first").await;
    assert!(matches!(a.recv().await, Some(ServerMsg::Sent { .. })));
    a.post(direct, id(100), "same id, other chat").await;
    assert_eq!(a.closed_with().await, Some(WsErrorCode::InvalidRequest));
}

#[tokio::test]
async fn sync_pages_in_order() {
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let chat = a.note_to_self().await;
    for n in 0..5u8 {
        a.post(chat, id(100 + n), &format!("message {n}")).await;
        assert!(matches!(a.recv().await, Some(ServerMsg::Sent { .. })));
        assert!(matches!(a.recv().await, Some(ServerMsg::NewMessage { .. })));
    }
    let (page1, more1) = a.sync(chat, 0, 2).await;
    assert!(more1);
    let (page2, more2) = a.sync(chat, page1[1].seq, 2).await;
    assert!(more2);
    let (page3, more3) = a.sync(chat, page2[1].seq, 2).await;
    assert!(!more3);
    let texts: Vec<_> = [page1, page2, page3].concat().into_iter().map(|m| m.content).collect();
    assert_eq!(texts, (0..5).map(|n| md(&format!("message {n}"))).collect::<Vec<_>>());
}

#[tokio::test]
async fn direct_messages_are_addressed_to_the_agent() {
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let (direct, _) = seed_agents(&s, a.you);
    let chats = a.chats().await;
    let row = chats.iter().find(|c| c.id == direct).unwrap();
    assert_eq!(row.title, "Ada");
    assert_eq!(row.kind, ChatKind::Direct);
    a.post(direct, id(100), "hi Ada").await;
    assert!(matches!(a.recv().await, Some(ServerMsg::Sent { .. })));
    match a.recv().await {
        Some(ServerMsg::NewMessage { message }) => assert_eq!(message.recipient_id, Some(id(1))),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn agent_conversations_are_read_only_and_unknown_chats_untouchable() {
    let s = TestServer::start().await;
    let mut probe = Client::connect(&s).await;
    let (_, between_agents) = seed_agents(&s, probe.you);
    // The user reads along in conversations between agents...
    assert!(probe.chats().await.iter().any(|c| c.id == between_agents));
    let (msgs, _) = probe.sync(between_agents, 0, 10).await;
    assert!(msgs.is_empty());

    // ...but can't post in them. Writing there, or reading or writing a guessed id,
    // all get the same answer, which never says whether the chat exists.
    let attempts = [
        ClientMsg::Send {
            chat_id: between_agents,
            client_msg_id: id(200),
            content: md("let me in"),
        },
        ClientMsg::Sync { chat_id: id(99), after_seq: 0, limit: 10 },
        ClientMsg::Send { chat_id: id(99), client_msg_id: id(201), content: md("hello?") },
    ];
    for attempt in attempts {
        let mut c = Client::connect(&s).await;
        c.send(attempt.clone()).await;
        assert_eq!(c.closed_with().await, Some(WsErrorCode::Forbidden), "{attempt:?}");
    }
    let count =
        open_db(&s).call_blocking(|c| Ok(db::messages_after(c, id(11), 0, 10)?.len())).unwrap();
    assert_eq!(count, 0, "nothing was written to the foreign chat");
}

#[tokio::test]
async fn the_sender_cannot_be_chosen_by_the_client() {
    let s = TestServer::start().await;
    let mut c = Client::connect(&s).await;
    let chat = c.note_to_self().await;
    let spoof = format!(
        r#"{{"v":1,"msg":{{"type":"send","chat_id":"{chat}","client_msg_id":"{}","sender_id":"{}","content":{{"kind":"markdown","text":"as Ada"}}}}}}"#,
        id(100),
        id(1)
    );
    c.send_raw(&spoof).await;
    assert_eq!(c.closed_with().await, Some(WsErrorCode::BadFrame));
}

#[tokio::test]
async fn content_rules_are_enforced_by_the_server() {
    let s = TestServer::start_with("[limits]\nmax_message_bytes = 100\n").await;
    for (n, bad) in [
        String::new(),
        " \n\t ".to_owned(),
        "a".repeat(101),
        "bell\u{7}".to_owned(),
        "windows line\r\n".to_owned(),
        "invoice_\u{202E}fdp.exe".to_owned(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut c = Client::connect(&s).await;
        let chat = c.note_to_self().await;
        c.post(chat, id(100 + n as u8), &bad).await;
        assert_eq!(c.closed_with().await, Some(WsErrorCode::InvalidContent), "{bad:?}");
    }
    let mut c = Client::connect(&s).await;
    let chat = c.note_to_self().await;
    let (msgs, _) = c.sync(chat, 0, 10).await;
    assert!(msgs.is_empty(), "nothing invalid was stored");
}

#[tokio::test]
async fn sync_parameters_are_bounded() {
    let s = TestServer::start().await;
    for (after_seq, limit) in [(0, 0), (0, 201), (0, u32::MAX), (-1, 10), (i64::MIN, 10)] {
        let mut c = Client::connect(&s).await;
        let chat = c.note_to_self().await;
        c.send(ClientMsg::Sync { chat_id: chat, after_seq, limit }).await;
        assert_eq!(c.closed_with().await, Some(WsErrorCode::InvalidRequest), "{after_seq} {limit}");
    }
}

#[tokio::test]
async fn chat_list_is_most_recent_first() {
    let s = TestServer::start().await;
    let mut c = Client::connect(&s).await;
    let (direct, _) = seed_agents(&s, c.you);
    let note = c.note_to_self().await;
    c.post(note, id(100), "note").await;
    let _ = (c.recv().await, c.recv().await);
    let first: Vec<Id> = c.chats().await.iter().map(|r| r.id).collect();
    // The conversation between agents (no messages yet) comes last.
    assert_eq!(first, vec![note, direct, id(11)]);
    c.post(direct, id(101), "now the direct chat is newest").await;
    let _ = (c.recv().await, c.recv().await);
    let second: Vec<Id> = c.chats().await.iter().map(|r| r.id).collect();
    assert_eq!(second, vec![direct, note, id(11)]);
}

/// The user socket's write cap at default config (4 × max_ws_message_bytes).
const USER_FRAME_CAP: usize = 4 * 64 * 1024;

#[tokio::test]
async fn sync_pages_fit_the_socket_write_limit() {
    // 40 × ~16 KiB messages is 2.5× the socket's write cap: the reply must arrive
    // in pages (has_more), never as one frame the server can't send. Before the
    // byte budget, a chat like this made every fresh client reconnect-loop.
    let s = TestServer::start().await;
    let mut a = Client::connect(&s).await;
    let chat = a.note_to_self().await;
    let big = "x".repeat(16_000);
    for n in 0..40u8 {
        a.post(chat, id(n), &big).await;
    }
    // Drain the confirms and broadcasts.
    for _ in 0..80 {
        assert!(a.recv().await.is_some());
    }
    drop(a);

    // A fresh device syncs from zero.
    let mut b = Client::connect(&s).await;
    let mut after = 0i64;
    let mut pages = 0;
    let mut all: Vec<MessageView> = vec![];
    loop {
        let (messages, more) = b.sync(chat, after, 200).await;
        let frame = encode(&snowpaw_proto::ws::ServerEnvelope::new(ServerMsg::Messages {
            chat_id: chat,
            messages: messages.clone(),
            has_more: more,
        }));
        assert!(frame.len() <= USER_FRAME_CAP, "page {} is {} bytes", pages, frame.len());
        after = messages.last().map(|m| m.seq).unwrap_or(after);
        all.extend(messages);
        pages += 1;
        if !more {
            break;
        }
    }
    assert!(pages > 1, "the chat is far larger than one page");
    assert_eq!(all.len(), 40);
    assert!(all.iter().all(|m| m.content == md(&big)), "full bodies, not previews");
}

#[tokio::test]
async fn chat_lists_fit_the_socket_write_limit() {
    // 24 direct chats whose last messages are ~16 KiB: the list is 1.5× the
    // socket's write cap. It must arrive complete, with preview-only last
    // messages (the full bodies come from a sync), instead of dropping the
    // connection — which, before, made the account unloadable.
    let s = TestServer::start().await;
    let mut c = Client::connect(&s).await;
    let user = c.you;
    let big = "y".repeat(16_000);
    let db = open_db(&s);
    db.call_blocking(|conn| {
        for n in 0..24u8 {
            let agent = Id::from_bytes([n + 1; 16]);
            conn.execute(
                "INSERT INTO principals (id, kind, display_name, created_at_ms)
                 VALUES (?1, 'agent', 'a', 0)",
                [agent.to_string()],
            )?;
            db::create_chat(
                conn,
                Id::from_bytes([n + 100; 16]),
                ChatKind::Direct,
                &[user, agent],
                0,
            )?;
            let content = md(&big);
            db::append_message(
                conn,
                &db::NewMessage {
                    id: Id::from_bytes([n + 200; 16]),
                    chat_id: Id::from_bytes([n + 100; 16]),
                    thread_id: None,
                    sender_id: user,
                    recipient_id: None,
                    client_msg_id: Id::from_bytes([n + 150; 16]),
                    content: &content,
                    depth: 0,
                },
                1,
            )?;
        }
        Ok(())
    })
    .unwrap();

    c.send(ClientMsg::ListChats {}).await;
    let chats = match c.recv().await {
        Some(ServerMsg::Chats { chats }) => chats,
        other => panic!("the chat list must arrive, got {other:?}"),
    };
    let frame =
        encode(&snowpaw_proto::ws::ServerEnvelope::new(ServerMsg::Chats { chats: chats.clone() }));
    assert!(frame.len() <= USER_FRAME_CAP, "chat list is {} bytes", frame.len());
    assert_eq!(chats.len(), 25, "note-to-self plus every direct chat");
    for ch in &chats {
        if let Some(m) = &ch.last_message {
            match &m.content {
                Content::Markdown { text } => {
                    assert!(text.chars().count() <= 161, "summaries carry a preview, not the body")
                }
                other => panic!("preview must be markdown text, got {other:?}"),
            }
        }
    }
    // The full bodies are still there, one sync away.
    let chat = chats.iter().find(|c| c.kind == ChatKind::Direct).unwrap().id;
    let (messages, _) = c.sync(chat, 0, 200).await;
    assert!(messages.iter().all(|m| m.content == md(&big)));
}
