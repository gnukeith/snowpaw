//! The runtime end to end: a real server, a fake model server, and the runtime in
//! between. The user asks for a quiz, answers it, and the model is told which answers
//! were wrong; the runtime resumes after a restart without answering twice.
#![allow(clippy::unwrap_used)]

#[path = "../../snowpaw-server/tests/common/mod.rs"]
mod common;

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{TestServer, Ws};
use futures_util::{SinkExt, StreamExt};
use snowpaw_agent::config::Config;
use snowpaw_agent::runtime;
use snowpaw_proto::agent::{ApiKeyChange, ModelSettings};
use snowpaw_proto::quiz::QuizAnswers;
use snowpaw_proto::ws::{ClientEnvelope, ClientMsg, Content, ServerEnvelope, ServerMsg};
use snowpaw_proto::{Id, SecretString, decode, encode, setup_code};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

struct FakeModel {
    url: String,
    bodies: Arc<Mutex<Vec<String>>>,
    heads: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<VecDeque<String>>>,
}

async fn fake_model() -> FakeModel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}/v1", listener.local_addr().unwrap().port());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(VecDeque::new()));
    let (b, h, sc) = (bodies.clone(), heads.clone(), script.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let (b, h, sc) = (b.clone(), h.clone(), sc.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if buf.len() < i + 4 + len {
                        continue;
                    }
                    b.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).into_owned());
                    h.lock().unwrap().push(head);
                    let text =
                        sc.lock().unwrap().pop_front().unwrap_or_else(|| reply("(no script)"));
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                        text.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    return;
                }
            });
        }
    });
    FakeModel { url, bodies, heads, script }
}

fn reply(text: &str) -> String {
    serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": text } }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 5 }
    })
    .to_string()
}

fn tool_call(name: &str, args: serde_json::Value) -> String {
    serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": null, "tool_calls": [
            { "id": "call_1", "type": "function", "function": { "name": name, "arguments": args.to_string() } }
        ] } }]
    })
    .to_string()
}

async fn recv(ws: &mut Ws) -> ServerMsg {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(20), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(t) = frame {
            return decode::<ServerEnvelope>(t.as_bytes()).unwrap().msg;
        }
    }
}

async fn send(ws: &mut Ws, msg: ClientMsg) {
    ws.send(Message::Text(encode(&ClientEnvelope::new(msg)).into())).await.unwrap();
}

/// The next message the agent posts.
async fn agent_says(ws: &mut Ws, agent: Id) -> Content {
    loop {
        if let ServerMsg::NewMessage { message } = recv(ws).await
            && message.sender_id == agent
        {
            return message.content;
        }
    }
}

#[tokio::test]
async fn quiz_round_trip_and_resume_after_restart() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let s = TestServer::start().await;
    let model = fake_model().await;
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    let _welcome = recv(&mut ws).await;

    send(
        &mut ws,
        ClientMsg::CreateAgent { name: "Tutor".into(), label: String::new(), about: String::new() },
    )
    .await;
    let (chat, agent) = loop {
        if let ServerMsg::AgentCreated { chat_id, agent } = recv(&mut ws).await {
            break (chat_id, agent.id);
        }
    };
    send(
        &mut ws,
        ClientMsg::SetAgentModel {
            agent,
            model: ModelSettings {
                base_url: model.url.clone(),
                model: "fake".into(),
                tls_pin: None,
                instructions: "Teach geography.".into(),
                max_reply_tokens: 200,
                context_messages: 20,
                daily_token_limit: 100_000,
            },
            api_key: ApiKeyChange::Set { key: SecretString::new("sk-test-key".into()) },
        },
    )
    .await;
    send(&mut ws, ClientMsg::IssueAgentToken { agent }).await;
    let agent_token = loop {
        if let ServerMsg::AgentToken { token, .. } = recv(&mut ws).await {
            break token;
        }
    };

    let tmp = tempfile::tempdir().unwrap();
    let token_file = tmp.path().join("token");
    std::fs::write(&token_file, agent_token.expose()).unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let code = setup_code::encode(&s.addr.to_string(), &s.fingerprint);
    let cfg =
        Config::parse(&format!("server = \"{code}\"\ntoken_file = \"{}\"\n", token_file.display()))
            .unwrap();
    let uid = snowpaw_agent::config::effective_uid(tmp.path()).unwrap();
    let loaded = snowpaw_agent::config::load_token(&cfg.token_file, uid).unwrap();
    let rt = tokio::spawn(runtime::run(cfg.clone(), loaded));

    // 1. The model sends a quiz (tool call), then a line of text.
    model.script.lock().unwrap().extend([
        tool_call(
            "send_quiz",
            serde_json::json!({ "title": "Capitals", "questions": [
                { "prompt": "Iceland?", "choices": ["Reykjavík", "Oslo"], "answer": 0 },
                { "prompt": "Norway?", "choices": ["Bergen", "Oslo"], "answer": 1, "explanation": "Oslo since 1814." }
            ]}),
        ),
        reply("Good luck!"),
    ]);
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([1; 16]),
            content: Content::Markdown { text: "Quiz me!".into() },
        },
    )
    .await;
    let quiz_id = loop {
        if let ServerMsg::NewMessage { message } = recv(&mut ws).await
            && let Content::Quiz { quiz } = &message.content
        {
            assert_eq!(quiz.questions.len(), 2);
            break message.id;
        }
    };
    assert_eq!(agent_says(&mut ws, agent).await, Content::Markdown { text: "Good luck!".into() });

    // 2. One wrong answer: the model is told exactly which.
    model.script.lock().unwrap().push_back(reply("Let's look at Norway again."));
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([2; 16]),
            content: Content::QuizAnswers {
                answers: QuizAnswers { quiz_id, answers: vec![Some(0), Some(0)], results: vec![] },
            },
        },
    )
    .await;
    assert_eq!(
        agent_says(&mut ws, agent).await,
        Content::Markdown { text: "Let's look at Norway again.".into() }
    );
    let last = model.bodies.lock().unwrap().last().cloned().unwrap();
    assert!(last.contains("1 of 2 right"), "{last}");
    assert!(
        last.contains(r#"Norway? — answered \"Bergen\": wrong (correct answer: Oslo)"#),
        "{last}"
    );
    assert!(last.contains("Teach geography."), "the user's instructions are the system prompt");
    // The model server got the API key from the server; never the agent's token.
    for head in model.heads.lock().unwrap().iter() {
        assert!(head.contains("authorization: Bearer sk-test-key"));
        assert!(!head.contains("spw_"));
    }
    for body in model.bodies.lock().unwrap().iter() {
        assert!(!body.contains(agent_token.expose()));
    }

    // 3. Stop the runtime; a message arrives while it's down; a new runtime answers it
    // once, and doesn't re-answer anything else.
    rt.abort();
    let calls_before = model.bodies.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([3; 16]),
            content: Content::Markdown { text: "Still there?".into() },
        },
    )
    .await;
    model.script.lock().unwrap().push_back(reply("Yes!"));
    let loaded = snowpaw_agent::config::load_token(&cfg.token_file, uid).unwrap();
    let rt = tokio::spawn(runtime::run(cfg.clone(), loaded));
    assert_eq!(agent_says(&mut ws, agent).await, Content::Markdown { text: "Yes!".into() });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(model.bodies.lock().unwrap().len(), calls_before + 1, "exactly one new model call");

    // 4. Revoking the token stops the runtime for good.
    send(&mut ws, ClientMsg::RevokeAgentToken { agent }).await;
    let reason = tokio::time::timeout(Duration::from_secs(10), rt).await.unwrap().unwrap();
    assert!(reason.contains("revoked") || reason.contains("refused"), "{reason}");
}

#[tokio::test]
async fn scheduled_jobs_run_and_proposals_wait_for_the_user() {
    use snowpaw_proto::jobs::{JobSchedule, JobState};
    let s = TestServer::start().await;
    let model = fake_model().await;
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    let _welcome = recv(&mut ws).await;
    send(
        &mut ws,
        ClientMsg::CreateAgent { name: "Clerk".into(), label: String::new(), about: String::new() },
    )
    .await;
    let (chat, agent) = loop {
        if let ServerMsg::AgentCreated { chat_id, agent } = recv(&mut ws).await {
            break (chat_id, agent.id);
        }
    };
    send(
        &mut ws,
        ClientMsg::SetAgentModel {
            agent,
            model: ModelSettings {
                base_url: model.url.clone(),
                model: "fake".into(),
                tls_pin: None,
                instructions: String::new(),
                max_reply_tokens: 200,
                context_messages: 20,
                daily_token_limit: 100_000,
            },
            api_key: ApiKeyChange::Keep,
        },
    )
    .await;
    send(&mut ws, ClientMsg::IssueAgentToken { agent }).await;
    let (agent_token, code) = loop {
        if let ServerMsg::AgentToken { token, code, .. } = recv(&mut ws).await {
            break (token, code);
        }
    };
    let tmp = tempfile::tempdir().unwrap();
    let token_file = tmp.path().join("token");
    std::fs::write(&token_file, agent_token.expose()).unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg =
        Config::parse(&format!("server = \"{code}\"\ntoken_file = \"{}\"\n", token_file.display()))
            .unwrap();
    let uid = snowpaw_agent::config::effective_uid(tmp.path()).unwrap();
    let rt = tokio::spawn(runtime::run(
        cfg,
        snowpaw_agent::config::load_token(&token_file, uid).unwrap(),
    ));

    // A job: the model's answer is posted, and the job finishes.
    model.script.lock().unwrap().push_back(reply("Here's your summary."));
    send(
        &mut ws,
        ClientMsg::CreateJob {
            agent,
            title: "Summary".into(),
            prompt: "Summarize today.".into(),
            schedule: JobSchedule { first_run_at_ms: common::START_MS, every_secs: None },
        },
    )
    .await;
    assert_eq!(
        agent_says(&mut ws, agent).await,
        Content::Markdown { text: "Here's your summary.".into() }
    );
    let body = model.bodies.lock().unwrap().last().cloned().unwrap();
    assert!(
        body.contains("[Scheduled task: Summary]") && body.contains("Summarize today."),
        "{body}"
    );
    loop {
        if let ServerMsg::JobChanged { job } = recv(&mut ws).await
            && job.state == JobState::Done
        {
            assert_eq!(job.last_run.unwrap().outcome, Some(snowpaw_proto::jobs::RunOutcome::Ok));
            break;
        }
    }

    // The model proposes a job: it shows up as a proposal and doesn't run.
    model.script.lock().unwrap().extend([
        tool_call(
            "propose_job",
            serde_json::json!({ "title": "Morning", "instructions": "Brief me.", "start_in_minutes": 0, "repeat_every_hours": 24 }),
        ),
        reply("I've suggested a morning briefing; approve it if you like."),
    ]);
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([9; 16]),
            content: Content::Markdown { text: "Could you brief me daily?".into() },
        },
    )
    .await;
    let proposal = loop {
        if let ServerMsg::JobChanged { job } = recv(&mut ws).await
            && job.state == JobState::Proposed
        {
            break job;
        }
    };
    assert!(proposal.proposed_by_agent);
    assert_eq!(proposal.schedule.every_secs, Some(86_400));
    agent_says(&mut ws, agent).await;
    rt.abort();
}
