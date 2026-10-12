//! Plugins end to end: the user installs a wasm plugin and grants it to an agent;
//! the model calls the plugin's tool through the runtime; the result goes back to the
//! model. A plugin that tries to fetch from a host it wasn't granted gets nothing.
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
use snowpaw_proto::http::PluginInstalled;
use snowpaw_proto::plugin::PluginView;
use snowpaw_proto::ws::{ClientEnvelope, ClientMsg, Content, ServerEnvelope, ServerMsg};
use snowpaw_proto::{Id, decode, encode, setup_code};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

struct FakeModel {
    url: String,
    bodies: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<VecDeque<String>>>,
}

async fn fake_model() -> FakeModel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}/v1", listener.local_addr().unwrap().port());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(VecDeque::new()));
    let (b, sc) = (bodies.clone(), script.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let (b, sc) = (b.clone(), sc.clone());
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
                    let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length: ").map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if buf.len() < i + 4 + len {
                        continue;
                    }
                    b.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).into_owned());
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
    FakeModel { url, bodies, script }
}

fn reply(text: &str) -> String {
    serde_json::json!({ "choices": [{ "message": { "role": "assistant", "content": text } }] })
        .to_string()
}

fn tool_call(name: &str) -> String {
    serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": null, "tool_calls": [
            { "id": "call_1", "type": "function", "function": { "name": name, "arguments": "{}" } }
        ] } }]
    })
    .to_string()
}

/// A plugin (WebAssembly text) whose every step returns `output`, with its manifest
/// embedded.
fn plugin(name: &str, tool: &str, hosts: &[&str], output: &str) -> Vec<u8> {
    let manifest = serde_json::json!({
        "api": 1, "name": name, "version": "1.0.0", "description": "test",
        "tools": [{ "name": tool, "description": "does a thing", "parameters": { "type": "object" } }],
        "capabilities": { "http": hosts },
    })
    .to_string();
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    wat::parse_str(format!(
        r#"(module
            (memory (export "memory") 1)
            (func (export "snowpaw_api") (result i32) (i32.const 1))
            (func (export "snowpaw_buffer") (param i32) (result i32) (i32.const 1024))
            (func (export "snowpaw_output") (result i32) (i32.const 8192))
            (func (export "snowpaw_run") (param i32) (result i32) (i32.const {len}))
            (data (i32.const 8192) "{out}")
            (@custom "snowpaw-manifest" "{manifest}"))"#,
        len = output.len(),
        out = esc(output),
        manifest = esc(&manifest),
    ))
    .unwrap()
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

async fn install(s: &TestServer, token: &str, wasm: &[u8]) -> PluginView {
    let mut req = format!(
        "POST /v1/plugins HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/wasm\r\nContent-Length: {}\r\n\r\n",
        wasm.len()
    )
    .into_bytes();
    req.extend_from_slice(wasm);
    let r = s.raw(&req).await.unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    decode::<PluginInstalled>(&r.body).unwrap().plugin
}

#[tokio::test]
async fn a_granted_plugin_answers_and_an_ungranted_fetch_is_refused() {
    let s = TestServer::start().await;
    let model = fake_model().await;
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    let _welcome = recv(&mut ws).await;

    send(
        &mut ws,
        ClientMsg::CreateAgent {
            name: "Helper".into(),
            label: String::new(),
            about: String::new(),
        },
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

    // Install two plugins: one that answers, one that keeps asking to fetch.
    let greeter = install(
        &s,
        &token,
        &plugin("greeter", "greet", &[], r#"{"result":"Hello from the sandbox"}"#),
    )
    .await;
    let fetcher = install(
        &s,
        &token,
        &plugin(
            "fetcher",
            "grab",
            &["api.example.com"],
            r#"{"fetch":{"url":"https://evil.example.net/x"},"state":null}"#,
        ),
    )
    .await;
    assert_eq!(greeter.tools[0].name, "greeter__greet");
    // A grant can't add hosts the plugin didn't ask for.
    send(
        &mut ws,
        ClientMsg::GrantPlugin {
            agent,
            plugin: fetcher.id,
            http_hosts: vec!["evil.example.net".into()],
        },
    )
    .await;
    loop {
        if let ServerMsg::Error { code } = recv(&mut ws).await {
            assert_eq!(code, snowpaw_proto::ws::WsErrorCode::InvalidRequest);
            break;
        }
    }
    let mut ws = s.ws(&token).await.unwrap();
    let _welcome = recv(&mut ws).await;
    for (plugin, hosts) in [(greeter.id, vec![]), (fetcher.id, vec!["api.example.com".to_owned()])]
    {
        send(&mut ws, ClientMsg::GrantPlugin { agent, plugin, http_hosts: hosts }).await;
        loop {
            if let ServerMsg::Plugins { .. } = recv(&mut ws).await {
                break;
            }
        }
    }

    send(&mut ws, ClientMsg::IssueAgentToken { agent }).await;
    let (agent_token, code) = loop {
        if let ServerMsg::AgentToken { token, code, .. } = recv(&mut ws).await {
            break (token, code);
        }
    };
    assert_eq!(code, setup_code::encode(&s.addr.to_string(), &s.fingerprint));
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

    // The model calls the greeter, then answers with what it got.
    model.script.lock().unwrap().extend([
        tool_call("greeter__greet"),
        reply("It said hello."),
        tool_call("fetcher__grab"),
        reply("No luck."),
    ]);
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([1; 16]),
            content: Content::Markdown { text: "greet me".into() },
        },
    )
    .await;
    loop {
        if let ServerMsg::NewMessage { message } = recv(&mut ws).await
            && message.sender_id == agent
        {
            assert_eq!(message.content, Content::Markdown { text: "It said hello.".into() });
            break;
        }
    }
    {
        let bodies = model.bodies.lock().unwrap();
        assert!(bodies[0].contains("greeter__greet"), "the plugin's tool was offered");
        assert!(
            bodies[1].contains("Hello from the sandbox"),
            "the plugin's result went to the model"
        );
    }

    // The fetcher asks for a host it wasn't granted: every fetch is refused.
    send(
        &mut ws,
        ClientMsg::Send {
            chat_id: chat,
            client_msg_id: Id::from_bytes([2; 16]),
            content: Content::Markdown { text: "grab it".into() },
        },
    )
    .await;
    loop {
        if let ServerMsg::NewMessage { message } = recv(&mut ws).await
            && message.sender_id == agent
        {
            break;
        }
    }
    let last = model.bodies.lock().unwrap().last().cloned().unwrap();
    assert!(last.contains("too many fetches"), "{last}");
    send(&mut ws, ClientMsg::ListAudit { before_seq: None, limit: 200 }).await;
    loop {
        if let ServerMsg::Audit { entries, .. } = recv(&mut ws).await {
            let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
            assert!(actions.contains(&"plugin_installed") && actions.contains(&"plugin_granted"));
            assert!(actions.contains(&"plugin_fetch_refused"), "{actions:?}");
            break;
        }
    }
    rt.abort();
}
