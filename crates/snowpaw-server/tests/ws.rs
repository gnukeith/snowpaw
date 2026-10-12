//! The WebSocket: authentication, strict frames, limits, and session teardown.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{TestServer, Ws, upgrade_status};
use futures_util::{SinkExt, StreamExt};
use snowpaw_proto::ws::{ServerEnvelope, ServerMsg, WsErrorCode};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

/// Next server message, skipping pings/pongs. None if the socket closed or nothing arrived.
async fn next_msg(ws: &mut Ws) -> Option<ServerMsg> {
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

/// Drain until the socket closes; return the error code the server sent, if any.
/// Panics if the socket stays open past `limit`.
async fn closed_with(ws: &mut Ws, limit: Duration) -> Option<WsErrorCode> {
    let mut code = None;
    let result = tokio::time::timeout(limit, async {
        while let Some(frame) = ws.next().await {
            match frame {
                Ok(Message::Text(t)) => {
                    if let Ok(env) = snowpaw_proto::decode::<ServerEnvelope>(t.as_bytes())
                        && let ServerMsg::Error { code: c } = env.msg
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
    assert!(result.is_ok(), "socket was not closed within {limit:?}");
    code
}

async fn connect(s: &TestServer) -> Ws {
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    assert!(matches!(
        next_msg(&mut ws).await,
        Some(ServerMsg::Welcome { protocol_version: 1, .. })
    ));
    ws
}

async fn send_text(ws: &mut Ws, text: &str) {
    ws.send(Message::Text(text.into())).await.unwrap();
}

#[tokio::test]
async fn authenticated_socket_gets_welcome_and_pong() {
    let s = TestServer::start().await;
    let mut ws = connect(&s).await;
    send_text(&mut ws, r#"{"v":1,"msg":{"type":"ping","nonce":42}}"#).await;
    assert_eq!(next_msg(&mut ws).await, Some(ServerMsg::Pong { nonce: 42 }));
}

#[tokio::test]
async fn upgrade_requires_a_valid_session() {
    let s = TestServer::start().await;
    let token = s.token().await;

    let err = s.ws_with(&[]).await.unwrap_err();
    assert_eq!(upgrade_status(&err), Some(401));
    let err = s.ws("spw_s_0000").await.unwrap_err();
    assert_eq!(upgrade_status(&err), Some(401));

    // Token in the query string is ignored.
    let stream = s.tls().await;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let req = format!("wss://localhost:{}/v1/ws?token={token}", s.addr.port())
        .into_client_request()
        .unwrap();
    let err = tokio_tungstenite::client_async(req, stream).await.unwrap_err();
    assert_eq!(upgrade_status(&err), Some(401));

    // Revoked token.
    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 204);
    let err = s.ws(&token).await.unwrap_err();
    assert_eq!(upgrade_status(&err), Some(401));
}

#[tokio::test]
async fn malformed_frames_close_the_socket() {
    let s = TestServer::start().await;
    for bad in [
        "not json",
        "{}",
        r#"{"v":1,"msg":{"type":"ping","nonce":1,"extra":true}}"#,
        r#"{"v":1,"msg":{"type":"ping","nonce":1},"extra":true}"#,
        r#"{"v":1,"msg":{"type":"admin","nonce":1}}"#,
        r#"{"v":1,"msg":["ping",1]}"#,
        r#"{"v":1,"msg":{"type":"ping","nonce":1,"nonce":2}}"#,
        r#"{"v":1,"msg":{"type":"ping","nonce":-1}}"#,
        r#"{"v":1,"msg":{"type":"ping","nonce":1}}{"v":1,"msg":{"type":"ping","nonce":2}}"#,
    ] {
        let mut ws = connect(&s).await;
        send_text(&mut ws, bad).await;
        assert_eq!(
            closed_with(&mut ws, Duration::from_secs(5)).await,
            Some(WsErrorCode::BadFrame),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn binary_frames_close_the_socket() {
    let s = TestServer::start().await;
    let mut ws = connect(&s).await;
    ws.send(Message::Binary(br#"{"v":1,"msg":{"type":"ping","nonce":1}}"#.to_vec().into()))
        .await
        .unwrap();
    assert_eq!(closed_with(&mut ws, Duration::from_secs(5)).await, Some(WsErrorCode::BadFrame));
}

#[tokio::test]
async fn unsupported_version_closes_the_socket() {
    let s = TestServer::start().await;
    let mut ws = connect(&s).await;
    send_text(&mut ws, r#"{"v":2,"msg":{"type":"ping","nonce":1}}"#).await;
    assert_eq!(
        closed_with(&mut ws, Duration::from_secs(5)).await,
        Some(WsErrorCode::UnsupportedVersion)
    );
}

#[tokio::test]
async fn oversized_messages_close_the_socket() {
    let s =
        TestServer::start_with("[limits]\nmax_ws_message_bytes = 1024\nmax_message_bytes = 256\n")
            .await;
    let mut ws = connect(&s).await;
    let big =
        format!(r#"{{"v":1,"msg":{{"type":"ping","nonce":1}},"pad":"{}"}}"#, "a".repeat(2000));
    let _ = ws.send(Message::Text(big.into())).await;
    closed_with(&mut ws, Duration::from_secs(5)).await;
}

#[tokio::test]
async fn flooding_hits_the_rate_limit() {
    let s = TestServer::start_with("[limits]\nws_messages_per_sec = 1\nws_burst = 5\n").await;
    let mut ws = connect(&s).await;
    for n in 0..50u64 {
        if ws
            .send(Message::Text(format!(r#"{{"v":1,"msg":{{"type":"ping","nonce":{n}}}}}"#).into()))
            .await
            .is_err()
        {
            break;
        }
    }
    let mut pongs = 0;
    let code = loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap() {
            Some(Ok(Message::Text(t))) => {
                match snowpaw_proto::decode::<ServerEnvelope>(t.as_bytes()).unwrap().msg {
                    ServerMsg::Pong { .. } => pongs += 1,
                    ServerMsg::Error { code } => break Some(code),
                    other => panic!("unexpected frame {other:?}"),
                }
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            _ => break None,
        }
    };
    assert_eq!(code, Some(WsErrorCode::RateLimited));
    assert!(pongs <= 6, "{pongs} pongs got through a burst of 5");
}

#[tokio::test]
async fn ping_floods_count_against_the_rate_limit() {
    let s = TestServer::start_with("[limits]\nws_messages_per_sec = 1\nws_burst = 5\n").await;
    let mut ws = connect(&s).await;
    for _ in 0..50 {
        if ws.send(Message::Ping(Default::default())).await.is_err() {
            break;
        }
    }
    assert_eq!(closed_with(&mut ws, Duration::from_secs(5)).await, Some(WsErrorCode::RateLimited));
}

#[tokio::test]
async fn logout_closes_open_sockets_immediately() {
    let s = TestServer::start().await;
    let token = s.token().await;
    let other = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    let mut ws_other = s.ws(&other).await.unwrap();
    assert!(next_msg(&mut ws).await.is_some());
    assert!(next_msg(&mut ws_other).await.is_some());

    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 204);
    assert_eq!(closed_with(&mut ws, Duration::from_secs(2)).await, Some(WsErrorCode::SessionEnded));

    // The other session's socket is untouched.
    send_text(&mut ws_other, r#"{"v":1,"msg":{"type":"ping","nonce":7}}"#).await;
    assert_eq!(next_msg(&mut ws_other).await, Some(ServerMsg::Pong { nonce: 7 }));

    assert_eq!(s.authed("POST", "/v1/logout_all", &other).await.status, 204);
    assert_eq!(
        closed_with(&mut ws_other, Duration::from_secs(2)).await,
        Some(WsErrorCode::SessionEnded)
    );
}

#[tokio::test]
async fn eviction_closes_the_evicted_socket() {
    let s = TestServer::start_with("[auth]\nmax_sessions = 1\n").await;
    let mut ws = connect(&s).await;
    let _newer = s.token().await;
    assert_eq!(closed_with(&mut ws, Duration::from_secs(2)).await, Some(WsErrorCode::SessionEnded));
}

#[tokio::test]
async fn revocation_by_another_process_is_noticed() {
    let s = TestServer::start_with("[limits]\nsession_recheck_secs = 1\n").await;
    let mut ws = connect(&s).await;
    // Simulate the `set-password` command: a separate connection to the database
    // deletes the sessions, bypassing the in-process broadcast.
    let tmp = s.data_dir.clone();
    let uid = snowpaw_server::fsperm::effective_uid(&tmp).unwrap();
    let db = snowpaw_server::db::Db::open(&s.db_path(), uid).unwrap();
    db.call_blocking(|c| Ok(c.execute("DELETE FROM sessions", [])?)).unwrap();
    assert_eq!(closed_with(&mut ws, Duration::from_secs(4)).await, Some(WsErrorCode::SessionEnded));
}

#[tokio::test]
async fn session_expiry_closes_the_socket() {
    let s = TestServer::start_with(
        "[auth]\nsession_idle_timeout_secs = 300\nsession_max_lifetime_secs = 3600\n[limits]\nsession_recheck_secs = 1\n",
    )
    .await;
    let mut ws = connect(&s).await;
    s.clock.advance_secs(3600);
    assert_eq!(closed_with(&mut ws, Duration::from_secs(4)).await, Some(WsErrorCode::SessionEnded));
}

#[tokio::test]
async fn silent_peers_are_disconnected() {
    let s = TestServer::start_with("[limits]\nws_idle_timeout_secs = 10\n").await;
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    // Don't read: tungstenite only answers pings while being polled, so the server
    // sees nothing from us and must give up after the idle timeout.
    tokio::time::sleep(Duration::from_secs(15)).await;
    closed_with(&mut ws, Duration::from_secs(5)).await;
}

#[tokio::test]
async fn client_close_is_clean() {
    let s = TestServer::start().await;
    let mut ws = connect(&s).await;
    ws.close(Some(CloseFrame { code: 1000.into(), reason: "".into() })).await.unwrap();
    closed_with(&mut ws, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn every_allowed_message_size_limit_works() {
    // Regression: some buffer settings made the WebSocket library panic.
    for limit in [1024, 65_536, 1_048_576] {
        let s = TestServer::start_with(&format!(
            "[limits]\nmax_ws_message_bytes = {limit}\nmax_message_bytes = {}\n",
            ((limit - 512) / 2).min(65_536)
        ))
        .await;
        let mut ws = connect(&s).await;
        send_text(&mut ws, r#"{"v":1,"msg":{"type":"ping","nonce":1}}"#).await;
        assert_eq!(next_msg(&mut ws).await, Some(ServerMsg::Pong { nonce: 1 }), "{limit}");
    }
}
