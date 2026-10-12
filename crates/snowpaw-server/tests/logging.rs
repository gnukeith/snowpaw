//! Secrets never reach the logs. Its own test binary, so the global subscriber
//! captures only this test's server.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{PASSWORD, TestServer};
use futures_util::{SinkExt, StreamExt};
use snowpaw_server::config::LogLevel;
use snowpaw_server::logging;
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn passwords_tokens_and_frames_are_never_logged() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(move || writer.clone()))
        // The most verbose level the config allows.
        .with(logging::targets(LogLevel::Debug))
        .init();

    let s = TestServer::start().await;
    let wrong = "wrong-but-close correct horse battery";
    assert_eq!(s.login(wrong).await.status, 401);
    let first = s.login(PASSWORD).await;
    let device = first.json()["device_token"].as_str().unwrap().to_owned();
    let second = s.login_device(PASSWORD, Some(&device)).await;
    let device2 = second.json()["device_token"].as_str().unwrap().to_owned();
    let token = s.token().await;
    let mut ws = s.ws(&token).await.unwrap();
    ws.send(Message::Text(r#"{"v":1,"msg":{"type":"ping","nonce":31337}}"#.into())).await.unwrap();
    let _ = ws.next().await;
    ws.send(Message::Text(r#"{"v":1,"msg":{"type":"bogus","secret":"frame-body-xyz"}}"#.into()))
        .await
        .unwrap();
    while let Some(Ok(_)) = ws.next().await {}
    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 204);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("login failed"), "capture isn't working:\n{logs}");
    assert!(logs.contains("login succeeded"));
    for secret in [
        PASSWORD,
        wrong,
        token.as_str(),
        &token[6..],
        &device,
        &device[6..],
        &device2,
        "31337",
        "frame-body-xyz",
        "bogus",
    ] {
        assert!(!logs.contains(secret), "{secret:?} leaked into logs:\n{logs}");
    }
}
