//! The client's network code against a real server.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use snowpaw_client::config::ClientConfig;
use snowpaw_client::net::{self, LoginError, WsConnectError};
use snowpaw_client::tls::ConnectError;
use snowpaw_proto::ws::{ChatKind, ClientEnvelope, ClientMsg, ServerEnvelope, ServerMsg};
use snowpaw_proto::{SecretString, decode, encode};
use snowpaw_server::clock::SystemClock;
use snowpaw_server::config::Config;
use snowpaw_server::server::Server;
use snowpaw_server::setup;
use tokio_tungstenite::tungstenite::Message;

const PASSWORD: &str = "correct horse battery staple";

struct TestServer {
    settings: ClientConfig,
    _tmp: tempfile::TempDir,
}

async fn start() -> TestServer {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let report = setup::init(&data, &SystemClock).unwrap();
    let cfg = Config::parse(&format!(
        "[server]\nlisten = \"127.0.0.1:0\"\ndata_dir = \"{}\"\n",
        data.display()
    ))
    .unwrap();
    setup::set_password(&cfg, &SecretString::new(PASSWORD.into()), &SystemClock).unwrap();
    let server = Server::bind(cfg, Arc::new(SystemClock)).await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run(std::future::pending()));
    let settings = ClientConfig::new(&addr.to_string(), &report.fingerprint).unwrap();
    TestServer { settings, _tmp: tmp }
}

fn pw(s: &str) -> SecretString {
    SecretString::new(s.into())
}

async fn next(ws: &mut net::Ws) -> ServerMsg {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(t) = frame {
            return decode::<ServerEnvelope>(t.as_bytes()).unwrap().msg;
        }
    }
}

#[tokio::test]
async fn login_websocket_and_logout() {
    let s = start().await;
    let ok = net::login(&s.settings, &pw(PASSWORD), None).await.unwrap();
    let mut ws = net::connect_ws(&s.settings, &ok.token).await.unwrap();
    assert!(matches!(next(&mut ws).await, ServerMsg::Welcome { .. }));
    ws.send(Message::Text(encode(&ClientEnvelope::new(ClientMsg::ListChats {})).into()))
        .await
        .unwrap();
    match next(&mut ws).await {
        ServerMsg::Chats { chats } => assert_eq!(chats[0].kind, ChatKind::NoteToSelf),
        other => panic!("{other:?}"),
    }
    net::logout(&s.settings, &ok.token).await.unwrap();
    assert!(matches!(
        net::connect_ws(&s.settings, &ok.token).await,
        Err(WsConnectError::Unauthorized)
    ));
}

#[tokio::test]
async fn wrong_password() {
    let s = start().await;
    assert!(matches!(
        net::login(&s.settings, &pw("not the password at all"), None).await,
        Err(LoginError::WrongPassword)
    ));
}

#[tokio::test]
async fn device_tokens_round_trip() {
    let s = start().await;
    let first = net::login(&s.settings, &pw(PASSWORD), None).await.unwrap();
    let second = net::login(&s.settings, &pw(PASSWORD), Some(&first.device_token)).await.unwrap();
    assert_ne!(first.device_token.expose(), second.device_token.expose(), "rotated");
}

#[tokio::test]
async fn a_server_with_a_different_certificate_is_refused() {
    let real = start().await;
    let impostor = start().await;
    // Settings pinned to `real`, but pointed at `impostor`'s address: what an attacker
    // who can redirect traffic would look like.
    let (host, port) = impostor.settings.host_port();
    let pinned_wrong =
        ClientConfig::new(&format!("{host}:{port}"), &real.settings.fingerprint).unwrap();
    assert!(matches!(
        net::login(&pinned_wrong, &pw(PASSWORD), None).await,
        Err(LoginError::Connect(ConnectError::PinMismatch))
    ));
    assert!(matches!(
        net::connect_ws(&pinned_wrong, &pw("spw_s_x")).await,
        Err(WsConnectError::Connect(ConnectError::PinMismatch))
    ));
}

#[tokio::test]
async fn unreachable_server_is_reported() {
    let settings = ClientConfig::new(
        "127.0.0.1:1",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(matches!(
        net::login(&settings, &pw(PASSWORD), None).await,
        Err(LoginError::Connect(ConnectError::Unreachable(_)))
    ));
}

/// A minimal valid PNG header for a 256x256 image (the server only checks the header).
fn png_256() -> Vec<u8> {
    let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 13];
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&256u32.to_be_bytes());
    png.extend_from_slice(&256u32.to_be_bytes());
    png.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    png.extend_from_slice(b"pixels");
    png
}

#[tokio::test]
async fn pictures_round_trip_and_are_hash_checked() {
    let s = start().await;
    let ok = net::login(&s.settings, &pw(PASSWORD), None).await.unwrap();
    let png = png_256();
    let hash = net::upload_blob(&s.settings, &ok.token, png.clone()).await.unwrap();
    assert_eq!(net::fetch_blob(&s.settings, &ok.token, hash).await.unwrap(), png);
    // Unknown hash: refused, not some other picture.
    let other = snowpaw_proto::profile::BlobHash::from_bytes([9; 32]);
    assert!(net::fetch_blob(&s.settings, &ok.token, other).await.is_err());
    // The server rejects non-PNGs; the client reports it instead of attaching anything.
    assert!(net::upload_blob(&s.settings, &ok.token, b"GIF89a".to_vec()).await.is_err());
    // Without a valid session nothing works.
    let bad = pw("spw_s_0000");
    assert!(net::fetch_blob(&s.settings, &bad, hash).await.is_err());
}

#[tokio::test]
async fn connection_test_reports_what_went_wrong() {
    let s = start().await;
    assert_eq!(net::test_connection(&s.settings).await, Ok(()));

    let wrong_pin =
        ClientConfig::new(&s.settings.server, &format!("sha256:{}", "ab".repeat(32))).unwrap();
    let err = net::test_connection(&wrong_pin).await.unwrap_err();
    assert!(err.contains("doesn't match your code"), "{err}");

    // A port nobody listens on.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let nobody = ClientConfig::new(&addr.to_string(), &s.settings.fingerprint).unwrap();
    let err = net::test_connection(&nobody).await.unwrap_err();
    assert!(err.starts_with("Nothing answered at 127.0.0.1:"), "{err}");
}
