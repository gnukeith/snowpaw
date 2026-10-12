//! TLS and HTTP-level controls: no plaintext, TLS 1.3 only, pinning, browser
//! refusal, size and time limits, and the connection cap.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::{PASSWORD, TestServer, client_config};
use rustls::NamedGroup;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Read until EOF/error or `limit`, returning what arrived and how long it took.
async fn read_until_closed(
    s: &mut (impl AsyncReadExt + Unpin),
    limit: Duration,
) -> (Vec<u8>, Option<Duration>) {
    let start = Instant::now();
    let mut buf = vec![];
    let res = tokio::time::timeout(limit, async {
        let mut chunk = [0u8; 1024];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    (buf, res.ok().map(|()| start.elapsed()))
}

#[tokio::test]
async fn plaintext_http_gets_no_http_response() {
    let s = TestServer::start().await;
    let mut tcp = TcpStream::connect(s.addr).await.unwrap();
    tcp.write_all(b"POST /v1/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        .await
        .unwrap();
    let (buf, closed) = read_until_closed(&mut tcp, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "server should hang up");
    assert!(
        !buf.starts_with(b"HTTP/"),
        "server spoke plaintext HTTP: {:?}",
        String::from_utf8_lossy(&buf)
    );
}

#[tokio::test]
async fn tls12_is_refused() {
    let s = TestServer::start().await;
    let cfg = client_config(s.cert.clone(), &[&rustls::version::TLS12]);
    assert!(s.tls_with(cfg).await.is_err());
}

#[tokio::test]
async fn hybrid_post_quantum_key_exchange_is_negotiated() {
    let s = TestServer::start().await;
    let stream = s.tls().await;
    let (_, conn) = stream.get_ref();
    assert_eq!(conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(
        conn.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::X25519MLKEM768)
    );
}

#[tokio::test]
async fn a_client_pinned_to_another_cert_refuses_the_server() {
    let s = TestServer::start().await;
    let other = TestServer::start().await;
    let cfg = client_config(other.cert.clone(), &[&rustls::version::TLS13]);
    assert!(s.tls_with(cfg).await.is_err());
    assert_ne!(s.fingerprint, other.fingerprint);
}

#[tokio::test]
async fn browsers_are_refused_everywhere() {
    let s = TestServer::start().await;
    let token = s.token().await;
    let auth = format!("Bearer {token}");
    for (name, value) in [
        ("Origin", "https://evil.example"),
        ("Origin", "null"),
        ("Origin", "https://localhost:7443"),
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Mode", "navigate"),
        ("sec-fetch-dest", "empty"),
    ] {
        // Login with the right password from a browser context: refused, and no token.
        let r = s.login_with(PASSWORD, &[(name, value)]).await;
        assert_eq!(r.status, 403, "{name}: {value}");
        assert_eq!(r.error_code().as_deref(), Some("forbidden_origin"));
        // Even a valid session can't be used from a browser.
        let r =
            s.request("POST", "/v1/logout", &[("Authorization", &auth), (name, value)], "").await;
        assert_eq!(r.status, 403);
        let r = s.request("GET", "/nonexistent", &[(name, value)], "").await;
        assert_eq!(r.status, 403);
    }
    // The session survived all of that.
    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 204);
}

#[tokio::test]
async fn browser_websocket_is_refused() {
    let s = TestServer::start().await;
    let token = s.token().await;
    let auth = format!("Bearer {token}");
    let err = s
        .ws_with(&[("Authorization", &auth), ("Origin", "https://evil.example")])
        .await
        .unwrap_err();
    assert_eq!(common::upgrade_status(&err), Some(403));
}

#[tokio::test]
async fn unknown_routes_and_methods() {
    let s = TestServer::start().await;
    assert_eq!(s.request("GET", "/", &[], "").await.status, 404);
    assert_eq!(s.request("GET", "/v1/../v1/login", &[], "").await.status, 404);
    assert_eq!(s.request("GET", "/admin", &[], "").await.status, 404);
    assert_eq!(s.request("GET", "/v1/login", &[], "").await.status, 405);
    assert_eq!(s.request("PUT", "/v1/logout", &[], "").await.status, 405);
    let r = s.request("GET", "/", &[], "").await;
    assert_eq!(r.header("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
}

#[tokio::test]
async fn login_body_must_be_strict_json() {
    let s = TestServer::start().await;
    let json = [("Content-Type", "application/json")];
    // The canonical login body, built (not spelled out) so no literal that looks
    // like a credential sits in the source.
    let login = serde_json::json!({ "password": PASSWORD }).to_string();
    for (headers, body, status) in [
        (&[("Content-Type", "text/plain")][..], login.clone(), 415),
        (&[][..], login.clone(), 415),
        (&json[..], "not json".to_owned(), 400),
        (&json[..], "{}".to_owned(), 400),
        (
            &json[..],
            serde_json::json!({ "password": PASSWORD, "admin": true }).to_string(),
            400,
        ),
        (&json[..], format!(r#"["{PASSWORD}"]"#), 400),
        (&json[..], format!(r#"{{"password":"x","password":"{PASSWORD}"}}"#), 400),
        (&json[..], format!(r#"{{"password":"{}"}}"#, "a".repeat(2000)), 400),
    ] {
        let r = s.request("POST", "/v1/login", headers, &body).await;
        assert_eq!(r.status, status, "{headers:?} {}", &body[..body.len().min(60)]);
        assert!(r.json().get("token").is_none());
    }
    // Error bodies never echo input.
    let r = s.request("POST", "/v1/login", &json, r#"{"password":"x","sneaky<script>":1}"#).await;
    assert!(!String::from_utf8_lossy(&r.body).contains("sneaky"));
}

#[tokio::test]
async fn oversized_bodies_and_headers_are_refused() {
    let s = TestServer::start().await;
    let big = format!(r#"{{"password":"{}"}}"#, "a".repeat(20_000));
    let r = s.request("POST", "/v1/login", &[("Content-Type", "application/json")], &big).await;
    assert_eq!(r.status, 413);

    // Declared length over the limit is refused before reading anything.
    let req = "POST /v1/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n";
    assert_eq!(s.raw(req.as_bytes()).await.unwrap().status, 413);

    // Chunked body over the limit.
    let chunk = "a".repeat(8000);
    let mut req = String::from(
        "POST /v1/login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    for _ in 0..3 {
        req.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
    }
    req.push_str("0\r\n\r\n");
    assert_eq!(s.raw(req.as_bytes()).await.unwrap().status, 413);

    // Huge headers: not processed (431 or hang-up), never a 2xx.
    let req = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Big: {}\r\n\r\n",
        "a".repeat(32_000)
    );
    if let Some(r) = s.raw(req.as_bytes()).await {
        assert!(r.status >= 400, "{}", r.status);
    }
}

#[tokio::test]
async fn idle_tls_handshakes_are_cut_off() {
    let s = TestServer::start_with("[limits]\ntls_handshake_timeout_secs = 1\n").await;
    let mut tcp = TcpStream::connect(s.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut tcp, Duration::from_secs(5)).await;
    let took = closed.expect("server should drop a silent connection");
    assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(4), "{took:?}");
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let s = TestServer::start_with("[limits]\nhttp_header_timeout_secs = 1\n").await;
    let mut tls = s.tls().await;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n").await.unwrap(); // never finished
    let (_, closed) = read_until_closed(&mut tls, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "server should drop a connection that never finishes its headers");
}

#[tokio::test]
async fn idle_keep_alive_connections_are_cut_off() {
    let s = TestServer::start_with("[limits]\nhttp_header_timeout_secs = 1\n").await;
    let mut tls = s.tls().await;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let (buf, closed) = read_until_closed(&mut tls, Duration::from_secs(5)).await;
    assert_eq!(common::parse_response(&buf).map(|r| r.status), Some(404));
    let took = closed.expect("an idle keep-alive connection must not be held open");
    assert!(took < Duration::from_secs(3), "{took:?}");
}

#[tokio::test]
async fn dribbled_headers_hit_a_total_deadline() {
    // Security review #2 claimed the header timeout resets on every byte. It doesn't:
    // the deadline covers the whole header, so dribbling can't hold a slot open.
    let s = TestServer::start_with("[limits]\nhttp_header_timeout_secs = 1\n").await;
    let mut tls = s.tls().await;
    let start = Instant::now();
    let dribble = async {
        for b in
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        {
            if tls.write_all(&[*b]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(6), dribble).await.unwrap();
    let (_, closed) = read_until_closed(&mut tls, Duration::from_secs(3)).await;
    assert!(closed.is_some(), "connection should be closed");
    assert!(start.elapsed() < Duration::from_secs(4), "{:?}", start.elapsed());
}

#[tokio::test]
async fn unread_bodies_cannot_hold_a_connection_open() {
    // A route that doesn't read the body (logout) must not keep the connection
    // waiting for a slow, huge body after it has answered.
    let s = TestServer::start_with("[limits]\nhttp_header_timeout_secs = 1\n").await;
    let mut tls = s.tls().await;
    tls.write_all(
        b"POST /v1/logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\nabc",
    )
    .await
    .unwrap();
    let start = Instant::now();
    let mut got = vec![];
    let mut chunk = [0u8; 1024];
    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            tokio::select! {
                r = tls.read(&mut chunk) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                },
                () = tokio::time::sleep(Duration::from_millis(200)) => {
                    // keep dribbling body bytes
                    if tls.write_all(b"x").await.is_err() { break; }
                }
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "connection held open by a dribbled body");
    assert_eq!(common::parse_response(&got).map(|r| r.status), Some(401));
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
}

#[tokio::test]
async fn per_address_cap_drops_extra_connections() {
    let s = TestServer::start_with("[limits]\nmax_connections_per_ip = 2\n").await;
    let hold1 = TcpStream::connect(s.addr).await.unwrap();
    let hold2 = TcpStream::connect(s.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = TcpStream::connect(s.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut third, Duration::from_secs(2)).await;
    assert!(closed.is_some(), "third connection from one address should be dropped");
    drop((hold1, hold2));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.login(PASSWORD).await.status, 200);
}

#[tokio::test]
async fn slow_bodies_are_cut_off() {
    let s = TestServer::start_with("[limits]\nhttp_body_timeout_secs = 1\n").await;
    let mut tls = s.tls().await;
    tls.write_all(b"POST /v1/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"pass")
        .await
        .unwrap();
    let (buf, closed) = read_until_closed(&mut tls, Duration::from_secs(5)).await;
    assert!(closed.is_some());
    assert_eq!(common::parse_response(&buf).map(|r| r.status), Some(408));
}

#[tokio::test]
async fn connection_cap_drops_extra_connections() {
    let s =
        TestServer::start_with("[limits]\nmax_connections = 2\nmax_connections_per_ip = 2\n").await;
    let hold1 = TcpStream::connect(s.addr).await.unwrap();
    let hold2 = TcpStream::connect(s.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = TcpStream::connect(s.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut third, Duration::from_secs(2)).await;
    assert!(closed.is_some(), "third connection should be dropped immediately");

    // Slots are released when connections end.
    drop((hold1, hold2));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.login(PASSWORD).await.status, 200);
}
