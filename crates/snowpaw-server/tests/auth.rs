//! Login, sessions, and attempts to get around them.
#![allow(clippy::unwrap_used)]

mod common;

use common::{PASSWORD, TestServer};
use snowpaw_proto::SESSION_TOKEN_PREFIX;

#[tokio::test]
async fn login_issues_a_fresh_well_formed_token() {
    let s = TestServer::start().await;
    let r = s.login(PASSWORD).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let token = r.json()["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with(SESSION_TOKEN_PREFIX));
    assert_eq!(token.len(), SESSION_TOKEN_PREFIX.len() + 64);
    // Every login mints a new token.
    assert_ne!(token, s.token().await);
    assert_eq!(s.authed("POST", "/v1/logout", &token).await.status, 204);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let s = TestServer::start().await;
    for pw in [
        "",
        "correct horse battery stapl",
        "correct horse battery staple ",
        "CORRECT HORSE BATTERY STAPLE",
    ] {
        let r = s.login(pw).await;
        assert_eq!(r.status, 401, "{pw:?}");
        assert_eq!(r.error_code().as_deref(), Some("unauthorized"));
        assert!(r.json().get("token").is_none());
    }
}

#[tokio::test]
async fn protected_routes_require_a_valid_bearer_token() {
    let s = TestServer::start().await;
    let good = s.token().await;
    let hex = &good[SESSION_TOKEN_PREFIX.len()..];
    let mut flipped = good.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    let flipped = String::from_utf8(flipped).unwrap();

    let bad_headers: Vec<Vec<(&str, String)>> = vec![
        vec![],
        vec![("Authorization", String::new())],
        vec![("Authorization", "Bearer".into())],
        vec![("Authorization", "Bearer ".into())],
        vec![("Authorization", format!("Basic {good}"))],
        vec![("Authorization", format!("Token {good}"))],
        vec![("Authorization", good.clone())],
        vec![("Authorization", format!("Bearer {hex}"))],
        vec![("Authorization", format!("Bearer  {good}"))],
        // (A trailing space isn't tested: HTTP strips whitespace around header values,
        // so the server never sees it.)
        vec![("Authorization", format!("Bearer {}", good.to_uppercase()))],
        vec![("Authorization", format!("Bearer {flipped}"))],
        vec![("Authorization", format!("Bearer {good}x"))],
        vec![("Authorization", format!("Bearer spw_s_{}", "0".repeat(64)))],
        // Two Authorization headers, even if one is valid.
        vec![
            ("Authorization", format!("Bearer {good}")),
            ("Authorization", format!("Bearer {good}")),
        ],
        vec![("Authorization", format!("Bearer {good}")), ("Authorization", "Bearer x".into())],
        // Tokens anywhere other than the Authorization header are ignored.
        vec![("Cookie", format!("token={good}"))],
        vec![("X-Auth-Token", good.clone())],
    ];
    for headers in &bad_headers {
        let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = s.request("POST", "/v1/logout", &hs, "").await;
        assert_eq!(r.status, 401, "{headers:?}");
        assert_eq!(r.header("www-authenticate").as_deref(), Some("Bearer"));
    }
    let r = s.request("POST", &format!("/v1/logout?token={good}"), &[], "").await;
    assert_eq!(r.status, 401, "token in query string");
    let r = s.request("POST", &format!("/v1/logout?access_token={good}"), &[], "").await;
    assert_eq!(r.status, 401, "token in query string");

    // The scheme is case-insensitive per RFC 9110; the token is not.
    let r =
        s.request("POST", "/v1/logout", &[("Authorization", &format!("bearer {good}"))], "").await;
    assert_eq!(r.status, 204);
}

#[tokio::test]
async fn logout_revokes_only_that_session() {
    let s = TestServer::start().await;
    let a = s.token().await;
    let b = s.token().await;
    assert_eq!(s.authed("POST", "/v1/logout", &a).await.status, 204);
    assert_eq!(s.authed("POST", "/v1/logout", &a).await.status, 401, "revoked token is dead");
    assert_eq!(s.authed("POST", "/v1/logout", &b).await.status, 204, "other session unaffected");
}

#[tokio::test]
async fn logout_all_revokes_every_session() {
    let s = TestServer::start().await;
    let tokens = [s.token().await, s.token().await, s.token().await];
    assert_eq!(s.authed("POST", "/v1/logout_all", &tokens[0]).await.status, 204);
    for t in &tokens {
        assert_eq!(s.authed("POST", "/v1/logout", t).await.status, 401);
    }
}

#[tokio::test]
async fn login_rotates_a_presented_session() {
    let s = TestServer::start().await;
    let old = s.token().await;
    let other = s.token().await;
    let auth = format!("Bearer {old}");
    let r = s.login_with(PASSWORD, &[("Authorization", &auth)]).await;
    assert_eq!(r.status, 200);
    let new = r.json()["token"].as_str().unwrap().to_owned();
    assert_ne!(new, old);
    assert_eq!(s.authed("POST", "/v1/logout", &old).await.status, 401, "old session replaced");
    assert_eq!(
        s.authed("POST", "/v1/logout", &other).await.status,
        204,
        "other devices unaffected"
    );
    assert_eq!(s.authed("POST", "/v1/logout", &new).await.status, 204);
}

#[tokio::test]
async fn a_failed_login_does_not_revoke_the_presented_session() {
    let s = TestServer::start().await;
    let t = s.token().await;
    let r =
        s.login_with("wrong password wrong", &[("Authorization", &format!("Bearer {t}"))]).await;
    assert_eq!(r.status, 401);
    assert_eq!(s.authed("POST", "/v1/logout", &t).await.status, 204);
}

#[tokio::test]
async fn session_cap_evicts_the_oldest() {
    let s = TestServer::start_with("[auth]\nmax_sessions = 2\n").await;
    let t1 = s.token().await;
    s.clock.advance_secs(1);
    let t2 = s.token().await;
    s.clock.advance_secs(1);
    let t3 = s.token().await;
    assert_eq!(s.authed("POST", "/v1/logout", &t1).await.status, 401, "oldest evicted");
    assert_eq!(s.authed("POST", "/v1/logout", &t2).await.status, 204);
    assert_eq!(s.authed("POST", "/v1/logout", &t3).await.status, 204);
}

#[tokio::test]
async fn idle_sessions_expire_and_activity_extends_them() {
    let s = TestServer::start_with(
        "[auth]\nsession_idle_timeout_secs = 300\nsession_max_lifetime_secs = 3600\n",
    )
    .await;
    let idle = s.token().await;
    let active = s.token().await;
    // Keep `active` busy; leave `idle` alone. A plain GET on /v1/ws is an
    // authenticated no-op: it passes the session check, then fails as a non-upgrade (400).
    for _ in 0..2 {
        s.clock.advance_secs(200);
        let r = s.authed("GET", "/v1/ws", &active).await;
        assert_eq!(r.status, 400, "authenticated, but not a WebSocket request");
    }
    let r = s.authed("GET", "/v1/ws", &idle).await;
    assert_eq!(r.status, 401, "idle for 400s > 300s");
    let r = s.authed("GET", "/v1/ws", &active).await;
    assert_eq!(r.status, 400, "still alive");
}

#[tokio::test]
async fn sessions_have_an_absolute_lifetime() {
    let s = TestServer::start_with(
        "[auth]\nsession_idle_timeout_secs = 300\nsession_max_lifetime_secs = 3600\n",
    )
    .await;
    let t = s.token().await;
    for _ in 0..17 {
        s.clock.advance_secs(200);
        assert_eq!(s.authed("GET", "/v1/ws", &t).await.status, 400, "alive at {}", s.clock_secs());
    }
    s.clock.advance_secs(200); // 3600s
    assert_eq!(
        s.authed("GET", "/v1/ws", &t).await.status,
        401,
        "activity can't extend past max lifetime"
    );
}

trait ClockSecs {
    fn clock_secs(&self) -> i64;
}

impl ClockSecs for TestServer {
    fn clock_secs(&self) -> i64 {
        use snowpaw_server::clock::Clock;
        (self.clock.now_ms() - common::START_MS) / 1000
    }
}

#[tokio::test]
async fn brute_force_is_throttled_and_lockout_is_not_an_oracle() {
    let s = TestServer::start_with(
        "[auth]\nlogin_free_failures = 3\nlogin_backoff_base_secs = 10\nlogin_backoff_max_secs = 60\n",
    )
    .await;
    assert_eq!(s.login("wrong password 1xx").await.status, 401);
    assert_eq!(s.login("wrong password 2xx").await.status, 401);
    assert_eq!(s.login("wrong password 3xx").await.status, 401); // starts a 10s lock

    // During the lock, right and wrong passwords get the identical response.
    let wrong = s.login("wrong password 4xx").await;
    let right = s.login(PASSWORD).await;
    assert_eq!(wrong.status, 429);
    assert_eq!(right.status, 429);
    assert_eq!(wrong.body, right.body);
    assert_eq!(wrong.header("retry-after"), right.header("retry-after"));
    assert_eq!(right.header("retry-after").as_deref(), Some("10"));

    // Locked attempts don't count as failures (they're never evaluated).
    s.clock.advance_secs(10);
    assert_eq!(s.login("wrong password 5xx").await.status, 401); // 4th failure: 20s lock
    s.clock.advance_secs(19);
    assert_eq!(s.login(PASSWORD).await.status, 429);
    s.clock.advance_secs(1);
    assert_eq!(s.login(PASSWORD).await.status, 200, "lock over, right password works");

    // Success resets the counter: the next few failures are free again.
    assert_eq!(s.login("wrong password 6xx").await.status, 401);
    assert_eq!(s.login(PASSWORD).await.status, 200);
}

#[tokio::test]
async fn backoff_is_capped_at_the_max() {
    let s = TestServer::start_with(
        "[auth]\nlogin_free_failures = 1\nlogin_backoff_base_secs = 10\nlogin_backoff_max_secs = 30\n",
    )
    .await;
    for _ in 0..5 {
        assert_eq!(s.login("wrong password wrong").await.status, 401);
        let r = s.login("wrong password wrong").await;
        assert_eq!(r.status, 429);
        let wait: i64 = r.header("retry-after").unwrap().parse().unwrap();
        assert!(wait <= 30, "{wait}");
        s.clock.advance_secs(wait);
    }
}

#[tokio::test]
async fn lockout_survives_a_restart() {
    let s =
        TestServer::start_with("[auth]\nlogin_free_failures = 1\nlogin_backoff_base_secs = 60\n")
            .await;
    assert_eq!(s.login("wrong password wrong").await.status, 401);
    assert_eq!(s.login(PASSWORD).await.status, 429);
    let s = s.restart().await;
    assert_eq!(
        s.login(PASSWORD).await.status,
        429,
        "restarting the server must not reset the lock"
    );
    s.clock.advance_secs(60);
    assert_eq!(s.login(PASSWORD).await.status, 200);
}

#[tokio::test]
async fn sessions_survive_a_restart_but_revocations_do_too() {
    let s = TestServer::start().await;
    let keep = s.token().await;
    let gone = s.token().await;
    assert_eq!(s.authed("POST", "/v1/logout", &gone).await.status, 204);
    let s = s.restart().await;
    assert_eq!(s.authed("GET", "/v1/ws", &keep).await.status, 400);
    assert_eq!(s.authed("GET", "/v1/ws", &gone).await.status, 401);
}

#[tokio::test]
async fn parallel_guesses_cannot_race_past_the_throttle() {
    let s = std::sync::Arc::new(
        TestServer::start_with("[auth]\nlogin_free_failures = 3\nlogin_backoff_base_secs = 60\n")
            .await,
    );
    let mut tasks = vec![];
    for i in 0..12 {
        let s = std::sync::Arc::clone(&s);
        tasks.push(tokio::spawn(
            async move { s.login(&format!("wrong password {i:03}")).await.status },
        ));
    }
    let mut evaluated = 0;
    for t in tasks {
        match t.await.unwrap() {
            401 => evaluated += 1,
            429 => {}
            other => panic!("unexpected status {other}"),
        }
    }
    // At most `login_free_failures` guesses can be evaluated before the lock: the
    // gate serializes checks, so concurrent requests can't all slip in.
    assert!((1..=3).contains(&evaluated), "{evaluated} guesses were evaluated");
}

#[tokio::test]
async fn set_password_ends_every_session() {
    let s = TestServer::start().await;
    let t = s.token().await;
    let cfg = TestServer::config(&s.data_dir, "");
    let clock = snowpaw_server::clock::SystemClock;
    let revoked = snowpaw_server::setup::set_password(
        &cfg,
        &snowpaw_proto::SecretString::new("a different long passphrase".into()),
        &clock,
    )
    .unwrap();
    assert_eq!(revoked, 1);
    assert_eq!(s.authed("GET", "/v1/ws", &t).await.status, 401);
    assert_eq!(s.login(PASSWORD).await.status, 401, "old password no longer works");
    assert_eq!(s.login("a different long passphrase").await.status, 200);
}

#[tokio::test]
async fn raw_tokens_never_reach_the_database() {
    let s = TestServer::start().await;
    let token = s.token().await;
    let raw_hex = &token[SESSION_TOKEN_PREFIX.len()..];
    let raw_bytes: Vec<u8> =
        (0..32).map(|i| u8::from_str_radix(&raw_hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    let mut haystack = vec![];
    for suffix in ["", "-wal", "-shm"] {
        let mut p = s.db_path().into_os_string();
        p.push(suffix);
        if let Ok(bytes) = std::fs::read(p) {
            haystack.extend(bytes);
        }
    }
    assert!(!haystack.is_empty());
    let contains = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(token.as_bytes()), "wire token found in database files");
    assert!(!contains(raw_hex.as_bytes()), "token hex found in database files");
    assert!(!contains(&raw_bytes), "raw token bytes found in database files");
    assert!(!contains(PASSWORD.as_bytes()), "password found in database files");
}

// ---- device tokens: someone guessing passwords can't lock out your devices ----

const LOCK_FAST: &str =
    "[auth]\nlogin_free_failures = 2\nlogin_backoff_base_secs = 60\nlogin_backoff_max_secs = 900\n";

fn device_of(r: &common::RawResponse) -> String {
    r.json()["device_token"].as_str().unwrap().to_owned()
}

/// Keep the shared unknown-device bucket locked, like a remote attacker would.
async fn lock_unknown_bucket(s: &TestServer) {
    for i in 0..2 {
        let r = s.login(&format!("attacker guess {i:04}")).await;
        assert!(r.status == 401 || r.status == 429);
    }
    assert_eq!(s.login(PASSWORD).await.status, 429, "unknown bucket should now be locked");
}

#[tokio::test]
async fn an_attacker_cannot_lock_out_a_known_device() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let first = s.login(PASSWORD).await;
    assert_eq!(first.status, 200);
    let mut device = device_of(&first);
    assert!(device.starts_with(snowpaw_proto::DEVICE_TOKEN_PREFIX));

    // The attacker keeps the shared bucket locked for hours: one guess per lock window.
    for _ in 0..10 {
        lock_unknown_bucket(&s).await;
        // The known device still gets in, every time.
        let r = s.login_device(PASSWORD, Some(&device)).await;
        assert_eq!(r.status, 200, "known device locked out by an attacker");
        device = device_of(&r);
        s.clock.advance_secs(900);
    }
}

#[tokio::test]
async fn device_tokens_rotate_on_every_login() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let old = device_of(&s.login(PASSWORD).await);
    let new = device_of(&s.login_device(PASSWORD, Some(&old)).await);
    assert_ne!(old, new);
    lock_unknown_bucket(&s).await;
    // The retired token is now just an unknown device.
    assert_eq!(s.login_device(PASSWORD, Some(&old)).await.status, 429);
    assert_eq!(s.login_device(PASSWORD, Some(&new)).await.status, 200);
}

#[tokio::test]
async fn bogus_device_tokens_are_treated_as_unknown() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let first = s.login(PASSWORD).await;
    let real = device_of(&first);
    let session_token = first.json()["token"].as_str().unwrap().to_owned();
    lock_unknown_bucket(&s).await;
    let forged = format!("{}{}", snowpaw_proto::DEVICE_TOKEN_PREFIX, "0".repeat(64));
    for bogus in [
        forged.as_str(),
        "spw_d_",
        "garbage",
        &real.to_uppercase(),
        &real[..real.len() - 1],
        // A session token is not a device token.
        session_token.as_str(),
    ] {
        let r = s.login_device(PASSWORD, Some(bogus)).await;
        assert_eq!(r.status, 429, "{bogus:?} escaped the shared lock");
    }
    assert_eq!(s.login_device(PASSWORD, Some(&real)).await.status, 200);
}

#[tokio::test]
async fn a_device_has_its_own_lock_and_it_is_not_an_oracle() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let device = device_of(&s.login(PASSWORD).await);
    assert_eq!(s.login_device("wrong guess number 1", Some(&device)).await.status, 401);
    assert_eq!(s.login_device("wrong guess number 2", Some(&device)).await.status, 401);
    // That device is locked now; right and wrong passwords look identical.
    let right = s.login_device(PASSWORD, Some(&device)).await;
    let wrong = s.login_device("wrong guess number 3", Some(&device)).await;
    assert_eq!((right.status, wrong.status), (429, 429));
    assert_eq!(right.body, wrong.body);
    assert_eq!(right.header("retry-after"), wrong.header("retry-after"));
    // Its failures didn't touch the shared bucket.
    assert_eq!(s.login(PASSWORD).await.status, 200);
    s.clock.advance_secs(60);
    assert_eq!(s.login_device(PASSWORD, Some(&device)).await.status, 200);
}

#[tokio::test]
async fn a_known_device_logging_in_does_not_reset_the_shared_lock() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let device = device_of(&s.login(PASSWORD).await);
    lock_unknown_bucket(&s).await;
    assert_eq!(s.login_device(PASSWORD, Some(&device)).await.status, 200);
    assert_eq!(s.login(PASSWORD).await.status, 429, "attacker must not get fresh attempts");
}

#[tokio::test]
async fn set_password_forgets_known_devices() {
    let s = TestServer::start_with(LOCK_FAST).await;
    let device = device_of(&s.login(PASSWORD).await);
    let cfg = TestServer::config(&s.data_dir, LOCK_FAST);
    let pw = "a brand new long passphrase";
    snowpaw_server::setup::set_password(
        &cfg,
        &snowpaw_proto::SecretString::new(pw.into()),
        &snowpaw_server::clock::SystemClock,
    )
    .unwrap();
    for i in 0..2 {
        assert_eq!(s.login(&format!("attacker guess {i:04}")).await.status, 401);
    }
    assert_eq!(s.login_device(pw, Some(&device)).await.status, 429, "old device forgotten");
}

#[tokio::test]
async fn device_tokens_never_reach_the_database_raw() {
    let s = TestServer::start().await;
    let device = device_of(&s.login(PASSWORD).await);
    let hex = &device[snowpaw_proto::DEVICE_TOKEN_PREFIX.len()..];
    let mut haystack = vec![];
    for suffix in ["", "-wal", "-shm"] {
        let mut p = s.db_path().into_os_string();
        p.push(suffix);
        if let Ok(bytes) = std::fs::read(p) {
            haystack.extend(bytes);
        }
    }
    let contains = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(device.as_bytes()));
    assert!(!contains(hex.as_bytes()));
}
