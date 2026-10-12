//! Startup refuses unsafe state: loose permissions, missing setup, bad config files.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use common::TestServer;
use snowpaw_proto::SecretString;
use snowpaw_server::clock::SystemClock;
use snowpaw_server::config::Config;
use snowpaw_server::server::Server;
use snowpaw_server::setup;

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn fresh() -> (tempfile::TempDir, std::path::PathBuf, Config) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    setup::init(&dir, &SystemClock).unwrap();
    let cfg = TestServer::config(&dir, "");
    (tmp, dir, cfg)
}

fn set_pw(cfg: &Config) {
    setup::set_password(cfg, &SecretString::new(common::PASSWORD.into()), &SystemClock).unwrap();
}

async fn bind_err(cfg: Config) -> String {
    Server::bind(cfg, Arc::new(SystemClock)).await.unwrap_err().to_string()
}

#[tokio::test]
async fn init_creates_private_files() {
    let (_tmp, dir, _) = fresh();
    assert_eq!(mode(&dir), 0o700);
    for f in ["server.toml", "snowpaw.db", "tls-cert.pem", "tls-key.pem"] {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
    let cfg = Config::load(&dir.join("server.toml")).unwrap();
    assert_eq!(cfg.server.data_dir, dir);
    assert!(cfg.server.listen.ip().is_loopback());
}

#[test]
fn init_refuses_an_existing_non_empty_dir() {
    let (_tmp, dir, _) = fresh();
    let err = setup::init(&dir, &SystemClock).unwrap_err().to_string();
    assert!(err.contains("not empty"), "{err}");
}

#[test]
fn init_refuses_an_existing_empty_dir_that_is_not_private() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);
    assert!(setup::init(&dir, &SystemClock).is_err());
    chmod(&dir, 0o700);
    setup::init(&dir, &SystemClock).unwrap();
}

#[tokio::test]
async fn refuses_to_start_without_a_password() {
    let (_tmp, _dir, cfg) = fresh();
    assert!(bind_err(cfg).await.contains("no password set"));
}

#[tokio::test]
async fn refuses_to_start_on_an_uninitialized_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = TestServer::config(&tmp.path().join("missing"), "");
    assert!(bind_err(cfg).await.contains("init"));
}

#[tokio::test]
async fn refuses_loose_data_dir_permissions() {
    let (_tmp, dir, cfg) = fresh();
    set_pw(&cfg);
    for m in [0o755, 0o750, 0o701, 0o777] {
        chmod(&dir, m);
        let err = bind_err(cfg.clone()).await;
        assert!(err.contains("group/other"), "{m:o}: {err}");
    }
    chmod(&dir, 0o700);
    Server::bind(cfg, Arc::new(SystemClock)).await.unwrap();
}

#[tokio::test]
async fn refuses_readable_secrets() {
    let (_tmp, dir, cfg) = fresh();
    set_pw(&cfg);
    for f in ["tls-key.pem", "snowpaw.db"] {
        chmod(&dir.join(f), 0o644);
        let err = bind_err(cfg.clone()).await;
        assert!(err.contains("group/other"), "{f}: {err}");
        chmod(&dir.join(f), 0o600);
    }
    Server::bind(cfg, Arc::new(SystemClock)).await.unwrap();
}

#[tokio::test]
async fn refuses_a_symlinked_key_or_data_dir() {
    let (tmp, dir, cfg) = fresh();
    set_pw(&cfg);
    // Key swapped for a symlink to an attacker-chosen key.
    let key = dir.join("tls-key.pem");
    let elsewhere = tmp.path().join("other-key.pem");
    std::fs::rename(&key, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &key).unwrap();
    assert!(bind_err(cfg.clone()).await.contains("symlink"));
    std::fs::remove_file(&key).unwrap();
    std::fs::rename(&elsewhere, &key).unwrap();

    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    let linked = TestServer::config(&link, "");
    assert!(bind_err(linked).await.contains("symlink"));
}

#[test]
fn refuses_a_writable_config_file() {
    let (_tmp, dir, _) = fresh();
    let path = dir.join("server.toml");
    chmod(&path, 0o664);
    assert!(Config::load(&path).is_err());
    chmod(&path, 0o646);
    assert!(Config::load(&path).is_err());
    chmod(&path, 0o644);
    Config::load(&path).unwrap();
}

#[test]
fn refuses_an_oversized_config_file() {
    let (_tmp, dir, _) = fresh();
    let path = dir.join("server.toml");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(&format!("\n#{}\n", "x".repeat(70_000)));
    std::fs::write(&path, text).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn set_password_enforces_the_policy() {
    let (_tmp, _dir, cfg) = fresh();
    for weak in ["", "short", "fourteen chars", "has a newline in it\n"] {
        let r = setup::set_password(&cfg, &SecretString::new(weak.into()), &SystemClock);
        assert!(r.is_err(), "{weak:?}");
    }
    setup::set_password(&cfg, &SecretString::new("fifteen chars!!".into()), &SystemClock).unwrap();
}

#[test]
fn the_cli_refuses_insecure_invocations() {
    let bin = env!("CARGO_BIN_EXE_snowpaw-server");
    let (_tmp, dir, _) = fresh();
    let cfg = dir.join("server.toml");
    let run = |args: &[&str]| std::process::Command::new(bin).args(args).output().unwrap();

    assert!(!run(&["run", "--config", cfg.to_str().unwrap(), "--insecure"]).status.success());
    assert!(!run(&["run"]).status.success());
    // No password set yet: run must refuse.
    let out = run(&["run", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no password set"));

    // Password via stdin; the password must not be echoed anywhere.
    let mut child = std::process::Command::new(bin)
        .args(["set-password", "--stdin", "--config", cfg.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(format!("{}\n", common::PASSWORD).as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let all = [out.stdout, out.stderr].concat();
    assert!(!String::from_utf8_lossy(&all).contains(common::PASSWORD));

    let fp = run(&["fingerprint", "--config", cfg.to_str().unwrap()]);
    assert!(fp.status.success());
    let fp = String::from_utf8_lossy(&fp.stdout).trim().to_owned();
    assert!(fp.starts_with("sha256:"));

    // The connection code names the configured address and the same fingerprint.
    let out = run(&["connection-code", "--config", cfg.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = text.lines().map(str::trim).find(|l| l.starts_with("snowpaw://")).unwrap();
    let (server, code_fp) = snowpaw_proto::setup_code::parse(line).unwrap();
    assert_eq!(code_fp, fp);
    assert!(server.starts_with("127.0.0.1:"), "{server}");
}
