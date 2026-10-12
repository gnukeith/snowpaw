//! The runtime's configuration: where the server is (a connection code, which carries
//! the certificate fingerprint to pin) and where this agent's token is kept.
//!
//! The token lives in its own file, never in the config, the command line or the
//! environment (all of which leak more easily: shell history, `ps`, `/proc/*/environ`,
//! container inspect output). The file must be private to the user running the
//! runtime. In Podman, mount it as a secret:
//! `--secret snowpaw-agent-token,target=/run/secrets/token,uid=<uid>,mode=0400`.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use snowpaw_proto::agent::AGENT_TOKEN_PREFIX;
use snowpaw_proto::{SecretString, setup_code};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: String,
    token_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// `host:port`
    pub server: String,
    pub pin: [u8; 32],
    pub token_file: PathBuf,
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

fn parse_pin(fp: &str) -> Result<[u8; 32], ConfigError> {
    let hex = fp.strip_prefix("sha256:").ok_or_else(|| err("bad fingerprint"))?;
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| err("bad fingerprint"))?;
        *out.get_mut(i).ok_or_else(|| err("bad fingerprint"))? =
            u8::from_str_radix(s, 16).map_err(|_| err("bad fingerprint"))?;
    }
    Ok(out)
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| err(e.to_string()))?;
        let (server, fingerprint) =
            setup_code::parse(&raw.server).map_err(|e| err(format!("server: {e}")))?;
        if !raw.token_file.is_absolute() {
            return Err(err("token_file must be an absolute path"));
        }
        Ok(Self { server, pin: parse_pin(&fingerprint)?, token_file: raw.token_file })
    }

    /// Read the config file: a regular file, not writable by group/other.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let shown = path.display();
        let file = std::fs::File::open(path).map_err(|e| err(format!("{shown}: {e}")))?;
        let meta = file.metadata().map_err(|e| err(format!("{shown}: {e}")))?;
        if !meta.is_file() {
            return Err(err(format!("{shown}: not a regular file")));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(err(format!("{shown}: must not be writable by group/other")));
        }
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| err(format!("{shown}: {e}")))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(err(format!("{shown}: too large")));
        }
        Self::parse(&text).map_err(|e| err(format!("{shown}: {e}")))
    }

    /// `host` and `port` to connect to.
    pub fn host_port(&self) -> (String, u16) {
        let (host, port) = match self.server.strip_prefix('[') {
            Some(v6) => v6.split_once("]:").unwrap_or((v6, "0")),
            None => self.server.rsplit_once(':').unwrap_or((&self.server, "0")),
        };
        (host.to_owned(), port.parse().unwrap_or(0))
    }
}

/// Read the token: a private file (no group/other access) owned by us, holding one
/// well-formed agent token.
pub fn load_token(path: &Path, euid: u32) -> Result<SecretString, ConfigError> {
    let shown = path.display();
    let file = std::fs::File::open(path).map_err(|e| err(format!("{shown}: {e}")))?;
    let meta = file.metadata().map_err(|e| err(format!("{shown}: {e}")))?;
    if !meta.is_file() {
        return Err(err(format!("{shown}: not a regular file")));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(err(format!(
            "{shown}: has mode {:04o}; it must be readable by this user only (chmod 600)",
            meta.mode() & 0o7777
        )));
    }
    if meta.uid() != euid {
        return Err(err(format!("{shown}: must be owned by uid {euid}")));
    }
    let mut text = Zeroizing::new(String::new());
    file.take(256).read_to_string(&mut text).map_err(|e| err(format!("{shown}: {e}")))?;
    let token = text.trim();
    let well_formed = token.strip_prefix(AGENT_TOKEN_PREFIX).is_some_and(|h| {
        h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    if !well_formed {
        return Err(err(format!("{shown}: doesn't hold an agent token (spw_a_...)")));
    }
    Ok(SecretString::new(token.to_owned()))
}

/// Our effective uid, learned from a file we create (no unsafe, no libc).
pub fn effective_uid(dir: &Path) -> std::io::Result<u32> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
    let probe = dir.join(format!(".snowpaw-agent-uid-{}", u64::from_le_bytes(nonce)));
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const CODE: &str = "snowpaw://127.0.0.1:7443#sha256:3f9a1c0000000000000000000000000000000000000000000000000000007be2";

    #[test]
    fn config() {
        let c = Config::parse(&format!("server = \"{CODE}\"\ntoken_file = \"/run/secrets/t\"\n"))
            .expect("ok");
        assert_eq!(c.host_port(), ("127.0.0.1".into(), 7443));
        assert_eq!(c.pin[0], 0x3f);
        for bad in [
            "server = \"127.0.0.1:7443\"\ntoken_file = \"/t\"\n".to_owned(),
            format!("server = \"{CODE}\"\ntoken_file = \"relative\"\n"),
            format!("server = \"{CODE}\"\ntoken_file = \"/t\"\ntoken = \"spw_a_x\"\n"),
        ] {
            assert!(Config::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_file_rules() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = effective_uid(tmp.path()).expect("uid");
        let path = tmp.path().join("token");
        let token = format!("spw_a_{}", "ab".repeat(32));
        std::fs::write(&path, format!("{token}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(load_token(&path, uid).expect("ok").expose(), token);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        assert!(load_token(&path, uid).is_err(), "group-readable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).expect("chmod");
        assert!(load_token(&path, uid).is_ok());
        assert!(load_token(&path, uid + 1).is_err(), "someone else's file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::write(&path, "spw_s_session_token").expect("write");
        assert!(load_token(&path, uid).is_err(), "not an agent token");
    }
}
