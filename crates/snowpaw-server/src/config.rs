//! Server configuration: strict parsing, secure defaults, bounded values.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// The documented example config. `init` writes this with `data_dir` filled in.
pub const EXAMPLE_CONFIG: &str = include_str!("../../../config/server.example.toml");

/// Config files are small; refuse to read anything bigger.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

const DAY: u64 = 86_400;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub log: LogSection,
    #[serde(default)]
    pub agents: AgentsSection,
    #[serde(default)]
    pub secrets: SecretsSection,
    /// Owner uid of the file this was loaded from (None when parsed from a string).
    #[serde(skip)]
    source_owner: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// A second address that serves only agent runtimes (`/v1/agent/ws`): no login,
    /// no user API. Bind it on the agents' isolated network.
    #[serde(default)]
    pub agent_listen: Option<SocketAddr>,
    pub data_dir: PathBuf,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7443))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthSection {
    pub session_idle_timeout_secs: u64,
    pub session_max_lifetime_secs: u64,
    pub max_sessions: u32,
    pub login_free_failures: u32,
    pub login_backoff_base_secs: u64,
    pub login_backoff_max_secs: u64,
    pub max_login_devices: u32,
    pub login_device_lifetime_secs: u64,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            session_idle_timeout_secs: 7 * DAY,
            session_max_lifetime_secs: 30 * DAY,
            max_sessions: 8,
            login_free_failures: 5,
            login_backoff_base_secs: 2,
            login_backoff_max_secs: 900,
            max_login_devices: 16,
            login_device_lifetime_secs: 365 * DAY,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub tls_handshake_timeout_secs: u64,
    pub http_header_timeout_secs: u64,
    pub http_body_timeout_secs: u64,
    pub max_http_body_bytes: usize,
    pub max_ws_message_bytes: usize,
    pub max_message_bytes: usize,
    pub ws_messages_per_sec: u32,
    pub ws_burst: u32,
    pub ws_idle_timeout_secs: u64,
    pub session_recheck_secs: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_connections_per_ip: 32,
            tls_handshake_timeout_secs: 5,
            http_header_timeout_secs: 10,
            http_body_timeout_secs: 10,
            max_http_body_bytes: 16 * 1024,
            max_ws_message_bytes: 64 * 1024,
            max_message_bytes: 16 * 1024,
            ws_messages_per_sec: 20,
            ws_burst: 40,
            ws_idle_timeout_secs: 60,
            session_recheck_secs: 30,
        }
    }
}

/// Limits on agents. All enforced by the server, whatever a runtime or model does.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsSection {
    /// Largest WebSocket message to or from an agent runtime (inference requests
    /// carry the conversation).
    pub max_ws_message_bytes: usize,
    /// Longest agent-to-agent back-and-forth started by one message.
    pub max_depth: u32,
    /// Messages one agent may post per minute, across all chats.
    pub messages_per_minute: u32,
    /// Messages one agent may post per hour in one conversation with another agent.
    pub link_messages_per_hour: u32,
    /// Model calls one agent may make per minute.
    pub inference_per_minute: u32,
    /// A model call is abandoned after this long.
    pub inference_timeout_secs: u64,
    /// Largest model API response accepted.
    pub max_inference_response_bytes: usize,
    /// URL fetches (for plugins) one agent may make per minute.
    pub fetches_per_minute: u32,
    /// A job run that hasn't finished after this long is given up on (and retried).
    pub job_run_timeout_secs: u64,
}

impl Default for AgentsSection {
    fn default() -> Self {
        Self {
            max_ws_message_bytes: 2 * 1024 * 1024,
            max_depth: 6,
            messages_per_minute: 12,
            link_messages_per_hour: 60,
            inference_per_minute: 10,
            inference_timeout_secs: 180,
            max_inference_response_bytes: 4 * 1024 * 1024,
            fetches_per_minute: 30,
            job_run_timeout_secs: 900,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecretsSection {
    /// The 32-byte key that seals secrets at rest. Default: `<data_dir>/secrets.key`
    /// (created if missing). Point it elsewhere (e.g. a systemd credential) to keep
    /// the key off the data volume; it must then already exist.
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogSection {
    pub level: LogLevel,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Config {
    /// Read, parse, and validate a config file.
    ///
    /// The config decides where data lives and what we bind to, so it must not be
    /// writable by group/other, and (checked later by `check_owner`, once we know our
    /// uid) must be owned by the server's user or root. Symlinks are followed (packagers
    /// often link configs); every check is made on the opened file handle, so the file
    /// can't be swapped between the check and the read.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let shown = path.display();
        let file = std::fs::File::open(path).map_err(|e| err(format!("{shown}: {e}")))?;
        let meta = file.metadata().map_err(|e| err(format!("{shown}: {e}")))?;
        if !meta.is_file() {
            return Err(err(format!("{shown}: is not a regular file")));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(err(format!(
                "{shown}: has mode {:04o}; must not be writable by group/other (chmod go-w)",
                meta.mode() & 0o7777
            )));
        }
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| err(format!("{shown}: {e}")))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(err(format!("{shown}: larger than {MAX_CONFIG_BYTES} bytes")));
        }
        let mut cfg = Self::parse(&text).map_err(|e| err(format!("{shown}: {e}")))?;
        cfg.source_owner = Some(meta.uid());
        Ok(cfg)
    }

    /// The config file must be owned by the user running the server, or by root.
    pub fn check_owner(&self, euid: u32) -> Result<(), ConfigError> {
        match self.source_owner {
            Some(owner) if owner != euid && owner != 0 => Err(err(format!(
                "config file is owned by uid {owner}; it must be owned by uid {euid} or root"
            ))),
            _ => Ok(()),
        }
    }

    /// Parse and validate config text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| err(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_listen(self.server.listen, self.server.allow_non_loopback)?;
        if let Some(agent) = self.server.agent_listen {
            validate_listen(agent, self.server.allow_non_loopback)?;
            if agent == self.server.listen && agent.port() != 0 {
                return Err(err("server.agent_listen must differ from server.listen"));
            }
        }
        validate_abs_path("server.data_dir", &self.server.data_dir)?;
        match (&self.tls.cert_file, &self.tls.key_file) {
            (None, None) => {}
            (Some(c), Some(k)) => {
                validate_abs_path("tls.cert_file", c)?;
                validate_abs_path("tls.key_file", k)?;
            }
            _ => return Err(err("tls.cert_file and tls.key_file must be set together")),
        }

        let a = &self.auth;
        range("auth.session_idle_timeout_secs", a.session_idle_timeout_secs, 300, 90 * DAY)?;
        range("auth.session_max_lifetime_secs", a.session_max_lifetime_secs, 3600, 365 * DAY)?;
        if a.session_max_lifetime_secs < a.session_idle_timeout_secs {
            return Err(err(
                "auth.session_max_lifetime_secs must be >= auth.session_idle_timeout_secs",
            ));
        }
        range("auth.max_sessions", a.max_sessions.into(), 1, 64)?;
        range("auth.login_free_failures", a.login_free_failures.into(), 1, 20)?;
        range("auth.login_backoff_base_secs", a.login_backoff_base_secs, 1, 60)?;
        range(
            "auth.login_backoff_max_secs",
            a.login_backoff_max_secs,
            a.login_backoff_base_secs,
            DAY,
        )?;
        range("auth.max_login_devices", a.max_login_devices.into(), 1, 64)?;
        range("auth.login_device_lifetime_secs", a.login_device_lifetime_secs, DAY, 2 * 365 * DAY)?;

        let l = &self.limits;
        range("limits.max_connections", l.max_connections.into(), 1, 4096)?;
        range(
            "limits.max_connections_per_ip",
            l.max_connections_per_ip.into(),
            1,
            l.max_connections.into(),
        )?;
        range("limits.tls_handshake_timeout_secs", l.tls_handshake_timeout_secs, 1, 60)?;
        range("limits.http_header_timeout_secs", l.http_header_timeout_secs, 1, 60)?;
        range("limits.http_body_timeout_secs", l.http_body_timeout_secs, 1, 60)?;
        range("limits.max_http_body_bytes", l.max_http_body_bytes as u64, 1024, 1 << 20)?;
        range("limits.max_ws_message_bytes", l.max_ws_message_bytes as u64, 1024, 1 << 20)?;
        range("limits.ws_messages_per_sec", l.ws_messages_per_sec.into(), 1, 1000)?;
        range("limits.max_message_bytes", l.max_message_bytes as u64, 1, 64 * 1024)?;
        // JSON escaping can double the size of text, plus the frame envelope.
        if l.max_message_bytes * 2 + 512 > l.max_ws_message_bytes {
            return Err(err(
                "limits.max_message_bytes is too large for limits.max_ws_message_bytes \
                 (need max_message_bytes * 2 + 512 <= max_ws_message_bytes)",
            ));
        }
        range("limits.ws_burst", l.ws_burst.into(), 1, 10_000)?;
        range("limits.ws_idle_timeout_secs", l.ws_idle_timeout_secs, 10, 3600)?;
        range("limits.session_recheck_secs", l.session_recheck_secs, 1, 300)?;

        let g = &self.agents;
        // The floor is the largest rule-following inference request, so a runtime
        // that follows the size rules can never build a frame the socket refuses.
        let infer_floor = snowpaw_proto::agent::infer_frame_bound() as u64;
        range("agents.max_ws_message_bytes", g.max_ws_message_bytes as u64, infer_floor, 8 << 20)?;
        range("agents.max_depth", g.max_depth.into(), 1, 32)?;
        range("agents.messages_per_minute", g.messages_per_minute.into(), 1, 600)?;
        range("agents.link_messages_per_hour", g.link_messages_per_hour.into(), 1, 3600)?;
        range("agents.inference_per_minute", g.inference_per_minute.into(), 1, 600)?;
        range("agents.inference_timeout_secs", g.inference_timeout_secs, 10, 1800)?;
        range(
            "agents.max_inference_response_bytes",
            g.max_inference_response_bytes as u64,
            64 * 1024,
            32 << 20,
        )?;
        range("agents.fetches_per_minute", g.fetches_per_minute.into(), 1, 600)?;
        range("agents.job_run_timeout_secs", g.job_run_timeout_secs, 60, 86_400)?;
        if let Some(k) = &self.secrets.key_file {
            validate_abs_path("secrets.key_file", k)?;
        }
        Ok(())
    }

    /// The secrets key file, and whether it may be created if missing (only the default).
    pub fn secrets_key_path(&self) -> (PathBuf, bool) {
        match &self.secrets.key_file {
            Some(p) => (p.clone(), false),
            None => (self.server.data_dir.join("secrets.key"), true),
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.server.data_dir.join("snowpaw.db")
    }

    /// Certificate and key paths, defaulting to the generated pair in data_dir.
    pub fn tls_paths(&self) -> (PathBuf, PathBuf) {
        match (&self.tls.cert_file, &self.tls.key_file) {
            (Some(c), Some(k)) => (c.clone(), k.clone()),
            _ => default_tls_paths(&self.server.data_dir),
        }
    }
}

pub fn default_tls_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (data_dir.join("tls-cert.pem"), data_dir.join("tls-key.pem"))
}

fn range(name: &str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(err(format!("{name} = {value} is out of range ({min} ..= {max})")))
    }
}

fn validate_abs_path(name: &str, path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(err(format!("{name} must be an absolute path")));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(err(format!("{name} must not contain '..' components")));
    }
    Ok(())
}

fn validate_listen(addr: SocketAddr, allow_non_loopback: bool) -> Result<(), ConfigError> {
    // Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as the IPv4 address it maps to.
    let ip = addr.ip().to_canonical();
    if ip.is_unspecified() {
        return Err(err(
            "server.listen must not be 0.0.0.0 or :: (all interfaces); bind one specific address",
        ));
    }
    if ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]) {
        return Err(err("server.listen must be a unicast address"));
    }
    if !ip.is_loopback() && !allow_non_loopback {
        return Err(err(
            "server.listen is not a loopback address; set server.allow_non_loopback = true \
             only for a VPN or isolated-network address (never the internet)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_server(server: &str) -> String {
        format!("[server]\n{server}\n")
    }

    #[test]
    fn example_config_is_valid_and_matches_defaults() {
        let cfg = Config::parse(EXAMPLE_CONFIG).expect("example config parses");
        let d = Config::parse(&with_server(r#"data_dir = "/var/lib/snowpaw""#)).expect("minimal");
        assert_eq!(cfg.server.listen, d.server.listen);
        assert_eq!(cfg.server.allow_non_loopback, d.server.allow_non_loopback);
        assert_eq!(format!("{:?}", cfg.auth), format!("{:?}", d.auth));
        assert_eq!(format!("{:?}", cfg.limits), format!("{:?}", d.limits));
        assert_eq!(cfg.log.level, d.log.level);
        assert!(cfg.tls.cert_file.is_none());
    }

    #[test]
    fn config_owner_must_be_us_or_root() {
        let mut cfg = Config::parse(&with_server(r#"data_dir = "/x""#)).expect("valid");
        assert!(cfg.check_owner(1000).is_ok(), "parsed from a string: nothing to check");
        cfg.source_owner = Some(1000);
        assert!(cfg.check_owner(1000).is_ok());
        cfg.source_owner = Some(0);
        assert!(cfg.check_owner(1000).is_ok(), "root-owned packaged config");
        cfg.source_owner = Some(1001);
        assert!(cfg.check_owner(1000).is_err(), "another user's config");
    }

    #[test]
    fn default_listen_is_loopback() {
        let cfg = Config::parse(&with_server(r#"data_dir = "/x""#)).expect("valid");
        assert!(cfg.server.listen.ip().is_loopback());
        assert!(!cfg.server.allow_non_loopback);
    }

    #[test]
    fn rejects_unknown_keys_anywhere() {
        for text in [
            "[server]\ndata_dir = \"/x\"\nlisten_addr = \"127.0.0.1:1\"\n",
            "[server]\ndata_dir = \"/x\"\n[tls]\nenabled = false\n",
            "[server]\ndata_dir = \"/x\"\n[auth]\nrequire_password = false\n",
            "[server]\ndata_dir = \"/x\"\n[limits]\nmax_conections = 5\n",
            "[server]\ndata_dir = \"/x\"\n[debug]\ninsecure = true\n",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_wildcard_and_non_loopback_listen() {
        for listen in ["0.0.0.0:7443", "[::]:7443", "[::ffff:0.0.0.0]:7443"] {
            let text = with_server(&format!(
                "listen = \"{listen}\"\nallow_non_loopback = true\ndata_dir = \"/x\""
            ));
            assert!(Config::parse(&text).is_err(), "{listen} must be rejected even with opt-in");
        }
        for listen in
            ["192.168.1.10:7443", "[fd00::1]:7443", "100.64.0.1:7443", "[::ffff:10.0.0.1]:7443"]
        {
            let text = with_server(&format!("listen = \"{listen}\"\ndata_dir = \"/x\""));
            assert!(Config::parse(&text).is_err(), "{listen} needs opt-in");
            let text = with_server(&format!(
                "listen = \"{listen}\"\nallow_non_loopback = true\ndata_dir = \"/x\""
            ));
            assert!(Config::parse(&text).is_ok(), "{listen} with opt-in");
        }
        for listen in ["224.0.0.1:7443", "255.255.255.255:7443"] {
            let text = with_server(&format!(
                "listen = \"{listen}\"\nallow_non_loopback = true\ndata_dir = \"/x\""
            ));
            assert!(Config::parse(&text).is_err(), "{listen}");
        }
        let ok = with_server("listen = \"[::1]:7443\"\ndata_dir = \"/x\"");
        assert!(Config::parse(&ok).is_ok());
    }

    #[test]
    fn rejects_bad_paths() {
        for dir in ["relative/dir", "./x", "/var/lib/../etc", ""] {
            let text = with_server(&format!("data_dir = \"{dir}\""));
            assert!(Config::parse(&text).is_err(), "{dir}");
        }
        let half_tls = "[server]\ndata_dir = \"/x\"\n[tls]\ncert_file = \"/c.pem\"\n";
        assert!(Config::parse(half_tls).is_err());
        let rel_tls =
            "[server]\ndata_dir = \"/x\"\n[tls]\ncert_file = \"c.pem\"\nkey_file = \"/k.pem\"\n";
        assert!(Config::parse(rel_tls).is_err());
    }

    #[test]
    fn rejects_out_of_range_limits() {
        for (section, kv) in [
            ("auth", "session_idle_timeout_secs = 0"),
            ("auth", "session_idle_timeout_secs = 99999999"),
            ("auth", "session_max_lifetime_secs = 3600\nsession_idle_timeout_secs = 7200"),
            ("auth", "max_sessions = 0"),
            ("auth", "max_sessions = 65"),
            ("auth", "login_free_failures = 0"),
            ("auth", "login_free_failures = 1000"),
            ("auth", "login_backoff_max_secs = 1\nlogin_backoff_base_secs = 2"),
            ("limits", "max_connections = 0"),
            ("limits", "max_connections = 4\nmax_connections_per_ip = 5"),
            ("limits", "max_connections_per_ip = 0"),
            ("limits", "max_message_bytes = 0"),
            ("limits", "max_message_bytes = 70000"),
            ("limits", "max_message_bytes = 40000"),
            ("auth", "max_login_devices = 0"),
            ("auth", "login_device_lifetime_secs = 60"),
            ("limits", "tls_handshake_timeout_secs = 0"),
            ("limits", "tls_handshake_timeout_secs = 3600"),
            ("limits", "max_http_body_bytes = 104857600"),
            ("limits", "max_ws_message_bytes = 10"),
            ("limits", "ws_messages_per_sec = 0"),
            ("limits", "ws_idle_timeout_secs = 1"),
            ("limits", "max_connections = -1"),
            ("log", "level = \"trace\""),
            ("agents", "max_ws_message_bytes = 262144"),
        ] {
            let text = format!("[server]\ndata_dir = \"/x\"\n[{section}]\n{kv}\n");
            assert!(Config::parse(&text).is_err(), "[{section}] {kv}");
        }
    }

    #[test]
    fn agent_socket_cap_covers_a_maximal_inference_request() {
        // The floor is derived from the protocol's size rules, so it can't drift.
        let floor = snowpaw_proto::agent::infer_frame_bound() as u64;
        let ok = format!("[server]\ndata_dir = \"/x\"\n[agents]\nmax_ws_message_bytes = {floor}\n");
        assert!(Config::parse(&ok).is_ok(), "the floor itself must parse");
        let under = format!(
            "[server]\ndata_dir = \"/x\"\n[agents]\nmax_ws_message_bytes = {}\n",
            floor - 1
        );
        assert!(Config::parse(&under).is_err(), "anything smaller is rejected");
    }

    #[test]
    fn rejects_duplicate_keys_and_wrong_types() {
        assert!(Config::parse("[server]\ndata_dir = \"/x\"\ndata_dir = \"/y\"\n").is_err());
        assert!(
            Config::parse("[server]\ndata_dir = \"/x\"\nallow_non_loopback = \"yes\"\n").is_err()
        );
        assert!(
            Config::parse("[server]\ndata_dir = \"/x\"\nlisten = \"localhost:7443\"\n").is_err()
        );
        assert!(Config::parse("").is_err(), "data_dir is required");
    }
}
