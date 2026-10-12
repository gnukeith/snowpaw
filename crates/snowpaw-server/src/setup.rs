//! `init` and `set-password`.

use std::path::{Component, Path, PathBuf};

use snowpaw_proto::{SecretString, check_new_password};

use crate::clock::Clock;
use crate::config::{self, Config};
use crate::db::{self, Db};
use crate::server::preflight;
use crate::{auth, fsperm, tls};

pub const CONFIG_FILE_NAME: &str = "server.toml";

#[derive(Debug)]
pub struct SetupError(pub String);

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SetupError {}

fn fail(msg: impl Into<String>) -> SetupError {
    SetupError(msg.into())
}

#[derive(Debug)]
pub struct InitReport {
    pub config_path: PathBuf,
    pub fingerprint: String,
}

/// The code agent runtimes use: the agents-only listener if there is one, else the
/// main address.
pub fn agent_connection_code(cfg: &Config) -> Result<String, SetupError> {
    let addr = cfg.server.agent_listen.unwrap_or(cfg.server.listen);
    Ok(snowpaw_proto::setup_code::encode(&addr.to_string(), &fingerprint_of(cfg)?))
}

fn fingerprint_of(cfg: &Config) -> Result<String, SetupError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let (cert, _) = cfg.tls_paths();
    let der = CertificateDer::from_pem_file(&cert)
        .map_err(|e| fail(format!("{}: {e}", cert.display())))?;
    Ok(tls::fingerprint(&der))
}

/// The one-line code the desktop app takes instead of an address plus fingerprint.
pub fn connection_code(cfg: &Config) -> Result<String, SetupError> {
    Ok(snowpaw_proto::setup_code::encode(&cfg.server.listen.to_string(), &fingerprint_of(cfg)?))
}

/// Create a new data dir (mode 0700) with a config file, database, user principal,
/// and self-signed TLS certificate. Refuses to touch an existing non-empty directory.
pub fn init(data_dir: &Path, clock: &dyn Clock) -> Result<InitReport, SetupError> {
    let shown = data_dir.display();
    if !data_dir.is_absolute() || data_dir.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(fail(format!("{shown}: data dir must be an absolute path without '..'")));
    }
    let as_str =
        data_dir.to_str().ok_or_else(|| fail(format!("{shown}: path must be valid UTF-8")))?;
    // The path is embedded in a TOML string; keep it to characters that need no escaping.
    if as_str.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(fail(format!(
            "{shown}: path must not contain quotes, backslashes, or control characters"
        )));
    }

    match std::fs::symlink_metadata(data_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = data_dir.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| fail(format!("{}: {e}", parent.display())))?;
            }
            fsperm::create_private_dir(data_dir).map_err(|e| fail(format!("{shown}: {e}")))?;
        }
        Err(e) => return Err(fail(format!("{shown}: {e}"))),
        Ok(meta) => {
            // An existing empty dir is allowed (e.g. a pre-created container volume),
            // but it must already be private and ours; we don't chmod things we didn't create.
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(fail(format!("{shown}: exists and is not a directory")));
            }
            let empty = std::fs::read_dir(data_dir)
                .map_err(|e| fail(format!("{shown}: {e}")))?
                .next()
                .is_none();
            if !empty {
                return Err(fail(format!(
                    "{shown}: already exists and is not empty (already initialized?)"
                )));
            }
        }
    }
    let uid = preflight(data_dir).map_err(|e| fail(e.0))?;

    let config_text = render_config(as_str)?;
    let cfg = Config::parse(&config_text)
        .map_err(|e| fail(format!("generated config is invalid: {e}")))?;
    let config_path = data_dir.join(CONFIG_FILE_NAME);
    fsperm::write_new_private_file(&config_path, config_text.as_bytes())
        .map_err(|e| fail(format!("{}: {e}", config_path.display())))?;

    let db = Db::open(&cfg.db_path(), uid).map_err(|e| fail(e.to_string()))?;
    let user_id = auth::random_id().map_err(|e| fail(e.to_string()))?;
    let now = clock.now_ms();
    let note_id = auth::random_id().map_err(|e| fail(e.to_string()))?;
    db.call_blocking(|c| {
        let user = db::ensure_user(c, user_id, "You", now)?;
        db::ensure_note_to_self(c, user, note_id, now)
    })
    .map_err(|e| fail(e.to_string()))?;

    let (cert, key) = config::default_tls_paths(data_dir);
    let fingerprint = tls::generate(&cert, &key).map_err(|e| fail(e.to_string()))?;
    crate::secrets::Secrets::create(&data_dir.join("secrets.key"))
        .map_err(|e| fail(e.to_string()))?;
    Ok(InitReport { config_path, fingerprint })
}

/// The example config with `data_dir` filled in.
fn render_config(data_dir: &str) -> Result<String, SetupError> {
    let placeholder = "data_dir = \"/var/lib/snowpaw\"";
    if config::EXAMPLE_CONFIG.matches(placeholder).count() != 1 {
        return Err(fail("example config is missing the data_dir placeholder"));
    }
    Ok(config::EXAMPLE_CONFIG.replacen(placeholder, &format!("data_dir = \"{data_dir}\""), 1))
}

/// Set (or change) the password. Revokes every existing session and clears any
/// login lockout. Returns how many sessions were revoked.
pub fn set_password(
    cfg: &Config,
    password: &SecretString,
    clock: &dyn Clock,
) -> Result<usize, SetupError> {
    check_new_password(password.expose()).map_err(|e| fail(e.to_string()))?;
    let uid = preflight(&cfg.server.data_dir).map_err(|e| fail(e.0))?;
    cfg.check_owner(uid).map_err(|e| fail(e.to_string()))?;
    let db = Db::open(&cfg.db_path(), uid).map_err(|e| fail(e.to_string()))?;
    if db.call_blocking(|c| db::user_id(c)).map_err(|e| fail(e.to_string()))?.is_none() {
        return Err(fail("database has no user; run `snowpaw-server init` first"));
    }
    let phc = auth::hash_password(password).map_err(|e| fail(e.to_string()))?;
    let now = clock.now_ms();
    db.call_blocking(|c| db::set_password_hash(c, &phc, now)).map_err(|e| fail(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_config_is_valid() {
        let text = render_config("/srv/snowpaw").expect("render");
        let cfg = Config::parse(&text).expect("valid");
        assert_eq!(cfg.server.data_dir, PathBuf::from("/srv/snowpaw"));
    }

    #[test]
    fn init_rejects_unsafe_paths() {
        let clock = crate::clock::SystemClock;
        for p in ["relative", "/tmp/../etc/x", "/tmp/a\"b", "/tmp/a\\b", "/tmp/a\nb"] {
            assert!(init(Path::new(p), &clock).is_err(), "{p:?}");
        }
    }
}
