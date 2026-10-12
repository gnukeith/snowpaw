//! Startup checks and the running server.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::api::{self, AppState};
use crate::clock::Clock;
use crate::config::Config;
use crate::db::{self, Db};
use crate::secrets::Secrets;
use crate::{fsperm, listener, tls};

#[derive(Debug)]
pub struct StartError(pub String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StartError {}

fn fail(msg: impl Into<String>) -> StartError {
    StartError(msg.into())
}

/// Refuse to run as root. Inside a rootless Podman container, run as a non-root
/// USER too: root in the container is still root over the data volume.
pub fn refuse_root(uid: u32) -> Result<(), StartError> {
    if uid == 0 {
        return Err(fail("refusing to run as root; run snowpaw-server as an unprivileged user"));
    }
    Ok(())
}

/// Check the data dir is a real, private directory owned by us, and that we're not
/// root. Returns our effective uid.
pub fn preflight(data_dir: &Path) -> Result<u32, StartError> {
    let meta = std::fs::symlink_metadata(data_dir)
        .map_err(|e| fail(format!("data dir {}: {e} (did you run `init`?)", data_dir.display())))?;
    if meta.file_type().is_symlink() {
        return Err(fail(format!("data dir {} is a symlink (refused)", data_dir.display())));
    }
    let uid = fsperm::effective_uid(data_dir)
        .map_err(|e| fail(format!("data dir {}: {e}", data_dir.display())))?;
    refuse_root(uid)?;
    fsperm::check_private_dir(data_dir, uid)
        .map_err(|e| fail(format!("data dir {} {e}", data_dir.display())))?;
    Ok(uid)
}

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    /// `server.agent_listen`: agent runtimes only.
    agent_listener: Option<TcpListener>,
    tls: tls::TlsMaterial,
    state: Arc<AppState>,
}

impl Server {
    /// Run every startup check, open the database, load TLS, and bind. Nothing is
    /// served until `run`.
    pub async fn bind(cfg: Config, clock: Arc<dyn Clock>) -> Result<Self, StartError> {
        let uid = preflight(&cfg.server.data_dir)?;
        cfg.check_owner(uid).map_err(|e| fail(e.to_string()))?;
        let db = Db::open(&cfg.db_path(), uid)
            .map_err(|e| fail(format!("{}: {e}", cfg.db_path().display())))?;
        let (user_id, has_password) = db
            .call(|c| Ok((db::user_id(c)?, db::password_hash(c)?.is_some())))
            .await
            .map_err(|e| fail(e.to_string()))?;
        let user_id =
            user_id.ok_or_else(|| fail("database has no user; run `snowpaw-server init` first"))?;
        if !has_password {
            return Err(fail(
                "no password set; run `snowpaw-server set-password --config <FILE>` first",
            ));
        }
        let (cert, key) = cfg.tls_paths();
        let tls = tls::load(&cert, &key, uid).map_err(|e| fail(e.to_string()))?;
        let (key_path, may_create) = cfg.secrets_key_path();
        if may_create && std::fs::symlink_metadata(&key_path).is_err() {
            // Data dirs from before secrets existed get a key now.
            Secrets::create(&key_path).map_err(|e| fail(e.to_string()))?;
        }
        let secrets = Secrets::load(&key_path, uid).map_err(|e| fail(e.to_string()))?;
        // Databases from before Note to Self existed get one now.
        let note_id = crate::auth::random_id().map_err(|e| fail(e.to_string()))?;
        let now = clock.now_ms();
        db.call(move |c| db::ensure_note_to_self(c, user_id, note_id, now))
            .await
            .map_err(|e| fail(e.to_string()))?;
        let listener = TcpListener::bind(cfg.server.listen)
            .await
            .map_err(|e| fail(format!("binding {}: {e}", cfg.server.listen)))?;
        let agent_listener = match cfg.server.agent_listen {
            Some(addr) => Some(
                TcpListener::bind(addr).await.map_err(|e| fail(format!("binding {addr}: {e}")))?,
            ),
            None => None,
        };
        // Where runtimes connect: the agents-only listener if there is one.
        let agent_addr = match &agent_listener {
            Some(l) => l.local_addr(),
            None => listener.local_addr(),
        }
        .map_err(|e| fail(e.to_string()))?;
        let agent_code =
            snowpaw_proto::setup_code::encode(&agent_addr.to_string(), &tls.fingerprint);
        let state = Arc::new(AppState::new(db, Arc::new(cfg), clock, user_id, secrets, agent_code));
        Ok(Self { listener, agent_listener, tls, state })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The agents-only listener's address, if configured.
    pub fn local_agent_addr(&self) -> Option<std::io::Result<SocketAddr>> {
        self.agent_listener.as_ref().map(TcpListener::local_addr)
    }

    /// The SHA-256 fingerprint clients must pin.
    pub fn fingerprint(&self) -> &str {
        &self.tls.fingerprint
    }

    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let limits = self.state.cfg.limits.clone();
        let app = api::router(Arc::clone(&self.state));
        spawn_maintenance(Arc::clone(&self.state));
        crate::jobs::spawn_scheduler(Arc::clone(&self.state));
        let Some(agent_listener) = self.agent_listener else {
            listener::serve(self.listener, Arc::clone(&self.tls.config), app, limits, shutdown)
                .await;
            return;
        };
        // Two listeners, one shutdown signal.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|s| *s).await;
        };
        let agents = listener::serve(
            agent_listener,
            Arc::clone(&self.tls.config),
            api::agent_router(Arc::clone(&self.state)),
            limits.clone(),
            stopped(stop_rx.clone()),
        );
        let users = listener::serve(
            self.listener,
            Arc::clone(&self.tls.config),
            app,
            limits,
            stopped(stop_rx),
        );
        let signal = async move {
            shutdown.await;
            let _ = stop_tx.send(true);
        };
        tokio::join!(users, agents, signal);
    }
}

/// Housekeeping while the server runs: model-usage rows older than the rolling
/// budget window are worthless and would otherwise grow without bound (a dead model
/// endpoint plus a determined runtime can add rows at the rate limit forever).
fn spawn_maintenance(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let keep_from = st.clock.now_ms().saturating_sub(2 * 86_400_000);
            if let Err(e) = st.db.call(move |c| db::prune_usage(c, keep_from)).await {
                tracing::warn!(error = %e, "pruning model usage failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_refused() {
        assert!(refuse_root(0).is_err());
        assert!(refuse_root(1000).is_ok());
    }
}
