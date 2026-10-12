//! SQLite storage: the single source of truth.
//!
//! Integrity rules are enforced in the schema itself, not just in Rust, so a bug in a
//! handler can't silently corrupt the log:
//! - `STRICT` tables (no type coercion) and CHECK constraints on every ID and size.
//! - Messages are append-only: triggers abort any UPDATE or DELETE.
//! - A message's sender (and recipient, if any) must be a member of its chat, enforced
//!   by a foreign key into `chat_members`.
//! - Session tokens are stored only as SHA-256 hashes.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use snowpaw_proto::Id;
use snowpaw_proto::agent::{AgentLink, AuditEntry, ModelSettings};
use snowpaw_proto::jobs::{
    JobRunView, JobSchedule, JobState, JobView, MAX_ATTEMPTS, RunOutcome, next_slot,
};
use snowpaw_proto::profile::BlobHash;
use snowpaw_proto::ws::{ChatKind, Content, Member, MessageView, PrincipalKind};

use crate::fsperm;

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Perm(fsperm::PermError),
    /// The database was written by a newer snowpaw; refusing to touch it.
    TooNew {
        found: i64,
        supported: i64,
    },
    Corrupt(&'static str),
    TaskFailed,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "database error: {e}"),
            Self::Io(e) => write!(f, "database I/O error: {e}"),
            Self::Perm(e) => write!(f, "database file {e}"),
            Self::TooNew { found, supported } => write!(
                f,
                "database schema version {found} is newer than this server supports ({supported}); \
                 upgrade snowpaw-server"
            ),
            Self::Corrupt(what) => write!(f, "database integrity problem: {what}"),
            Self::TaskFailed => f.write_str("database task failed"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

const ID_CHECK: &str = "length({c}) = 32 AND {c} NOT GLOB '*[^0-9a-f]*'";

fn id_check(col: &str) -> String {
    ID_CHECK.replace("{c}", col)
}

/// Schema migrations, applied in order and recorded in `PRAGMA user_version`.
///
/// Migration 1 is in use by existing data dirs: NEVER edit a published migration.
/// Every change is a new entry appended to this list.
fn migrations() -> Vec<String> {
    let v1 = format!(
        r#"
CREATE TABLE principals (
    id            TEXT PRIMARY KEY NOT NULL CHECK ({principal_id}),
    kind          TEXT NOT NULL CHECK (kind IN ('user', 'agent')),
    display_name  TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    created_at_ms INTEGER NOT NULL
) STRICT;
-- Single-user: at most one 'user' principal can ever exist.
CREATE UNIQUE INDEX principals_one_user ON principals(kind) WHERE kind = 'user';

CREATE TABLE user_password (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    phc           TEXT NOT NULL CHECK (phc LIKE '$argon2id$%' AND length(phc) <= 512),
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    token_hash      BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
    principal_id    TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at_ms   INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_by_principal ON sessions(principal_id, created_at_ms);

CREATE TABLE login_throttle (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
    locked_until_ms      INTEGER NOT NULL
) STRICT;
INSERT INTO login_throttle (id, consecutive_failures, locked_until_ms) VALUES (1, 0, 0);

-- Devices that have logged in before ("device cookies"), each with its own login
-- throttle so an attacker locking the shared bucket can't lock out known devices.
CREATE TABLE login_devices (
    token_hash           BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
    created_at_ms        INTEGER NOT NULL,
    last_used_at_ms      INTEGER NOT NULL,
    expires_at_ms        INTEGER NOT NULL,
    consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
    locked_until_ms      INTEGER NOT NULL
) STRICT;

CREATE TABLE chats (
    id            TEXT PRIMARY KEY NOT NULL CHECK ({chat_id}),
    kind          TEXT NOT NULL CHECK (kind IN ('note_to_self', 'direct', 'agent_to_agent')),
    created_at_ms INTEGER NOT NULL
) STRICT;
-- Single user: one Note to Self.
CREATE UNIQUE INDEX chats_one_note_to_self ON chats(kind) WHERE kind = 'note_to_self';

CREATE TABLE chat_members (
    chat_id      TEXT NOT NULL REFERENCES chats(id),
    principal_id TEXT NOT NULL REFERENCES principals(id),
    PRIMARY KEY (chat_id, principal_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE messages (
    -- Server-assigned, strictly increasing; clients sync with "everything after seq N".
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    id            TEXT NOT NULL UNIQUE CHECK ({message_id}),
    chat_id       TEXT NOT NULL,
    thread_id     TEXT CHECK (thread_id IS NULL OR ({thread_id})),
    sender_id     TEXT NOT NULL,
    recipient_id  TEXT,
    -- Client-chosen idempotency key: a retried send doesn't duplicate the message.
    client_msg_id TEXT NOT NULL CHECK ({client_msg_id}),
    -- Markdown text, or canonical JSON for structured kinds.
    content_kind  TEXT NOT NULL CHECK (content_kind IN ('markdown', 'quiz', 'quiz_answers')),
    body          TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) BETWEEN 1 AND 65536),
    -- Server-assigned; client timestamps are never trusted.
    created_at_ms INTEGER NOT NULL,
    UNIQUE (sender_id, client_msg_id),
    FOREIGN KEY (chat_id, sender_id) REFERENCES chat_members(chat_id, principal_id),
    FOREIGN KEY (chat_id, recipient_id) REFERENCES chat_members(chat_id, principal_id)
) STRICT;
CREATE INDEX messages_by_chat ON messages(chat_id, seq);

CREATE TRIGGER messages_no_update BEFORE UPDATE ON messages
BEGIN SELECT RAISE(ABORT, 'messages are append-only'); END;
CREATE TRIGGER messages_no_delete BEFORE DELETE ON messages
BEGIN SELECT RAISE(ABORT, 'messages are append-only'); END;
"#,
        principal_id = id_check("id"),
        chat_id = id_check("id"),
        message_id = id_check("id"),
        thread_id = id_check("thread_id"),
        client_msg_id = id_check("client_msg_id"),
    );
    // 2: agent profiles (label, about, picture) and content-addressed blobs.
    let v2 = r#"
CREATE TABLE blobs (
    hash          BLOB PRIMARY KEY NOT NULL CHECK (length(hash) = 32),
    mime          TEXT NOT NULL CHECK (mime IN ('image/png')),
    data          BLOB NOT NULL CHECK (length(data) BETWEEN 1 AND 524288),
    created_at_ms INTEGER NOT NULL
) STRICT;
ALTER TABLE principals ADD COLUMN label TEXT NOT NULL DEFAULT '' CHECK (length(label) <= 32);
ALTER TABLE principals ADD COLUMN about TEXT NOT NULL DEFAULT '' CHECK (length(about) <= 500);
ALTER TABLE principals ADD COLUMN avatar BLOB DEFAULT NULL REFERENCES blobs(hash)
    CHECK (avatar IS NULL OR length(avatar) = 32);
"#
    .to_owned();
    // 3: agent runtimes (tokens, models, usage), agent-to-agent links and depth, the
    // audit log, and the kill switch.
    let v3 = r#"
CREATE TABLE agent_tokens (
    agent           TEXT PRIMARY KEY NOT NULL REFERENCES principals(id),
    token_hash      BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at_ms   INTEGER NOT NULL,
    last_used_at_ms INTEGER
) STRICT;

CREATE TABLE agent_models (
    agent             TEXT PRIMARY KEY NOT NULL REFERENCES principals(id),
    base_url          TEXT NOT NULL CHECK (length(base_url) BETWEEN 1 AND 512),
    model             TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 128),
    -- AES-256-GCM: version byte, nonce, ciphertext, tag. Never stored in the clear.
    api_key           BLOB CHECK (api_key IS NULL OR length(api_key) BETWEEN 30 AND 2048),
    tls_pin           BLOB CHECK (tls_pin IS NULL OR length(tls_pin) = 32),
    instructions      TEXT NOT NULL CHECK (length(instructions) <= 8000),
    max_reply_tokens  INTEGER NOT NULL CHECK (max_reply_tokens BETWEEN 16 AND 32768),
    context_messages  INTEGER NOT NULL CHECK (context_messages BETWEEN 1 AND 200),
    daily_token_limit INTEGER NOT NULL CHECK (daily_token_limit BETWEEN 0 AND 1000000000),
    updated_at_ms     INTEGER NOT NULL
) STRICT;

CREATE TABLE usage (
    id                INTEGER PRIMARY KEY,
    agent             TEXT NOT NULL REFERENCES principals(id),
    at_ms             INTEGER NOT NULL,
    prompt_tokens     INTEGER NOT NULL CHECK (prompt_tokens >= 0),
    completion_tokens INTEGER NOT NULL CHECK (completion_tokens >= 0)
) STRICT;
CREATE INDEX usage_by_agent ON usage(agent, at_ms);

-- Which pairs of agents may talk, and their chat. agent_a < agent_b, one row per pair.
CREATE TABLE agent_links (
    chat_id TEXT PRIMARY KEY NOT NULL REFERENCES chats(id),
    agent_a TEXT NOT NULL REFERENCES principals(id),
    agent_b TEXT NOT NULL REFERENCES principals(id),
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    CHECK (agent_a < agent_b),
    UNIQUE (agent_a, agent_b)
) STRICT;

-- How many agent-to-agent hops led to this message (0 = started by the user).
ALTER TABLE messages ADD COLUMN depth INTEGER NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 64);
CREATE INDEX messages_by_sender ON messages(sender_id, created_at_ms);

CREATE TABLE audit (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms   INTEGER NOT NULL,
    actor   TEXT,
    action  TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    target  TEXT,
    detail  TEXT NOT NULL CHECK (length(detail) <= 500)
) STRICT;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;

CREATE TABLE server_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    agents_paused INTEGER NOT NULL CHECK (agents_paused IN (0, 1)),
    changed_at_ms INTEGER NOT NULL
) STRICT;
INSERT INTO server_state (id, agents_paused, changed_at_ms) VALUES (1, 0, 0);
"#
    .to_owned();
    // 4: plugins and per-agent grants.
    let v4 = format!(
        r#"
CREATE TABLE plugins (
    id            TEXT PRIMARY KEY NOT NULL CHECK ({plugin_id}),
    name          TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 24),
    version       TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 32),
    -- The manifest exactly as embedded in the module (validated at install).
    manifest      BLOB NOT NULL CHECK (length(manifest) BETWEEN 2 AND 65536),
    wasm          BLOB NOT NULL CHECK (length(wasm) BETWEEN 8 AND 4194304),
    hash          BLOB NOT NULL CHECK (length(hash) = 32),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE plugin_grants (
    agent         TEXT NOT NULL REFERENCES principals(id),
    plugin        TEXT NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    -- JSON array of host names: a subset of what the manifest asks for.
    http_hosts    TEXT NOT NULL CHECK (length(http_hosts) <= 8192),
    granted_at_ms INTEGER NOT NULL,
    PRIMARY KEY (agent, plugin)
) STRICT;
"#,
        plugin_id = id_check("id"),
    );
    // 5: durable jobs.
    let v5 = format!(
        r#"
CREATE TABLE jobs (
    id                TEXT PRIMARY KEY NOT NULL CHECK ({job_id}),
    agent             TEXT NOT NULL REFERENCES principals(id),
    chat_id           TEXT NOT NULL REFERENCES chats(id),
    title             TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    prompt            TEXT NOT NULL CHECK (length(prompt) BETWEEN 1 AND 4000),
    first_run_at_ms   INTEGER NOT NULL,
    every_secs        INTEGER CHECK (every_secs IS NULL OR every_secs BETWEEN 300 AND 31622400),
    next_run_at_ms    INTEGER,
    state             TEXT NOT NULL
                      CHECK (state IN ('proposed', 'active', 'done', 'failed', 'cancelled')),
    attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    proposed_by_agent INTEGER NOT NULL CHECK (proposed_by_agent IN (0, 1)),
    progress          TEXT NOT NULL DEFAULT '' CHECK (length(progress) <= 300),
    created_at_ms     INTEGER NOT NULL,
    updated_at_ms     INTEGER NOT NULL
) STRICT;
CREATE INDEX jobs_due ON jobs(state, next_run_at_ms);
CREATE INDEX jobs_by_agent ON jobs(agent, state);

CREATE TABLE job_runs (
    id             TEXT PRIMARY KEY NOT NULL CHECK ({run_id}),
    job            TEXT NOT NULL REFERENCES jobs(id),
    started_at_ms  INTEGER NOT NULL,
    deadline_ms    INTEGER NOT NULL,
    finished_at_ms INTEGER,
    outcome        TEXT CHECK (outcome IS NULL OR outcome IN ('ok', 'failed', 'lost', 'cancelled')),
    detail         TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 500)
) STRICT;
CREATE INDEX job_runs_by_job ON job_runs(job, started_at_ms);
"#,
        job_id = id_check("id"),
        run_id = id_check("id"),
    );
    vec![v1, v2, v3, v4, v5]
}

/// Shared handle to the database. One connection behind a mutex: the server has a
/// single user, and SQLite serializes writers anyway.
#[derive(Debug, Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open (creating if needed) the database at `path`. A new file is created with
    /// mode 0600; an existing one must already be private to `uid`. Runs migrations.
    pub fn open(path: &Path, uid: u32) -> Result<Self, DbError> {
        // Resolve symlinks in the directory part only (e.g. macOS /var -> /private/var,
        // which is the admin's business), then open with NOFOLLOW so the database file
        // itself can never be a symlink, even if swapped in after our checks.
        let name = path
            .file_name()
            .ok_or_else(|| DbError::Io(std::io::Error::other("database path has no file name")))?;
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let path = &std::fs::canonicalize(dir).map_err(DbError::Io)?.join(name);
        match fsperm::write_new_private_file(path, b"") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(DbError::Io(e)),
        }
        fsperm::check_private_file(path, uid).map_err(DbError::Perm)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE;
        let mut conn = Connection::open_with_flags(path, flags)?;
        harden(&conn)?;
        migrate(&mut conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Run `f` on a blocking thread with exclusive access to the connection.
    pub async fn call<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(&mut Connection) -> Result<R, DbError> + Send + 'static,
        R: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            // A panic mid-call can't leave a half-applied transaction (rusqlite rolls
            // back on drop), so recovering from poisoning is safe.
            let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut guard)
        })
        .await
        .map_err(|_| DbError::TaskFailed)?
    }

    /// Synchronous access, for the CLI.
    pub fn call_blocking<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        let mut guard = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

fn harden(conn: &Connection) -> Result<(), DbError> {
    // Defensive mode blocks writable_schema and other ways to corrupt the file via SQL.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    // Don't run SQL functions embedded in the schema, and no double-quoted string literals.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         -- Without this, INSERT OR REPLACE deletes conflicting rows *without* firing
         -- DELETE triggers, which would let a message be overwritten in place.
         PRAGMA recursive_triggers = ON;
         PRAGMA secure_delete = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    if fk != 1 {
        return Err(DbError::Corrupt("foreign key enforcement could not be enabled"));
    }
    Ok(())
}

fn migrate(conn: &mut Connection) -> Result<(), DbError> {
    let all = migrations();
    let supported = all.len() as i64;
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > supported {
        return Err(DbError::TooNew { found: current, supported });
    }
    for (i, sql) in all.iter().enumerate().skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

fn get_id(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Id> {
    let s: String = row.get(idx)?;
    Id::parse(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

// ---- principals ----

/// Return the user principal, creating it if it doesn't exist.
pub fn ensure_user(
    conn: &Connection,
    new_id: Id,
    display_name: &str,
    now_ms: i64,
) -> Result<Id, DbError> {
    if let Some(id) = user_id(conn)? {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'user', ?2, ?3)",
        params![new_id.to_string(), display_name, now_ms],
    )?;
    Ok(new_id)
}

pub fn user_id(conn: &Connection) -> Result<Option<Id>, DbError> {
    Ok(conn
        .query_row("SELECT id FROM principals WHERE kind = 'user'", [], |r| get_id(r, 0))
        .optional()?)
}

// ---- password ----

/// Set the user password hash and revoke every session (a password change must log
/// out everything). Returns the number of sessions revoked.
pub fn set_password_hash(conn: &mut Connection, phc: &str, now_ms: i64) -> Result<usize, DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO user_password (id, phc, updated_at_ms) VALUES (1, ?1, ?2)
         ON CONFLICT (id) DO UPDATE SET phc = excluded.phc, updated_at_ms = excluded.updated_at_ms",
        params![phc, now_ms],
    )?;
    let revoked = tx.execute("DELETE FROM sessions", [])?;
    // A password change is a fresh start: forget every known device too.
    tx.execute("DELETE FROM login_devices", [])?;
    tx.execute(
        "UPDATE login_throttle SET consecutive_failures = 0, locked_until_ms = 0 WHERE id = 1",
        [],
    )?;
    tx.commit()?;
    Ok(revoked)
}

pub fn password_hash(conn: &Connection) -> Result<Option<String>, DbError> {
    Ok(conn.query_row("SELECT phc FROM user_password WHERE id = 1", [], |r| r.get(0)).optional()?)
}

// ---- login throttle ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Throttle {
    pub consecutive_failures: u32,
    pub locked_until_ms: i64,
}

pub fn throttle(conn: &Connection) -> Result<Throttle, DbError> {
    conn.query_row(
        "SELECT consecutive_failures, locked_until_ms FROM login_throttle WHERE id = 1",
        [],
        |r| Ok(Throttle { consecutive_failures: r.get(0)?, locked_until_ms: r.get(1)? }),
    )
    .optional()?
    .ok_or(DbError::Corrupt("login_throttle row missing"))
}

pub fn set_throttle(conn: &Connection, t: Throttle) -> Result<(), DbError> {
    let n = conn.execute(
        "UPDATE login_throttle SET consecutive_failures = ?1, locked_until_ms = ?2 WHERE id = 1",
        params![t.consecutive_failures, t.locked_until_ms],
    )?;
    if n != 1 {
        return Err(DbError::Corrupt("login_throttle row missing"));
    }
    Ok(())
}

// ---- known login devices ----

/// The throttle of a known, unexpired device, or None if the token is unknown/expired.
pub fn device_throttle(
    conn: &Connection,
    token_hash: &[u8; 32],
    now_ms: i64,
) -> Result<Option<Throttle>, DbError> {
    Ok(conn
        .query_row(
            "SELECT consecutive_failures, locked_until_ms FROM login_devices
             WHERE token_hash = ?1 AND expires_at_ms > ?2",
            params![&token_hash[..], now_ms],
            |r| Ok(Throttle { consecutive_failures: r.get(0)?, locked_until_ms: r.get(1)? }),
        )
        .optional()?)
}

pub fn set_device_throttle(
    conn: &Connection,
    token_hash: &[u8; 32],
    t: Throttle,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE login_devices SET consecutive_failures = ?2, locked_until_ms = ?3
         WHERE token_hash = ?1",
        params![&token_hash[..], t.consecutive_failures, t.locked_until_ms],
    )?;
    Ok(())
}

/// After a successful login: retire the device token that was presented (if any),
/// register the new one, and keep at most `max_devices` (least recently used go first).
pub fn rotate_device(
    conn: &mut Connection,
    old: Option<[u8; 32]>,
    new: [u8; 32],
    now_ms: i64,
    expires_at_ms: i64,
    max_devices: u32,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    if let Some(old) = old {
        tx.execute("DELETE FROM login_devices WHERE token_hash = ?1", params![&old[..]])?;
    }
    tx.execute("DELETE FROM login_devices WHERE expires_at_ms <= ?1", params![now_ms])?;
    tx.execute(
        "INSERT INTO login_devices
         (token_hash, created_at_ms, last_used_at_ms, expires_at_ms, consecutive_failures, locked_until_ms)
         VALUES (?1, ?2, ?2, ?3, 0, 0)",
        params![&new[..], now_ms, expires_at_ms],
    )?;
    tx.execute(
        "DELETE FROM login_devices WHERE token_hash IN (
             SELECT token_hash FROM login_devices
             ORDER BY last_used_at_ms DESC, rowid DESC LIMIT -1 OFFSET ?1)",
        params![max_devices],
    )?;
    tx.commit()?;
    Ok(())
}

// ---- sessions ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub token_hash: [u8; 32],
    pub principal_id: Id,
    pub created_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub expires_at_ms: i64,
}

impl SessionRow {
    pub fn is_live(&self, now_ms: i64, idle_timeout_ms: i64) -> bool {
        now_ms < self.expires_at_ms && now_ms < self.last_seen_at_ms.saturating_add(idle_timeout_ms)
    }
}

/// Insert a session, then evict the oldest sessions of that principal beyond
/// `max_sessions`. Returns the evicted token hashes so live connections can be closed.
pub fn insert_session(
    conn: &mut Connection,
    row: &SessionRow,
    max_sessions: u32,
) -> Result<Vec<[u8; 32]>, DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO sessions (token_hash, principal_id, created_at_ms, last_seen_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &row.token_hash[..],
            row.principal_id.to_string(),
            row.created_at_ms,
            row.last_seen_at_ms,
            row.expires_at_ms
        ],
    )?;
    let evicted = {
        let mut stmt = tx.prepare(
            "SELECT token_hash FROM sessions WHERE principal_id = ?1
             ORDER BY created_at_ms DESC, rowid DESC LIMIT -1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![row.principal_id.to_string(), max_sessions], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|r| r.map_err(DbError::from).and_then(to_hash)).collect::<Result<Vec<_>, _>>()?
    };
    for h in &evicted {
        tx.execute("DELETE FROM sessions WHERE token_hash = ?1", params![&h[..]])?;
    }
    tx.commit()?;
    Ok(evicted)
}

fn to_hash(v: Vec<u8>) -> Result<[u8; 32], DbError> {
    v.try_into().map_err(|_| DbError::Corrupt("session hash has wrong length"))
}

pub fn session(conn: &Connection, token_hash: &[u8; 32]) -> Result<Option<SessionRow>, DbError> {
    let row = conn
        .query_row(
            "SELECT token_hash, principal_id, created_at_ms, last_seen_at_ms, expires_at_ms
             FROM sessions WHERE token_hash = ?1",
            params![&token_hash[..]],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    get_id(r, 1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(h, principal_id, created_at_ms, last_seen_at_ms, expires_at_ms)| {
        Ok(SessionRow {
            token_hash: to_hash(h)?,
            principal_id,
            created_at_ms,
            last_seen_at_ms,
            expires_at_ms,
        })
    })
    .transpose()
}

pub fn touch_session(conn: &Connection, token_hash: &[u8; 32], now_ms: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE sessions SET last_seen_at_ms = max(last_seen_at_ms, ?2) WHERE token_hash = ?1",
        params![&token_hash[..], now_ms],
    )?;
    Ok(())
}

pub fn delete_session(conn: &Connection, token_hash: &[u8; 32]) -> Result<bool, DbError> {
    Ok(conn.execute("DELETE FROM sessions WHERE token_hash = ?1", params![&token_hash[..]])? == 1)
}

pub fn delete_sessions_for(conn: &Connection, principal_id: Id) -> Result<usize, DbError> {
    Ok(conn.execute(
        "DELETE FROM sessions WHERE principal_id = ?1",
        params![principal_id.to_string()],
    )?)
}

pub fn delete_dead_sessions(
    conn: &Connection,
    now_ms: i64,
    idle_timeout_ms: i64,
) -> Result<usize, DbError> {
    Ok(conn.execute(
        "DELETE FROM sessions WHERE expires_at_ms <= ?1 OR last_seen_at_ms + ?2 <= ?1",
        params![now_ms, idle_timeout_ms],
    )?)
}

// ---- chats and the message log ----

fn chat_kind_str(kind: ChatKind) -> &'static str {
    match kind {
        ChatKind::NoteToSelf => "note_to_self",
        ChatKind::Direct => "direct",
        ChatKind::AgentToAgent => "agent_to_agent",
    }
}

fn chat_kind_from(s: &str) -> Result<ChatKind, DbError> {
    match s {
        "note_to_self" => Ok(ChatKind::NoteToSelf),
        "direct" => Ok(ChatKind::Direct),
        "agent_to_agent" => Ok(ChatKind::AgentToAgent),
        _ => Err(DbError::Corrupt("unknown chat kind")),
    }
}

/// (content_kind, body) as stored: Markdown as is, structured kinds as canonical JSON.
fn content_columns(content: &Content) -> (&'static str, String) {
    match content {
        Content::Markdown { text } => ("markdown", text.clone()),
        Content::Quiz { quiz } => ("quiz", snowpaw_proto::encode(quiz)),
        Content::QuizAnswers { answers } => ("quiz_answers", snowpaw_proto::encode(answers)),
    }
}

fn content_from(kind: &str, body: String) -> Result<Content, DbError> {
    let corrupt = |_| DbError::Corrupt("stored message content doesn't parse");
    match kind {
        "markdown" => Ok(Content::Markdown { text: body }),
        "quiz" => {
            Ok(Content::Quiz { quiz: snowpaw_proto::decode(body.as_bytes()).map_err(corrupt)? })
        }
        "quiz_answers" => Ok(Content::QuizAnswers {
            answers: snowpaw_proto::decode(body.as_bytes()).map_err(corrupt)?,
        }),
        _ => Err(DbError::Corrupt("message content kind not supported by this server")),
    }
}

pub fn create_chat(
    conn: &mut Connection,
    id: Id,
    kind: ChatKind,
    members: &[Id],
    now_ms: i64,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO chats (id, kind, created_at_ms) VALUES (?1, ?2, ?3)",
        params![id.to_string(), chat_kind_str(kind), now_ms],
    )?;
    for m in members {
        tx.execute(
            "INSERT INTO chat_members (chat_id, principal_id) VALUES (?1, ?2)",
            params![id.to_string(), m.to_string()],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Make sure the user's Note to Self chat exists. Returns its id.
pub fn ensure_note_to_self(
    conn: &mut Connection,
    user_id: Id,
    new_id: Id,
    now_ms: i64,
) -> Result<Id, DbError> {
    let existing = conn
        .query_row("SELECT id FROM chats WHERE kind = 'note_to_self'", [], |r| get_id(r, 0))
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    create_chat(conn, new_id, ChatKind::NoteToSelf, &[user_id], now_ms)?;
    Ok(new_id)
}

/// A chat as seen by one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRow {
    pub id: Id,
    pub kind: ChatKind,
    pub title: String,
    pub members: Vec<Member>,
    pub last_message: Option<StoredMessage>,
    pub link_allowed: Option<bool>,
}

/// Every chat `principal` is a member of, most recently active first. The user
/// (`observer`) also sees every conversation between agents, read-only.
pub fn chats_for(
    conn: &Connection,
    principal: Id,
    observer: bool,
) -> Result<Vec<ChatRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT c.id, c.kind, (SELECT max(seq) FROM messages m WHERE m.chat_id = c.id) AS last_seq
         FROM chats c
         WHERE c.id IN (SELECT chat_id FROM chat_members WHERE principal_id = ?1)
            OR (?2 AND c.kind = 'agent_to_agent')
         ORDER BY coalesce(last_seq, 0) DESC, c.created_at_ms DESC",
    )?;
    let rows = stmt
        .query_map(params![principal.to_string(), observer], |r| {
            Ok((get_id(r, 0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, kind, last_seq) in rows {
        let kind = chat_kind_from(&kind)?;
        let title = chat_title(conn, id, kind, principal)?;
        let members = chat_members(conn, id)?;
        let last_message = match last_seq {
            Some(seq) => messages_after(conn, id, seq - 1, 1)?.into_iter().next(),
            None => None,
        };
        let link_allowed = match kind {
            ChatKind::AgentToAgent => link_allowed(conn, id)?,
            ChatKind::NoteToSelf | ChatKind::Direct => None,
        };
        out.push(ChatRow { id, kind, title, members, last_message, link_allowed });
    }
    Ok(out)
}

const MEMBER_COLUMNS: &str = "p.id, p.kind, p.display_name, p.label, p.about, p.avatar";

/// (id, kind, name, label, about, avatar) as read from the database.
type MemberRow = (Id, String, String, String, String, Option<Vec<u8>>);

fn member_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MemberRow> {
    Ok((get_id(r, 0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
}

fn finish_member((id, kind, name, label, about, avatar): MemberRow) -> Result<Member, DbError> {
    let kind = match kind.as_str() {
        "user" => PrincipalKind::User,
        "agent" => PrincipalKind::Agent,
        _ => return Err(DbError::Corrupt("unknown principal kind")),
    };
    let avatar = match avatar {
        None => None,
        Some(b) => Some(BlobHash::from_bytes(
            b.try_into().map_err(|_| DbError::Corrupt("bad avatar hash"))?,
        )),
    };
    Ok(Member { id, kind, name, label, about, avatar })
}

fn chat_members(conn: &Connection, chat: Id) -> Result<Vec<Member>, DbError> {
    let sql = format!(
        "SELECT {MEMBER_COLUMNS} FROM chat_members cm JOIN principals p ON p.id = cm.principal_id
         WHERE cm.chat_id = ?1 ORDER BY p.kind DESC, p.display_name"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![chat.to_string()], member_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(finish_member).collect()
}

/// One principal's public profile.
pub fn member(conn: &Connection, id: Id) -> Result<Option<Member>, DbError> {
    let sql = format!("SELECT {MEMBER_COLUMNS} FROM principals p WHERE p.id = ?1");
    conn.query_row(&sql, params![id.to_string()], member_from_row)
        .optional()?
        .map(finish_member)
        .transpose()
}

// ---- agents and blobs ----

/// A new agent and the ids for it and its direct chat with the user.
#[derive(Debug, Clone, Copy)]
pub struct NewAgent<'a> {
    pub user: Id,
    pub agent: Id,
    pub chat: Id,
    pub name: &'a str,
    pub label: &'a str,
    pub about: &'a str,
}

/// Create an agent and the user's direct chat with it, in one transaction.
pub fn create_agent(
    conn: &mut Connection,
    new: &NewAgent<'_>,
    now_ms: i64,
) -> Result<Member, DbError> {
    let NewAgent { user, agent, chat, name, label, about } = *new;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO principals (id, kind, display_name, label, about, created_at_ms)
         VALUES (?1, 'agent', ?2, ?3, ?4, ?5)",
        params![agent.to_string(), name, label, about, now_ms],
    )?;
    tx.execute(
        "INSERT INTO chats (id, kind, created_at_ms) VALUES (?1, 'direct', ?2)",
        params![chat.to_string(), now_ms],
    )?;
    for m in [user, agent] {
        tx.execute(
            "INSERT INTO chat_members (chat_id, principal_id) VALUES (?1, ?2)",
            params![chat.to_string(), m.to_string()],
        )?;
    }
    let created = member(&tx, agent)?.ok_or(DbError::Corrupt("agent vanished"))?;
    tx.commit()?;
    Ok(created)
}

/// Update an agent's profile text. Only agents can be edited this way.
pub fn update_agent(
    conn: &Connection,
    agent: Id,
    name: &str,
    label: &str,
    about: &str,
) -> Result<Option<Member>, DbError> {
    let n = conn.execute(
        "UPDATE principals SET display_name = ?2, label = ?3, about = ?4 WHERE id = ?1 AND kind = 'agent'",
        params![agent.to_string(), name, label, about],
    )?;
    if n == 0 { Ok(None) } else { member(conn, agent) }
}

/// Set or clear an agent's picture. The blob must exist (enforced by a foreign key).
pub fn set_avatar(
    conn: &Connection,
    agent: Id,
    avatar: Option<BlobHash>,
) -> Result<Option<Member>, DbError> {
    let n = conn.execute(
        "UPDATE principals SET avatar = ?2 WHERE id = ?1 AND kind = 'agent'",
        params![agent.to_string(), avatar.map(|h| h.as_bytes().to_vec())],
    )?;
    if n == 0 { Ok(None) } else { member(conn, agent) }
}

pub fn blob_exists(conn: &Connection, hash: &BlobHash) -> Result<bool, DbError> {
    Ok(conn
        .query_row("SELECT 1 FROM blobs WHERE hash = ?1", params![&hash.as_bytes()[..]], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Store a blob under its SHA-256 (idempotent).
pub fn put_blob(
    conn: &Connection,
    hash: &BlobHash,
    mime: &str,
    data: &[u8],
    now_ms: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO blobs (hash, mime, data, created_at_ms) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (hash) DO NOTHING",
        params![&hash.as_bytes()[..], mime, data, now_ms],
    )?;
    Ok(())
}

pub fn get_blob(conn: &Connection, hash: &BlobHash) -> Result<Option<(String, Vec<u8>)>, DbError> {
    Ok(conn
        .query_row(
            "SELECT mime, data FROM blobs WHERE hash = ?1",
            params![&hash.as_bytes()[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// Titles are derived, never stored: Note to Self, the other member's name, or both
/// agents' names.
fn chat_title(conn: &Connection, chat: Id, kind: ChatKind, viewer: Id) -> Result<String, DbError> {
    if kind == ChatKind::NoteToSelf {
        return Ok("Note to Self".to_owned());
    }
    let mut stmt = conn.prepare(
        "SELECT p.display_name FROM chat_members cm JOIN principals p ON p.id = cm.principal_id
         WHERE cm.chat_id = ?1 AND cm.principal_id != ?2 ORDER BY p.display_name",
    )?;
    let names = stmt
        .query_map(params![chat.to_string(), viewer.to_string()], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.join(" & "))
}

/// The chat's kind and members, if `principal` is one of them. `None` means "no such
/// chat or not a member": callers must not distinguish the two.
pub fn chat_if_member(
    conn: &Connection,
    chat: Id,
    principal: Id,
) -> Result<Option<(ChatKind, Vec<Id>)>, DbError> {
    let kind: Option<String> = conn
        .query_row(
            "SELECT c.kind FROM chats c JOIN chat_members cm ON cm.chat_id = c.id
             WHERE c.id = ?1 AND cm.principal_id = ?2",
            params![chat.to_string(), principal.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(kind) = kind else { return Ok(None) };
    let mut stmt = conn.prepare("SELECT principal_id FROM chat_members WHERE chat_id = ?1")?;
    let members = stmt
        .query_map(params![chat.to_string()], |r| get_id(r, 0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some((chat_kind_from(&kind)?, members)))
}

/// The chat's kind and members if `principal` may read it: as a member, or as the
/// user (`observer`) reading a conversation between agents. Same "no such chat or
/// not allowed" ambiguity as `chat_if_member`.
pub fn chat_if_visible(
    conn: &Connection,
    chat: Id,
    principal: Id,
    observer: bool,
) -> Result<Option<(ChatKind, Vec<Id>)>, DbError> {
    if let Some(found) = chat_if_member(conn, chat, principal)? {
        return Ok(Some(found));
    }
    if !observer {
        return Ok(None);
    }
    let kind: Option<String> = conn
        .query_row(
            "SELECT kind FROM chats WHERE id = ?1 AND kind = 'agent_to_agent'",
            params![chat.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(kind) = kind else { return Ok(None) };
    let mut stmt = conn.prepare("SELECT principal_id FROM chat_members WHERE chat_id = ?1")?;
    let members = stmt
        .query_map(params![chat.to_string()], |r| get_id(r, 0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some((chat_kind_from(&kind)?, members)))
}

#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub id: Id,
    pub chat_id: Id,
    pub thread_id: Option<Id>,
    /// Must come from the authenticated session, never from a request body.
    pub sender_id: Id,
    pub recipient_id: Option<Id>,
    pub client_msg_id: Id,
    pub content: &'a Content,
    /// Agent-to-agent hops that led here (computed by the server).
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub seq: i64,
    pub id: Id,
    pub chat_id: Id,
    pub thread_id: Option<Id>,
    pub sender_id: Id,
    pub recipient_id: Option<Id>,
    pub client_msg_id: Id,
    pub content: Content,
    pub created_at_ms: i64,
}

impl StoredMessage {
    pub fn into_view(self) -> MessageView {
        MessageView {
            seq: self.seq,
            id: self.id,
            chat_id: self.chat_id,
            thread_id: self.thread_id,
            sender_id: self.sender_id,
            recipient_id: self.recipient_id,
            client_msg_id: self.client_msg_id,
            content: self.content,
            created_at_ms: self.created_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Appended {
    New(StoredMessage),
    /// Same sender and client_msg_id already stored: a retry. Returns the original.
    Duplicate(StoredMessage),
}

/// Append to the log. The server assigns `seq` and `created_at_ms`.
pub fn append_message(
    conn: &mut Connection,
    m: &NewMessage<'_>,
    now_ms: i64,
) -> Result<Appended, DbError> {
    let tx = conn.transaction()?;
    let existing: Option<i64> = tx
        .query_row(
            "SELECT seq FROM messages WHERE sender_id = ?1 AND client_msg_id = ?2",
            params![m.sender_id.to_string(), m.client_msg_id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(seq) = existing {
        let original = message_by_seq(&tx, seq)?;
        return Ok(Appended::Duplicate(original));
    }
    let (kind, body) = content_columns(m.content);
    tx.execute(
        "INSERT INTO messages
         (id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, content_kind, body,
          created_at_ms, depth)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            m.id.to_string(),
            m.chat_id.to_string(),
            m.thread_id.map(|t| t.to_string()),
            m.sender_id.to_string(),
            m.recipient_id.map(|r| r.to_string()),
            m.client_msg_id.to_string(),
            kind,
            body,
            now_ms,
            m.depth
        ],
    )?;
    let seq = tx.last_insert_rowid();
    let stored = message_by_seq(&tx, seq)?;
    tx.commit()?;
    Ok(Appended::New(stored))
}

const MESSAGE_COLUMNS: &str = "seq, id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, \
                               content_kind, body, created_at_ms";

/// A message row before its content has been decoded.
struct RawMessage {
    seq: i64,
    id: Id,
    chat_id: Id,
    thread_id: Option<Id>,
    sender_id: Id,
    recipient_id: Option<Id>,
    client_msg_id: Id,
    content_kind: String,
    body: String,
    created_at_ms: i64,
}

fn message_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessage> {
    let opt_id = |idx: usize| -> rusqlite::Result<Option<Id>> {
        match r.get::<_, Option<String>>(idx)? {
            None => Ok(None),
            Some(s) => Id::parse(&s).map(Some).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    idx,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            }),
        }
    };
    Ok(RawMessage {
        seq: r.get(0)?,
        id: get_id(r, 1)?,
        chat_id: get_id(r, 2)?,
        thread_id: opt_id(3)?,
        sender_id: get_id(r, 4)?,
        recipient_id: opt_id(5)?,
        client_msg_id: get_id(r, 6)?,
        content_kind: r.get(7)?,
        body: r.get(8)?,
        created_at_ms: r.get(9)?,
    })
}

fn finish(m: RawMessage) -> Result<StoredMessage, DbError> {
    Ok(StoredMessage {
        seq: m.seq,
        id: m.id,
        chat_id: m.chat_id,
        thread_id: m.thread_id,
        sender_id: m.sender_id,
        recipient_id: m.recipient_id,
        client_msg_id: m.client_msg_id,
        content: content_from(&m.content_kind, m.body)?,
        created_at_ms: m.created_at_ms,
    })
}

fn message_by_seq(conn: &Connection, seq: i64) -> Result<StoredMessage, DbError> {
    let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE seq = ?1");
    finish(conn.query_row(&sql, params![seq], message_from_row)?)
}

pub fn messages_after(
    conn: &Connection,
    chat_id: Id,
    after_seq: i64,
    limit: u32,
) -> Result<Vec<StoredMessage>, DbError> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages WHERE chat_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![chat_id.to_string(), after_seq, limit], message_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(finish).collect()
}

/// A message `sender` already posted with this idempotency key.
pub fn message_by_client_id(
    conn: &Connection,
    sender: Id,
    client_msg_id: Id,
) -> Result<Option<StoredMessage>, DbError> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages WHERE sender_id = ?1 AND client_msg_id = ?2"
    );
    conn.query_row(&sql, params![sender.to_string(), client_msg_id.to_string()], message_from_row)
        .optional()?
        .map(finish)
        .transpose()
}

/// A message by id, if it's in `chat`.
pub fn message_in_chat(
    conn: &Connection,
    chat: Id,
    id: Id,
) -> Result<Option<StoredMessage>, DbError> {
    let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE id = ?1 AND chat_id = ?2");
    conn.query_row(&sql, params![id.to_string(), chat.to_string()], message_from_row)
        .optional()?
        .map(finish)
        .transpose()
}

/// The chat, sender, and depth of message `seq`, if `principal` is a member of its
/// chat.
pub fn reply_target(
    conn: &Connection,
    seq: i64,
    principal: Id,
) -> Result<Option<(Id, Id, u32)>, DbError> {
    conn.query_row(
        "SELECT m.chat_id, m.sender_id, m.depth FROM messages m
         JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.principal_id = ?2
         WHERE m.seq = ?1",
        params![seq, principal.to_string()],
        |r| Ok((get_id(r, 0)?, get_id(r, 1)?, r.get::<_, u32>(2)?)),
    )
    .optional()
    .map_err(Into::into)
}

/// Messages `sender` posted since `since_ms`, in one chat or all of them.
pub fn messages_sent_since(
    conn: &Connection,
    sender: Id,
    chat: Option<Id>,
    since_ms: i64,
) -> Result<i64, DbError> {
    Ok(conn.query_row(
        "SELECT count(*) FROM messages
         WHERE sender_id = ?1 AND created_at_ms >= ?2 AND (?3 IS NULL OR chat_id = ?3)",
        params![sender.to_string(), since_ms, chat.map(|c| c.to_string())],
        |r| r.get(0),
    )?)
}

// ---- agent runtimes ----

pub fn is_agent(conn: &Connection, id: Id) -> Result<bool, DbError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM principals WHERE id = ?1 AND kind = 'agent'",
            params![id.to_string()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Store a new runtime token hash for an agent, replacing any earlier one.
pub fn set_agent_token(
    conn: &Connection,
    agent: Id,
    token_hash: &[u8; 32],
    now_ms: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO agent_tokens (agent, token_hash, created_at_ms, last_used_at_ms)
         VALUES (?1, ?2, ?3, NULL)
         ON CONFLICT (agent) DO UPDATE SET
             token_hash = excluded.token_hash,
             created_at_ms = excluded.created_at_ms,
             last_used_at_ms = NULL",
        params![agent.to_string(), &token_hash[..], now_ms],
    )?;
    Ok(())
}

pub fn delete_agent_token(conn: &Connection, agent: Id) -> Result<bool, DbError> {
    Ok(conn.execute("DELETE FROM agent_tokens WHERE agent = ?1", params![agent.to_string()])? > 0)
}

/// The agent a runtime token belongs to.
pub fn agent_for_token(conn: &Connection, token_hash: &[u8; 32]) -> Result<Option<Id>, DbError> {
    conn.query_row(
        "SELECT agent FROM agent_tokens WHERE token_hash = ?1",
        params![&token_hash[..]],
        |r| get_id(r, 0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn touch_agent_token(conn: &Connection, agent: Id, now_ms: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE agent_tokens SET last_used_at_ms = ?2 WHERE agent = ?1",
        params![agent.to_string(), now_ms],
    )?;
    Ok(())
}

/// (issued_at, last_used_at) of the agent's runtime token.
pub fn agent_token_info(
    conn: &Connection,
    agent: Id,
) -> Result<Option<(i64, Option<i64>)>, DbError> {
    conn.query_row(
        "SELECT created_at_ms, last_used_at_ms FROM agent_tokens WHERE agent = ?1",
        params![agent.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

/// An agent's model settings as stored. The API key stays sealed.
#[derive(Debug, Clone)]
pub struct ModelRow {
    pub settings: ModelSettings,
    pub sealed_api_key: Option<Vec<u8>>,
}

pub fn agent_model(conn: &Connection, agent: Id) -> Result<Option<ModelRow>, DbError> {
    conn.query_row(
        "SELECT base_url, model, api_key, tls_pin, instructions, max_reply_tokens,
                context_messages, daily_token_limit
         FROM agent_models WHERE agent = ?1",
        params![agent.to_string()],
        |r| {
            let pin: Option<Vec<u8>> = r.get(3)?;
            Ok(ModelRow {
                settings: ModelSettings {
                    base_url: r.get(0)?,
                    model: r.get(1)?,
                    tls_pin: pin.map(|p| {
                        let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
                        format!("sha256:{hex}")
                    }),
                    instructions: r.get(4)?,
                    max_reply_tokens: r.get(5)?,
                    context_messages: r.get(6)?,
                    daily_token_limit: u64::try_from(r.get::<_, i64>(7)?).unwrap_or(0),
                },
                sealed_api_key: r.get(2)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

/// What to do with the stored (sealed) key when saving settings.
#[derive(Debug)]
pub enum KeyUpdate {
    Keep,
    Clear,
    Set(Vec<u8>),
}

/// Save settings already checked with `ModelSettings::validate`.
pub fn set_agent_model(
    conn: &mut Connection,
    agent: Id,
    settings: &ModelSettings,
    tls_pin: Option<[u8; 32]>,
    key: KeyUpdate,
    now_ms: i64,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    let existing: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT api_key FROM agent_models WHERE agent = ?1",
            params![agent.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let api_key = match key {
        KeyUpdate::Keep => existing.flatten(),
        KeyUpdate::Clear => None,
        KeyUpdate::Set(sealed) => Some(sealed),
    };
    tx.execute(
        "INSERT INTO agent_models (agent, base_url, model, api_key, tls_pin, instructions,
             max_reply_tokens, context_messages, daily_token_limit, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (agent) DO UPDATE SET
             base_url = excluded.base_url, model = excluded.model, api_key = excluded.api_key,
             tls_pin = excluded.tls_pin, instructions = excluded.instructions,
             max_reply_tokens = excluded.max_reply_tokens,
             context_messages = excluded.context_messages,
             daily_token_limit = excluded.daily_token_limit,
             updated_at_ms = excluded.updated_at_ms",
        params![
            agent.to_string(),
            settings.base_url,
            settings.model,
            api_key,
            tls_pin.map(|p| p.to_vec()),
            settings.instructions,
            settings.max_reply_tokens,
            settings.context_messages,
            i64::try_from(settings.daily_token_limit).unwrap_or(i64::MAX),
            now_ms
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// Model calls an agent started since `since_ms` (failed ones included).
pub fn usage_calls_since(conn: &Connection, agent: Id, since_ms: i64) -> Result<i64, DbError> {
    Ok(conn.query_row(
        "SELECT count(*) FROM usage WHERE agent = ?1 AND at_ms >= ?2",
        params![agent.to_string(), since_ms],
        |r| r.get(0),
    )?)
}

/// Charge the worst case for a call about to start. Returns the row to settle.
pub fn reserve_usage(
    conn: &Connection,
    agent: Id,
    now_ms: i64,
    prompt_tokens: u64,
    completion_tokens: u32,
) -> Result<i64, DbError> {
    record_usage(conn, agent, now_ms, prompt_tokens, completion_tokens.into())?;
    Ok(conn.last_insert_rowid())
}

/// Replace a reservation with what the call actually used.
pub fn settle_usage(
    conn: &Connection,
    row: i64,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE usage SET prompt_tokens = ?2, completion_tokens = ?3 WHERE id = ?1",
        params![
            row,
            i64::try_from(prompt_tokens).unwrap_or(i64::MAX),
            i64::try_from(completion_tokens).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

pub fn record_usage(
    conn: &Connection,
    agent: Id,
    now_ms: i64,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO usage (agent, at_ms, prompt_tokens, completion_tokens) VALUES (?1, ?2, ?3, ?4)",
        params![
            agent.to_string(),
            now_ms,
            i64::try_from(prompt_tokens).unwrap_or(i64::MAX),
            i64::try_from(completion_tokens).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

/// Prompt + reply tokens an agent used since `since_ms`.
pub fn usage_since(conn: &Connection, agent: Id, since_ms: i64) -> Result<u64, DbError> {
    let total: i64 = conn.query_row(
        "SELECT coalesce(sum(prompt_tokens + completion_tokens), 0) FROM usage
         WHERE agent = ?1 AND at_ms >= ?2",
        params![agent.to_string(), since_ms],
        |r| r.get(0),
    )?;
    Ok(u64::try_from(total).unwrap_or(0))
}

pub fn prune_usage(conn: &Connection, before_ms: i64) -> Result<usize, DbError> {
    Ok(conn.execute("DELETE FROM usage WHERE at_ms < ?1", params![before_ms])?)
}

// ---- agent-to-agent links ----

fn ordered(a: Id, b: Id) -> (Id, Id) {
    if a.to_string() < b.to_string() { (a, b) } else { (b, a) }
}

/// The chat between two agents and whether they may currently talk.
pub fn link(conn: &Connection, a: Id, b: Id) -> Result<Option<(Id, bool)>, DbError> {
    let (a, b) = ordered(a, b);
    conn.query_row(
        "SELECT chat_id, allowed FROM agent_links WHERE agent_a = ?1 AND agent_b = ?2",
        params![a.to_string(), b.to_string()],
        |r| Ok((get_id(r, 0)?, r.get::<_, bool>(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

/// Allow or pause two agents talking. Creates their chat the first time (with id
/// `new_chat`). Returns the chat id and whether it was created.
pub fn set_link(
    conn: &mut Connection,
    a: Id,
    b: Id,
    allowed: bool,
    new_chat: Id,
    now_ms: i64,
) -> Result<(Id, bool), DbError> {
    let (a, b) = ordered(a, b);
    if let Some((chat, _)) = link(conn, a, b)? {
        conn.execute(
            "UPDATE agent_links SET allowed = ?2 WHERE chat_id = ?1",
            params![chat.to_string(), allowed],
        )?;
        return Ok((chat, false));
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO chats (id, kind, created_at_ms) VALUES (?1, 'agent_to_agent', ?2)",
        params![new_chat.to_string(), now_ms],
    )?;
    for m in [a, b] {
        tx.execute(
            "INSERT INTO chat_members (chat_id, principal_id) VALUES (?1, ?2)",
            params![new_chat.to_string(), m.to_string()],
        )?;
    }
    tx.execute(
        "INSERT INTO agent_links (chat_id, agent_a, agent_b, allowed) VALUES (?1, ?2, ?3, ?4)",
        params![new_chat.to_string(), a.to_string(), b.to_string(), allowed],
    )?;
    tx.commit()?;
    Ok((new_chat, true))
}

/// Whether posting is allowed in a chat between agents (`None`: not such a chat).
pub fn link_allowed(conn: &Connection, chat: Id) -> Result<Option<bool>, DbError> {
    conn.query_row(
        "SELECT allowed FROM agent_links WHERE chat_id = ?1",
        params![chat.to_string()],
        |r| r.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn links_for(conn: &Connection, agent: Id) -> Result<Vec<AgentLink>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT CASE WHEN agent_a = ?1 THEN agent_b ELSE agent_a END, chat_id, allowed
         FROM agent_links WHERE agent_a = ?1 OR agent_b = ?1 ORDER BY chat_id",
    )?;
    let rows = stmt
        .query_map(params![agent.to_string()], |r| {
            Ok(AgentLink { agent: get_id(r, 0)?, chat_id: get_id(r, 1)?, allowed: r.get(2)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---- kill switch and audit log ----

pub fn agents_paused(conn: &Connection) -> Result<bool, DbError> {
    Ok(conn.query_row("SELECT agents_paused FROM server_state WHERE id = 1", [], |r| r.get(0))?)
}

pub fn set_agents_paused(conn: &Connection, paused: bool, now_ms: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE server_state SET agents_paused = ?1, changed_at_ms = ?2 WHERE id = 1",
        params![paused, now_ms],
    )?;
    Ok(())
}

/// Longest audit detail kept; longer text is cut (never rejected: auditing must not fail).
const MAX_AUDIT_DETAIL_CHARS: usize = 500;

/// Append to the audit log. Callers pass no secrets and no message text.
pub fn audit(
    conn: &Connection,
    now_ms: i64,
    actor: Option<Id>,
    action: &str,
    target: Option<Id>,
    detail: &str,
) -> Result<(), DbError> {
    let detail: String =
        detail.chars().filter(|c| !c.is_control()).take(MAX_AUDIT_DETAIL_CHARS).collect();
    conn.execute(
        "INSERT INTO audit (at_ms, actor, action, target, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            now_ms,
            actor.map(|a| a.to_string()),
            action,
            target.map(|t| t.to_string()),
            detail
        ],
    )?;
    Ok(())
}

/// Newest first; `has_more` says whether older entries exist.
pub fn audit_page(
    conn: &Connection,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<(Vec<AuditEntry>, bool), DbError> {
    let mut stmt = conn.prepare(
        "SELECT seq, at_ms, actor, action, target, detail FROM audit
         WHERE (?1 IS NULL OR seq < ?1) ORDER BY seq DESC LIMIT ?2",
    )?;
    let opt_id = |r: &rusqlite::Row<'_>, idx: usize| -> rusqlite::Result<Option<Id>> {
        match r.get::<_, Option<String>>(idx)? {
            None => Ok(None),
            Some(_) => get_id(r, idx).map(Some),
        }
    };
    let mut rows = stmt
        .query_map(params![before_seq, limit + 1], |r| {
            Ok(AuditEntry {
                seq: r.get(0)?,
                at_ms: r.get(1)?,
                actor: opt_id(r, 2)?,
                action: r.get(3)?,
                target: opt_id(r, 4)?,
                detail: r.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    Ok((rows, has_more))
}

// ---- plugins ----

/// An installed plugin as stored.
#[derive(Debug, Clone)]
pub struct PluginRow {
    pub id: Id,
    pub manifest: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct NewPlugin<'a> {
    pub id: Id,
    pub name: &'a str,
    pub version: &'a str,
    pub manifest: &'a [u8],
    pub wasm: &'a [u8],
    pub hash: &'a [u8; 32],
}

/// Install a plugin. One version per name: an existing plugin with the same name is
/// replaced, and its grants go with it (the new version may ask for different
/// capabilities). Returns the replaced plugin's id, if any.
pub fn install_plugin(
    conn: &mut Connection,
    new: &NewPlugin<'_>,
    now_ms: i64,
) -> Result<Option<Id>, DbError> {
    let NewPlugin { id, name, version, manifest, wasm, hash } = *new;
    let tx = conn.transaction()?;
    let old: Option<Id> = tx
        .query_row("SELECT id FROM plugins WHERE name = ?1", params![name], |r| get_id(r, 0))
        .optional()?;
    if let Some(old) = old {
        tx.execute("DELETE FROM plugins WHERE id = ?1", params![old.to_string()])?;
    }
    tx.execute(
        "INSERT INTO plugins (id, name, version, manifest, wasm, hash, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id.to_string(), name, version, manifest, wasm, &hash[..], now_ms],
    )?;
    tx.commit()?;
    Ok(old)
}

pub fn plugins(conn: &Connection) -> Result<Vec<PluginRow>, DbError> {
    let mut stmt = conn.prepare("SELECT id, manifest, hash FROM plugins ORDER BY name")?;
    let rows = stmt
        .query_map([], |r| Ok((get_id(r, 0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, manifest, hash)| Ok(PluginRow { id, manifest, hash: to_hash(hash)? }))
        .collect()
}

pub fn plugin(conn: &Connection, id: Id) -> Result<Option<PluginRow>, DbError> {
    let row = conn
        .query_row(
            "SELECT manifest, hash FROM plugins WHERE id = ?1",
            params![id.to_string()],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(manifest, hash)| Ok(PluginRow { id, manifest, hash: to_hash(hash)? })).transpose()
}

/// The module, if `agent` was granted the plugin.
pub fn granted_plugin_code(
    conn: &Connection,
    agent: Id,
    plugin: Id,
) -> Result<Option<Vec<u8>>, DbError> {
    conn.query_row(
        "SELECT p.wasm FROM plugins p JOIN plugin_grants g ON g.plugin = p.id
         WHERE p.id = ?1 AND g.agent = ?2",
        params![plugin.to_string(), agent.to_string()],
        |r| r.get(0),
    )
    .optional()
    .map_err(Into::into)
}

/// (agent, hosts) for every grant of a plugin.
pub fn plugin_grants(conn: &Connection, plugin: Id) -> Result<Vec<(Id, Vec<String>)>, DbError> {
    let mut stmt = conn
        .prepare("SELECT agent, http_hosts FROM plugin_grants WHERE plugin = ?1 ORDER BY agent")?;
    let rows = stmt
        .query_map(params![plugin.to_string()], |r| Ok((get_id(r, 0)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(agent, hosts)| {
            let hosts =
                serde_json::from_str(&hosts).map_err(|_| DbError::Corrupt("bad grant hosts"))?;
            Ok((agent, hosts))
        })
        .collect()
}

/// (plugin, hosts) for every plugin granted to `agent`.
pub fn grants_for(conn: &Connection, agent: Id) -> Result<Vec<(PluginRow, Vec<String>)>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT p.id, p.manifest, p.hash, g.http_hosts FROM plugin_grants g
         JOIN plugins p ON p.id = g.plugin WHERE g.agent = ?1 ORDER BY p.name",
    )?;
    let rows = stmt
        .query_map(params![agent.to_string()], |r| {
            Ok((
                get_id(r, 0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, manifest, hash, hosts)| {
            let hosts =
                serde_json::from_str(&hosts).map_err(|_| DbError::Corrupt("bad grant hosts"))?;
            Ok((PluginRow { id, manifest, hash: to_hash(hash)? }, hosts))
        })
        .collect()
}

pub fn grant_plugin(
    conn: &Connection,
    agent: Id,
    plugin: Id,
    http_hosts: &[String],
    now_ms: i64,
) -> Result<(), DbError> {
    let hosts = serde_json::to_string(http_hosts).map_err(|_| DbError::Corrupt("hosts"))?;
    conn.execute(
        "INSERT INTO plugin_grants (agent, plugin, http_hosts, granted_at_ms) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (agent, plugin) DO UPDATE SET http_hosts = excluded.http_hosts,
             granted_at_ms = excluded.granted_at_ms",
        params![agent.to_string(), plugin.to_string(), hosts, now_ms],
    )?;
    Ok(())
}

pub fn revoke_plugin(conn: &Connection, agent: Id, plugin: Id) -> Result<bool, DbError> {
    Ok(conn.execute(
        "DELETE FROM plugin_grants WHERE agent = ?1 AND plugin = ?2",
        params![agent.to_string(), plugin.to_string()],
    )? > 0)
}

pub fn remove_plugin(conn: &Connection, plugin: Id) -> Result<bool, DbError> {
    Ok(conn.execute("DELETE FROM plugins WHERE id = ?1", params![plugin.to_string()])? > 0)
}

// ---- jobs ----

fn job_state_str(s: JobState) -> &'static str {
    match s {
        JobState::Proposed => "proposed",
        JobState::Active => "active",
        JobState::Done => "done",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    }
}

fn job_state_from(s: &str) -> Result<JobState, DbError> {
    Ok(match s {
        "proposed" => JobState::Proposed,
        "active" => JobState::Active,
        "done" => JobState::Done,
        "failed" => JobState::Failed,
        "cancelled" => JobState::Cancelled,
        _ => return Err(DbError::Corrupt("unknown job state")),
    })
}

fn outcome_str(o: RunOutcome) -> &'static str {
    match o {
        RunOutcome::Ok => "ok",
        RunOutcome::Failed => "failed",
        RunOutcome::Lost => "lost",
        RunOutcome::Cancelled => "cancelled",
    }
}

fn outcome_from(s: &str) -> Result<RunOutcome, DbError> {
    Ok(match s {
        "ok" => RunOutcome::Ok,
        "failed" => RunOutcome::Failed,
        "lost" => RunOutcome::Lost,
        "cancelled" => RunOutcome::Cancelled,
        _ => return Err(DbError::Corrupt("unknown run outcome")),
    })
}

#[derive(Debug, Clone)]
pub struct NewJob<'a> {
    pub id: Id,
    pub agent: Id,
    pub chat_id: Id,
    pub title: &'a str,
    pub prompt: &'a str,
    pub schedule: JobSchedule,
    pub state: JobState,
    pub proposed_by_agent: bool,
}

pub fn create_job(conn: &Connection, j: &NewJob<'_>, now_ms: i64) -> Result<(), DbError> {
    let next = (j.state == JobState::Active).then_some(j.schedule.first_run_at_ms.max(now_ms));
    conn.execute(
        "INSERT INTO jobs (id, agent, chat_id, title, prompt, first_run_at_ms, every_secs,
             next_run_at_ms, state, attempts, proposed_by_agent, progress, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, '', ?11, ?11)",
        params![
            j.id.to_string(),
            j.agent.to_string(),
            j.chat_id.to_string(),
            j.title,
            j.prompt,
            j.schedule.first_run_at_ms,
            j.schedule.every_secs,
            next,
            job_state_str(j.state),
            j.proposed_by_agent,
            now_ms
        ],
    )?;
    Ok(())
}

/// Open (proposed or active) jobs an agent has, and how many of them are proposals.
pub fn open_jobs_of(conn: &Connection, agent: Id) -> Result<(i64, i64), DbError> {
    Ok(conn.query_row(
        "SELECT count(*), coalesce(sum(state = 'proposed'), 0) FROM jobs
         WHERE agent = ?1 AND state IN ('proposed', 'active')",
        params![agent.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

const JOB_COLUMNS: &str = "j.id, j.agent, j.chat_id, j.title, j.prompt, j.first_run_at_ms, \
    j.every_secs, j.next_run_at_ms, j.state, j.attempts, j.proposed_by_agent, j.progress";

fn job_from_row(conn: &Connection, r: &rusqlite::Row<'_>) -> Result<JobView, DbError> {
    let id = get_id(r, 0)?;
    let last_run = conn
        .query_row(
            "SELECT started_at_ms, finished_at_ms, outcome, detail FROM job_runs
             WHERE job = ?1 ORDER BY started_at_ms DESC, rowid DESC LIMIT 1",
            params![id.to_string()],
            |x| {
                Ok((
                    x.get::<_, i64>(0)?,
                    x.get::<_, Option<i64>>(1)?,
                    x.get::<_, Option<String>>(2)?,
                    x.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let last_run = match last_run {
        Some((started_at_ms, finished_at_ms, outcome, detail)) => Some(JobRunView {
            started_at_ms,
            finished_at_ms,
            outcome: outcome.as_deref().map(outcome_from).transpose()?,
            detail,
        }),
        None => None,
    };
    let running = last_run.as_ref().is_some_and(|r| r.finished_at_ms.is_none());
    Ok(JobView {
        id,
        agent: get_id(r, 1)?,
        chat_id: get_id(r, 2)?,
        title: r.get(3)?,
        prompt: r.get(4)?,
        schedule: JobSchedule { first_run_at_ms: r.get(5)?, every_secs: r.get(6)? },
        next_run_at_ms: r.get(7)?,
        state: job_state_from(&r.get::<_, String>(8)?)?,
        attempts: r.get(9)?,
        proposed_by_agent: r.get(10)?,
        progress: r.get(11)?,
        running,
        last_run,
    })
}

pub fn job(conn: &Connection, id: Id) -> Result<Option<JobView>, DbError> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM jobs j WHERE j.id = ?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![id.to_string()])?;
    match rows.next()? {
        Some(r) => Ok(Some(job_from_row(conn, r)?)),
        None => Ok(None),
    }
}

/// Every job, open ones first, newest first.
pub fn jobs(conn: &Connection) -> Result<Vec<JobView>, DbError> {
    let sql = format!(
        "SELECT {JOB_COLUMNS} FROM jobs j
         ORDER BY (j.state IN ('proposed', 'active')) DESC, j.created_at_ms DESC LIMIT 500"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = vec![];
    while let Some(r) = rows.next()? {
        out.push(job_from_row(conn, r)?);
    }
    Ok(out)
}

pub fn set_job_state(
    conn: &Connection,
    id: Id,
    state: JobState,
    next_run_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<bool, DbError> {
    Ok(conn.execute(
        "UPDATE jobs SET state = ?2, next_run_at_ms = ?3, updated_at_ms = ?4,
             attempts = CASE WHEN ?2 = 'active' THEN attempts ELSE attempts END
         WHERE id = ?1",
        params![id.to_string(), job_state_str(state), next_run_at_ms, now_ms],
    )? > 0)
}

/// An open run: (run id, job id, agent, deadline).
pub type OpenRun = (Id, Id, Id, i64);

pub fn open_runs(conn: &Connection) -> Result<Vec<OpenRun>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT r.id, r.job, j.agent, r.deadline_ms FROM job_runs r JOIN jobs j ON j.id = r.job
         WHERE r.finished_at_ms IS NULL",
    )?;
    let rows = stmt
        .query_map([], |r| Ok((get_id(r, 0)?, get_id(r, 1)?, get_id(r, 2)?, r.get(3)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The open run with this id, if it belongs to one of `agent`'s jobs: (job id).
pub fn open_run_of(conn: &Connection, run: Id, agent: Id) -> Result<Option<Id>, DbError> {
    conn.query_row(
        "SELECT r.job FROM job_runs r JOIN jobs j ON j.id = r.job
         WHERE r.id = ?1 AND j.agent = ?2 AND r.finished_at_ms IS NULL",
        params![run.to_string(), agent.to_string()],
        |r| get_id(r, 0),
    )
    .optional()
    .map_err(Into::into)
}

/// Active jobs that are due and not running: (job id, agent).
pub fn due_jobs(conn: &Connection, now_ms: i64) -> Result<Vec<(Id, Id)>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT j.id, j.agent FROM jobs j
         WHERE j.state = 'active' AND j.next_run_at_ms IS NOT NULL AND j.next_run_at_ms <= ?1
           AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job = j.id AND r.finished_at_ms IS NULL)
         ORDER BY j.next_run_at_ms LIMIT 100",
    )?;
    let rows = stmt
        .query_map(params![now_ms], |r| Ok((get_id(r, 0)?, get_id(r, 1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn start_run(
    conn: &Connection,
    run: Id,
    job: Id,
    now_ms: i64,
    deadline_ms: i64,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO job_runs (id, job, started_at_ms, deadline_ms) VALUES (?1, ?2, ?3, ?4)",
        params![run.to_string(), job.to_string(), now_ms, deadline_ms],
    )?;
    conn.execute(
        "UPDATE jobs SET progress = '', updated_at_ms = ?2 WHERE id = ?1",
        params![job.to_string(), now_ms],
    )?;
    Ok(())
}

pub fn set_job_progress(
    conn: &Connection,
    job: Id,
    text: &str,
    now_ms: i64,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE jobs SET progress = ?2, updated_at_ms = ?3 WHERE id = ?1",
        params![job.to_string(), text, now_ms],
    )?;
    Ok(())
}

/// Close a run and move its job on: the next slot (repeating jobs), done (one-off),
/// a retry with backoff, or failed after `MAX_ATTEMPTS`. `count_attempt`: whether a
/// failure counts toward the limit (a pause doesn't).
pub fn finish_run(
    conn: &mut Connection,
    run: Id,
    outcome: RunOutcome,
    detail: &str,
    count_attempt: bool,
    now_ms: i64,
) -> Result<Option<Id>, DbError> {
    let tx = conn.transaction()?;
    let job: Option<Id> = tx
        .query_row(
            "SELECT job FROM job_runs WHERE id = ?1 AND finished_at_ms IS NULL",
            params![run.to_string()],
            |r| get_id(r, 0),
        )
        .optional()?;
    let Some(job) = job else { return Ok(None) };
    tx.execute(
        "UPDATE job_runs SET finished_at_ms = ?2, outcome = ?3, detail = ?4 WHERE id = ?1",
        params![run.to_string(), now_ms, outcome_str(outcome), detail],
    )?;
    let Some(view) = self::job(&tx, job)? else { return Ok(None) };
    if view.state == JobState::Active {
        let (state, next, attempts) = match outcome {
            RunOutcome::Ok => match next_slot(&view.schedule, now_ms) {
                Some(next) => (JobState::Active, Some(next), 0),
                None => (JobState::Done, None, 0),
            },
            RunOutcome::Cancelled => (view.state, view.next_run_at_ms, view.attempts),
            RunOutcome::Failed | RunOutcome::Lost if !count_attempt => {
                (JobState::Active, Some(now_ms), view.attempts)
            }
            RunOutcome::Failed | RunOutcome::Lost => {
                let attempts = view.attempts + 1;
                if attempts >= MAX_ATTEMPTS {
                    // A repeating job skips to its next slot; a one-off gives up.
                    match next_slot(&view.schedule, now_ms) {
                        Some(next) => (JobState::Active, Some(next), 0),
                        None => (JobState::Failed, None, attempts),
                    }
                } else {
                    let backoff = 60_000i64 << (attempts - 1).min(10);
                    (JobState::Active, Some(now_ms + backoff), attempts)
                }
            }
        };
        tx.execute(
            "UPDATE jobs SET state = ?2, next_run_at_ms = ?3, attempts = ?4, updated_at_ms = ?5 WHERE id = ?1",
            params![job.to_string(), job_state_str(state), next, attempts, now_ms],
        )?;
    }
    tx.commit()?;
    Ok(Some(job))
}

/// The agent's direct chat with the user (where its jobs post).
pub fn direct_chat_of(conn: &Connection, agent: Id, user: Id) -> Result<Option<Id>, DbError> {
    conn.query_row(
        "SELECT c.id FROM chats c
         JOIN chat_members a ON a.chat_id = c.id AND a.principal_id = ?1
         JOIN chat_members u ON u.chat_id = c.id AND u.principal_id = ?2
         WHERE c.kind = 'direct' LIMIT 1",
        params![agent.to_string(), user.to_string()],
        |r| get_id(r, 0),
    )
    .optional()
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        Id::from_bytes([n; 16])
    }

    fn open_tmp() -> (tempfile::TempDir, Db) {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let db = Db::open(&tmp.path().join("t.db"), uid).expect("open");
        (tmp, db)
    }

    /// user (1) and agent (2) in direct chat (10); agent 3 is not a member.
    fn seed(conn: &mut Connection) {
        ensure_user(conn, id(1), "You", 0).expect("user");
        for n in [2u8, 3] {
            conn.execute(
                "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'agent', 'a', 0)",
                params![id(n).to_string()],
            )
            .expect("agent");
        }
        create_chat(conn, id(10), ChatKind::Direct, &[id(1), id(2)], 0).expect("chat");
    }

    fn md(text: &str) -> Content {
        Content::Markdown { text: text.to_owned() }
    }

    fn msg(n: u8, sender: Id, content: &Content) -> NewMessage<'_> {
        NewMessage {
            id: id(100 + n),
            chat_id: id(10),
            thread_id: None,
            sender_id: sender,
            recipient_id: None,
            client_msg_id: id(200 + n),
            content,
            depth: 0,
        }
    }

    #[test]
    fn new_db_file_is_private_and_reopens() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let path = tmp.path().join("t.db");
        drop(Db::open(&path, uid).expect("open"));
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(Db::open(&path, uid).expect("reopen runs no migrations twice"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(Db::open(&path, uid), Err(DbError::Perm(_))));
    }

    #[test]
    fn refuses_newer_schema() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let path = tmp.path().join("t.db");
        let db = Db::open(&path, uid).expect("open");
        db.call_blocking(|c| Ok(c.pragma_update(None, "user_version", 99)?)).expect("bump");
        drop(db);
        assert!(matches!(Db::open(&path, uid), Err(DbError::TooNew { found: 99, .. })));
    }

    #[test]
    fn refuses_symlinked_db() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let real = tmp.path().join("real.db");
        drop(Db::open(&real, uid).expect("open"));
        let link = tmp.path().join("link.db");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(Db::open(&link, uid).is_err());
    }

    #[test]
    fn messages_are_append_only() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            assert!(matches!(append_message(c, &msg(1, id(1), &md("hello")), 5)?, Appended::New(m) if m.seq == 1));
            assert!(c.execute("UPDATE messages SET body = 'tampered'", []).is_err());
            assert!(c.execute("DELETE FROM messages", []).is_err());
            // REPLACE and UPSERT are deletes/updates in disguise.
            let overwrite = "INSERT OR REPLACE INTO messages
                (seq, id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, body, created_at_ms)
                SELECT seq, id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, 'tampered', created_at_ms
                FROM messages";
            assert!(c.execute(overwrite, []).is_err());
            let upsert = "INSERT INTO messages
                (seq, id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, body, created_at_ms)
                SELECT seq, id, chat_id, thread_id, sender_id, recipient_id, client_msg_id, 'x', created_at_ms
                FROM messages WHERE true ON CONFLICT DO UPDATE SET body = 'tampered'";
            assert!(c.execute(upsert, []).is_err());
            // Deleting a chat or membership out from under the log is blocked by foreign keys.
            assert!(c.execute("DELETE FROM chat_members", []).is_err());
            assert!(c.execute("DELETE FROM chats", []).is_err());
            let all = messages_after(c, id(10), 0, 10)?;
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].content, md("hello"));
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn writable_schema_is_blocked() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            // Defensive mode: can't flip writable_schema to drop the triggers behind SQLite's back.
            let _ = c.execute_batch("PRAGMA writable_schema = ON;");
            assert!(
                c.execute(
                    "UPDATE sqlite_schema SET sql = '' WHERE name = 'messages_no_update'",
                    []
                )
                .is_err()
            );
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn sender_and_recipient_must_be_members() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            assert!(append_message(c, &msg(1, id(3), &md("not a member")), 1).is_err());
            let outsider = md("to outsider");
            let mut m = msg(2, id(1), &outsider);
            m.recipient_id = Some(id(3));
            assert!(append_message(c, &m, 1).is_err());
            let member = md("to member");
            let mut m = msg(3, id(1), &member);
            m.recipient_id = Some(id(2));
            assert!(append_message(c, &m, 1).is_ok());
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn idempotent_append_and_server_ordering() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            assert!(matches!(append_message(c, &msg(1, id(1), &md("a")), 1)?, Appended::New(m) if m.seq == 1));
            assert!(matches!(append_message(c, &msg(2, id(2), &md("b")), 2)?, Appended::New(m) if m.seq == 2));
            // Retry with the same client_msg_id: no duplicate, original seq.
            let a = md("a");
            let mut retry = msg(1, id(1), &a);
            retry.id = id(150);
            assert!(matches!(append_message(c, &retry, 3)?, Appended::Duplicate(m) if m.seq == 1 && m.created_at_ms == 1));
            let after1 = messages_after(c, id(10), 1, 10)?;
            assert_eq!(after1.len(), 1);
            assert_eq!(after1[0].seq, 2);
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn chats_titles_and_membership() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            let note = ensure_note_to_self(c, id(1), id(20), 0)?;
            assert_eq!(note, id(20));
            assert_eq!(ensure_note_to_self(c, id(1), id(21), 0)?, id(20), "idempotent");
            // Another chat the user is not in.
            create_chat(c, id(11), ChatKind::AgentToAgent, &[id(2), id(3)], 0)?;
            let hello = md("hello");
            append_message(c, &msg(1, id(1), &hello), 5)?;

            let chats = chats_for(c, id(1), false)?;
            let ids: Vec<Id> = chats.iter().map(|ch| ch.id).collect();
            assert_eq!(ids, vec![id(10), id(20)], "most recently active first; no foreign chats");
            assert_eq!(chats[0].title, "a");
            assert_eq!(chats[0].last_message.as_ref().map(|m| &m.content), Some(&hello));
            assert_eq!(chats[1].title, "Note to Self");
            assert_eq!(chats[1].kind, ChatKind::NoteToSelf);

            assert!(chat_if_member(c, id(10), id(1))?.is_some());
            assert!(chat_if_member(c, id(11), id(1))?.is_none(), "not a member");
            assert!(chat_if_member(c, id(99), id(1))?.is_none(), "no such chat");
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn schema_rejects_bad_values() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            let big = "x".repeat(65537);
            assert!(append_message(c, &msg(1, id(1), &md(&big)), 1).is_err());
            assert!(append_message(c, &msg(2, id(1), &md("")), 1).is_err());
            // Raw SQL bypassing Rust types still hits CHECKs.
            assert!(c
                .execute(
                    "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES ('ABC', 'agent', 'x', 0)",
                    []
                )
                .is_err());
            assert!(c
                .execute(
                    "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'admin', 'x', 0)",
                    params![id(9).to_string()]
                )
                .is_err());
            // STRICT: no type coercion.
            assert!(c.execute("UPDATE login_throttle SET consecutive_failures = 'lots'", []).is_err());
            // Only one user principal can exist.
            assert!(c
                .execute(
                    "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'user', 'x', 0)",
                    params![id(9).to_string()]
                )
                .is_err());
            // Only argon2id hashes can be stored.
            assert!(set_password_hash(c, "$2b$12$bcrypt...", 0).is_err());
            assert!(set_password_hash(c, "plaintext", 0).is_err());
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn devices_rotate_expire_and_are_capped() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            rotate_device(c, None, [1; 32], 10, 1000, 2)?;
            assert!(device_throttle(c, &[1; 32], 10)?.is_some());
            assert!(device_throttle(c, &[1; 32], 1000)?.is_none(), "expired");
            // Rotation retires the presented token.
            rotate_device(c, Some([1; 32]), [2; 32], 20, 1000, 2)?;
            assert!(device_throttle(c, &[1; 32], 20)?.is_none());
            assert!(device_throttle(c, &[2; 32], 20)?.is_some());
            // Cap of 2: the least recently used device goes.
            rotate_device(c, None, [3; 32], 30, 1000, 2)?;
            rotate_device(c, None, [4; 32], 40, 1000, 2)?;
            assert!(device_throttle(c, &[2; 32], 40)?.is_none());
            assert!(device_throttle(c, &[3; 32], 40)?.is_some());
            // Per-device throttle state.
            let locked = Throttle { consecutive_failures: 3, locked_until_ms: 99 };
            set_device_throttle(c, &[3; 32], locked)?;
            assert_eq!(device_throttle(c, &[3; 32], 40)?, Some(locked));
            assert_eq!(device_throttle(c, &[4; 32], 40)?, Some(Throttle::default()));
            // A password change forgets every device.
            set_password_hash(c, "$argon2id$v=19$m=65536,t=3,p=4$x$y", 50)?;
            assert!(device_throttle(c, &[3; 32], 50)?.is_none());
            assert!(device_throttle(c, &[4; 32], 50)?.is_none());
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn session_cap_evicts_oldest() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            let row = |n: u8, t: i64| SessionRow {
                token_hash: [n; 32],
                principal_id: id(1),
                created_at_ms: t,
                last_seen_at_ms: t,
                expires_at_ms: t + 1000,
            };
            assert!(insert_session(c, &row(1, 1), 2)?.is_empty());
            assert!(insert_session(c, &row(2, 2), 2)?.is_empty());
            assert_eq!(insert_session(c, &row(3, 3), 2)?, vec![[1u8; 32]]);
            assert!(session(c, &[1; 32])?.is_none());
            assert!(session(c, &[3; 32])?.is_some());
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn usage_rows_are_pruned_by_age() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            record_usage(c, id(2), 0, 10, 10)?;
            record_usage(c, id(2), 50_000_000, 1, 1)?;
            assert_eq!(prune_usage(c, 25_000_000)?, 1, "only the row older than the cut goes");
            assert_eq!(usage_since(c, id(2), 0)?, 2, "the recent row remains");
            assert_eq!(prune_usage(c, 25_000_000)?, 0, "pruning is idempotent");
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn password_change_revokes_sessions() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            seed(c);
            let row = SessionRow {
                token_hash: [7; 32],
                principal_id: id(1),
                created_at_ms: 0,
                last_seen_at_ms: 0,
                expires_at_ms: 10,
            };
            insert_session(c, &row, 8)?;
            assert_eq!(set_password_hash(c, "$argon2id$v=19$m=65536,t=3,p=4$x$y", 1)?, 1);
            assert!(session(c, &[7; 32])?.is_none());
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn agents_profiles_and_avatars() {
        let (_tmp, db) = open_tmp();
        db.call_blocking(|c| {
            ensure_user(c, id(1), "You", 0)?;
            let new = NewAgent {
                user: id(1),
                agent: id(5),
                chat: id(50),
                name: "Mochi",
                label: "Research",
                about: "Looks things up.",
            };
            let a = create_agent(c, &new, 7)?;
            assert_eq!(
                (a.name.as_str(), a.label.as_str(), a.kind),
                ("Mochi", "Research", PrincipalKind::Agent)
            );
            let chats = chats_for(c, id(1), false)?;
            assert!(
                chats.iter().any(|ch| ch.id == id(50)
                    && ch.title == "Mochi"
                    && ch.kind == ChatKind::Direct)
            );
            // The direct chat's members carry the profile.
            let row = chats.iter().find(|ch| ch.id == id(50)).expect("chat");
            assert!(row.members.iter().any(|m| m.label == "Research"));

            let updated = update_agent(c, id(5), "Mochi 2", "", "")?.expect("agent");
            assert_eq!(updated.name, "Mochi 2");
            // The user principal can't be edited through the agent path.
            assert!(update_agent(c, id(1), "Mallory", "", "")?.is_none());

            // Pictures must be stored blobs.
            let h = BlobHash::from_bytes([9; 32]);
            assert!(set_avatar(c, id(5), Some(h)).is_err(), "unknown blob rejected by FK");
            put_blob(c, &h, "image/png", b"png", 1)?;
            put_blob(c, &h, "image/png", b"png", 2)?; // idempotent
            assert_eq!(set_avatar(c, id(5), Some(h))?.and_then(|m| m.avatar), Some(h));
            assert!(blob_exists(c, &h)?);
            assert_eq!(get_blob(c, &h)?, Some(("image/png".into(), b"png".to_vec())));
            assert!(
                put_blob(c, &BlobHash::from_bytes([1; 32]), "text/html", b"<x>", 1).is_err(),
                "only PNG"
            );
            assert!(
                c.execute(
                    "UPDATE principals SET label = ?1 WHERE id = ?2",
                    params!["x".repeat(33), id(5).to_string()]
                )
                .is_err()
            );
            Ok(())
        })
        .expect("ok");
    }

    #[test]
    fn migration_2_upgrades_a_version_1_database() {
        // A data dir created before profiles existed must upgrade in place.
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        let path = tmp.path().join("old.db");
        fsperm::write_new_private_file(&path, b"").expect("file");
        {
            let mut conn = Connection::open(&path).expect("open");
            let tx = conn.transaction().expect("tx");
            tx.execute_batch(&migrations()[0]).expect("v1");
            tx.pragma_update(None, "user_version", 1).expect("ver");
            tx.execute(
                "INSERT INTO principals (id, kind, display_name, created_at_ms) VALUES (?1, 'agent', 'Old', 0)",
                params![id(3).to_string()],
            )
            .expect("old agent");
            tx.commit().expect("commit");
        }
        let db = Db::open(&path, uid).expect("upgrade");
        db.call_blocking(|c| {
            let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            assert_eq!(v, migrations().len() as i64);
            let m = member(c, id(3))?.expect("old agent survives");
            assert_eq!((m.label.as_str(), m.about.as_str(), m.avatar), ("", "", None));
            Ok(())
        })
        .expect("ok");
    }
}
