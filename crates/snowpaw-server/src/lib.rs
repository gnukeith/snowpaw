//! snowpaw sync server: the single source of truth for chats, agents, and jobs.
//!
//! See `docs/threat-model.md` for what each control here defends against.

mod agent_ws;
pub mod api;
pub mod auth;
mod chat_ops;
pub mod clock;
pub mod config;
pub mod db;
pub mod fetch;
pub mod fsperm;
pub mod inference;
mod jobs;
pub mod listener;
pub mod logging;
mod plugins;
pub mod secrets;
pub mod server;
pub mod setup;
pub mod tls;
mod ws;
