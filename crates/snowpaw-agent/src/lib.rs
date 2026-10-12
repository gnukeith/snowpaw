//! snowpaw agent runtime: runs one agent.
//!
//! It connects to the sync server (and nothing else) with the agent's own token,
//! answers messages in the agent's chats by asking the server to run the agent's
//! model, and can send quizzes and talk to other agents the user allowed. It holds no
//! API keys and no state: everything comes from the server. Meant to run in its own
//! rootless Podman container or VM with network access to the server only.

pub mod brain;
pub mod config;
pub mod conn;
pub mod plugins;
pub mod runtime;
