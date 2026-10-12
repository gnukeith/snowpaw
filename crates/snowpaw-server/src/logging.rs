//! Logging setup. The level comes from the config file only, never from an
//! environment variable, and dependencies are capped at `warn`: some libraries log
//! frame or header contents at debug/trace, and those can contain tokens or messages.

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogLevel;

pub fn targets(level: LogLevel) -> Targets {
    let ours = match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    };
    Targets::new()
        .with_default(LevelFilter::WARN.min(ours))
        .with_target("snowpaw_server", ours)
        .with_target("snowpaw_proto", ours)
}

/// Install the global subscriber, writing to stderr.
pub fn init(level: LogLevel) {
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_target(false))
        .with(targets(level))
        .try_init();
}
