//! `snowpaw-agent` command-line entry point.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use snowpaw_agent::{config, runtime};

const USAGE: &str = "\
snowpaw-agent: runs one snowpaw agent

USAGE:
    snowpaw-agent run --config <FILE>
        Connect to the server and run the agent whose token is in the config's
        token_file. Runs until stopped or until the token is revoked.

    snowpaw-agent --help | --version

CONFIG (TOML):
    # The connection code from `snowpaw-server connection-code`.
    server = \"snowpaw://127.0.0.1:7443#sha256:...\"
    # A file holding only this agent's runtime token (mode 0600 or 0400).
    token_file = \"/run/secrets/snowpaw-agent-token\"
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["run", "--config", path] => PathBuf::from(path),
        ["--version" | "-V"] => {
            println!("snowpaw-agent {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        [] | ["--help" | "-h" | "help"] => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("error: unexpected arguments\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt().with_target(false).with_writer(std::io::stderr).init();
    match start(&config) {
        Ok(reason) => {
            eprintln!("stopped: {reason}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn start(config: &Path) -> Result<String, String> {
    let cfg = config::Config::load(config).map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir();
    let uid = config::effective_uid(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if uid == 0 {
        return Err("refusing to run as root; run as an unprivileged user".into());
    }
    let token = config::load_token(&cfg.token_file, uid).map_err(|e| e.to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    Ok(rt.block_on(runtime::run(cfg, token)))
}
