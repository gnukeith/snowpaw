//! `snowpaw-server` command-line entry point.

use std::ffi::OsString;
use std::io::{BufRead, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use snowpaw_proto::{MAX_PASSWORD_BYTES, SecretString};
use snowpaw_server::clock::SystemClock;
use snowpaw_server::config::Config;
use snowpaw_server::server::Server;
use snowpaw_server::{logging, setup, tls};
use tracing::{error, info};

const USAGE: &str = "\
snowpaw-server: the snowpaw sync server

USAGE:
    snowpaw-server init <DATA_DIR>
        Create a new data directory (mode 0700) with a config file, database,
        and self-signed TLS certificate. Prints the connection code to paste
        into the desktop app.

    snowpaw-server set-password --config <FILE> [--stdin]
        Set or change the login password (at least 15 characters). Ends every
        existing session. Prompts on the terminal unless --stdin is given.

    snowpaw-server run --config <FILE>
        Start the server.

    snowpaw-server connection-code [--agents] --config <FILE>
        Print the connection code again (server address + certificate fingerprint).
        --agents prints the code for agent runtimes (server.agent_listen, if set).

    snowpaw-server fingerprint --config <FILE>
        Print the TLS certificate fingerprint that clients must pin.

    snowpaw-server --help | --version
";

#[derive(Debug)]
enum Cmd {
    Init(PathBuf),
    SetPassword { config: PathBuf, stdin: bool },
    Run(PathBuf),
    Fingerprint(PathBuf),
    ConnectionCode { config: PathBuf, agents: bool },
    Help,
    Version,
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<Cmd, String> {
    let Some(cmd) = args.next() else {
        return Ok(Cmd::Help);
    };
    let cmd = cmd.to_str().ok_or("invalid command")?.to_owned();
    let rest: Vec<OsString> = args.collect();
    let config_flag = |rest: &[OsString], allow_stdin: bool| -> Result<(PathBuf, bool), String> {
        let mut config = None;
        let mut stdin = false;
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            match arg.to_str() {
                Some("--config") if config.is_none() => {
                    config = Some(PathBuf::from(it.next().ok_or("--config needs a file")?));
                }
                Some("--stdin") if allow_stdin && !stdin => stdin = true,
                _ => return Err(format!("unexpected argument: {}", arg.to_string_lossy())),
            }
        }
        Ok((config.ok_or("--config <FILE> is required")?, stdin))
    };
    match cmd.as_str() {
        "init" => match rest.as_slice() {
            [dir] => Ok(Cmd::Init(PathBuf::from(dir))),
            _ => Err("usage: snowpaw-server init <DATA_DIR>".into()),
        },
        "set-password" => {
            config_flag(&rest, true).map(|(config, stdin)| Cmd::SetPassword { config, stdin })
        }
        "run" => config_flag(&rest, false).map(|(c, _)| Cmd::Run(c)),
        "fingerprint" => config_flag(&rest, false).map(|(c, _)| Cmd::Fingerprint(c)),
        "connection-code" => {
            let agents = rest.iter().any(|a| a == "--agents");
            let rest: Vec<OsString> = rest.into_iter().filter(|a| a != "--agents").collect();
            config_flag(&rest, false).map(|(config, _)| Cmd::ConnectionCode { config, agents })
        }
        "help" | "--help" | "-h" if rest.is_empty() => Ok(Cmd::Help),
        "--version" | "-V" if rest.is_empty() => Ok(Cmd::Version),
        other => Err(format!("unknown command: {other}")),
    }
}

fn main() -> ExitCode {
    let cmd = match parse_args(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match cmd {
        Cmd::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Cmd::Version => {
            println!("snowpaw-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Init(dir) => cmd_init(dir),
        Cmd::SetPassword { config, stdin } => cmd_set_password(config, stdin),
        Cmd::Fingerprint(config) => cmd_fingerprint(config),
        Cmd::ConnectionCode { config, agents } => cmd_connection_code(config, agents),
        Cmd::Run(config) => cmd_run(config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_init(dir: PathBuf) -> Result<(), String> {
    let report = setup::init(&dir, &SystemClock).map_err(|e| e.to_string())?;
    let config = report.config_path.display();
    println!("Initialized {}", dir.display());
    println!("Config: {config}");
    println!("TLS certificate fingerprint (pin this in clients):\n  {}", report.fingerprint);
    let cfg = Config::load(&report.config_path).map_err(|e| e.to_string())?;
    print_connection_code(&cfg)?;
    println!("\nNext: snowpaw-server set-password --config {config}");
    Ok(())
}

fn print_connection_code(cfg: &Config) -> Result<(), String> {
    let code = setup::connection_code(cfg).map_err(|e| e.to_string())?;
    println!("\nConnection code (paste this into the snowpaw app):\n\n    {code}\n");
    if cfg.server.listen.ip().is_loopback() {
        println!(
            "The server listens on {} only, so this code works on this machine. To connect \
             from another machine or VM, set server.listen (and allow_non_loopback) and run \
             connection-code again.",
            cfg.server.listen.ip()
        );
    }
    Ok(())
}

fn cmd_connection_code(config: PathBuf, agents: bool) -> Result<(), String> {
    let cfg = Config::load(&config).map_err(|e| e.to_string())?;
    if agents {
        let code = setup::agent_connection_code(&cfg).map_err(|e| e.to_string())?;
        println!("Agent connection code (for snowpaw-agent's `server` setting):\n\n    {code}\n");
        return Ok(());
    }
    print_connection_code(&cfg)
}

fn read_password(stdin: bool) -> Result<SecretString, String> {
    if stdin {
        // Bounded read: one line, at most a little over the maximum password size.
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .take(MAX_PASSWORD_BYTES as u64 + 2)
            .read_line(&mut line)
            .map_err(|e| format!("reading stdin: {e}"))?;
        let mut line = SecretString::new(line);
        let trimmed = line.expose().strip_suffix('\n').map(|s| s.strip_suffix('\r').unwrap_or(s));
        if let Some(t) = trimmed {
            line = SecretString::new(t.to_owned());
        }
        return Ok(line);
    }
    let first =
        SecretString::new(rpassword::prompt_password("New password: ").map_err(|e| e.to_string())?);
    let second = SecretString::new(
        rpassword::prompt_password("Repeat password: ").map_err(|e| e.to_string())?,
    );
    if first != second {
        return Err("passwords do not match".into());
    }
    Ok(first)
}

fn cmd_set_password(config: PathBuf, stdin: bool) -> Result<(), String> {
    let cfg = Config::load(&config).map_err(|e| e.to_string())?;
    let password = read_password(stdin)?;
    let revoked = setup::set_password(&cfg, &password, &SystemClock).map_err(|e| e.to_string())?;
    println!("Password set. {revoked} existing session(s) ended.");
    Ok(())
}

fn cmd_fingerprint(config: PathBuf) -> Result<(), String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let cfg = Config::load(&config).map_err(|e| e.to_string())?;
    let (cert, _) = cfg.tls_paths();
    let der =
        CertificateDer::from_pem_file(&cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    println!("{}", tls::fingerprint(&der));
    Ok(())
}

fn cmd_run(config: PathBuf) -> Result<(), String> {
    let cfg = Config::load(&config).map_err(|e| e.to_string())?;
    logging::init(cfg.log.level);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting runtime: {e}"))?;
    runtime
        .block_on(async move {
            let server =
                Server::bind(cfg, Arc::new(SystemClock)).await.map_err(|e| e.to_string())?;
            let addr = server.local_addr().map_err(|e| e.to_string())?;
            info!(%addr, fingerprint = server.fingerprint(), "listening (TLS 1.3)");
            server.run(shutdown_signal()).await;
            info!("shut down");
            Ok::<(), String>(())
        })
        .inspect_err(|e| error!("{e}"))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = async {
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = term => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cmd, String> {
        parse_args(args.iter().map(OsString::from))
    }

    #[test]
    fn cli_parsing() {
        assert!(matches!(parse(&[]), Ok(Cmd::Help)));
        assert!(matches!(parse(&["init", "/x"]), Ok(Cmd::Init(_))));
        assert!(parse(&["init"]).is_err());
        assert!(matches!(
            parse(&["connection-code", "--config", "/c"]),
            Ok(Cmd::ConnectionCode { agents: false, .. })
        ));
        assert!(matches!(
            parse(&["connection-code", "--agents", "--config", "/c"]),
            Ok(Cmd::ConnectionCode { agents: true, .. })
        ));
        assert!(parse(&["connection-code"]).is_err());
        assert!(parse(&["init", "/x", "/y"]).is_err());
        assert!(matches!(parse(&["run", "--config", "/c"]), Ok(Cmd::Run(_))));
        assert!(parse(&["run"]).is_err());
        assert!(parse(&["run", "--config", "/c", "--config", "/d"]).is_err());
        assert!(parse(&["run", "--config", "/c", "--stdin"]).is_err());
        assert!(parse(&["run", "--config", "/c", "--insecure"]).is_err());
        assert!(matches!(
            parse(&["set-password", "--stdin", "--config", "/c"]),
            Ok(Cmd::SetPassword { stdin: true, .. })
        ));
        assert!(parse(&["frobnicate"]).is_err());
    }
}
