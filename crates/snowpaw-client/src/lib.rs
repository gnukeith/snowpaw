//! snowpaw desktop client.

pub mod app;
pub mod config;
pub mod markdown;
pub mod net;
pub mod render;
pub mod store;
pub mod timefmt;
pub mod tls;
pub mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use snowpaw_proto::SecretString;
use snowpaw_proto::agent::{ApiKeyChange, ModelSettings, check_api_key};
use snowpaw_proto::ws::Content;

use slint::{ComponentHandle, Model, SharedString};
use tokio::sync::mpsc::UnboundedSender;

use crate::app::Command;

/// The UI compiled from `ui/app.slint`. Generated code: it carries Slint's own
/// unsafe-code allowance for its vtables (see the lint note in Cargo.toml).
mod generated {
    #![allow(missing_debug_implementations, clippy::all, clippy::restriction)]
    slint::include_modules!();
}
pub use generated::{
    AgentLinkRow, AgentSetup, AppWindow, AuditRow, ChatRow, Conversation, HostRow, JobRow,
    MessageRow, MsgBlock, Person, PluginAgentRow, PluginPreview, PluginRow, PluginTool, Quiz,
    QuizQuestion, Theme, TimelineRow,
};

const USAGE: &str = "\
snowpaw: desktop client for your snowpaw server

USAGE:
    snowpaw [--settings-dir <DIR>]

OPTIONS:
    --settings-dir <DIR>   Where to keep settings (default: the platform config folder)
    --help, --version
";

fn parse_args() -> Result<Option<Option<PathBuf>>, String> {
    let mut args = std::env::args_os().skip(1);
    let mut dir = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--settings-dir") if dir.is_none() => {
                let d = PathBuf::from(args.next().ok_or("--settings-dir needs a folder")?);
                if !d.is_absolute() {
                    return Err("--settings-dir must be an absolute path".into());
                }
                dir = Some(d);
            }
            Some("--help" | "-h") => {
                print!("{USAGE}");
                return Ok(None);
            }
            Some("--version" | "-V") => {
                println!("snowpaw {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            _ => return Err(format!("unexpected argument: {}", arg.to_string_lossy())),
        }
    }
    Ok(Some(dir))
}

/// The picture chosen for an agent that doesn't exist yet. UI thread only.
fn pending_picture() -> &'static std::thread::LocalKey<std::cell::RefCell<Option<PathBuf>>> {
    thread_local! {
        static PICTURE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }
    &PICTURE
}

/// Check the editor's fields as they change, so the form can explain problems
/// before anything is sent. The app checks again before acting.
fn validate_agent(w: &AppWindow, name: &str, label: &str, about: &str) {
    use snowpaw_proto::profile::{check_about, check_label, check_name};
    let (name, label, about) = (name.trim(), label.trim(), about.trim());
    let error = |r: Result<(), snowpaw_proto::profile::ProfileError>| match r {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    };
    // An empty name just keeps the button disabled; no need to scold.
    let name_error = if name.is_empty() { String::new() } else { error(check_name(name)) };
    let label_error = error(check_label(label));
    let about_error = error(check_about(about));
    let valid = !name.is_empty()
        && name_error.is_empty()
        && label_error.is_empty()
        && about_error.is_empty();
    let initials: String =
        name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default();
    w.set_editor_name_error(name_error.into());
    w.set_editor_label_error(label_error.into());
    w.set_editor_about_error(about_error.into());
    w.set_editor_valid(valid);
    w.set_editor_initials(initials.into());
}

fn wire_agent_editor(window: &AppWindow, tx: &UnboundedSender<Command>) {
    {
        let weak = window.as_weak();
        window.on_editor_validate(move |name, label, about| {
            if let Some(w) = weak.upgrade() {
                validate_agent(&w, &name, &label, &about);
            }
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_choose_picture(move |agent| {
            let tx = tx.clone();
            let weak = weak.clone();
            app::choose_picture(move |path| {
                if agent.is_empty() {
                    // A new agent: keep the file until the agent exists.
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    if let Some(w) = weak.upgrade() {
                        w.set_editor_picture_name(name.unwrap_or_default().into());
                    }
                    pending_picture().with(|p| *p.borrow_mut() = Some(path));
                } else {
                    let _ = tx.send(Command::SetAvatarFromFile { agent: agent.into(), path });
                }
            });
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_remove_picture(move |agent| {
            if agent.is_empty() {
                pending_picture().with(|p| *p.borrow_mut() = None);
                if let Some(w) = weak.upgrade() {
                    w.set_editor_picture_name(Default::default());
                }
            } else {
                let _ = tx.send(Command::ClearAvatar { agent: agent.into() });
            }
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_create_agent(move |name, label, about| {
            let picture = pending_picture().with(|p| p.borrow_mut().take());
            if let Some(w) = weak.upgrade() {
                w.set_editor_picture_name(Default::default());
            }
            let _ = tx.send(Command::CreateAgent {
                name: name.trim().into(),
                label: label.trim().into(),
                about: about.trim().into(),
                picture,
            });
        });
    }
    {
        let tx = tx.clone();
        window.on_update_agent(move |agent, name, label, about| {
            let _ = tx.send(Command::UpdateAgent {
                agent: agent.into(),
                name: name.trim().into(),
                label: label.trim().into(),
                about: about.trim().into(),
            });
        });
    }
}

/// Read the model form (in the order the UI sends it) into settings to save, or
/// explain what's wrong.
fn parse_model_form(f: &[SharedString]) -> Result<(ModelSettings, ApiKeyChange), String> {
    let field = |i: usize| f.get(i).map(|s| s.trim().to_owned()).unwrap_or_default();
    let number = |i: usize, what: &str| {
        field(i).parse::<u64>().map_err(|_| format!("{what} must be a whole number."))
    };
    let pin = field(2);
    let model = ModelSettings {
        base_url: field(0),
        model: field(1),
        tls_pin: (!pin.is_empty()).then_some(pin),
        instructions: f.get(3).map(|s| s.to_string()).unwrap_or_default(),
        max_reply_tokens: u32::try_from(number(4, "Reply length")?)
            .map_err(|_| "Reply length is too large.".to_owned())?,
        context_messages: u32::try_from(number(5, "Memory")?)
            .map_err(|_| "Memory is too large.".to_owned())?,
        daily_token_limit: number(6, "Daily limit")?,
    };
    model.validate().map_err(|e| e.to_string())?;
    let api_key = match field(7).as_str() {
        "clear" => ApiKeyChange::Clear,
        "set" => {
            let key = f.get(8).map(|s| s.trim().to_owned()).unwrap_or_default();
            check_api_key(&key).map_err(|e| e.to_string())?;
            ApiKeyChange::Set { key: SecretString::new(key) }
        }
        _ => ApiKeyChange::Keep,
    };
    Ok((model, api_key))
}

fn wire_agents(window: &AppWindow, tx: &UnboundedSender<Command>) {
    let send = |tx: &UnboundedSender<Command>| {
        let tx = tx.clone();
        move |c: Command| {
            let _ = tx.send(c);
        }
    };
    {
        let send = send(tx);
        window.on_set_agents_paused(move |on| send(Command::SetAgentsPaused(on)));
    }
    {
        let send = send(tx);
        let weak = window.as_weak();
        window.on_save_model(move |agent, fields| {
            let Some(w) = weak.upgrade() else { return };
            let fields: Vec<SharedString> = fields.iter().collect();
            match parse_model_form(&fields) {
                Ok((model, api_key)) => {
                    w.set_model_error(SharedString::new());
                    send(Command::SetAgentModel { agent: agent.into(), model, api_key });
                }
                Err(e) => w.set_model_error(e.into()),
            }
        });
    }
    {
        let send = send(tx);
        window.on_issue_token(move |agent| send(Command::IssueAgentToken { agent: agent.into() }));
    }
    {
        let send = send(tx);
        window
            .on_revoke_token(move |agent| send(Command::RevokeAgentToken { agent: agent.into() }));
    }
    {
        let send = send(tx);
        window.on_set_agent_link(move |a, b, allowed| {
            send(Command::SetAgentLink { a: a.into(), b: b.into(), allowed });
        });
    }
    {
        let weak = window.as_weak();
        window.on_quiz_pick(move |message, question, choice| {
            if let (Some(w), Ok(q), Ok(c)) =
                (weak.upgrade(), usize::try_from(question), usize::try_from(choice))
            {
                ui::quiz_pick(&w, &message, q, c);
            }
        });
    }
    {
        let send = send(tx);
        window.on_quiz_submit(move |message| {
            if let Some(answers) = ui::quiz_answers(&message) {
                send(Command::AnswerQuiz { message_id: message.into(), answers });
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_quiz_retry(move |message| {
            if let Some(w) = weak.upgrade() {
                ui::quiz_retry(&w, &message);
            }
        });
    }
    {
        let send = send(tx);
        window.on_load_audit(move |older| send(Command::LoadAudit { older }));
    }
    {
        // The token is a secret: drop it from the UI as soon as the dialog closes.
        let weak = window.as_weak();
        window.on_close_token(move || {
            if let Some(w) = weak.upgrade() {
                w.set_token_open(false);
                w.set_token_secret(SharedString::new());
                w.set_token_code(SharedString::new());
                w.set_token_agent(SharedString::new());
            }
        });
    }
}

/// The plugin file waiting for the user to confirm installing it. UI thread only.
fn pending_plugin() -> &'static std::thread::LocalKey<std::cell::RefCell<Option<PathBuf>>> {
    thread_local! {
        static PLUGIN: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }
    &PLUGIN
}

fn wire_plugins(window: &AppWindow, tx: &UnboundedSender<Command>) {
    {
        let tx = tx.clone();
        window.on_plugins_opened(move || {
            let _ = tx.send(Command::ListPlugins);
        });
    }
    {
        // Choose a file, then show what it says it can do. Nothing runs yet.
        let weak = window.as_weak();
        window.on_install_plugin(move || {
            let weak = weak.clone();
            app::choose_plugin(move |path| {
                let Some(w) = weak.upgrade() else { return };
                match app::plugin_preview(&path) {
                    Ok(p) => {
                        ui::show_plugin_preview(
                            &w,
                            &p.name,
                            &p.version,
                            &p.description,
                            &p.tools,
                            &p.http_hosts,
                            &p.sha256,
                        );
                        pending_plugin().with(|f| *f.borrow_mut() = Some(path));
                    }
                    Err(e) => ui::show_plugin_error(&w, &e),
                }
            });
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_confirm_plugin_install(move || {
            if let Some(w) = weak.upgrade() {
                w.set_plugin_preview(Default::default());
            }
            if let Some(path) = pending_plugin().with(|f| f.borrow_mut().take()) {
                let _ = tx.send(Command::InstallPlugin { path });
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_cancel_plugin_install(move || {
            pending_plugin().with(|f| *f.borrow_mut() = None);
            if let Some(w) = weak.upgrade() {
                w.set_plugin_preview(Default::default());
            }
        });
    }
    {
        let tx = tx.clone();
        window.on_grant_plugin(move |agent, plugin, hosts| {
            let http_hosts = hosts.iter().map(|h| h.to_string()).collect();
            let _ = tx.send(Command::GrantPlugin {
                agent: agent.into(),
                plugin: plugin.into(),
                http_hosts,
            });
        });
    }
    {
        let tx = tx.clone();
        window.on_revoke_plugin(move |agent, plugin| {
            let _ = tx.send(Command::RevokePlugin { agent: agent.into(), plugin: plugin.into() });
        });
    }
    {
        let tx = tx.clone();
        window.on_toggle_plugin_host(move |agent, plugin, host| {
            if let Some(http_hosts) = ui::plugin_hosts_toggled(&agent, &plugin, &host) {
                let _ = tx.send(Command::GrantPlugin {
                    agent: agent.into(),
                    plugin: plugin.into(),
                    http_hosts,
                });
            }
        });
    }
    {
        let tx = tx.clone();
        window.on_remove_plugin(move |plugin| {
            let _ = tx.send(Command::RemovePlugin { plugin: plugin.into() });
        });
    }
}

fn wire_jobs(window: &AppWindow, tx: &UnboundedSender<Command>) {
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_create_job(move |agent, title, prompt, start, time, repeat| {
            use snowpaw_proto::jobs::{JobSchedule, check_job};
            let Some(w) = weak.upgrade() else { return };
            let first_run_at_ms = match ui::job_start_ms(start, &time) {
                Ok(t) => t,
                Err(e) => return w.set_job_error(e.into()),
            };
            let every_secs = match repeat {
                1 => Some(3_600),
                2 => Some(86_400),
                3 => Some(604_800),
                _ => None,
            };
            let (title, prompt) = (title.trim().to_owned(), prompt.trim().to_owned());
            let schedule = JobSchedule { first_run_at_ms, every_secs };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
                .unwrap_or(0);
            if let Err(e) = check_job(&title, &prompt, &schedule, now) {
                return w.set_job_error(e.to_string().into());
            }
            w.set_job_error(SharedString::new());
            w.set_job_dialog_open(false);
            let _ = tx.send(Command::CreateJob {
                agent: agent.into(),
                title,
                prompt,
                first_run_at_ms,
                every_secs,
            });
        });
    }
    {
        let tx = tx.clone();
        window.on_approve_job(move |job| {
            let _ = tx.send(Command::ApproveJob { job: job.into() });
        });
    }
    {
        let tx = tx.clone();
        window.on_cancel_job(move |job| {
            let _ = tx.send(Command::CancelJob { job: job.into() });
        });
    }
    {
        let tx = tx.clone();
        window.on_run_job(move |job| {
            let _ = tx.send(Command::RunJobNow { job: job.into() });
        });
    }
}

/// Run the desktop client. Returns the process exit code.
pub fn main_entry() -> ExitCode {
    let dir = match parse_args() {
        Ok(Some(dir)) => dir.or_else(config::default_dir),
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let window = match AppWindow::new() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: can't open a window: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Command>();

    {
        let tx = tx.clone();
        window.on_save_setup(move |server, fingerprint| {
            let _ = tx.send(Command::SaveSetup {
                server: server.into(),
                fingerprint: fingerprint.into(),
            });
        });
    }
    {
        let tx = tx.clone();
        window.on_cancel_setup(move || {
            let _ = tx.send(Command::CancelSetup);
        });
    }
    {
        let tx = tx.clone();
        window.on_open_setup(move || {
            let _ = tx.send(Command::OpenSetup);
        });
    }
    {
        let tx = tx.clone();
        window.on_login(move |password| {
            let _ = tx.send(Command::Login(SecretString::new(password.into())));
        });
    }
    {
        let tx = tx.clone();
        window.on_open_chat(move |id| {
            let _ = tx.send(Command::OpenChat(id.into()));
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_send(move |text| {
            let Some(w) = weak.upgrade() else { return false };
            let text = text.replace("\r\n", "\n");
            let max = usize::try_from(w.get_max_message_bytes()).unwrap_or(0);
            let content = Content::Markdown { text };
            match content.validate(max) {
                Ok(()) => {
                    w.set_notice(Default::default());
                    tx.send(Command::Send(content)).is_ok()
                }
                Err(snowpaw_proto::ws::ContentError::Empty) => false,
                Err(e) => {
                    w.set_notice(format!("Can't send: {e}.").into());
                    false
                }
            }
        });
    }
    {
        let tx = tx.clone();
        window.on_logout(move || {
            let _ = tx.send(Command::Logout);
        });
    }
    {
        let weak = window.as_weak();
        window.on_code_edited(move |code| {
            if let Some(w) = weak.upgrade() {
                ui::apply_setup_code(&w, &code);
            }
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_test_connection(move |server, fingerprint| {
            if let Some(w) = weak.upgrade() {
                ui::show_fingerprint(&w, &fingerprint);
            }
            let _ = tx.send(Command::TestConnection {
                server: server.into(),
                fingerprint: fingerprint.into(),
            });
        });
    }
    {
        let tx = tx.clone();
        let weak = window.as_weak();
        window.on_dismiss_welcome(move || {
            if let Some(w) = weak.upgrade() {
                w.set_welcome(false);
                ui::refresh_welcome(&w);
            }
            let _ = tx.send(Command::DismissWelcome);
        });
    }
    {
        // Applied right away, then saved.
        let weak = window.as_weak();
        let tx = tx.clone();
        window.on_set_reduce_motion(move |on| {
            if let Some(w) = weak.upgrade() {
                w.global::<Theme>().set_reduce_motion(on);
            }
            let _ = tx.send(Command::SetReduceMotion(on));
        });
    }
    wire_agent_editor(&window, &tx);
    wire_agents(&window, &tx);
    wire_plugins(&window, &tx);
    wire_jobs(&window, &tx);
    window.set_app_version(env!("CARGO_PKG_VERSION").into());
    {
        let tx = tx.clone();
        window.on_search(move |text| {
            ui::note_search(&text);
            let _ = tx.send(Command::Search(text.into()));
        });
    }
    {
        let tx = tx.clone();
        window.on_toggle_pin(move |id| {
            let _ = tx.send(Command::TogglePin(id.into()));
        });
    }
    {
        let tx = tx.clone();
        window.on_set_font(move |font| {
            let _ = tx.send(Command::SetFont(font.into()));
        });
    }
    {
        let tx = tx.clone();
        window.on_set_appearance(move |appearance| {
            let _ = tx.send(Command::SetAppearance(appearance.into()));
        });
    }
    {
        let tx = tx.clone();
        window.on_theme_changed(move |dark| {
            let _ = tx.send(Command::Theme(dark));
        });
    }
    // A monospace font that exists on each platform.
    window
        .global::<Theme>()
        .set_mono(if cfg!(target_os = "macos") { "Menlo" } else { "DejaVu Sans Mono" }.into());
    let _ = tx.send(Command::Theme(window.get_dark_mode()));
    drop(tx);

    let ui = ui::Ui::new(&window);
    let controller = std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("error: can't start the network runtime: {e}");
                return;
            }
        };
        runtime.block_on(app::run(dir, rx, ui));
    });

    let result = window.run();
    // Dropping the window drops the callbacks and with them the command channel,
    // which tells the controller to log out and stop.
    drop(window);
    let _ = controller.join();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
