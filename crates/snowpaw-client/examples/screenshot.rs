//! Development tool: render each client screen offscreen with sample data and save
//! them as BMP images, so the UI can be checked without a display or screen-recording
//! permission. Every main screen is rendered in both themes, and some at a narrow
//! window size. Not part of the shipped app.
//!
//!     cargo build -p snowpaw-render && cargo run -p snowpaw-client --example screenshot -- <OUT_DIR>
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::rc::Rc;

use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize};
use snowpaw_client::render::{RenderCache, RenderService, RenderedImage};
use snowpaw_client::store::{RenderView, Store};
use snowpaw_client::timefmt::TimeFmt;
use snowpaw_client::ui::{apply_chat_list, apply_conversation, apply_timeline};
use snowpaw_client::{AppWindow, Theme};
use snowpaw_proto::Id;
use snowpaw_proto::agent::ToolSpec;
use snowpaw_proto::jobs::{JobSchedule, JobState, JobView};
use snowpaw_proto::plugin::{PluginGrant, PluginView};
use snowpaw_proto::profile::BlobHash;
use snowpaw_proto::quiz::{Question, Quiz};
use snowpaw_proto::ws::{ChatKind, ChatSummary, Content, Member, MessageView, PrincipalKind};

struct Offscreen(Rc<MinimalSoftwareWindow>);

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.0.clone())
    }
}

fn save_bmp(path: &Path, w: u32, h: u32, px: &[PremultipliedRgbaColor]) {
    let row = w as usize * 4;
    let size = 54 + row * h as usize;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&(-(h as i32)).to_le_bytes()); // top-down
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&[0; 24]);
    for p in px {
        out.extend_from_slice(&[p.blue, p.green, p.red, 255]);
    }
    std::fs::write(path, out).unwrap();
}

struct Shooter {
    window: Rc<MinimalSoftwareWindow>,
    out: PathBuf,
}

impl Shooter {
    fn shot(&self, ui: &AppWindow, name: &str, w: u32, h: u32) {
        self.shot_in(ui, name, w, h, &[true, false]);
    }

    fn shot_in(&self, ui: &AppWindow, name: &str, w: u32, h: u32, themes: &[bool]) {
        self.window.set_size(PhysicalSize::new(w, h));
        // Let entrance animations and timers (onboarding) run to the end. Frames
        // must really render: elements shown conditionally only exist once drawn.
        let mut scratch = vec![PremultipliedRgbaColor::default(); (w * h) as usize];
        for _ in 0..30 {
            slint::platform::update_timers_and_animations();
            self.window.request_redraw();
            self.window.draw_if_needed(|r| {
                r.render(&mut scratch, w as usize);
            });
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        for &dark in themes {
            ui.global::<Theme>().set_appearance(if dark { "dark" } else { "light" }.into());
            let mut buf =
                vec![
                    PremultipliedRgbaColor { red: 255, green: 255, blue: 255, alpha: 255 };
                    (w * h) as usize
                ];
            for _ in 0..3 {
                slint::platform::update_timers_and_animations();
                self.window.request_redraw();
                self.window.draw_if_needed(|r| {
                    r.render(&mut buf, w as usize);
                });
            }
            let theme = if dark { "dark" } else { "light" };
            save_bmp(&self.out.join(format!("{name}-{theme}.bmp")), w, h, &buf);
        }
    }
}

const NOW: i64 = 1_791_723_900_000;
const MIN: i64 = 60_000;
const DAY: i64 = 24 * 60 * MIN;

fn id(n: u8) -> Id {
    // Varied first and last bytes give each sample a different avatar color.
    let mut b = [n; 16];
    b[15] = n.wrapping_mul(37);
    Id::from_bytes(b)
}

/// A made-up profile picture: a soft face on a tinted background, drawn in code
/// (the app itself only ever shows pictures decoded by the sandboxed worker).
fn sample_picture(bg: (u8, u8, u8)) -> RenderedImage {
    let n = 256u32;
    let mut px = Vec::with_capacity((n * n) as usize);
    for i in 0..n * n {
        let (x, y) = ((i % n) as f32, (i / n) as f32);
        let face =
            ((x - 128.0).powi(2) / 95f32.powi(2) + (y - 160.0).powi(2) / 85f32.powi(2)) < 1.0;
        let eye = |cx: f32| (x - cx).powi(2) + (y - 150.0).powi(2) < 100.0;
        let cheek = |cx: f32| (x - cx).powi(2) / 2.0 + (y - 178.0).powi(2) < 60.0;
        let c = if eye(96.0) || eye(160.0) {
            (11, 30, 58)
        } else if face && (cheek(84.0) || cheek(172.0)) {
            (255, 170, 185)
        } else if face {
            (246, 249, 252)
        } else {
            bg
        };
        px.push(slint::Rgba8Pixel { r: c.0, g: c.1, b: c.2, a: 255 });
    }
    let mut pixels = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(n, n);
    pixels.make_mut_slice().copy_from_slice(&px);
    RenderedImage { width: n, height: n, pixels }
}

fn picture_hash(n: u8) -> BlobHash {
    BlobHash::parse(&format!("{n:02x}").repeat(32)).unwrap()
}

fn member(n: u8, kind: PrincipalKind, name: &str, label: &str) -> Member {
    Member {
        id: id(n),
        kind,
        name: name.into(),
        label: label.into(),
        about: String::new(),
        // Bean and Mochi have pictures (see sample_store).
        avatar: (n == 2 || n == 3).then(|| picture_hash(n)),
    }
}

const RICH: &str = r#"Here's the idea, with *math* and `inline code`:

A neuron computes $y = w \times x + b$ with weight $w = 3$.

$$\frac{\partial L}{\partial w} = \sum_{i=1}^{n} (y_i - \hat{y}_i) x_i$$

```rust
fn neuron(w: f64, x: f64, b: f64) -> f64 {
    w * x + b // y = wx + b
}
```

> Links show where they go: [docs](https://example.com/docs)"#;

/// A store with a realistic set of chats: Note to Self, direct chats with agents,
/// and conversations between agents.
fn sample_store() -> (Store, Vec<Id>) {
    let me = member(1, PrincipalKind::User, "You", "");
    let bean = member(2, PrincipalKind::Agent, "Bean", "Assistant");
    let mochi = member(3, PrincipalKind::Agent, "Mochi", "Research");
    let pip = member(4, PrincipalKind::Agent, "Pip", "Code");
    let rosette = member(5, PrincipalKind::Agent, "Rosette", "Writing");
    let (note, c_bean, c_mochi, c_pip, c_rosette, c_bm, c_pr) =
        (id(10), id(11), id(12), id(13), id(14), id(15), id(16));
    let chat = |cid: Id, kind: ChatKind, title: &str, members: Vec<Member>| ChatSummary {
        id: cid,
        kind,
        title: title.into(),
        members,
        last_message: None,
        link_allowed: (kind == ChatKind::AgentToAgent).then_some(true),
    };
    let mut s = Store::default();
    s.me = Some(me.id);
    s.set_chats(vec![
        chat(note, ChatKind::NoteToSelf, "Note to Self", vec![me.clone()]),
        chat(c_bean, ChatKind::Direct, "Bean", vec![me.clone(), bean.clone()]),
        chat(c_mochi, ChatKind::Direct, "Mochi", vec![me.clone(), mochi.clone()]),
        chat(c_pip, ChatKind::Direct, "Pip", vec![me.clone(), pip.clone()]),
        chat(c_rosette, ChatKind::Direct, "Rosette", vec![me.clone(), rosette.clone()]),
        chat(c_bm, ChatKind::AgentToAgent, "Bean and Mochi", vec![bean.clone(), mochi.clone()]),
        chat(c_pr, ChatKind::AgentToAgent, "Pip and Rosette", vec![pip.clone(), rosette.clone()]),
    ]);
    let mut seq = 0i64;
    let mut add = |s: &mut Store, cid: Id, sender: Id, at: i64, text: &str| {
        seq += 1;
        let n = u8::try_from(seq).unwrap();
        s.add_messages(
            cid,
            vec![MessageView {
                seq,
                id: Id::from_bytes([n; 16].map(|b| b ^ 0x5a)),
                chat_id: cid,
                thread_id: None,
                sender_id: sender,
                recipient_id: None,
                client_msg_id: Id::from_bytes([n; 16].map(|b| b ^ 0xa5)),
                content: Content::Markdown { text: text.into() },
                created_at_ms: at,
            }],
        );
    };
    add(&mut s, note, me.id, NOW - 9 * DAY, "Ask Mochi about planting garlic before the frost.");
    add(&mut s, note, me.id, NOW - 9 * DAY + MIN, "Buy straw for mulch.");
    add(
        &mut s,
        c_rosette,
        me.id,
        NOW - 4 * DAY,
        "Can you make the first paragraph of my README shorter?",
    );
    add(
        &mut s,
        c_rosette,
        rosette.id,
        NOW - 4 * DAY + 2 * MIN,
        "Here's a tighter version that still tells a new reader what snowpaw is.",
    );
    add(
        &mut s,
        c_pip,
        me.id,
        NOW - DAY - 3 * 60 * MIN,
        "What's the simplest way to read a file line by line in Rust?",
    );
    add(
        &mut s,
        c_pip,
        pip.id,
        NOW - DAY - 3 * 60 * MIN + MIN,
        "Wrap the file in a `BufReader` and loop over `lines()`. Each line comes back as a `Result`, because reading can fail partway through.",
    );
    add(
        &mut s,
        c_mochi,
        me.id,
        NOW - 17 * 60 * MIN,
        "When should I plant garlic this year? We usually get the first hard frost in early November.",
    );
    add(
        &mut s,
        c_mochi,
        mochi.id,
        NOW - 17 * 60 * MIN + 2 * MIN,
        "Plant it a few weeks before the ground freezes, so mid to late October should work for you. That gives the cloves time to grow roots before winter without sending up much green.\n\nSplit the bulb into cloves on planting day. Set each clove pointed end up, about 5 cm deep and 15 cm apart, then cover the bed with straw once the soil starts to cool.",
    );
    add(
        &mut s,
        c_bm,
        mochi.id,
        NOW - 16 * 60 * MIN,
        "Bean, can you check the weather for the next two weeks?",
    );
    add(
        &mut s,
        c_bm,
        bean.id,
        NOW - 16 * 60 * MIN + MIN,
        "Dry and cool, with the first frost likely in the first week of November.",
    );
    add(&mut s, c_bm, mochi.id, NOW - 16 * 60 * MIN + 2 * MIN, "Thanks. That fits the plan.");
    add(
        &mut s,
        c_mochi,
        me.id,
        NOW - 4 * MIN,
        "Great. Can you turn that into a plan for both raised beds?",
    );
    add(
        &mut s,
        c_mochi,
        mochi.id,
        NOW - 3 * MIN,
        "On it. I'll lay out the spacing for both beds and add a short checklist for planting day.",
    );
    add(
        &mut s,
        c_pr,
        pip.id,
        NOW - 2 * MIN,
        "Rosette, can you look over the error messages in this module?",
    );
    add(
        &mut s,
        c_bean,
        bean.id,
        NOW - MIN,
        "Morning. Mochi is working on your garlic plan. Nothing else needs you today.",
    );
    s.set_pinned(vec![c_bean, c_mochi]);
    // Pictures for two of the agents; the others show initials.
    s.set_avatar(picture_hash(2), Some(sample_picture((0x13, 0x29, 0x4b))));
    s.set_avatar(picture_hash(3), Some(sample_picture((0x3e, 0xd6, 0xc9))));
    for c in [note, c_mochi, c_rosette, c_bm] {
        s.mark_read(c);
    }
    (s, vec![note, c_bean, c_mochi, c_pip, c_rosette, c_bm, c_pr])
}

/// Show `chat` as the open conversation, rendering code and math through the real
/// sandboxed worker when it is available.
fn open(
    ui: &AppWindow,
    rt: &tokio::runtime::Runtime,
    s: &mut Store,
    chat: Id,
    worker: Option<&RenderService>,
    rx: &mut Rx,
) {
    let fmt = TimeFmt::utc();
    s.current = Some(chat);
    s.mark_read(chat);
    let mut cache = RenderCache::default();
    if let Some(service) = worker {
        for _ in 0..3 {
            let (_, reqs) = s.timeline(chat, &fmt, NOW, &RenderView { cache: &cache, dark: true });
            let mut waiting = 0;
            for r in reqs {
                if cache.want(&r) && service.request(r) {
                    waiting += 1;
                }
            }
            while waiting > 0 {
                let got = rt.block_on(async {
                    tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv()).await
                });
                let (req, out) = got.unwrap().unwrap();
                cache.insert(req, out);
                waiting -= 1;
            }
        }
    }
    let (items, _) = s.timeline(chat, &fmt, NOW, &RenderView { cache: &cache, dark: true });
    apply_chat_list(ui, &s.chat_rows(&fmt, NOW), Some(chat.to_string()));
    apply_conversation(ui, s.conversation(chat, &fmt, NOW));
    apply_timeline(ui, items);
}

type Rx = tokio::sync::mpsc::UnboundedReceiver<(
    snowpaw_proto::render::RenderRequest,
    snowpaw_client::render::Rendered,
)>;

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: screenshot <OUT_DIR>"));
    std::fs::create_dir_all(&out).unwrap();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(PhysicalSize::new(1280, 820));
    slint::platform::set_platform(Box::new(Offscreen(window.clone()))).unwrap();
    let ui = AppWindow::new().unwrap();
    ui.show().unwrap();
    let shots = Shooter { window, out: out.clone() };

    // Onboarding, step by step.
    ui.set_page("setup".into());
    ui.set_setup_address("127.0.0.1:7443".into());
    for step in ["welcome", "server", "guide"] {
        ui.invoke_show_step(step.into());
        shots.shot(&ui, &format!("o-{step}"), 1280, 820);
    }
    ui.invoke_show_step("connect".into());
    let code = snowpaw_proto::setup_code::encode(
        "127.0.0.1:7443",
        &format!("sha256:{}", "3f9a1c7be24d08e6a5b91f3c2e7d4a60".repeat(2)),
    );
    ui.set_setup_code(code.clone().into());
    snowpaw_client::ui::apply_setup_code(&ui, &code);
    shots.shot(&ui, "o-connect", 1280, 820);
    ui.set_setup_code("snowpaw://not quite".into());
    snowpaw_client::ui::apply_setup_code(&ui, "snowpaw://not quite");
    shots.shot_in(&ui, "o-connect-bad", 1280, 820, &[true]);
    snowpaw_client::ui::apply_setup_code(&ui, &code);
    for (state, name) in
        [("checking", "o-verify-checking"), ("ok", "o-verify-ok"), ("failed", "o-verify-failed")]
    {
        ui.set_verify_message(
            "Something answered at 127.0.0.1:7443, but its certificate doesn’t match your code. That can mean a typo, a server you set up again, or someone in the middle.".into(),
        );
        ui.invoke_show_step("verify".into());
        ui.set_verify_state(state.into());
        shots.shot(&ui, name, 1280, 820);
    }
    ui.set_setup_manual(true);
    ui.set_setup_can_cancel(true);
    ui.set_setup_error(
        "The fingerprint should be \"sha256:\" followed by 64 hex characters".into(),
    );
    ui.invoke_show_step("connect".into());
    shots.shot(&ui, "o-server-settings-narrow", 860, 720);
    ui.set_setup_error("".into());

    ui.set_page("login".into());
    ui.set_server_label("127.0.0.1:7443".into());
    ui.invoke_show_step("login".into());
    ui.set_login_error("That password didn’t work. Check it and try again.".into());
    shots.shot(&ui, "o-login", 1280, 820);

    // The main window, through the real store.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _guard = rt.enter();
    let exe = std::env::current_exe().unwrap();
    let worker_path = exe.parent().unwrap().parent().unwrap().join("snowpaw-render");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let service = worker_path.exists().then(|| RenderService::start(worker_path, tx));
    if service.is_none() {
        eprintln!("snowpaw-render not built: code and math show as plain text");
    }

    let (mut s, ids) = sample_store();
    let fmt = TimeFmt::utc();
    ui.set_page("main".into());
    ui.set_server_address("127.0.0.1:7443".into());
    ui.set_server_fingerprint(format!("sha256:{}", "3f9a1c".repeat(10) + "7be2").into());
    ui.set_server_fingerprint_short("sha256:3f9a1c…7be2".into());
    ui.set_connection("online".into());

    apply_chat_list(&ui, &s.chat_rows(&fmt, NOW), None);
    shots.shot(&ui, "4-main-empty", 1280, 820);

    open(&ui, &rt, &mut s, ids[2], service.as_ref(), &mut rx);
    shots.shot(&ui, "5-direct-chat", 1280, 820);
    shots.shot(&ui, "6-direct-chat-narrow", 980, 720);

    open(&ui, &rt, &mut s, ids[5], service.as_ref(), &mut rx);
    shots.shot(&ui, "7-between-agents", 1280, 820);

    open(&ui, &rt, &mut s, ids[0], service.as_ref(), &mut rx);
    ui.set_connection("offline".into());
    ui.set_status("Offline: Can't reach the server (connection refused). Retrying in 4s…".into());
    ui.set_notice("Can't send: message is too long.".into());
    shots.shot(&ui, "8-note-offline", 1280, 820);
    ui.set_connection("online".into());
    ui.set_status("".into());
    ui.set_notice("".into());

    // Rich content through the real render worker.
    if let Some(service) = service.as_ref() {
        let pip = ids[3];
        s.add_messages(
            pip,
            vec![MessageView {
                seq: 100,
                id: id(100),
                chat_id: pip,
                thread_id: None,
                sender_id: id(4),
                recipient_id: None,
                client_msg_id: id(101),
                content: Content::Markdown { text: RICH.into() },
                created_at_ms: NOW,
            }],
        );
        open(&ui, &rt, &mut s, pip, Some(service), &mut rx);
        // Math was typeset for the dark theme.
        shots.shot_in(&ui, "9-rich", 1280, 1000, &[true]);
    }

    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.invoke_open_settings();
    shots.shot_in(&ui, "10-settings", 1280, 1500, &[true, false]);

    ui.invoke_new_agent();
    ui.set_editor_picture_name("garlic-helper.png".into());
    shots.shot(&ui, "11-new-agent", 1280, 820);

    // An agent's settings: profile, model, runtime and who it can talk to.
    open(&ui, &rt, &mut s, ids[2], None, &mut rx);
    ui.invoke_edit_agent();
    shots.shot_in(&ui, "13-agent-settings", 1280, 1700, &[true, false]);

    // A quiz from an agent, partly answered.
    let quiz = Content::Quiz {
        quiz: Quiz {
            title: "Garlic basics".into(),
            questions: vec![
                Question {
                    prompt: "When should garlic go in the ground?".into(),
                    choices: vec![
                        "Early spring".into(),
                        "A few weeks before the ground freezes".into(),
                        "Midsummer".into(),
                    ],
                    answer: 1,
                    hint: "It needs time to grow roots before winter.".into(),
                    explanation: "Planting in autumn lets the cloves root before winter.".into(),
                },
                Question {
                    prompt: "Which way up does a clove go when you set it in the soil, so the shoot grows up and the roots grow down?".into(),
                    choices: vec!["Pointed end up".into(), "Flat end up".into(), "Either way".into()],
                    answer: 0,
                    hint: String::new(),
                    explanation: "The pointed tip is where the shoot comes out.".into(),
                },
                Question {
                    prompt: "What goes on the bed once the soil cools?".into(),
                    choices: vec!["Sand".into(), "Straw".into(), "Nothing".into()],
                    answer: 1,
                    hint: String::new(),
                    explanation: "A layer of straw protects the cloves over winter.".into(),
                },
            ],
        },
    };
    s.add_messages(
        ids[2],
        vec![MessageView {
            seq: 200,
            id: id(200),
            chat_id: ids[2],
            thread_id: None,
            sender_id: id(3),
            recipient_id: None,
            client_msg_id: id(201),
            content: quiz,
            created_at_ms: NOW,
        }],
    );
    ui.invoke_reset_main();
    open(&ui, &rt, &mut s, ids[2], None, &mut rx);
    snowpaw_client::ui::quiz_pick(&ui, &id(200).to_string(), 0, 1);
    snowpaw_client::ui::quiz_pick(&ui, &id(200).to_string(), 1, 1);
    shots.shot_in(&ui, "14-quiz", 1280, 1100, &[true, false]);

    // Jobs: Mochi suggests one, and another is running now.
    let job = |n: u8, title: &str, state: JobState, running: bool, every: Option<u32>| JobView {
        id: id(n),
        agent: id(3),
        chat_id: ids[2],
        title: title.into(),
        prompt: "Check the frost forecast and tell me if I should cover the garlic bed tonight."
            .into(),
        state,
        schedule: JobSchedule { first_run_at_ms: NOW + 18 * 3_600_000, every_secs: every },
        next_run_at_ms: Some(NOW + 18 * 3_600_000),
        attempts: 0,
        running,
        progress: if running {
            "Reading the weather for the next 48 hours".into()
        } else {
            String::new()
        },
        proposed_by_agent: state == JobState::Proposed,
        last_run: None,
    };
    s.jobs = vec![
        job(70, "Frost check", JobState::Proposed, false, Some(86_400)),
        job(71, "Seed order reminder", JobState::Active, true, Some(604_800)),
    ];
    ui.invoke_reset_main();
    open(&ui, &rt, &mut s, ids[2], None, &mut rx);
    shots.shot_in(&ui, "18-jobs", 1280, 1000, &[true, false]);
    ui.set_job_dialog_open(true);
    shots.shot(&ui, "19-new-job", 1280, 820);
    ui.set_job_dialog_open(false);

    // Plugins: one installed, granted to Mochi with one of its two websites.
    let weather = PluginView {
        id: id(60),
        name: "weather".into(),
        version: "1.2.0".into(),
        description: "Forecasts and current conditions for a place.".into(),
        hash: picture_hash(61),
        tools: vec![
            ToolSpec {
                name: "weather__forecast".into(),
                description: "The forecast for the next days at a place.".into(),
                parameters: "{}".into(),
            },
            ToolSpec {
                name: "weather__now".into(),
                description: "Current temperature, wind and rain.".into(),
                parameters: "{}".into(),
            },
        ],
        http_hosts: vec!["api.open-meteo.com".into(), "geocoding-api.open-meteo.com".into()],
        grants: vec![PluginGrant { agent: id(3), http_hosts: vec!["api.open-meteo.com".into()] }],
    };
    snowpaw_client::ui::apply_plugins(&ui, vec![weather]);
    ui.invoke_open_plugins();
    shots.shot_in(&ui, "16-plugins", 1280, 1100, &[true, false]);
    snowpaw_client::ui::show_plugin_preview(
        &ui,
        "weather",
        "1.3.0",
        "Forecasts and current conditions for a place.",
        &[("weather__forecast".into(), "The forecast for the next days at a place.".into())],
        &["api.open-meteo.com".into()],
        &"ab".repeat(32),
    );
    shots.shot(&ui, "17-plugin-preview", 1280, 820);
    ui.set_plugin_preview(Default::default());
    ui.invoke_reset_main();

    // A new runtime token, shown once.
    ui.set_token_agent("Mochi".into());
    ui.set_token_secret("spw_a_EXAMPLE-ONLY-not-a-real-token-0123456789abcdef".into());
    ui.set_token_code(
        snowpaw_proto::setup_code::encode(
            "127.0.0.1:7443",
            &format!("sha256:{}", "3f9a1c7b".repeat(8)),
        )
        .into(),
    );
    ui.set_token_open(true);
    shots.shot(&ui, "15-token", 1280, 820);
    ui.set_token_open(false);
    ui.set_token_secret("".into());

    // First run: only Note to Self, with the welcome card.
    let mut first = Store::default();
    let me = member(1, PrincipalKind::User, "You", "");
    first.me = Some(me.id);
    first.set_chats(vec![ChatSummary {
        id: id(10),
        kind: ChatKind::NoteToSelf,
        title: "Note to Self".into(),
        members: vec![me],
        last_message: None,
        link_allowed: None,
    }]);
    ui.invoke_reset_main();
    ui.set_welcome(true);
    open(&ui, &rt, &mut first, id(10), None, &mut rx);
    shots.shot(&ui, "12-first-run", 1280, 820);
    println!("wrote screenshots to {}", out.display());
}
