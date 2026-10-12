//! Client side of the render worker (`snowpaw-render`).
//!
//! Code highlighting and math typesetting run on untrusted text with complex parsers
//! (including Oniguruma, written in C), so they happen in a separate process that:
//! - holds no secrets (fresh process, empty environment, working directory `/`);
//! - can't open files or the network (macOS: `sandbox-exec` with a deny-by-default
//!   profile; Linux: the worker applies Landlock to itself) and has CPU/memory limits;
//! - proves the sandbox holds (its self-test result is in the hello message) or isn't
//!   used at all;
//! - is killed and restarted if a request takes too long or anything looks wrong.
//!
//! Everything it sends back is checked again here. If rendering isn't available,
//! messages fall back to plain text and profile pictures to initials.
//!
//! Pictures go through the worker too: the client never decodes an image itself.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use slint::{Rgba8Pixel, SharedPixelBuffer};
use snowpaw_proto::profile::{AVATAR_SIDE, MAX_AVATAR_BYTES, png_dimensions};
use snowpaw_proto::render::{
    Hello, MAX_RESPONSE_BYTES, RENDER_PROTOCOL_VERSION, RenderRequest, RenderResponse, Span,
    image_size_ok, spans_match,
};
use snowpaw_proto::{decode, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;

const START_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Decoding and resizing a large photo takes longer than a code block.
const PICTURE_TIMEOUT: Duration = Duration::from_secs(20);
/// Give up on the worker after this many consecutive failures (crash loop).
const MAX_CONSECUTIVE_FAILURES: u32 = 5;
/// Cached results before the cache is cleared.
const MAX_CACHED: usize = 2000;

#[derive(Clone)]
pub struct RenderedImage {
    pub width: u32,
    pub height: u32,
    pub pixels: SharedPixelBuffer<Rgba8Pixel>,
}

impl std::fmt::Debug for RenderedImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RenderedImage({}x{})", self.width, self.height)
    }
}

#[derive(Debug, Clone)]
pub enum Rendered {
    Highlighted(Vec<Vec<Span>>),
    Image(RenderedImage),
    /// A normalized profile picture: a 256x256 PNG.
    Png(Vec<u8>),
    /// Show the plain-text fallback.
    Failed,
}

enum Job {
    Render(RenderRequest),
    /// A request with a binary payload; the result goes to `reply`, not the cache.
    Picture {
        req: RenderRequest,
        data: Vec<u8>,
        reply: oneshot::Sender<Rendered>,
    },
}

/// Results so far, plus what's in flight.
#[derive(Debug, Default)]
pub struct RenderCache {
    done: HashMap<RenderRequest, Rendered>,
    pending: HashSet<RenderRequest>,
}

impl RenderCache {
    pub fn get(&self, req: &RenderRequest) -> Option<&Rendered> {
        self.done.get(req)
    }

    /// Returns true if this request should be sent (not done and not already in flight).
    pub fn want(&mut self, req: &RenderRequest) -> bool {
        !self.done.contains_key(req) && self.pending.insert(req.clone())
    }

    pub fn insert(&mut self, req: RenderRequest, result: Rendered) {
        self.pending.remove(&req);
        if self.done.len() >= MAX_CACHED {
            self.done.clear();
        }
        self.done.insert(req, result);
    }
}

#[derive(Clone)]
pub struct RenderService {
    tx: Option<UnboundedSender<Job>>,
}

impl std::fmt::Debug for RenderService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RenderService(enabled: {})", self.tx.is_some())
    }
}

impl RenderService {
    /// A service that renders nothing (everything falls back to plain text).
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    /// Start the service. Results arrive on `results`.
    pub fn start(worker: PathBuf, results: UnboundedSender<(RenderRequest, Rendered)>) -> Self {
        let (tx, rx) = unbounded_channel();
        tokio::spawn(run(worker, rx, results));
        Self { tx: Some(tx) }
    }

    /// Queue a request. Returns false if rendering is unavailable.
    pub fn request(&self, req: RenderRequest) -> bool {
        self.tx.as_ref().is_some_and(|tx| tx.send(Job::Render(req)).is_ok())
    }

    async fn picture(&self, req: RenderRequest, data: Vec<u8>) -> Rendered {
        let Some(tx) = &self.tx else { return Rendered::Failed };
        if req.validate().is_err() || req.payload_len() != Some(data.len()) {
            return Rendered::Failed;
        }
        let (reply, rx) = oneshot::channel();
        if tx.send(Job::Picture { req, data, reply }).is_err() {
            return Rendered::Failed;
        }
        rx.await.unwrap_or(Rendered::Failed)
    }

    /// A picture file the user chose -> a 256x256 PNG without metadata, ready to upload.
    pub async fn normalize_avatar(&self, file: Vec<u8>) -> Option<Vec<u8>> {
        let bytes = u32::try_from(file.len()).ok()?;
        match self.picture(RenderRequest::NormalizeAvatar { bytes }, file).await {
            Rendered::Png(png) => Some(png),
            _ => None,
        }
    }

    /// A stored profile picture -> pixels to draw.
    pub async fn decode_avatar(&self, png: Vec<u8>) -> Option<RenderedImage> {
        let bytes = u32::try_from(png.len()).ok()?;
        match self.picture(RenderRequest::DecodeAvatar { bytes }, png).await {
            Rendered::Image(img) => Some(img),
            _ => None,
        }
    }
}

/// The worker binary next to our own executable.
pub fn default_worker_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.with_file_name("snowpaw-render");
    path.is_file().then_some(path)
}

/// macOS sandbox profile: deny everything except what any process needs to start
/// (Apple's `system.sb` base) and executing/reading the worker binary itself.
fn macos_profile(worker: &Path) -> Option<String> {
    let p = worker.to_str()?;
    if p.contains(['"', '\\', '\n']) {
        return None;
    }
    Some(format!(
        "(version 1)(deny default)(import \"system.sb\")\
         (allow process-exec (literal \"{p}\"))(allow file-read* (literal \"{p}\"))"
    ))
}

struct Worker {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

async fn read_frame(r: &mut ChildStdout, max: usize) -> Result<Vec<u8>, String> {
    let len = r.read_u32().await.map_err(|e| e.to_string())? as usize;
    if len > max {
        return Err("frame too large".into());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

impl Worker {
    async fn spawn(path: &Path) -> Result<Self, String> {
        let path = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
        let mut cmd = if cfg!(target_os = "macos") {
            let profile = macos_profile(&path).ok_or("worker path can't be sandboxed")?;
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-p").arg(profile).arg(&path);
            c
        } else {
            Command::new(&path)
        };
        cmd.env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let mut stdout = child.stdout.take().ok_or("no stdout")?;
        let hello = tokio::time::timeout(START_TIMEOUT, read_frame(&mut stdout, 1024))
            .await
            .map_err(|_| "worker didn't start in time".to_owned())??;
        let hello: Hello = decode(&hello).map_err(|e| e.to_string())?;
        if hello.version != RENDER_PROTOCOL_VERSION {
            return Err("worker version mismatch".into());
        }
        if !hello.sandbox_verified {
            return Err("the render sandbox isn't working on this system".into());
        }
        Ok(Self { _child: child, stdin, stdout })
    }

    async fn write_frame(&mut self, bytes: &[u8]) -> Result<(), String> {
        let len = u32::try_from(bytes.len()).map_err(|_| "request too large")?;
        self.stdin.write_u32(len).await.map_err(|e| e.to_string())?;
        self.stdin.write_all(bytes).await.map_err(|e| e.to_string())
    }

    async fn read_image(&mut self, width: u32, height: u32) -> Result<RenderedImage, String> {
        if !image_size_ok(width, height) {
            return Err("image too large".into());
        }
        let expected = (width as usize) * (height as usize) * 4;
        let pixels = read_frame(&mut self.stdout, expected).await?;
        if pixels.len() != expected {
            return Err("image size mismatch".into());
        }
        let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(width, height);
        buffer.make_mut_bytes().copy_from_slice(&pixels);
        Ok(RenderedImage { width, height, pixels: buffer })
    }

    async fn call(&mut self, req: &RenderRequest, payload: &[u8]) -> Result<Rendered, String> {
        self.write_frame(encode(req).as_bytes()).await?;
        if req.payload_len().is_some() {
            self.write_frame(payload).await?;
        }
        self.stdin.flush().await.map_err(|e| e.to_string())?;
        let resp: RenderResponse = decode(&read_frame(&mut self.stdout, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| e.to_string())?;
        match (req, resp) {
            (RenderRequest::Highlight { code, .. }, RenderResponse::Highlighted { lines }) => {
                // The worker may color the code, never change it.
                if spans_match(code, &lines) {
                    Ok(Rendered::Highlighted(lines))
                } else {
                    Err("altered code".into())
                }
            }
            (
                RenderRequest::Math { .. } | RenderRequest::MathParagraph { .. },
                RenderResponse::Image { width, height },
            ) => Ok(Rendered::Image(self.read_image(width, height).await?)),
            (RenderRequest::DecodeAvatar { .. }, RenderResponse::Image { width, height }) => {
                if (width, height) != (AVATAR_SIDE, AVATAR_SIDE) {
                    return Err("wrong picture size".into());
                }
                Ok(Rendered::Image(self.read_image(width, height).await?))
            }
            (RenderRequest::NormalizeAvatar { .. }, RenderResponse::Png { bytes }) => {
                let bytes = bytes as usize;
                if bytes > MAX_AVATAR_BYTES {
                    return Err("picture too large".into());
                }
                let png = read_frame(&mut self.stdout, bytes).await?;
                // The server checks this too; a worker can't hand us anything else.
                if png.len() != bytes || png_dimensions(&png) != Some((AVATAR_SIDE, AVATAR_SIDE)) {
                    return Err("not a 256x256 PNG".into());
                }
                Ok(Rendered::Png(png))
            }
            (_, RenderResponse::Failed { .. }) => Ok(Rendered::Failed),
            _ => Err("response doesn't match the request".into()),
        }
    }
}

async fn run(
    path: PathBuf,
    mut rx: UnboundedReceiver<Job>,
    results: UnboundedSender<(RenderRequest, Rendered)>,
) {
    let mut worker: Option<Worker> = None;
    let mut failures = 0u32;
    while let Some(job) = rx.recv().await {
        let (req, payload, limit) = match &job {
            Job::Render(req) => (req, &[][..], REQUEST_TIMEOUT),
            Job::Picture { req, data, .. } => (req, &data[..], PICTURE_TIMEOUT),
        };
        let outcome = if failures >= MAX_CONSECUTIVE_FAILURES {
            Rendered::Failed
        } else {
            if worker.is_none() {
                match Worker::spawn(&path).await {
                    Ok(w) => worker = Some(w),
                    // A worker that can't start (or can't sandbox itself) won't start
                    // next time either: stop trying.
                    Err(_) => failures = MAX_CONSECUTIVE_FAILURES,
                }
            }
            match worker.as_mut() {
                None => Rendered::Failed,
                Some(w) => match tokio::time::timeout(limit, w.call(req, payload)).await {
                    Ok(Ok(r)) => {
                        failures = 0;
                        r
                    }
                    // Too slow or misbehaving: kill it (dropping kills) and start
                    // fresh next time.
                    Ok(Err(_)) | Err(_) => {
                        worker = None;
                        failures += 1;
                        Rendered::Failed
                    }
                },
            }
        };
        match job {
            Job::Render(req) => {
                let _ = results.send((req, outcome));
            }
            Job::Picture { reply, .. } => {
                let _ = reply.send(outcome);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_refuses_odd_paths() {
        assert!(
            macos_profile(Path::new("/Applications/snowpaw.app/Contents/MacOS/snowpaw-render"))
                .is_some()
        );
        assert!(macos_profile(Path::new("/tmp/a\"(allow default)\"/w")).is_none());
        assert!(macos_profile(Path::new("/tmp/a\\b")).is_none());
    }

    #[test]
    fn cache_dedups_in_flight_requests() {
        let mut c = RenderCache::default();
        let r = RenderRequest::Highlight { lang: "rust".into(), code: "x".into(), dark: false };
        assert!(c.want(&r));
        assert!(!c.want(&r), "already in flight");
        c.insert(r.clone(), Rendered::Failed);
        assert!(!c.want(&r), "already done");
        assert!(matches!(c.get(&r), Some(Rendered::Failed)));
    }
}
