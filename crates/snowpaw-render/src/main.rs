//! snowpaw render worker.
//!
//! Started by the desktop client, one per client. Locks itself down (see `sandbox`),
//! says hello, then answers render requests on stdin/stdout until stdin closes. It
//! holds no secrets and talks to nothing but its parent.

mod avatar;
mod highlight;
mod math;
mod sandbox;

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;

use snowpaw_proto::render::{
    Hello, MAX_REQUEST_BYTES, RENDER_PROTOCOL_VERSION, RenderFailure, RenderRequest, RenderResponse,
};
use snowpaw_proto::{decode, encode};

fn read_frame(input: &mut impl Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
    }
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| io::Error::other("frame too large"))?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(bytes)
}

struct Worker {
    highlighter: highlight::Highlighter,
    math: Option<math::MathEngine>,
}

impl Worker {
    fn math(&mut self) -> Result<&math::MathEngine, RenderFailure> {
        if self.math.is_none() {
            self.math = math::MathEngine::new();
        }
        self.math.as_ref().ok_or(RenderFailure::Internal)
    }

    /// Returns the response and, for images and PNGs, the binary payload.
    fn handle(
        &mut self,
        request: RenderRequest,
        input: &[u8],
    ) -> (RenderResponse, Option<Vec<u8>>) {
        if request.validate().is_err() {
            return (RenderResponse::Failed { reason: RenderFailure::InvalidRequest }, None);
        }
        let image = |r: Result<math::Image, RenderFailure>| match r {
            Ok(img) => {
                (RenderResponse::Image { width: img.width, height: img.height }, Some(img.rgba))
            }
            Err(reason) => (RenderResponse::Failed { reason }, None),
        };
        match request {
            RenderRequest::Highlight { lang, code, dark } => {
                match self.highlighter.highlight(&lang, &code, dark) {
                    Ok(lines) => (RenderResponse::Highlighted { lines }, None),
                    Err(reason) => (RenderResponse::Failed { reason }, None),
                }
            }
            RenderRequest::Math { latex, color, size_pt, scale } => {
                let r = self.math().and_then(|m| m.display(&latex, color, size_pt, scale));
                image(r)
            }
            RenderRequest::MathParagraph { runs, color, size_pt, width_pt, scale } => {
                let r =
                    self.math().and_then(|m| m.paragraph(&runs, color, size_pt, width_pt, scale));
                image(r)
            }
            RenderRequest::NormalizeAvatar { .. } => match avatar::normalize(input) {
                Ok(png) => match u32::try_from(png.len()) {
                    Ok(bytes) => (RenderResponse::Png { bytes }, Some(png)),
                    Err(_) => (RenderResponse::Failed { reason: RenderFailure::TooLarge }, None),
                },
                Err(reason) => (RenderResponse::Failed { reason }, None),
            },
            RenderRequest::DecodeAvatar { .. } => image(avatar::decode(input)),
        }
    }
}

fn main() -> ExitCode {
    // Before reading a single byte of input.
    let sandbox_verified = sandbox::enter();

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let hello = encode(&Hello { version: RENDER_PROTOCOL_VERSION, sandbox_verified });
    if write_frame(&mut output, hello.as_bytes()).and_then(|()| output.flush()).is_err() {
        return ExitCode::FAILURE;
    }

    let mut worker = Worker { highlighter: highlight::Highlighter::default(), math: None };
    loop {
        let frame = match read_frame(&mut input, MAX_REQUEST_BYTES) {
            Ok(Some(f)) => f,
            Ok(None) => return ExitCode::SUCCESS,
            Err(_) => return ExitCode::FAILURE,
        };
        let request = decode::<RenderRequest>(&frame);
        // A request with a binary frame after it must be valid, and the frame exactly
        // as long as announced; otherwise the framing can't be trusted: stop.
        let payload_in = match request.as_ref().ok().and_then(RenderRequest::payload_len) {
            None => Vec::new(),
            Some(len) => {
                if request.as_ref().is_ok_and(|r| r.validate().is_err()) {
                    return ExitCode::FAILURE;
                }
                match read_frame(&mut input, len) {
                    Ok(Some(p)) if p.len() == len => p,
                    _ => return ExitCode::FAILURE,
                }
            }
        };
        let (response, payload) = match request {
            Ok(request) => catch_unwind(AssertUnwindSafe(|| worker.handle(request, &payload_in)))
                .unwrap_or((RenderResponse::Failed { reason: RenderFailure::Internal }, None)),
            Err(_) => (RenderResponse::Failed { reason: RenderFailure::InvalidRequest }, None),
        };
        let written = write_frame(&mut output, encode(&response).as_bytes())
            .and_then(|()| payload.map_or(Ok(()), |p| write_frame(&mut output, &p)))
            .and_then(|()| output.flush());
        if written.is_err() {
            return ExitCode::FAILURE;
        }
    }
}
