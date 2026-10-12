//! Messages between the desktop client and its sandboxed render worker
//! (`snowpaw-render`), which highlights code and typesets math from untrusted
//! message content.
//!
//! Framing over the worker's stdin/stdout: a 4-byte big-endian length, then that many
//! bytes of canonical JSON. An `Image` response is followed by a second frame holding
//! exactly `width * height * 4` bytes of premultiplied RGBA. Picture requests
//! (`NormalizeAvatar`, `DecodeAvatar`) are followed by one binary frame holding the
//! file, and a `Png` response by one holding the PNG.
//!
//! The client treats the worker as untrusted too: highlighted spans must reassemble to
//! exactly the code it sent, and images must fit the size limits below.

use serde::{Deserialize, Serialize};

/// Largest request frame the worker accepts.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Largest JSON response frame the client accepts.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CODE_BYTES: usize = 64 * 1024;
pub const MAX_LATEX_BYTES: usize = 8 * 1024;
pub const MAX_LANG_CHARS: usize = 32;
pub const MAX_INLINE_RUNS: usize = 512;
/// Largest image side and area, in pixels.
pub const MAX_IMAGE_SIDE: u32 = 4096;
pub const MAX_IMAGE_PIXELS: u64 = 2048 * 2048;
/// Largest picture file the worker takes for `NormalizeAvatar`.
pub const MAX_SOURCE_IMAGE_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// Sent once by the worker when it starts, after it has locked itself down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub version: u16,
    /// The worker tried to open a file and a network socket after sandboxing and
    /// both were refused.
    pub sandbox_verified: bool,
}

pub const RENDER_PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RenderRequest {
    Highlight {
        /// Language from the code fence, e.g. "rust". Unknown languages render as plain text.
        lang: String,
        code: String,
        dark: bool,
    },
    /// Typeset LaTeX math on its own (a `$$ ... $$` block).
    Math {
        latex: String,
        color: Rgb,
        /// Font size in points.
        size_pt: u8,
        /// Pixels per point, for high-DPI screens.
        scale: u8,
    },
    /// Typeset a paragraph that mixes text and inline `$ ... $` math.
    MathParagraph {
        runs: Vec<InlineRun>,
        color: Rgb,
        size_pt: u8,
        /// Line width in points.
        width_pt: u16,
        scale: u8,
    },
    /// Turn a picture the user chose (PNG, JPEG, GIF or WebP) into a profile picture:
    /// upright, center-cropped, 256x256, re-encoded as a PNG with no metadata.
    /// Followed by a binary frame of exactly `bytes` bytes. Answered with `Png`.
    NormalizeAvatar { bytes: u32 },
    /// Decode a profile picture (a 256x256 PNG) for display. Followed by a binary
    /// frame of exactly `bytes` bytes. Answered with a 256x256 `Image`.
    DecodeAvatar { bytes: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InlineRun {
    Text { text: String, strong: bool, emph: bool },
    Code { text: String },
    Math { latex: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RenderResponse {
    Highlighted {
        lines: Vec<Vec<Span>>,
    },
    /// Followed by a binary frame of `width * height * 4` bytes.
    Image {
        width: u32,
        height: u32,
    },
    /// Followed by a binary frame of exactly `bytes` bytes: a 256x256 PNG.
    Png {
        bytes: u32,
    },
    Failed {
        reason: RenderFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub text: String,
    pub color: Rgb,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderFailure {
    /// The request broke a size or format rule.
    InvalidRequest,
    /// The LaTeX couldn't be converted or typeset.
    InvalidMath,
    /// The result would exceed the image limits.
    TooLarge,
    /// Not a picture we can read (wrong format, corrupt, or too big to decode).
    InvalidImage,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestError;

fn valid_lang(lang: &str) -> bool {
    lang.chars().count() <= MAX_LANG_CHARS
        && lang
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '#' | '-' | '_' | '.'))
}

impl RenderRequest {
    /// Size and format rules, checked by both sides.
    pub fn validate(&self) -> Result<(), RequestError> {
        let ok = match self {
            Self::Highlight { lang, code, .. } => valid_lang(lang) && code.len() <= MAX_CODE_BYTES,
            Self::Math { latex, size_pt, scale, .. } => {
                !latex.trim().is_empty()
                    && latex.len() <= MAX_LATEX_BYTES
                    && (6..=72).contains(size_pt)
                    && (1..=4).contains(scale)
            }
            Self::MathParagraph { runs, size_pt, width_pt, scale, .. } => {
                let total: usize = runs
                    .iter()
                    .map(|r| match r {
                        InlineRun::Text { text, .. } | InlineRun::Code { text } => text.len(),
                        InlineRun::Math { latex } => latex.len(),
                    })
                    .sum();
                !runs.is_empty()
                    && runs.len() <= MAX_INLINE_RUNS
                    && total <= MAX_CODE_BYTES
                    && runs.iter().all(|r| match r {
                        InlineRun::Math { latex } => latex.len() <= MAX_LATEX_BYTES,
                        _ => true,
                    })
                    && (6..=72).contains(size_pt)
                    && (100..=2000).contains(width_pt)
                    && (1..=4).contains(scale)
            }
            Self::NormalizeAvatar { bytes } => {
                (1..=MAX_SOURCE_IMAGE_BYTES).contains(&(*bytes as usize))
            }
            Self::DecodeAvatar { bytes } => {
                (1..=crate::profile::MAX_AVATAR_BYTES).contains(&(*bytes as usize))
            }
        };
        if ok { Ok(()) } else { Err(RequestError) }
    }
}

impl RenderRequest {
    /// Length of the binary frame that follows this request, if any.
    pub fn payload_len(&self) -> Option<usize> {
        match self {
            Self::NormalizeAvatar { bytes } | Self::DecodeAvatar { bytes } => Some(*bytes as usize),
            _ => None,
        }
    }
}

/// Image dimensions the client will accept.
pub fn image_size_ok(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_IMAGE_SIDE
        && height <= MAX_IMAGE_SIDE
        && u64::from(width) * u64::from(height) <= MAX_IMAGE_PIXELS
}

/// The highlighted spans must spell out exactly the code that was sent, line by line,
/// so a misbehaving worker can't change what the user reads.
pub fn spans_match(code: &str, lines: &[Vec<Span>]) -> bool {
    let normalized = code.replace("\r\n", "\n");
    let expected: Vec<&str> = normalized.split('\n').collect();
    // A trailing newline may or may not produce a final empty line.
    let lines: Vec<String> =
        lines.iter().map(|l| l.iter().map(|s| s.text.as_str()).collect()).collect();
    let mut got: Vec<&str> = lines.iter().map(String::as_str).collect();
    if got.len() == expected.len() + 1 && got.last() == Some(&"") {
        got.pop();
    }
    let mut exp = expected;
    if exp.len() == got.len() + 1 && exp.last() == Some(&"") {
        exp.pop();
    }
    got == exp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(t: &str) -> Span {
        Span {
            text: t.into(),
            color: Rgb { r: 0, g: 0, b: 0 },
            bold: false,
            italic: false,
            underline: false,
            strike: false,
        }
    }

    #[test]
    fn spans_must_reassemble_the_code() {
        let code = "let x = 1;\nfoo()\n";
        let good = vec![vec![span("let "), span("x = 1;")], vec![span("foo()")]];
        assert!(spans_match(code, &good));
        let with_empty = vec![vec![span("let x = 1;")], vec![span("foo()")], vec![]];
        assert!(spans_match(code, &with_empty));
        let altered = vec![vec![span("let x = 2;")], vec![span("foo()")]];
        assert!(!spans_match(code, &altered));
        let extra = vec![vec![span("let x = 1;")], vec![span("foo()")], vec![span("rm -rf /")]];
        assert!(!spans_match(code, &extra));
        let missing = vec![vec![span("let x = 1;")]];
        assert!(!spans_match(code, &missing));
    }

    #[test]
    fn request_limits() {
        let hl = |lang: &str, code: String| RenderRequest::Highlight {
            lang: lang.into(),
            code,
            dark: false,
        };
        assert!(hl("rust", "x".into()).validate().is_ok());
        assert!(hl("c++", "x".into()).validate().is_ok());
        assert!(hl("", "x".into()).validate().is_ok(), "no language = plain");
        assert!(hl("rust; rm", "x".into()).validate().is_err());
        assert!(hl("../../etc/passwd", "x".into()).validate().is_err());
        assert!(hl("rust", "x".repeat(MAX_CODE_BYTES + 1)).validate().is_err());
        let math = |latex: &str, size_pt: u8| RenderRequest::Math {
            latex: latex.into(),
            color: Rgb { r: 0, g: 0, b: 0 },
            size_pt,
            scale: 2,
        };
        assert!(math(r"\frac{a}{b}", 14).validate().is_ok());
        assert!(math("  ", 14).validate().is_err());
        assert!(math("x", 200).validate().is_err());
        assert!(math(&"x".repeat(MAX_LATEX_BYTES + 1), 14).validate().is_err());
        assert!(RenderRequest::NormalizeAvatar { bytes: 1000 }.validate().is_ok());
        assert!(RenderRequest::NormalizeAvatar { bytes: 0 }.validate().is_err());
        let too_big = u32::try_from(MAX_SOURCE_IMAGE_BYTES + 1).unwrap_or(u32::MAX);
        assert!(RenderRequest::NormalizeAvatar { bytes: too_big }.validate().is_err());
        assert!(RenderRequest::DecodeAvatar { bytes: 600 * 1024 }.validate().is_err());
    }

    #[test]
    fn image_limits() {
        assert!(image_size_ok(100, 40));
        assert!(!image_size_ok(0, 40));
        assert!(!image_size_ok(5000, 10));
        assert!(!image_size_ok(4096, 4096));
    }
}
