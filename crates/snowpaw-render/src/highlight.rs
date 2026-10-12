//! Code highlighting with giallo (VS Code / Shiki grammars and themes).

use giallo::{FontStyle, HighlightOptions, PLAIN_GRAMMAR_NAME, Registry, ThemeVariant};
use snowpaw_proto::render::{RenderFailure, Rgb, Span};

const LIGHT_THEME: &str = "github-light";
const DARK_THEME: &str = "github-dark";

#[derive(Default)]
pub struct Highlighter {
    registry: Option<Registry>,
}

impl std::fmt::Debug for Highlighter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Highlighter")
    }
}

fn parse_hex(hex: &str) -> Rgb {
    let h = hex.trim_start_matches('#');
    let byte = |i: usize| h.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()).unwrap_or(0);
    Rgb { r: byte(0), g: byte(2), b: byte(4) }
}

impl Highlighter {
    fn registry(&mut self) -> Result<&Registry, RenderFailure> {
        if self.registry.is_none() {
            let mut r = Registry::builtin().map_err(|_| RenderFailure::Internal)?;
            r.link_grammars();
            self.registry = Some(r);
        }
        self.registry.as_ref().ok_or(RenderFailure::Internal)
    }

    pub fn highlight(
        &mut self,
        lang: &str,
        code: &str,
        dark: bool,
    ) -> Result<Vec<Vec<Span>>, RenderFailure> {
        let registry = self.registry()?;
        let lang = lang.to_ascii_lowercase();
        let lang = if !lang.is_empty() && registry.contains_grammar(&lang) {
            lang.as_str()
        } else {
            PLAIN_GRAMMAR_NAME
        };
        let theme = if dark { DARK_THEME } else { LIGHT_THEME };
        let options =
            HighlightOptions::new(lang, ThemeVariant::Single(theme)).fallback_to_plain(true);
        let highlighted =
            registry.highlight(code, &options).map_err(|_| RenderFailure::Internal)?;
        Ok(highlighted
            .tokens
            .into_iter()
            .map(|line| {
                line.into_iter()
                    .map(|token| {
                        let style = match token.style {
                            ThemeVariant::Single(s) | ThemeVariant::Dual { light: s, .. } => s,
                        };
                        let fs = style.font_style;
                        Span {
                            text: token.text,
                            color: parse_hex(&style.foreground.as_hex()),
                            bold: fs.contains(FontStyle::BOLD),
                            italic: fs.contains(FontStyle::ITALIC),
                            underline: fs.contains(FontStyle::UNDERLINE),
                            strike: fs.contains(FontStyle::STRIKETHROUGH),
                        }
                    })
                    .collect()
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_and_preserves_text() {
        let mut h = Highlighter::default();
        let code = "fn main() {\n    let x = 42; // answer\n}\n";
        let lines = h.highlight("rust", code, false).expect("highlight");
        assert!(snowpaw_proto::render::spans_match(code, &lines));
        let colors: std::collections::HashSet<_> =
            lines.iter().flatten().map(|s| s.color).collect();
        assert!(colors.len() > 2, "expected several token colors, got {colors:?}");
    }

    #[test]
    fn unknown_language_is_plain() {
        let mut h = Highlighter::default();
        let code = "just text";
        let lines = h.highlight("no-such-language", code, true).expect("highlight");
        assert!(snowpaw_proto::render::spans_match(code, &lines));
    }

    #[test]
    fn hex_colors() {
        assert_eq!(parse_hex("#24292e"), Rgb { r: 0x24, g: 0x29, b: 0x2e });
        assert_eq!(parse_hex("#24292eff"), Rgb { r: 0x24, g: 0x29, b: 0x2e });
        assert_eq!(parse_hex("bogus"), Rgb { r: 0, g: 0, b: 0 });
    }
}
