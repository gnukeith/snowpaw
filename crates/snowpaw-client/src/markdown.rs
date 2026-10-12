//! Markdown from messages -> display blocks, using a deliberately small safe subset.
//!
//! Message text is untrusted (it will come from models). What we allow:
//! bold, italics, strikethrough, inline code, lists, headings, quotes, code blocks,
//! tables (as monospace text), rules, and math (rendered by the sandboxed worker).
//!
//! What we never do:
//! - Make links clickable. A link shows its text and then its real address, so the
//!   address can't hide behind innocent text.
//! - Load images. They show as "[image: alt text]".
//! - Pass through HTML or Slint's styling tags (colors, underline): those could hide
//!   text or imitate the UI. Everything is escaped before it reaches StyledText.

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use snowpaw_proto::render::InlineRun;

/// Most blocks rendered for one message; the rest is summarized.
const MAX_BLOCKS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Block {
    /// Safe StyledText markdown, plus a plain-text fallback.
    Text {
        md: String,
        plain: String,
        style: TextStyle,
    },
    Code {
        lang: String,
        code: String,
    },
    /// A `$$ ... $$` equation.
    Math {
        latex: String,
    },
    /// A paragraph mixing text and inline `$ ... $` math.
    MathText {
        runs: Vec<InlineRun>,
        md: String,
        plain: String,
        style: TextStyle,
    },
    Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextStyle {
    Body,
    Heading(u8),
    Quote,
}

/// Backslash-escape every ASCII punctuation character (CommonMark allows escaping all
/// of them), so text can never become markup.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            c if c.is_ascii_punctuation() => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Inline code span with a fence longer than any backtick run inside.
fn code_span(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let text = text.replace(['\n', '\r'], " ");
    if text.starts_with('`') || text.ends_with('`') || text.starts_with(' ') {
        format!("{fence} {text} {fence}")
    } else {
        format!("{fence}{text}{fence}")
    }
}

#[derive(Debug, Default)]
struct Para {
    md: String,
    plain: String,
    runs: Vec<InlineRun>,
    has_math: bool,
}

impl Para {
    fn is_empty(&self) -> bool {
        self.md.trim().is_empty() && !self.has_math
    }
}

#[derive(Debug, Default)]
struct Builder {
    blocks: Vec<Block>,
    para: Para,
    strong: u32,
    emph: u32,
    links: Vec<String>,
    heading: Option<u8>,
    quote: u32,
    /// Ordered-list counters (None for bullet lists), innermost last.
    lists: Vec<Option<u64>>,
    code: Option<(String, String)>,
    table: Option<Vec<Vec<String>>>,
    cell: Option<String>,
}

impl Builder {
    fn style(&self) -> TextStyle {
        match (self.heading, self.quote) {
            (Some(level), _) => TextStyle::Heading(level),
            (None, q) if q > 0 => TextStyle::Quote,
            _ => TextStyle::Body,
        }
    }

    fn push_block(&mut self, b: Block) {
        if self.blocks.len() < MAX_BLOCKS {
            self.blocks.push(b);
        } else if self.blocks.len() == MAX_BLOCKS {
            let note = "(message truncated)";
            self.blocks.push(Block::Text {
                md: escape(note),
                plain: note.into(),
                style: TextStyle::Body,
            });
        }
    }

    fn flush(&mut self) {
        let para = std::mem::take(&mut self.para);
        if para.is_empty() {
            return;
        }
        let style = self.style();
        let md = match style {
            TextStyle::Heading(_) => format!("**{}**", para.md.trim()),
            _ => para.md.trim_end().to_owned(),
        };
        if para.has_math {
            self.push_block(Block::MathText { runs: para.runs, md, plain: para.plain, style });
        } else {
            self.push_block(Block::Text { md, plain: para.plain, style });
        }
    }

    fn text(&mut self, t: &str) {
        if let Some(cell) = &mut self.cell {
            cell.push_str(t);
            return;
        }
        if let Some((_, code)) = &mut self.code {
            code.push_str(t);
            return;
        }
        self.para.md.push_str(&escape(t));
        self.para.plain.push_str(t);
        self.para.runs.push(InlineRun::Text {
            text: t.to_owned(),
            strong: self.strong > 0,
            emph: self.emph > 0,
        });
    }

    fn list_prefix(&mut self) {
        let depth = self.lists.len().saturating_sub(1);
        let indent = "\u{a0}\u{a0}\u{a0}\u{a0}".repeat(depth);
        let marker = match self.lists.last_mut() {
            Some(Some(n)) => {
                let m = format!("{n}. ");
                *n += 1;
                m
            }
            _ => "• ".to_owned(),
        };
        // Lists are rendered as their own lines with literal markers, which keeps the
        // markdown subset handed to StyledText minimal.
        self.para.md.push_str(&indent);
        self.para.md.push_str(&escape(&marker));
        self.para.plain.push_str(&indent);
        self.para.plain.push_str(&marker);
        self.para.runs.push(InlineRun::Text {
            text: format!("{indent}{marker}"),
            strong: false,
            emph: false,
        });
    }

    fn event(&mut self, ev: Event<'_>) {
        match ev {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(t) => self.text(&t),
            Event::Code(t) => {
                if let Some(cell) = &mut self.cell {
                    cell.push_str(&t);
                    return;
                }
                self.para.md.push_str(&code_span(&t));
                self.para.plain.push_str(&t);
                self.para.runs.push(InlineRun::Code { text: t.to_string() });
            }
            Event::InlineMath(t) => {
                if let Some(cell) = &mut self.cell {
                    cell.push_str(&format!("${t}$"));
                    return;
                }
                self.para.has_math = true;
                self.para.md.push_str(&code_span(&format!("${t}$")));
                self.para.plain.push_str(&format!("${t}$"));
                self.para.runs.push(InlineRun::Math { latex: t.to_string() });
            }
            Event::DisplayMath(t) => {
                self.flush();
                self.push_block(Block::Math { latex: t.trim().to_owned() });
            }
            Event::Html(t) | Event::InlineHtml(t) => self.text(&t),
            Event::SoftBreak => self.text(" "),
            Event::HardBreak => {
                if self.cell.is_none() && self.code.is_none() {
                    self.para.md.push_str("\\\n");
                    self.para.plain.push('\n');
                    self.para.runs.push(InlineRun::Text {
                        text: " ".into(),
                        strong: false,
                        emph: false,
                    });
                }
            }
            Event::Rule => {
                self.flush();
                self.push_block(Block::Rule);
            }
            Event::TaskListMarker(done) => self.text(if done { "☑ " } else { "☐ " }),
            Event::FootnoteReference(t) => self.text(&format!("[{t}]")),
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => {}
            Tag::Heading { level, .. } => {
                self.flush();
                self.heading = Some(match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    _ => 3,
                });
            }
            Tag::BlockQuote(_) => {
                self.flush();
                self.quote += 1;
            }
            Tag::CodeBlock(kind) => {
                self.flush();
                let lang = match kind {
                    CodeBlockKind::Fenced(info) => {
                        info.split_whitespace().next().unwrap_or("").to_owned()
                    }
                    CodeBlockKind::Indented => String::new(),
                };
                self.code = Some((lang, String::new()));
            }
            Tag::List(start) => {
                self.flush();
                self.lists.push(start);
            }
            Tag::Item => {
                self.flush();
                self.list_prefix();
            }
            Tag::Emphasis => {
                self.emph += 1;
                self.para.md.push('*');
            }
            Tag::Strong => {
                self.strong += 1;
                self.para.md.push_str("**");
            }
            Tag::Strikethrough => self.para.md.push_str("~~"),
            Tag::Link { dest_url, .. } => self.links.push(dest_url.to_string()),
            Tag::Image { .. } => self.text("[image: "),
            Tag::Table(_) => {
                self.flush();
                self.table = Some(vec![]);
            }
            Tag::TableHead | Tag::TableRow => {
                if let Some(t) = &mut self.table {
                    t.push(vec![]);
                }
            }
            Tag::TableCell => self.cell = Some(String::new()),
            _ => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => {
                if self.lists.is_empty() {
                    self.flush();
                } else {
                    self.text(" ");
                }
            }
            TagEnd::Heading(_) => {
                self.flush();
                self.heading = None;
            }
            TagEnd::BlockQuote(_) => {
                self.flush();
                self.quote = self.quote.saturating_sub(1);
            }
            TagEnd::CodeBlock => {
                if let Some((lang, code)) = self.code.take() {
                    let code = code.strip_suffix('\n').unwrap_or(&code).to_owned();
                    self.push_block(Block::Code { lang, code });
                }
            }
            TagEnd::List(_) => {
                self.flush();
                self.lists.pop();
            }
            TagEnd::Item => self.flush(),
            TagEnd::Emphasis => {
                self.emph = self.emph.saturating_sub(1);
                self.para.md.push('*');
            }
            TagEnd::Strong => {
                self.strong = self.strong.saturating_sub(1);
                self.para.md.push_str("**");
            }
            TagEnd::Strikethrough => self.para.md.push_str("~~"),
            TagEnd::Link => {
                if let Some(url) = self.links.pop() {
                    // Always show where a link really goes (unless it already says so).
                    if !self.para.plain.ends_with(&url) {
                        self.text(&format!(" ({url})"));
                    }
                }
            }
            TagEnd::Image => self.text("]"),
            TagEnd::TableCell => {
                if let (Some(cell), Some(t)) = (self.cell.take(), &mut self.table)
                    && let Some(row) = t.last_mut()
                {
                    row.push(cell.trim().to_owned());
                }
            }
            TagEnd::Table => {
                if let Some(rows) = self.table.take() {
                    self.push_block(Block::Code { lang: String::new(), code: table_text(&rows) });
                }
            }
            _ => {}
        }
    }
}

/// A table as aligned monospace text.
fn table_text(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| rows.iter().filter_map(|r| r.get(c)).map(|s| s.chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        let cells: Vec<String> = (0..cols)
            .map(|c| {
                let s = row.get(c).map_or("", String::as_str);
                format!("{s}{}", " ".repeat(widths[c] - s.chars().count()))
            })
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
        if i == 0 && rows.len() > 1 {
            let rule: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            out.push_str(&rule.join("  "));
            out.push('\n');
        }
    }
    out.trim_end().to_owned()
}

pub fn parse(source: &str) -> Vec<Block> {
    let options = Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TABLES
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH;
    let mut b = Builder::default();
    for ev in Parser::new_ext(source, options) {
        b.event(ev);
    }
    b.flush();
    if let Some((lang, code)) = b.code.take() {
        b.push_block(Block::Code { lang, code });
    }
    b.blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_mds(blocks: &[Block]) -> Vec<String> {
        blocks
            .iter()
            .filter_map(|b| match b {
                Block::Text { md, .. } | Block::MathText { md, .. } => Some(md.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn escapes_everything_that_could_be_markup() {
        let e = escape("<font color=\"white\">hidden</font> [x](y) *a* `c` &amp; \\");
        for c in ['<', '>', '[', ']', '(', ')', '*', '`', '&', '"', '='] {
            let unescaped = e.match_indices(c).any(|(i, _)| i == 0 || &e[i - 1..i] != "\\");
            assert!(!unescaped, "{c} left unescaped in {e}");
        }
        assert_eq!(escape("\\"), "\\\\", "a backslash becomes an escaped backslash");
    }

    #[test]
    fn html_and_styling_tags_are_shown_as_text() {
        let blocks = parse("before <font color=\"#ffffff\">hidden</font> <u>u</u> after");
        let Block::Text { md, plain, .. } = &blocks[0] else { panic!("{blocks:?}") };
        assert!(md.contains("\\<font"), "{md}");
        assert!(plain.contains("<font color"));
        // It also survives Slint's own markdown parser as literal text.
        let styled = slint::StyledText::from_markdown(md);
        assert!(styled.is_ok(), "{styled:?}");
    }

    #[test]
    fn links_show_their_real_address_and_images_never_load() {
        let blocks = parse(
            "[click here](https://evil.example/login) and ![logo](https://x/y.png) and <https://ok.example>",
        );
        let Block::Text { plain, md, .. } = &blocks[0] else { panic!() };
        assert!(plain.contains("click here (https://evil.example/login)"), "{plain}");
        assert!(plain.contains("[image: logo]"), "{plain}");
        assert!(
            plain.contains("https://ok.example") && !plain.contains("https://ok.example (https"),
            "{plain}"
        );
        assert!(!md.contains("](http"), "no link markup reaches StyledText: {md}");
    }

    #[test]
    fn basic_formatting() {
        let blocks = parse(
            "**bold** *it* ~~gone~~ `code`\n\n# Title\n\n> quoted\n\n---\n\n- a\n- b\n\n1. one\n2. two",
        );
        let mds = text_mds(&blocks);
        assert_eq!(mds[0], "**bold** *it* ~~gone~~ `code`");
        assert!(matches!(blocks[1], Block::Text { style: TextStyle::Heading(1), .. }));
        assert!(matches!(blocks[2], Block::Text { style: TextStyle::Quote, .. }));
        assert!(matches!(blocks[3], Block::Rule));
        let plains: Vec<_> = blocks
            .iter()
            .filter_map(|b| {
                if let Block::Text { plain, .. } = b { Some(plain.trim().to_owned()) } else { None }
            })
            .collect();
        assert!(
            plains.contains(&"• a".to_owned()) && plains.contains(&"2. two".to_owned()),
            "{plains:?}"
        );
        for md in &mds {
            assert!(slint::StyledText::from_markdown(md).is_ok(), "{md}");
        }
    }

    #[test]
    fn code_blocks_keep_language_and_content() {
        let blocks = parse("```rust\nfn main() {}\n    indented\n```\n\n```\nplain\n```");
        assert_eq!(
            blocks[0],
            Block::Code { lang: "rust".into(), code: "fn main() {}\n    indented".into() }
        );
        assert_eq!(blocks[1], Block::Code { lang: String::new(), code: "plain".into() });
    }

    #[test]
    fn math_blocks_and_inline_math() {
        let blocks = parse("A neuron computes $y = wx + b$.\n\n$$\\frac{a}{b}$$");
        let Block::MathText { runs, md, .. } = &blocks[0] else { panic!("{blocks:?}") };
        assert!(
            runs.iter().any(|r| matches!(r, InlineRun::Math { latex } if latex == "y = wx + b"))
        );
        assert!(md.contains("`$y = wx + b$`"), "fallback shows the source: {md}");
        assert!(
            blocks.iter().any(|b| matches!(b, Block::Math { latex } if latex == "\\frac{a}{b}"))
        );
    }

    #[test]
    fn tables_become_aligned_text() {
        let blocks = parse("| a | bb |\n|---|---|\n| ccc | d |");
        let Block::Code { code, .. } = &blocks[0] else { panic!("{blocks:?}") };
        assert_eq!(code, "a    bb\n───  ──\nccc  d");
    }

    #[test]
    fn huge_messages_are_capped() {
        let source = "para\n\n".repeat(1000);
        assert_eq!(parse(&source).len(), MAX_BLOCKS + 1);
    }

    #[test]
    fn inline_code_with_backticks() {
        assert_eq!(code_span("a`b"), "``a`b``");
        assert_eq!(code_span("`x"), "`` `x ``");
        assert!(slint::StyledText::from_markdown(&code_span("``")).is_ok());
    }
}
