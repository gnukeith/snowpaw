//! Math typesetting: LaTeX -> Typst math (mitex) -> image (Typst).
//!
//! The Typst "world" here has no filesystem, no packages, and no clock: the only
//! sources are the generated document and the vendored mitex scope, and the only
//! fonts are the ones bundled in the binary.

use snowpaw_proto::render::{InlineRun, MAX_IMAGE_PIXELS, MAX_IMAGE_SIDE, RenderFailure, Rgb};
use typst::diag::{FileError, FileResult};
use typst::foundations::{Bytes, Datetime, Duration};
use typst::syntax::{FileId, RootedPath, Source, VirtualPath, VirtualRoot};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, LibraryExt, World};
use typst_layout::PagedDocument;

const MITEX_FILES: [(&str, &str); 3] = [
    ("/mitex/mod.typ", include_str!("../assets/mitex/mod.typ")),
    ("/mitex/prelude.typ", include_str!("../assets/mitex/prelude.typ")),
    ("/mitex/latex/standard.typ", include_str!("../assets/mitex/latex/standard.typ")),
];

pub struct MathEngine {
    library: LazyHash<Library>,
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
    scope: Vec<Source>,
    main_id: FileId,
}

impl std::fmt::Debug for MathEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MathEngine")
    }
}

fn file_id(path: &str) -> Option<FileId> {
    Some(RootedPath::new(VirtualRoot::Project, VirtualPath::new(path).ok()?).intern())
}

/// A Typst string literal containing `s`.
fn string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Symbols mitex 0.2.4 emits under names Typst has since renamed (checked against
/// Typst 0.15's symbol table). Prefix match on dotted names, longest first.
const RENAMES: &[(&str, &str)] = &[
    ("bracket.l.double", "bracket.l.stroked"),
    ("bracket.r.double", "bracket.r.stroked"),
    ("planck.reduce", "planck"),
    ("circle.nested", "compose.o"),
    ("arrow.l.dash", "arrow.l.dashed"),
    ("arrow.r.dash", "arrow.r.dashed"),
    ("minus.circle", "minus.o"),
    ("times.circle", "times.o"),
    ("plus.circle", "plus.o"),
    ("dash.circle", "dash.o"),
    ("ast.circle", "ast.op.o"),
    ("dot.circle", "dot.o"),
    ("ohm.inv", "Omega.inv"),
    ("angle.l", "chevron.l"),
    ("angle.r", "chevron.r"),
    ("argmax", "op(\"arg max\", limits: #true)"),
    ("argmin", "op(\"arg min\", limits: #true)"),
    ("diff", "partial"),
    ("sect", "inter"),
];

fn rename(token: &str) -> String {
    for (old, new) in RENAMES {
        if token == *old {
            return (*new).to_owned();
        }
        if let Some(rest) = token.strip_prefix(old)
            && rest.starts_with('.')
        {
            return format!("{new}{rest}");
        }
    }
    token.to_owned()
}

/// Rewrite outdated symbol names in mitex's Typst math. Only identifiers in math code
/// are touched: never text inside `[...]` content blocks or string literals.
fn modernize(math: &str) -> String {
    let chars: Vec<char> = math.chars().collect();
    let mut out = String::with_capacity(math.len());
    let (mut i, mut depth, mut in_str) = (0, 0usize, false);
    let ident = |c: char| c.is_ascii_alphanumeric();
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            in_str = c != '"';
            i += 1;
            continue;
        }
        match c {
            '"' => in_str = true,
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            c if c.is_ascii_alphabetic() && depth == 0 && (i == 0 || !ident(chars[i - 1])) => {
                let start = i;
                while i < chars.len()
                    && (ident(chars[i])
                        || (chars[i] == '.'
                            && chars.get(i + 1).is_some_and(char::is_ascii_alphabetic)))
                {
                    i += 1;
                }
                let token: String = chars[start..i].iter().collect();
                out.push_str(&rename(&token));
                continue;
            }
            _ => {}
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Typst code that evaluates converted LaTeX as math in the mitex scope.
fn equation(latex: &str, block: bool) -> Result<String, RenderFailure> {
    let converted = mitex::convert_math(latex, None).map_err(|_| RenderFailure::InvalidMath)?;
    let converted = modernize(&converted);
    Ok(format!(
        "#math.equation(block: {block}, eval(\"$\" + {} + \"$\", scope: mitex-scope))",
        string_literal(&converted)
    ))
}

fn preamble(color: Rgb, size_pt: u8, width: Option<u16>) -> String {
    let width = width.map_or_else(|| "auto".to_owned(), |w| format!("{w}pt"));
    format!(
        "#import \"/mitex/mod.typ\": mitex-scope\n\
         #set page(width: {width}, height: auto, margin: 1pt, fill: none)\n\
         #set text(size: {size_pt}pt, fill: rgb({}, {}, {}), font: \"New Computer Modern\")\n\
         #set par(justify: false)\n",
        color.r, color.g, color.b
    )
}

struct RequestWorld<'a> {
    engine: &'a MathEngine,
    main: Source,
}

impl World for RequestWorld<'_> {
    fn library(&self) -> &LazyHash<Library> {
        &self.engine.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &self.engine.book
    }

    fn main(&self) -> FileId {
        self.engine.main_id
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.engine.main_id {
            return Ok(self.main.clone());
        }
        self.engine
            .scope
            .iter()
            .find(|s| s.id() == id)
            .cloned()
            .ok_or_else(|| FileError::NotFound(std::path::PathBuf::new()))
    }

    fn file(&self, _id: FileId) -> FileResult<Bytes> {
        // No binary files of any kind: no images, data, or plugins.
        Err(FileError::AccessDenied)
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.engine.fonts.get(index).cloned()
    }

    fn today(&self, _offset: Option<Duration>) -> Option<Datetime> {
        None
    }
}

/// A rendered image: premultiplied RGBA.
#[derive(Debug)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl MathEngine {
    pub fn new() -> Option<Self> {
        let fonts: Vec<Font> =
            typst_assets::fonts().flat_map(|data| Font::iter(Bytes::new(data))).collect();
        let book = FontBook::from_fonts(&fonts);
        let scope = MITEX_FILES
            .iter()
            .map(|(path, text)| Some(Source::new(file_id(path)?, (*text).to_owned())))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            library: LazyHash::new(Library::default()),
            book: LazyHash::new(book),
            fonts,
            scope,
            main_id: file_id("/main.typ")?,
        })
    }

    pub fn display(
        &self,
        latex: &str,
        color: Rgb,
        size_pt: u8,
        scale: u8,
    ) -> Result<Image, RenderFailure> {
        let doc = format!("{}{}\n", preamble(color, size_pt, None), equation(latex, true)?);
        self.render(doc, scale)
    }

    pub fn paragraph(
        &self,
        runs: &[InlineRun],
        color: Rgb,
        size_pt: u8,
        width_pt: u16,
        scale: u8,
    ) -> Result<Image, RenderFailure> {
        let mut doc = preamble(color, size_pt, Some(width_pt));
        for run in runs {
            match run {
                InlineRun::Text { text, strong, emph } => {
                    let mut inner = string_literal(text);
                    if *emph {
                        inner = format!("emph({inner})");
                    }
                    if *strong {
                        inner = format!("strong({inner})");
                    }
                    doc.push_str(&format!("#{inner}"));
                }
                InlineRun::Code { text } => {
                    doc.push_str(&format!("#raw({})", string_literal(text)))
                }
                InlineRun::Math { latex } => doc.push_str(&equation(latex, false)?),
            }
        }
        doc.push('\n');
        self.render(doc, scale)
    }

    fn render(&self, doc: String, scale: u8) -> Result<Image, RenderFailure> {
        let world = RequestWorld { engine: self, main: Source::new(self.main_id, doc) };
        let document: PagedDocument =
            typst::compile(&world).output.map_err(|_| RenderFailure::InvalidMath)?;
        let page = document.pages().first().ok_or(RenderFailure::InvalidMath)?;
        // Check the size before allocating any pixels.
        let size = page.frame.size();
        let w = (size.x.to_pt() * f64::from(scale)).ceil();
        let h = (size.y.to_pt() * f64::from(scale)).ceil();
        let side = f64::from(MAX_IMAGE_SIDE);
        if !(w >= 1.0 && h >= 1.0 && w <= side && h <= side && w * h <= MAX_IMAGE_PIXELS as f64) {
            return Err(RenderFailure::TooLarge);
        }
        let options = typst_render::RenderOptions {
            pixel_per_pt: f64::from(scale).into(),
            render_bleed: false,
        };
        let pixmap = typst_render::render(page, &options);
        Ok(Image { width: pixmap.width(), height: pixmap.height(), rgba: pixmap.data().to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLACK: Rgb = Rgb { r: 0, g: 0, b: 0 };

    fn engine() -> MathEngine {
        MathEngine::new().expect("engine")
    }

    #[test]
    fn renders_display_math() {
        let img = engine()
            .display(r"\frac{a}{b} + \sum_{i=1}^{n} i^2 = \sqrt{x}", BLACK, 14, 2)
            .expect("render");
        assert!(img.width > 50 && img.height > 20, "{}x{}", img.width, img.height);
        assert_eq!(img.rgba.len(), (img.width * img.height * 4) as usize);
        assert!(img.rgba.chunks(4).any(|p| p[3] > 0), "something was drawn");
    }

    #[test]
    fn renders_matrices_and_arrows() {
        let e = engine();
        assert!(e.display(r"\begin{pmatrix} 1 & 2 \\ 3 & 4 \end{pmatrix}", BLACK, 14, 1).is_ok());
        assert!(e.display(r"A \xrightarrow{f} B", BLACK, 14, 1).is_ok());
        assert!(e.display(r"\mathbb{R}^n \to \mathbb{R}", BLACK, 14, 1).is_ok());
    }

    #[test]
    fn renders_a_mixed_paragraph() {
        let runs = vec![
            InlineRun::Text { text: "A neuron computes ".into(), strong: false, emph: false },
            InlineRun::Math { latex: r"y = w \times x + b".into() },
            InlineRun::Text { text: " with weight ".into(), strong: true, emph: false },
            InlineRun::Code { text: "w".into() },
        ];
        let img = engine().paragraph(&runs, BLACK, 14, 400, 2).expect("render");
        assert!(img.width > 100);
    }

    #[test]
    fn typst_code_in_latex_stays_inert() {
        let e = engine();
        // These must never run as Typst code; at worst they render as symbols or fail.
        for hostile in [
            r#"#read("/etc/passwd")"#,
            r#"\text{#read("/etc/passwd")}"#,
            r#"#import "@preview/x:1.0.0""#,
        ] {
            match e.display(hostile, BLACK, 14, 1) {
                Ok(_) | Err(RenderFailure::InvalidMath) => {}
                Err(other) => panic!("{hostile}: {other:?}"),
            }
        }
        // Text runs are string literals, never markup.
        let runs = vec![InlineRun::Text {
            text: r#"#read("/etc/passwd") $x$ *bold* " \"#.into(),
            strong: false,
            emph: false,
        }];
        assert!(e.paragraph(&runs, BLACK, 14, 400, 1).is_ok());
    }

    #[test]
    fn huge_output_is_refused() {
        let e = engine();
        let wide = r"x + ".repeat(800);
        assert!(matches!(
            e.display(&wide, BLACK, 72, 4),
            Err(RenderFailure::TooLarge | RenderFailure::InvalidMath)
        ));
    }

    #[test]
    fn vendored_mitex_scope_compiles() {
        // Guards against Typst upgrades breaking the vendored scope (e.g. removed symbols).
        let e = engine();
        let doc = format!("{}ok", preamble(BLACK, 14, None));
        let world = RequestWorld { engine: &e, main: Source::new(e.main_id, doc) };
        assert!(typst::compile::<PagedDocument>(&world).output.is_ok());
    }

    #[test]
    fn string_literals_escape() {
        assert_eq!(string_literal(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(string_literal("x\ny"), r#""x\ny""#);
    }
}

#[cfg(test)]
mod mitex_compat {
    use super::*;
    use mitex::{CmdShape, CommandSpecItem};

    fn errors(e: &MathEngine, latex: &str) -> Vec<String> {
        let Ok(eq) = equation(latex, true) else { return vec![] };
        let doc = format!("{}{eq}\n", preamble(Rgb { r: 0, g: 0, b: 0 }, 14, None));
        let world = RequestWorld { engine: e, main: Source::new(e.main_id, doc) };
        match typst::compile::<PagedDocument>(&world).output {
            Ok(_) => vec![],
            Err(errs) => errs.iter().map(|e| e.message.to_string()).collect(),
        }
    }

    /// Every LaTeX command mitex knows must map to symbols this Typst version has.
    /// Catches renames/removals (e.g. `diff` -> `partial`) on Typst upgrades. Other
    /// failures (document commands like `\cite` used in math) are expected.
    #[test]
    fn every_mitex_command_uses_known_symbols() {
        let e = MathEngine::new().expect("engine");
        let mut failures = vec![];
        // Document/table commands that have no meaning in math, and spacing commands
        // whose argument must be a length (our generic test argument isn't one).
        const NOT_MATH: [&str; 6] =
            ["toprule", "midrule", "bottomrule", "textwidth", "hspace", "vspace"];
        for (name, item) in mitex_spec_gen::DEFAULT_SPEC.items() {
            let CommandSpecItem::Cmd(CmdShape { args, .. }) = item else { continue };
            if NOT_MATH.contains(&name) {
                continue;
            }
            let no_args = matches!(format!("{args:?}").as_str(), s if s.contains("Fixed(0)") || s == "Right(None)");
            let latex = if no_args { format!("\\{name}") } else { format!("\\{name}{{x}}") };
            for msg in errors(&e, &latex) {
                if msg.contains("unknown variable") || msg.contains("unknown symbol") {
                    failures.push(format!("{latex}: {msg}"));
                }
            }
        }
        failures.sort();
        assert!(failures.is_empty(), "{} commands fail:\n{}", failures.len(), failures.join("\n"));
    }

    #[test]
    fn modernize_only_touches_math_identifiers() {
        assert_eq!(modernize("frac(diff  L ,diff  w )"), "frac(partial  L ,partial  w )");
        assert_eq!(modernize("sect.big  x"), "inter.big  x");
        assert_eq!(modernize("plus.circle.big"), "plus.o.big");
        assert_eq!(modernize("difff  sector"), "difff  sector");
        assert_eq!(
            modernize(r#"#textmath[diff and sect] diff"#),
            "#textmath[diff and sect] partial"
        );
        assert_eq!(modernize(r#"op("diff \" sect") diff"#), r#"op("diff \" sect") partial"#);
    }
}
