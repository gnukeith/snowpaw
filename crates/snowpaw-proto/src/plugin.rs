//! Plugins: WebAssembly modules that give agents new tools.
//!
//! A plugin is a core wasm module with its manifest embedded in a custom section named
//! `snowpaw-manifest`. Only the user installs plugins and grants them to agents; a
//! grant can narrow the capabilities the manifest asks for, never widen them.
//!
//! ## Plugin API, version 1
//!
//! The module imports nothing: no WASI, no host functions, so a plugin can only
//! compute. It exports:
//! - `memory`
//! - `snowpaw_api() -> i32`: returns 1.
//! - `snowpaw_buffer(len: i32) -> i32`: makes room for `len` input bytes, returns where.
//! - `snowpaw_run(len: i32) -> i32`: handles the `len` input bytes, returns the output length.
//! - `snowpaw_output() -> i32`: where the output is.
//!
//! Input (JSON): `{"tool": "...", "args": {...}, "state": <json or null>,
//! "fetched": <Fetched or null>}`.
//! Output (JSON): `{"result": "text for the model"}`, `{"error": "..."}`, or
//! `{"fetch": {"url": "https://..."}, "state": <json>}` to have the runtime fetch a URL
//! (through the server, which checks it against the hosts this agent was granted) and
//! call the plugin again with the response in `fetched` and the same `state`.

use serde::{Deserialize, Serialize};

use crate::Id;
use crate::agent::ToolSpec;
use crate::profile::BlobHash;

pub const PLUGIN_API_VERSION: u32 = 1;
/// The wasm custom section that holds the manifest.
pub const MANIFEST_SECTION: &str = "snowpaw-manifest";
/// Largest plugin module.
pub const MAX_PLUGIN_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_PLUGIN_NAME_CHARS: usize = 24;
pub const MAX_PLUGIN_TOOLS: usize = 16;
pub const MAX_PLUGIN_TOOL_NAME_CHARS: usize = 32;
pub const MAX_HTTP_HOSTS: usize = 16;
/// Largest response body handed to a plugin.
pub const MAX_FETCH_BYTES: usize = 1024 * 1024;
pub const MAX_URL_CHARS: usize = 2048;

/// The manifest, as plugin authors write it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub api: u32,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub tools: Vec<ManifestTool>,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTool {
    pub name: String,
    pub description: String,
    /// JSON Schema object for the arguments.
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Hosts the plugin may fetch from (HTTPS only), exact names.
    #[serde(default)]
    pub http: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginError {
    NotWasm,
    TooLarge,
    /// No `snowpaw-manifest` section, or more than one.
    NoManifest,
    BadManifest,
    UnsupportedApi,
    BadName,
    BadTool,
    BadHost,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotWasm => "not a WebAssembly module",
            Self::TooLarge => "the plugin is too large",
            Self::NoManifest => "the plugin has no snowpaw-manifest section (or more than one)",
            Self::BadManifest => "the manifest isn't valid JSON of the expected shape",
            Self::UnsupportedApi => "the plugin was built for a different plugin API version",
            Self::BadName => "the plugin name or version isn't valid",
            Self::BadTool => "a tool name, description or parameter schema isn't valid",
            Self::BadHost => "an HTTP host isn't a valid host name",
        })
    }
}

impl std::error::Error for PluginError {}

fn leb_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    for i in 0..5 {
        let b = *bytes.get(*pos)?;
        *pos += 1;
        result |= u32::from(b & 0x7f).checked_shl(7 * i)?;
        if b & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

/// The manifest bytes from a wasm module's `snowpaw-manifest` custom section. Walks
/// the section headers only; the code itself is never looked at here.
pub fn manifest_section(wasm: &[u8]) -> Result<&[u8], PluginError> {
    if wasm.len() > MAX_PLUGIN_BYTES {
        return Err(PluginError::TooLarge);
    }
    if wasm.len() < 8 || wasm[..4] != *b"\0asm" || wasm[4..8] != [1, 0, 0, 0] {
        return Err(PluginError::NotWasm);
    }
    let mut pos = 8;
    let mut found: Option<&[u8]> = None;
    while pos < wasm.len() {
        let id = wasm[pos];
        pos += 1;
        let size = leb_u32(wasm, &mut pos).ok_or(PluginError::NotWasm)? as usize;
        let end = pos.checked_add(size).filter(|e| *e <= wasm.len()).ok_or(PluginError::NotWasm)?;
        if id == 0 {
            let mut p = pos;
            let name_len = leb_u32(wasm, &mut p).ok_or(PluginError::NotWasm)? as usize;
            let name_end =
                p.checked_add(name_len).filter(|e| *e <= end).ok_or(PluginError::NotWasm)?;
            if &wasm[p..name_end] == MANIFEST_SECTION.as_bytes() {
                if found.is_some() {
                    return Err(PluginError::NoManifest);
                }
                found = Some(&wasm[name_end..end]);
            }
        }
        pos = end;
    }
    found.ok_or(PluginError::NoManifest)
}

fn valid_host(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.parse::<std::net::IpAddr>().is_err()
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // The last label of a real domain isn't all digits.
        && h.rsplit('.').next().is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

fn short_text_ok(s: &str, max: usize) -> bool {
    s.chars().count() <= max
        && s.chars().all(|c| !c.is_control() && !('\u{202A}'..='\u{202E}').contains(&c))
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, PluginError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PluginError::TooLarge);
        }
        let m: Self = serde_json::from_slice(bytes).map_err(|_| PluginError::BadManifest)?;
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), PluginError> {
        if self.api != PLUGIN_API_VERSION {
            return Err(PluginError::UnsupportedApi);
        }
        let name_ok = (1..=MAX_PLUGIN_NAME_CHARS).contains(&self.name.len())
            && self.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && (1..=32).contains(&self.version.len())
            && self.version.bytes().all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
            && short_text_ok(&self.description, 500);
        if !name_ok {
            return Err(PluginError::BadName);
        }
        let mut names: Vec<&str> = self.tools.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        let tools_ok = !self.tools.is_empty()
            && self.tools.len() <= MAX_PLUGIN_TOOLS
            && names.len() == self.tools.len()
            && self.tools.iter().all(|t| {
                (1..=MAX_PLUGIN_TOOL_NAME_CHARS).contains(&t.name.len())
                    && t.name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    && short_text_ok(&t.description, 1024)
                    && t.parameters.is_object()
                    && serde_json::to_string(&t.parameters).is_ok_and(|s| s.len() <= 16 * 1024)
            });
        if !tools_ok {
            return Err(PluginError::BadTool);
        }
        let mut hosts = self.capabilities.http.clone();
        hosts.sort_unstable();
        hosts.dedup();
        if self.capabilities.http.len() > MAX_HTTP_HOSTS
            || hosts.len() != self.capabilities.http.len()
            || !self.capabilities.http.iter().all(|h| valid_host(h))
        {
            return Err(PluginError::BadHost);
        }
        Ok(())
    }

    /// The tools as offered to a model: `<plugin>__<tool>`.
    pub fn tool_specs(&self) -> Vec<ToolSpec> {
        self.tools
            .iter()
            .map(|t| ToolSpec {
                name: format!("{}__{}", self.name.replace('-', "_"), t.name),
                description: t.description.clone(),
                parameters: serde_json::to_string(&t.parameters).unwrap_or_else(|_| "{}".into()),
            })
            .collect()
    }
}

/// An installed plugin, as the user sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginView {
    pub id: Id,
    pub name: String,
    pub version: String,
    pub description: String,
    pub hash: BlobHash,
    pub tools: Vec<ToolSpec>,
    /// Hosts the plugin asks to fetch from.
    pub http_hosts: Vec<String>,
    /// Which agents may use it, and with which hosts.
    pub grants: Vec<PluginGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginGrant {
    pub agent: Id,
    pub http_hosts: Vec<String>,
}

/// A plugin as an agent runtime sees it: what to load and what it may do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedPlugin {
    pub plugin: Id,
    pub name: String,
    pub version: String,
    /// SHA-256 of the module; the runtime checks the code it downloads against it.
    pub hash: BlobHash,
    pub tools: Vec<ToolSpec>,
    pub http_hosts: Vec<String>,
}

/// A fetched response, as handed to a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fetched {
    pub status: u16,
    pub content_type: String,
    /// Text (invalid UTF-8 replaced), at most `MAX_FETCH_BYTES`.
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchFailure {
    /// The host isn't one this agent was granted for this plugin, or the URL isn't
    /// HTTPS.
    NotAllowed,
    /// The name resolved to an address that isn't on the public internet.
    Blocked,
    Paused,
    RateLimited,
    TooLarge,
    Timeout,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal wasm module with the given custom sections.
    pub(crate) fn module(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        for (name, payload) in sections {
            let mut body = vec![name.len() as u8];
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(payload);
            out.push(0);
            out.push(body.len() as u8);
            out.extend_from_slice(&body);
        }
        out
    }

    const MANIFEST: &str = r#"{"api":1,"name":"weather","version":"1.0.0","description":"Forecasts",
        "tools":[{"name":"forecast","description":"Weather for a city","parameters":{"type":"object"}}],
        "capabilities":{"http":["api.open-meteo.com"]}}"#;

    #[test]
    fn finds_the_manifest() {
        let wasm = module(&[("name", b"x"), (MANIFEST_SECTION, br#"{"a":1}"#)]);
        assert_eq!(manifest_section(&wasm), Ok(&br#"{"a":1}"#[..]));
        assert_eq!(manifest_section(&module(&[("other", b"x")])), Err(PluginError::NoManifest));
        let twice = module(&[(MANIFEST_SECTION, b"{}"), (MANIFEST_SECTION, b"{}")]);
        assert_eq!(manifest_section(&twice), Err(PluginError::NoManifest));
        assert_eq!(manifest_section(b"\x7fELF...."), Err(PluginError::NotWasm));
        // A section claiming to run past the end.
        let mut bad = module(&[(MANIFEST_SECTION, b"{}")]);
        bad[9] = 0x7f;
        assert_eq!(manifest_section(&bad), Err(PluginError::NotWasm));
        // An endless LEB128.
        let mut leb = b"\0asm\x01\0\0\0\0".to_vec();
        leb.extend_from_slice(&[0xff; 10]);
        assert_eq!(manifest_section(&leb), Err(PluginError::NotWasm));
    }

    #[test]
    fn manifest_rules() {
        let m = Manifest::parse(MANIFEST.as_bytes()).expect("valid");
        assert_eq!(m.tool_specs()[0].name, "weather__forecast");
        let with = |from: &str, to: &str| MANIFEST.replace(from, to);
        for (bad, why) in [
            (with(r#""api":1"#, r#""api":2"#), PluginError::UnsupportedApi),
            (with("weather", "Weather"), PluginError::BadName),
            (with("weather", "../etc"), PluginError::BadName),
            (with(r#""forecast""#, r#""fore cast""#), PluginError::BadTool),
            (with(r#"{"type":"object"}"#, "[]"), PluginError::BadTool),
            (with("api.open-meteo.com", "127.0.0.1"), PluginError::BadHost),
            (with("api.open-meteo.com", "localhost"), PluginError::BadHost),
            (with("api.open-meteo.com", "*.example.com"), PluginError::BadHost),
            (with("api.open-meteo.com", "https://x.com"), PluginError::BadHost),
            (with("api.open-meteo.com", "1.2.3.4.5"), PluginError::BadHost),
            (
                with(r#""version":"1.0.0""#, r#""version":"1.0.0","exec":"rm"#),
                PluginError::BadManifest,
            ),
        ] {
            assert_eq!(Manifest::parse(bad.as_bytes()), Err(why), "{bad}");
        }
    }
}
