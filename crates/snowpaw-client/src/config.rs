//! Client settings: which server to talk to and the certificate fingerprint to pin,
//! plus the device token from the last login.
//!
//! The fingerprint is what stops a network attacker from impersonating the server, so
//! the settings file must not be writable by anyone else: whoever can change it can
//! point the client at their own server and fingerprint.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snowpaw_proto::{DEVICE_TOKEN_PREFIX, SecretString};

const CONFIG_FILE: &str = "client.toml";
const DEVICE_FILE: &str = "device-token";
const PREFS_FILE: &str = "prefs.toml";
const PINS_FILE: &str = "pins";
const MAX_FONT_CHARS: usize = 100;
const MAX_FILE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// `host:port` (IPv6 in brackets).
    pub server: String,
    /// `sha256:` + 64 lowercase hex.
    pub fingerprint: String,
}

impl ClientConfig {
    /// Validate and normalize user input.
    pub fn new(server: &str, fingerprint: &str) -> Result<Self, String> {
        let (host, port) = parse_server(server)?;
        let pin = parse_fingerprint(fingerprint)?;
        let server =
            if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        Ok(Self { server, fingerprint: format_fingerprint(&pin) })
    }

    pub fn host_port(&self) -> (String, u16) {
        // Validated on construction and on load.
        parse_server(&self.server).unwrap_or_else(|_| (String::new(), 0))
    }

    pub fn pin(&self) -> [u8; 32] {
        parse_fingerprint(&self.fingerprint).unwrap_or([0; 32])
    }
}

/// `host:port`, `[v6]:port`. No scheme, no path.
pub fn parse_server(input: &str) -> Result<(String, u16), String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Enter the server address, like 127.0.0.1:7443".into());
    }
    if s.contains("://") || s.contains('/') {
        return Err("Enter just host:port, without https:// or a path".into());
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or("IPv6 addresses look like [::1]:7443")?;
        (h, p)
    } else {
        let (h, p) = s.rsplit_once(':').ok_or("Include the port, like 127.0.0.1:7443")?;
        if h.contains(':') {
            return Err("Put IPv6 addresses in brackets, like [::1]:7443".into());
        }
        (h, p)
    };
    let port: u16 = port.parse().map_err(|_| "The port must be a number from 1 to 65535")?;
    if port == 0 {
        return Err("The port must be a number from 1 to 65535".into());
    }
    if host.parse::<IpAddr>().is_err() && !valid_dns_name(host) {
        return Err(format!("\"{host}\" isn't a valid host name or IP address"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn valid_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Accepts `sha256:<hex>`, bare hex, upper or lower case, with or without colons or
/// spaces between bytes (as different tools print it).
pub fn parse_fingerprint(input: &str) -> Result<[u8; 32], String> {
    let lower = input.trim().to_ascii_lowercase();
    let body = lower.strip_prefix("sha256:").unwrap_or(&lower);
    let hex: String = body.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("The fingerprint should be \"sha256:\" followed by 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid fingerprint")?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "invalid fingerprint")?;
    }
    Ok(out)
}

pub fn format_fingerprint(pin: &[u8; 32]) -> String {
    let mut s = String::from("sha256:");
    for b in pin {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Where settings live by default: `~/Library/Application Support/snowpaw` on macOS,
/// `$XDG_CONFIG_HOME/snowpaw` (or `~/.config/snowpaw`) on Linux.
pub fn default_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute());
    if cfg!(target_os = "macos") {
        return home.map(|h| h.join("Library/Application Support/snowpaw"));
    }
    match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(x) if x.is_absolute() => Some(x.join("snowpaw")),
        _ => home.map(|h| h.join(".config/snowpaw")),
    }
}

/// Create the settings dir (mode 0700) if needed, and check an existing one isn't
/// writable by others.
fn ensure_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", dir.display()));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(format!(
                    "{} is writable by other users; run: chmod go-w \"{}\"",
                    dir.display(),
                    dir.display()
                ));
            }
            Ok(())
        }
        Err(_) => DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("creating {}: {e}", dir.display())),
    }
}

/// The effective uid settings files must belong to, learned the way the server does
/// it (the owner of a file we just created); `None` if it can't be determined, in
/// which case the owner check is skipped rather than every settings file refused.
fn effective_uid() -> Option<u32> {
    let dir = std::env::temp_dir();
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).ok()?;
    let probe = dir.join(format!(".snowpaw-uid-{}", u64::from_le_bytes(nonce)));
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&probe).ok()?;
    let uid = file.metadata().ok().map(|m| m.uid());
    drop(file);
    let _ = fs::remove_file(&probe);
    uid
}

/// The settings folder must not be writable by anyone else: whoever can change it
/// can replace settings files wholesale.
fn check_dir_at_load(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", dir.display()));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(format!(
                    "{} is writable by other users; run: chmod go-w \"{}\"",
                    dir.display(),
                    dir.display()
                ));
            }
            Ok(())
        }
        Err(_) => Ok(()), // nothing has been saved yet
    }
}

/// Read a small private file; refuse symlinks, files others can write, and files
/// owned by someone else.
///
/// Symlinks are detected without O_NOFOLLOW (whose value differs per architecture):
/// lstat the path, open it, and require the opened file to be the same inode, so a
/// symlink swapped in between the two steps is caught too. Mode bits alone aren't
/// trust: whoever creates the file chooses them, so the owner must be us (or root).
fn read_private(path: &Path) -> Result<Option<String>, String> {
    read_private_as(path, effective_uid())
}

fn read_private_as(path: &Path, euid: Option<u32>) -> Result<Option<String>, String> {
    if let Some(dir) = path.parent() {
        check_dir_at_load(dir)?;
    }
    let link_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !link_meta.file_type().is_file() {
        return Err(format!("{} is not a regular file (symlinks are refused)", path.display()));
    }
    let mut file =
        OpenOptions::new().read(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = file.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.dev() != link_meta.dev() || meta.ino() != link_meta.ino() {
        return Err(format!("{} changed while being opened", path.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by other users, so it can't be trusted; run: chmod 600 \"{}\"",
            path.display(),
            path.display()
        ));
    }
    if let Some(uid) = euid
        && meta.uid() != uid
        && meta.uid() != 0
    {
        return Err(format!("{} is owned by another user, so it can't be trusted", path.display()));
    }
    let mut text = String::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    Ok(Some(text))
}

/// Write a file atomically (temp file + rename) with mode 0600.
fn write_private(dir: &Path, name: &str, contents: &[u8]) -> Result<(), String> {
    ensure_dir(dir)?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".{name}.{}", u64::from_le_bytes(nonce)));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(contents).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn load(dir: &Path) -> Result<Option<ClientConfig>, String> {
    let Some(text) = read_private(&dir.join(CONFIG_FILE))? else { return Ok(None) };
    let raw: ClientConfig =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", dir.join(CONFIG_FILE).display()))?;
    // Re-validate: the file could have been edited by hand.
    ClientConfig::new(&raw.server, &raw.fingerprint).map(Some)
}

pub fn save(dir: &Path, cfg: &ClientConfig) -> Result<(), String> {
    let text = format!(
        "# snowpaw client settings. The fingerprint pins your server's TLS certificate.\n\
         server = \"{}\"\nfingerprint = \"{}\"\n",
        cfg.server, cfg.fingerprint
    );
    write_private(dir, CONFIG_FILE, text.as_bytes())
}

/// Light, dark, or follow the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

impl Appearance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

/// Display preferences. Not security-relevant, but still validated: a bad or
/// tampered file falls back to defaults rather than failing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Prefs {
    /// Font family: "" = the bundled default, "System" = the OS UI font, else a name.
    pub font: String,
    pub appearance: Appearance,
    /// The first-run welcome card in Note to Self was dismissed.
    pub welcomed: bool,
    /// Turn off decorative animation (falling snow, the walking-paw loader).
    pub reduce_motion: bool,
}

impl Prefs {
    /// Normalize a font name: trimmed, at most 100 characters, no control characters.
    pub fn valid_font(font: &str) -> Option<String> {
        let f = font.trim();
        (f.chars().count() <= MAX_FONT_CHARS && !f.chars().any(char::is_control))
            .then(|| f.to_owned())
    }
}

pub fn load_prefs(dir: &Path) -> Prefs {
    let Ok(Some(text)) = read_private(&dir.join(PREFS_FILE)) else { return Prefs::default() };
    match toml::from_str::<Prefs>(&text) {
        Ok(p) => Prefs { font: Prefs::valid_font(&p.font).unwrap_or_default(), ..p },
        Err(_) => Prefs::default(),
    }
}

pub fn save_prefs(dir: &Path, prefs: &Prefs) -> Result<(), String> {
    let font = Prefs::valid_font(&prefs.font).ok_or("invalid font name")?;
    // Written by hand (no TOML serializer in the build): escape for a basic string.
    let escaped: String = font
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c => vec![c],
        })
        .collect();
    let text = format!(
        "font = \"{escaped}\"\nappearance = \"{}\"\nwelcomed = {}\nreduce_motion = {}\n",
        prefs.appearance.as_str(),
        prefs.welcomed,
        prefs.reduce_motion
    );
    write_private(dir, PREFS_FILE, text.as_bytes())
}

/// Pinned chat ids (client-local), one per line. Malformed lines are ignored.
pub fn load_pins(dir: &Path) -> Vec<snowpaw_proto::Id> {
    let Ok(Some(text)) = read_private(&dir.join(PINS_FILE)) else { return vec![] };
    text.lines().filter_map(|l| snowpaw_proto::Id::parse(l.trim()).ok()).take(3).collect()
}

pub fn save_pins(dir: &Path, pins: &[snowpaw_proto::Id]) -> Result<(), String> {
    let text: String = pins.iter().map(|p| format!("{p}\n")).collect();
    write_private(dir, PINS_FILE, text.as_bytes())
}

/// The device token from the last successful login, if any. A bad or missing file just
/// means "unknown device" (it only affects login throttling).
pub fn load_device_token(dir: &Path) -> Option<SecretString> {
    let text = read_private(&dir.join(DEVICE_FILE)).ok()??;
    let token = text.trim();
    let well_formed = token.strip_prefix(DEVICE_TOKEN_PREFIX).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    well_formed.then(|| SecretString::new(token.to_owned()))
}

pub fn save_device_token(dir: &Path, token: &SecretString) -> Result<(), String> {
    write_private(dir, DEVICE_FILE, format!("{}\n", token.expose()).as_bytes())
}

pub fn forget_device_token(dir: &Path) {
    let _ = fs::remove_file(dir.join(DEVICE_FILE));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FP: &str = "sha256:8b77c1a7f5b9765267ca4547028e789427630cae167727ecc54deff732393cf9";

    #[test]
    fn server_addresses() {
        assert_eq!(parse_server("127.0.0.1:7443"), Ok(("127.0.0.1".into(), 7443)));
        assert_eq!(parse_server(" [::1]:7443 "), Ok(("::1".into(), 7443)));
        assert_eq!(
            parse_server("Snowpaw.Tail1234.ts.net:7443"),
            Ok(("snowpaw.tail1234.ts.net".into(), 7443))
        );
        for bad in [
            "",
            "127.0.0.1",
            "https://127.0.0.1:7443",
            "127.0.0.1:7443/v1",
            "127.0.0.1:0",
            "127.0.0.1:99999",
            "::1:7443",
            "bad_host:7443",
            "-x.example:7443",
            "host name:7443",
        ] {
            assert!(parse_server(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fingerprints_in_any_common_format() {
        let canonical = parse_fingerprint(FP).expect("canonical");
        let hex = &FP[7..];
        let colons: String = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect::<Vec<_>>()
            .join(":");
        for form in
            [hex.to_owned(), hex.to_uppercase(), format!("SHA256:{colons}"), format!("  {FP}\n")]
        {
            assert_eq!(parse_fingerprint(&form), Ok(canonical), "{form}");
        }
        assert_eq!(format_fingerprint(&canonical), FP);
        for bad in ["", "sha256:", &FP[..70], &format!("{FP}00"), "sha256:zz"] {
            assert!(parse_fingerprint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn save_and_load_round_trip_privately() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        assert_eq!(load(&dir), Ok(None));
        let cfg = ClientConfig::new("127.0.0.1:7443", FP).expect("valid");
        save(&dir, &cfg).expect("save");
        assert_eq!(load(&dir), Ok(Some(cfg)));
        let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(CONFIG_FILE)), 0o600);
    }

    #[test]
    fn refuses_settings_others_can_change() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        save(&dir, &ClientConfig::new("127.0.0.1:7443", FP).expect("valid")).expect("save");
        let file = dir.join(CONFIG_FILE);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(load(&dir).is_err(), "world-writable settings must not be trusted");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
        // A symlink in place of the settings file is refused.
        let elsewhere = tmp.path().join("attacker.toml");
        fs::write(&elsewhere, "server = \"10.6.6.6:7443\"\nfingerprint = \"sha256:00\"\n")
            .expect("w");
        fs::remove_file(&file).expect("rm");
        std::os::unix::fs::symlink(&elsewhere, &file).expect("symlink");
        assert!(load(&dir).is_err());
    }

    #[test]
    fn refuses_settings_someone_else_owns() {
        // Mode bits alone don't make a file ours: whoever planted it chose them.
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        let cfg = ClientConfig::new("127.0.0.1:7443", FP).expect("valid");
        save(&dir, &cfg).expect("save");
        let file = dir.join(CONFIG_FILE);
        let uid = fs::metadata(&file).expect("meta").uid();
        // Another user's file with tame mode bits (0644: group/other may read).
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(read_private_as(&file, Some(uid + 1)).is_err(), "foreign owner must be refused");
        assert!(read_private_as(&file, Some(uid)).is_ok(), "our own file is fine");
        assert!(
            read_private_as(&file, None).is_ok(),
            "an undeterminable uid skips the check rather than refusing everything"
        );
        assert!(load(&dir).is_ok(), "the real uid owns it");
    }

    #[test]
    fn refuses_a_settings_dir_others_can_write() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        let cfg = ClientConfig::new("127.0.0.1:7443", FP).expect("valid");
        save(&dir, &cfg).expect("save");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o077)).expect("chmod");
        assert!(load(&dir).is_err(), "a writable settings folder can't be trusted");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(load(&dir).is_ok());
        // The device token gets the same owner treatment: a file someone else
        // planted (here: tame 0644 bits, checked as a foreign owner) is refused.
        let token = dir.join(DEVICE_FILE);
        let t = SecretString::new(format!("{DEVICE_TOKEN_PREFIX}{}", "a".repeat(64)));
        save_device_token(&dir, &t).expect("save");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).expect("chmod");
        let uid = fs::metadata(&token).expect("meta").uid();
        assert!(read_private_as(&token, Some(uid + 1)).is_err(), "foreign owner must be refused");
        assert!(read_private_as(&token, Some(uid)).is_ok());
    }

    #[test]
    fn hand_edited_settings_are_revalidated() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        write_private(&dir, CONFIG_FILE, b"server = \"127.0.0.1:7443\"\nfingerprint = \"nope\"\n")
            .expect("w");
        assert!(load(&dir).is_err());
        write_private(&dir, CONFIG_FILE, b"server = \"x:1\"\nfingerprint = \"x\"\nextra = 1\n")
            .expect("w");
        assert!(load(&dir).is_err());
    }

    #[test]
    fn prefs_round_trip_and_validation() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        assert_eq!(load_prefs(&dir), Prefs::default());
        let p = Prefs {
            font: "Atkinson \"Hyperlegible\" \\ Next".into(),
            appearance: Appearance::Dark,
            welcomed: true,
            reduce_motion: true,
        };
        save_prefs(&dir, &p).expect("save");
        assert_eq!(load_prefs(&dir), p);
        assert!(save_prefs(&dir, &Prefs { font: "x".repeat(101), ..Prefs::default() }).is_err());
        assert!(save_prefs(&dir, &Prefs { font: "bad\u{7}".into(), ..Prefs::default() }).is_err());
        // Hand-edited garbage falls back to defaults.
        write_private(&dir, PREFS_FILE, b"appearance = \"neon\"\n").expect("w");
        assert_eq!(load_prefs(&dir), Prefs::default());
        write_private(&dir, PREFS_FILE, b"font = \"a\"\nevil = 1\n").expect("w");
        assert_eq!(load_prefs(&dir), Prefs::default());
        assert_eq!(Appearance::parse("light"), Some(Appearance::Light));
        assert_eq!(Appearance::parse("Light"), None);
    }

    #[test]
    fn pins_file() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        let ids: Vec<_> = (1..=5u8).map(|n| snowpaw_proto::Id::from_bytes([n; 16])).collect();
        save_pins(&dir, &ids[..2]).expect("save");
        assert_eq!(load_pins(&dir), ids[..2].to_vec());
        save_pins(&dir, &ids).expect("save");
        assert_eq!(load_pins(&dir).len(), 3, "never more than three");
        write_private(&dir, PINS_FILE, b"not-an-id\n").expect("w");
        assert!(load_pins(&dir).is_empty());
    }

    #[test]
    fn device_token_file() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("snowpaw");
        assert!(load_device_token(&dir).is_none());
        let t = SecretString::new(format!("{DEVICE_TOKEN_PREFIX}{}", "a".repeat(64)));
        save_device_token(&dir, &t).expect("save");
        assert_eq!(
            load_device_token(&dir).map(|x| x.expose().to_owned()),
            Some(t.expose().to_owned())
        );
        write_private(&dir, DEVICE_FILE, b"spw_s_not_a_device_token\n").expect("w");
        assert!(load_device_token(&dir).is_none());
        forget_device_token(&dir);
        assert!(load_device_token(&dir).is_none());
    }
}
