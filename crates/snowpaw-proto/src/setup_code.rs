//! Connection codes: the one line the server prints so a first-time user pastes a
//! single thing instead of an address plus a certificate fingerprint.
//!
//! `snowpaw://<host:port>#sha256:<64 lowercase hex>`
//!
//! The code carries nothing secret (the fingerprint identifies the server's public
//! certificate); it only saves typing. It is never registered as a URL handler, so
//! nothing outside the app can make the client open one.

/// Longest code accepted, after trimming.
pub const MAX_CODE_CHARS: usize = 300;

const SCHEME: &str = "snowpaw://";
const ALGORITHM: &str = "sha256:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCodeError {
    Empty,
    TooLong,
    /// Doesn't start with `snowpaw://` or has no `#sha256:` part.
    NotACode,
    BadServer,
    BadFingerprint,
}

impl std::fmt::Display for SetupCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "Paste the connection code your server printed.",
            Self::TooLong | Self::NotACode => {
                "That isn't a connection code. It starts with snowpaw:// and is printed by \
                 snowpaw-server init (or snowpaw-server connection-code)."
            }
            Self::BadServer => "The address in this code isn't valid. Copy the code again.",
            Self::BadFingerprint => {
                "The fingerprint in this code is incomplete. Copy the whole line again."
            }
        })
    }
}

impl std::error::Error for SetupCodeError {}

/// `server` is `host:port` or `[v6]:port`; `fingerprint` is `sha256:<64 hex>`.
pub fn encode(server: &str, fingerprint: &str) -> String {
    let hex = fingerprint.strip_prefix(ALGORITHM).unwrap_or(fingerprint);
    format!("{SCHEME}{server}#{ALGORITHM}{}", hex.to_ascii_lowercase())
}

/// Returns `(server, fingerprint)` with the fingerprint as `sha256:<lowercase hex>`.
/// The caller still validates the address fully before using it.
pub fn parse(code: &str) -> Result<(String, String), SetupCodeError> {
    let code = code.trim();
    if code.is_empty() {
        return Err(SetupCodeError::Empty);
    }
    if code.chars().count() > MAX_CODE_CHARS {
        return Err(SetupCodeError::TooLong);
    }
    let rest = code
        .get(..SCHEME.len())
        .filter(|s| s.eq_ignore_ascii_case(SCHEME))
        .map(|_| &code[SCHEME.len()..])
        .ok_or(SetupCodeError::NotACode)?;
    let (server, fp) = rest.split_once('#').ok_or(SetupCodeError::NotACode)?;
    let hex = fp
        .get(..ALGORITHM.len())
        .filter(|s| s.eq_ignore_ascii_case(ALGORITHM))
        .map(|_| &fp[ALGORITHM.len()..])
        .ok_or(SetupCodeError::NotACode)?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SetupCodeError::BadFingerprint);
    }
    if !valid_server(server) {
        return Err(SetupCodeError::BadServer);
    }
    Ok((server.to_ascii_lowercase(), format!("{ALGORITHM}{}", hex.to_ascii_lowercase())))
}

/// Shape only: a host made of address characters, then `:port`. No user info, path,
/// query, spaces or anything else a URL could smuggle in.
fn valid_server(s: &str) -> bool {
    let (host, port) = match s.strip_prefix('[') {
        Some(v6) => match v6.split_once("]:") {
            Some((h, p)) => (h, p),
            None => return false,
        },
        None => match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p),
            _ => return false,
        },
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p != 0);
    host_ok && port_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "sha256:3f9a1c0000000000000000000000000000000000000000000000000000007be2";

    #[test]
    fn round_trips() {
        let code = encode("127.0.0.1:7443", FP);
        assert_eq!(code, format!("snowpaw://127.0.0.1:7443#{FP}"));
        assert_eq!(parse(&code), Ok(("127.0.0.1:7443".into(), FP.into())));
        let v6 = encode("[::1]:7443", FP);
        assert_eq!(parse(&v6).map(|p| p.0), Ok("[::1]:7443".into()));
    }

    #[test]
    fn forgiving_about_case_and_whitespace() {
        let code = format!("  SnowPaw://Home.LAN:7443#SHA256:{}\n", FP[7..].to_uppercase());
        assert_eq!(parse(&code), Ok(("home.lan:7443".into(), FP.into())));
    }

    #[test]
    fn strict_about_everything_else() {
        let hex = &FP[7..];
        for bad in [
            format!("https://127.0.0.1:7443#{FP}"),
            format!("snowpaw:/127.0.0.1:7443#{FP}"),
            format!("snowpaw://127.0.0.1:7443{FP}"),
            format!("snowpaw://127.0.0.1:7443#md5:{hex}"),
            "snowpaw://127.0.0.1:7443#sha256:abc".into(),
            format!("snowpaw://127.0.0.1:7443#sha256:{hex}00"),
            format!("snowpaw://127.0.0.1:7443#sha256:{}zz", &hex[2..]),
            format!("snowpaw://127.0.0.1#{FP}"),
            format!("snowpaw://127.0.0.1:0#{FP}"),
            format!("snowpaw://127.0.0.1:99999#{FP}"),
            format!("snowpaw://user@evil.example:7443#{FP}"),
            format!("snowpaw://evil.example:7443/path#{FP}"),
            format!("snowpaw://evil.example:7443?x=1#{FP}"),
            format!("snowpaw://a b:7443#{FP}"),
            format!("snowpaw://::1:7443#{FP}"),
            format!("snowpaw://:7443#{FP}"),
            format!("snowpaw://127.0.0.1:7443#{FP} trailing"),
            format!("snowpaw://ex\u{0430}mple.com:7443#{FP}"),
            format!("snowpaw://{}:7443#{FP}", "a".repeat(300)),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        assert_eq!(parse("   "), Err(SetupCodeError::Empty));
        // Byte-boundary safety: a multibyte character right where the scheme ends.
        assert_eq!(parse("snowpa\u{00e9}//x"), Err(SetupCodeError::NotACode));
        assert_eq!(parse("ééééé"), Err(SetupCodeError::NotACode));
    }
}
