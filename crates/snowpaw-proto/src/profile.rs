//! Agent profiles (name, role label, about text, picture) and the content-addressed
//! blobs pictures are stored as.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest display name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest role label ("Research", "Code"), in characters.
pub const MAX_LABEL_CHARS: usize = 32;
/// Longest "about" text, in characters.
pub const MAX_ABOUT_CHARS: usize = 500;
/// Largest picture accepted by the server, in bytes (a 256x256 PNG is far smaller).
pub const MAX_AVATAR_BYTES: usize = 512 * 1024;
/// Pictures are stored as square PNGs of exactly this size.
pub const AVATAR_SIDE: u32 = 256;

/// SHA-256 of a blob, encoded as exactly 64 lowercase hex characters. A blob is
/// always fetched by this hash, and the fetcher checks the hash of what it got, so a
/// server (or anyone in between) can't substitute different content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobHash([u8; 32]);

impl BlobHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let val = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, [hi, lo]) in b.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (val(*hi)? << 4) | val(*lo)?;
        }
        Some(Self(out))
    }
}

impl std::fmt::Display for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlobHash({self})")
    }
}

impl Serialize for BlobHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BlobHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid blob hash"))
    }
}

/// Why profile text was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    EmptyName,
    TooLong,
    /// Leading/trailing whitespace: names must be stored trimmed.
    Untrimmed,
    /// Control characters, or bidi overrides that could make a name display as
    /// something else ("Bean" impersonating another agent).
    BadCharacter,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EmptyName => "the name can't be empty",
            Self::TooLong => "too long",
            Self::Untrimmed => "remove spaces at the start and end",
            Self::BadCharacter => "contains a character that isn't allowed",
        })
    }
}

impl std::error::Error for ProfileError {}

fn check(text: &str, max_chars: usize, allow_newlines: bool) -> Result<(), ProfileError> {
    if text.chars().count() > max_chars {
        return Err(ProfileError::TooLong);
    }
    if text.trim() != text {
        return Err(ProfileError::Untrimmed);
    }
    for c in text.chars() {
        let newline_ok = allow_newlines && c == '\n';
        if (c.is_control() && !newline_ok)
            || ('\u{202A}'..='\u{202E}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
        {
            return Err(ProfileError::BadCharacter);
        }
    }
    Ok(())
}

/// A display name: 1-64 characters, trimmed, no control or bidi characters.
pub fn check_name(name: &str) -> Result<(), ProfileError> {
    if name.trim().is_empty() {
        return Err(ProfileError::EmptyName);
    }
    check(name, MAX_NAME_CHARS, false)
}

/// A role label: 0-32 characters, same character rules as names.
pub fn check_label(label: &str) -> Result<(), ProfileError> {
    check(label, MAX_LABEL_CHARS, false)
}

/// "About" text: 0-500 characters; newlines allowed.
pub fn check_about(about: &str) -> Result<(), ProfileError> {
    check(about, MAX_ABOUT_CHARS, true)
}

/// Width and height of a PNG, from its signature and IHDR chunk only. This is all
/// the server ever looks at: it never decodes images.
pub fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    if bytes.len() < 24 || bytes[..8] != SIGNATURE || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if len != 13 {
        return None;
    }
    let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    (w > 0 && h > 0).then_some((w, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_strict() {
        let h = BlobHash::from_bytes([0xab; 32]);
        assert_eq!(BlobHash::parse(&h.to_string()), Some(h));
        for bad in ["", &"a".repeat(63), &"A".repeat(64), &format!("{h}0"), &"g".repeat(64)] {
            assert_eq!(BlobHash::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn names() {
        assert!(check_name("Mochi").is_ok());
        assert!(check_name("Ünïcødé 名前").is_ok());
        assert_eq!(check_name(""), Err(ProfileError::EmptyName));
        assert_eq!(check_name("   "), Err(ProfileError::EmptyName));
        assert_eq!(check_name(" Mochi"), Err(ProfileError::Untrimmed));
        assert_eq!(check_name(&"x".repeat(65)), Err(ProfileError::TooLong));
        assert_eq!(check_name("Bean\nSystem"), Err(ProfileError::BadCharacter));
        assert_eq!(check_name("Be\u{202E}an"), Err(ProfileError::BadCharacter));
        assert_eq!(check_name("Be\u{2066}an"), Err(ProfileError::BadCharacter));
        assert!(check_label("").is_ok());
        assert!(check_about("line one\nline two").is_ok());
        assert_eq!(check_about(&"x".repeat(501)), Err(ProfileError::TooLong));
    }

    #[test]
    fn png_header() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 13];
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&256u32.to_be_bytes());
        png.extend_from_slice(&256u32.to_be_bytes());
        assert_eq!(png_dimensions(&png), Some((256, 256)));
        assert_eq!(png_dimensions(b"GIF89a................"), None);
        let mut bad = png.clone();
        bad[12..16].copy_from_slice(b"IDAT");
        assert_eq!(png_dimensions(&bad), None);
        assert_eq!(png_dimensions(&png[..20]), None);
    }
}
