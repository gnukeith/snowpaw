use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 128-bit random identifier, encoded on the wire as exactly 32 lowercase hex chars.
///
/// Used for principals, chats, messages, threads, and client idempotency keys.
/// Parsing is strict (no uppercase, no prefixes, no whitespace) so that each ID has
/// exactly one textual form and comparisons can't be confused by aliases.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdParseError;

impl std::fmt::Display for IdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("id must be exactly 32 lowercase hex characters")
    }
}

impl std::error::Error for IdParseError {}

impl Id {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse(s: &str) -> Result<Self, IdParseError> {
        let b = s.as_bytes();
        if b.len() != 32 {
            return Err(IdParseError);
        }
        let mut out = [0u8; 16];
        for (i, [hi, lo]) in b.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (hex_val(*hi)? << 4) | hex_val(*lo)?;
        }
        Ok(Self(out))
    }
}

fn hex_val(c: u8) -> Result<u8, IdParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(IdParseError),
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id({self})")
    }
}

impl std::str::FromStr for Id {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let id = Id::from_bytes([0xab; 16]);
        let s = id.to_string();
        assert_eq!(s, "abababababababababababababababab");
        assert_eq!(Id::parse(&s), Ok(id));
    }

    #[test]
    fn rejects_non_canonical_forms() {
        for bad in [
            "",
            "abababababababababababababababa",   // 31
            "ababababababababababababababababa", // 33
            "ABABABABABABABABABABABABABABABAB",  // uppercase
            "0xababababababababababababababab",
            " abababababababababababababababa",
            "abababababababababababababababag",
            "ababababababababababababababab\u{e9}",
        ] {
            assert_eq!(Id::parse(bad), Err(IdParseError), "{bad:?}");
        }
    }
}
