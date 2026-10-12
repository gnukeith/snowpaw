use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A string that must never appear in logs: passwords and tokens.
///
/// `Debug` is redacted, there is no `Display`, and the buffer is wiped on drop.
/// Wiping is best effort: intermediate buffers (e.g. the raw request body) are
/// outside our control.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Explicit, greppable access to the secret value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretString::new("hunter2-hunter2-hunter2".into());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert_eq!(dbg, "SecretString([REDACTED])");
        // Nested inside other Debug output, too.
        let dbg = format!("{:?}", Some(vec![s]));
        assert!(!dbg.contains("hunter2"));
    }
}
