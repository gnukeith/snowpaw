//! The one entry point for turning untrusted bytes into protocol types.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroize;

/// Why input was rejected. Deliberately carries no detail: serde error messages
/// can quote the input, and input may be secret or attacker-controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Not well-formed JSON (or trailing garbage).
    Syntax,
    /// Well-formed JSON that doesn't match the schema.
    Schema,
    /// Matches the schema only through an alternate encoding, e.g. a struct
    /// written as a positional array, or an explicit `null` for an omitted field.
    NonCanonical,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Syntax => "malformed JSON",
            Self::Schema => "input does not match the schema",
            Self::NonCanonical => "input is not in canonical form",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Strictly decode `input` as `T`.
///
/// On top of serde's checks (`deny_unknown_fields`, duplicate keys, exact types),
/// this re-serializes the result and requires it to equal the input. Serde's derive
/// also accepts structs as positional arrays; this closes that and any other
/// alias, so each message has exactly one accepted wire form and no two parsers
/// in the system can disagree about what a message says.
///
/// Callers must still run any type-specific `validate` step afterwards.
pub fn decode<T: Serialize + DeserializeOwned>(input: &[u8]) -> Result<T, DecodeError> {
    // Parse straight into `T` first: this is the pass that rejects duplicate keys.
    // (`Value` silently keeps the last duplicate, so it can't be the only parse.)
    let parsed: T = serde_json::from_slice(input).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => DecodeError::Schema,
        _ => DecodeError::Syntax,
    })?;
    let mut raw: Value = serde_json::from_slice(input).map_err(|_| DecodeError::Syntax)?;
    let mut canonical = serde_json::to_value(&parsed).map_err(|_| DecodeError::Schema)?;
    let same = canonical == raw;
    wipe(&mut raw);
    wipe(&mut canonical);
    if same { Ok(parsed) } else { Err(DecodeError::NonCanonical) }
}

/// Serialize a protocol value to its canonical JSON form.
pub fn encode<T: Serialize>(value: &T) -> String {
    // Protocol types contain only strings, integers, and enums, so serialization can't fail.
    serde_json::to_string(value).unwrap_or_else(|_| unreachable!("protocol types always serialize"))
}

/// Best-effort wipe of intermediate copies (e.g. a password inside a login body).
fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Opt {
        a: u8,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        b: Option<u8>,
    }

    #[test]
    fn accepts_canonical() {
        assert_eq!(decode::<Opt>(br#"{"a":1}"#), Ok(Opt { a: 1, b: None }));
        assert_eq!(decode::<Opt>(br#" { "b":2, "a":1 } "#), Ok(Opt { a: 1, b: Some(2) }));
    }

    #[test]
    fn rejects_aliases() {
        assert_eq!(decode::<Opt>(br#"[1]"#), Err(DecodeError::NonCanonical));
        assert_eq!(decode::<Opt>(br#"{"a":1,"b":null}"#), Err(DecodeError::NonCanonical));
        assert_eq!(decode::<Opt>(br#"{"a":1,"c":3}"#), Err(DecodeError::Schema));
        assert_eq!(decode::<Opt>(br#"{"a":1,"a":1}"#), Err(DecodeError::Schema));
        assert_eq!(decode::<Opt>(br#"{"a":1} x"#), Err(DecodeError::Syntax));
        assert_eq!(decode::<Opt>(b"\xff"), Err(DecodeError::Syntax));
    }
}
