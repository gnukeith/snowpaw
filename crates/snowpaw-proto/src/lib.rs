//! Wire protocol shared by the snowpaw sync server, desktop client, and agent runtime.
//!
//! Every type here is a strict schema: unknown fields, duplicate fields, and wrong
//! types are rejected at deserialization time, and anything with a length or
//! character constraint has a `validate` step that callers must run before use.
//! Nothing in this crate trusts its input.

mod decode;
mod id;
mod secret;

pub mod agent;
pub mod http;
pub mod jobs;
pub mod plugin;
pub mod profile;
pub mod quiz;
pub mod render;
pub mod setup_code;
pub mod ws;

pub use decode::{DecodeError, decode, encode};
pub use id::{Id, IdParseError};
pub use secret::SecretString;

/// Protocol version spoken on `/v1/*`. Bumped on any breaking wire change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound on password size accepted anywhere. Keeps hashing cost bounded.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Minimum password length for the single-user password.
///
/// NIST SP 800-63B-4 requires at least 15 characters when a password is the
/// only authentication factor, which it is here.
pub const MIN_PASSWORD_CHARS: usize = 15;

/// Prefix on user session tokens. Makes leaked tokens easy to spot with secret scanners.
pub const SESSION_TOKEN_PREFIX: &str = "spw_s_";

/// Length of a session token on the wire: prefix + 64 hex chars (256 bits).
pub const SESSION_TOKEN_LEN: usize = SESSION_TOKEN_PREFIX.len() + 64;

/// Prefix on device tokens ("device cookies"). A device token is not a credential:
/// it only lets a device that logged in before use its own login-throttle bucket, so
/// someone hammering the login endpoint can't lock you out of devices you already use.
pub const DEVICE_TOKEN_PREFIX: &str = "spw_d_";

/// Why a candidate password was rejected when setting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPolicyError {
    TooShort,
    TooLong,
    /// Contains a control character (including newlines), which usually means a paste error.
    ControlCharacter,
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => {
                write!(f, "password must be at least {MIN_PASSWORD_CHARS} characters")
            }
            Self::TooLong => write!(f, "password must be at most {MAX_PASSWORD_BYTES} bytes"),
            Self::ControlCharacter => write!(f, "password must not contain control characters"),
        }
    }
}

impl std::error::Error for PasswordPolicyError {}

/// Policy for setting a new password. Login only enforces the size bound, so a
/// policy change never locks out an existing password.
pub fn check_new_password(password: &str) -> Result<(), PasswordPolicyError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordPolicyError::TooLong);
    }
    if password.chars().any(char::is_control) {
        return Err(PasswordPolicyError::ControlCharacter);
    }
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PasswordPolicyError::TooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy() {
        assert_eq!(check_new_password("short"), Err(PasswordPolicyError::TooShort));
        assert_eq!(check_new_password(&"a".repeat(14)), Err(PasswordPolicyError::TooShort));
        assert_eq!(check_new_password(&"a".repeat(15)), Ok(()));
        // Characters, not bytes: 15 multi-byte chars pass.
        assert_eq!(check_new_password(&"ß".repeat(15)), Ok(()));
        assert_eq!(check_new_password(&"a".repeat(1025)), Err(PasswordPolicyError::TooLong));
        assert_eq!(
            check_new_password("correct horse battery\n"),
            Err(PasswordPolicyError::ControlCharacter)
        );
        assert_eq!(
            check_new_password("correct horse\0battery staple"),
            Err(PasswordPolicyError::ControlCharacter)
        );
    }
}
