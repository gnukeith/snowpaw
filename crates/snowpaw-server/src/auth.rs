//! Password hashing, session and device tokens, and login throttling.

use argon2::password_hash::{Error as HashError, PasswordHasher, PasswordVerifier};
use argon2::{ARGON2ID_IDENT, Algorithm, Argon2, Params, PasswordHash, Version};
use sha2::{Digest, Sha256};
use snowpaw_proto::{Id, MAX_PASSWORD_BYTES, SecretString};
use zeroize::Zeroizing;

use crate::config::AuthSection;
use crate::db::Throttle;

/// Argon2id parameters: RFC 9106's second recommended option (64 MiB, 3 passes, 4 lanes).
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;

/// Bounds on parameters we'll accept from a stored hash. Below the floor would mean a
/// weakened hash; above the ceiling would let a tampered DB turn every login into a
/// memory/CPU bomb.
const STORED_M_KIB: std::ops::RangeInclusive<u32> = 19 * 1024..=1024 * 1024;
const STORED_T: std::ops::RangeInclusive<u32> = 1..=10;
const STORED_P: std::ops::RangeInclusive<u32> = 1..=16;

#[derive(Debug)]
pub enum AuthError {
    Rng,
    Hash,
    /// The stored hash isn't an Argon2id hash with acceptable parameters.
    BadStoredHash,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rng => "OS random number generator failed",
            Self::Hash => "password hashing failed",
            Self::BadStoredHash => "stored password hash is not an acceptable Argon2id hash",
        })
    }
}

impl std::error::Error for AuthError {}

fn hasher() -> Result<Argon2<'static>, AuthError> {
    let params =
        Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32)).map_err(|_| AuthError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a password to a PHC string with a fresh 128-bit salt. CPU/memory heavy:
/// call from a blocking thread.
pub fn hash_password(password: &SecretString) -> Result<String, AuthError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| AuthError::Rng)?;
    let hash = hasher()?
        .hash_password_with_salt(password.expose().as_bytes(), &salt)
        .map_err(|_| AuthError::Hash)?;
    Ok(hash.to_string())
}

/// Check a password against a stored PHC string. Comparison is constant-time.
/// CPU/memory heavy: call from a blocking thread.
pub fn verify_password(password: &SecretString, phc: &str) -> Result<bool, AuthError> {
    let pw = password.expose().as_bytes();
    if pw.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let hash = PasswordHash::new(phc).map_err(|_| AuthError::BadStoredHash)?;
    if hash.algorithm != ARGON2ID_IDENT || hash.version != Some(Version::V0x13 as u32) {
        return Err(AuthError::BadStoredHash);
    }
    let params = Params::try_from(&hash).map_err(|_| AuthError::BadStoredHash)?;
    if !STORED_M_KIB.contains(&params.m_cost())
        || !STORED_T.contains(&params.t_cost())
        || !STORED_P.contains(&params.p_cost())
    {
        return Err(AuthError::BadStoredHash);
    }
    match hasher()?.verify_password(pw, &hash) {
        Ok(()) => Ok(true),
        Err(HashError::PasswordInvalid) => Ok(false),
        Err(_) => Err(AuthError::BadStoredHash),
    }
}

/// A 256-bit random token from the OS CSPRNG: session tokens (`spw_s_`) and device
/// tokens (`spw_d_`). Only its SHA-256 is ever stored.
pub struct RandomToken(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RandomToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RandomToken([REDACTED])")
    }
}

impl RandomToken {
    pub fn generate() -> Result<Self, AuthError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| AuthError::Rng)?;
        Ok(Self(bytes))
    }

    /// The wire form handed to the client exactly once: prefix + 64 lowercase hex.
    pub fn to_wire(&self, prefix: &str) -> SecretString {
        let mut s = String::with_capacity(prefix.len() + 64);
        s.push_str(prefix);
        for b in self.0.iter() {
            s.push(hex_digit(b >> 4));
            s.push(hex_digit(b & 0x0f));
        }
        SecretString::new(s)
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_ref()).into()
    }
}

fn hex_digit(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
}

/// Strictly parse a wire token with the given prefix and return the hash used to look
/// it up. Anything that isn't exactly the canonical form is rejected.
pub fn hash_wire_token(wire: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex = wire.strip_prefix(prefix)?;
    if hex.len() != 64 {
        return None;
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    for (i, [hi, lo]) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        raw[i] = (hex_val(*hi)? << 4) | hex_val(*lo)?;
    }
    Some(Sha256::digest(raw.as_ref()).into())
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// A new random 128-bit ID.
pub fn random_id() -> Result<Id, AuthError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| AuthError::Rng)?;
    Ok(Id::from_bytes(b))
}

/// Throttle state after one more failed login.
///
/// The first `login_free_failures - 1` failures cost nothing. From then on every
/// failure locks login for `base * 2^k` seconds (k = 0, 1, 2, ...) up to the max.
///
/// This applies per throttle bucket: one bucket per known device (identified by its
/// device token) and one shared bucket for unknown devices. Not per address: there is
/// one user, and per-address limits are bypassable by anyone with many addresses. An
/// attacker can keep the unknown-device bucket locked, but can't touch the buckets of
/// devices that have logged in before, so they can't lock you out.
pub fn after_failure(t: Throttle, now_ms: i64, cfg: &AuthSection) -> Throttle {
    let failures = t.consecutive_failures.saturating_add(1);
    let locked_until_ms = if failures >= cfg.login_free_failures {
        let k = (failures - cfg.login_free_failures).min(32);
        let secs =
            cfg.login_backoff_base_secs.saturating_mul(1u64 << k).min(cfg.login_backoff_max_secs);
        now_ms.saturating_add(i64::try_from(secs * 1000).unwrap_or(i64::MAX))
    } else {
        0
    };
    Throttle { consecutive_failures: failures, locked_until_ms }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned())
    }

    #[test]
    fn hash_and_verify() {
        let pw = secret("correct horse battery staple");
        let phc = hash_password(&pw).expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"), "{phc}");
        assert!(verify_password(&pw, &phc).expect("verify"));
        assert!(!verify_password(&secret("correct horse battery stapl"), &phc).expect("verify"));
        assert!(!verify_password(&secret(""), &phc).expect("verify"));
        // Same password, different salt.
        assert_ne!(phc, hash_password(&pw).expect("hash"));
    }

    #[test]
    fn rejects_weak_or_hostile_stored_hashes() {
        let pw = secret("correct horse battery staple");
        let phc = hash_password(&pw).expect("hash");
        // Downgraded algorithm.
        let argon2i = phc.replacen("$argon2id$", "$argon2i$", 1);
        assert!(matches!(verify_password(&pw, &argon2i), Err(AuthError::BadStoredHash)));
        // Weakened memory cost.
        let weak = phc.replacen("m=65536", "m=8", 1);
        assert!(matches!(verify_password(&pw, &weak), Err(AuthError::BadStoredHash)));
        // Memory bomb (4 TiB).
        let bomb = phc.replacen("m=65536", "m=4294967295", 1);
        assert!(matches!(verify_password(&pw, &bomb), Err(AuthError::BadStoredHash)));
        let slow = phc.replacen("t=3", "t=100000", 1);
        assert!(matches!(verify_password(&pw, &slow), Err(AuthError::BadStoredHash)));
        assert!(matches!(verify_password(&pw, "plaintext"), Err(AuthError::BadStoredHash)));
    }

    #[test]
    fn token_wire_roundtrip_and_strict_parse() {
        use snowpaw_proto::{DEVICE_TOKEN_PREFIX, SESSION_TOKEN_LEN, SESSION_TOKEN_PREFIX};
        let t = RandomToken::generate().expect("token");
        let wire = t.to_wire(SESSION_TOKEN_PREFIX);
        assert_eq!(wire.expose().len(), SESSION_TOKEN_LEN);
        assert_eq!(hash_wire_token(wire.expose(), SESSION_TOKEN_PREFIX), Some(t.hash()));
        assert!(!format!("{t:?}").contains(&wire.expose()[6..]));
        // A session token is never accepted as a device token, or vice versa.
        assert_eq!(hash_wire_token(wire.expose(), DEVICE_TOKEN_PREFIX), None);
        let dev = t.to_wire(DEVICE_TOKEN_PREFIX);
        assert_eq!(hash_wire_token(dev.expose(), SESSION_TOKEN_PREFIX), None);

        let w = wire.expose();
        for bad in [
            String::new(),
            w[6..].to_owned(),                      // no prefix
            format!("{w}0"),                        // too long
            w[..w.len() - 1].to_owned(),            // too short
            w.to_uppercase(),                       // uppercase
            w.replacen("spw_s_", "spw_a_", 1),      // wrong kind
            format!(" {}", &w[1..]),                // leading space
            format!("{}\u{e9}", &w[..w.len() - 2]), // non-hex, same byte length
        ] {
            assert_eq!(hash_wire_token(&bad, SESSION_TOKEN_PREFIX), None, "{bad:?}");
        }
    }

    #[test]
    fn tokens_are_unique() {
        let a = RandomToken::generate().expect("a").hash();
        let b = RandomToken::generate().expect("b").hash();
        assert_ne!(a, b);
    }

    #[test]
    fn backoff_schedule() {
        let cfg = AuthSection {
            login_free_failures: 3,
            login_backoff_base_secs: 2,
            login_backoff_max_secs: 10,
            ..AuthSection::default()
        };
        let mut t = Throttle::default();
        let mut locks = vec![];
        for _ in 0..7 {
            t = after_failure(t, 0, &cfg);
            locks.push(t.locked_until_ms / 1000);
        }
        assert_eq!(locks, vec![0, 0, 2, 4, 8, 10, 10]);
        // Saturates instead of overflowing after absurd failure counts.
        let t = after_failure(
            Throttle { consecutive_failures: u32::MAX, locked_until_ms: 0 },
            i64::MAX - 5,
            &cfg,
        );
        assert_eq!(t.consecutive_failures, u32::MAX);
        assert_eq!(t.locked_until_ms, i64::MAX);
    }
}
