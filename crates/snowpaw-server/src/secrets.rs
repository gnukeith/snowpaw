//! Secrets at rest (model API keys): sealed with AES-256-GCM before they reach the
//! database, so a copy of the database alone (a backup, a synced folder, a stolen
//! disk image without the key file) doesn't reveal them.
//!
//! The 256-bit key lives in its own file, `secrets.key` in the data dir by default
//! (mode 0600). For stronger separation, point `secrets.key_file` somewhere else, e.g.
//! a systemd credential sealed to the TPM (`LoadCredentialEncrypted=`), so the key is
//! never on disk in the clear next to the database.
//!
//! Each sealed value is bound to what it is and whose it is (the AAD names the purpose
//! and the agent), so a ciphertext copied into another agent's row won't open.

use std::io::Read;
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use snowpaw_proto::Id;
use zeroize::Zeroizing;

use crate::fsperm;

const KEY_LEN: usize = 32;
const VERSION: u8 = 1;

/// What a sealed value is. Part of the AAD.
#[derive(Debug, Clone, Copy)]
pub enum Purpose {
    ModelApiKey,
}

impl Purpose {
    fn label(self) -> &'static str {
        match self {
            Self::ModelApiKey => "model-api-key",
        }
    }
}

pub struct Secrets {
    key: LessSafeKey,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(..)")
    }
}

#[derive(Debug)]
pub struct SecretsError(pub String);

impl std::fmt::Display for SecretsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SecretsError {}

fn fail(msg: impl Into<String>) -> SecretsError {
    SecretsError(msg.into())
}

/// Sealing or opening failed (tampered, wrong key, or wrong owner). Deliberately
/// without detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealError;

fn aad(purpose: Purpose, subject: Id) -> Vec<u8> {
    format!("snowpaw/secret/v{VERSION}/{}/{subject}", purpose.label()).into_bytes()
}

impl Secrets {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SecretsError> {
        let unbound =
            UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| fail("secrets key is unusable"))?;
        Ok(Self { key: LessSafeKey::new(unbound) })
    }

    /// Create a new random key file. Fails if the file exists.
    pub fn create(path: &Path) -> Result<(), SecretsError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(key.as_mut_slice()).map_err(|e| fail(e.to_string()))?;
        fsperm::write_new_private_file(path, key.as_slice())
            .map_err(|e| fail(format!("{}: {e}", path.display())))
    }

    /// Load the key file: a private regular file owned by `uid`, exactly 32 bytes.
    pub fn load(path: &Path, uid: u32) -> Result<Self, SecretsError> {
        let shown = path.display();
        fsperm::check_private_file(path, uid).map_err(|e| fail(format!("{shown} {e}")))?;
        let mut file = std::fs::File::open(path).map_err(|e| fail(format!("{shown}: {e}")))?;
        let mut key = Zeroizing::new(Vec::with_capacity(KEY_LEN + 1));
        (&mut file)
            .take(KEY_LEN as u64 + 1)
            .read_to_end(&mut key)
            .map_err(|e| fail(format!("{shown}: {e}")))?;
        if key.len() != KEY_LEN {
            return Err(fail(format!("{shown}: must be exactly {KEY_LEN} bytes")));
        }
        Self::from_bytes(&key)
    }

    /// For tests.
    pub fn ephemeral() -> Result<Self, SecretsError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(key.as_mut_slice()).map_err(|e| fail(e.to_string()))?;
        Self::from_bytes(key.as_slice())
    }

    /// version (1) || nonce (12) || ciphertext || tag (16)
    pub fn seal(&self, purpose: Purpose, subject: Id, plain: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| SealError)?;
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(purpose, subject)),
                &mut buf,
            )
            .map_err(|_| SealError)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + buf.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        // The plaintext copy (the key being sealed) is wiped.
        drop(Zeroizing::new(buf));
        Ok(out)
    }

    pub fn open(
        &self,
        purpose: Purpose,
        subject: Id,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let (&version, rest) = sealed.split_first().ok_or(SealError)?;
        if version != VERSION || rest.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            return Err(SealError);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError)?;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = self
            .key
            .open_in_place(nonce, Aad::from(aad(purpose, subject)), buf.as_mut_slice())
            .map_err(|_| SealError)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        Id::from_bytes([n; 16])
    }

    #[test]
    fn seal_and_open() {
        let s = Secrets::ephemeral().expect("key");
        let sealed = s.seal(Purpose::ModelApiKey, id(1), b"sk-secret").expect("seal");
        assert!(!sealed.windows(9).any(|w| w == b"sk-secret"), "no plaintext in the output");
        assert_eq!(
            s.open(Purpose::ModelApiKey, id(1), &sealed).expect("open").as_slice(),
            b"sk-secret"
        );
        // Fresh nonce every time.
        assert_ne!(sealed, s.seal(Purpose::ModelApiKey, id(1), b"sk-secret").expect("seal"));
    }

    #[test]
    fn bound_to_owner_key_and_integrity() {
        let s = Secrets::ephemeral().expect("key");
        let sealed = s.seal(Purpose::ModelApiKey, id(1), b"sk-secret").expect("seal");
        assert_eq!(
            s.open(Purpose::ModelApiKey, id(2), &sealed),
            Err(SealError),
            "another agent's row"
        );
        let other = Secrets::ephemeral().expect("key");
        assert_eq!(other.open(Purpose::ModelApiKey, id(1), &sealed), Err(SealError), "another key");
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 1;
            assert_eq!(s.open(Purpose::ModelApiKey, id(1), &t), Err(SealError), "byte {i}");
        }
        assert_eq!(s.open(Purpose::ModelApiKey, id(1), &sealed[..10]), Err(SealError));
        assert_eq!(s.open(Purpose::ModelApiKey, id(1), &[]), Err(SealError));
    }

    #[test]
    fn key_file_rules() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("secrets.key");
        let uid = fsperm::effective_uid(tmp.path()).expect("uid");
        Secrets::create(&path).expect("create");
        assert!(Secrets::create(&path).is_err(), "never overwrites");
        assert!(Secrets::load(&path, uid).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(Secrets::load(&path, uid).is_err(), "readable by others");
        let short = tmp.path().join("short.key");
        fsperm::write_new_private_file(&short, &[0u8; 16]).expect("write");
        assert!(Secrets::load(&short, uid).is_err(), "wrong length");
    }
}
