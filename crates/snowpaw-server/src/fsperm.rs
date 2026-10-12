//! File and directory permission checks for secrets and state.
//!
//! Everything the server keeps on disk (database, TLS key) lives in a data dir that
//! must be owned by the server's user with mode 0700, and secret files must be
//! mode 0600 (no group/other bits). Symlinks are refused so a local attacker can't
//! point a path somewhere else.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Debug)]
pub enum PermError {
    Io(io::Error),
    Symlink,
    NotADirectory,
    NotAFile,
    /// Group or other has some access. Carries the actual mode.
    TooOpen(u32),
    WrongOwner {
        owner: u32,
        expected: u32,
    },
}

impl std::fmt::Display for PermError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Symlink => f.write_str("is a symlink (refused)"),
            Self::NotADirectory => f.write_str("is not a directory"),
            Self::NotAFile => f.write_str("is not a regular file"),
            Self::TooOpen(mode) => {
                write!(
                    f,
                    "has mode {:04o}; group/other must have no access (chmod go-rwx)",
                    mode & 0o7777
                )
            }
            Self::WrongOwner { owner, expected } => {
                write!(f, "is owned by uid {owner}, expected uid {expected}")
            }
        }
    }
}

impl std::error::Error for PermError {}

impl From<io::Error> for PermError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The data dir: a real directory (not a symlink), owned by `uid`, no group/other access.
pub fn check_private_dir(path: &Path, uid: u32) -> Result<(), PermError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(PermError::Symlink);
    }
    if !meta.is_dir() {
        return Err(PermError::NotADirectory);
    }
    check_owner_and_mode(&meta, uid)
}

/// A secret file: a regular file (not a symlink), owned by `uid`, no group/other access.
pub fn check_private_file(path: &Path, uid: u32) -> Result<(), PermError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(PermError::Symlink);
    }
    if !meta.is_file() {
        return Err(PermError::NotAFile);
    }
    check_owner_and_mode(&meta, uid)
}

fn check_owner_and_mode(meta: &fs::Metadata, uid: u32) -> Result<(), PermError> {
    if meta.uid() != uid {
        return Err(PermError::WrongOwner { owner: meta.uid(), expected: uid });
    }
    if meta.mode() & 0o077 != 0 {
        return Err(PermError::TooOpen(meta.mode()));
    }
    Ok(())
}

/// Create a directory with mode 0700. Fails if it already exists.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

/// Create a new file with mode 0600 and write `contents`. Never overwrites, never
/// follows a symlink at `path` (`create_new` fails if anything exists there).
pub fn write_new_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// The effective uid of this process, without `unsafe` or a libc dependency: create
/// a probe file in `dir` (new files are owned by the euid) and read its owner.
pub fn effective_uid(dir: &Path) -> io::Result<u32> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let probe = dir.join(format!(".uid-probe-{}", u64::from_le_bytes(nonce)));
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    fs::remove_file(&probe)?;
    uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn private_dir_checks() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = effective_uid(tmp.path()).expect("uid");
        let dir = tmp.path().join("data");
        create_private_dir(&dir).expect("create");
        check_private_dir(&dir, uid).expect("fresh dir is private");

        for mode in [0o750, 0o705, 0o777, 0o701] {
            chmod(&dir, mode);
            assert!(matches!(check_private_dir(&dir, uid), Err(PermError::TooOpen(_))), "{mode:o}");
        }
        chmod(&dir, 0o700);
        assert!(matches!(check_private_dir(&dir, uid + 1), Err(PermError::WrongOwner { .. })));

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).expect("symlink");
        assert!(matches!(check_private_dir(&link, uid), Err(PermError::Symlink)));

        assert!(create_private_dir(&dir).is_err(), "must not reuse an existing dir");
    }

    #[test]
    fn private_file_checks() {
        let tmp = tempfile::tempdir().expect("tmp");
        let uid = effective_uid(tmp.path()).expect("uid");
        let f = tmp.path().join("key.pem");
        write_new_private_file(&f, b"secret").expect("write");
        check_private_file(&f, uid).expect("0600 is fine");
        assert!(write_new_private_file(&f, b"other").is_err(), "never overwrites");
        assert_eq!(fs::read(&f).expect("read"), b"secret");

        chmod(&f, 0o640);
        assert!(matches!(check_private_file(&f, uid), Err(PermError::TooOpen(_))));
        chmod(&f, 0o604);
        assert!(matches!(check_private_file(&f, uid), Err(PermError::TooOpen(_))));
        chmod(&f, 0o600);

        let link = tmp.path().join("link.pem");
        std::os::unix::fs::symlink(&f, &link).expect("symlink");
        assert!(matches!(check_private_file(&link, uid), Err(PermError::Symlink)));
        assert!(write_new_private_file(&link, b"x").is_err(), "won't write through a symlink");
    }
}
