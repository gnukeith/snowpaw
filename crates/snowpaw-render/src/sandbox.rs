//! Locking the worker down before it touches any untrusted input.
//!
//! - Resource limits (all platforms): CPU time, no core dumps, no file writes, few
//!   file descriptors, and on Linux a cap on address space.
//! - Linux: Landlock denies all filesystem access and TCP bind/connect for this process
//!   and every thread it creates later. Applied first thing, while single-threaded.
//! - macOS: the client starts the worker under `sandbox-exec` with a deny-by-default
//!   profile (see the client's render module); nothing to do here.
//!
//! Then a self-test: opening a file and connecting a socket must both be refused.
//! The client won't use a worker whose sandbox didn't hold.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use rustix::process::{Resource, Rlimit, setrlimit};

/// Cumulative CPU seconds before the kernel kills the worker. The client restarts it.
const CPU_SECONDS: u64 = 120;
/// Address space cap (Linux; macOS doesn't enforce RLIMIT_AS).
const ADDRESS_SPACE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_OPEN_FILES: u64 = 32;

fn limit(resource: Resource, value: u64) -> bool {
    setrlimit(resource, Rlimit { current: Some(value), maximum: Some(value) }).is_ok()
}

#[cfg(target_os = "linux")]
fn landlock() -> bool {
    use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope};
    let abi = ABI::V9;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self());
    matches!(
        status,
        Ok(s) if matches!(s.ruleset, RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced)
    )
}

/// Apply every restriction available, then verify. Returns whether the self-test passed.
pub fn enter() -> bool {
    #[cfg(target_os = "linux")]
    let kernel_sandbox = landlock();
    #[cfg(not(target_os = "linux"))]
    let kernel_sandbox = true;

    let limits = limit(Resource::Cpu, CPU_SECONDS)
        & limit(Resource::Core, 0)
        & limit(Resource::Fsize, 0)
        & limit(Resource::Nofile, MAX_OPEN_FILES);
    if cfg!(target_os = "linux") {
        let _ = limit(Resource::As, ADDRESS_SPACE_BYTES);
    }
    kernel_sandbox && limits && self_test()
}

/// Both a file open and a network connect must be refused with a permission error
/// (not merely fail because the file or port doesn't exist).
fn self_test() -> bool {
    let file_denied = matches!(
        std::fs::File::open("/etc/hosts").map(drop),
        Err(e) if e.kind() == ErrorKind::PermissionDenied
    );
    let addr: SocketAddr = ([127, 0, 0, 1], 9).into();
    let net_denied = matches!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(500)).map(drop),
        Err(e) if e.kind() == ErrorKind::PermissionDenied
    );
    file_denied && net_denied
}
