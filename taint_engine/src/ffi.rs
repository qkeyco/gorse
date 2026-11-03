// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! C FFI exports for Swift interop.
//!
//! These functions are called from the Swift system extension via the C ABI.
//! The TaintEngine is heap-allocated and passed as an opaque pointer.

use std::ffi::{c_char, c_int, CStr};
use std::path::Path;

use crate::taint::TaintEngine;
use crate::tier::Tier;

/// Create a new TaintEngine. Returns an opaque pointer.
/// Caller must eventually call `hedgehog_destroy` to free.
#[no_mangle]
pub extern "C" fn hedgehog_create() -> *mut TaintEngine {
    Box::into_raw(Box::new(TaintEngine::new()))
}

/// Destroy a TaintEngine and free its memory.
///
/// # Safety
/// `engine` must be a valid pointer returned by `hedgehog_create`.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_destroy(engine: *mut TaintEngine) {
    if !engine.is_null() {
        drop(unsafe { Box::from_raw(engine) });
    }
}

/// Handle a file open event.
/// Returns: 0 = Allow, 1 = Taint (allowed but process marked), 2 = Block.
///
/// # Safety
/// `engine` must be a valid pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_file_open(
    engine: *mut TaintEngine,
    pid: c_int,
    path: *const c_char,
) -> c_int {
    let engine = unsafe { &mut *engine };
    let path_str = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or("");
    engine.on_file_open(pid as i32, Path::new(path_str)) as c_int
}

/// Handle a network connect event.
/// Returns: 0 = Allow, 2 = Block.
///
/// # Safety
/// `engine` must be a valid pointer. `addr` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_connect(
    engine: *mut TaintEngine,
    pid: c_int,
    addr: *const c_char,
    port: u16,
) -> c_int {
    let engine = unsafe { &mut *engine };
    let addr_str = unsafe { CStr::from_ptr(addr) }.to_str().unwrap_or("");
    engine.on_connect(pid as i32, addr_str, port) as c_int
}

/// Handle a process fork event.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_fork(
    engine: *mut TaintEngine,
    parent_pid: c_int,
    child_pid: c_int,
) {
    let engine = unsafe { &mut *engine };
    engine.on_fork(parent_pid as i32, child_pid as i32);
}

/// Handle a process exec event.
///
/// # Safety
/// `engine` must be a valid pointer. `new_path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_exec(
    engine: *mut TaintEngine,
    pid: c_int,
    new_path: *const c_char,
) {
    let engine = unsafe { &mut *engine };
    let path_str = unsafe { CStr::from_ptr(new_path) }.to_str().unwrap_or("");
    engine.on_exec(pid as i32, Path::new(path_str));
}

/// Handle a process exit event.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_exit(engine: *mut TaintEngine, pid: c_int) {
    let engine = unsafe { &mut *engine };
    engine.on_exit(pid as i32);
}

/// Check if a process is currently tainted.
/// Returns 1 if tainted, 0 if not.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_is_tainted(engine: *const TaintEngine, pid: c_int) -> c_int {
    let engine = unsafe { &*engine };
    if engine.is_tainted(pid as i32) {
        1
    } else {
        0
    }
}

/// Get the number of currently tainted processes.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_tainted_count(engine: *const TaintEngine) -> c_int {
    let engine = unsafe { &*engine };
    engine.tainted_count() as c_int
}

/// Get total number of blocks since engine creation.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_total_blocks(engine: *const TaintEngine) -> u64 {
    let engine = unsafe { &*engine };
    engine.stats().total_blocks
}

/// Add a secret file path to monitor.
///
/// # Safety
/// `engine` must be a valid pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_secret_path(engine: *mut TaintEngine, path: *const c_char) {
    let engine = unsafe { &mut *engine };
    let path_str = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or("");
    engine.secrets_mut().add_path(path_str);
}

/// Register the default secret locations (~/.ssh, ~/.aws/credentials, ...)
/// for the user whose home directory is `home`. The extension runs as root,
/// so its own HOME is /var/root; call this once per real user under /Users.
/// Returns 0 on success, -1 if `home` is null, empty, or not valid UTF-8.
///
/// # Safety
/// `engine` must be a valid pointer. `home` must be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_user_home(
    engine: *mut TaintEngine,
    home: *const c_char,
) -> c_int {
    if home.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    let home_str = match unsafe { CStr::from_ptr(home) }.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return -1,
    };
    engine.secrets_mut().add_user_home(Path::new(home_str));
    0
}

/// Add a domain to the network allowlist.
///
/// # Safety
/// `engine` must be a valid pointer. `domain` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_allowed_domain(
    engine: *mut TaintEngine,
    domain: *const c_char,
) {
    let engine = unsafe { &mut *engine };
    let domain_str = unsafe { CStr::from_ptr(domain) }.to_str().unwrap_or("");
    engine.allowlist_mut().add_domain(domain_str);
}

/// Add a domain suffix to the network allowlist (matches all subdomains).
///
/// # Safety
/// `engine` must be a valid pointer. `suffix` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_allowed_suffix(
    engine: *mut TaintEngine,
    suffix: *const c_char,
) {
    let engine = unsafe { &mut *engine };
    let suffix_str = unsafe { CStr::from_ptr(suffix) }.to_str().unwrap_or("");
    engine.allowlist_mut().add_suffix(suffix_str);
}

/// Add a DNS resolver IP. When resolvers are configured, only these IPs
/// are allowed on port 53 (prevents DNS exfiltration).
///
/// # Safety
/// `engine` must be a valid pointer. `ip` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_dns_resolver(engine: *mut TaintEngine, ip: *const c_char) {
    let engine = unsafe { &mut *engine };
    let ip_str = unsafe { CStr::from_ptr(ip) }.to_str().unwrap_or("");
    engine.allowlist_mut().add_dns_resolver(ip_str);
}

// ─── v0.3: Localhost relay detection ───

/// Notify that a process is listening on a local port.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_listen(engine: *mut TaintEngine, pid: c_int, port: u16) {
    let engine = unsafe { &mut *engine };
    engine.on_listen(pid as i32, port);
}

/// Notify that a process stopped listening on a port.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_unlisten(engine: *mut TaintEngine, pid: c_int, port: u16) {
    let engine = unsafe { &mut *engine };
    engine.on_unlisten(pid as i32, port);
}

// ─── v0.4: Per-project scoping ───

/// Set the working directory for a process (determines project scope).
///
/// # Safety
/// `engine` must be a valid pointer. `cwd` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_set_pid_cwd(
    engine: *mut TaintEngine,
    pid: c_int,
    cwd: *const c_char,
) {
    let engine = unsafe { &mut *engine };
    let cwd_str = unsafe { CStr::from_ptr(cwd) }.to_str().unwrap_or("");
    engine.set_pid_cwd(pid as i32, Path::new(cwd_str));
}

/// Register a project. `root` is the project directory, `config_toml` is the
/// contents of hedgehog.toml. Returns the project index, or -1 on error.
///
/// # Safety
/// `engine` must be a valid pointer. String params must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_add_project(
    engine: *mut TaintEngine,
    root: *const c_char,
    config_toml: *const c_char,
) -> c_int {
    let engine = unsafe { &mut *engine };
    let root_str = unsafe { CStr::from_ptr(root) }.to_str().unwrap_or("");
    let toml_str = unsafe { CStr::from_ptr(config_toml) }
        .to_str()
        .unwrap_or("");

    match crate::project::parse_project_config(Path::new(root_str), toml_str) {
        Some(config) => engine.projects_mut().add_project(config) as c_int,
        None => -1,
    }
}

// ─── v0.5: Write taint propagation ───

/// Notify that a process wrote to a file. If tainted, the file becomes
/// a derived secret. Returns 1 if newly marked, 0 otherwise.
///
/// # Safety
/// `engine` must be a valid pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_on_file_write(
    engine: *mut TaintEngine,
    pid: c_int,
    path: *const c_char,
) -> c_int {
    let engine = unsafe { &mut *engine };
    let path_str = unsafe { CStr::from_ptr(path) }.to_str().unwrap_or("");
    if engine.on_file_write(pid as i32, Path::new(path_str)) {
        1
    } else {
        0
    }
}

/// Get the number of tracked derived secrets.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_derived_count(engine: *const TaintEngine) -> c_int {
    let engine = unsafe { &*engine };
    engine.derived_count() as c_int
}

/// Clean up expired derived secrets.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_cleanup_derived(engine: *mut TaintEngine) {
    let engine = unsafe { &mut *engine };
    engine.derived_mut().cleanup_expired();
}

// ─── Licensing ───

/// Apply a platform-verified, machine-bound lease with an absolute expiry.
/// This trusted-host API does not itself verify a signature.
///
/// # Safety
/// `engine` must be a valid exclusively borrowed pointer. The host must
/// authenticate the lease and choose an engine belonging to its owner UID.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_set_verified_lease(
    engine: *mut TaintEngine,
    tier: c_int,
    expires_at: u64,
) {
    unsafe { &mut *engine }
        .set_verified_lease(Tier::from_i32(tier).unwrap_or(Tier::Free), expires_at);
}

/// Set the host's strict egress policy. The pointer must be a live engine
/// exclusively owned by the caller for the duration of this call.
///
/// # Safety
/// `engine` must be a valid, exclusively borrowed pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_set_deny_tainted_network(
    engine: *mut TaintEngine,
    enabled: bool,
) {
    unsafe { &mut *engine }.set_deny_tainted_network(enabled);
}

/// Get the current license tier.
/// Returns: 0=Free, 2=Pro, 3=Team.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_get_tier(engine: *const TaintEngine) -> c_int {
    let engine = unsafe { &*engine };
    engine.license().effective_tier() as c_int
}

/// Activate a license. tier: 2=Pro, 3=Team (1, the retired Personal
/// tier, is accepted as Pro).
///
/// # Safety
/// `engine` must be a valid pointer. `key` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_activate_license(
    engine: *mut TaintEngine,
    tier: c_int,
    key: *const c_char,
    valid_days: u64,
) {
    let engine = unsafe { &mut *engine };
    let key_str = unsafe { CStr::from_ptr(key) }.to_str().unwrap_or("");
    let tier = match tier {
        1 | 2 => Tier::Pro,
        3 => Tier::Team,
        _ => return, // Can't activate Free
    };
    engine.activate_license(tier, key_str.to_string(), valid_days);
}

/// Get the number of protected secrets (within tier limit).
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_protected_count(engine: *const TaintEngine) -> c_int {
    let engine = unsafe { &*engine };
    let (protected, _) = engine.protection_summary();
    protected as c_int
}

/// Get the number of unprotected secrets (over tier limit).
/// This is the "upgrade now" number shown to free tier users.
///
/// # Safety
/// `engine` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn hedgehog_unprotected_count(engine: *const TaintEngine) -> c_int {
    let engine = unsafe { &*engine };
    let (_, unprotected) = engine.protection_summary();
    unprotected as c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn add_user_home_registers_defaults_for_that_home_only() {
        let engine = hedgehog_create();
        let home = CString::new("/Users/alice").unwrap();
        assert_eq!(unsafe { hedgehog_add_user_home(engine, home.as_ptr()) }, 0);

        let secrets = unsafe { &mut *engine }.secrets_mut();
        assert!(secrets.is_secret(Path::new("/Users/alice/.aws/credentials")));
        assert!(secrets.is_secret(Path::new("/Users/alice/.ssh/id_rsa")));
        assert!(!secrets.is_secret(Path::new("/Users/bob/.ssh/id_rsa")));

        unsafe { hedgehog_destroy(engine) };
    }

    #[test]
    fn add_user_home_rejects_null_empty_and_invalid_utf8() {
        let engine = hedgehog_create();
        assert_eq!(
            unsafe { hedgehog_add_user_home(engine, std::ptr::null()) },
            -1
        );
        let empty = CString::new("").unwrap();
        assert_eq!(
            unsafe { hedgehog_add_user_home(engine, empty.as_ptr()) },
            -1
        );
        let invalid = CString::new(vec![0xff, 0xfe]).unwrap();
        assert_eq!(
            unsafe { hedgehog_add_user_home(engine, invalid.as_ptr()) },
            -1
        );
        unsafe { hedgehog_destroy(engine) };
    }
}
