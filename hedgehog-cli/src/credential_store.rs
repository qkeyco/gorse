// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Signed, machine-bound short leases. General config and cached UI preferences
//! never authorize paid behavior. Lease files are private and every use verifies
//! the signature, binding, issued time and absolute expiry again.

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use hedgehog_taint::tier::Tier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_KEY_BYTES: usize = 8192;
/// A signed lease lives at most 24 hours; the server never issues a longer one.
pub const MAX_LEASE_SECONDS: u64 = 86400;
/// After the signed expiry, renewal is still accepted and the lease's tier
/// stays effective for this long, so a laptop that is offline for a fortnight
/// keeps its paid features until it next reaches the server. The server keeps
/// its own copy of this window and still answers a cancelled subscription
/// with 403, so the grace is the only period in which a stale lease counts.
pub const RENEWAL_GRACE_SECONDS: u64 = 14 * 86400;
/// The exact error text a bad signature produces; callers match on it to
/// decide whether to ask the server which issuer key it signs with.
pub const SIGNATURE_FAILURE: &str = "License signature verification failed";
/// Tier strings a signed lease may carry. The server issues "pro" and "team";
/// "personal" and "developer" are the retired names and still count as Pro so
/// an older signed lease never downgrades its holder.
pub const LEASE_TIERS: [&str; 4] = ["pro", "personal", "developer", "team"];

/// Map a lease tier string to a [`Tier`]. Unknown strings are Free.
pub fn tier_from_lease_string(tier: &str) -> Tier {
    match tier {
        "pro" | "personal" | "developer" => Tier::Pro,
        "team" => Tier::Team,
        _ => Tier::Free,
    }
}
pub const ISSUER_PUBLIC_KEY: [u8; 32] = [
    0x74, 0xf1, 0xac, 0x9d, 0xba, 0x10, 0x57, 0x51, 0x2a, 0xbb, 0x79, 0x7c, 0x9c, 0x8f, 0xa6, 0xcc,
    0xfc, 0xdb, 0xb4, 0xd2, 0x88, 0x06, 0xb6, 0x40, 0x2d, 0x77, 0x00, 0x66, 0x13, 0x76, 0xb3, 0x53,
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub tier: String,
    pub email: String,
    pub machine_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Lease {
    /// The tier this lease grants at `now`: its signed tier while current or
    /// within the renewal grace, Free once the grace has ended.
    pub fn effective_tier(&self, now: u64) -> Tier {
        if now >= self.grace_ends_at() || self.issued_at > now.saturating_add(5) {
            return Tier::Free;
        }
        tier_from_lease_string(&self.tier)
    }
    /// When the renewal grace after the signed expiry ends.
    pub fn grace_ends_at(&self) -> u64 {
        self.expires_at.saturating_add(RENEWAL_GRACE_SECONDS)
    }
}

#[derive(Debug, Serialize)]
pub struct LeaseStatus {
    pub state: &'static str,
    pub tier: String,
    pub machine_id: Option<String>,
    pub email: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub seconds_remaining: u64,
    /// Whole days left in the renewal grace; present only in state "grace".
    pub grace_days_remaining: Option<u64>,
    /// The issuer public key this build trusts (base64url, no padding), so
    /// `gorse status --json` and `gorse license status --json` can be
    /// compared with `/api/health`.
    pub issuer_public_key: String,
    pub message: String,
    pub protection_tested: bool,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

pub fn validate_lease(
    key: &str,
    machine: &str,
    now: u64,
    require_current: bool,
) -> Result<Lease, String> {
    validate_with_issuer(key, machine, now, require_current, &ISSUER_PUBLIC_KEY)
}
fn validate_with_issuer(
    key: &str,
    machine: &str,
    now: u64,
    require_current: bool,
    issuer: &[u8; 32],
) -> Result<Lease, String> {
    let lease = verify_signed(key, issuer)?;
    if !LEASE_TIERS.contains(&lease.tier.as_str()) {
        return Err("Unsupported signed license tier".into());
    }
    if machine.is_empty() || lease.machine_id != machine {
        return Err("License is bound to a different machine".into());
    }
    if lease.email.is_empty()
        || lease.email.len() > 254
        || !lease.email.contains('@')
        || lease.email.chars().any(char::is_control)
    {
        return Err("Invalid signed license owner".into());
    }
    if now == 0
        || lease.issued_at == 0
        || lease.issued_at > now.saturating_add(5)
        || lease.expires_at <= lease.issued_at
        || lease.expires_at - lease.issued_at > MAX_LEASE_SECONDS
    {
        return Err("License must be a current machine-bound lease of at most 24 hours".into());
    }
    if require_current && lease.expires_at <= now {
        return Err("License lease has expired".into());
    }
    Ok(lease)
}

fn verify_signed(key: &str, issuer: &[u8; 32]) -> Result<Lease, String> {
    if key.len() > MAX_KEY_BYTES
        || !key.starts_with("HH1-")
        || key.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err("Invalid license key format".into());
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&key[4..])
        .map_err(|_| "Invalid license key encoding")?;
    if raw.len() <= 64 {
        return Err("Invalid license key length".into());
    }
    let (payload, signature) = raw.split_at(raw.len() - 64);
    let signature = Signature::from_slice(signature).map_err(|_| "Invalid license signature")?;
    VerifyingKey::from_bytes(issuer)
        .map_err(|_| "Invalid issuer key")?
        .verify_strict(payload, &signature)
        .map_err(|_| SIGNATURE_FAILURE)?;
    serde_json::from_slice(payload).map_err(|_| "Invalid signed license payload".into())
}

pub fn check_license_signature(key: &str) -> Result<(), String> {
    verify_signed(key, &ISSUER_PUBLIC_KEY).map(|_| ())
}

/// The issuer public key this build trusts, base64url without padding. It is
/// public information; `/api/health` publishes the server's counterpart so a
/// mismatch between the two can be seen before a customer hits it.
pub fn issuer_public_key_base64url() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ISSUER_PUBLIC_KEY)
}

/// Short identifier for a public key: the first 16 hex characters of its
/// SHA-256. The website computes the same value as `issuer_key_fingerprint`.
pub fn key_fingerprint(key: &[u8]) -> String {
    format!("{:x}", Sha256::digest(key))[..16].to_string()
}

pub fn issuer_key_fingerprint() -> String {
    key_fingerprint(&ISSUER_PUBLIC_KEY)
}

/// Compare the server's advertised issuer key (the `issuer_public_key` member
/// of a `/api/health` body) with the key this build trusts. Returns the
/// customer-facing explanation when they differ, None when they match or the
/// body does not carry a usable key.
pub fn issuer_mismatch_from_health(body: &[u8], trusted: &[u8; 32]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let encoded = value.get("issuer_public_key")?.as_str()?;
    let server = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    if server.len() != 32 || server == trusted {
        return None;
    }
    Some(format!(
        "This build trusts issuer key {}, but the server signs with {}. This is a deployment problem on our side, not your key. Please email support@gorse.is.",
        key_fingerprint(trusted),
        key_fingerprint(&server)
    ))
}

/// Best-effort GET of the health endpoint to explain a signature failure.
/// Sends no credentials, follows no redirects, gives up after five seconds
/// and answers None on any problem; it never fails the calling command.
pub fn fetch_issuer_mismatch(health_url: &str, trusted: &[u8; 32]) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let response = agent
        .get(health_url)
        .set("Accept", "application/json")
        .call()
        .ok()?;
    if response.status() != 200 {
        return None;
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 64 * 1024 {
        return None;
    }
    issuer_mismatch_from_health(&bytes, trusted)
}

/// When `error` is a signature failure, ask the configured server which issuer
/// key it signs with and append the explanation if it is not ours. Any other
/// error, and a server that cannot be reached, leave the text unchanged.
pub fn explain_signature_failure(error: String) -> String {
    if error != SIGNATURE_FAILURE {
        return error;
    }
    let url = crate::api_origin::api_url("/api/health");
    match fetch_issuer_mismatch(&url, &ISSUER_PUBLIC_KEY) {
        Some(hint) => format!("{error}. {hint}"),
        None => error,
    }
}

/// Pro keys work wherever Gorse can bind a lease to the machine and keep it
/// in a private file: macOS, Linux and Windows.
pub fn require_runtime_support() -> Result<(), String> {
    if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
        Ok(())
    } else {
        Err("Gorse Pro is not available on this platform. The free exposure check and Deep Scan work in full here.".into())
    }
}

fn fingerprint(platform: &str, identity: &str) -> String {
    let value = format!(
        "hedgehog-machine-v1\0{platform}\0{}",
        identity.trim().to_ascii_lowercase()
    );
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

/// Hardware/installation identity only; no hostname or environment override.
pub fn machine_id() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return mac_identity().map(|identity| fingerprint("macos", &identity));
    }
    #[cfg(target_os = "linux")]
    {
        let mut options = std::fs::OpenOptions::new();
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let file = options
            .open("/etc/machine-id")
            .map_err(|_| "Machine identity is unavailable")?;
        let metadata = file
            .metadata()
            .map_err(|_| "Machine identity is unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() > 128
        {
            return Err("Machine identity cannot be verified".into());
        }
        let mut identity = String::new();
        file.take(129)
            .read_to_string(&mut identity)
            .map_err(|_| "Invalid machine identity")?;
        let identity = identity.trim();
        if identity.len() != 32 || !identity.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid machine identity".into());
        }
        return Ok(fingerprint("linux", identity));
    }
    #[cfg(windows)]
    {
        return windows_identity().map(|identity| fingerprint("windows", &identity));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err("Paid runtime leases are not qualified on this platform".into())
    }
}

/// The installation's MachineGuid, written by Windows setup and readable by
/// every user. Read straight from the registry, so no other program's output
/// is trusted; the 64-bit view is named so a 32-bit build sees the same value.
#[cfg(windows)]
fn windows_identity() -> Result<String, String> {
    use std::ffi::c_void;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            key: *mut c_void,
            sub_key: *const u16,
            options: u32,
            desired: u32,
            result: *mut *mut c_void,
        ) -> i32;
        fn RegQueryValueExW(
            key: *mut c_void,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            size: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: *mut c_void) -> i32;
    }
    // HKEY_LOCAL_MACHINE is a sign-extended 0x80000002.
    const HKEY_LOCAL_MACHINE: isize = -2_147_483_646;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let sub_key = wide(r"SOFTWARE\Microsoft\Cryptography");
    let name = wide("MachineGuid");
    let mut key: *mut c_void = std::ptr::null_mut();
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE as *mut c_void,
            sub_key.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if opened != 0 || key.is_null() {
        return Err("Machine identity is unavailable".into());
    }
    let mut kind = 0u32;
    let mut buffer = [0u8; 256];
    let mut size = buffer.len() as u32;
    let queried = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    unsafe { RegCloseKey(key) };
    let size = size as usize;
    if queried != 0 || kind != REG_SZ || size > buffer.len() || size % 2 != 0 {
        return Err("Machine identity is unavailable".into());
    }
    let units: Vec<u16> = buffer[..size]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let identity = String::from_utf16(&units).map_err(|_| "Invalid machine identity")?;
    let identity = identity.trim_end_matches('\0').trim();
    // A GUID: 8-4-4-4-12 hex digits.
    let guid_shaped = identity.len() == 36
        && identity.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    if !guid_shaped {
        return Err("Invalid machine identity".into());
    }
    Ok(identity.to_string())
}

#[cfg(target_os = "macos")]
fn mac_identity() -> Result<String, String> {
    use std::ffi::{c_char, c_void};
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceMatching(name: *const c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(port: u32, matching: *mut c_void) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: *const c_void,
            allocator: *const c_void,
            options: u32,
        ) -> *const c_void;
        fn IOObjectRelease(object: u32) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            allocator: *const c_void,
            text: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFStringGetCString(
            value: *const c_void,
            buffer: *mut c_char,
            size: isize,
            encoding: u32,
        ) -> bool;
        fn CFGetTypeID(value: *const c_void) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFRelease(value: *const c_void);
    }
    unsafe {
        let service =
            IOServiceGetMatchingService(0, IOServiceMatching(c"IOPlatformExpertDevice".as_ptr()));
        if service == 0 {
            return Err("Hardware identity is unavailable".into());
        }
        let key =
            CFStringCreateWithCString(std::ptr::null(), c"IOPlatformUUID".as_ptr(), 0x08000100);
        if key.is_null() {
            IOObjectRelease(service);
            return Err("Hardware identity is unavailable".into());
        }
        let value = IORegistryEntryCreateCFProperty(service, key, std::ptr::null(), 0);
        CFRelease(key);
        IOObjectRelease(service);
        if value.is_null() {
            return Err("Hardware identity is unavailable".into());
        }
        let mut buffer = [0i8; 128];
        let valid = CFGetTypeID(value) == CFStringGetTypeID()
            && CFStringGetCString(
                value,
                buffer.as_mut_ptr(),
                buffer.len() as isize,
                0x08000100,
            );
        CFRelease(value);
        if !valid {
            return Err("Hardware identity cannot be decoded".into());
        }
        let identity = std::ffi::CStr::from_ptr(buffer.as_ptr())
            .to_str()
            .map_err(|_| "Invalid hardware identity")?;
        if identity.len() != 36 || !identity.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err("Invalid hardware identity".into());
        }
        Ok(identity.to_string())
    }
}

fn license_file_path() -> PathBuf {
    crate::config::config_dir().join("license.key")
}

#[cfg(unix)]
fn private_directory(path: &Path, create: bool) -> Result<std::fs::File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    // Resolve only system aliases in the user's home before entering the
    // dedicated state directory. The state directory itself must never link.
    let parent = path.parent().ok_or("License storage has no parent")?;
    let grandparent = parent.parent().ok_or("License storage has no home")?;
    let home = grandparent
        .canonicalize()
        .map_err(|_| "License home is unavailable")?;
    let mut home_file = std::fs::File::open("/").map_err(|_| "License home is unavailable")?;
    for component in home.components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        let component =
            std::ffi::CString::new(component.as_bytes()).map_err(|_| "Invalid home path")?;
        let next = unsafe {
            libc::openat(
                home_file.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err("License home changed or cannot be opened safely".into());
        }
        home_file = unsafe { std::fs::File::from_raw_fd(next) };
    }
    if home_file
        .metadata()
        .map_err(|_| "Cannot inspect license home")?
        .uid()
        != unsafe { libc::geteuid() }
    {
        return Err("License home must be owned by this user".into());
    }
    let name = std::ffi::CString::new(
        parent
            .file_name()
            .ok_or("Invalid license directory")?
            .as_bytes(),
    )
    .map_err(|_| "Invalid license directory")?;
    if create {
        let result = unsafe { libc::mkdirat(home_file.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err("Cannot create private license directory".into());
        }
    }
    let fd = unsafe {
        libc::openat(
            home_file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("License directory is missing or cannot be opened safely".into());
    }
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = directory
        .metadata()
        .map_err(|_| "Cannot inspect license directory")?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(
            "License directory must be owned by this user and not writable by other users".into(),
        );
    }
    Ok(directory)
}

#[cfg(unix)]
fn read_license_file(path: &Path) -> Result<Option<String>, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    // Absence is not an error, but broken links or unsafe existing files are.
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot inspect license file".into()),
        _ => {}
    }
    let directory = private_directory(path, false)?;
    let name = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes())
        .map_err(|_| "Invalid license path")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return Err("Cannot open license file safely".into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|_| "Cannot inspect license file")?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o077 != 0
        || before.len() > MAX_KEY_BYTES as u64
    {
        return Err(
            "License file must be private, owned by this user and unlinked elsewhere".into(),
        );
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read license file")?;
    let after = file.metadata().map_err(|_| "Cannot recheck license file")?;
    if bytes.len() > MAX_KEY_BYTES
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("License file changed during its read".into());
    }
    let key = String::from_utf8(bytes).map_err(|_| "License file is not valid text")?;
    Ok(Some(key.trim().to_string()))
}
/// Reparse points (symbolic links, junctions, mount points) are refused
/// everywhere in the licence path on Windows.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
/// Opens the link itself rather than what it points at, so a planted link is
/// seen for what it is.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// The licence lives in `%APPDATA%\hedgehog`, inside the user's own roaming
/// profile. Windows gives that profile to the user, administrators and the
/// system only, and the folder inherits it; no explicit permissions are set,
/// so the checks here are that nothing on the path is a link and that the
/// state folder is an ordinary directory.
///
/// The checks are made by path and the file is then opened by path, so a
/// junction swapped onto the folder between the two would redirect the
/// open; the Unix version works relative to a directory descriptor and has
/// no such window. Only the same user can plant that junction, and that
/// user can already read and replace their own lease, which is signed and
/// machine-bound, so the window is accepted here rather than closed with
/// directory-relative handles.
#[cfg(windows)]
fn private_directory(path: &Path, create: bool) -> Result<PathBuf, String> {
    use std::os::windows::fs::MetadataExt;
    let parent = path.parent().ok_or("License storage has no parent")?;
    let home = parent.parent().ok_or("License storage has no home")?;
    let home_metadata =
        std::fs::symlink_metadata(home).map_err(|_| "License home is unavailable")?;
    if !home_metadata.is_dir()
        || home_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("License home changed or cannot be opened safely".into());
    }
    if create {
        match std::fs::create_dir(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("Cannot create private license directory".into()),
        }
    }
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| "License directory is missing or cannot be opened safely")?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("License directory must be an ordinary folder, not a link".into());
    }
    Ok(parent.to_path_buf())
}

#[cfg(windows)]
fn read_license_file(path: &Path) -> Result<Option<String>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // Absence is not an error, but broken links or unsafe existing files are.
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot inspect license file".into()),
        _ => {}
    }
    private_directory(path, false)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| "Cannot open license file safely")?;
    let before = file.metadata().map_err(|_| "Cannot inspect license file")?;
    if !before.is_file()
        || before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || before.len() > MAX_KEY_BYTES as u64
        || link_count(&file)? != 1
    {
        return Err("License file must be an ordinary private file, not a link".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read license file")?;
    let after = file.metadata().map_err(|_| "Cannot recheck license file")?;
    if bytes.len() > MAX_KEY_BYTES
        || before.len() != after.len()
        || before.file_attributes() != after.file_attributes()
        || before.creation_time() != after.creation_time()
        || before.last_write_time() != after.last_write_time()
    {
        return Err("License file changed during its read".into());
    }
    let key = String::from_utf8(bytes).map_err(|_| "License file is not valid text")?;
    Ok(Some(key.trim().to_string()))
}
/// How many directory entries name the open file. A hard link to a file
/// outside the state folder has no reparse-point attribute, so only the
/// link count tells it from an ordinary private file; Unix checks `nlink`
/// the same way.
#[cfg(windows)]
fn link_count(file: &std::fs::File) -> Result<u32, String> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    // BY_HANDLE_FILE_INFORMATION, field for field.
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation: FileTime,
        last_access: FileTime,
        last_write: FileTime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
    let ok = unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as *mut c_void, info.as_mut_ptr())
    };
    if ok == 0 {
        return Err("Cannot inspect license file".into());
    }
    Ok(unsafe { info.assume_init() }.links)
}

#[cfg(not(any(unix, windows)))]
fn read_license_file(_path: &Path) -> Result<Option<String>, String> {
    Err("Private lease storage is not qualified on this platform".into())
}

#[cfg(unix)]
fn store_license_file(path: &Path, key: &str) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if key.len() > MAX_KEY_BYTES {
        return Err("License exceeds size limit".into());
    }
    let directory = private_directory(path, true)?;
    if std::fs::symlink_metadata(path).is_ok() {
        read_license_file(path)?;
    }
    let target = std::ffi::CString::new(path.file_name().unwrap().as_encoded_bytes())
        .map_err(|_| "Invalid license path")?;
    let temporary =
        std::ffi::CString::new(format!(".license-{:032x}", rand::random::<u128>())).unwrap();
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("Cannot create private license file".into());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| {
        file.write_all(key.as_bytes())
            .map_err(|_| "Cannot write license file")?;
        file.sync_all().map_err(|_| "Cannot sync license file")?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err("Cannot replace license file".to_string());
        }
        let _ = directory.sync_all();
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    result
}
/// Written to a fresh temporary file in the same folder and renamed into
/// place, so a reader sees the old key or the new one, never a partial file.
#[cfg(windows)]
fn store_license_file(path: &Path, key: &str) -> Result<(), String> {
    if key.len() > MAX_KEY_BYTES {
        return Err("License exceeds size limit".into());
    }
    let directory = private_directory(path, true)?;
    if std::fs::symlink_metadata(path).is_ok() {
        // An unsafe existing file is refused rather than replaced.
        read_license_file(path)?;
    }
    let temporary = directory.join(format!(".license-{:032x}", rand::random::<u128>()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| "Cannot create private license file")?;
    let result = (|| {
        file.write_all(key.as_bytes())
            .map_err(|_| "Cannot write license file")?;
        file.sync_all().map_err(|_| "Cannot sync license file")?;
        drop(file);
        std::fs::rename(&temporary, path).map_err(|_| "Cannot replace license file".to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
#[cfg(not(any(unix, windows)))]
fn store_license_file(_path: &Path, _key: &str) -> Result<(), String> {
    Err("Private lease storage is not qualified on this platform".into())
}

/// Serialize activation, renewal and removal so a late response cannot revive
/// a locally deactivated lease or overwrite a newly activated subscription.
#[cfg(unix)]
fn license_lock(path: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    let directory = private_directory(path, true)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".license.lock".as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_NOCTTY,
            0o600,
        )
    };
    if fd < 0 {
        return Err("Cannot open private license lock".into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| "Cannot inspect license lock")?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
    {
        return Err("License lock is not a private owned file".into());
    }
    // Waits out a lock briefly kept alive by a concurrent spawn (see the helper).
    crate::encrypted_store::try_lock_briefly(&file)
        .map_err(|_| "A license update is already running; retry shortly")?;
    Ok(file)
}
#[cfg(windows)]
fn license_lock(path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let directory = private_directory(path, true)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join(".license.lock"))
        .map_err(|_| "Cannot open private license lock")?;
    let meta = file.metadata().map_err(|_| "Cannot inspect license lock")?;
    if !meta.is_file()
        || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || link_count(&file)? != 1
    {
        return Err("License lock is not an ordinary private file".into());
    }
    // Waits out a lock briefly kept alive by a concurrent spawn (see the helper).
    crate::encrypted_store::try_lock_briefly(&file)
        .map_err(|_| "A license update is already running; retry shortly")?;
    Ok(file)
}
#[cfg(not(any(unix, windows)))]
fn license_lock(_path: &Path) -> Result<std::fs::File, String> {
    Err("Private lease storage is not qualified on this platform".into())
}

pub fn store_license_key(key: &str) -> Result<(), String> {
    check_license_signature(key)?;
    require_runtime_support()?;
    validate_lease(key, &machine_id()?, now(), true)?;
    let _lock = license_lock(&license_file_path())?;
    store_license_file(&license_file_path(), key)
}
pub fn load_license_key() -> Option<String> {
    require_runtime_support().ok()?;
    let key = read_license_file(&license_file_path()).ok()??;
    validate_lease(&key, &machine_id().ok()?, now(), true).ok()?;
    Some(key)
}
pub fn delete_license_key() -> Result<(), String> {
    let path = license_file_path();
    if read_license_file(&path)?.is_none() {
        return Ok(());
    }
    let _lock = license_lock(&path)?;
    delete_license_file(&path)
}
fn delete_license_file(path: &Path) -> Result<(), String> {
    if read_license_file(path)?.is_none() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let directory = private_directory(path, false)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c"license.key".as_ptr(), 0) } != 0 {
            return Err("Cannot remove stored license".into());
        }
        let _ = directory.sync_all();
        Ok(())
    }
    #[cfg(windows)]
    {
        // read_license_file above has already refused a link in its place.
        std::fs::remove_file(path).map_err(|_| "Cannot remove stored license".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err("Private lease storage is not qualified on this platform".into())
    }
}

pub fn status() -> LeaseStatus {
    let mut result = LeaseStatus {
        state: "missing",
        tier: "free".into(),
        machine_id: None,
        email: None,
        issued_at: None,
        expires_at: None,
        seconds_remaining: 0,
        grace_days_remaining: None,
        issuer_public_key: issuer_public_key_base64url(),
        message: "No paid lease is installed. Existing free security features remain available."
            .into(),
        protection_tested: false,
    };
    let machine = match machine_id() {
        Ok(machine) => machine,
        Err(error) => {
            result.state = "unavailable";
            result.message = error;
            return result;
        }
    };
    result.machine_id = Some(machine.clone());
    if let Err(error) = require_runtime_support() {
        result.state = "unavailable";
        result.message = error;
        return result;
    }
    let key = match read_license_file(&license_file_path()) {
        Ok(Some(key)) => key,
        Ok(None) => return result,
        Err(error) => {
            result.state = "invalid";
            result.message = error;
            return result;
        }
    };
    let now = now();
    match validate_lease(&key, &machine, now, false) {
        Ok(lease) => {
            let grace_ends_at = lease.grace_ends_at();
            result.email = Some(lease.email);
            result.issued_at = Some(lease.issued_at);
            result.expires_at = Some(lease.expires_at);
            result.seconds_remaining = lease.expires_at.saturating_sub(now);
            if lease.expires_at > now {
                result.state = "active";
                result.tier = lease.tier;
                result.message =
                    "Signed lease is valid for this machine. This does not establish protection."
                        .into();
            } else if now < grace_ends_at {
                // Renewal is overdue but still possible: the paid tier stays
                // effective until the grace ends, and the next refresh (quiet
                // or by hand) replaces this lease with a current one.
                let days = (grace_ends_at - now).div_ceil(86400);
                result.state = "grace";
                result.tier = lease.tier.clone();
                result.grace_days_remaining = Some(days);
                result.message = format!(
                    "Renewal overdue: {} features continue for {days} more day{}; connect to the internet and run `gorse license refresh`.",
                    tier_from_lease_string(&lease.tier).name(),
                    if days == 1 { "" } else { "s" }
                );
            } else {
                result.state = "expired";
                result.message="Paid lease expired and its renewal grace has ended. Sign in on the dashboard to obtain a new key; existing free security features remain available.".into();
            }
        }
        Err(error) => {
            result.state = "invalid";
            result.message = error;
        }
    }
    result
}

pub fn current_tier() -> Tier {
    tier_of(&status())
}

/// The effective tier of a lease status: Free unless the lease is active or
/// inside its renewal grace.
pub fn tier_of(status: &LeaseStatus) -> Tier {
    if status.state == "active" || status.state == "grace" {
        tier_from_lease_string(&status.tier)
    } else {
        Tier::Free
    }
}

/// Whether a quiet renewal attempt is worthwhile: the lease is past half its
/// signed life, or already in its renewal grace. The server hands back the
/// current lease unchanged until it has under twelve hours left, so asking
/// earlier would only waste a request.
pub fn renewal_due(status: &LeaseStatus, now: u64) -> bool {
    match (status.state, status.issued_at, status.expires_at) {
        ("active", Some(issued), Some(expires)) if expires > issued => {
            now >= issued + (expires - issued) / 2
        }
        ("grace", _, _) => true,
        _ => false,
    }
}

/// Silent, best-effort renewal before a paid command runs. Nothing is printed
/// and the command is never blocked on failure: the request already carries a
/// ten-second timeout, and whatever the outcome the stored lease is read again
/// so a renewal the server refused (a cancelled subscription) takes effect at
/// once while a server that cannot be reached leaves the grace untouched.
pub fn refresh_quietly_if_due(status: LeaseStatus) -> LeaseStatus {
    if !renewal_due(&status, now()) {
        return status;
    }
    let _ = refresh_license();
    self::status()
}

#[derive(Deserialize)]
struct RefreshResponse {
    license_key: String,
    tier: String,
    expires_at: String,
}

pub fn refresh_license() -> Result<LeaseStatus, String> {
    // Resolve the endpoint first so an invalid GORSE_API_ORIGIN is reported
    // on every platform, even where renewal is not yet qualified.
    let url = crate::api_origin::api_url("/api/refresh");
    require_runtime_support()?;
    refresh_at(
        &license_file_path(),
        &machine_id()?,
        &ISSUER_PUBLIC_KEY,
        &url,
        now,
    )
    .map_err(explain_signature_failure)?;
    Ok(status())
}

// The runtime wrapper fixes the issuer, HTTPS endpoint and clock. This private
// seam lets tests exercise the actual HTTP client against local synthetic data.
fn refresh_at(
    path: &Path,
    machine: &str,
    issuer: &[u8; 32],
    url: &str,
    clock: fn() -> u64,
) -> Result<(), String> {
    let _lock = license_lock(path)?;
    let old =
        read_license_file(path)?.ok_or("No stored lease; sign in to obtain a machine-bound key")?;
    let previous = validate_with_issuer(&old, machine, clock(), false, issuer)?;
    if clock() >= previous.grace_ends_at() {
        return Err(
            "Lease renewal grace has ended. Sign in on the dashboard to obtain a new key.".into(),
        );
    }
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let response = agent
        .post(url)
        .set("Authorization", &format!("Bearer {old}"))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"machine_id":machine}).to_string());
    let response = match response {
        Ok(response)=>response,
        Err(ureq::Error::Status(code,_)) if [401,403].contains(&code)=>{
            // Do not delete a newer lease installed by another cooperating process.
            if read_license_file(path)?.as_deref()==Some(&old) {delete_license_file(path)?;}
            return Err("The server denied renewal. Paid access was removed; sign in to review the subscription.".into());
        },
        Err(_)=>return Err("Renewal did not complete. The existing lease remains usable only until its signed expiry.".into()),
    };
    if response.status() != 200 {
        return Err("Unexpected renewal response; existing expiry is unchanged".into());
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read renewal response")?;
    if bytes.len() > 64 * 1024 {
        return Err("Renewal response exceeds size limit".into());
    }
    let response = verify_renewal_response(&bytes, &previous, machine, clock(), issuer)?;
    if read_license_file(path)?.as_deref() != Some(&old) {
        return Err("Stored lease changed during renewal; check status before retrying".into());
    }
    store_license_file(path, &response.license_key)?;
    Ok(())
}

fn verify_renewal_response(
    bytes: &[u8],
    previous: &Lease,
    machine: &str,
    timestamp: u64,
    issuer: &[u8; 32],
) -> Result<RefreshResponse, String> {
    if bytes.len() > 64 * 1024 {
        return Err("Renewal response exceeds size limit".into());
    }
    let response: RefreshResponse =
        serde_json::from_slice(bytes).map_err(|_| "Invalid renewal response")?;
    let renewed = validate_with_issuer(&response.license_key, machine, timestamp, true, issuer)?;
    let expiry = chrono::DateTime::parse_from_rfc3339(&response.expires_at)
        .map_err(|_| "Invalid renewal expiry")?
        .timestamp();
    if renewed.tier != response.tier
        || renewed.email != previous.email
        || renewed.issued_at < previous.issued_at
        || expiry < 0
        || expiry as u64 != renewed.expires_at
    {
        return Err("Renewal response does not match its signed lease".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn payload() -> serde_json::Value {
        serde_json::json!({"tier":"developer","email":"synthetic@example.invalid","machine_id":"fixture-machine","issued_at":1000,"expires_at":87400})
    }
    fn sign(payload: &serde_json::Value) -> (String, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let bytes = serde_json::to_vec(payload).unwrap();
        let mut raw = bytes.clone();
        raw.extend_from_slice(&signing.sign(&bytes).to_bytes());
        (
            format!(
                "HH1-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
            ),
            signing.verifying_key().to_bytes(),
        )
    }
    #[test]
    fn signed_lease_checks_binding_signature_and_absolute_expiry() {
        let (key, issuer) = sign(&payload());
        let lease = validate_with_issuer(&key, "fixture-machine", 1000, true, &issuer).unwrap();
        assert_eq!(lease.effective_tier(87399), Tier::Pro);
        // The signed expiry starts the renewal grace; the tier stays effective
        // until the grace ends.
        assert_eq!(lease.effective_tier(87400), Tier::Pro);
        assert_eq!(lease.grace_ends_at(), 87400 + RENEWAL_GRACE_SECONDS);
        assert_eq!(
            lease.effective_tier(87400 + RENEWAL_GRACE_SECONDS - 1),
            Tier::Pro
        );
        assert_eq!(
            lease.effective_tier(87400 + RENEWAL_GRACE_SECONDS),
            Tier::Free
        );
        assert!(validate_with_issuer(&key, "other-machine", 1000, true, &issuer).is_err());
        assert!(validate_with_issuer(&key, "fixture-machine", 87400, true, &issuer).is_err());
        assert!(validate_with_issuer(&key, "fixture-machine", 87400, false, &issuer).is_ok());
        assert!(validate_lease(&key, "fixture-machine", 1000, true)
            .unwrap_err()
            .contains("signature"));
        let mut changed = payload();
        changed["tier"] = "team".into();
        let bytes = serde_json::to_vec(&changed).unwrap();
        let original = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&key[4..])
            .unwrap();
        let mut raw = bytes;
        raw.extend_from_slice(&original[original.len() - 64..]);
        let forged = format!(
            "HH1-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        assert!(validate_with_issuer(&forged, "fixture-machine", 1000, true, &issuer).is_err());
    }
    #[test]
    fn signed_lease_rejects_long_future_unknown_and_unbound_grants() {
        for (field, value) in [
            ("expires_at", serde_json::json!(87401)),
            ("issued_at", serde_json::json!(1006)),
            ("issued_at", serde_json::json!(0)),
            ("tier", serde_json::json!("free")),
            ("machine_id", serde_json::json!("")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut value_json = payload();
            value_json[field] = value;
            let (key, issuer) = sign(&value_json);
            assert!(
                validate_with_issuer(&key, "fixture-machine", 1000, true, &issuer).is_err(),
                "accepted {field}"
            );
        }
    }
    #[test]
    fn renewal_requires_consistent_signed_response_and_never_extends_on_metadata_alone() {
        let (old, issuer) = sign(&payload());
        let previous = validate_with_issuer(&old, "fixture-machine", 1000, true, &issuer).unwrap();
        let mut renewed = payload();
        renewed["issued_at"] = 2000.into();
        renewed["expires_at"] = 88400.into();
        let (key, _) = sign(&renewed);
        let expiry = chrono::DateTime::from_timestamp(88400, 0)
            .unwrap()
            .to_rfc3339();
        let response =
            serde_json::json!({"license_key":key,"tier":"developer","expires_at":expiry});
        let verify = |response: &serde_json::Value| {
            verify_renewal_response(
                &serde_json::to_vec(response).unwrap(),
                &previous,
                "fixture-machine",
                2000,
                &issuer,
            )
        };
        assert!(verify(&response).is_ok());
        for (field, value) in [
            ("tier", serde_json::json!("team")),
            ("expires_at", serde_json::json!("2099-01-01T00:00:00Z")),
            ("license_key", serde_json::json!("HH1-invalid")),
        ] {
            let mut changed = response.clone();
            changed[field] = value;
            assert!(verify(&changed).is_err());
        }
        renewed["email"] = "different@example.invalid".into();
        let (different, _) = sign(&renewed);
        let mut changed = response.clone();
        changed["license_key"] = different.into();
        assert!(verify(&changed).is_err());
        assert!(verify_renewal_response(
            &vec![0; 65537],
            &previous,
            "fixture-machine",
            2000,
            &issuer
        )
        .is_err());
        assert!(verify_renewal_response(
            &serde_json::to_vec(&response).unwrap(),
            &previous,
            "fixture-machine",
            88400,
            &issuer
        )
        .is_err());
    }
    #[test]
    #[cfg(unix)]
    fn local_http_refresh_enforces_transport_denial_and_persistence_rules() {
        use std::net::TcpListener;
        let (old, issuer) = sign(&payload());
        let mut renewal = payload();
        renewal["issued_at"] = 2000.into();
        renewal["expires_at"] = 88400.into();
        let (new, _) = sign(&renewal);
        let body=serde_json::json!({"license_key":new,"tier":"developer","expires_at":chrono::DateTime::from_timestamp(88400,0).unwrap().to_rfc3339()}).to_string();
        for (status, body, should_pass, deleted) in [
            (200, body, true, false),
            (500, "temporary failure".into(), false, false),
            (403, "revoked".into(), false, true),
            (401, "invalid".into(), false, true),
            (302, "redirect".into(), false, false),
            (200, "x".repeat(65537), false, false),
            (200, "{}".into(), false, false),
        ] {
            let fixture = Fixture::new();
            let path = fixture.path();
            store_license_file(&path, &old).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 16384);
                }
                let header = String::from_utf8(request).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                assert!(length < 1024);
                let mut request_body = vec![0; length];
                stream.read_exact(&mut request_body).unwrap();
                let headers=format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/must-not-follow\r\nConnection: close\r\n\r\n",body.len());
                stream.write_all(headers.as_bytes()).unwrap();
                let _ = stream.write_all(body.as_bytes());
                (header, request_body)
            });
            let result = refresh_at(
                &path,
                "fixture-machine",
                &issuer,
                &crate::api_origin::api_url_with(&format!("http://{address}"), "/api/refresh"),
                || 2000,
            );
            let (header, request_body) = server.join().unwrap();
            assert!(header.starts_with("POST /api/refresh HTTP/1.1"));
            assert!(header.contains(&format!("Authorization: Bearer {old}")));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request_body).unwrap(),
                serde_json::json!({"machine_id":"fixture-machine"})
            );
            assert_eq!(result.is_ok(), should_pass, "status {status}: {result:?}");
            let stored = read_license_file(&path).unwrap();
            if deleted {
                assert!(stored.is_none());
            } else {
                assert_eq!(
                    stored.as_deref(),
                    Some(if should_pass {
                        new.as_str()
                    } else {
                        old.as_str()
                    })
                );
            }
            if status == 302 {
                assert!(
                    result.unwrap_err().contains("Unexpected renewal response"),
                    "redirect must be rejected before a second request"
                );
            }
        }
    }
    fn synthetic_status(state: &'static str, issued_at: u64, expires_at: u64) -> LeaseStatus {
        LeaseStatus {
            state,
            tier: "pro".into(),
            machine_id: Some("fixture-machine".into()),
            email: Some("synthetic@example.invalid".into()),
            issued_at: Some(issued_at),
            expires_at: Some(expires_at),
            seconds_remaining: expires_at.saturating_sub(issued_at),
            grace_days_remaining: None,
            issuer_public_key: issuer_public_key_base64url(),
            message: String::new(),
            protection_tested: false,
        }
    }
    #[test]
    fn grace_state_counts_as_the_paid_tier_and_makes_renewal_due() {
        let active = synthetic_status("active", 1000, 87400);
        assert_eq!(tier_of(&active), Tier::Pro);
        assert!(!renewal_due(&active, 1000));
        assert!(!renewal_due(&active, 44199));
        assert!(
            renewal_due(&active, 44200),
            "half the signed life has passed"
        );
        let mut grace = synthetic_status("grace", 1000, 87400);
        grace.grace_days_remaining = Some(3);
        assert_eq!(tier_of(&grace), Tier::Pro);
        assert!(renewal_due(&grace, 87400 + 11 * 86400));
        for state in ["expired", "missing", "invalid", "unavailable"] {
            let status = synthetic_status(state, 1000, 87400);
            assert_eq!(tier_of(&status), Tier::Free, "{state}");
            assert!(!renewal_due(&status, 90000), "{state}");
        }
        let mut team = synthetic_status("grace", 1000, 87400);
        team.tier = "team".into();
        assert_eq!(tier_of(&team), Tier::Team);
    }
    #[test]
    #[cfg(unix)]
    fn renewal_is_accepted_through_the_grace_and_refused_after_it() {
        use std::net::TcpListener;
        let (old, issuer) = sign(&payload());
        // Ten days after the signed expiry: still inside the fortnight.
        let clock = 87400 + 10 * 86400;
        let mut renewal = payload();
        renewal["issued_at"] = clock.into();
        renewal["expires_at"] = (clock + 86400).into();
        let (new, _) = sign(&renewal);
        let body = serde_json::json!({"license_key": new, "tier": "developer", "expires_at": chrono::DateTime::from_timestamp((clock + 86400) as i64, 0).unwrap().to_rfc3339()}).to_string();
        let fixture = Fixture::new();
        let path = fixture.path();
        store_license_file(&path, &old).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let header = String::from_utf8(request).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap();
            let mut request_body = vec![0; length];
            stream.read_exact(&mut request_body).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        });
        let result = refresh_at(
            &path,
            "fixture-machine",
            &issuer,
            &crate::api_origin::api_url_with(&format!("http://{address}"), "/api/refresh"),
            || 87400 + 10 * 86400,
        );
        server.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            read_license_file(&path).unwrap().as_deref(),
            Some(new.as_str())
        );

        // Once the grace has ended the request is never sent: a closed port
        // would otherwise produce a transport error, not this message.
        let fixture = Fixture::new();
        let path = fixture.path();
        store_license_file(&path, &old).unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let result = refresh_at(
            &path,
            "fixture-machine",
            &issuer,
            &crate::api_origin::api_url_with(&format!("http://{address}"), "/api/refresh"),
            || 87400 + RENEWAL_GRACE_SECONDS,
        );
        assert!(result.unwrap_err().contains("grace has ended"));
        assert_eq!(
            read_license_file(&path).unwrap().as_deref(),
            Some(old.as_str())
        );
    }
    #[test]
    fn issuer_key_is_published_and_compared_by_fingerprint() {
        let encoded = issuer_public_key_base64url();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&encoded)
                .unwrap(),
            ISSUER_PUBLIC_KEY
        );
        let fingerprint = issuer_key_fingerprint();
        assert_eq!(fingerprint.len(), 16);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(fingerprint, key_fingerprint(&ISSUER_PUBLIC_KEY));

        let (_, other) = sign(&payload());
        let other_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other);
        let same = serde_json::json!({"status": "ok", "issuer_public_key": encoded}).to_string();
        assert_eq!(
            issuer_mismatch_from_health(same.as_bytes(), &ISSUER_PUBLIC_KEY),
            None
        );
        let different =
            serde_json::json!({"status": "ok", "issuer_public_key": other_encoded}).to_string();
        let message = issuer_mismatch_from_health(different.as_bytes(), &ISSUER_PUBLIC_KEY)
            .expect("a different server key must be explained");
        assert!(message.contains(&format!("trusts issuer key {fingerprint}")));
        assert!(message.contains(&format!("signs with {}", key_fingerprint(&other))));
        assert!(message.contains("not your key"));
        assert!(
            !message.contains(&other_encoded),
            "no raw key material in the hint"
        );
        for body in [
            r#"{"status":"ok"}"#,
            r#"{"status":"ok","issuer_public_key":null}"#,
            r#"{"status":"ok","issuer_public_key":"not base64url!"}"#,
            r#"{"status":"ok","issuer_public_key":"AAAA"}"#,
            "not json",
        ] {
            assert_eq!(
                issuer_mismatch_from_health(body.as_bytes(), &ISSUER_PUBLIC_KEY),
                None,
                "{body}"
            );
        }
        assert_eq!(
            explain_signature_failure("Invalid license key format".into()),
            "Invalid license key format",
            "only a signature failure consults the server"
        );
    }
    #[test]
    #[cfg(unix)]
    fn health_lookup_explains_a_different_server_key_over_loopback() {
        use std::net::TcpListener;
        let (_, other) = sign(&payload());
        let other_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other);
        for (status, body, expect_hint) in [
            (200, serde_json::json!({"status":"ok","issuer_public_key": other_encoded}).to_string(), true),
            (200, serde_json::json!({"status":"ok","issuer_public_key": issuer_public_key_base64url()}).to_string(), false),
            (503, serde_json::json!({"status":"ok","issuer_public_key": other_encoded}).to_string(), false),
            (200, "not json".to_string(), false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let header = String::from_utf8(request).unwrap();
                let reply = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
                header
            });
            let result = fetch_issuer_mismatch(
                &crate::api_origin::api_url_with(&format!("http://{address}"), "/api/health"),
                &ISSUER_PUBLIC_KEY,
            );
            let header = server.join().unwrap();
            assert!(header.starts_with("GET /api/health HTTP/1.1"), "{header}");
            assert!(
                !header.to_ascii_lowercase().contains("authorization:"),
                "the health lookup must carry no credentials"
            );
            assert_eq!(result.is_some(), expect_hint, "status {status}: {result:?}");
        }
        // A server that is not listening leaves the error untouched.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        assert_eq!(
            fetch_issuer_mismatch(&format!("http://{address}/api/health"), &ISSUER_PUBLIC_KEY),
            None
        );
    }
    #[test]
    fn identity_hash_is_canonical_and_platform_separated() {
        assert_eq!(fingerprint("macos", "  A-B  "), fingerprint("macos", "a-b"));
        assert_ne!(fingerprint("macos", "a-b"), fingerprint("linux", "a-b"));
        assert_eq!(fingerprint("macos", "a-b").len(), 64);
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let home = std::env::temp_dir().join(format!(
                "hedgehog-license-test-{:032x}",
                rand::random::<u128>()
            ));
            std::fs::create_dir(&home).unwrap();
            Self(home)
        }
        fn path(&self) -> PathBuf {
            self.0.join(".hedgehog/license.key")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn private_atomic_storage_and_locking() {
        let fixture = Fixture::new();
        let path = fixture.path();
        assert!(read_license_file(&path).unwrap().is_none());
        let lock = license_lock(&path).unwrap();
        assert!(license_lock(&path).is_err());
        store_license_file(&path, "synthetic-first").unwrap();
        store_license_file(&path, "synthetic-second").unwrap();
        assert_eq!(
            read_license_file(&path).unwrap().as_deref(),
            Some("synthetic-second")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }
        drop(lock);
        assert!(license_lock(&path).is_ok());
        delete_license_file(&path).unwrap();
        assert!(read_license_file(&path).unwrap().is_none());
        // No temporary file is left behind by the two writes.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".license-"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
    }
    #[test]
    #[cfg(windows)]
    fn refuses_links_and_oversized_files_on_windows() {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let fixture = Fixture::new();
        let path = fixture.path();
        store_license_file(&path, "synthetic-original").unwrap();
        // Over the size limit: refused on read, never replaced.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&vec![b'x'; MAX_KEY_BYTES])
            .unwrap();
        assert!(read_license_file(&path).is_err());
        assert!(store_license_file(&path, "replacement").is_err());
        std::fs::remove_file(&path).unwrap();
        // Links need a privilege the test runner may lack; when they can be
        // made, both a linked file and a linked state folder are refused.
        let target = fixture.0.join("elsewhere.key");
        std::fs::write(&target, "synthetic-elsewhere").unwrap();
        if symlink_file(&target, &path).is_ok() {
            assert!(read_license_file(&path).is_err());
            assert!(store_license_file(&path, "replacement").is_err());
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "synthetic-elsewhere"
            );
            std::fs::remove_file(&path).unwrap();
        }
        let other = Fixture::new();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        if symlink_dir(&other.0, path.parent().unwrap()).is_ok() {
            assert!(store_license_file(&path, "value").is_err());
            assert!(license_lock(&path).is_err());
            assert!(std::fs::read_dir(&other.0).unwrap().next().is_none());
        }
    }
    #[test]
    #[cfg(unix)]
    fn refuses_unsafe_actual_files_without_overwriting_them() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let path = fixture.path();
        store_license_file(&path, "synthetic-original").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_license_file(&path).is_err());
        assert!(store_license_file(&path, "replacement").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = fixture.0.join("hardlink");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(read_license_file(&path).is_err());
        assert!(store_license_file(&path, "replacement").is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(&link, &path).unwrap();
        assert!(read_license_file(&path).is_err());
        assert!(store_license_file(&path, "replacement").is_err());
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            "synthetic-original"
        );
        std::fs::remove_file(&path).unwrap();
        store_license_file(&path, &"x".repeat(MAX_KEY_BYTES)).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(read_license_file(&path).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn refuses_linked_or_shared_state_directories_and_locks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let path = fixture.path();
        std::fs::create_dir(fixture.0.join("target")).unwrap();
        symlink(fixture.0.join("target"), path.parent().unwrap()).unwrap();
        assert!(store_license_file(&path, "value").is_err());
        std::fs::remove_file(path.parent().unwrap()).unwrap();
        store_license_file(&path, "value").unwrap();
        let lock = path.parent().unwrap().join(".license.lock");
        symlink(&path, &lock).unwrap();
        assert!(license_lock(&path).is_err());
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(read_license_file(&path).is_err());
    }
}
