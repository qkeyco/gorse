// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Encrypted storage for sensitive registry data.
//!
//! Uses AES-256-GCM with a key stored in the OS credential store:
//!   - macOS: Keychain (via `security` CLI)
//!   - Linux: Secret Service (via `secret-tool`), fallback to machine-bound file
//!   - Windows: DPAPI (via PowerShell), fallback to plain file
//!
//! The on-disk file is just encrypted bytes — meaningless without
//! the credential-store key.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::io::{Read, Write};
use std::path::Path;

const KEYCHAIN_SERVICE: &str = "com.hedgehog.credential-monitor";
const KEYCHAIN_ACCOUNT: &str = "registry-key";

/// Nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;
/// Key length for AES-256 (256 bits).
const KEY_LEN: usize = 32;

/// Serialize cooperating registry writers and read/modify/write alert logs.
/// Locks are released automatically on process exit.
pub struct StorageLock {
    _file: std::fs::File,
}

pub fn storage_lock(path: &Path) -> Result<StorageLock, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Cannot open storage lock: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Storage lock is not a regular file".into());
    }
    try_lock_briefly(&file).map_err(|e| format!("Canary storage is busy; retry: {e}"))?;
    Ok(StorageLock { _file: file })
}

/// Take an exclusive advisory lock, waiting briefly if it is still held.
///
/// On macOS and the BSDs a `flock` belongs to the open file description, and
/// a child created by `fork`/`posix_spawn` in any other thread of this process
/// shares that description until it execs. So a lock this process has just
/// released can stay held for the length of a concurrent spawn (the canary
/// code-signature verifier, for instance). Waiting a bounded moment absorbs
/// that window; a lock held for real still fails quickly.
pub(crate) fn try_lock_briefly(file: &std::fs::File) -> Result<(), std::fs::TryLockError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    loop {
        match file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            result => return result,
        }
    }
}

/// Encrypt data and write to file.
pub fn encrypt_to_file(path: &std::path::Path, plaintext: &[u8]) -> Result<(), String> {
    let key = if std::fs::symlink_metadata(path).is_ok() {
        keychain_load()
            .filter(|key| key.len() == KEY_LEN)
            .ok_or("Existing registry encryption key is unavailable; refusing to replace it")?
    } else {
        get_or_create_key()?
    };
    encrypt_with_key(path, plaintext, &key)
}

fn encrypt_with_key(path: &std::path::Path, plaintext: &[u8], key: &[u8]) -> Result<(), String> {
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {e}"))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Write: nonce (12 bytes) || ciphertext
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    write_private_atomic(path, &output)
}

/// Replace a regular file using a private, exclusive temporary file in the same
/// directory. A failed write leaves the previous destination intact.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Storage path has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create storage directory: {e}"))?;
    let parent = parent
        .canonicalize()
        .map_err(|e| format!("Invalid storage directory: {e}"))?;
    let destination = parent.join(path.file_name().ok_or("Storage path has no filename")?);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err("Storage destination is not a regular file".into())
        }
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(format!("Cannot inspect storage destination: {e}")),
    }
    let temp = parent.join(format!(".hedgehog-write-{:032x}", rand::random::<u128>()));
    let mut created = false;
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| format!("Cannot create private storage file: {e}"))?;
        created = true;
        file.write_all(data)
            .map_err(|e| format!("Storage write failed: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("Storage sync failed: {e}"))?;
        drop(file);
        std::fs::rename(&temp, &destination)
            .map_err(|e| format!("Atomic storage replacement failed: {e}"))?;
        // The rename is already committed. Report a directory-sync failure as
        // a warning, since returning an error would incorrectly invite rollback
        // of other state while the new registry is present.
        #[cfg(unix)]
        if let Err(e) = std::fs::File::open(&parent).and_then(|dir| dir.sync_all()) {
            log::warn!("Storage was replaced but directory sync failed: {e}");
        }
        Ok(())
    })();
    if result.is_err() && created {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Read a bounded regular file without following a final symlink.
pub fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    if !std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("Storage path is not a regular file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    let mut data = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_BYTES {
        return Err("Storage file exceeds 16 MiB limit".into());
    }
    Ok(data)
}

/// Read and decrypt data from file.
pub fn decrypt_from_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let data = read_regular_file(path)?;

    if data.len() < NONCE_LEN + 16 {
        // 16 = minimum GCM tag size
        return Err("File too small to contain encrypted data".to_string());
    }

    // Never create or replace a key while attempting to read existing data.
    let key = keychain_load()
        .filter(|key| key.len() == KEY_LEN)
        .ok_or("Registry encryption key is unavailable; unlock or restore the credential store")?;
    decrypt_with_key(&data, &key)
}

fn decrypt_with_key(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN + 16 {
        return Err("File too small to contain encrypted data".to_string());
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {e}"))?;

    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed (wrong key or corrupted file): {e}"))
}

/// Get the encryption key from the OS credential store, or create one if it doesn't exist.
fn get_or_create_key() -> Result<Vec<u8>, String> {
    // Try to load from credential store
    if let Some(key) = keychain_load() {
        if key.len() == KEY_LEN {
            return Ok(key);
        }
        return Err(
            "Credential store contains an invalid registry key; refusing to replace it".into(),
        );
    }

    if std::fs::symlink_metadata(key_file_path()).is_ok() {
        return Err(
            "Existing registry key file is unavailable or corrupt; refusing to replace it".into(),
        );
    }
    #[cfg(target_os = "windows")]
    if std::fs::symlink_metadata(dpapi_file_path()).is_ok() {
        return Err("Existing DPAPI key is unavailable or corrupt; refusing to replace it".into());
    }

    // Generate a new key and store it
    let mut key = vec![0u8; KEY_LEN];
    rand::thread_rng().fill(&mut key[..]);
    keychain_store(&key)?;

    Ok(key)
}

// ═══════════════════════════════════════════════════════════════════
// macOS: Keychain via `security` CLI
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
fn keychain_store(key: &[u8]) -> Result<(), String> {
    let hex_key = hex_encode(key);

    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
            &hex_key,
        ])
        .output()
        .map_err(|e| format!("Failed to run security command: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to store key in keychain: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn keychain_load() -> Option<Vec<u8>> {
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w", // output password only
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let hex = String::from_utf8(output.stdout).ok()?;
    hex_decode(hex.trim())
}

// ═══════════════════════════════════════════════════════════════════
// Windows: DPAPI via PowerShell, with plain-file fallback
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn keychain_store(key: &[u8]) -> Result<(), String> {
    let hex_key = hex_encode(key);

    // Use DPAPI via PowerShell — encrypts data bound to the current Windows user.
    // Even if the file is copied, it can't be decrypted by another user or machine.
    let ps_command = format!(
        "Add-Type -AssemblyName System.Security; \
         $bytes = [System.Text.Encoding]::UTF8.GetBytes('{}'); \
         $enc = [System.Security.Cryptography.ProtectedData]::Protect(\
             $bytes, $null, \
             [System.Security.Cryptography.DataProtectionScope]::CurrentUser); \
         [Convert]::ToBase64String($enc)",
        hex_key
    );

    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_command,
        ])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {e}"))?;

    if !output.status.success() {
        log::warn!("DPAPI storage failed, using file-based fallback");
        return plain_file_store(key);
    }

    let encrypted_b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if encrypted_b64.is_empty() {
        return plain_file_store(key);
    }

    // Store the DPAPI-protected blob in a file
    let path = dpapi_file_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create dir: {e}"))?;
    }
    std::fs::write(&path, &encrypted_b64)
        .map_err(|e| format!("Failed to write DPAPI file: {e}"))?;

    // Clean up any old plain-text key file
    let _ = std::fs::remove_file(key_file_path());

    Ok(())
}

#[cfg(target_os = "windows")]
fn keychain_load() -> Option<Vec<u8>> {
    // Try DPAPI first
    if let Some(key) = dpapi_load() {
        return Some(key);
    }

    // Try legacy plain file and migrate to DPAPI if found
    if let Some(key) = plain_file_load() {
        log::info!("Migrating key from plain file to DPAPI");
        let _ = keychain_store(&key);
        return Some(key);
    }

    None
}

#[cfg(target_os = "windows")]
fn dpapi_file_path() -> std::path::PathBuf {
    crate::config::config_dir().join(".registry_key.dpapi")
}

#[cfg(target_os = "windows")]
fn dpapi_load() -> Option<Vec<u8>> {
    let path = dpapi_file_path();
    let encrypted_b64 = std::fs::read_to_string(&path).ok()?;
    let trimmed = encrypted_b64.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ps_command = format!(
        "Add-Type -AssemblyName System.Security; \
         $enc = [Convert]::FromBase64String('{}'); \
         $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(\
             $enc, $null, \
             [System.Security.Cryptography.DataProtectionScope]::CurrentUser); \
         [System.Text.Encoding]::UTF8.GetString($bytes)",
        trimmed
    );

    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_command,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let hex = String::from_utf8(output.stdout).ok()?;
    hex_decode(hex.trim())
}

// ═══════════════════════════════════════════════════════════════════
// Linux: Secret Service via `secret-tool`, with machine-bound fallback
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn keychain_store(key: &[u8]) -> Result<(), String> {
    let hex_key = hex_encode(key);

    // secret-tool (libsecret) is a desktop component. Headless Linux — servers,
    // containers, CI — does not have it, and that is where a Linux install most
    // often runs. A missing binary is the normal case, not an error: fall back
    // to the machine-bound file store, exactly as we do when secret-tool exists
    // but fails.
    let mut child = match std::process::Command::new("secret-tool")
        .args([
            "store",
            "--label",
            "Gorse credential monitor key",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return machine_bound_store(key),
    };

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        let _ = stdin.write_all(hex_key.as_bytes());
    }

    let status = child
        .wait()
        .map_err(|e| format!("secret-tool failed: {e}"))?;
    if !status.success() {
        // Fall back to machine-bound file storage
        return machine_bound_store(key);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn keychain_load() -> Option<Vec<u8>> {
    // Same fallback as keychain_store: no secret-tool means the key lives in
    // the machine-bound file, not that there is no key.
    let output = match std::process::Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
    {
        Ok(output) => output,
        Err(_) => return machine_bound_load(),
    };

    if !output.status.success() {
        // Try machine-bound fallback, then legacy plain
        return machine_bound_load();
    }

    let hex = String::from_utf8(output.stdout).ok()?;
    hex_decode(hex.trim())
}

/// Derive a wrapping key from machine identity (machine-id + uid).
/// This key is deterministic per machine+user but can't be reproduced elsewhere.
#[cfg(target_os = "linux")]
fn derive_machine_wrapping_key() -> Result<[u8; KEY_LEN], String> {
    // Read machine-id (unique per Linux installation, set at install time)
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map_err(|_| "Cannot read /etc/machine-id".to_string())?;

    let uid = unsafe { libc::getuid() };

    // Build key material from machine identity + application salt
    let material = format!("hedgehog-credential-monitor:{}:{}", machine_id.trim(), uid);
    let bytes = material.as_bytes();

    // Fold material into a 32-byte seed via XOR
    let mut seed = [0u8; KEY_LEN];
    for (i, &b) in bytes.iter().enumerate() {
        seed[i % KEY_LEN] ^= b;
    }

    // Use AES-256-GCM as a PRF to derive the final key from the seed.
    // Encrypt a fixed plaintext with the seed key — the ciphertext is
    // a cryptographically strong function of the seed.
    let cipher =
        Aes256Gcm::new_from_slice(&seed).map_err(|e| format!("Key derivation failed: {e}"))?;
    let nonce = Nonce::from_slice(b"hedgehog-kdf");
    let tag_plaintext = b"derive-machine-encryption-key-v1";
    let derived = cipher
        .encrypt(nonce, tag_plaintext.as_slice())
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&derived[..KEY_LEN]);
    Ok(key)
}

/// Store key wrapped with machine-derived key. File is useless on another machine.
#[cfg(target_os = "linux")]
fn machine_bound_store(key: &[u8]) -> Result<(), String> {
    let wrapping_key = derive_machine_wrapping_key()?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("Failed to create wrapping cipher: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let wrapped = cipher
        .encrypt(nonce, key)
        .map_err(|e| format!("Key wrapping failed: {e}"))?;

    // File format: hex(nonce || wrapped_key)
    // This is longer than the old plain format (64 chars) so we can distinguish them.
    let mut output = Vec::with_capacity(NONCE_LEN + wrapped.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&wrapped);

    let path = key_file_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create dir: {e}"))?;
    }

    let hex = hex_encode(&output);
    std::fs::write(&path, &hex).map_err(|e| format!("Failed to write key file: {e}"))?;

    // Restrict permissions
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Load key from machine-bound file. Also handles migration from legacy plain format.
#[cfg(target_os = "linux")]
fn machine_bound_load() -> Option<Vec<u8>> {
    let path = key_file_path();
    let hex_str = std::fs::read_to_string(&path).ok()?;
    let trimmed = hex_str.trim();

    // Old plain format: exactly 64 hex chars (32 bytes = the raw key)
    // New wrapped format: longer (12 nonce + 32 key + 16 GCM tag = 60 bytes = 120 hex chars)
    if trimmed.len() == KEY_LEN * 2 {
        // Legacy plain format — read and migrate
        let key = hex_decode(trimmed)?;
        if key.len() == KEY_LEN {
            log::info!("Migrating key file to machine-bound format");
            let _ = machine_bound_store(&key);
            return Some(key);
        }
        return None;
    }

    // New wrapped format — unwrap with machine key
    let wrapping_key = derive_machine_wrapping_key().ok()?;
    let data = hex_decode(trimmed)?;

    if data.len() < NONCE_LEN + 16 {
        return None;
    }

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).ok()?;
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    cipher.decrypt(nonce, &data[NONCE_LEN..]).ok()
}

// ═══════════════════════════════════════════════════════════════════
// Generic fallback (other platforms)
// ═══════════════════════════════════════════════════════════════════

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn keychain_store(key: &[u8]) -> Result<(), String> {
    plain_file_store(key)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn keychain_load() -> Option<Vec<u8>> {
    plain_file_load()
}

// ═══════════════════════════════════════════════════════════════════
// Plain file storage (used as fallback on Windows + generic platforms)
// ═══════════════════════════════════════════════════════════════════

#[allow(dead_code)] // Used on Windows, Linux, and generic platforms
fn key_file_path() -> std::path::PathBuf {
    crate::config::config_dir().join(".registry_key")
}

#[allow(dead_code)] // Used on Windows and generic platforms
fn plain_file_store(key: &[u8]) -> Result<(), String> {
    let path = key_file_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create dir: {e}"))?;
    }

    let hex = hex_encode(key);
    std::fs::write(&path, &hex).map_err(|e| format!("Failed to write key file: {e}"))?;

    // Restrict permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[allow(dead_code)] // Used on Windows and generic platforms
fn plain_file_load() -> Option<Vec<u8>> {
    let path = key_file_path();
    let hex = std::fs::read_to_string(&path).ok()?;
    hex_decode(hex.trim())
}

// ═══════════════════════════════════════════════════════════════════
// Hex encoding (no extra dependency)
// ═══════════════════════════════════════════════════════════════════

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.is_ascii() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_replacement_preserves_previous_data_on_invalid_target() {
        let dir =
            std::env::temp_dir().join(format!("hedgehog-store-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("registry");
        write_private_atomic(&path, b"first generation").unwrap();
        write_private_atomic(&path, b"second generation").unwrap();
        assert_eq!(read_regular_file(&path).unwrap(), b"second generation");
        let invalid = dir.join("directory");
        std::fs::create_dir(&invalid).unwrap();
        assert!(write_private_atomic(&invalid, b"replacement").is_err());
        assert!(invalid.is_dir());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_symlinks_and_creates_private_files_and_exclusive_locks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir =
            std::env::temp_dir().join(format!("hedgehog-store-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("unrelated");
        std::fs::write(&target, b"preserve me").unwrap();
        let link = dir.join("monitor.enc");
        symlink(&target, &link).unwrap();
        assert!(write_private_atomic(&link, b"replacement").is_err());
        assert!(read_regular_file(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve me");
        let private = dir.join("private");
        write_private_atomic(&private, b"data").unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let lock_path = dir.join("lock");
        let lock = storage_lock(&lock_path).unwrap();
        assert!(storage_lock(&lock_path).is_err());
        drop(lock);
        assert!(storage_lock(&lock_path).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The key file is one global path, so tests that create or read the key
    /// must not interleave: on a fresh machine two of them can both see "no
    /// key", both generate one, and the last writer wins — which is exactly
    /// how `key_is_deterministic_per_machine` failed on CI. Poisoning is
    /// ignored so one failing test does not cascade into the rest.
    fn key_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"secret registry data with tokens and values";
        let path = std::env::temp_dir().join(format!(
            "hedgehog_test_encrypt_{}.enc",
            rand::random::<u64>()
        ));
        let key = [42u8; KEY_LEN];

        encrypt_with_key(&path, plaintext, &key).unwrap();
        assert!(path.exists());

        // File on disk should NOT contain plaintext
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(plaintext.len()).any(|w| w == plaintext));

        let decrypted = decrypt_with_key(&raw, &key).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(decrypt_with_key(&raw, &[43u8; KEY_LEN]).is_err());
        let mut tampered = raw;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_with_key(&tampered, &key).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_file_not_readable_as_text() {
        let plaintext = b"{\"tokens\": [{\"value\": \"AKIA1234567890ABCDEF\"}]}";
        let path = std::env::temp_dir().join(format!(
            "hedgehog_test_opaque_{}.enc",
            rand::random::<u64>()
        ));

        encrypt_with_key(&path, plaintext, &[42u8; KEY_LEN]).unwrap();

        let raw = std::fs::read(&path).unwrap();
        // Should not contain any of the original JSON
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("AKIA"));
        assert!(!raw_str.contains("tokens"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0xff, 0xab, 0x12, 0x34];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "00ffab1234");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert!(hex_decode("€€").is_none());
    }

    #[test]
    #[ignore = "requires an isolated OS credential store; run on the disposable release test VM"]
    fn key_is_deterministic_per_machine() {
        let _guard = key_lock();
        // Calling get_or_create_key twice should return the same key
        let k1 = get_or_create_key().unwrap();
        let k2 = get_or_create_key().unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), KEY_LEN);
    }

    #[test]
    fn corrupt_file_fails_gracefully() {
        let path = std::env::temp_dir().join(format!(
            "hedgehog_test_corrupt_{}.enc",
            rand::random::<u64>()
        ));
        std::fs::write(&path, b"not encrypted data at all").unwrap();
        let result = decrypt_from_file(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn machine_key_derivation_is_deterministic() {
        let k1 = derive_machine_wrapping_key().unwrap();
        let k2 = derive_machine_wrapping_key().unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), KEY_LEN);
        // Key should not be all zeros
        assert!(k1.iter().any(|&b| b != 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "writes the OS key store; run on the disposable release test VM"]
    fn machine_bound_roundtrip() {
        let _guard = key_lock();
        // Store and load a key via machine-bound wrapping
        let test_key = [42u8; KEY_LEN];
        machine_bound_store(&test_key).unwrap();
        let loaded = machine_bound_load().unwrap();
        assert_eq!(loaded, test_key);
    }
}
