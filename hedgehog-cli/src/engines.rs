// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Optional engines the user can add with one click: today, TruffleHog.
//!
//! `gorse engines install trufflehog` downloads the pinned release for
//! this machine from Truffle Security's GitHub releases, checks it against a
//! checksum baked in here (taken from their published checksum file), keeps
//! only the executable and its licence under Gorse's own folder, and the
//! deep scan uses it from then on. The user installs their own copy of a
//! free program; Gorse distributes nothing of theirs. Nothing is sent
//! anywhere: this is one download.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const TRUFFLEHOG_VERSION: &str = "3.99.7";
const BASE_URL: &str = "https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.7/";

/// (os, arch, asset file name, sha256 from trufflehog_3.99.7_checksums.txt)
const ASSETS: &[(&str, &str, &str, &str)] = &[
    (
        "macos",
        "aarch64",
        "trufflehog_3.99.7_darwin_arm64.tar.gz",
        "5540ef352fc88b1f580e91603689782c0107ca7d4a96c1aeb2714b3a98c766ce",
    ),
    (
        "macos",
        "x86_64",
        "trufflehog_3.99.7_darwin_amd64.tar.gz",
        "6bdbc7b0aaeefcb50275036b49be1a3561b3c2e5902879300339abf9c64914c0",
    ),
    (
        "windows",
        "x86_64",
        "trufflehog_3.99.7_windows_amd64.tar.gz",
        "16e85ace8d7724774559d418e1bd876ae410a684321c1c44a34c499b03703d9d",
    ),
    (
        "windows",
        "aarch64",
        "trufflehog_3.99.7_windows_arm64.tar.gz",
        "7718dd78aabdbae63d534a88bdecdae0db92004f341395f540d6a03106c78099",
    ),
    (
        "linux",
        "x86_64",
        "trufflehog_3.99.7_linux_amd64.tar.gz",
        "bdbea0508e439b144f49de14e775908de5f902f3d14ea7ae8354bae72b0b72ef",
    ),
    (
        "linux",
        "aarch64",
        "trufflehog_3.99.7_linux_arm64.tar.gz",
        "3060f7c9f18c70afdc432984cacabdd1e9103729b5d5fee7fb6755a90d1c59d4",
    ),
];

/// Download size users are told to expect, in megabytes, before clicking.
pub const TRUFFLEHOG_DOWNLOAD_MB: u64 = 75;

pub fn engines_dir() -> PathBuf {
    crate::config::config_dir().join("engines")
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "trufflehog.exe"
    } else {
        "trufflehog"
    }
}

/// The copy Gorse installed, if any.
pub fn trufflehog_installed() -> Option<PathBuf> {
    let p = engines_dir().join(exe_name());
    p.is_file().then_some(p)
}

fn asset_for_this_machine() -> Result<(&'static str, &'static str), String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    ASSETS
        .iter()
        .find(|(o, a, _, _)| *o == os && *a == arch)
        .map(|(_, _, name, sha)| (*name, *sha))
        .ok_or_else(|| format!("no TruffleHog build is published for {os} {arch}"))
}

/// Minimal ustar reader: yields (name, bytes) for regular files. Enough for
/// the few-entry archives Truffle publishes; anything odd is an error.
pub fn tar_entries(tar: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 512 <= tar.len() {
        let header = &tar[pos..pos + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name_raw = &header[0..100];
        let name = String::from_utf8_lossy(
            &name_raw[..name_raw.iter().position(|&b| b == 0).unwrap_or(100)],
        )
        .to_string();
        let prefix_raw = &header[345..500];
        let prefix = String::from_utf8_lossy(
            &prefix_raw[..prefix_raw.iter().position(|&b| b == 0).unwrap_or(155)],
        )
        .to_string();
        let size_raw = String::from_utf8_lossy(&header[124..136]).to_string();
        let size = usize::from_str_radix(size_raw.trim_matches(|c: char| c == '\0' || c == ' '), 8)
            .map_err(|_| format!("bad size in tar header for {name}"))?;
        let typeflag = header[156];
        let full = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let data_start = pos + 512;
        let data_end = data_start.checked_add(size).ok_or("tar size overflow")?;
        if data_end > tar.len() {
            return Err(format!("tar entry {full} is truncated"));
        }
        if typeflag == b'0' || typeflag == 0 {
            out.push((full, tar[data_start..data_end].to_vec()));
        }
        pos = data_start + size.div_ceil(512) * 512;
    }
    Ok(out)
}

fn report(progress: &mut Option<&mut dyn FnMut(u64, Option<u64>)>, got: u64, total: Option<u64>) {
    if let Some(p) = progress.as_mut() {
        p(got, total);
    }
}

/// Where to download from and which SHA-256 to require. Debug builds accept
/// two test seams (a local server and a checksum for a synthetic archive)
/// from the environment; release builds compile them out, exactly as
/// `release_signature::trusted_key_b64` does, so anyone who can set the
/// user's environment cannot make `gorse engines install trufflehog` fetch
/// and run another binary. Release builds always use the pinned URL and the
/// pinned checksum table.
fn download_source(pinned_sha: &str) -> (String, String) {
    #[cfg(debug_assertions)]
    {
        let base =
            crate::config::env_var("TRUFFLEHOG_BASE_URL").unwrap_or_else(|| BASE_URL.to_string());
        let sha =
            crate::config::env_var("TRUFFLEHOG_SHA256").unwrap_or_else(|| pinned_sha.to_string());
        (base, sha)
    }
    #[cfg(not(debug_assertions))]
    {
        (BASE_URL.to_string(), pinned_sha.to_string())
    }
}

/// Download, verify and install. `progress` is called with bytes received
/// and the total when known. Returns the installed executable's path.
pub fn install_trufflehog(
    mut progress: Option<&mut dyn FnMut(u64, Option<u64>)>,
) -> Result<PathBuf, String> {
    let (asset, pinned_sha) = asset_for_this_machine()?;
    let (base, expected_sha) = download_source(pinned_sha);
    let url = format!("{}{}", base, asset);

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(900))
        .user_agent(&format!("gorse/{}", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .get(&url)
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let total = response
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok());
    let mut reader = response.into_reader();
    let mut archive = Vec::new();
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut got = 0u64;
    report(&mut progress, 0, total);
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("download interrupted: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        archive.extend_from_slice(&buf[..n]);
        got += n as u64;
        if archive.len() > 400 * 1024 * 1024 {
            return Err("download is larger than any TruffleHog release; refusing".into());
        }
        report(&mut progress, got, total);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected_sha {
        return Err(format!(
            "checksum mismatch: the download does not match the pinned TruffleHog {TRUFFLEHOG_VERSION} release (expected {}…, got {}…); nothing was installed",
            &expected_sha[..12],
            &actual[..12]
        ));
    }

    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(&archive[..])
        .read_to_end(&mut tar)
        .map_err(|e| format!("archive could not be decompressed: {e}"))?;
    let entries = tar_entries(&tar)?;
    let wanted = exe_name();
    let binary = entries
        .iter()
        .find(|(n, _)| n == wanted || n.ends_with(&format!("/{wanted}")))
        .map(|(_, b)| b.clone())
        .ok_or("archive has no trufflehog executable")?;
    let licence = entries
        .iter()
        .find(|(n, _)| n == "LICENSE" || n.ends_with("/LICENSE"))
        .map(|(_, b)| b.clone());

    let dir = engines_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let dest = dir.join(wanted);
    let tmp = dir.join(format!("{wanted}.download"));
    std::fs::write(&tmp, &binary).map_err(|e| format!("could not write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &dest)
        .map_err(|e| format!("could not install {}: {e}", dest.display()))?;
    if let Some(text) = licence {
        let _ = std::fs::write(dir.join("TRUFFLEHOG-LICENSE"), text);
    }
    let _ = std::fs::write(
        dir.join("trufflehog.version"),
        format!("{TRUFFLEHOG_VERSION}\n"),
    );
    #[cfg(target_os = "macos")]
    {
        // The checksum is our vouching; without this macOS refuses to run a
        // quarantined, ad-hoc-signed download.
        let _ = std::process::Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&dest)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    Ok(dest)
}

pub fn remove_trufflehog() -> Result<bool, String> {
    let dir = engines_dir();
    let dest = dir.join(exe_name());
    if !dest.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&dest).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(dir.join("TRUFFLEHOG-LICENSE"));
    let _ = std::fs::remove_file(dir.join("trufflehog.version"));
    Ok(true)
}

pub fn installed_version(path: &Path) -> String {
    std::fs::read_to_string(path.parent().unwrap_or(path).join("trufflehog.version"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar entry the way GNU tar writes it, for synthetic archives.
    pub fn tar_entry(name: &str, data: &[u8], mode: &str) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(mode.as_bytes());
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = b'0';
        h[257..262].copy_from_slice(b"ustar");
        h[263..265].copy_from_slice(b"00");
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..154].copy_from_slice(format!("{:06o}", sum).as_bytes());
        h[154] = 0;
        h[155] = b' ';
        let mut out = h;
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    #[test]
    fn minimal_tar_reader_finds_regular_files() {
        let mut tar = tar_entry("LICENSE", b"AGPL text", "0000644");
        tar.extend(tar_entry("trufflehog", b"#!/bin/sh\necho hi\n", "0000755"));
        tar.extend(vec![0u8; 1024]);
        let entries = tar_entries(&tar).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "LICENSE");
        assert_eq!(entries[1].0, "trufflehog");
        assert_eq!(entries[1].1, b"#!/bin/sh\necho hi\n");
        assert!(
            tar_entries(&tar[..515]).is_err(),
            "an entry cut inside its data is an error"
        );
    }

    #[test]
    fn every_platform_has_a_pinned_checksum() {
        for (_, _, name, sha) in ASSETS {
            assert!(name.contains(TRUFFLEHOG_VERSION));
            assert_eq!(sha.len(), 64);
            assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
