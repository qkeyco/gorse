// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Is there a newer Gorse? One GET to `/api/release` on gorse.is (or
//! `GORSE_API_ORIGIN`), carrying nothing but the user agent with this
//! version in it. The apps ask explicitly through `gorse version --check
//! --json`. The command-line `version` and `status` commands ask on their
//! own at most once a day, only when stdout is a terminal (never in scripts
//! or tests), and never when `GORSE_NO_UPDATE_CHECK` (or the older
//! `HEDGEHOG_NO_UPDATE_CHECK`) is set. The exposure
//! check and the scans never ask: they stay offline.
//!
//! A newer version is only *recommended* (the text notice, the `newer`
//! result, `newer_available` in the JSON) when its signed release manifest
//! verifies with the QKey release key *and* names that release's tag
//! (signature format v2; see `release_signature`). A newer version whose
//! manifest is missing, invalid, unreachable or signed in the older
//! tag-unbound format (`unbound`) is reported as published but not
//! recommended.
//!
//! The version recommended is the one the verified manifest's tag names,
//! never the server's word for it: `/api/release` is not signed, so a
//! version it reports that differs from the signed tag (`mismatch`) is not
//! recommended either.
//!
//! The daily cache never holds a verdict. It keeps the signed manifest and
//! its signature, which are verified again with the embedded key on every
//! cache hit; anything else in it is untrusted local data. Only a real
//! network check writes it.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::release_signature::{self, FetchError, V1Policy, VerifyError};

pub const DOWNLOAD_URL: &str = "https://www.gorse.is/download";
pub const SECURITY_URL: &str = "https://www.gorse.is/trust";
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// A newer version whose release manifest verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Newer {
    pub latest: String,
    pub url: String,
}

/// What `/api/release` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latest {
    pub version: String,
    pub tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// A v2 manifest for the tag verified.
    Verified,
    Missing,
    Invalid,
    /// Only a v1 (hash-only) manifest is published: genuine, but it does
    /// not name the release, so it cannot recommend one.
    Unbound,
    Unreachable,
    /// A manifest verified, but for a different version than the one
    /// `/api/release` reported.
    Mismatch,
}

impl SignatureStatus {
    pub fn label(self) -> &'static str {
        match self {
            SignatureStatus::Verified => "verified",
            SignatureStatus::Missing => "missing",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::Unbound => "unbound",
            SignatureStatus::Unreachable => "unreachable",
            SignatureStatus::Mismatch => "mismatch",
        }
    }

    fn of(error: &FetchError) -> Self {
        match error {
            FetchError::Missing => SignatureStatus::Missing,
            FetchError::Invalid(_) => SignatureStatus::Invalid,
            FetchError::Unbound => SignatureStatus::Unbound,
            FetchError::Network(_) => SignatureStatus::Unreachable,
        }
    }
}

/// The full result of an update check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The tag-derived version when the manifest verified; otherwise what
    /// `/api/release` reported.
    pub latest: String,
    pub tag: String,
    /// The version `/api/release` reported.
    pub advertised: String,
    /// `latest` is numerically newer than this build.
    pub is_newer: bool,
    /// Manifest verification for `tag`; only attempted when `is_newer`.
    pub signature: Option<SignatureStatus>,
    /// Asset name to hex SHA-256, when the manifest verified.
    pub sha256: Option<BTreeMap<String, String>>,
}

impl Check {
    /// The recommendation: newer *and* verified.
    pub fn newer(&self) -> Option<Newer> {
        (self.is_newer && self.signature == Some(SignatureStatus::Verified)).then(|| Newer {
            latest: self.latest.clone(),
            url: DOWNLOAD_URL.to_string(),
        })
    }

    /// The one line a text command prints: the recommendation, or the
    /// sentence that explains why a published newer version is not one.
    pub fn notice_line(&self) -> Option<String> {
        if let Some(newer) = self.newer() {
            return Some(notice(&newer));
        }
        if self.signature == Some(SignatureStatus::Mismatch) {
            return Some(mismatch_notice(
                &self.advertised,
                &version_of_tag(&self.tag),
            ));
        }
        self.is_newer.then(|| unverified_notice(&self.latest))
    }

    pub fn signature_label(&self) -> Option<&'static str> {
        self.signature.map(SignatureStatus::label)
    }
}

/// Numeric dotted comparison: "0.2.10" is newer than "0.2.9"; anything that
/// does not parse is never newer.
pub fn is_newer(latest: &str, current: &str) -> bool {
    fn parts(v: &str) -> Option<Vec<u64>> {
        v.trim()
            .trim_start_matches('v')
            .split('-')
            .next()?
            .split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect()
    }
    match (parts(latest), parts(current)) {
        (Some(l), Some(c)) => {
            let n = l.len().max(c.len());
            let pad = |v: &Vec<u64>, i: usize| v.get(i).copied().unwrap_or(0);
            for i in 0..n {
                match pad(&l, i).cmp(&pad(&c, i)) {
                    std::cmp::Ordering::Greater => return true,
                    std::cmp::Ordering::Less => return false,
                    std::cmp::Ordering::Equal => {}
                }
            }
            false
        }
        _ => false,
    }
}

fn cache_path() -> std::path::PathBuf {
    crate::config::config_dir().join("update-check.json")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The release tag for a version: what the server said, else `v<version>`.
pub fn tag_for(version: &str, tag: Option<&str>) -> String {
    match tag {
        Some(t) if release_signature::valid_tag(t.trim()) => t.trim().to_string(),
        _ if version.starts_with('v') => version.to_string(),
        _ => format!("v{version}"),
    }
}

/// The version a release tag names: the tag without its leading `v`.
pub fn version_of_tag(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_string()
}

/// Settle what to report from the advertised version, the tag and the
/// manifest verification. Only a verified manifest whose tag names exactly
/// the advertised version can recommend anything; a verified manifest for
/// another version is a `Mismatch` and carries no hashes.
fn reconcile(
    advertised: String,
    tag: String,
    signature: Option<SignatureStatus>,
    sha256: Option<BTreeMap<String, String>>,
    current: &str,
) -> Check {
    let signed = version_of_tag(&tag);
    match signature {
        Some(SignatureStatus::Verified) if signed != advertised.trim().trim_start_matches('v') => {
            Check {
                latest: advertised.clone(),
                tag,
                advertised,
                is_newer: false,
                signature: Some(SignatureStatus::Mismatch),
                sha256: None,
            }
        }
        Some(SignatureStatus::Verified) => Check {
            is_newer: is_newer(&signed, current),
            latest: signed,
            tag,
            advertised,
            signature,
            sha256,
        },
        _ => Check {
            is_newer: is_newer(&advertised, current),
            latest: advertised.clone(),
            tag,
            advertised,
            signature,
            sha256,
        },
    }
}

/// Ask the server. Short timeout; any failure is `None` and never an error
/// the user sees.
pub fn fetch_latest() -> Option<Latest> {
    let url = crate::api_origin::api_url("/api/release");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(3))
        .user_agent(&format!("gorse/{}", env!("CARGO_PKG_VERSION")))
        .build();
    let text = agent.get(&url).call().ok()?.into_string().ok()?;
    let body: serde_json::Value = serde_json::from_str(&text).ok()?;
    let version = body.get("version")?.as_str()?.trim().to_string();
    if version.is_empty() || version.len() > 32 {
        return None;
    }
    let tag = tag_for(&version, body.get("tag").and_then(|t| t.as_str()));
    Some(Latest { version, tag })
}

/// A signed manifest exactly as published: the bytes of `SHA256SUMS.all`
/// and the text of `SHA256SUMS.all.sig`. This, and not any verdict about
/// it, is what the cache keeps, so a cache hit is verified again with the
/// key this build trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedManifest {
    sums: String,
    sig: String,
}

impl SignedManifest {
    /// Verify for `tag` with the embedded key. A v1 manifest is `Unbound`,
    /// never verified: the recommendation needs the tag bound.
    fn verify(&self, tag: &str) -> Result<BTreeMap<String, String>, FetchError> {
        release_signature::verify_manifest(self.sums.as_bytes(), &self.sig, tag, V1Policy::Reject)
            .map(|manifest| manifest.entries)
            .map_err(|error| match error {
                VerifyError::Invalid(why) => FetchError::Invalid(why),
                VerifyError::Unbound => FetchError::Unbound,
            })
    }
}

/// A manifest is a few kilobytes; anything larger is not one.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// Read one file under `<releases base>/<tag>/`, over HTTP(S), from a
/// `file://` base or from a directory (the same places
/// `release_signature::fetch_manifest` reads), keeping the raw bytes so
/// the cache can store them.
fn fetch_release_file(tag: &str, file: &str) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    let base = release_signature::releases_base();
    let too_large = || FetchError::Invalid(format!("{file} is too large"));
    if base.starts_with("http://") || base.starts_with("https://") {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .redirects(5)
            .user_agent(&format!("gorse/{}", env!("CARGO_PKG_VERSION")))
            .build();
        return match agent.get(&format!("{base}/{tag}/{file}")).call() {
            Ok(response) => {
                let mut bytes = Vec::new();
                response
                    .into_reader()
                    .take(MAX_MANIFEST_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| FetchError::Network(e.to_string()))?;
                if bytes.len() as u64 > MAX_MANIFEST_BYTES {
                    return Err(too_large());
                }
                Ok(bytes)
            }
            Err(ureq::Error::Status(404, _)) => Err(FetchError::Missing),
            Err(ureq::Error::Status(code, _)) => {
                Err(FetchError::Network(format!("HTTP {code} for {file}")))
            }
            Err(ureq::Error::Transport(t)) => Err(FetchError::Network(t.to_string())),
        };
    }
    let path = std::path::Path::new(base.strip_prefix("file://").unwrap_or(&base))
        .join(tag)
        .join(file);
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() as u64 > MAX_MANIFEST_BYTES => Err(too_large()),
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(FetchError::Missing),
        Err(e) => Err(FetchError::Network(format!("{}: {e}", path.display()))),
    }
}

/// Fetch the signed manifest for `tag` and verify it.
fn fetch_signed(tag: &str) -> Result<(SignedManifest, BTreeMap<String, String>), FetchError> {
    if !release_signature::valid_tag(tag) {
        return Err(FetchError::Invalid(format!("`{tag}` is not a release tag")));
    }
    let utf8 = |bytes: Vec<u8>, what: &str| {
        String::from_utf8(bytes).map_err(|_| FetchError::Invalid(format!("{what} is not UTF-8")))
    };
    let sums = utf8(
        fetch_release_file(tag, release_signature::SUMS_FILE)?,
        "manifest",
    )?;
    let sig = utf8(
        fetch_release_file(tag, release_signature::SIG_FILE)?,
        "signature file",
    )?;
    let signed = SignedManifest { sums, sig };
    let entries = signed.verify(tag)?;
    Ok((signed, entries))
}

/// A cache entry that passed [`read_cache`]: either a signed manifest that
/// verified again just now for the cached tag, or a result that recommends
/// nothing (the cached version is not newer than this build).
#[derive(Debug, Clone)]
struct Cached {
    checked_at: u64,
    latest: String,
    tag: String,
    signed: Option<(SignedManifest, BTreeMap<String, String>)>,
}

/// Read the daily cache. Only what can be trusted without the network is
/// accepted: a stored manifest and signature are verified again with the
/// embedded key for the stored tag, and an entry whose signature does not
/// verify is discarded whole. An entry without a manifest is used only
/// when it recommends nothing; a claimed newer version without a manifest
/// is discarded, whatever verdict the file asserts. Verdict fields
/// (`signature`, `sha256`) are never read.
fn read_cache(path: &std::path::Path, current: &str) -> Option<Cached> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let checked_at = v.get("checked_at")?.as_u64()?;
    let latest = v.get("latest")?.as_str()?.trim().to_string();
    if latest.is_empty() || latest.len() > 32 {
        return None;
    }
    let tag = tag_for(&latest, v.get("tag").and_then(|t| t.as_str()));
    let text = |key: &str| v.get(key).and_then(|s| s.as_str()).map(str::to_string);
    let signed = match (text("manifest"), text("manifest_sig")) {
        (Some(sums), Some(sig)) => {
            let signed = SignedManifest { sums, sig };
            let entries = signed.verify(&tag).ok()?;
            Some((signed, entries))
        }
        (None, None) if !is_newer(&latest, current) => None,
        _ => return None,
    };
    Some(Cached {
        checked_at,
        latest,
        tag,
        signed,
    })
}

/// Record a real network check. Only the advertised version, its tag and
/// (when one verified) the signed manifest bytes are stored; never a
/// verdict.
fn write_cache(
    path: &std::path::Path,
    checked_at: u64,
    check: &Check,
    signed: Option<&SignedManifest>,
) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut entry = serde_json::json!({
        "checked_at": checked_at,
        "latest": check.advertised,
        "tag": check.tag,
    });
    if let Some(signed) = signed {
        entry["manifest"] = serde_json::Value::String(signed.sums.clone());
        entry["manifest_sig"] = serde_json::Value::String(signed.sig.clone());
    }
    let _ = std::fs::write(path, entry.to_string());
}

/// Tests can run the passive (terminal-only) check from a pipe. Debug
/// builds only, like the release key override.
fn stdout_counts_as_terminal() -> bool {
    #[cfg(debug_assertions)]
    if crate::config::env_flag("UPDATE_CHECK_ASSUME_TERMINAL") {
        return true;
    }
    std::io::stdout().is_terminal()
}

/// `force` asks the server now (the apps and `version --check`). Otherwise
/// the result comes from the daily cache, refreshed only when stdout is a
/// terminal, and nothing happens at all when the opt-out is set.
///
/// A cache hit is re-verified (see [`read_cache`]) and never rewritten, so
/// `checked_at` only ever records a real network check and an entry
/// expires a day after it. A newer version's manifest is fetched and
/// verified on every network check.
pub fn check_detailed(force: bool) -> Option<Check> {
    if !force {
        if crate::config::env_flag("NO_UPDATE_CHECK") {
            return None;
        }
        if !stdout_counts_as_terminal() {
            return None;
        }
    }
    let current = env!("CARGO_PKG_VERSION");
    let path = cache_path();
    let now = now();
    if !force {
        let cached = read_cache(&path, current)
            .filter(|c| c.checked_at <= now && now - c.checked_at < CACHE_TTL_SECS);
        if let Some(c) = cached {
            let (signature, sha256) = match c.signed {
                Some((_, entries)) if is_newer(&c.latest, current) => {
                    (Some(SignatureStatus::Verified), Some(entries))
                }
                _ => (None, None),
            };
            return Some(reconcile(c.latest, c.tag, signature, sha256, current));
        }
    }
    let latest = fetch_latest()?;
    let (signature, sha256, signed) = if is_newer(&latest.version, current) {
        match fetch_signed(&latest.tag) {
            Ok((signed, entries)) => (Some(SignatureStatus::Verified), Some(entries), Some(signed)),
            Err(error) => (Some(SignatureStatus::of(&error)), None, None),
        }
    } else {
        (None, None, None)
    };
    let check = reconcile(latest.version, latest.tag, signature, sha256, current);
    write_cache(&path, now, &check, signed.as_ref());
    Some(check)
}

/// The one-line notice the text commands print at the end.
pub fn notice(newer: &Newer) -> String {
    format!(
        "A newer Gorse ({}) is available: {}",
        newer.latest, newer.url
    )
}

/// The one sentence for a newer version Gorse will not recommend.
pub fn unverified_notice(latest: &str) -> String {
    format!(
        "A newer version ({latest}) is published but its signature could not be verified, so Gorse is not recommending it. See {SECURITY_URL}"
    )
}

/// The one sentence for a release whose signed manifest names another
/// version than the release page.
pub fn mismatch_notice(advertised: &str, signed: &str) -> String {
    format!(
        "The release page reports version {advertised} but the signed manifest is for {signed}, so Gorse is not recommending it."
    )
}

/// What a text command prints at the end when it checks on its own.
pub fn passive_notice() -> Option<String> {
    check_detailed(false).and_then(|c| c.notice_line())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_dotted_comparison() {
        assert!(is_newer("0.2.10", "0.2.9"));
        assert!(is_newer("1.0.0", "0.9.99"));
        assert!(is_newer("v0.3.0", "0.2.23"));
        assert!(!is_newer("0.2.23", "0.2.23"));
        assert!(!is_newer("0.2.22", "0.2.23"));
        assert!(!is_newer("garbage", "0.2.23"));
        assert!(!is_newer("", "0.2.23"));
        assert!(is_newer("0.2.23.1", "0.2.23"));
    }

    #[test]
    fn tag_defaults_to_v_version() {
        assert_eq!(tag_for("0.4.1", None), "v0.4.1");
        assert_eq!(tag_for("0.4.1", Some("v0.4.1")), "v0.4.1");
        assert_eq!(tag_for("0.4.1", Some("release/0.4.1")), "v0.4.1");
        assert_eq!(tag_for("v0.4.1", None), "v0.4.1");
    }

    #[test]
    fn only_a_verified_newer_version_is_recommended() {
        let mut check = Check {
            latest: "99.0.0".into(),
            tag: "v99.0.0".into(),
            advertised: "99.0.0".into(),
            is_newer: true,
            signature: Some(SignatureStatus::Missing),
            sha256: None,
        };
        assert!(check.newer().is_none());
        assert_eq!(
            check.notice_line().unwrap(),
            "A newer version (99.0.0) is published but its signature could not be verified, so Gorse is not recommending it. See https://www.gorse.is/trust"
        );
        check.signature = Some(SignatureStatus::Verified);
        assert_eq!(check.newer().unwrap().latest, "99.0.0");
        assert!(check
            .notice_line()
            .unwrap()
            .starts_with("A newer Gorse (99.0.0)"));
        check.is_newer = false;
        assert!(check.newer().is_none());
        assert!(check.notice_line().is_none());
    }

    #[test]
    fn recommended_version_comes_from_the_signed_tag() {
        let sha = || Some(BTreeMap::from([("a.zip".to_string(), "ab".to_string())]));
        // Advertised 9.9.9, manifest verified for v0.4.2: a mismatch.
        let check = reconcile(
            "9.9.9".into(),
            "v0.4.2".into(),
            Some(SignatureStatus::Verified),
            sha(),
            "0.4.1",
        );
        assert_eq!(check.signature, Some(SignatureStatus::Mismatch));
        assert!(check.newer().is_none());
        assert!(check.sha256.is_none());
        assert_eq!(
            check.notice_line().unwrap(),
            "The release page reports version 9.9.9 but the signed manifest is for 0.4.2, so Gorse is not recommending it."
        );
        // Consistent: the tag-derived version is recommended.
        let check = reconcile(
            "0.4.2".into(),
            "v0.4.2".into(),
            Some(SignatureStatus::Verified),
            sha(),
            "0.4.1",
        );
        assert_eq!(check.signature, Some(SignatureStatus::Verified));
        assert_eq!(check.newer().unwrap().latest, "0.4.2");
        // Consistent but not newer than this build: nothing to recommend.
        let check = reconcile(
            "0.4.2".into(),
            "v0.4.2".into(),
            Some(SignatureStatus::Verified),
            sha(),
            "0.4.2",
        );
        assert!(check.newer().is_none());
    }

    fn temp_cache() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "gorse-update-cache-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn cache_keeps_no_verdicts() {
        let path = temp_cache();
        let check = Check {
            latest: "0.0.1".into(),
            tag: "v0.0.1".into(),
            advertised: "0.0.1".into(),
            is_newer: false,
            signature: None,
            sha256: None,
        };
        write_cache(&path, 42, &check, None);
        let stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(stored.get("signature").is_none(), "{stored}");
        assert!(stored.get("sha256").is_none(), "{stored}");
        let cached = read_cache(&path, "0.4.5").unwrap();
        assert_eq!(cached.checked_at, 42);
        assert_eq!(cached.latest, "0.0.1");
        assert!(cached.signed.is_none());
        // The pre-signature cache shape still reads as a negative result.
        std::fs::write(&path, r#"{"checked_at": 5, "latest": "0.1.0"}"#).unwrap();
        let old = read_cache(&path, "0.4.5").unwrap();
        assert_eq!(old.tag, "v0.1.0");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_cached_verdict_without_a_manifest_is_discarded() {
        let path = temp_cache();
        // What an attacker (or any local process) can write: a newer
        // version, a claimed verdict and made-up hashes.
        std::fs::write(
            &path,
            serde_json::json!({
                "checked_at": now(),
                "latest": "9.9.9",
                "tag": "v9.9.9",
                "signature": "verified",
                "sha256": {"gorse-macos-aarch64.zip": "00".repeat(32)},
            })
            .to_string(),
        )
        .unwrap();
        assert!(read_cache(&path, "0.4.5").is_none());
        // A manifest whose signature does not verify: discarded too.
        std::fs::write(
            &path,
            serde_json::json!({
                "checked_at": now(),
                "latest": "9.9.9",
                "tag": "v9.9.9",
                "manifest": format!("{}  gorse-macos-aarch64.zip\n", "00".repeat(32)),
                "manifest_sig": "gorse-release-signature v2 key=AAAAAAAA tag=v9.9.9\nAAAA\n",
            })
            .to_string(),
        )
        .unwrap();
        assert!(read_cache(&path, "0.4.5").is_none());
        // Half a manifest: discarded, even for a version that is not newer.
        std::fs::write(
            &path,
            r#"{"checked_at": 5, "latest": "0.1.0", "manifest": "x"}"#,
        )
        .unwrap();
        assert!(read_cache(&path, "0.4.5").is_none());
        std::fs::remove_file(&path).unwrap();
    }
}
