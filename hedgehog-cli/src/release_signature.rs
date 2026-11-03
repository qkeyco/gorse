// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Signed release manifests.
//!
//! Every Gorse release on the public releases repository carries two files:
//!
//! * `SHA256SUMS.all`: one line per release asset, `<64 hex sha256>` two
//!   spaces `<asset file name>`, LF line endings, sorted by file name.
//! * `SHA256SUMS.all.sig`, signature format v2: exactly two LF-terminated
//!   lines. Line 1 `gorse-release-signature v2 key=<first 8 characters of
//!   the base64 public key> tag=<release tag>`, line 2 the standard padded
//!   base64 of the 64-byte Ed25519 signature over the ASCII bytes of
//!   `<tag>`, one LF, then the exact bytes of `SHA256SUMS.all`.
//!
//! Binding the tag is what stops a replay: a stale but genuinely signed
//! manifest copied under an invented newer tag would otherwise verify and
//! make Gorse recommend a "release" QKey never made. The verifier checks
//! the header's tag against the tag it asked for and then verifies the
//! signature over the tag it asked for, never the header's.
//!
//! Format v1 (`gorse-release-signature v1 key=<key id>`, signature over the
//! bare manifest) predates the binding. It is accepted only by
//! `gorse verify-download` for an explicitly given `--tag` that sorts
//! before v0.4.2 (0.4.1's published manifest is v1), so an existing
//! download can still be checked; it is never enough for the update check
//! to recommend a version.
//!
//! The update check only recommends a version whose manifest verifies with
//! the key below, and `gorse verify-download` lets a person check that a
//! file they downloaded is one QKey published. Nothing here reads or writes
//! user data; the only network traffic is two GETs for the manifest.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// The QKey release signing key: an Ed25519 public key, 32 bytes, standard
/// base64. Every `SHA256SUMS.all.sig` on the releases repository is made
/// with the matching private key, which never leaves the release machine.
/// Rotating this key requires a new release: a Gorse built with the old
/// key will refuse to recommend (or verify) anything signed with the new
/// one, which is the point.
pub const RELEASE_PUBLIC_KEY_B64: &str = "Dntss+6znmHXEgrCkvZy6GENQOA+bScwD5jtCYdraG0=";

/// Where the manifest files live: `<base>/<tag>/<file>`. Overridable with
/// `GORSE_RELEASES_BASE` (or `HEDGEHOG_RELEASES_BASE`), which may be an
/// `http(s)://` base, a `file://` base or a plain directory path.
pub const RELEASES_BASE: &str = "https://github.com/jamestagg/hedgehog-releases/releases/download";

pub const SUMS_FILE: &str = "SHA256SUMS.all";
pub const SIG_FILE: &str = "SHA256SUMS.all.sig";
const SIG_FORMAT: &str = "gorse-release-signature";
/// The first release whose manifest carries a v2 (tag-bound) signature.
/// Tags before it may be checked with a v1 signature by `verify-download`.
pub const FIRST_V2_VERSION: &str = "0.4.2";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// A manifest is a few kilobytes; anything larger is not one.
const MAX_FETCH_BYTES: usize = 1 << 20;

/// The verified contents of `SHA256SUMS.all`: asset file name to lowercase
/// hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub entries: BTreeMap<String, String>,
    /// The signature named the release tag (format v2). `false` only for a
    /// v1 manifest accepted under [`V1Policy::AcceptBeforeV2`].
    pub tag_bound: bool,
}

/// Whether a v1 (hash-only, tag-unbound) signature may be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1Policy {
    /// Never: the update recommendation, and any check where the tag was
    /// not given explicitly by the person.
    Reject,
    /// For an explicitly given tag that sorts before [`FIRST_V2_VERSION`]
    /// (`gorse verify-download --tag`). Later tags always need v2.
    AcceptBeforeV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The release has no manifest (404 or no such file).
    Missing,
    /// The manifest was fetched but does not verify or does not parse.
    Invalid(String),
    /// The manifest is genuinely signed but its signature is format v1,
    /// which does not name the release tag, and the policy needs v2.
    Unbound,
    /// Could not reach the releases host.
    Network(String),
}

impl FetchError {
    /// The one-word status the JSON outputs carry.
    pub fn label(&self) -> &'static str {
        match self {
            FetchError::Missing => "missing",
            FetchError::Invalid(_) => "invalid",
            FetchError::Unbound => "unbound",
            FetchError::Network(_) => "unreachable",
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Missing => write!(f, "no signed manifest is published for this release"),
            FetchError::Invalid(why) => write!(f, "the signed manifest is not valid: {why}"),
            FetchError::Unbound => write!(
                f,
                "the signed manifest does not name the release tag (signature format v1)"
            ),
            FetchError::Network(why) => write!(f, "could not fetch the signed manifest: {why}"),
        }
    }
}

/// Why a manifest did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Malformed, wrong key, wrong tag or a signature that does not match.
    Invalid(String),
    /// A valid v1 signature where the policy requires the tag to be bound.
    Unbound,
}

impl VerifyError {
    fn into_fetch(self) -> FetchError {
        match self {
            VerifyError::Invalid(why) => FetchError::Invalid(why),
            VerifyError::Unbound => FetchError::Unbound,
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Invalid(why) => write!(f, "{why}"),
            VerifyError::Unbound => write!(f, "signature does not name the release tag"),
        }
    }
}

/// The key this build trusts, as base64. Debug builds (which is what
/// `cargo test` runs) accept `GORSE_RELEASE_PUBLIC_KEY_B64` so the tests can
/// sign fixtures with a throwaway key; release builds compile the override
/// out and only ever use [`RELEASE_PUBLIC_KEY_B64`].
fn trusted_key_b64() -> String {
    #[cfg(debug_assertions)]
    if let Some(key) = crate::config::env_var("RELEASE_PUBLIC_KEY_B64") {
        return key;
    }
    RELEASE_PUBLIC_KEY_B64.to_string()
}

/// The short key id a signature file names: the first 8 characters of the
/// base64 public key.
pub fn key_id(public_key_b64: &str) -> &str {
    let end = public_key_b64
        .char_indices()
        .nth(8)
        .map(|(i, _)| i)
        .unwrap_or(public_key_b64.len());
    &public_key_b64[..end]
}

fn decode_key(public_key_b64: &str) -> Result<VerifyingKey, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| "public key is not valid base64".to_string())?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&raw).map_err(|_| "public key is not a valid Ed25519 key".to_string())
}

/// Parse `SHA256SUMS.all` without checking any signature. Rejects anything
/// that is not exactly `<64 hex>  <name>` per line, names that are not
/// plain file names, and duplicate names.
pub fn parse_sums(sums: &[u8]) -> Result<Manifest, String> {
    let text = std::str::from_utf8(sums).map_err(|_| "manifest is not UTF-8".to_string())?;
    let mut entries = BTreeMap::new();
    // Exactly one trailing LF; what remains must be whole lines.
    let body = text.strip_suffix('\n').unwrap_or(text);
    for (index, line) in body.split('\n').enumerate() {
        let number = index + 1;
        if line.is_empty() {
            return Err(format!("line {number}: empty line"));
        }
        let (hex, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("line {number}: expected `<sha256>  <file>`"))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("line {number}: hash is not 64 hex characters"));
        }
        if !valid_asset_name(name) {
            return Err(format!("line {number}: file name is not a plain file name"));
        }
        if entries
            .insert(name.to_string(), hex.to_ascii_lowercase())
            .is_some()
        {
            return Err(format!("line {number}: duplicate entry for {name}"));
        }
    }
    if entries.is_empty() {
        return Err("manifest has no entries".into());
    }
    Ok(Manifest {
        entries,
        tag_bound: false,
    })
}

fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

/// A parsed signature file: which format, the key id it names, the tag it
/// names (v2 only) and the raw 64-byte signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignature {
    pub version: u8,
    pub key_id: String,
    pub tag: Option<String>,
    pub signature: Vec<u8>,
}

/// A release tag as a v2 header carries it: `v<digits>.<digits>.<digits>`.
pub fn is_strict_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn decode_signature(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "signature is not valid base64".to_string())?;
    if bytes.len() != 64 {
        return Err("signature is not 64 bytes".into());
    }
    Ok(bytes)
}

/// Parse a signature file of either format. v2 is strict: exactly two
/// LF-terminated lines and nothing else. v1 tolerates CRLF and trailing
/// blank lines, as the 0.4.1 verifier did.
pub fn parse_signature(sig_text: &str) -> Result<ParsedSignature, String> {
    if let Some(rest) = sig_text.strip_prefix(&format!("{SIG_FORMAT} v2 ")) {
        let parts: Vec<&str> = rest.split('\n').collect();
        let [header, encoded, ""] = parts.as_slice() else {
            return Err("v2 signature file must be exactly two LF-terminated lines".to_string());
        };
        let (key, tag) = header
            .split_once(' ')
            .and_then(|(k, t)| Some((k.strip_prefix("key=")?, t.strip_prefix("tag=")?)))
            .ok_or("v2 signature header must be `key=<id> tag=<tag>`")?;
        if key.len() != 8
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        {
            return Err("v2 signature key id must be 8 base64 characters".into());
        }
        if !is_strict_release_tag(tag) {
            return Err(format!(
                "v2 signature names `{tag}`, which is not a release tag"
            ));
        }
        if encoded.len() != 88 || !encoded.ends_with("==") {
            return Err("v2 signature line must be 88 characters of padded base64".into());
        }
        return Ok(ParsedSignature {
            version: 2,
            key_id: key.to_string(),
            tag: Some(tag.to_string()),
            signature: decode_signature(encoded)?,
        });
    }
    let mut lines = sig_text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty());
    let header = lines.next().ok_or("signature file is empty")?;
    let key = header
        .strip_prefix(&format!("{SIG_FORMAT} v1 key="))
        .ok_or("signature file does not start with `gorse-release-signature v1` or `v2`")?;
    let encoded = lines.next().ok_or("signature file has no signature line")?;
    if lines.next().is_some() {
        return Err("signature file has extra lines".into());
    }
    Ok(ParsedSignature {
        version: 1,
        key_id: key.to_string(),
        tag: None,
        signature: decode_signature(encoded)?,
    })
}

/// The bytes a v2 signature covers: the tag, one LF, the manifest.
pub fn signed_message(tag: &str, sums: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(tag.len() + 1 + sums.len());
    message.extend_from_slice(tag.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(sums);
    message
}

/// Whether `tag` sorts numerically before [`FIRST_V2_VERSION`].
pub fn tag_predates_v2(tag: &str) -> bool {
    crate::update_check::is_newer(FIRST_V2_VERSION, tag)
}

/// Verify `SHA256SUMS.all` against `SHA256SUMS.all.sig` for the release
/// `expected_tag` with the key this build trusts and return the parsed
/// manifest. Any failure is an error, never a partial manifest.
pub fn verify_manifest(
    sums: &[u8],
    sig_text: &str,
    expected_tag: &str,
    v1: V1Policy,
) -> Result<Manifest, VerifyError> {
    verify_manifest_with(sums, sig_text, &trusted_key_b64(), expected_tag, v1)
}

/// [`verify_manifest`] with an explicit public key (base64).
///
/// Order for v2: parse, key id matches, the header's tag equals
/// `expected_tag`, then the signature is verified over `expected_tag` (not
/// the header's text) plus the manifest. A v1 signature is verified over
/// the bare manifest and then accepted only under the policy.
pub fn verify_manifest_with(
    sums: &[u8],
    sig_text: &str,
    public_key_b64: &str,
    expected_tag: &str,
    v1: V1Policy,
) -> Result<Manifest, VerifyError> {
    let invalid = VerifyError::Invalid;
    let key = decode_key(public_key_b64).map_err(invalid)?;
    let parsed = parse_signature(sig_text).map_err(invalid)?;
    let expected_key_id = key_id(public_key_b64);
    if parsed.key_id != expected_key_id {
        return Err(invalid(format!(
            "signature was made with key {}, this Gorse trusts key {expected_key_id}",
            parsed.key_id
        )));
    }
    let raw: [u8; 64] = parsed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| invalid("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&raw);
    let bound = match parsed.tag.as_deref() {
        Some(tag) => {
            if tag != expected_tag {
                return Err(invalid(format!(
                    "signature is for release {tag}, not {expected_tag}"
                )));
            }
            key.verify(&signed_message(expected_tag, sums), &signature)
                .map_err(|_| invalid("signature does not match the manifest and tag".into()))?;
            true
        }
        None => {
            key.verify(sums, &signature)
                .map_err(|_| invalid("signature does not match the manifest".into()))?;
            match v1 {
                V1Policy::AcceptBeforeV2 if tag_predates_v2(expected_tag) => false,
                _ => return Err(VerifyError::Unbound),
            }
        }
    };
    let mut manifest = parse_sums(sums).map_err(invalid)?;
    manifest.tag_bound = bound;
    Ok(manifest)
}

/// The releases base in effect: the environment override or the public
/// releases repository.
pub fn releases_base() -> String {
    match crate::config::env_var("RELEASES_BASE") {
        Some(base) if !base.trim().is_empty() => base.trim().trim_end_matches('/').to_string(),
        _ => RELEASES_BASE.to_string(),
    }
}

/// A release tag is `v` plus a version: letters, digits, dots, hyphens and
/// underscores only, so it can never be a path component trick.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && !tag.starts_with('.')
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Read one file under `<base>/<tag>/` from the web, a `file://` base or a
/// directory.
fn fetch_bytes(base: &str, tag: &str, file: &str) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    if base.starts_with("http://") || base.starts_with("https://") {
        let url = format!("{base}/{tag}/{file}");
        let agent = ureq::AgentBuilder::new()
            .timeout(FETCH_TIMEOUT)
            .redirects(5)
            .user_agent(&format!("gorse/{}", env!("CARGO_PKG_VERSION")))
            .build();
        return match agent.get(&url).call() {
            Ok(response) => {
                let mut bytes = Vec::new();
                response
                    .into_reader()
                    .take(MAX_FETCH_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| FetchError::Network(e.to_string()))?;
                if bytes.len() > MAX_FETCH_BYTES {
                    return Err(FetchError::Invalid(format!("{file} is too large")));
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
    let dir = Path::new(base.strip_prefix("file://").unwrap_or(base));
    let path = dir.join(tag).join(file);
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() > MAX_FETCH_BYTES => {
            Err(FetchError::Invalid(format!("{file} is too large")))
        }
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(FetchError::Missing),
        Err(e) => Err(FetchError::Network(format!("{}: {e}", path.display()))),
    }
}

/// Fetch and verify the signed manifest for a release tag. `v1` says
/// whether a tag-unbound (v1) signature may be accepted for this check.
pub fn fetch_manifest(tag: &str, v1: V1Policy) -> Result<Manifest, FetchError> {
    if !valid_tag(tag) {
        return Err(FetchError::Invalid(format!("`{tag}` is not a release tag")));
    }
    let base = releases_base();
    let sums = fetch_bytes(&base, tag, SUMS_FILE)?;
    let sig = fetch_bytes(&base, tag, SIG_FILE)?;
    let sig_text = String::from_utf8(sig)
        .map_err(|_| FetchError::Invalid("signature file is not UTF-8".into()))?;
    verify_manifest(&sums, &sig_text, tag, v1).map_err(VerifyError::into_fetch)
}

/// Lowercase hex SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> (SigningKey, String) {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        (signing, public)
    }

    /// A v2 signature file for `tag` over `sums`.
    fn sign(signing: &SigningKey, public_b64: &str, tag: &str, sums: &[u8]) -> String {
        format!(
            "{SIG_FORMAT} v2 key={} tag={tag}\n{}\n",
            key_id(public_b64),
            base64::engine::general_purpose::STANDARD
                .encode(signing.sign(&signed_message(tag, sums)).to_bytes())
        )
    }

    /// A v1 (hash-only) signature file over `sums`.
    fn sign_v1(signing: &SigningKey, public_b64: &str, sums: &[u8]) -> String {
        format!(
            "{SIG_FORMAT} v1 key={}\n{}\n",
            key_id(public_b64),
            base64::engine::general_purpose::STANDARD.encode(signing.sign(sums).to_bytes())
        )
    }

    const TAG: &str = "v9.9.9";
    const OLD_TAG: &str = "v0.4.1";

    fn verify(sums: &[u8], sig: &str, public: &str) -> Result<Manifest, VerifyError> {
        verify_manifest_with(sums, sig, public, TAG, V1Policy::Reject)
    }

    const SUMS: &[u8] =
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  Gorse-macOS.dmg\n\
fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  gorse-macos-aarch64.zip\n";

    #[test]
    fn embedded_key_is_a_valid_ed25519_key() {
        decode_key(RELEASE_PUBLIC_KEY_B64).unwrap();
        assert_eq!(key_id(RELEASE_PUBLIC_KEY_B64).len(), 8);
    }

    #[test]
    fn parses_a_well_formed_manifest() {
        let manifest = parse_sums(SUMS).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(
            manifest.entries["Gorse-macOS.dmg"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        // Uppercase hex is accepted and normalised.
        let upper = parse_sums(
            b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF  a.zip\n",
        )
        .unwrap();
        assert_eq!(
            upper.entries["a.zip"]
                .chars()
                .filter(|c| c.is_ascii_uppercase())
                .count(),
            0
        );
    }

    #[test]
    fn rejects_malformed_manifests() {
        let short = b"0123  a.zip\n";
        assert!(parse_sums(short).unwrap_err().contains("64 hex"));
        let single_space =
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef a.zip\n";
        assert!(parse_sums(single_space).is_err());
        let duplicate =
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  a.zip\n\
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  a.zip\n";
        assert!(parse_sums(duplicate).unwrap_err().contains("duplicate"));
        let path = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ../a.zip\n";
        assert!(parse_sums(path).is_err());
        let crlf = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  a.zip\r\n";
        assert!(parse_sums(crlf).is_err());
        let blank_inside =
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  a.zip\n\n\
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  b.zip\n";
        assert!(parse_sums(blank_inside).is_err());
        assert!(parse_sums(b"").is_err());
        assert!(parse_sums(&[0xff, 0xfe]).is_err());
    }

    fn err_text(result: Result<Manifest, VerifyError>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn verifies_a_good_signature_and_rejects_tampering() {
        let (signing, public) = key();
        let sig = sign(&signing, &public, TAG, SUMS);
        let manifest = verify(SUMS, &sig, &public).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.tag_bound);

        let mut tampered = SUMS.to_vec();
        tampered[0] = b'f';
        assert!(err_text(verify(&tampered, &sig, &public)).contains("does not match"));

        let other = SigningKey::from_bytes(&[9; 32]);
        let other_b64 =
            base64::engine::general_purpose::STANDARD.encode(other.verifying_key().to_bytes());
        let other_sig = sign(&other, &other_b64, TAG, SUMS);
        let err = err_text(verify(SUMS, &other_sig, &public));
        assert!(err.contains("key"), "{err}");
        // Same key id claimed, wrong key: the signature itself fails.
        let forged_header = sign(&other, &public, TAG, SUMS);
        assert!(verify(SUMS, &forged_header, &public).is_err());
    }

    #[test]
    fn v2_binds_the_tag() {
        let (signing, public) = key();
        // A genuine manifest for v9.9.8 served under v9.9.9 (a replay):
        // the header names the wrong tag.
        let stale = sign(&signing, &public, "v9.9.8", SUMS);
        let err = err_text(verify(SUMS, &stale, &public));
        assert!(err.contains("for release v9.9.8, not v9.9.9"), "{err}");
        // The header edited to claim v9.9.9 while the signature covers
        // v9.9.8: the signature is checked over the requested tag and fails.
        let edited = stale.replacen("tag=v9.9.8", "tag=v9.9.9", 1);
        let err = err_text(verify(SUMS, &edited, &public));
        assert!(err.contains("does not match"), "{err}");
        // The same signature file is only good for its own tag.
        assert!(verify_manifest_with(SUMS, &stale, &public, "v9.9.8", V1Policy::Reject).is_ok());
        // The message is `<tag>\n<sums>`, so a signature over the bare
        // manifest with a v2 header never verifies.
        let bare = format!(
            "{SIG_FORMAT} v2 key={} tag={TAG}\n{}\n",
            key_id(&public),
            base64::engine::general_purpose::STANDARD.encode(signing.sign(SUMS).to_bytes())
        );
        assert!(verify(SUMS, &bare, &public).is_err());
        assert_eq!(signed_message("v1.2.3", b"abc"), b"v1.2.3\nabc");
    }

    #[test]
    fn v1_is_accepted_only_for_an_old_explicit_tag() {
        let (signing, public) = key();
        let v1 = sign_v1(&signing, &public, SUMS);
        // The update recommendation never accepts v1.
        assert_eq!(
            verify_manifest_with(SUMS, &v1, &public, OLD_TAG, V1Policy::Reject).unwrap_err(),
            VerifyError::Unbound
        );
        // verify-download with an explicit tag before v0.4.2 does.
        let manifest =
            verify_manifest_with(SUMS, &v1, &public, OLD_TAG, V1Policy::AcceptBeforeV2).unwrap();
        assert!(!manifest.tag_bound);
        assert_eq!(manifest.entries.len(), 2);
        // A tag from v0.4.2 on always needs v2, whatever the policy.
        for tag in ["v0.4.2", "v0.5.0", TAG] {
            assert_eq!(
                verify_manifest_with(SUMS, &v1, &public, tag, V1Policy::AcceptBeforeV2)
                    .unwrap_err(),
                VerifyError::Unbound,
                "{tag}"
            );
        }
        // An invalid v1 signature is invalid, not merely unbound.
        let mut tampered = SUMS.to_vec();
        tampered[0] = b'f';
        assert!(matches!(
            verify_manifest_with(&tampered, &v1, &public, OLD_TAG, V1Policy::AcceptBeforeV2),
            Err(VerifyError::Invalid(_))
        ));
        assert!(tag_predates_v2("v0.4.1"));
        assert!(tag_predates_v2("0.1.0-alpha"));
        assert!(!tag_predates_v2("v0.4.2"));
        assert!(!tag_predates_v2("garbage"));
    }

    #[test]
    fn parses_both_formats_strictly() {
        let (signing, public) = key();
        let v2 = parse_signature(&sign(&signing, &public, TAG, SUMS)).unwrap();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.key_id, key_id(&public));
        assert_eq!(v2.tag.as_deref(), Some(TAG));
        assert_eq!(v2.signature.len(), 64);
        let v1 = parse_signature(&sign_v1(&signing, &public, SUMS)).unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.tag, None);
        assert!(is_strict_release_tag("v0.4.2"));
        assert!(!is_strict_release_tag("0.4.2"));
        assert!(!is_strict_release_tag("v0.4"));
        assert!(!is_strict_release_tag("v0.1.0-alpha"));
    }

    #[test]
    fn rejects_malformed_signature_files() {
        let (signing, public) = key();
        let good = sign(&signing, &public, TAG, SUMS);
        let header = good.lines().next().unwrap().to_string();
        let body = good.lines().nth(1).unwrap().to_string();

        assert!(verify(SUMS, "", &public).is_err());
        assert!(verify(SUMS, &format!("{header}\n"), &public).is_err());
        assert!(verify(SUMS, &format!("nope v2 key=x tag={TAG}\n{body}\n"), &public).is_err());
        assert!(verify(SUMS, &format!("{header}\n{body}\nextra\n"), &public).is_err());
        assert!(verify(SUMS, &format!("{header}\n{body}\n\n"), &public).is_err());
        assert!(verify(SUMS, &format!("{header}\n{body}"), &public).is_err());
        assert!(verify(SUMS, &format!("{header} \n{body}\n"), &public).is_err());
        assert!(err_text(verify(
            SUMS,
            &format!("{header}\n!!not base64!!\n"),
            &public
        ))
        .contains("base64"));
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert!(
            err_text(verify(SUMS, &format!("{header}\n{short}\n"), &public)).contains("base64")
        );
        // v2 is LF only: CRLF is not the documented format.
        let crlf = format!("{header}\r\n{body}\r\n");
        assert!(verify(SUMS, &crlf, &public).is_err());
        // The header's tag must look like a release tag.
        let odd = sign(&signing, &public, "v9.9.9-rc1", SUMS);
        assert!(verify_manifest_with(SUMS, &odd, &public, "v9.9.9-rc1", V1Policy::Reject).is_err());
        // A bad trusted key is an error, not a pass.
        assert!(verify(SUMS, &good, "AAAA").is_err());

        // v1 keeps the older tolerance: CRLF and trailing blank lines.
        let v1 = sign_v1(&signing, &public, SUMS);
        let v1_crlf = v1.replace('\n', "\r\n") + "\r\n";
        assert!(
            verify_manifest_with(SUMS, &v1_crlf, &public, OLD_TAG, V1Policy::AcceptBeforeV2)
                .is_ok()
        );
        let v1_short = format!("{SIG_FORMAT} v1 key={}\n{short}\n", key_id(&public));
        assert!(err_text(verify_manifest_with(
            SUMS,
            &v1_short,
            &public,
            OLD_TAG,
            V1Policy::AcceptBeforeV2
        ))
        .contains("64 bytes"));
    }

    #[test]
    fn signed_but_malformed_manifest_is_still_rejected() {
        let (signing, public) = key();
        let bad = b"not a manifest\n";
        let sig = sign(&signing, &public, TAG, bad);
        assert!(verify(bad, &sig, &public).is_err());
    }

    #[test]
    fn tag_validation() {
        assert!(valid_tag("v0.4.1"));
        assert!(valid_tag("v0.1.0-alpha"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("../v1"));
        assert!(!valid_tag("v1/x"));
        assert!(!valid_tag(".."));
        assert!(!valid_tag("v1 "));
    }

    #[test]
    fn fetches_from_a_directory_base() {
        let (signing, public) = key();
        let root = std::env::temp_dir().join(format!(
            "gorse-release-sig-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let dir = root.join("v9.9.9");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SUMS_FILE), SUMS).unwrap();
        std::fs::write(dir.join(SIG_FILE), sign(&signing, &public, "v9.9.9", SUMS)).unwrap();

        let fetched = fetch_bytes(&root.display().to_string(), "v9.9.9", SUMS_FILE).unwrap();
        assert_eq!(fetched, SUMS);
        let file_url = format!("file://{}", root.display());
        assert_eq!(
            fetch_bytes(&file_url, "v9.9.9", SIG_FILE).unwrap(),
            sign(&signing, &public, "v9.9.9", SUMS).as_bytes()
        );
        assert_eq!(
            fetch_bytes(&file_url, "v0.0.0", SUMS_FILE).unwrap_err(),
            FetchError::Missing
        );
        assert_eq!(
            fetch_bytes(&file_url, "v9.9.9", "other").unwrap_err(),
            FetchError::Missing
        );
        let dead = fetch_bytes("http://127.0.0.1:9", "v9.9.9", SUMS_FILE).unwrap_err();
        assert!(matches!(dead, FetchError::Network(_)), "{dead:?}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sha256_of_a_file() {
        let path = std::env::temp_dir().join(format!(
            "gorse-sha256-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(&path).unwrap();
        assert!(sha256_file(&path).is_err());
    }
}
