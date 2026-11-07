// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Content-based secret and risk pattern matching.
//!
//! Pure matching logic — no file I/O, no external dependencies.
//! Detects secrets embedded in file contents: API keys, seed phrases,
//! PEM keys, credit cards, connection strings, passwords, and more.
//!
//! All detection uses only `std` library types. Pattern matching is
//! organized into four confidence tiers:
//!   - Definitive: zero false positives (PEM headers, API key prefixes)
//!   - High: strong structural match (seed phrases, JWT, credit cards)
//!   - ContextDependent: keyword + value patterns (passwords, SSN)
//!   - Heuristic: filename-based suspicion (photos of recovery keys)

/// Confidence level of a content finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Definitive,
    High,
    ContextDependent,
    Heuristic,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Definitive => "definitive",
            Confidence::High => "high",
            Confidence::ContextDependent => "context",
            Confidence::Heuristic => "heuristic",
        }
    }

    pub fn priority(&self) -> &'static str {
        match self {
            Confidence::Definitive => "critical",
            Confidence::High => "high",
            Confidence::ContextDependent => "medium",
            Confidence::Heuristic => "medium",
        }
    }

    /// Downgrade confidence by one tier (used when finding is in a comment).
    pub fn downgrade(&self) -> Confidence {
        match self {
            Confidence::Definitive => Confidence::High,
            Confidence::High => Confidence::ContextDependent,
            Confidence::ContextDependent => Confidence::Heuristic,
            Confidence::Heuristic => Confidence::Heuristic,
        }
    }
}

/// Context in which a finding was detected. Affects effective risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineContext {
    /// Pattern found in code or data (default).
    Code,
    /// Pattern found inside a code comment (lower risk — may be documentation).
    Comment,
    /// Pattern found in shell history or executed command (higher risk).
    Executed,
    /// Pattern found inside base64-encoded content.
    Base64Encoded,
}

impl LineContext {
    pub fn label(&self) -> &'static str {
        match self {
            LineContext::Code => "code",
            LineContext::Comment => "comment",
            LineContext::Executed => "executed",
            LineContext::Base64Encoded => "base64",
        }
    }
}

/// Type of content secret detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSecretType {
    PemPrivateKey,
    AwsAccessKey,
    ApiKey { service: &'static str },
    GoogleServiceAccount,
    SeedPhrase,
    WifPrivateKey,
    EthHexKey,
    JwtToken,
    CreditCard,
    DbConnectionString,
    PasswordPattern,
    SsnPattern,
    TwoFactorBackupCodes,
    SuspiciousImage,
    IbanPattern,
    SensitiveMarking { marking: &'static str },
}

/// Severity level based on the *type* of secret, not match confidence.
///
/// Confidence answers "how sure are we this is a match?"
/// Severity answers "how dangerous is this type of secret?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Direct credentials that enable immediate exploitation.
    Critical,
    /// Sensitive material: financial data, identity info, auth tokens, classified docs.
    High,
    /// Policy/regulatory concerns: corporate labels, export control, dissemination markings.
    Medium,
    /// Heuristic suspicion — e.g. image filenames that might contain photographed keys.
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl ContentSecretType {
    /// Severity based on the danger of this secret type — independent of match confidence.
    pub fn severity(&self) -> Severity {
        match self {
            // Direct credentials — immediate exploit
            ContentSecretType::PemPrivateKey
            | ContentSecretType::AwsAccessKey
            | ContentSecretType::ApiKey { .. }
            | ContentSecretType::GoogleServiceAccount
            | ContentSecretType::WifPrivateKey
            | ContentSecretType::EthHexKey
            | ContentSecretType::DbConnectionString
            | ContentSecretType::PasswordPattern => Severity::Critical,

            // Financial, identity, auth material
            ContentSecretType::SeedPhrase
            | ContentSecretType::CreditCard
            | ContentSecretType::IbanPattern
            | ContentSecretType::SsnPattern
            | ContentSecretType::JwtToken
            | ContentSecretType::TwoFactorBackupCodes => Severity::High,

            // Sensitivity markings — classify by sub-type
            ContentSecretType::SensitiveMarking { marking } => {
                match *marking {
                    // Government classification banners are high severity
                    "TOP SECRET" | "SECRET" | "CONFIDENTIAL" | "(TS)" | "(S)" | "(C)" => {
                        Severity::High
                    }
                    // Regulatory/policy markings are medium severity
                    _ => Severity::Medium,
                }
            }

            // Heuristic image suspicion
            ContentSecretType::SuspiciousImage => Severity::Low,
        }
    }

    /// True for government classification and dissemination markings
    /// (TOP SECRET, SECRET, CONFIDENTIAL, CUI, NOFORN, ORCON, REL TO and the
    /// portion marks). Policy since 2026-02-11: these are detected so the
    /// guard protects the file, but they are never shown to the user, written
    /// to JSON or uploaded. Commercial and export-control markings
    /// (Proprietary, Trade Secret, NDA, ITAR, EAR) stay visible.
    pub fn is_government_classification(&self) -> bool {
        match self {
            ContentSecretType::SensitiveMarking { marking } => is_government_marking(marking),
            _ => false,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ContentSecretType::PemPrivateKey => "pem_private_key",
            ContentSecretType::AwsAccessKey => "aws_access_key",
            ContentSecretType::ApiKey { .. } => "api_key",
            ContentSecretType::GoogleServiceAccount => "google_service_account",
            ContentSecretType::SeedPhrase => "seed_phrase",
            ContentSecretType::WifPrivateKey => "wif_private_key",
            ContentSecretType::EthHexKey => "eth_hex_key",
            ContentSecretType::JwtToken => "jwt_token",
            ContentSecretType::CreditCard => "credit_card",
            ContentSecretType::DbConnectionString => "db_connection_string",
            ContentSecretType::PasswordPattern => "password_pattern",
            ContentSecretType::SsnPattern => "ssn_pattern",
            ContentSecretType::TwoFactorBackupCodes => "two_factor_backup_codes",
            ContentSecretType::SuspiciousImage => "suspicious_image",
            ContentSecretType::IbanPattern => "iban_pattern",
            ContentSecretType::SensitiveMarking { .. } => "sensitive_marking",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            ContentSecretType::PemPrivateKey
            | ContentSecretType::WifPrivateKey
            | ContentSecretType::EthHexKey => "Crypto Keys",
            ContentSecretType::AwsAccessKey
            | ContentSecretType::ApiKey { .. }
            | ContentSecretType::GoogleServiceAccount => "API Keys",
            ContentSecretType::SeedPhrase => "Seed Phrases",
            ContentSecretType::JwtToken => "Auth Tokens",
            ContentSecretType::CreditCard | ContentSecretType::IbanPattern => "Financial",
            ContentSecretType::DbConnectionString => "DB Credentials",
            ContentSecretType::PasswordPattern => "Passwords",
            ContentSecretType::SsnPattern => "Identity (SSN)",
            ContentSecretType::TwoFactorBackupCodes => "2FA Codes",
            ContentSecretType::SuspiciousImage => "Suspicious Images",
            ContentSecretType::SensitiveMarking { .. } => "Sensitivity Labels",
        }
    }
}

/// Government classification/dissemination marking names, as stored in
/// `ContentSecretType::SensitiveMarking { marking }`. See
/// [`ContentSecretType::is_government_classification`].
pub fn is_government_marking(marking: &str) -> bool {
    matches!(
        marking,
        "TOP SECRET"
            | "SECRET"
            | "CONFIDENTIAL"
            | "CUI"
            | "(TS)"
            | "(S)"
            | "(C)"
            | "(CUI)"
            | "NOFORN"
            | "ORCON"
            | "REL TO"
    )
}

/// A single content-based finding within a file.
#[derive(Debug, Clone)]
pub struct ContentFinding {
    pub secret_type: ContentSecretType,
    pub confidence: Confidence,
    pub context: LineContext,
    pub line_number: usize,
    pub redacted_preview: String,
    pub description: &'static str,
}

// ─── API Key Prefix Table (~70+ services) ────────────────────────────────────

/// (prefix, min_total_length, service_name)
const API_KEY_PREFIXES: &[(&str, usize, &str)] = &[
    // GitHub
    ("ghp_", 40, "GitHub Personal Access Token"),
    ("gho_", 40, "GitHub OAuth Token"),
    ("ghu_", 40, "GitHub User-to-Server Token"),
    ("ghs_", 40, "GitHub Server-to-Server Token"),
    ("github_pat_", 40, "GitHub Fine-Grained PAT"),
    // Stripe
    ("sk_live_", 30, "Stripe Secret Key (Live)"),
    ("sk_test_", 30, "Stripe Secret Key (Test)"),
    ("rk_live_", 30, "Stripe Restricted Key"),
    ("pk_live_", 30, "Stripe Publishable Key (Live)"),
    ("whsec_", 30, "Stripe Webhook Secret"),
    // Anthropic
    ("sk-ant-api03-", 40, "Anthropic API Key"),
    // Slack
    ("xoxb-", 40, "Slack Bot Token"),
    ("xoxp-", 40, "Slack User Token"),
    ("xoxs-", 40, "Slack Session Token"),
    ("xoxa-", 40, "Slack App Token"),
    // npm
    ("npm_", 30, "npm Access Token"),
    // Google
    ("AIza", 35, "Google API Key"),
    // SendGrid
    ("SG.", 50, "SendGrid API Key"),
    // OpenAI
    ("sk-proj-", 40, "OpenAI API Key"),
    // Square
    ("sq0csp-", 40, "Square Client Secret"),
    ("sq0atp-", 40, "Square Access Token"),
    // Facebook / Meta
    ("EAAG", 40, "Facebook Access Token"),
    ("EAABw", 40, "Meta Access Token"),
    // Google OAuth
    ("ya29.", 30, "Google OAuth Token"),
    // age encryption
    ("AGE-SECRET-KEY-", 50, "age Encryption Secret Key"),
    // DigitalOcean
    ("dop_v1_", 40, "DigitalOcean Personal Token"),
    ("doo_v1_", 40, "DigitalOcean OAuth Token"),
    // GitLab
    ("glpat-", 26, "GitLab Personal Access Token"),
    // PyPI
    ("pypi-", 40, "PyPI API Token"),
    // Notion
    ("napi_", 40, "Notion API Key"),
    // Hugging Face
    ("hf_", 30, "Hugging Face Token"),
    // Slack (legacy)
    ("slack-", 40, "Slack Legacy Token"),
    // Flutterwave
    ("FLWSECK-", 30, "Flutterwave Secret Key"),
    ("FLWPUBK-", 30, "Flutterwave Public Key"),
    // Twilio
    ("AC", 34, "Twilio Account SID"),
    // Shopify
    ("shpat_", 30, "Shopify Admin API Token"),
    ("shpss_", 30, "Shopify Shared Secret"),
    ("shpca_", 30, "Shopify Custom App Token"),
    ("shppa_", 30, "Shopify Partner API Token"),
    // Resend
    ("re_", 30, "Resend API Key"),
    // Sentry
    ("sntrys_", 40, "Sentry Auth Token"),
    // Optic
    ("od_", 30, "Optic API Key"),
    // Clojars
    ("CLOJARS_", 30, "Clojars Deploy Token"),
    // RubyGems
    ("rubygems_", 30, "RubyGems API Key"),
    // Coinbase
    ("NhqPtmd", 30, "Coinbase API Key"),
    // Databricks
    ("dapi", 30, "Databricks API Token"),
    // Confluent
    ("CONFLUENT_", 30, "Confluent API Key"),
    // Postman
    ("PMAK-", 40, "Postman API Key"),
    // Linear
    ("lin_api_", 30, "Linear API Key"),
    // Supabase
    ("sbp_", 30, "Supabase Service Key"),
    // Vercel
    ("vercel_", 30, "Vercel API Token"),
    // Railway
    ("railway_", 30, "Railway API Token"),
    // Planetscale
    ("pscale_tkn_", 30, "PlanetScale Token"),
    // Hashicorp Vault
    ("hvs.", 20, "HashiCorp Vault Token"),
    // Pulumi
    ("pul-", 30, "Pulumi Access Token"),
    // Doppler
    ("dp.st.", 30, "Doppler Service Token"),
    // Buildkite
    ("bkua_", 30, "Buildkite Agent Token"),
    // Netlify
    ("nfp_", 30, "Netlify Personal Access Token"),
    // Airtable
    ("pat", 30, "Airtable Personal Access Token"),
    // Mapbox
    ("sk.", 60, "Mapbox Secret Token"),
    // Algolia
    ("ALGOLIA_", 30, "Algolia API Key"),
    // Figma
    ("figd_", 30, "Figma Personal Access Token"),
    // CircleCI
    ("circle-", 30, "CircleCI API Token"),
    // D-27: AI Provider Token Prefixes
    // DeepSeek
    ("dsk-", 40, "DeepSeek API Key"),
    // Groq
    ("gsk_", 40, "Groq API Key"),
    // Replicate
    ("r8_", 40, "Replicate API Token"),
    // ElevenLabs
    ("el_", 30, "ElevenLabs API Key"),
    // Cohere
    ("co_", 30, "Cohere API Key"),
    // Mistral
    ("mist_", 30, "Mistral API Key"),
    // Perplexity
    ("pplx-", 40, "Perplexity API Key"),
    // Together AI
    ("tog_", 30, "Together AI API Key"),
    // Fireworks AI
    ("fw_", 30, "Fireworks AI API Key"),
    // Stability AI
    ("sk-", 40, "Stability AI API Key"),
];

// ─── BIP-39 Wordlist Prefixes (4-char prefixes of the 2048 BIP-39 words) ─────
//
// We store sorted 4-char prefixes for O(log n) binary search.
// This catches seed phrases without embedding the full wordlist.
// A word matches if its first 4 chars are in this list.

include!("bip39_english.rs");

/// Base58 character set (Bitcoin).
const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// PEM header suffixes that indicate private keys.
const PEM_PRIVATE_SUFFIXES: &[&str] = &[
    "RSA PRIVATE KEY-----",
    "EC PRIVATE KEY-----",
    "PRIVATE KEY-----",
    "DSA PRIVATE KEY-----",
    "OPENSSH PRIVATE KEY-----",
    "ENCRYPTED PRIVATE KEY-----",
    "PGP PRIVATE KEY BLOCK-----",
];

/// Database connection string prefixes with embedded credentials.
const DB_PREFIXES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "mssql://",
    "mariadb://",
    "smtp://",
    "smtps://",
];

/// Keywords that indicate a password or secret assignment.
const PASSWORD_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "psw",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "auth_token",
    "auth_key",
    "private_key",
    "encryption_key",
    "master_key",
    "session_secret",
    "jwt_secret",
    "signing_key",
    "client_secret",
];

/// Assignment operators to look for after password keywords.
const ASSIGNMENT_OPS: &[&str] = &["=", ":", "=>", ":="];

/// Placeholder values that should NOT trigger a finding.
const PLACEHOLDER_VALUES: &[&str] = &[
    "xxx",
    "XXX",
    "your-",
    "your_",
    "YOUR_",
    "TODO",
    "todo",
    "CHANGE",
    "change_me",
    "changeme",
    "example",
    "EXAMPLE",
    "placeholder",
    "replace",
    "REPLACE",
    "insert",
    "INSERT",
    "<",
    "${",
    "{{",
    "null",
    "nil",
    "none",
    "false",
    "true",
    "0",
    "1",
    "\"\"",
    "''",
    "empty",
    "EMPTY",
    "test",
    "TEST",
    "dummy",
    "DUMMY",
    "fake",
    "FAKE",
    "sample",
    "SAMPLE",
];

/// Words that mark a value anywhere inside it as a stand-in, not a secret:
/// `sk_test_not_a_real_key`, `synthetic-recipient-secret`,
/// `acme-dev-jwt-secret-CHANGE-ME`.
const PLACEHOLDER_WORDS: &[&str] = &[
    "placeholder",
    "not_a_real",
    "not-a-real",
    "notareal",
    "changeme",
    "change_me",
    "change-me",
    "dummy",
    "fake",
    "synthetic",
    "redacted",
];

/// Image extensions (filename-only heuristic).
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "heic", "webp", "gif", "bmp", "tiff"];

/// Keywords in image filenames that suggest photographed secrets.
/// Must be specific enough to avoid matching normal filenames like "keyboard.png".
const IMAGE_SECRET_KEYWORDS: &[&str] = &[
    "recovery",
    "seed phrase",
    "mnemonic",
    "2fa",
    "backup code",
    "password",
    "wallet",
    "authenticator",
    "totp",
    "passphrase",
    "private key",
    "credential",
    "secret key",
    "recovery key",
    "seed-phrase",
    "backup-code",
    "private-key",
    "secret-key",
    "recovery-key",
    "seed_phrase",
    "backup_code",
    "private_key",
    "secret_key",
    "recovery_key",
];

// ─── Context Detection ──────────────────────────────────────────────────────

/// Detect whether a line is a code comment. Uses common comment syntax markers.
/// The longest prefix of `s` that is at most `max_bytes` long and ends on a
/// character boundary. Byte-offset slicing of scanned text panics when the
/// cut lands inside a multi-byte character (an em dash, an accented letter),
/// and a scanner must never crash on the content it is scanning.
pub fn safe_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn detect_line_context(line: &str) -> LineContext {
    let trimmed = line.trim();

    // Single-line comment styles
    if trimmed.starts_with("//")  // Rust, C, C++, Go, Java, JS, TS, Swift
        || trimmed.starts_with('#')   // Python, Ruby, Shell, YAML, TOML
            && !trimmed.starts_with("#!")  // Shebangs are executable, not comments
            && !trimmed.starts_with("#[") // Rust attributes
        || trimmed.starts_with("--")  // SQL, Haskell, Lua
        || trimmed.starts_with("/*")  // C-style block comment start
        || trimmed.starts_with("* ")  // Middle of a block comment
        || trimmed.starts_with("*/")  // End of block comment
        || trimmed.starts_with(';')   // INI, Assembly, Lisp
        || trimmed.starts_with("REM ") // Batch files
        || trimmed.starts_with("rem ")
    // Batch files (lowercase)
    {
        // But "#!" shebangs are executable
        if trimmed.starts_with("#!") || trimmed.starts_with("#[") {
            return LineContext::Code;
        }
        return LineContext::Comment;
    }

    LineContext::Code
}

// ─── Single-Line Checks ──────────────────────────────────────────────────────

/// Check a single line of text for secrets. Returns all findings on this line.
/// Findings default to `LineContext::Code`. Use `check_line_with_context` for
/// context-aware scanning that adjusts confidence based on comment detection.
pub fn check_line(line: &str, line_number: usize) -> Vec<ContentFinding> {
    check_line_cover(line, line_number).0
}

/// Byte spans of a line that a credential finding already covers.
type Cover = Vec<(usize, usize)>;

/// Whether `[s, e)` overlaps any covered span.
fn overlaps(cover: &[(usize, usize)], s: usize, e: usize) -> bool {
    cover.iter().any(|&(a, b)| s < b && a < e)
}

/// Byte offset of `part`, a slice of `line`, within `line`.
fn offset_in(line: &str, part: &str) -> usize {
    (part.as_ptr() as usize).saturating_sub(line.as_ptr() as usize)
}

/// End of the URL-like token starting at `pos`: the first whitespace,
/// quote, backtick or angle bracket.
fn url_token_end(line: &str, pos: usize) -> usize {
    line[pos..]
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>'))
        .map_or(line.len(), |e| pos + e)
}

/// `check_line`, plus the spans its credential findings cover (the key,
/// URL or value each one reports).
fn check_line_cover(line: &str, line_number: usize) -> (Vec<ContentFinding>, Cover) {
    let mut findings = Vec::new();
    let mut cover: Cover = Vec::new();

    // Skip very short lines
    if line.len() < 4 {
        return (findings, cover);
    }

    // Fast path for numeric data: plain-ASCII lines whose only letters, if
    // any, are `e`/`E` (CSV and TSV rows, instrument logs, scientific
    // notation such as `-9.98E-7`). Every other check needs a letter other
    // than e to match (key prefixes, keywords, schemes, PEM headers, `0x`,
    // `eyJ`, markings), and ASCII text has no case mapping that could make
    // one. Only the checks that can match digits, punctuation and `e`/`E`
    // run, in their usual order: card numbers, WIF keys (base58 includes
    // digits and e/E), SSNs and IBANs (`EE` is Estonia). This skips the
    // dozens of substring searches per line that dominate a scan of data
    // files. A new check that can match such a line must be added here and
    // to `check_line_all_checks` in the tests.
    if line.is_ascii()
        && line
            .bytes()
            .all(|b| !b.is_ascii_alphabetic() || b == b'e' || b == b'E')
    {
        check_credit_card(line, line_number, &mut findings);
        check_wif_key(line, line_number, &mut findings, &mut cover);
        check_ssn(line, line_number, &mut findings);
        check_iban(line, line_number, &mut findings);
        return (findings, cover);
    }

    // Tier 1: Definitive
    check_pem_header(line, line_number, &mut findings, &mut cover);
    check_aws_access_key(line, line_number, &mut findings, &mut cover);
    check_api_key_prefixes(line, line_number, &mut findings, &mut cover);
    check_google_service_account(line, line_number, &mut findings, &mut cover);
    check_webhook_urls(line, line_number, &mut findings, &mut cover);
    check_azure_patterns(line, line_number, &mut findings, &mut cover);

    // Tier 2: High confidence
    check_jwt_token(line, line_number, &mut findings, &mut cover);
    check_credit_card(line, line_number, &mut findings);
    check_wif_key(line, line_number, &mut findings, &mut cover);
    check_eth_hex_key(line, line_number, &mut findings, &mut cover);
    // URLs with credentials cover the whole URL; a key inside one
    // (`https://x-access-token:ghp_…@github.com`) is still named by its
    // service below, so these spans join the cover only after the imported rules.
    let mut url_cover: Cover = Vec::new();
    check_db_connection_string(line, line_number, &mut findings, &mut url_cover);
    check_uri_credentials(line, line_number, &mut findings, &mut url_cover);
    check_curl_user(line, line_number, &mut findings, &mut cover);

    // Betterleaks' service rules (MIT, converted to Gorse's own matcher), for
    // the hundreds of services Gorse has no rule of its own for. They always
    // run, so a second key on a line Gorse already flagged (one-line JSON,
    // a .env pasted as one line) is still found. An imported finding is
    // dropped only when its secret overlaps a span a Gorse key finding
    // already reports, or one an earlier imported rule reported: the same
    // key, listed once. Imported spans are kept in an ordered map so a line
    // with thousands of keys costs a lookup each, not a scan of all before.
    let mut imported: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (f, (s, e)) in crate::rules::check_line_imported_spans(line, line_number) {
        if overlaps(&cover, s, e) {
            continue;
        }
        // Stored spans never overlap each other, so the one starting last
        // before `e` is the only one that could overlap `s..e`.
        if imported
            .range(..e)
            .next_back()
            .is_some_and(|(_, &end)| end > s)
        {
            continue;
        }
        imported.insert(s, e);
        findings.push(f);
    }
    cover.extend(imported);
    cover.extend(url_cover);

    // Tier 3: Context-dependent. A value a service rule already named
    // needs no generic "password assigned" finding as well; any other
    // value on the line (a password beside a public identifier) still does.
    check_password_pattern(line, line_number, &mut findings, &mut cover);
    check_ssn(line, line_number, &mut findings);
    check_iban(line, line_number, &mut findings);

    // Tier 4: Sensitive document markings
    check_sensitive_markings(line, line_number, &mut findings);

    (findings, cover)
}

/// Whether one segment of an upper-case `.env` name (split at `_`, `.`,
/// `-`) names a secret: PASSWORD, PGPASSWORD, SECRET, CREDENTIALS, TOKEN,
/// AUTHTOKEN, KEY, APIKEY, PASS, PWD. TOKENIZER and KEYBOARD do not.
fn env_secret_segment(seg: &str) -> bool {
    ["PASSWORD", "PASSWD", "SECRET", "CREDENTIAL", "PASSPHRASE"]
        .iter()
        .any(|w| seg.contains(w))
        || matches!(seg, "PASS" | "PWD" | "PW" | "KEY" | "KEYS" | "PIN")
        || seg.ends_with("TOKEN")
        || seg.ends_with("TOKENS")
        || [
            "APIKEY",
            "PRIVKEY",
            "PRIVATEKEY",
            "ACCESSKEY",
            "SECRETKEY",
            "AUTHKEY",
            "MASTERKEY",
        ]
        .iter()
        .any(|w| seg.ends_with(w))
}

/// Name endings that describe a secret rather than hold one
/// (`PRIVATE_KEY_PATH`, `TOKEN_URL`, `API_KEY_ID`).
const ENV_NON_SECRET_SUFFIXES: &[&str] = &[
    "_ID",
    "_IDS",
    "_PATH",
    "_FILE",
    "_DIR",
    "_URL",
    "_URI",
    "_ENDPOINT",
    "_HOST",
    "_PORT",
    "_NAME",
    "_TYPE",
    "_USER",
    "_USERNAME",
    "_REGION",
    "_VERSION",
    "_LENGTH",
    "_LEN",
    "_SIZE",
    "_TTL",
    "_EXPIRY",
    "_EXPIRES",
    "_SECONDS",
    "_HEADER",
    "_ALGORITHM",
    "_ALG",
    "_ENABLED",
    "_FORMAT",
];

/// `NAME=value` or `export NAME=value` (`.env` syntax): the name and the
/// value with its quotes and any trailing ` # comment` removed.
fn env_assignment(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    let t = t.strip_prefix("export ").map_or(t, str::trim_start);
    let name_end =
        t.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))?;
    let name = &t[..name_end];
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    let rest = t[name_end..].trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=')?.trim_start_matches([' ', '\t']);
    let value = match rest.chars().next() {
        Some(q @ ('"' | '\'')) => {
            let inner = &rest[1..];
            &inner[..inner.find(q).unwrap_or(inner.len())]
        }
        _ => {
            let v = match rest.find(" #").or_else(|| rest.find("\t#")) {
                Some(c) => &rest[..c],
                None => rest,
            };
            v.trim_end()
        }
    };
    Some((name, value))
}

/// Checks one line of a `.env`-style file. A `NAME=value` (optionally
/// `export NAME=value`) whose name holds a password, secret, token or key
/// word reports its value as a literal secret whenever the value is not
/// empty, not a placeholder and not an interpolation (`$VAR`, `${VAR}`).
/// A `.env` file holds values, not code, so the code-shape rules that keep
/// `check_line` quiet on source files (`correct_horse_battery_staple`
/// reads as a snake_case name there) do not apply. Everything else on the
/// line is checked as `check_line` does.
pub fn check_env_line(line: &str, line_number: usize) -> Vec<ContentFinding> {
    let (mut findings, cover) = check_line_cover(line, line_number);
    let Some((name, value)) = env_assignment(line) else {
        return findings;
    };
    let upper = name.to_ascii_uppercase();
    let secret_name = upper.split(['_', '.', '-']).any(env_secret_segment)
        && !ENV_NON_SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
        && !upper.contains("PUBLIC")
        && !upper.contains("PUBLISHABLE");
    if !secret_name || value.len() < 4 {
        return findings;
    }
    let lower = value.to_ascii_lowercase();
    let interpolation = value.starts_with('$') || value.contains("${") || value.contains("{{");
    let placeholder = PLACEHOLDER_VALUES
        .iter()
        .any(|p| lower == p.to_ascii_lowercase())
        || ["xxx", "your-", "your_", "<", "change", "replace", "insert"]
            .iter()
            .any(|p| lower.starts_with(p))
        || PLACEHOLDER_WORDS.iter().any(|w| lower.contains(w))
        || value.chars().all(|c| c == '*' || c == 'x' || c == 'X');
    // A bare number is a setting (`TOKEN_REFRESH_MINUTES=30`) unless the
    // name says password.
    let number_setting = value.chars().all(|c| c.is_ascii_digit())
        && !["PASS", "PWD", "SECRET", "PIN"]
            .iter()
            .any(|w| upper.contains(w));
    if interpolation || placeholder || number_setting {
        return findings;
    }
    let s = offset_in(line, value);
    if overlaps(&cover, s, s + value.len()) {
        return findings;
    }
    findings.push(ContentFinding {
        secret_type: ContentSecretType::PasswordPattern,
        confidence: Confidence::High,
        context: LineContext::Code,
        line_number,
        redacted_preview: format!("{}=****", safe_prefix(name, 40)),
        description: "Password or secret value assigned in plain text",
    });
    findings
}

/// Check a line with context-aware confidence adjustment.
///
/// Detects whether the line is a comment and downgrades confidence for
/// findings in comments. For Executed context (shell history), upgrades
/// context-dependent findings.
pub fn check_line_with_context(
    line: &str,
    line_number: usize,
    override_context: Option<LineContext>,
) -> Vec<ContentFinding> {
    let mut findings = check_line(line, line_number);

    if findings.is_empty() {
        return findings;
    }

    let ctx = override_context.unwrap_or_else(|| detect_line_context(line));

    for finding in &mut findings {
        finding.context = ctx;
        match ctx {
            LineContext::Comment => {
                // Secrets in comments are lower risk — may be documentation/examples
                finding.confidence = finding.confidence.downgrade();
            }
            LineContext::Executed => {
                // Secrets in executed commands are higher risk — no downgrade
            }
            LineContext::Base64Encoded => {
                // Secrets hidden in base64 are deliberate evasion — no downgrade
            }
            LineContext::Code => {}
        }
    }

    findings
}

/// Scan a line for base64-encoded secrets. Extracts base64-looking tokens,
/// decodes them, and scans the decoded content for secrets.
///
/// Returns findings with `LineContext::Base64Encoded` context.
pub fn check_base64_content(line: &str, line_number: usize) -> Vec<ContentFinding> {
    let mut findings = Vec::new();

    // Find base64-looking tokens in the line (space/quote delimited, 20+ chars)
    for token in extract_base64_tokens(line) {
        if let Some(decoded_bytes) = base64_decode(token) {
            // Must decode to valid UTF-8
            if let Ok(decoded) = core::str::from_utf8(&decoded_bytes) {
                // Scan the decoded content
                let mut inner = check_line(decoded, line_number);
                for finding in &mut inner {
                    finding.context = LineContext::Base64Encoded;
                    finding.redacted_preview = format!("[base64] {}", finding.redacted_preview);
                }
                findings.extend(inner);
            }
        }
    }

    findings
}

/// Extract potential base64-encoded tokens from a line.
/// Splits on whitespace, quotes, and common assignment operators, then checks
/// each token for valid base64 format (20+ chars, valid alphabet, padding).
fn extract_base64_tokens(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();

    // Split on common delimiters: whitespace, quotes, semicolons, commas, backticks
    for token in line.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == ';' || c == ',' || c == '`'
    }) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        // If token contains '=' that looks like assignment (key=value), split on it
        // But preserve trailing '=' which is base64 padding
        if let Some(eq_pos) = token.find('=') {
            // Check if the part before '=' is a key (contains non-base64 chars like letters only)
            let before = &token[..eq_pos];
            let after = &token[eq_pos + 1..];

            // If there's content after '=', the '=' is likely an assignment
            if !after.is_empty() && !after.chars().all(|c| c == '=') {
                // Check the value part (after '=')
                if after.len() >= 20 && is_likely_base64(after) {
                    tokens.push(after);
                }
                // Also check the key part (unlikely but possible)
                if before.len() >= 20 && is_likely_base64(before) {
                    tokens.push(before);
                }
                continue;
            }
        }

        // Check the whole token
        if token.len() >= 20 && is_likely_base64(token) {
            tokens.push(token);
        }
    }

    tokens
}

/// Check multiple lines for patterns that span across lines (seed phrases, 2FA codes).
pub fn check_multi_line(lines: &[&str]) -> Vec<ContentFinding> {
    let mut findings = Vec::new();
    check_seed_phrase(lines, &mut findings);
    check_2fa_backup_codes(lines, &mut findings);
    findings
}

/// Check an image filename for suspicious keywords.
pub fn check_image_filename(filename: &str) -> Option<ContentFinding> {
    let lower = filename.to_ascii_lowercase();

    // Check extension
    let is_image = IMAGE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
    if !is_image {
        return None;
    }

    // Check for secret-related keywords in filename
    for keyword in IMAGE_SECRET_KEYWORDS {
        if contains_word(&lower, keyword) {
            return Some(ContentFinding {
                secret_type: ContentSecretType::SuspiciousImage,
                confidence: Confidence::Heuristic,
                context: LineContext::Code,
                line_number: 0,
                redacted_preview: format!("Image: {filename}"),
                description: "Image filename suggests photographed recovery key or credentials \
                              — may sync to cloud photo libraries",
            });
        }
    }

    None
}

/// Check if `haystack` contains `keyword` as a whole word, not embedded in a
/// hex string or UUID. A word boundary is any non-alphanumeric character or
/// start/end of string.
fn contains_word(haystack: &str, keyword: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(keyword) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !haystack.as_bytes()[abs_pos - 1].is_ascii_alphanumeric();
        let after_pos = abs_pos + keyword.len();
        let after_ok =
            after_pos >= haystack.len() || !haystack.as_bytes()[after_pos].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

// ─── Tier 1: Definitive ──────────────────────────────────────────────────────

fn check_pem_header(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    let Some(begin) = line.find("-----BEGIN ") else {
        return;
    };
    for suffix in PEM_PRIVATE_SUFFIXES {
        if let Some(at) = line.find(suffix) {
            cover.push((begin.min(at), (at + suffix.len()).max(begin + 11)));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::PemPrivateKey,
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: "-----BEGIN ****-----".to_string(),
                description: "PEM-encoded private key — grants access to encrypted \
                              communications or code signing",
            });
            return;
        }
    }
}

fn check_aws_access_key(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // AWS access keys start with AKIA followed by 16 alphanumeric chars [A-Z2-7]
    let mut start = 0;
    while let Some(pos) = line[start..].find("AKIA") {
        let abs_pos = start + pos;
        let after = &line[abs_pos + 4..];
        if let Some(candidate) = after.get(..16) {
            if candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
            {
                let preview = format!("AKIA{}****", &candidate[..4]);
                cover.push((abs_pos, abs_pos + 20));
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::AwsAccessKey,
                    confidence: Confidence::Definitive,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: preview,
                    description: "AWS Access Key — grants access to AWS services and billing",
                });
                return;
            }
        }
        start = abs_pos + 4;
    }
}

fn check_api_key_prefixes(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // Every distinct key on the line is reported (one-line JSON can hold
    // two tokens of one service); a token two prefixes both match
    // (`sk-proj-…` and `sk-`) is reported once, by the first.
    let mut reported: Vec<(usize, usize)> = Vec::new();
    for &(prefix, min_len, service) in API_KEY_PREFIXES {
        for (pos, _) in line.match_indices(prefix) {
            if overlaps(&reported, pos, pos + 1) {
                continue;
            }
            // The prefix must start a token: "re_" inside "pre_bind" or a
            // path is not a Resend key.
            if let Some(before) = line[..pos].chars().next_back() {
                if before.is_ascii_alphanumeric() || matches!(before, '_' | '-' | '/' | '\\' | '.')
                {
                    continue;
                }
            }
            // Extract the token: run forward until whitespace, a quote, a
            // separator, or a URL query separator (`?key=AIza…&callback=`
            // ends the key at `&`; `#` starts a fragment).
            let token_start = pos;
            let rest = &line[token_start..];
            let token_end = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(c, '"' | '\'' | ',' | ';' | ')' | '}' | '&' | '?' | '#')
                })
                .unwrap_or(rest.len());
            let token = &rest[..token_end];

            // A key is one run of key characters; a path, a file name or an
            // expression is not.
            let dotted = prefix.ends_with('.') || prefix == "pat";
            if token.contains([
                '/', '\\', '+', '=', ':', '(', '[', '{', '<', '>', '*', '%', '$', '@',
            ]) || (!dotted && token.contains('.'))
            {
                continue;
            }
            // Short prefixes also start ordinary names (re_render_all,
            // hf_scale_v2). Keys of those services carry digits or capitals,
            // and never read as snake_case or kebab-case words. A lowercase
            // value with separators is a key only when one of its parts is a
            // long random run of letters and digits (`dapi<32 hex>-2`).
            if prefix.len() <= 4 {
                let suffix = &token[prefix.len().min(token.len())..];
                let upper = suffix.chars().any(|c| c.is_ascii_uppercase());
                let digit = suffix.chars().any(|c| c.is_ascii_digit());
                let random_part = || {
                    suffix.split(['_', '-']).any(|part| {
                        part.len() >= 16
                            && part.chars().any(|c| c.is_ascii_digit())
                            && part.chars().any(|c| c.is_ascii_alphabetic())
                            && shannon_entropy(part) >= ENTROPY_THRESHOLD_API_KEY
                    })
                };
                if (!upper && !digit) || (!upper && suffix.contains(['_', '-']) && !random_part()) {
                    continue;
                }
                // A camelCase identifier (hf_cliLoginWithTokenFromEnvironmentVar)
                // has capitals too, but splits into readable word pieces;
                // key material never compresses that well.
                if crate::rules::tokens::token_ratio(suffix).is_some_and(|ratio| ratio >= 2.5) {
                    continue;
                }
            }

            if token.len() >= min_len {
                // For Twilio "AC" prefix, require exactly 32 hex chars after
                if prefix == "AC" && token.len() != 34 {
                    continue;
                }
                if prefix == "AC" && !token[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                // For "pat" prefix (Airtable), be more strict — require alphanumeric after
                if prefix == "pat" && (token.len() < 40 || !token[3..].starts_with('.')) {
                    continue;
                }

                // Entropy check: the suffix after the prefix should have real randomness
                let suffix = &token[prefix.len()..];
                if suffix.len() >= 8 && shannon_entropy(suffix) < ENTROPY_THRESHOLD_API_KEY {
                    continue;
                }

                // D-23: False positive filter
                if is_false_positive(token) || is_false_positive(suffix) {
                    continue;
                }

                let preview_len = prefix.len().min(8);
                let preview = format!("{}****", &token[..preview_len]);
                reported.push((pos, pos + token.len()));
                cover.push((pos, pos + token.len()));
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::ApiKey { service },
                    confidence: Confidence::Definitive,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: preview,
                    description: match service {
                        "Stripe Secret Key (Live)" => {
                            "Stripe live secret key — can process payments"
                        }
                        "Anthropic API Key" => "Anthropic API key — access to Claude models",
                        "OpenAI API Key" => "OpenAI API key — access to GPT models and billing",
                        "GitHub Personal Access Token" => {
                            "GitHub PAT — repository and account access"
                        }
                        "Slack Bot Token" => "Slack bot token — can read/post messages",
                        "SendGrid API Key" => "SendGrid API key — can send email as your domain",
                        "Google API Key" => "Google API key — access to Google Cloud services",
                        _ => "API key or access token for external service",
                    },
                });
            }
        }
    }
}

fn check_google_service_account(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // Google service account JSON has both "type" and "service_account"
    let lower = line.to_ascii_lowercase();
    if let (true, Some(at)) = (lower.contains("\"type\""), lower.find("service_account")) {
        cover.push((at, at + "service_account".len()));
        findings.push(ContentFinding {
            secret_type: ContentSecretType::GoogleServiceAccount,
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "Google service account JSON".to_string(),
            description: "Google Cloud service account key — full API access to GCP project",
        });
    }
}

// ─── Tier 2: High Confidence ─────────────────────────────────────────────────

fn check_jwt_token(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // JWT: eyJ + base64url + . + base64url + . + base64url
    let mut start = 0;
    while let Some(pos) = line[start..].find("eyJ") {
        let abs_pos = start + pos;
        let rest = &line[abs_pos..];

        // Find the end of the token
        let token_end = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';')
            .unwrap_or(rest.len());
        let token = &rest[..token_end];

        // Must have exactly 2 dots (3 parts)
        let dot_count = token.chars().filter(|&c| c == '.').count();
        if dot_count == 2 {
            let parts: Vec<&str> = token.splitn(3, '.').collect();
            if parts.len() == 3
                && parts[0].len() >= 4
                && parts[1].len() >= 4
                && parts[2].len() >= 4
                && is_base64url(parts[0])
                && is_base64url(parts[1])
            {
                cover.push((abs_pos, abs_pos + token.len()));
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::JwtToken,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("eyJ****...({} chars)", token.len()),
                    description: "JWT token — may contain session credentials or API access",
                });
                return;
            }
        }
        start = abs_pos + 3;
    }
}

fn check_credit_card(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // Cheap gate: a card number needs at least 13 digits on the line.
    if line.bytes().filter(u8::is_ascii_digit).count() < 13 {
        return;
    }
    for pure_digits in card_candidates(line) {
        check_card_digits(&pure_digits, line_number, findings);
        if findings.last().is_some_and(|f| {
            f.line_number == line_number && f.secret_type == ContentSecretType::CreditCard
        }) {
            return;
        }
    }
}

/// Runs of 13 to 19 digits written as one number, optionally grouped by
/// single spaces or dashes ("NNNN NNNN NNNN NNNN"). A run that is part of a
/// decimal number (123.4567890123456), or glued to letters (an id or a
/// hash), is not a card number.
fn card_candidates(line: &str) -> Vec<String> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = String::new();
        let mut end = i;
        while i < b.len() {
            if b[i].is_ascii_digit() {
                digits.push(b[i] as char);
                i += 1;
                end = i;
            } else if (b[i] == b' ' || b[i] == b'-') && i + 1 < b.len() && b[i + 1].is_ascii_digit()
            {
                i += 1;
            } else {
                break;
            }
        }
        let before = start.checked_sub(1).map(|j| b[j]);
        let after = b.get(end).copied();
        let after2 = b.get(end + 1).copied();
        // Only `.` marks a decimal; `,` separates fields (CSV rows such as
        // `name,4532…,1225,123`) and digit groups, never a card's digits.
        let decimal = before == Some(b'.')
            || (after == Some(b'.') && after2.is_some_and(|c| c.is_ascii_digit()));
        let glued = before.is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
            || after.is_some_and(|c| c.is_ascii_alphabetic() || c == b'_');
        if (13..=19).contains(&digits.len()) && !decimal && !glued {
            out.push(digits);
        }
    }
    out
}

fn check_card_digits(pure_digits: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // Check BIN prefix (first 1-2 digits)
    let card_type = match pure_digits.as_bytes()[0] {
        b'4' if pure_digits.len() == 16 => "Visa",
        b'5' if pure_digits.len() == 16 && (b'1'..=b'5').contains(&pure_digits.as_bytes()[1]) => {
            "Mastercard"
        }
        b'3' if pure_digits.len() == 15
            && (pure_digits.as_bytes()[1] == b'4' || pure_digits.as_bytes()[1] == b'7') =>
        {
            "Amex"
        }
        b'6' if pure_digits.len() == 16 && pure_digits.starts_with("6011") => "Discover",
        _ => return,
    };

    if luhn_check(&pure_digits) {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::CreditCard,
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: format!(
                "{}****{}",
                &pure_digits[..4],
                &pure_digits[pure_digits.len() - 4..]
            ),
            description: match card_type {
                "Visa" => "Credit card number (Visa, Luhn valid)",
                "Mastercard" => "Credit card number (Mastercard, Luhn valid)",
                "Amex" => "Credit card number (American Express, Luhn valid)",
                "Discover" => "Credit card number (Discover, Luhn valid)",
                _ => "Credit card number (Luhn valid)",
            },
        });
    }
}

fn check_db_connection_string(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    let lower = line.to_ascii_lowercase();
    // Every occurrence of every scheme: `postgres://localhost/db` first and
    // `postgres://app:pw@db` later on the same line is still found.
    for prefix in DB_PREFIXES {
        for (pos, _) in lower.match_indices(prefix) {
            // `postgres://` inside `postgresql://` style overlaps, or a URL
            // already reported.
            if overlaps(cover, pos, pos + 1) {
                continue;
            }
            let end = url_token_end(line, pos);
            // Must contain @ (embedded credentials) within the URL itself.
            if line[pos..end].contains('@') {
                let scheme = prefix.trim_end_matches("://");
                cover.push((pos, end));
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::DbConnectionString,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("{scheme}://****@****"),
                    description: "Database connection string with embedded credentials",
                });
            }
        }
    }
}

fn check_wif_key(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // WIF private keys: start with '5' (len 51) or 'K'/'L' (len 52)
    for word in line.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric());
        let valid = match trimmed.as_bytes().first() {
            Some(b'5') if trimmed.len() == 51 => true,
            Some(b'K') | Some(b'L') if trimmed.len() == 52 => true,
            _ => false,
        };
        if valid && is_base58(trimmed) {
            let at = offset_in(line, trimmed);
            cover.push((at, at + trimmed.len()));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::WifPrivateKey,
                confidence: Confidence::High,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("{}****", &trimmed[..4]),
                description: "Bitcoin WIF private key — grants full control of crypto wallet",
            });
            return;
        }
    }
}

/// Words in a name that say a 64-hex value is a private key.
const HEX_KEY_WORDS: &[&str] = &[
    "privatekey",
    "privkey",
    "secretkey",
    "signingkey",
    "signerkey",
    "walletkey",
    "deployerkey",
    "accountkey",
    "ethkey",
    "mnemonic",
    "wallet",
    "secret",
];

/// Further words that make the *name* a value is assigned to a key name
/// (`accounts: ["0x…"]`, `OPERATOR_KEY`, `signer`). Elsewhere on a line
/// they are too common to count.
const HEX_NAME_KEY_WORDS: &[&str] = &["private", "account", "signer", "operator", "deployer"];

/// Words in a name that say a 64-hex value is a hash, slot, root or other
/// public constant. Code is full of these; a key is not.
const HEX_HASH_WORDS: &[&str] = &[
    "hash",
    "slot",
    "root",
    "salt",
    "topic",
    "selector",
    "digest",
    "checksum",
    "txid",
    "bytes32",
    "constant",
    "commit",
    "nonce",
    "sha1",
    "sha256",
    "sha512",
    "etag",
    "fingerprint",
    "public",
    "pubkey",
    "address",
    "storage",
    "cache",
];

/// Lowercase, without `_`, `-`, spaces and tabs: "ROOT_PRIVATE_KEY" ->
/// "rootprivatekey".
fn squash(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' ' | '\t'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The name a value at `pos` is assigned to: the text left of the last `=`
/// or `:` before it, back to the previous statement or field separator
/// (`ROOT_PRIVATE_KEY` in `ROOT_PRIVATE_KEY=0x…`). Empty when the value is
/// not assigned to anything.
fn assigned_name(line: &str, pos: usize) -> &str {
    let before = &line[..pos];
    let Some(op) = before.rfind(['=', ':']) else {
        return "";
    };
    let name = &before[..op];
    match name.rfind([';', ',', '{', '(', '[']) {
        Some(sep) => &name[sep + 1..],
        None => name,
    }
}

/// What the assigned name says about a 64-hex value: Some(true) a key,
/// Some(false) a hash or constant, None nothing. The word nearer the end of
/// the name wins, so "ROOT_PRIVATE_KEY" is a key and "PRIVATE_KEY_SHA256"
/// or "bytes32 constant ROLE_HASH" is not. Key words are those of
/// `HEX_KEY_WORDS` and a name ending in `pk` (`DEPLOYER_PK`, `{pk: …}`);
/// with `key_suffix`, any name ending in `key` or `keys` (`ADMIN_KEY`,
/// `const key`) too, which is said only of `0x` values: a bare 64-hex
/// value beside `must_match_key` is a checksum.
fn hex_name_verdict(name: &str, key_suffix: bool) -> Option<bool> {
    // Solidity visibility words (`bytes32 private immutable X`) say
    // nothing about the value.
    let name: String = name
        .split_whitespace()
        .filter(|w| {
            !matches!(
                *w,
                "private" | "public" | "internal" | "external" | "immutable"
            )
        })
        .flat_map(str::chars)
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let last_end = |words: &[&str]| {
        words
            .iter()
            .filter_map(|w| name.rfind(w).map(|i| i + w.len()))
            .max()
    };
    // A key suffix counts from where it starts, so a hash word just before
    // it still wins (`publicKey`, `cacheKey`, `storageKey`).
    let suffix_start = ["pk"]
        .iter()
        .chain(if key_suffix {
            &["keys", "key"][..]
        } else {
            &[][..]
        })
        .find(|w| name.ends_with(*w))
        .map(|w| name.len() - w.len());
    let key = suffix_start
        .max(last_end(HEX_KEY_WORDS))
        .max(last_end(HEX_NAME_KEY_WORDS));
    match (key, last_end(HEX_HASH_WORDS)) {
        (Some(k), Some(h)) => Some(k > h),
        (Some(_), None) => Some(true),
        (None, Some(_)) => Some(false),
        (None, None) => None,
    }
}

/// Whether what follows a value is nothing or only a comment
/// (`0x…  // my main account`).
fn only_comment_after(rest: &str) -> bool {
    let rest = rest.trim();
    rest.is_empty()
        || ["//", "#", "--", "/*", ";"]
            .iter()
            .any(|c| rest.starts_with(c))
}

/// Whether a 0x-prefixed 64-hex value at `pos` reads as a private key.
/// Such values are mostly hashes, storage slots, roots and test vectors in
/// code; a key comes with words that say so, or is pasted on its own line.
/// The name the value is assigned to decides first; only when it says
/// nothing do words elsewhere on the line count (a key word, and no hash
/// word anywhere). A comment such as `# do not commit` never outweighs
/// `PRIVATE_KEY=`.
fn hex_key_context(line: &str, pos: usize) -> bool {
    if let Some(verdict) = hex_name_verdict(assigned_name(line, pos), true) {
        return verdict;
    }
    let squashed = squash(line);
    if HEX_HASH_WORDS.iter().any(|w| squashed.contains(w)) {
        return false;
    }
    if HEX_KEY_WORDS.iter().any(|w| squashed.contains(w)) {
        return true;
    }
    // Pasted on its own (a note, a text file): nothing else on the line but
    // a comment.
    line[..pos].trim().is_empty() && line.get(pos + 66..).is_some_and(only_comment_after)
}

fn check_eth_hex_key(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // 0x + 64 hex chars, at every `0x` on the line. Use .get() to avoid
    // panicking on multi-byte UTF-8.
    for (pos, _) in line.match_indices("0x") {
        let after = &line[pos + 2..];
        let Some(candidate) = after.get(..64) else {
            continue;
        };
        if !candidate.chars().all(|c| c.is_ascii_hexdigit()) || !hex_key_context(line, pos) {
            continue;
        }
        // Reject EVM bytecode: if hex continues well past 64 chars, it's
        // contract bytecode (often thousands of hex chars), not a private key.
        let extra_hex = after[64..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .count();
        if extra_hex > 16 {
            continue; // bytecode, not a key
        }
        // Entropy check: reject repeated patterns like "aabbccdd" x 8
        if shannon_entropy(candidate) < ENTROPY_THRESHOLD_HEX_KEY {
            continue;
        }
        // D-23: False positive filter
        if is_false_positive(candidate) {
            continue;
        }
        let preview_end = &candidate[..4]; // safe: all ASCII hex
        cover.push((pos, pos + 66));
        findings.push(ContentFinding {
            secret_type: ContentSecretType::EthHexKey,
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: format!("0x{preview_end}****"),
            description: "Ethereum/EVM hex private key — grants full control of crypto wallet",
        });
        return;
    }

    // 64 hex chars near a keyword.
    // "key" and "hex" alone also sit beside every SHA-256 checksum
    // ("must_match_key", sha256sum listings); a wallet key comes with words
    // like these, and a line about hashes is about hashes.
    let line_says_key = || {
        let lower = line.to_ascii_lowercase();
        [
            "private", "priv_key", "privkey", "wallet", "secret", "signer", "mnemonic", "eth_key",
            "evm",
        ]
        .iter()
        .any(|w| lower.contains(w))
            && ![
                "sha256",
                "sha-256",
                "sha512",
                "hash",
                "digest",
                "checksum",
                "etag",
                "commit",
                "fingerprint",
                "slot",
                "root",
                "salt",
                "bytes32",
                "constant",
                "topic",
                "selector",
            ]
            .iter()
            .any(|w| lower.contains(w))
    };
    // Every run of hex digits, so "PRIVATE_KEY=<hex>" and "0x<hex>" count.
    // The name each run is assigned to decides first, as for 0x values.
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        // ASCII hex digits only, so both ends are character boundaries.
        let run = &line[start..i];
        if run.len() != 64 || shannon_entropy(run) < ENTROPY_THRESHOLD_HEX_KEY {
            continue;
        }
        // D-23: False positive filter, as for 0x values.
        if is_false_positive(run) {
            continue;
        }
        if hex_name_verdict(assigned_name(line, start), false).unwrap_or_else(line_says_key) {
            cover.push((start, i));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::EthHexKey,
                confidence: Confidence::High,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("{}****", safe_prefix(run, 4)),
                description: "Possible Ethereum/EVM hex private key near crypto keyword",
            });
            return;
        }
    }
}

// ─── Tier 3: Context-Dependent ───────────────────────────────────────────────

fn check_password_pattern(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    let lower = line.to_ascii_lowercase();
    for keyword in PASSWORD_KEYWORDS {
        // Every occurrence: `"auth_mode": "pass_through", "pass": "…"` holds
        // the keyword twice and only the second is assigned.
        for (kw_pos, _) in lower.match_indices(keyword) {
            // Three letters occur by chance in binary data read as text
            // (`PSw=` inside a browser database): `psw` counts only in its
            // ordinary spellings.
            if *keyword == "psw" && !matches!(&line[kw_pos..kw_pos + 3], "psw" | "PSW" | "Psw") {
                continue;
            }
            let Some((value, op)) = password_value(line, kw_pos, keyword) else {
                continue;
            };
            // A value a credential finding (or an earlier keyword) already
            // reports is not reported again.
            let vs = offset_in(line, value);
            if overlaps(cover, vs, vs + value.len()) {
                continue;
            }
            cover.push((vs, vs + value.len()));
            let redacted_kw = &line[kw_pos..kw_pos + keyword.len()];
            // A UUID under `token` or `key` is as often a record id as a
            // credential: kept, at a lower likelihood.
            let confidence = if uuid_shaped(value) {
                Confidence::Heuristic
            } else {
                Confidence::ContextDependent
            };
            findings.push(ContentFinding {
                secret_type: ContentSecretType::PasswordPattern,
                confidence,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("{redacted_kw} {op} ****"),
                description: "Password or secret value assigned in plain text",
            });
        }
    }
}

/// Whether a keyword names a password or secret itself (`password`,
/// `pass`, `client_secret`), rather than a token or key.
fn password_keyword(keyword: &str) -> bool {
    keyword.contains("pass") || keyword.contains("secret") || keyword == "psw"
}

/// `8-4-4-4-12` hex: a UUID.
fn uuid_shaped(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Words that, beside a password keyword in a key name, say the key
/// describes a password field rather than holds a password:
/// `passwordLabel`, `password_hint`, `token_url`, `has_password`,
/// `secret_name`, `private_key_path`.
const UI_KEY_WORDS: &[&str] = &[
    "label",
    "placeholder",
    "hint",
    "title",
    "message",
    "error",
    "required",
    "prompt",
    "help",
    "text",
    "description",
    "field",
    "input",
    "rule",
    "rules",
    "policy",
    "strength",
    "confirm",
    "confirmation",
    "reset",
    "forgot",
    "change",
    "changed",
    "visible",
    "show",
    "hide",
    "toggle",
    "mismatch",
    "length",
    "min",
    "max",
    "pattern",
    "validation",
    "invalid",
    "empty",
    "blank",
    "tooltip",
    "caption",
    "header",
    "heading",
    "button",
    "link",
    "icon",
    "type",
    "kind",
    "mode",
    "format",
    "status",
    "state",
    "enabled",
    "disabled",
    "expiry",
    "expires",
    "expired",
    "age",
    "count",
    "attempts",
    "retries",
    "timeout",
    "ttl",
    "url",
    "uri",
    "path",
    "file",
    "dir",
    "name",
    "id",
    "index",
    "version",
    "hash",
    "salt",
    "algorithm",
    "method",
    "scheme",
    "provider",
    "source",
    "scope",
    "role",
    "group",
    "user",
    "username",
    "email",
    "domain",
    "host",
    "has",
    "is",
    "use",
    "no",
    "wrong",
    "enter",
    "your",
    "with",
    "require",
    "requires",
    "validate",
    "check",
    "verify",
];

/// One word that may precede a bare password name and keep it bare:
/// `db_password`, `NEW_PASS`, `admin_secret`, `PGPASSWORD`.
const BARE_KEY_PREFIXES: &[&str] = &[
    "new",
    "old",
    "current",
    "db",
    "admin",
    "root",
    "api",
    "app",
    "service",
    "client",
    "master",
    "access",
    "refresh",
    "session",
    "jwt",
    "signing",
    "encryption",
    "private",
    "secret",
    "key",
    "pg",
    "wifi",
    "smtp",
    "ssh",
    "sudo",
    "ldap",
    "mysql",
    "redis",
    "ftp",
];

/// Keywords that name a password outright: a sentence assigned to one of
/// these (bare, or behind one `BARE_KEY_PREFIXES` word) may be a pass
/// phrase.
const BARE_PASSWORD_NAMES: &[&str] = &[
    "password",
    "passphrase",
    "pass",
    "passwd",
    "psw",
    "pwd",
    "secret",
];

/// What the key holding a password keyword says about its value.
#[derive(Clone, Copy)]
struct KeyName {
    /// The keyword is a password or secret word (`password`, `pass`,
    /// `client_secret`), not a token or key: a few code-like shapes are
    /// a password after all (`!MintyRidge42`, `AutumnRiver42`).
    password: bool,
    /// The key is a bare password name (`password`, `DB_PASSWORD`,
    /// `new_pass`): a quoted sentence may be a pass phrase.
    bare: bool,
}

/// The words of a key name other than the keyword, lower-cased:
/// `passwordLabel` -> ["label"], `DB_PASSWORD` -> ["db"], `PGPASSWORD` ->
/// ["pg"], `has_password` -> ["has"], `api_key` -> ["api", "key"].
fn key_words(ident: &str, keyword: &str) -> Vec<String> {
    let mut words = Vec::new();
    for piece in ident.split(['_', '-', '$']).filter(|p| !p.is_empty()) {
        // A SCREAMING_CASE piece is one word; a camelCase piece splits
        // at each capital.
        let parts = if piece.chars().any(|c| c.is_ascii_lowercase()) {
            split_capitals(piece)
        } else {
            vec![piece]
        };
        for part in parts {
            let lower = part.to_ascii_lowercase();
            match lower.find(keyword) {
                Some(i) => {
                    let (before, after) = (&lower[..i], &lower[i + keyword.len()..]);
                    if !before.is_empty() {
                        words.push(before.to_string());
                    }
                    if !after.is_empty() {
                        words.push(after.to_string());
                    }
                }
                None => words.push(lower),
            }
        }
    }
    words
}

/// What the key `ident` (the identifier holding `keyword`) says, or None
/// when one of its other words marks it as describing a password field
/// rather than holding a password.
fn key_name(ident: &str, keyword: &str) -> Option<KeyName> {
    let words = key_words(ident, keyword);
    if words.iter().any(|w| UI_KEY_WORDS.contains(&w.as_str())) {
        return None;
    }
    let bare = BARE_PASSWORD_NAMES.contains(&keyword)
        && match words.as_slice() {
            [] => true,
            [one] => BARE_KEY_PREFIXES.contains(&one.as_str()),
            _ => false,
        };
    Some(KeyName {
        password: password_keyword(keyword),
        bare,
    })
}

/// The literal value assigned to the password keyword at `kw_pos`, and the
/// assignment operator, or None when the keyword is not assigned a literal.
fn password_value<'a>(
    line: &'a str,
    kw_pos: usize,
    keyword: &str,
) -> Option<(&'a str, &'static str)> {
    // The keyword must not continue a lowercase word: "bypass" and
    // "compass" do not count. A camelCase part ("dbPass"), a separated
    // name ("db_pass") and a SCREAMING_CASE run-on ("PGPASSWORD",
    // "DBPASSWORD") do.
    if let Some(before) = line[..kw_pos].chars().next_back() {
        let kw_lower = line[kw_pos..].starts_with(|c: char| c.is_ascii_lowercase());
        if before.is_ascii_lowercase() && kw_lower {
            return None;
        }
    }
    // Look for assignment after the keyword. A JSON or YAML key closes its
    // quote first: `"password": "…"`, `'db_pass': …`.
    let after_kw = &line[kw_pos + keyword.len()..];
    let after_kw = match after_kw.strip_prefix(['"', '\'']) {
        Some(rest) if line[..kw_pos].contains(['"', '\'']) => rest,
        _ => after_kw,
    };
    let trimmed = after_kw.trim_start();
    let op = ASSIGNMENT_OPS.iter().find(|op| trimmed.starts_with(**op))?;
    // The identifier holding the keyword (`db_password`, `user.passwordLabel`,
    // `$pwd`); its last dotted segment decides what the key describes.
    let name_start = line[..kw_pos]
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$')))
        .map_or(0, |(i, c)| i + c.len_utf8());
    let kw_end = kw_pos + keyword.len();
    let name_end = kw_end
        + line[kw_end..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$')))
            .unwrap_or(line.len() - kw_end);
    let ident = line[name_start..name_end].rsplit('.').next().unwrap_or("");
    let name = key_name(ident, keyword)?;
    let value = assigned_value(&trimmed[op.len()..], name)?;
    // `process.env.ADMIN_TOKEN = previous`, `flow.auditToken = token(1)`:
    // a member assigned an unquoted name or call is code.
    let vs = offset_in(line, value);
    let quoted = line[..vs].ends_with(['"', '\'', '`']);
    if !quoted
        && line[name_start..kw_pos].contains('.')
        && value.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '(' | ')' | '[' | ']'))
    {
        return None;
    }
    // `token: token`, `secret: client_secret`: the variable named after the
    // keyword. (`password: newPassword` is camelCase code, rejected by
    // `assigned_value`.) A value that merely contains the word stays a
    // candidate: `SuperSecretPassword2024`, `my-secret-value-Q9`.
    let name = value.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
    let name_lower = name.to_ascii_lowercase();
    // Also a name: a last segment that is the keyword (`'refresh-token'`,
    // `'aal2-token'`).
    let last_segment = name_lower.ends_with(keyword)
        && name_lower[..name_lower.len() - keyword.len()].ends_with(['-', '_']);
    if name_lower == *keyword
        || last_segment
        || (name_lower.ends_with(keyword)
            && name
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-'))
    {
        return None;
    }
    // Fixture and documentation values say what they are.
    if PLACEHOLDER_WORDS.iter().any(|w| name_lower.contains(w)) {
        return None;
    }
    if value.len() < 4 {
        return None;
    }
    // Check it's not a placeholder
    if PLACEHOLDER_VALUES
        .iter()
        .any(|p| value.starts_with(p) || value == *p)
    {
        return None;
    }
    // D-23: False positive filter
    if is_false_positive(value) {
        return None;
    }
    // Entropy check: reject low-entropy values (repeated chars, simple sequences)
    if shannon_entropy(value) < ENTROPY_THRESHOLD_PASSWORD {
        return None;
    }
    Some((value, op))
}

/// "accessToken" -> ["access", "Token"]; "Uint8Array" -> ["Uint8", "Array"];
/// "PQSecretBuffer" -> ["PQ", "Secret", "Buffer"] (a run of capitals is an
/// acronym up to the capital that starts the next word).
fn split_capitals(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    for (n, &(i, c)) in chars.iter().enumerate() {
        if i == start || !c.is_ascii_uppercase() {
            continue;
        }
        let prev_upper = chars[n - 1].1.is_ascii_uppercase();
        let next_lower = chars
            .get(n + 1)
            .is_some_and(|(_, d)| d.is_ascii_lowercase());
        if !prev_upper || next_lower {
            parts.push(&s[start..i]);
            start = i;
        }
    }
    if start < s.len() {
        parts.push(&s[start..]);
    }
    parts
}

/// A camelCase part that reads as a word: two or more lowercase letters and
/// fewer than four digits ("Uint8", "Array", "Int32" are words; the "kX9"
/// fragments of a random password and "Password2024" are not), or an
/// acronym of two or more capitals ("PQ", "URL").
fn word_like(part: &str) -> bool {
    let lower = part.chars().filter(|c| c.is_ascii_lowercase()).count();
    let digits = part.chars().filter(|c| c.is_ascii_digit()).count();
    (lower >= 2 && digits < 4) || (part.len() >= 2 && part.chars().all(|c| c.is_ascii_uppercase()))
}

/// A quoted value that is one capitalised word of letters only
/// ("Password", "Contraseña", "Şifre"): a label, not a password. A
/// lowercase word stays a candidate.
fn capitalised_word(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(char::is_uppercase)
        && chars.clone().next().is_some()
        && chars.all(|c| c.is_alphabetic() && c.is_lowercase())
}

/// A quoted value that is CamelCase words or a dotted type path, letters
/// only ("LookupValue", "fooBar", "SomeType.Member"): a name, not a password.
fn quoted_type_name(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_alphabetic() || c == '.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && camel_words(value)
}

/// A relative or absolute path: two or more `/`, every segment lowercase
/// letters, digits, `.`, `_` and `-` ("modules/credential/2025/file-name").
fn path_value(value: &str) -> bool {
    value.matches('/').count() >= 2
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && value.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/')
        })
        && value
            .split('/')
            .enumerate()
            .all(|(i, seg)| !seg.is_empty() || i == 0)
}

/// camelCase or a type like Uint8Array: split at `_`, `.` and each capital,
/// two or more parts, every part a word.
fn camel_words(value: &str) -> bool {
    let parts: Vec<&str> = value.split(['_', '.']).flat_map(split_capitals).collect();
    parts.len() >= 2 && parts.iter().all(|p| word_like(p))
}

/// Whether the bracket or pipe at `at` in an unquoted value makes it code:
/// what precedes it reads as a name (lowercase, snake_case or dotted, or
/// word-like CamelCase such as a type): `items[i].auth`, `parser.expect(`,
/// `Coin<SUI>`, `Optional[str]`, `a||b`. A value that starts with one is
/// code too. `Summer(2024)` (one capitalised word and digits in brackets)
/// stays a possible password, as does `Zk8#q(…`.
fn bracket_is_code(value: &str, at: usize) -> bool {
    // `format!(`, `opt?(`: a macro or optional call keeps its name.
    let name = value[..at].trim_end_matches(['!', '?']);
    if name.is_empty() {
        return true;
    }
    // A call or index with a name inside (`MakeThing(arg)`,
    // `Coerce(*items[key])`) is code whatever the name looks like; a
    // password with brackets holds digits or symbols there (`Summer(2024)`).
    let inner = &value[at + 1..];
    if value[at..].starts_with(['(', '[', '<'])
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && inner
            .trim_start_matches(['*', '&'])
            .starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
    {
        return true;
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return false;
    }
    // `summer(2024)!`: one lowercase word, then a year alone in the
    // brackets, or digits and a closing mark, is a password like
    // `Summer(2024)`; a call such as `range(10)` or `token(23456)` is not.
    if value[at..].starts_with('(') && name.chars().all(|c| c.is_ascii_lowercase()) {
        let tail = &value[at + 1..];
        let marked = tail.ends_with(['!', '?', '#', '*', '$', '%', '&']);
        let inner = tail
            .trim_end_matches(['!', '?', '#', '*', '$', '%', '&'])
            .trim_end_matches(')');
        if inner.chars().all(|c| c.is_ascii_digit())
            && (inner.len() == 4 || (marked && inner.len() >= 2))
        {
            return false;
        }
    }
    if name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') || name.contains(['_', '.']) {
        return true;
    }
    let parts = split_capitals(name);
    if !parts.iter().all(|p| word_like(p)) {
        return false;
    }
    // `Summer(2024)`: one word, then only digits inside the brackets.
    if parts.len() == 1 && value[at..].starts_with('(') {
        let inner = value[at + 1..]
            .trim_end_matches(['!', '?'])
            .trim_end_matches(')');
        if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Words that mark a quoted multi-word value as interface text ("Must be at
/// least 8 characters"), not a pass phrase.
const UI_TEXT_WORDS: &[&str] = &[
    "must",
    "least",
    "enter",
    "please",
    "character",
    "required",
    "invalid",
    "should",
    "match",
    "confirm",
    "forgot",
    "reset",
    "incorrect",
    "wrong",
    "your",
    "cannot",
];

/// A quoted value with spaces is a pass phrase when it is short (eight words
/// or fewer), carries a digit or a symbol beyond sentence punctuation, and
/// does not read as interface text. "This is my pass phrase 2024" is one;
/// "Enter your password" and "Must be at least 8 characters" are not.
fn quoted_phrase(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    if words.is_empty() || words.len() > 8 {
        return false;
    }
    let marked = value.chars().any(|c| {
        !(c.is_alphabetic() || c.is_whitespace() || matches!(c, '.' | ',' | '\'' | '!' | '?' | ':'))
    });
    let ui = words.iter().any(|w| {
        let w = w
            .trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        UI_TEXT_WORDS.iter().any(|u| w.starts_with(u))
    });
    marked && !ui
}

/// A quoted value that refers to a secret held elsewhere rather than being
/// one: shell and template interpolation (`${VAR}`, `$(cmd)`, `$VAR`,
/// `{{ var }}`), printf-style names (`%(name)s`) and `%VAR%`.
fn quoted_reference(value: &str) -> bool {
    value.starts_with("${")
        || value.starts_with("$(")
        || value.starts_with("{{")
        || value.starts_with("%(")
        || (value.starts_with('$')
            && value[1..].starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        || (value.len() > 2
            && value.starts_with('%')
            && value.ends_with('%')
            && value[1..value.len() - 1]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// A quoted value of four to eight plain words, none of them interface
/// text: `'correct horse battery staple'`. Assigned to a password name it
/// is a pass phrase even without digits or symbols.
fn word_passphrase(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    (4..=8).contains(&words.len())
        && words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_alphabetic()))
        && !words.iter().any(|w| {
            let w = w.to_ascii_lowercase();
            UI_TEXT_WORDS.iter().any(|u| w.starts_with(u))
        })
}

/// The one value a `password: …` style line assigns, or None when what
/// follows is prose, code or a reference rather than a literal secret:
/// "PASS: tracking quality 0.93", `token = parser.expect("token:")`,
/// `pass: ${DB_PASS}`, `token: event_kind`. `name.password` says the name
/// is a password or secret word (not a token or key): such a name makes a
/// few code-like shapes a password after all (`!MintyRidge42`,
/// `AutumnRiver42`); `name.bare` says it is a bare password name, which
/// alone may take a pass phrase (`'correct horse battery staple'`).
fn assigned_value(after_op: &str, name: KeyName) -> Option<&str> {
    let password_name = name.password;
    // `Token::Kind`: a scoped name, not an assignment.
    if after_op.starts_with(':') {
        return None;
    }
    let raw = after_op.trim_start();
    let first = raw.chars().next()?;
    let (value, rest, quote) = if first == '"' || first == '\'' || first == '`' {
        let inner = &raw[1..];
        let end = inner.find(first)?;
        (&inner[..end], &inner[end + 1..], Some(first))
    } else {
        let end = raw
            .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '}' | ']'))
            .unwrap_or(raw.len());
        // An escaped newline or tab: a config written inside a string
        // literal of code (`"key = value\nnext = …"`), as below.
        if ["\\n", "\\r", "\\t"].iter().any(|e| raw[..end].contains(e)) {
            return None;
        }
        let mut value = &raw[..end];
        // The closing quote of an enclosing string (`["DB_PASSWORD=x9Q"]`)
        // is not part of the value.
        if let Some(q) = value
            .strip_suffix(['"', '\'', '`'])
            .filter(|v| !v.contains(['"', '`']))
        {
            value = q;
        }
        (value, &raw[end..], None)
    };
    let quoted = quote.is_some();
    let value = value.trim().trim_end_matches(';');
    // `token: 'string' | number`: a TypeScript type, not a value. A quoted
    // value with digits or symbols before the `|` is still a password
    // (`password: 'Tr0ub4dor&3' | number`).
    if quoted
        && rest.trim_start().starts_with('|')
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '-' | '.' | ' '))
    {
        return None;
    }
    if !quoted {
        // An unquoted value followed by more words is a sentence.
        if rest
            .trim_start()
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric())
        {
            return None;
        }
        // One plain word starting a comma-separated list of words is prose
        // ("Never the secret: fingerprint, identity, reach").
        if value.chars().all(|c| c.is_ascii_lowercase())
            && rest.strip_prefix(',').is_some_and(|r| {
                r.starts_with(' ') && r.trim_start().starts_with(|c: char| c.is_alphabetic())
            })
        {
            return None;
        }
        // `!flag`, `?x`, `a?.b`, `a!.b`: negation and optional chaining.
        // Assigned to a password name, a leading `!` or `?` with digits
        // after it starts a password (`DB_PASSWORD=!MintyRidge42`).
        let leading_mark = value.starts_with(['!', '?'])
            && !(password_name && value[1..].chars().any(|c| c.is_ascii_digit()));
        if leading_mark || value.contains("?.") || value.contains("!.") {
            return None;
        }
        // Inside a string literal of code: `"…_authToken=x\").unwrap();`,
        // `format!("{}{}", …)`, `\"123456:ABC\"`, `"API_KEY=\nURL=\n"`.
        if value.starts_with('\\') || value.contains(['"', '`']) {
            return None;
        }
        // A regex literal: `const TOKEN = /^[0-9a-f]{64}$/;`
        if value.starts_with('/')
            && value[1..].contains(['^', '$', '[', ']', '\\', '(', ')', '{', '}', '*', '+'])
        {
            return None;
        }
        // A decimal or scientific number (`drift_before_pass: 1.5e-05`)
        // is a measurement. A run of digits alone may still be a PIN.
        if value.contains(['.', 'e', 'E'])
            && value.starts_with(|c: char| c.is_ascii_digit() || c == '-')
            && value.parse::<f64>().is_ok()
        {
            return None;
        }
    }
    // A trailing `!` or `?` on an unquoted name is TypeScript's non-null or
    // optional mark (`SessionTokenPayload!`); on anything else it is part of
    // the password (`Summer2024!`).
    let core = if quoted {
        value
    } else {
        value.trim_end_matches(['!', '?'])
    };
    // Unquoted, a name that reads as code is code: camelCase, a member
    // (a.b), snake_case, or a type. A plain word stays a possible password.
    if core.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && core
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        // camelCase or a type like Uint8Array: split at each capital, every
        // part reads as a word (2+ lowercase letters). A random password
        // (kX9mP2nQ7) breaks into one-letter fragments instead.
        // Assigned to a password name, a camel-looking value with digits
        // is a password (`DB_PASSWORD=AutumnRiver42`, `MyP4ssW0rd`) unless
        // a part before the last ends in digits, which names a sized type
        // (`ownerSecret: Uint8Array`).
        let sized_type = {
            let parts = split_capitals(core);
            parts.len() > 1
                && parts[..parts.len() - 1]
                    .iter()
                    .any(|p| p.ends_with(|c: char| c.is_ascii_digit()))
        };
        let camel = !quoted
            && camel_words(core)
            && !(password_name
                && core.chars().any(|c| c.is_ascii_digit())
                && !sized_type
                && !core.contains('.'));
        let all_alpha = core
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '.'));
        let typed = matches!(
            core.to_ascii_lowercase().as_str(),
            "string"
                | "str"
                | "number"
                | "int"
                | "bool"
                | "boolean"
                | "true"
                | "false"
                | "null"
                | "nil"
                | "none"
                | "undefined"
                | "any"
                | "object"
                | "self"
                | "this"
                | "bytes"
                | "address"
                | "required"
                | "optional"
        );
        let named = !quoted && all_alpha && core.contains(['_', '.']);
        let member = !quoted && core.contains('.');
        if camel || typed || named || member {
            return None;
        }
    }
    // Brackets and pipes are code only after a name (see bracket_is_code).
    if !quoted {
        if let Some(at) = value.find(['(', '[', '<', ')', ']', '>', '|']) {
            if bracket_is_code(value, at) {
                return None;
            }
        }
    }
    // Words with spaces are a pass phrase only under a bare password name
    // (`password`, `DB_PASSWORD`, `new_pass`); under `token`, `api_key`
    // or a key with more words (`viewPassword`) they are text.
    if value.chars().any(char::is_whitespace)
        && !(quoted && name.bare && (quoted_phrase(value) || word_passphrase(value)))
    {
        return None;
    }
    if value.contains("${") || value.contains("::") {
        return None;
    }
    // `obj->field`: a pointer member access (C, C++, PHP).
    if !quoted && value.contains("->") {
        return None;
    }
    if quoted {
        if quoted_reference(value) {
            return None;
        }
        // A label ("Password", "Contraseña"), a type or member name
        // ("LookupValue", "SomeType.Member"), or an excerpt cut short
        // ("abC1Def...") is not a password.
        if capitalised_word(value)
            || quoted_type_name(value)
            || value.ends_with("...")
            || value.ends_with('…')
        {
            return None;
        }
    } else if value.starts_with(['=', '>', '&', '.', '$', '{', '[', '<', '%', '@', '*']) {
        return None;
    }
    // `modules/credential/2025/file-name`, `/etc/keys/app.pem`: a path.
    if path_value(value) {
        return None;
    }
    // A plain snake_case or kebab-case name is an identifier, unquoted or in
    // backticks (code in prose). In quotes it may be a pass phrase, which
    // has four or more words ("correct-horse-battery-staple"); a shorter one
    // ("my-service-name", 'some_constant_name') is a name.
    if value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-' || c == '.')
        && value.contains(['_', '-', '.'])
    {
        let words = value
            .split(['_', '-', '.'])
            .filter(|w| w.len() >= 3)
            .count();
        if quote.is_none_or(|q| q == '`') || words < 4 {
            return None;
        }
    }
    Some(value)
}

fn check_ssn(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // SSN: NNN-NN-NNNN with SSA validation
    let bytes = line.as_bytes();
    if bytes.len() < 11 {
        return;
    }
    for i in 0..=bytes.len().saturating_sub(11) {
        // Check pattern: D D D - D D - D D D D
        if i + 10 < bytes.len()
            && bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3] == b'-'
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'-'
            && bytes[i + 7].is_ascii_digit()
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
            && bytes[i + 10].is_ascii_digit()
        {
            // Make sure it's not embedded in a longer number
            if i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'-') {
                continue;
            }
            if i + 11 < bytes.len() && (bytes[i + 11].is_ascii_digit() || bytes[i + 11] == b'-') {
                continue;
            }

            let area: u16 = (bytes[i] - b'0') as u16 * 100
                + (bytes[i + 1] - b'0') as u16 * 10
                + (bytes[i + 2] - b'0') as u16;
            let group: u8 = (bytes[i + 4] - b'0') * 10 + (bytes[i + 5] - b'0');
            let serial: u16 = (bytes[i + 7] - b'0') as u16 * 1000
                + (bytes[i + 8] - b'0') as u16 * 100
                + (bytes[i + 9] - b'0') as u16 * 10
                + (bytes[i + 10] - b'0') as u16;

            // SSA validation: area not 000, 666, or 900-999; group not 00; serial not 0000
            if area == 0 || area == 666 || area >= 900 {
                continue;
            }
            if group == 0 || serial == 0 {
                continue;
            }

            findings.push(ContentFinding {
                secret_type: ContentSecretType::SsnPattern,
                confidence: Confidence::ContextDependent,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("***-**-{serial:04}"),
                description: "Possible Social Security Number (SSA-valid format)",
            });
            return;
        }
    }
}

fn check_iban(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // IBAN: 2 uppercase letters + 2 digits + 4-30 alphanumeric
    for word in line.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric());
        if trimmed.len() < 8 || trimmed.len() > 34 {
            continue;
        }
        let bytes = trimmed.as_bytes();
        if bytes[0].is_ascii_uppercase()
            && bytes[1].is_ascii_uppercase()
            && bytes[2].is_ascii_digit()
            && bytes[3].is_ascii_digit()
            && bytes[4..].iter().all(|b| b.is_ascii_alphanumeric())
        {
            // Quick country code validation (common IBAN countries)
            let country = &trimmed[..2];
            let valid_countries = [
                "AL", "AD", "AT", "AZ", "BH", "BY", "BE", "BA", "BR", "BG", "CR", "HR", "CY", "CZ",
                "DK", "DO", "EG", "EE", "FI", "FR", "GE", "DE", "GI", "GR", "GT", "HU", "IS", "IQ",
                "IE", "IL", "IT", "JO", "KZ", "KW", "LV", "LB", "LI", "LT", "LU", "MT", "MR", "MU",
                "MD", "MC", "ME", "NL", "MK", "NO", "PK", "PS", "PL", "PT", "QA", "RO", "LC", "SM",
                "SA", "RS", "SC", "SK", "SI", "ES", "SE", "CH", "TL", "TN", "TR", "UA", "AE", "GB",
            ];
            if valid_countries.contains(&country) {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::IbanPattern,
                    confidence: Confidence::ContextDependent,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!(
                        "{}****{}",
                        &trimmed[..4],
                        &trimmed[trimmed.len() - 4..]
                    ),
                    description: "International Bank Account Number (IBAN)",
                });
                return;
            }
        }
    }
}

// ─── Tier 4: Sensitive Document Markings ──────────────────────────────────────

/// Check if a keyword on this line appears inside string literal quotes.
/// Catches pattern definitions like `("NOFORN", "NOFORN")` in source code,
/// preventing false positives when scanning gorse's own source or similar
/// rule-definition files.
fn keyword_in_string_literal(line: &str, keyword: &str) -> bool {
    // Case-insensitive search for the keyword
    let upper_line = line.to_uppercase();
    let upper_keyword = keyword.to_uppercase();
    if let Some(pos) = upper_line.find(&upper_keyword) {
        let before = &line[..pos];
        let after_start = pos + keyword.len();
        let after = if after_start <= line.len() {
            &line[after_start..]
        } else {
            ""
        };
        // Check if there's a quote character before AND after the keyword
        let has_open_quote = before.contains('"') || before.contains('\'');
        let has_close_quote = after.contains('"') || after.contains('\'');
        has_open_quote && has_close_quote
    } else {
        false
    }
}

fn check_sensitive_markings(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    let trimmed = line.trim();
    let upper = trimmed.to_uppercase();

    // Skip lines where markings appear inside string literals (code pattern definitions).
    // This prevents false positives when scanning source code that defines detection rules.
    // We check the whole line once — if ANY marking keyword is inside quotes, skip entirely.
    // Real classified documents don't wrap markings in programming quotes.
    let likely_code_definition = trimmed.contains('"')
        && (keyword_in_string_literal(line, "TOP SECRET")
            || keyword_in_string_literal(line, "SECRET")
            || keyword_in_string_literal(line, "CONFIDENTIAL")
            || keyword_in_string_literal(line, "NOFORN")
            || keyword_in_string_literal(line, "ORCON")
            || keyword_in_string_literal(line, "REL TO")
            || keyword_in_string_literal(line, "PROPRIETARY")
            || keyword_in_string_literal(line, "TRADE SECRET")
            || keyword_in_string_literal(line, "ITAR")
            || keyword_in_string_literal(line, "EXPORT CONTROLLED"));
    if likely_code_definition {
        return;
    }

    // 1. Classification banners — standalone lines
    //    "TOP SECRET", "TOP SECRET//SCI", "TOP SECRET//SCI//NOFORN", etc.
    if upper.starts_with("TOP SECRET") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET",
            },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (TOP SECRET level)".to_string(),
            description: "Government classification banner — TOP SECRET",
        });
        return;
    }

    // "SECRET//" with compartment markers (not bare "SECRET")
    if upper.starts_with("SECRET//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "SECRET" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (SECRET level)".to_string(),
            description: "Government classification banner — SECRET with controls",
        });
        return;
    }

    // Bare "SECRET" or "CONFIDENTIAL" — only if line is exactly that word
    if trimmed == "SECRET" || trimmed == "CONFIDENTIAL" {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: if trimmed == "SECRET" {
                    "SECRET"
                } else {
                    "CONFIDENTIAL"
                },
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: if trimmed == "SECRET" {
                "[MARKING] classification banner (SECRET level)".to_string()
            } else {
                "[MARKING] classification banner (CONFIDENTIAL level)".to_string()
            },
            description: "Government classification banner — standalone marking",
        });
        return;
    }

    // "CONFIDENTIAL" with decorator: "CONFIDENTIAL//", "CONFIDENTIAL –", "CONFIDENTIAL -"
    if upper.starts_with("CONFIDENTIAL//")
        || upper.starts_with("CONFIDENTIAL \u{2013}")
        || upper.starts_with("CONFIDENTIAL -")
    {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: "CONFIDENTIAL",
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (CONFIDENTIAL level)".to_string(),
            description: "Government classification banner — CONFIDENTIAL with controls",
        });
        return;
    }

    // CUI banners
    if trimmed == "CUI" || upper.starts_with("CUI//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "CUI" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] CUI designation".to_string(),
            description: "Controlled Unclassified Information (CUI) banner",
        });
        return;
    }

    // 2. Portion markings — at start of line
    if trimmed.starts_with("(TS)") || trimmed.starts_with("(TS//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(TS)" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (TS)".to_string(),
            description: "TOP SECRET portion marking",
        });
        return;
    }
    if trimmed.starts_with("(S)") || trimmed.starts_with("(S//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(S)" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (S)".to_string(),
            description: "SECRET portion marking",
        });
        return;
    }
    if trimmed.starts_with("(C)") && trimmed.len() > 3 {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(C)" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (C)".to_string(),
            description: "CONFIDENTIAL portion marking",
        });
        return;
    }
    if trimmed.starts_with("(CUI)") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(CUI)" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (CUI)".to_string(),
            description: "CUI portion marking",
        });
        return;
    }

    // 3. Dissemination controls — anywhere in line, case-insensitive
    for &(keyword, marking) in &[
        ("NOFORN", "NOFORN"),
        ("ORCON", "ORCON"),
        ("REL TO", "REL TO"),
        ("EXPORT CONTROLLED", "EXPORT CONTROLLED"),
    ] {
        if upper.contains(keyword) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::SensitiveMarking { marking },
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("[MARKING] dissemination control {}", marking),
                description: "Dissemination control marking",
            });
            return;
        }
    }

    // 4. Export control regulatory citations
    if upper.contains("22 CFR 12") || upper.contains("22 CFR 13") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "ITAR" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] ITAR export-control notice".to_string(),
            description: "ITAR export control regulatory citation (22 CFR)",
        });
        return;
    }
    if upper.contains("15 CFR 73") || upper.contains("15 CFR 74") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "EAR" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] EAR export-control notice".to_string(),
            description: "EAR export control regulatory citation (15 CFR)",
        });
        return;
    }

    // 5. Corporate sensitivity — case-insensitive multi-word phrases
    for &(phrase, marking) in &[
        ("PROPRIETARY INFORMATION", "PROPRIETARY"),
        ("TRADE SECRET", "TRADE SECRET"),
        ("INTERNAL USE ONLY", "INTERNAL USE ONLY"),
        ("NOT FOR DISTRIBUTION", "NOT FOR DISTRIBUTION"),
        ("NDA PROTECTED", "NDA PROTECTED"),
    ] {
        if upper.contains(phrase) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::SensitiveMarking { marking },
                confidence: Confidence::ContextDependent,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("[MARKING] corporate sensitivity label {}", marking),
                description: "Corporate sensitivity marking",
            });
            return;
        }
    }
}

// ─── Multi-Line Checks ───────────────────────────────────────────────────────

fn check_seed_phrase(lines: &[&str], findings: &mut Vec<ContentFinding>) {
    // Fixed: require purely alphabetic words with only spaces between them.
    // Words with attached punctuation (commas, periods, etc.) break the run,
    // preventing false positives on normal English prose where ~40% of common
    // words happen to match BIP-39 4-char prefixes.
    let mut all_words: Vec<(usize, &str)> = Vec::new(); // (line_number, word)

    for (line_idx, line) in lines.iter().enumerate() {
        for word in line.split_whitespace() {
            // Punctuation gate: word must be purely alphabetic.
            // Real seed phrases are clean space-separated words.
            if word.chars().all(|c| c.is_alphabetic()) && !word.is_empty() {
                all_words.push((line_idx + 1, word));
            } else {
                // Non-alpha token acts as a run-breaker sentinel
                all_words.push((line_idx + 1, ""));
            }
        }
    }

    // Check for runs of 12+ consecutive BIP-39 words
    let mut run_start = 0;
    let mut run_len = 0;

    for (i, (_line_num, word)) in all_words.iter().enumerate() {
        if !word.is_empty() && is_bip39_word(word) {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
        } else {
            if run_len >= 12 {
                emit_valid_seed(&all_words, run_start, run_len, findings);
            }
            run_len = 0;
        }
    }

    // Check trailing run
    if run_len >= 12 {
        emit_valid_seed(&all_words, run_start, run_len, findings);
    }
}

/// How many list words a run may hold beyond a phrase length and still have
/// every window offset tried (`seed <12 words> key`, `my seed <12 words>
/// keep it safe`). A longer run (a word list, a dictionary) is tried at its
/// start and end only: a 12-word checksum is 4 bits, so trying every window
/// of a long run of list words would find one by chance.
const SEED_WINDOW_SLACK: usize = 6;

/// A run of list words is a seed phrase only if a phrase-length stretch of
/// it carries a valid BIP-39 checksum: at any offset when the run is at
/// most `SEED_WINDOW_SLACK` words longer than the phrase, else at its start
/// or its end.
fn emit_valid_seed(
    all_words: &[(usize, &str)],
    run_start: usize,
    run_len: usize,
    findings: &mut Vec<ContentFinding>,
) {
    for size in [24, 21, 18, 15, 12] {
        if size > run_len {
            continue;
        }
        let last = run_start + run_len - size;
        let starts: Vec<usize> = if run_len - size <= SEED_WINDOW_SLACK {
            (run_start..=last).collect()
        } else {
            vec![run_start, last]
        };
        for start in starts {
            let words: Vec<&str> = all_words[start..start + size]
                .iter()
                .map(|(_, w)| *w)
                .collect();
            if bip39_checksum_ok(&words) {
                emit_seed_finding(all_words, start, size, findings);
                return;
            }
        }
    }
}

fn emit_seed_finding(
    all_words: &[(usize, &str)],
    run_start: usize,
    run_len: usize,
    findings: &mut Vec<ContentFinding>,
) {
    let start_line = all_words[run_start].0;
    let end_line = all_words[run_start + run_len - 1].0;
    let word_count = run_len;
    findings.push(ContentFinding {
        secret_type: ContentSecretType::SeedPhrase,
        confidence: Confidence::High,
        context: LineContext::Code,
        line_number: start_line,
        redacted_preview: format!(
            "BIP-39 seed phrase ({word_count} words, lines {start_line}-{end_line})"
        ),
        description: "BIP-39 mnemonic seed phrase — crypto wallet recovery key, \
                      grants full control of all funds",
    });
}

fn check_2fa_backup_codes(lines: &[&str], findings: &mut Vec<ContentFinding>) {
    // 5+ consecutive lines of 6-8 char alphanumeric codes
    let mut run_start = 0;
    let mut run_len = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Allow codes with optional dashes (e.g., "1234-5678")
        let clean: String = trimmed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let is_code = (6..=12).contains(&clean.len())
            && clean.chars().all(|c| c.is_ascii_alphanumeric())
            && !clean.chars().all(|c| c.is_alphabetic()); // Must have at least some digits

        if is_code {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
        } else {
            if run_len >= 5 {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::TwoFactorBackupCodes,
                    confidence: Confidence::ContextDependent,
                    context: LineContext::Code,
                    line_number: run_start + 1,
                    redacted_preview: format!(
                        "2FA backup codes ({run_len} codes, lines {}-{})",
                        run_start + 1,
                        run_start + run_len
                    ),
                    description:
                        "Two-factor authentication backup codes — can bypass 2FA protection",
                });
            }
            run_len = 0;
        }
    }

    // Check trailing run
    if run_len >= 5 {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::TwoFactorBackupCodes,
            confidence: Confidence::ContextDependent,
            context: LineContext::Code,
            line_number: run_start + 1,
            redacted_preview: format!(
                "2FA backup codes ({run_len} codes, lines {}-{})",
                run_start + 1,
                run_start + run_len
            ),
            description: "Two-factor authentication backup codes — can bypass 2FA protection",
        });
    }
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/// Shannon entropy of a byte string (bits per byte).
///
/// Real secrets have high entropy (3.5+ for hex, 4.0+ for alphanumeric).
/// Placeholders, repeated patterns, and sequential strings have low entropy.
/// Used to reduce false positives on password patterns and API key validation.
///
/// Returns entropy in bits per byte (0.0 to 8.0). Pure Rust, no deps.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            // Exact, so an imported rule's `entropy < 3.0` means what it
            // meant upstream (an approximation was off by up to 0.01 bits).
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Entropy thresholds for different secret types.
/// These were calibrated against known real keys vs. common false positives.
const ENTROPY_THRESHOLD_PASSWORD: f64 = 2.5; // "password123" = ~2.8, "aaaa" = 0.0
const ENTROPY_THRESHOLD_API_KEY: f64 = 3.0; // Real API keys are 3.5+
const ENTROPY_THRESHOLD_HEX_KEY: f64 = 3.0; // Real hex keys are 3.5+

// ─── D-23: False Positive Wordlist ──────────────────────────────────────────
//
// Programming keywords, function names, hex color codes, and common constants
// that structurally resemble secrets but are not. Used to filter out false
// positives from API key prefix matching, hex key detection, and password
// pattern matching.

/// Known false positive tokens that match secret patterns but are not secrets.
/// These are checked against the extracted token value (case-insensitive).
const FALSE_POSITIVE_WORDS: &[&str] = &[
    // Programming / crypto function names
    "sha256",
    "sha384",
    "sha512",
    "sha1",
    "md5",
    "hmac",
    "encrypt",
    "decrypt",
    "cipher",
    "hash",
    "digest",
    "base64",
    "base32",
    "hex2bin",
    "bin2hex",
    "buffer",
    "stream",
    "socket",
    "handle",
    "callback",
    "promise",
    "async",
    "await",
    "function",
    "method",
    "class",
    "struct",
    "interface",
    "abstract",
    "extends",
    "implements",
    // Common variable/constant names
    "undefined",
    "null",
    "none",
    "true",
    "false",
    "default",
    "config",
    "options",
    "settings",
    "localhost",
    "hostname",
    "username",
    "password",
    "timestamp",
    "datetime",
    "timeout",
    "interval",
    "encoding",
    "charset",
    "utf8",
    "ascii",
    "content_type",
    "content-type",
    "application/json",
    "authorization",
    "bearer",
    "basic",
    // Color codes and common hex constants
    "ffffff",
    "000000",
    "ff0000",
    "00ff00",
    "0000ff",
    "ffff00",
    "ff00ff",
    "00ffff",
    "c0c0c0",
    "808080",
    "deadbeef",
    "cafebabe",
    "feedface",
    "baadf00d",
    "abcdef",
    "0123456789abcdef",
    // Common test/fixture strings
    "lorem ipsum",
    "hello world",
    "foo bar",
    "the quick brown fox",
];

/// Check if a token is a known false positive.
fn is_false_positive(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    // Check exact matches and prefix matches
    for &fp in FALSE_POSITIVE_WORDS {
        if lower == fp || lower.starts_with(fp) && lower.len() < fp.len() + 8 {
            return true;
        }
    }
    // 6-char hex strings that look like CSS colors (#aabbcc)
    if token.len() == 6 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        // Low entropy hex = likely a color code, not a secret
        if shannon_entropy(token) < 2.0 {
            return true;
        }
    }
    false
}

// ─── D-24: URI-Embedded Credential Detection ────────────────────────────────

/// Whether `host` is `domain` or a dot-delimited subdomain of it
/// (`example.com`, `db.example.com`; not `notexample.com`).
fn host_is_or_under(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// A password that stands for one (`password`, `$PASS`, `<pw>`, `%s`).
fn placeholder_password(password: &str) -> bool {
    let lowered = password.to_ascii_lowercase();
    PLACEHOLDER_VALUES.iter().any(|p| password.starts_with(p))
        || matches!(
            lowered.as_str(),
            "pass" | "password" | "passwd" | "secret" | "pwd" | "token" | "test"
        )
        || password.starts_with(['$', '*', '<', '[', '{'])
        // `%VAR%` or `%s` is a placeholder; `%40…` is a URL-escaped
        // character starting a real password.
        || (password.starts_with('%') && !starts_with_url_escape(password))
        || password.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

/// Detect credentials embedded in URIs: https://user:password@host
fn check_uri_credentials(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // Look for ://user:pass@host patterns in any scheme
    let schemes = [
        "http://", "https://", "ftp://", "ftps://", "ssh://", "svn://", "git://", "ldap://",
        "ldaps://", "smb://",
    ];
    let lower = line.to_ascii_lowercase();
    for scheme in &schemes {
        // Every occurrence: a plain link first on the line does not hide a
        // URL with credentials after it.
        for (pos, _) in lower.match_indices(scheme) {
            // `https://` also contains no other scheme, but `ftps://` and
            // `ftp://` style overlaps, or a URL already reported, are skipped.
            if overlaps(cover, pos, pos + 1) {
                continue;
            }
            let after_scheme = &line[pos + scheme.len()..];
            // Look for user:pass@host pattern
            let Some(at_pos) = after_scheme.find('@') else {
                continue;
            };
            let userinfo = &after_scheme[..at_pos];
            // user:password sits right after the scheme: no path, no
            // spaces or quotes between (minified code has '@' far later).
            if userinfo.len() > 256
                || userinfo.contains(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '/' | '"' | '\'' | '`' | '<' | '>' | '?' | '#' | '{' | '}'
                        )
                })
            {
                continue;
            }
            let host: String = after_scheme[at_pos + 1..]
                .chars()
                .take_while(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':')
                })
                .collect::<String>()
                .to_ascii_lowercase();
            let host_len = host.len();
            let host_name = host.split(':').next().unwrap_or("");
            // Documentation hosts and stand-in names: the credentials are
            // examples.
            let example = host_name.is_empty()
                || matches!(host_name, "[" | "host" | "hostname")
                || ["example.com", "example.org", "example.net"]
                    .iter()
                    .any(|d| host_is_or_under(host_name, d))
                || host_name.ends_with(".example")
                || host_name.ends_with(".test")
                || host_name.ends_with(".invalid");
            // Local and internal hosts: real credentials, but for a service
            // only this machine or network reaches. Reported at lower
            // confidence, never dropped.
            let local = matches!(host_name, "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]")
                || host_name.starts_with("127.")
                || host_name.ends_with(".local")
                || host_name.ends_with(".localhost")
                || host_name.ends_with(".internal")
                || host_name.ends_with(".lan")
                || host_name.ends_with(".home.arpa");
            let Some(colon_pos) = userinfo.find(':') else {
                continue;
            };
            let password = &userinfo[colon_pos + 1..];
            // Must have a non-empty password that isn't a placeholder. A
            // short one is still a credential (and a weak one at that).
            if password.is_empty() || placeholder_password(password) || example {
                continue;
            }
            cover.push((pos, pos + scheme.len() + at_pos + 1 + host_len));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::DbConnectionString,
                confidence: if local {
                    Confidence::ContextDependent
                } else {
                    Confidence::High
                },
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("{scheme}****:****@****"),
                description: "URI with embedded credentials (user:password@host)",
            });
        }
    }
}

/// `curl -u user:password` / `--user user:password` / `--user=user:password`.
/// Betterleaks' `curl-auth-user` covers the same command but its character
/// classes stop at symbols such as `!` that real passwords hold.
fn check_curl_user(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    let Some(curl) = line.find("curl ") else {
        return;
    };
    if curl > 0 && line.as_bytes()[curl - 1].is_ascii_alphanumeric() {
        return;
    }
    let cmd = &line[curl..];
    for flag in [" -u ", " --user ", " --user="] {
        for (at, _) in cmd.match_indices(flag) {
            let rest = cmd[at + flag.len()..].trim_start();
            let (value, quoted) = match rest.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let inner = &rest[1..];
                    (&inner[..inner.find(q).unwrap_or(inner.len())], true)
                }
                _ => (
                    &rest[..rest.find(char::is_whitespace).unwrap_or(rest.len())],
                    false,
                ),
            };
            let Some((user, password)) = value.split_once(':') else {
                continue;
            };
            if user.is_empty()
                || user.starts_with('$')
                || password.len() < 4
                || placeholder_password(password)
                || (!quoted && password.contains(['(', ')', '`']))
                || shannon_entropy(password) < ENTROPY_THRESHOLD_PASSWORD
            {
                continue;
            }
            let vs = offset_in(line, value);
            if overlaps(cover, vs, vs + value.len()) {
                continue;
            }
            cover.push((vs, vs + value.len()));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::PasswordPattern,
                confidence: Confidence::High,
                context: LineContext::Code,
                line_number,
                redacted_preview: "curl -u ****:****".to_string(),
                description: "Password passed to curl on the command line (-u user:password)",
            });
        }
    }
}

/// Whether `s` starts with a URL escape: `%` and two hex digits.
fn starts_with_url_escape(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0] == b'%' && b[1].is_ascii_hexdigit() && b[2].is_ascii_hexdigit()
}

// ─── D-25: Webhook URL Detection ────────────────────────────────────────────

/// Webhook URL patterns — these URLs are secrets themselves because they allow
/// posting messages or triggering actions without additional authentication.
const WEBHOOK_PATTERNS: &[(&str, &str)] = &[
    ("hooks.slack.com/services/", "Slack Incoming Webhook"),
    ("hooks.slack.com/workflows/", "Slack Workflow Webhook"),
    ("discord.com/api/webhooks/", "Discord Webhook"),
    ("discordapp.com/api/webhooks/", "Discord Webhook"),
    ("outlook.office.com/webhook/", "Microsoft Teams Webhook"),
    (".webhook.office.com/", "Microsoft Teams Webhook"),
    ("hooks.zapier.com/hooks/", "Zapier Webhook"),
    ("maker.ifttt.com/trigger/", "IFTTT Webhook"),
    ("api.telegram.org/bot", "Telegram Bot Token"),
];

const WEBHOOK_DESCRIPTION: &str =
    "Webhook URL — allows posting messages or triggering actions without authentication";

fn check_webhook_urls(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    let lower = line.to_ascii_lowercase();
    for &(pattern, service) in WEBHOOK_PATTERNS {
        if let Some(pos) = lower.find(pattern) {
            // At most 20 bytes, cut on a character boundary.
            let preview = format!("{}****", safe_prefix(&line[pos..], 20));
            cover.push((pos, url_token_end(line, pos)));
            findings.push(ContentFinding {
                secret_type: ContentSecretType::ApiKey { service },
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: preview,
                description: WEBHOOK_DESCRIPTION,
            });
            return;
        }
    }
}

// ─── D-26: Azure Cloud Patterns ─────────────────────────────────────────────

fn check_azure_patterns(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
    cover: &mut Cover,
) {
    // Azure Storage connection strings
    if let (Some(start), Some(key)) = (
        line.find("DefaultEndpointsProtocol="),
        line.find("AccountKey="),
    ) {
        let end = line[key..]
            .find(|c: char| c.is_whitespace() || matches!(c, ';' | '"' | '\'' | '`'))
            .map_or(line.len(), |e| key + e);
        cover.push((start.min(key), end));
        findings.push(ContentFinding {
            secret_type: ContentSecretType::ApiKey {
                service: "Azure Storage",
            },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "DefaultEndpointsProtocol=...AccountKey=****".to_string(),
            description: "Azure Storage connection string with account key",
        });
        return;
    }

    // Azure SAS tokens
    if (line.contains("sig=") || line.contains("&sig="))
        && (line.contains("sv=") || line.contains("&sv="))
        && (line.contains("se=") || line.contains("&se="))
    {
        let sig = line.find("sig=").unwrap_or(0);
        cover.push((sig, url_token_end(line, sig)));
        findings.push(ContentFinding {
            secret_type: ContentSecretType::ApiKey {
                service: "Azure SAS Token",
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "?sv=...&sig=****".to_string(),
            description: "Azure Shared Access Signature (SAS) token",
        });
        return;
    }

    // Azure Function keys
    let lower = line.to_ascii_lowercase();
    if lower.contains("x-functions-key")
        || lower.contains("code=") && lower.contains(".azurewebsites.net")
    {
        if let Some(_) = line.find(|c: char| c == '=' || c == ':') {
            let after = line
                .split(|c: char| c == '=' || c == ':')
                .nth(1)
                .unwrap_or("");
            let value = after.trim().trim_matches('"').trim_matches('\'');
            if value.len() >= 20 && shannon_entropy(value) >= ENTROPY_THRESHOLD_API_KEY {
                cover.push((0, line.len()));
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::ApiKey {
                        service: "Azure Function Key",
                    },
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: "x-functions-key: ****".to_string(),
                    description: "Azure Function host or master key",
                });
            }
        }
    }
}

/// Luhn checksum validation for credit card numbers.
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;

    for ch in digits.chars().rev() {
        let d = match ch.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        let val = if double {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += val;
        double = !double;
    }

    sum % 10 == 0
}

/// Check if a string is valid base58 (Bitcoin alphabet).
fn is_base58(s: &str) -> bool {
    s.bytes().all(|b| BASE58_CHARS.contains(&b))
}

/// Check if a string is valid base64url encoding.
fn is_base64url(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

/// Check if a string looks like standard base64 (A-Za-z0-9+/= with optional whitespace).
fn is_likely_base64(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 20 {
        return false;
    }
    // Must have valid length (multiple of 4 after stripping whitespace)
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return false;
    }
    // All chars must be base64 alphabet
    clean
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Pure Rust base64 decoder. No external dependencies.
/// Returns None if input is not valid base64.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();

    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(clean.len() * 3 / 4);

    for chunk in clean.chunks(4) {
        let mut buf = [0u8; 4];
        let mut pad = 0u8;

        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                _ => return None,
            };
        }

        let combined =
            (buf[0] as u32) << 18 | (buf[1] as u32) << 12 | (buf[2] as u32) << 6 | buf[3] as u32;

        output.push((combined >> 16) as u8);
        if pad < 2 {
            output.push((combined >> 8) as u8);
        }
        if pad < 1 {
            output.push(combined as u8);
        }
    }

    Some(output)
}

// ─── D-28: UTF-16 / Unicode Escape Decoding ─────────────────────────────────
//
// Agents can obfuscate secrets using Unicode escape sequences:
//   \u0041 (JS/JSON), \x41 (hex byte), %41 (URL encoding)
// This decoder handles all three forms, then rescans the decoded string.

/// Scan a line for Unicode-obfuscated secrets. Extracts escape sequences,
/// decodes them, and scans the decoded content for secrets.
///
/// Returns findings with `[unicode]` prefix in the redacted preview.
pub fn check_unicode_obfuscated(line: &str, line_number: usize) -> Vec<ContentFinding> {
    // Quick check: does this line contain any escape sequences worth decoding?
    if !has_unicode_escapes(line) {
        return Vec::new();
    }

    let decoded = decode_unicode_escapes(line);

    // Only rescan if decoding actually changed something
    if decoded == line {
        return Vec::new();
    }

    // Must be valid printable text after decoding
    if decoded
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n')
    {
        return Vec::new();
    }

    let mut findings = check_line(&decoded, line_number);
    for finding in &mut findings {
        finding.context = LineContext::Base64Encoded; // reuse "encoded" context
        finding.redacted_preview = format!("[unicode] {}", finding.redacted_preview);
    }
    findings
}

/// Quick check whether a line contains Unicode escape sequences worth decoding.
fn has_unicode_escapes(line: &str) -> bool {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'u' if i + 5 < len => return true, // \uXXXX
                b'x' if i + 3 < len => return true, // \xHH
                _ => {}
            }
        } else if bytes[i] == b'%' && i + 2 < len {
            // %XX URL encoding — need at least 2 hex digits after
            if bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Decode Unicode escape sequences in a string.
///
/// Handles:
///   - `\uXXXX` — JavaScript/JSON Unicode escapes
///   - `\xHH`   — Hex byte escapes
///   - `%XX`    — URL percent-encoding
///
/// Literal characters pass through unchanged.
fn decode_unicode_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'u' if i + 5 < len => {
                    // \uXXXX
                    let hex = &input[i + 2..i + 6];
                    if hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                b'x' if i + 3 < len => {
                    // \xHH
                    let hex = &input[i + 2..i + 4];
                    if hex.len() == 2 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(byte_val) = u8::from_str_radix(hex, 16) {
                            result.push(byte_val as char);
                            i += 4;
                            continue;
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                _ => {
                    result.push('\\');
                    i += 1;
                }
            }
        } else if bytes[i] == b'%'
            && i + 2 < len
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // %XX URL encoding
            let hex = &input[i + 1..i + 3];
            if let Ok(byte_val) = u8::from_str_radix(hex, 16) {
                result.push(byte_val as char);
                i += 3;
                continue;
            }
            result.push('%');
            i += 1;
        } else {
            // Safe to push byte-by-byte for ASCII; for multi-byte UTF-8 we need char boundaries
            let ch = input[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }

    result
}

/// Decode UTF-16 LE or BE bytes to a UTF-8 String.
///
/// Detects BOM to determine byte order. Returns None if the bytes
/// don't start with a UTF-16 BOM or contain invalid code units.
pub fn decode_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let (is_le, start) = if bytes[0] == 0xFF && bytes[1] == 0xFE {
        (true, 2) // UTF-16 LE BOM
    } else if bytes[0] == 0xFE && bytes[1] == 0xFF {
        (false, 2) // UTF-16 BE BOM
    } else {
        return None; // No BOM — not UTF-16
    };

    let data = &bytes[start..];
    // Must have an even number of bytes
    if data.len() % 2 != 0 {
        return None;
    }

    let code_units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| {
            if is_le {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();

    String::from_utf16(&code_units).ok()
}

/// Check if a word is in the BIP-39 wordlist (using 4-char prefix binary search).
fn is_bip39_word(word: &str) -> bool {
    bip39_index(word).is_some()
}

/// The word's position in the BIP-39 list: the full word, or its four-letter
/// abbreviation (the first four letters identify each word).
fn bip39_index(word: &str) -> Option<usize> {
    let lower = word.to_ascii_lowercase();
    if !lower.is_ascii() || lower.len() < 3 {
        return None;
    }
    let key = &lower[..lower.len().min(4)];
    let i = BIP39_WORDS
        .binary_search_by(|w| w[..w.len().min(4)].cmp(key))
        .ok()?;
    let full = BIP39_WORDS[i];
    (lower == full || (lower.len() == 4 && full.starts_with(&lower))).then_some(i)
}

/// True when `words` (12, 15, 18, 21 or 24 of them) carry a valid BIP-39
/// checksum: the last bits are the start of SHA-256 of the rest. Ordinary
/// text that happens to use list words passes about 1 time in 16 to 256.
fn bip39_checksum_ok(words: &[&str]) -> bool {
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    let mut bits: Vec<bool> = Vec::with_capacity(n * 11);
    for w in words {
        let Some(i) = bip39_index(w) else {
            return false;
        };
        bits.extend((0..11).rev().map(|b| (i >> b) & 1 == 1));
    }
    let checksum_bits = n / 3;
    let entropy_bits = n * 11 - checksum_bits;
    let entropy: Vec<u8> = bits[..entropy_bits]
        .chunks(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
        .collect();
    let hash = crate::authority::psbt::sha256(&entropy);
    (0..checksum_bits).all(|k| ((hash[k / 8] >> (7 - k % 8)) & 1 == 1) == bits[entropy_bits + k])
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check `check_line` can run, without the letter-free fast path.
    fn check_line_all_checks(line: &str, n: usize) -> Vec<ContentFinding> {
        let mut f = Vec::new();
        let c = &mut Vec::new();
        check_pem_header(line, n, &mut f, c);
        check_aws_access_key(line, n, &mut f, c);
        check_api_key_prefixes(line, n, &mut f, c);
        check_google_service_account(line, n, &mut f, c);
        check_webhook_urls(line, n, &mut f, c);
        check_azure_patterns(line, n, &mut f, c);
        check_jwt_token(line, n, &mut f, c);
        check_credit_card(line, n, &mut f);
        check_db_connection_string(line, n, &mut f, c);
        check_wif_key(line, n, &mut f, c);
        check_eth_hex_key(line, n, &mut f, c);
        check_uri_credentials(line, n, &mut f, c);
        check_curl_user(line, n, &mut f, c);
        check_password_pattern(line, n, &mut f, c);
        check_ssn(line, n, &mut f);
        check_iban(line, n, &mut f);
        check_sensitive_markings(line, n, &mut f);
        f
    }

    #[test]
    fn letter_free_fast_path_matches_the_full_checks() {
        let lines = [
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "378282246310005",
            "123-45-6789",
            "card: 4111111111111111",
            "5111111111111111111111111111111111111111111111111111",
            "511111111111111111111111111111111111111111111111111",
            "-0.00001400000,0.00000,0.50000,1.32000,-0.00092",
            "2024-01-02 03:04:05,123,456.7,-8",
            "22 12 13 73 74 // -- ;; (()) [] {} 0 = : =>",
            "____________________________________________",
            "1234 5678 9012 3456 7890",
            "-9.9800E-7,0.00000,0.50000,1.28000,-0.00108",
            "1e10 2E-3 4111111111111111",
            "EE382200221020145685",
            "iban EE382200221020145685",
            "5eEeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "ee ee ee ee 123-45-6789",
        ];
        for line in lines {
            let fast = check_line(line, 7);
            let full = check_line_all_checks(line, 7);
            let summary = |v: &[ContentFinding]| {
                format!(
                    "{:?}",
                    v.iter()
                        .map(|f| (&f.secret_type, &f.redacted_preview))
                        .collect::<Vec<_>>()
                )
            };
            assert_eq!(summary(&fast), summary(&full), "line {line:?}");
        }
        assert_eq!(
            check_line("4111 1111 1111 1111", 1)[0].secret_type,
            ContentSecretType::CreditCard
        );
        assert_eq!(
            check_line("123-45-6789", 1)[0].secret_type,
            ContentSecretType::SsnPattern
        );
        assert_eq!(
            check_line("EE382200221020145685", 1)[0].secret_type,
            ContentSecretType::IbanPattern
        );
    }

    // ── Tier 1 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_pem_private_key() {
        let findings = check_line("-----BEGIN RSA PRIVATE KEY-----", 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, ContentSecretType::PemPrivateKey);
        assert_eq!(findings[0].confidence, Confidence::Definitive);
    }

    #[test]
    fn detect_ec_private_key() {
        let findings = check_line("-----BEGIN EC PRIVATE KEY-----", 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, ContentSecretType::PemPrivateKey);
    }

    #[test]
    fn no_detect_pem_public_key() {
        let findings = check_line("-----BEGIN PUBLIC KEY-----", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PemPrivateKey));
    }

    #[test]
    fn detect_aws_access_key() {
        let findings = check_line("aws_access_key = AKIAIOSFODNN7EXAMPLE", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::AwsAccessKey));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_github_pat() {
        // Use realistic mixed-char token (real PATs have high entropy)
        let token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8W9";
        let findings = check_line(token, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("GitHub"))));
    }

    #[test]
    fn detect_stripe_live_key() {
        let key = "sk_live_51TESTFIXTUREdoNotUseThisIsNotARealKey000000";
        let findings = check_line(key, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("Stripe"))));
    }

    #[test]
    fn detect_anthropic_key() {
        let key = "sk-ant-api03-Kx9mP2nQ7rW8sT3uV6wY1zA4bC5dE6fG7hI8jK9lM0nO1pQ";
        let findings = check_line(key, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("Anthropic"))));
    }

    #[test]
    fn no_detect_api_key_low_entropy_suffix() {
        // Repeated chars after prefix — likely a placeholder, not a real key
        let fake_key = format!("ghp_{}", "a".repeat(36));
        let findings = check_line(&fake_key, 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(f.secret_type, ContentSecretType::ApiKey { .. })),
            "Repeated-char API key suffix should be rejected by entropy check"
        );
    }

    #[test]
    fn detect_google_service_account() {
        let line = r#"{ "type": "service_account", "project_id": "test" }"#;
        let findings = check_line(line, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::GoogleServiceAccount));
    }

    // ── Tier 2 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";
        let findings = check_line(jwt, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::JwtToken));
    }

    fn has_card(line: &str) -> bool {
        check_line(line, 1)
            .iter()
            .any(|f| f.secret_type == ContentSecretType::CreditCard)
    }

    fn has_api_key(line: &str) -> bool {
        check_line(line, 1)
            .iter()
            .any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { .. }))
    }

    #[test]
    fn decimal_numbers_are_not_cards() {
        // The digits either side of the point pass Luhn as 4532015112830366.
        assert!(!has_card("  \"x\": 453.2015112830366,"));
        assert!(!has_card("4532015.112830366"));
        assert!(!has_card("-45.32015112830366"));
    }

    #[test]
    fn digits_spread_over_a_line_are_not_a_card() {
        assert!(!has_card("frame 4532 at 0151 12830 by 366"));
        assert!(!has_card("id_4532015112830366"));
    }

    #[test]
    fn grouped_card_among_other_numbers_is_found() {
        assert!(has_card("card 4532-0151-1283-0366 exp 12/27 cvv 123"));
        assert!(has_card("4532 0151 1283 0366"));
    }

    #[test]
    fn short_key_prefix_inside_a_word_or_path_is_not_a_key() {
        assert!(!has_api_key(
            "path = \"/data/c20_hands_pre_bind_take1_rehearsal_v7_final.json\""
        ));
        assert!(!has_api_key(
            "filter=store_original_frames_and_render_all_takes_v2"
        ));
        assert!(!has_api_key(
            "x = re_render_all_frames_for_the_cafe_scene_now"
        ));
        assert!(!has_api_key(
            "model = \"hf_internal/some-model-name-that-is-long\""
        ));
    }

    fn has_password(line: &str) -> bool {
        check_line(line, 1)
            .iter()
            .any(|f| f.secret_type == ContentSecretType::PasswordPattern)
    }

    #[test]
    fn password_rule_skips_prose_code_and_names() {
        assert!(!has_password(
            "PASS: tracking quality held above threshold on every take"
        ));
        assert!(!has_password("token = parser.expect(\"token:\").strip()"));
        assert!(!has_password("password: ${DB_PASSWORD}"));
        assert!(!has_password("next_token: event_kind_marker, other: x"));
        assert!(!has_password(
            "\"token\":\"Engine::PlayerController(Engine::World&)\""
        ));
    }

    #[test]
    fn password_rule_still_finds_literal_values() {
        // Synthetic values.
        assert!(has_password("password = \"Tr0ub4dor&3xQ\""));
        assert!(has_password("DB_PASSWORD=Zk8#qL2vR9wP"));
        assert!(has_password("api_token: \"q8Fz2LkP0vN7mX4c\""));
    }

    #[test]
    fn psw_counts_only_in_its_ordinary_spellings() {
        assert!(has_password("psw = \"Tr0ub4dor&3xQ\""));
        assert!(has_password("PSW=Zk8#qL2vR9wP"));
        assert!(has_password("Psw: \"q8Fz2LkP0vN7mX4c\""));
        // Three letters in binary data read as text are not a key.
        assert!(!has_password("\u{1}\u{7f}PSw=Zk8#qL2vR9wPx\u{3}"));
        assert!(!has_password("pSW=Zk8#qL2vR9wP"));
    }

    fn has_hex_key(line: &str) -> bool {
        check_line(line, 1)
            .iter()
            .any(|f| f.secret_type == ContentSecretType::EthHexKey)
    }

    #[test]
    fn checksums_are_not_wallet_keys() {
        let h = "9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5c9e1a3b7d4f8c2e6a0b5d9f1";
        assert!(!has_hex_key(&format!("\"must_match_key\": \"{h}\",")));
        assert!(!has_hex_key(&format!(
            "{h}  Content/Icons/Key_Handle.uasset"
        )));
        assert!(!has_hex_key(&format!("private_key_sha256 = \"{h}\"")));
        assert!(has_hex_key(&format!("PRIVATE_KEY={h}")));
        assert!(has_hex_key(&format!("wallet: {h}")));
    }

    fn has_uri_creds(line: &str) -> bool {
        check_line(line, 1)
            .iter()
            .any(|f| f.description.starts_with("URI with embedded"))
    }

    #[test]
    fn code_is_not_a_password() {
        assert!(!has_password(
            "let x = Foo.make({ token: token, key: newKey });"
        ));
        assert!(!has_password("  apiToken: SessionTokenPayload!"));
        assert!(!has_password(
            "const isPasswordValid = hasLength && hasDigits"
        ));
        assert!(!has_password("    token: Coin<SUI>,"));
        assert!(!has_password("  sessionToken: ctx.accessToken,"));
        assert!(!has_password("bypass: enabled9"));
        assert!(!has_password("password: string;"));
        // Still found (synthetic): a literal, a plain word in a config.
        assert!(has_password("dbPassword = \"Qz7!mK2#pL9v\""));
        assert!(has_password("password = mysecretvalue"));
    }

    #[test]
    fn hashes_and_slots_are_not_wallet_keys() {
        let h = "9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5c9e1a3b7d4f8c2e6a0b5d9f1";
        assert!(!has_hex_key(&format!(
            "bytes32 internal constant ROLE_HASH = 0x{h};"
        )));
        assert!(!has_hex_key(&format!(
            "bytes32 private constant IMPLEMENTATION_SLOT = 0x{h};"
        )));
        assert!(!has_hex_key(&format!("const TX_ID = '0x{h}';")));
        assert!(!has_hex_key(&format!("  expect(x).to.equal('0x{h}')")));
        assert!(has_hex_key(&format!("DEPLOYER_PRIVATE_KEY=0x{h}")));
        assert!(has_hex_key(&format!("0x{h}")));
    }

    #[test]
    fn local_example_and_minified_uris_are_not_credentials() {
        // Local hosts: still credentials, at lower confidence (see
        // `local_uri_credentials_are_found_at_lower_confidence`).
        let uri_confidence = |line: &str| {
            check_line(line, 1)
                .into_iter()
                .find(|f| f.description.starts_with("URI with embedded"))
                .map(|f| f.confidence)
        };
        assert_eq!(
            uri_confidence("RPC=http://bitcoin:Rt7pQ2xZ@127.0.0.1:18443/"),
            Some(Confidence::ContextDependent)
        );
        assert_eq!(
            uri_confidence("url = 'https://admin:Rt7pQ2xZ@localhost:5432/db'"),
            Some(Confidence::ContextDependent)
        );
        assert!(!has_uri_creds(
            "see https://user:password@db.internal.net/x"
        ));
        assert!(!has_uri_creds(
            "a=\"https://cdn.site.io/x.js\";b.on(c);d=e(\"user@x\")"
        ));
        assert!(has_uri_creds(
            "API_URL=https://app:Rt7pQ2xZ9@db.acme-internal.net:5432/app"
        ));
    }

    #[test]
    fn bip39_checksums_follow_the_published_vectors() {
        // Public BIP-39 test vectors (Trezor's list), not anyone's wallet.
        let a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let z = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let l = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        for good in [a, z, l] {
            assert!(
                bip39_checksum_ok(&good.split(' ').collect::<Vec<_>>()),
                "{good}"
            );
        }
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(!bip39_checksum_ok(&bad.split(' ').collect::<Vec<_>>()));
        assert_eq!(BIP39_WORDS.len(), 2048);
        assert_eq!(bip39_index("zoo"), Some(2047));
        assert_eq!(bip39_index("aban"), Some(0));
        assert_eq!(bip39_index("socket"), None);
    }

    #[test]
    fn list_words_without_a_checksum_are_not_a_seed_phrase() {
        let prose =
            vec!["test socket server client value table window answer about water action fruit"];
        assert!(check_multi_line(&prose)
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SeedPhrase));
        let vector =
            vec!["legal winner thank year wave sausage worth useful legal winner thank yellow"];
        assert!(check_multi_line(&vector)
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SeedPhrase));
    }

    #[test]
    fn typed_and_scoped_code_is_not_a_password() {
        assert!(!has_password(
            "enum Kind { AccessToken::Literal : public Base::Node; }"
        ));
        assert!(!has_password(
            "Token::Kind              : public Node::Base;"
        ));
        assert!(!has_password(
            "function f(accessToken: Uint8Array, s: X): Y;"
        ));
        assert!(!has_password("  token: 'string' | number;"));
        assert!(!has_password("  password: 'read-only' | 'admin';"));
        assert!(has_password("password: 'Tr0ub4dor&3' | number"));
        assert!(!has_password("  authToken: `${prefix}.${suffix}`,"));
        assert!(!has_password("  dataToken: dataLayer[\"x\"][\"Token\"];"));
        assert!(!has_password("  sessionToken: items[i].auth.sessionToken,"));
        assert!(!has_password(
            "password: `config_value` is read from the vault"
        ));
        // Still found (synthetic).
        assert!(has_password("API_PASSWORD=Summer2024x"));
        assert!(has_password(
            "token='9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5'"
        ));
        assert!(has_password("password: `Xk9#mP2vL7q`"));
    }

    // ── Audit regressions (2026-11-06): false negatives from FP tuning ──
    // Every value below is synthetic.

    #[test]
    fn screaming_case_run_on_password_names_are_found() {
        assert!(has_password("PGPASSWORD=hunter2xyz9Q"));
        assert!(has_password("MYSQLPASSWORD=Zk8#qL2vR9wP"));
        assert!(has_password("DBPASSWORD=Zk8#qL2vR9wP"));
        // Still not: a lowercase word that merely contains the keyword.
        assert!(!has_password("bypass: enabled9"));
        assert!(!has_password("compass = north9x"));
    }

    #[test]
    fn unquoted_bang_question_and_bracket_values_are_passwords() {
        assert!(has_password("DB_PASSWORD=Summer2024!"));
        assert!(has_password("DB_PASSWORD=Summer2024?"));
        assert!(has_password("DB_PASSWORD=Zk8#qL2vR9wP!"));
        assert!(has_password("DB_PASSWORD=Summer(2024)"));
        // Code after a name stays code.
        assert!(!has_password("  sessionToken: items[i].auth.sessionToken,"));
        assert!(!has_password("token = parser.expect(\"token:\").strip()"));
        assert!(!has_password("    token: Coin<SUI>,"));
        assert!(!has_password("  password: Optional[str]"));
        assert!(!has_password("  apiToken: SessionTokenPayload!"));
        assert!(!has_password("  token: user?.session"));
        // Code inside string literals, regex literals and stand-in values.
        assert!(!has_password("const TOKEN = /^[0-9a-f]{64}$/;"));
        assert!(!has_password(
            "    fs::write(p, \"//registry/:_authToken=x\").unwrap();"
        ));
        assert!(!has_password("let aws_secret = format!(\"{}{}\", a, b);"));
        assert!(!has_password(
            "STRIPE_SECRET_KEY = 'sk_test_not_a_real_key'"
        ));
        assert!(!has_password("  token: 'synthetic-recipient-secret',"));
        assert!(!has_password("session = { access_token: 'aal2-token' }"));
        // The closing quote of an enclosing string is not part of the value.
        assert!(has_password("  \"env\": [\"DB_PASSWORD=Zk8#qL2vR9wP\"],"));
    }

    #[test]
    fn value_containing_the_keyword_is_still_a_password() {
        assert!(has_password("PASSWORD=SuperSecretPassword2024"));
        assert!(has_password("secret=my-secret-value-Q9"));
        assert!(has_password("API_TOKEN=abc-token-Q9x7"));
        // The variable named after the keyword is not.
        assert!(!has_password("let x = Foo.make({ token: token });"));
        assert!(!has_password("  password: newPassword,"));
        assert!(!has_password("  secret: client_secret,"));
    }

    #[test]
    fn quoted_phrases_kebab_values_and_punctuation_starts_are_passwords() {
        assert!(has_password("password = \"This is my pass phrase 2024\""));
        assert!(has_password(
            "DB_PASSWORD = \"correct-horse-battery-staple\""
        ));
        assert!(has_password("WIFI_PASSWORD = \"!Tr0ub4dor&3xQ\""));
        // Interpolations and interface text are not.
        assert!(!has_password("DB_PASSWORD = \"${VAULT_DB_PASSWORD}\""));
        assert!(!has_password("DB_PASSWORD = \"$(pass show db)\""));
        assert!(!has_password("password: \"Must be at least 8 characters\""));
        assert!(!has_password("password: \"Enter your password\""));
        assert!(!has_password(
            "password: `config_value` is read from the vault"
        ));
    }

    #[test]
    fn non_ascii_case_mapping_never_shifts_offsets() {
        // Kelvin sign and Angstrom sign lowercase to ASCII letters of a
        // different byte length under full Unicode lowercasing; dotted
        // capital I lowercases to two characters.
        let lines = [
            "\u{212A} password = \"Tr0ub4dor&3xQ\"",
            "\u{0130} password = \"Tr0ub4dor&3xQ\"",
        ];
        for l in lines {
            assert!(has_password(l), "{l:?}");
        }
        assert!(has_uri_creds(
            "\u{212B}\u{e9}https://admin:Rt7pQ2xZ9@db.acme-internal.net/x"
        ));
        // Webhook previews cut on a character boundary.
        let _ = check_line("hooks.slack.com/services/\u{e9}\u{e9}\u{e9}\u{e9}", 1);
    }

    #[test]
    fn url_query_separators_end_a_key() {
        let key = format!("AIza{}", "SyQ7xR2mK9pL4vN8cT3wZ6yB1hD5fJ0gS2u");
        assert!(has_api_key(&format!(
            "src=\"https://maps.googleapis.com/maps/api/js?key={key}&callback=initMap\""
        )));
        assert!(has_api_key(&format!("https://x.example/?key={key}#top")));
    }

    #[test]
    fn hex_key_name_decides_before_hash_words() {
        let h = "9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5c9e1a3b7d4f8c2e6a0b5d9f1";
        assert!(has_hex_key(&format!("ROOT_PRIVATE_KEY=0x{h}")));
        assert!(has_hex_key(&format!("PRIVATE_KEY=0x{h} # do not commit")));
        assert!(has_hex_key(&format!("ROOT_PRIVATE_KEY={h}")));
        assert!(!has_hex_key(&format!(
            "bytes32 internal constant ROLE_HASH = 0x{h};"
        )));
        assert!(!has_hex_key(&format!(
            "bytes32 private constant IMPLEMENTATION_SLOT = 0x{h};"
        )));
        assert!(!has_hex_key(&format!("PRIVATE_KEY_HASH=0x{h}")));
        // Every 0x on the line is examined, not only the first.
        assert!(has_hex_key(&format!(
            "deploy(0x0, 1); DEPLOYER_PRIVATE_KEY=0x{h}"
        )));
        assert!(has_hex_key(&format!(
            "ROLE_HASH=0x{h}; PRIVATE_KEY=0x{}",
            format!("{}7", &h[1..])
        )));
    }

    #[test]
    fn comma_separated_fields_can_hold_a_card() {
        assert!(has_card("john,4532015112830366,1225,123"));
        assert!(has_card("4532015112830366,12/25,123"));
        assert!(!has_card("453.2015112830366"));
    }

    #[test]
    fn url_escaped_password_start_is_not_a_placeholder() {
        assert!(has_uri_creds(
            "https://user:%40ssw0rdX9@db.acme-internal.net/db"
        ));
        assert!(!has_uri_creds(
            "https://user:%PASSWORD%@db.acme-internal.net/db"
        ));
    }

    #[test]
    fn imported_rules_run_beside_gorse_findings_and_report_a_key_once() {
        let pk = format!(
            "{}_{}_{}",
            "pk", "live", "51N9xR2mK9pL4vN8cT3wZ6yB1hD5fJ0gS"
        );
        let h = "9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5c9e1a3b7d4f8c2e6a0b5d9f1";
        let dop = format!("{}_{}_{h}", "dop", "v1");
        let line = format!("{{\"stripePublishableKey\":\"{pk}\",\"digitalOceanToken\":\"{dop}\"}}");
        let f = check_line(&line, 1);
        assert!(
            f.iter().any(|x| x.redacted_preview.starts_with("pk_l")),
            "{f:?}"
        );
        assert!(
            f.iter().any(|x| x.redacted_preview.starts_with("dop_")),
            "{f:?}"
        );

        let ghp = format!("{}{}", "ghp_", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7Ka");
        let f = check_line(&format!("token={ghp}"), 1);
        let n = f
            .iter()
            .filter(|x| x.redacted_preview.starts_with("ghp_"))
            .count();
        assert_eq!(n, 1, "{f:?}");
        // A webhook Gorse names is not listed again by an imported rule.
        let hook = format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            "Q7XR2MK9P", "L4VN8CT3W", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5"
        );
        assert_eq!(check_line(&hook, 1).len(), 1, "{:?}", check_line(&hook, 1));
        // The generic password rule still stays quiet next to a named key.
        assert!(f
            .iter()
            .all(|x| x.secret_type != ContentSecretType::PasswordPattern));
    }

    #[test]
    fn calls_pointer_members_and_short_quoted_names_are_code() {
        assert!(!has_password(
            "  BlendState = MakeBlendState(src0_a(BlendState) + 1));"
        ));
        assert!(!has_password(
            "  FToken OutToken = FToken(*TokenMap[TokenIndex]);"
        ));
        assert!(!has_password("  session_token = session->token;"));
        assert!(!has_password("  token_header_name=\"my-service-name\""));
        assert!(!has_password("  SECRET_TOKEN_NAME = 'some_constant_name'"));
        // Still found (synthetic).
        assert!(has_password("DB_PASSWORD=Summer(2024)"));
        assert!(has_password(
            "DB_PASSWORD = \"correct-horse-battery-staple\""
        ));
    }

    // ── Audit regressions (2026-11-06, third and fourth audits) ──
    // Every value below is synthetic or a published test vector.

    const HEX64: &str = "9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8a6b0d2f5c9e1a3b7d4f8c2e6a0b5d9f1";

    #[test]
    fn eth_keys_in_common_shapes_are_found() {
        let h = HEX64;
        for line in [
            format!("    accounts: [\"0x{h}\"],"),
            format!("ADMIN_KEY=0x{h}"),
            format!("OPERATOR_KEY=0x{h}"),
            format!("KEY=0x{h}"),
            format!("const key = '0x{h}';"),
            format!("{{\"key\":\"0x{h}\"}}"),
            format!("0x{h}  // my main account"),
            format!("DEPLOYER_PK=0x{h}"),
            format!("DEPLOYER_PK={h}"),
            format!("signer: '0x{h}'"),
        ] {
            assert!(has_hex_key(&line), "{line}");
        }
        for line in [
            format!("ROLE_HASH=0x{h}"),
            format!("IMPLEMENTATION_SLOT = 0x{h}"),
            format!("private_key_sha256 = \"{h}\""),
            format!("bytes32 private immutable DOMAIN_SEPARATOR = 0x{h};"),
            format!("\"must_match_key\": \"{h}\","),
            format!("publicKey: '0x{h}'"),
            format!("0x{h}  // tx hash"),
        ] {
            assert!(!has_hex_key(&line), "{line}");
        }
    }

    #[test]
    fn bare_hex_runs_pass_the_false_positive_filter() {
        // Both loops apply the same filters, so a value is judged the same
        // with or without 0x.
        for v in [HEX64, &"0123456789abcdef".repeat(4), &"ab".repeat(32)] {
            assert_eq!(
                has_hex_key(&format!("PRIVATE_KEY=0x{v}")),
                has_hex_key(&format!("PRIVATE_KEY={v}")),
                "{v}"
            );
        }
        assert!(!has_hex_key(&format!("PRIVATE_KEY={}", "ab".repeat(32))));
    }

    #[test]
    fn seed_phrase_is_found_at_any_offset_of_a_short_run() {
        // Published BIP-39 test vector between other list words.
        let v = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        for text in [
            format!("seed {v} key"),
            format!("my seed {v} keep it safe"),
            format!("wallet seed {v} key word"),
        ] {
            assert!(
                check_multi_line(&[text.as_str()])
                    .iter()
                    .any(|f| f.secret_type == ContentSecretType::SeedPhrase),
                "{text}"
            );
        }
    }

    #[test]
    fn same_service_second_key_on_a_line_is_reported() {
        let g1 = format!("{}{}", "ghp_", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7Ka");
        let g2 = format!("{}{}", "ghp_", "Pm4Kd8Rt2Vx6Bn1Qw9Lz3Hc7Fj5Ys0Ag2Te8Nu");
        let count = |line: &str, head: &str| {
            check_line(line, 1)
                .iter()
                .filter(|f| f.redacted_preview.starts_with(head))
                .count()
        };
        assert_eq!(
            count(&format!("{{\"a\":\"{g1}\",\"b\":\"{g2}\"}}"), "ghp_"),
            2
        );
        assert_eq!(count(&format!("token={g1}"), "ghp_"), 1);
        let n1 = format!("{}{}", "npm_", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7");
        let n2 = format!("{}{}", "npm_", "Pm4Kd8Rt2Vx6Bn1Qw9Lz3Hc7Fj5Ys0Ag2Te8");
        assert_eq!(
            count(
                &format!("//registry.npmjs.org/:_authToken={n1} //npm.acme-internal.net/:_authToken={n2}"),
                "npm_"
            ),
            2
        );
        let hook = format!(
            "https://hooks.slack.com/services/T00000000/B00000000/{}",
            "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5"
        );
        let line = format!(
            "{{\"proxy\":\"https://user:Tr0ub4dor3xQ9@proxy.acme-internal.net:8443\",\"slack\":\"{hook}\"}}"
        );
        let f = check_line(&line, 1);
        assert!(
            f.iter()
                .any(|x| x.description.starts_with("URI with embedded")),
            "{f:?}"
        );
        assert!(
            f.iter().any(|x| x.description == WEBHOOK_DESCRIPTION),
            "{f:?}"
        );
        assert_eq!(f.len(), 2, "{f:?}");
        // A key inside a credential URL is still named by its service.
        let f = check_line(
            &format!("git clone https://x-access-token:{g1}@github.com/org/repo.git"),
            1,
        );
        assert!(
            f.iter().any(|x| x.redacted_preview.starts_with("ghp_")),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|x| x.description.starts_with("URI with embedded")),
            "{f:?}"
        );
    }

    #[test]
    fn public_identifier_does_not_hide_a_password() {
        assert!(has_password(
            "{\"twilio_sid\":\"AC0123456789abcdef0123456789abcdef\",\"db_password\":\"Tr0ub4dor&3xQ9!\"}"
        ));
        let pk = format!(
            "{}_{}_{}",
            "pk", "live", "51N9xR2mK9pL4vN8cT3wZ6yB1hD5fJ0gS"
        );
        assert!(has_password(&format!(
            "STRIPE_PK={pk}; DB_PASSWORD=Zk8#qL2vR9wP"
        )));
        // The key's own value is still not reported twice.
        let ghp = format!("{}{}", "ghp_", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7Ka");
        assert!(!has_password(&format!("GITHUB_TOKEN={ghp}")));
    }

    #[test]
    fn every_keyword_and_scheme_occurrence_is_checked() {
        assert!(has_password(
            "{\"auth_mode\": \"pass_through\", \"pass\": \"Tr0ub4dor&3xQ9!\"}"
        ));
        assert!(has_password("bypass_check = 1; pass = \"Tr0ub4dor&3xQ9!\""));
        assert!(has_password("{\"password\": \"Tr0ub4dor&3xQ9!\"}"));
        assert!(has_uri_creds(
            "{\"docs\": \"https://acme.dev/docs\", \"feed\": \"https://admin:Tr0ub4dor3xQ9@feed.acme-internal.net/v1\"}"
        ));
        let db = |line: &str| {
            check_line(line, 1)
                .iter()
                .any(|f| f.description.starts_with("Database connection string"))
        };
        assert!(db(
            "a=postgres://localhost/app b=postgres://app:Rt7pQ2xZ9@db.acme-internal.net/app"
        ));
        assert!(!db("a=postgres://localhost/app contact ops@acme.dev"));
    }

    #[test]
    fn short_prefix_key_with_a_random_part_and_separator_is_found() {
        let line = "DATABRICKS_TOKEN=dapi9f2c4e1a7b3d8f60c5e2a9b1d4f7c3e8-2";
        let (mut f, mut c) = (Vec::new(), Vec::new());
        check_api_key_prefixes(line, 1, &mut f, &mut c);
        assert!(
            f.iter().any(|x| x.secret_type
                == ContentSecretType::ApiKey {
                    service: "Databricks API Token"
                }),
            "{f:?}"
        );
        // snake_case names with digits stay names.
        let (mut f, mut c) = (Vec::new(), Vec::new());
        check_api_key_prefixes(
            "x = co_occurrence_matrix_2d_cache_final_v2",
            1,
            &mut f,
            &mut c,
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn lowercase_word_with_a_year_in_brackets_is_a_password() {
        assert!(has_password("PASSWORD=summer(2024)!"));
        assert!(has_password("PASSWORD=Summer(2024)!"));
        assert!(!has_password("token = range(10)"));
        assert!(!has_password("flow.sourceProcessAuditToken = token(23456)"));
        assert!(!has_password("password = hash(value)"));
    }

    #[test]
    fn curl_user_password_with_symbols_is_found() {
        assert!(has_password(
            "curl -H \"X-Env:test\" https://api.acme-internal.net/v1 -u admin:MyRealProdS9!"
        ));
        assert!(has_password(
            "curl --user=admin:Tr0ub4dor3xQ9 https://192.0.2.10"
        ));
        assert!(!has_password("curl -u admin:password https://192.0.2.10"));
        assert!(!has_password("curl -u \"$USER:$PASS\" https://192.0.2.10"));
        assert!(!has_password("curl -u admin https://192.0.2.10"));
    }

    #[test]
    fn password_names_accept_passphrases_marks_and_digit_camel_values() {
        assert!(has_password("PASSWORD='correct horse battery staple'"));
        assert!(has_password("DB_PASSWORD=!MintyRidge42"));
        assert!(has_password("DB_PASSWORD=?Mige42"));
        assert!(has_password("DB_PASSWORD=AutumnRiver42"));
        // Still code: negation, camelCase without digits, token names,
        // interface text.
        assert!(!has_password("  password: !isValid,"));
        assert!(!has_password("  password: newPassword,"));
        assert!(!has_password("  accessToken: userSession2,"));
        assert!(!has_password("password: 'please enter it here'"));
        assert!(!has_password("password = 'see the docs'"));
        // Code and prose that only reached the check once every keyword
        // occurrence was examined.
        assert!(!has_password(
            "if (p === undefined) delete process.env.ADMIN_TOKEN; else process.env.ADMIN_TOKEN = previous"
        ));
        assert!(!has_password(
            "| Output | The secret, redacted | Never the secret: fingerprint, identity, reach |"
        ));
        assert!(!has_password(
            "\"[foo]\\naws_access_key_id = AKIAFOO\\naws_secret_access_key = other\\n\","
        ));
        assert!(has_password("password = mysecretvalue"));
    }

    #[test]
    fn key_words_that_describe_a_password_field_are_not_passwords() {
        // Interface and meta words beside the keyword: the key describes a
        // password field, it does not hold one.
        assert!(!has_password("\"resetPassword\": \"Tr0ub4dor&3xQ\""));
        assert!(!has_password("\"enterPassword\": \"Tr0ub4dor&3xQ\""));
        assert!(!has_password("\"wrong_password\": \"Tr0ub4dor&3xQ\""));
        assert!(!has_password("\"label_pass\": \"Tr0ub4dor&3xQ\""));
        assert!(!has_password("has_password = \"Tr0ub4dor&3xQ\""));
        assert!(!has_password("\"user_token\": \"q8Fz2LkP0vN7mX4c\""));
        assert!(!has_password("self.password_hash = \"q8Fz2LkP0vN7mX4c\""));
        assert!(!has_password("\"viewPassword\": \"Enter it to view 2024\""));
        // Kept: a bare name, a keep-word prefix, a member, a run-on name
        // and a word that says nothing about the field.
        assert!(has_password("\"db_password\": \"Tr0ub4dor&3xQ\""));
        assert!(has_password("\"adminPassword\": \"Tr0ub4dor&3xQ\""));
        assert!(has_password("PGPASSWORD=hunter2xyz9Q"));
        assert!(has_password("user.password = \"Tr0ub4dor&3xQ\""));
        assert!(has_password("\"wifi_pass\": \"Tr0ub4dor&3xQ\""));
        assert_eq!(key_words("passwordLabel", "password"), ["label"]);
        assert_eq!(key_words("DBPASSWORD", "password"), ["db"]);
        assert_eq!(key_words("api_key", "api_key"), ["api", "key"]);
        assert!(key_words("$password", "password").is_empty());
    }

    #[test]
    fn quoted_labels_type_names_and_paths_are_not_passwords() {
        // One capitalised word is a label (translation files); a lowercase
        // word stays a candidate.
        assert!(!has_password("\"password\": \"Contraseña\""));
        assert!(!has_password("\"password\": \"Şifre\""));
        assert!(!has_password("\"password\": \"Password\""));
        assert!(has_password("\"password\": \"mysecretvalue\""));
        // CamelCase words and dotted type paths are names.
        assert!(!has_password(
            "\"secret_token\": \"SomeTypeName.LookupValue\""
        ));
        assert!(!has_password("\"token\": \"ClassName.Value\""));
        assert!(!has_password("\"pass\": \"CamelCaseWordsWithoutDigits\""));
        assert!(!has_password("\"token\": \"PQSecretBuffer\""));
        assert!(!has_password("\"secret\": \"fooBarBaz\""));
        assert!(has_password("\"pass\": \"CamelCaseWords2024\""));
        assert!(has_password("\"pass\": \"iLoveMyDog9\""));
        // Relative and absolute paths.
        assert!(!has_password(
            "\"something_private_key\": \"modules/credential/path/20250101/file-name\""
        ));
        assert!(!has_password("private_key: /etc/keys/app.pem"));
        assert!(has_password("\"password\": \"ab/cd9Q!xy\""));
    }

    #[test]
    fn sentences_need_a_bare_password_name() {
        assert!(has_password("password = \"This is my pass phrase 2024\""));
        assert!(has_password(
            "DB_PASSWORD = \"This is my pass phrase 2024\""
        ));
        assert!(has_password("PASSWORD='correct horse battery staple'"));
        assert!(has_password("PGPASSWORD='correct horse battery staple'"));
        assert!(has_password("new_pass: 'correct horse battery staple'"));
        // Not bare: a describing word, an unknown prefix, a token or key.
        assert!(!has_password("\"viewPassword\": \"Open the vault 2024\""));
        assert!(!has_password("\"hint_password\": \"Use the vault 2024\""));
        assert!(!has_password(
            "\"wrongPassword\": \"That one is wrong 2024\""
        ));
        assert!(!has_password("\"weak_pass\": \"Four plain words here\""));
        assert!(!has_password("\"token\": \"Some words with 2024\""));
        assert!(!has_password("\"api_key\": \"Your key words 9\""));
        assert!(!has_password(
            "secret_token: 'correct horse battery staple'"
        ));
    }

    #[test]
    fn numbers_sized_types_acronym_names_and_cut_excerpts_are_not_passwords() {
        assert!(!has_password("\"drift_cm_before_pass\": 1.5e-05,"));
        assert!(!has_password("\"before_pass\": 0.9312,"));
        assert!(!has_password("ownerSecret: Uint8Array;"));
        assert!(!has_password("'pq-secret': PQSecretBuffer,"));
        assert!(!has_password("\"purchaseToken\": \"abC1DefgH2ijKlm...\""));
        assert!(!has_password("\"token\": \"abC1DefgH2ijKlm…\""));
        // Still passwords: digit camel values under a password name, a
        // bare run of digits.
        assert!(has_password("DB_PASSWORD=AutumnRiver42"));
        assert!(has_password("DB_PASSWORD=MyP4ssW0rd"));
        assert!(has_password("PASSWORD=SuperSecretPassword2024"));
        assert_eq!(split_capitals("PQSecretBuffer"), ["PQ", "Secret", "Buffer"]);
        assert_eq!(split_capitals("URLToken"), ["URL", "Token"]);
        assert_eq!(split_capitals("Uint8Array"), ["Uint8", "Array"]);
        assert_eq!(split_capitals("kX9mP2nQ7"), ["k", "X9m", "P2n", "Q7"]);
    }

    #[test]
    fn uuid_values_are_kept_at_lower_confidence() {
        let conf = |line: &str| {
            check_line(line, 1)
                .into_iter()
                .find(|f| f.secret_type == ContentSecretType::PasswordPattern)
                .map(|f| f.confidence)
        };
        assert_eq!(
            conf("\"token\": \"a4b1cd23-1234-4a5b-8c9d-0e1f23456789\""),
            Some(Confidence::Heuristic)
        );
        assert_eq!(
            conf("\"token\": \"q8Fz2LkP0vN7mX4c\""),
            Some(Confidence::ContextDependent)
        );
    }

    #[test]
    fn local_uri_credentials_are_found_at_lower_confidence() {
        let conf = |line: &str| {
            check_line(line, 1)
                .into_iter()
                .find(|f| f.description.starts_with("URI with embedded"))
                .map(|f| f.confidence)
        };
        for local in [
            "RPC=http://bitcoin:Rt7pQ2xZ@127.0.0.1:18443/",
            "url = 'https://admin:Rt7pQ2xZ@localhost:5432/db'",
            "https://u:Tr0ub4dor3xQ9@nas.local/share",
            "https://u:Tr0ub4dor3xQ9@svc.internal/x",
        ] {
            assert_eq!(conf(local), Some(Confidence::ContextDependent), "{local}");
        }
        assert_eq!(
            conf("https://u:Tr0ub4dor3xQ9@db.notexample.com/x"),
            Some(Confidence::High)
        );
        // Example domains, exactly or as a subdomain, and placeholders stay
        // quiet.
        assert_eq!(conf("https://u:Tr0ub4dor3xQ9@example.com/x"), None);
        assert_eq!(conf("https://u:Tr0ub4dor3xQ9@db.example.com/x"), None);
        assert_eq!(conf("https://admin:password@localhost/x"), None);
    }

    fn env_password(line: &str) -> bool {
        check_env_line(line, 1)
            .iter()
            .any(|f| f.secret_type == ContentSecretType::PasswordPattern)
    }

    #[test]
    fn env_lines_report_literal_values_without_code_shape_rules() {
        assert!(env_password("DB_PASSWORD=correct_horse_battery_staple"));
        assert!(env_password("DB_PASSWORD=correct-horse-battery-staple"));
        assert!(env_password("PASSWORD=mypassword9"));
        assert!(env_password("export API_TOKEN=\"camelCaseLooking\""));
        assert!(env_password("SESSION_SECRET='hunterTwo' # local"));
        assert!(!env_password("DB_PASSWORD=${DB_PASSWORD}"));
        assert!(!env_password("DB_PASSWORD=$DB_PASSWORD"));
        assert!(!env_password("PASSWORD=changeme"));
        assert!(!env_password("DB_PASSWORD="));
        assert!(!env_password("PRIVATE_KEY_PATH=/etc/keys/app.pem"));
        assert!(!env_password("TOKENIZER_MODEL=bert-base-uncased"));
        assert!(!env_password("STRIPE_PUBLISHABLE_KEY=pk_live_abcdefgh"));
        // Other checks still run, and a value they name is not repeated.
        let ghp = format!("{}{}", "ghp_", "Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7Ka");
        let f = check_env_line(&format!("GITHUB_TOKEN={ghp}"), 1);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(matches!(f[0].secret_type, ContentSecretType::ApiKey { .. }));
    }

    #[test]
    fn short_key_prefix_with_a_key_shaped_token_is_found() {
        // Synthetic, Resend-shaped.
        assert!(has_api_key(
            "RESEND_API_KEY=re_Ab3dE5fG_h7JkL9mNpQ2rS4tUvW6xYz8"
        ));
    }

    #[test]
    fn detect_credit_card_visa() {
        let findings = check_line("4532015112830366", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::CreditCard));
    }

    #[test]
    fn no_detect_invalid_luhn() {
        let findings = check_line("4532015112830367", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::CreditCard));
    }

    #[test]
    fn detect_postgres_connection() {
        let findings = check_line("postgres://user:password@localhost:5432/db", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::DbConnectionString));
    }

    #[test]
    fn no_detect_db_without_creds() {
        let findings = check_line("postgres://localhost:5432/db", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::DbConnectionString));
    }

    #[test]
    fn detect_eth_hex_key() {
        // Realistic hex key with high entropy (all 16 hex chars represented)
        let key = "0xa1b2c3d4e5f678901234567890abcdef1a2b3c4d5e6f7890fedcba9876543210";
        let findings = check_line(key, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::EthHexKey));
    }

    #[test]
    fn no_detect_eth_hex_low_entropy() {
        // Repeated hex pattern — likely not a real key
        let key = format!("0x{}", "aa".repeat(32));
        let findings = check_line(&key, 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::EthHexKey),
            "Low-entropy hex should be rejected by entropy check"
        );
    }

    #[test]
    fn no_detect_evm_bytecode() {
        // Solidity compiled bytecode: 0x + hundreds of hex chars. Not a private key.
        let bytecode = format!("0x{}", "60806040".repeat(50));
        let findings = check_line(&bytecode, 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::EthHexKey),
            "EVM bytecode should not be detected as an Ethereum hex key"
        );
    }

    // ── Tier 3 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_password_assignment() {
        let findings = check_line("password = supersecretvalue123", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::PasswordPattern));
    }

    #[test]
    fn no_detect_password_placeholder() {
        let findings = check_line("password = your-password-here", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PasswordPattern));
    }

    #[test]
    fn no_detect_password_empty() {
        let findings = check_line("password = \"\"", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PasswordPattern));
    }

    #[test]
    fn detect_ssn() {
        let findings = check_line("SSN: 123-45-6789", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SsnPattern));
    }

    #[test]
    fn no_detect_invalid_ssn_area() {
        // Area 000 is invalid
        let findings = check_line("000-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
        // Area 666 is invalid
        let findings = check_line("666-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
        // Area 900+ is invalid
        let findings = check_line("900-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
    }

    // ── Multi-line tests ─────────────────────────────────────────────────

    #[test]
    fn detect_seed_phrase_12_words() {
        let lines =
            vec!["legal winner thank year wave sausage worth useful legal winner thank yellow"];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SeedPhrase));
    }

    #[test]
    fn no_detect_short_word_run() {
        let lines = vec!["abandon ability able about above absent"];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SeedPhrase));
    }

    #[test]
    fn no_detect_english_prose_as_seed() {
        // Normal English prose — many words match BIP-39 prefixes but have punctuation
        let lines = vec![
            "About the project, we also need to action these items above all else.",
            "The primary call was about making a change, because the actual cost below",
            "the budget allows us to close the deal and carry forward with the plan.",
        ];
        let findings = check_multi_line(&lines);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::SeedPhrase),
            "Normal English prose should not trigger seed phrase detection"
        );
    }

    #[test]
    fn no_detect_prose_with_punctuation() {
        // Every word here is BIP-39, but commas/periods break runs
        let lines = vec![
            "abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse, access, accident",
        ];
        let findings = check_multi_line(&lines);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::SeedPhrase),
            "Punctuated word lists should not trigger seed phrase detection"
        );
    }

    #[test]
    fn category_method() {
        assert_eq!(ContentSecretType::PemPrivateKey.category(), "Crypto Keys");
        assert_eq!(ContentSecretType::AwsAccessKey.category(), "API Keys");
        assert_eq!(ContentSecretType::SeedPhrase.category(), "Seed Phrases");
        assert_eq!(ContentSecretType::JwtToken.category(), "Auth Tokens");
        assert_eq!(ContentSecretType::CreditCard.category(), "Financial");
        assert_eq!(ContentSecretType::PasswordPattern.category(), "Passwords");
        assert_eq!(
            ContentSecretType::SuspiciousImage.category(),
            "Suspicious Images"
        );
    }

    #[test]
    fn detect_2fa_backup_codes() {
        let lines = vec!["12345678", "87654321", "11223344", "55667788", "99001122"];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::TwoFactorBackupCodes));
    }

    // ── Image filename tests ─────────────────────────────────────────────

    #[test]
    fn detect_recovery_key_image() {
        let finding = check_image_filename("recovery-key-photo.heic");
        assert!(finding.is_some());
        assert_eq!(
            finding.unwrap().secret_type,
            ContentSecretType::SuspiciousImage
        );
    }

    #[test]
    fn detect_seed_phrase_image() {
        let finding = check_image_filename("seed-phrase-backup.png");
        assert!(finding.is_some());
    }

    #[test]
    fn no_detect_screenshot() {
        // Generic screenshots should NOT trigger — too noisy
        let finding = check_image_filename("Screenshot 2024-01-15.png");
        assert!(finding.is_none());
    }

    #[test]
    fn no_detect_normal_image() {
        let finding = check_image_filename("vacation-beach.jpg");
        assert!(finding.is_none());
    }

    #[test]
    fn no_detect_keyboard_image() {
        // "key" alone should not match — "keyboard" is not suspicious
        let finding = check_image_filename("keyboard-layout.png");
        assert!(finding.is_none());
    }

    // ── Helper tests ─────────────────────────────────────────────────────

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4532015112830366"));
        assert!(luhn_check("79927398713"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4532015112830367"));
        assert!(!luhn_check("1234567890"));
    }

    #[test]
    fn base58_valid() {
        assert!(is_base58(
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        ));
    }

    #[test]
    fn base58_invalid() {
        assert!(!is_base58("0OlI")); // These chars are not in base58
    }

    #[test]
    fn bip39_word_lookup() {
        assert!(is_bip39_word("abandon"));
        assert!(is_bip39_word("ability"));
        assert!(is_bip39_word("zoo"));
        assert!(!is_bip39_word("xyzzy"));
        assert!(!is_bip39_word("ab")); // too short
    }

    // ── Redaction tests ──────────────────────────────────────────────────

    // ── Sensitive marking tests ───────────────────────────────────────────

    #[test]
    fn detect_top_secret_banner() {
        let findings = check_line("TOP SECRET", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET"
            }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_secret_sci_noforn() {
        let findings = check_line("SECRET//SCI//NOFORN", 1);
        assert!(findings
            .iter()
            .any(|f| matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_portion_marking_ts() {
        let findings = check_line("(TS) The following data is classified", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "(TS)" }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_portion_marking_s() {
        let findings = check_line("(S) This paragraph is secret", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "(S)" }
        )));
    }

    #[test]
    fn detect_cui_banner() {
        let findings = check_line("CUI//SP-PRVCY", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "CUI" }
        )));
    }

    #[test]
    fn detect_export_controlled_itar() {
        let findings = check_line("This document is controlled under 22 CFR 120-130 (ITAR)", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "ITAR" }
        )));
        assert!(findings.iter().any(|f| f.confidence == Confidence::High));
    }

    #[test]
    fn detect_corporate_proprietary() {
        let findings = check_line(
            "This document contains proprietary information of Acme Corp.",
            1,
        );
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking {
                marking: "PROPRIETARY"
            }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::ContextDependent));
    }

    #[test]
    fn no_detect_secret_in_prose() {
        // "the secret ingredient is..." — bare word "secret" should NOT trigger
        let findings = check_line("the secret ingredient is love", 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
            "Prose containing 'secret' should not trigger sensitive marking detection"
        );
    }

    #[test]
    fn no_detect_confidential_in_prose() {
        // "this is confidential information" — not a standalone banner
        let findings = check_line("this is confidential information", 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
            "Prose containing 'confidential' should not trigger sensitive marking detection"
        );
    }

    #[test]
    fn no_detect_marking_in_string_literal() {
        // Source code pattern definitions should not trigger — keyword is inside quotes
        let cases = vec![
            r#"        ("NOFORN", "NOFORN"),"#,
            r#"        ("ORCON", "ORCON"),"#,
            r#"        ("REL TO", "REL TO"),"#,
            r#"    if upper.starts_with("TOP SECRET") {"#,
            r#"        marking: "CONFIDENTIAL","#,
            r#"    for &(phrase, marking) in &[("PROPRIETARY INFORMATION", "PROPRIETARY")]"#,
            r#"        ("EXPORT CONTROLLED", "EXPORT CONTROLLED"),"#,
        ];
        for line in &cases {
            let findings = check_line(line, 1);
            assert!(
                findings
                    .iter()
                    .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
                "String literal should not trigger marking detection: {}",
                line
            );
        }
    }

    #[test]
    fn severity_ranking() {
        // API keys should be critical
        assert_eq!(
            ContentSecretType::AwsAccessKey.severity(),
            Severity::Critical
        );
        assert_eq!(
            ContentSecretType::ApiKey { service: "GitHub" }.severity(),
            Severity::Critical
        );
        // Seed phrases should be high
        assert_eq!(ContentSecretType::SeedPhrase.severity(), Severity::High);
        // NOFORN should be medium (policy, not a credential)
        assert_eq!(
            ContentSecretType::SensitiveMarking { marking: "NOFORN" }.severity(),
            Severity::Medium
        );
        // TOP SECRET should be high (classified docs are serious)
        assert_eq!(
            ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET"
            }
            .severity(),
            Severity::High
        );
        // Suspicious images should be low
        assert_eq!(ContentSecretType::SuspiciousImage.severity(), Severity::Low);
    }

    #[test]
    fn category_sensitive() {
        let t = ContentSecretType::SensitiveMarking {
            marking: "TOP SECRET",
        };
        assert_eq!(t.category(), "Sensitivity Labels");
    }

    // ── Redaction tests ──────────────────────────────────────────────────

    #[test]
    fn redaction_never_shows_full_value() {
        let test_cases: Vec<String> = vec![
            "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            format!("ghp_{}", "a".repeat(36)),
            "4532015112830366".to_string(),
            "postgres://user:password@localhost:5432/db".to_string(),
            "password = mysecretvalue".to_string(),
        ];

        for case in &test_cases {
            let findings = check_line(case.as_str(), 1);
            for finding in &findings {
                // The redacted preview should never contain the full secret
                assert!(
                    finding.redacted_preview.contains("****")
                        || finding.redacted_preview.contains("..."),
                    "Finding preview should be redacted: {:?}",
                    finding.redacted_preview
                );
            }
        }
    }

    // ── Context detection tests ─────────────────────────────────────────

    #[test]
    fn detect_comment_line_double_slash() {
        assert_eq!(
            detect_line_context("  // password = secret123"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_line_hash() {
        assert_eq!(
            detect_line_context("# AWS_ACCESS_KEY=AKIA..."),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_line_sql() {
        assert_eq!(
            detect_line_context("  -- password: secret"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_block_start() {
        assert_eq!(
            detect_line_context("  /* secret key here */"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_block_middle() {
        assert_eq!(
            detect_line_context("  * AKIAIOSFODNN7EXAMPLE"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_code_not_comment() {
        assert_eq!(
            detect_line_context("password = supersecret123"),
            LineContext::Code
        );
    }

    #[test]
    fn detect_shebang_not_comment() {
        assert_eq!(detect_line_context("#!/bin/bash"), LineContext::Code);
    }

    #[test]
    fn detect_rust_attribute_not_comment() {
        assert_eq!(detect_line_context("#[derive(Debug)]"), LineContext::Code);
    }

    #[test]
    fn comment_downgrades_confidence() {
        // An AWS key in a comment should be downgraded from Definitive to High
        let findings =
            check_line_with_context("  // aws_access_key = AKIAIOSFODNN7EXAMPLE", 1, None);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::AwsAccessKey));
        assert!(findings.iter().all(|f| {
            if f.secret_type == ContentSecretType::AwsAccessKey {
                f.confidence == Confidence::High && f.context == LineContext::Comment
            } else {
                true
            }
        }));
    }

    #[test]
    fn code_preserves_confidence() {
        // An AWS key in code should stay Definitive
        let findings = check_line_with_context("aws_access_key = AKIAIOSFODNN7EXAMPLE", 1, None);
        assert!(findings.iter().any(|f| {
            f.secret_type == ContentSecretType::AwsAccessKey
                && f.confidence == Confidence::Definitive
                && f.context == LineContext::Code
        }));
    }

    #[test]
    fn executed_context_override() {
        // Shell history: override to Executed context, no downgrade
        let findings =
            check_line_with_context("password = mysecretvalue", 1, Some(LineContext::Executed));
        assert!(findings.iter().any(|f| {
            f.secret_type == ContentSecretType::PasswordPattern
                && f.confidence == Confidence::ContextDependent
                && f.context == LineContext::Executed
        }));
    }

    // ── Base64 decoding tests ───────────────────────────────────────────

    #[test]
    fn base64_decode_simple() {
        let decoded = base64_decode("SGVsbG8gV29ybGQ=");
        assert_eq!(decoded, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn base64_decode_no_padding() {
        let decoded = base64_decode("QUJDRA==");
        assert_eq!(decoded, Some(b"ABCD".to_vec()));
    }

    #[test]
    fn base64_decode_invalid() {
        // Invalid length (not multiple of 4)
        assert_eq!(base64_decode("abc"), None);
        // Invalid chars
        assert_eq!(base64_decode("a b!"), None);
    }

    #[test]
    fn detect_base64_encoded_aws_key() {
        // "AKIAIOSFODNN7EXAMPLE" base64-encoded
        let encoded = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should detect AWS key inside base64-encoded content"
        );
        assert!(findings
            .iter()
            .all(|f| f.context == LineContext::Base64Encoded));
        assert!(findings
            .iter()
            .all(|f| f.redacted_preview.starts_with("[base64]")));
    }

    #[test]
    fn detect_base64_encoded_pem_header() {
        // "-----BEGIN RSA PRIVATE KEY-----" base64-encoded
        let encoded = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PemPrivateKey),
            "Should detect PEM header inside base64-encoded content"
        );
    }

    #[test]
    fn no_detect_base64_normal_text() {
        // "Hello World, this is a normal sentence" base64-encoded
        let encoded = "SGVsbG8gV29ybGQsIHRoaXMgaXMgYSBub3JtYWwgc2VudGVuY2U=";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings.is_empty(),
            "Normal text in base64 should not trigger"
        );
    }

    #[test]
    fn detect_base64_in_longer_line() {
        // A line with a base64 token embedded among other text
        let line = format!("export DATA=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= # encoded key");
        let findings = check_base64_content(&line, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should find AWS key in base64 token within a longer line"
        );
    }

    #[test]
    fn is_likely_base64_rejects_short() {
        assert!(!is_likely_base64("abc="));
        assert!(!is_likely_base64(""));
    }

    #[test]
    fn is_likely_base64_accepts_valid() {
        assert!(is_likely_base64("QUtJQUlPU0ZPRE5ON0VYQU1QTEU="));
    }

    #[test]
    fn confidence_downgrade_chain() {
        assert_eq!(Confidence::Definitive.downgrade(), Confidence::High);
        assert_eq!(Confidence::High.downgrade(), Confidence::ContextDependent);
        assert_eq!(
            Confidence::ContextDependent.downgrade(),
            Confidence::Heuristic
        );
        assert_eq!(Confidence::Heuristic.downgrade(), Confidence::Heuristic);
    }

    #[test]
    fn line_context_labels() {
        assert_eq!(LineContext::Code.label(), "code");
        assert_eq!(LineContext::Comment.label(), "comment");
        assert_eq!(LineContext::Executed.label(), "executed");
        assert_eq!(LineContext::Base64Encoded.label(), "base64");
    }

    // ── Entropy scoring tests ───────────────────────────────────────────

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        assert!(shannon_entropy("aaaa") < 0.01);
    }

    #[test]
    fn entropy_high_randomness() {
        // Mix of all printable ASCII chars = high entropy
        let s = "aB3$xZ9@mK7!pQ2#wL5&";
        let e = shannon_entropy(s);
        assert!(
            e > 4.0,
            "High-entropy mixed string should be > 4.0 bits/byte, got {e}"
        );
    }

    #[test]
    fn entropy_real_api_key() {
        let e = shannon_entropy("51Srsy8Am5gWouXUPqhopS7VEKcxIPjv");
        assert!(
            e > ENTROPY_THRESHOLD_API_KEY,
            "Real API key suffix should exceed threshold, got {e}"
        );
    }

    #[test]
    fn entropy_placeholder_low() {
        let e = shannon_entropy("xxxxxxxxxxxx");
        assert!(
            e < ENTROPY_THRESHOLD_API_KEY,
            "Repeated chars should be below threshold, got {e}"
        );
    }

    #[test]
    fn entropy_password_real_vs_fake() {
        // Real password: high entropy
        let real = shannon_entropy("kX9$mP2!nQ7@sT3");
        assert!(real > ENTROPY_THRESHOLD_PASSWORD);

        // Fake/simple: low entropy
        let fake = shannon_entropy("aaaa");
        assert!(fake < ENTROPY_THRESHOLD_PASSWORD);
    }

    #[test]
    fn no_detect_password_low_entropy() {
        // "password = aaaa" should be rejected (low entropy value)
        let findings = check_line("password = aaaaaa", 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::PasswordPattern),
            "Low-entropy password value should be rejected"
        );
    }

    #[test]
    fn detect_password_high_entropy() {
        // "password = kX9$mP2!nQ7@" should be detected (high entropy)
        let findings = check_line("password = kX9mP2nQ7sT3uV6", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PasswordPattern),
            "High-entropy password value should be detected"
        );
    }

    // ── D-23: False positive wordlist tests ─────────────────────────────

    #[test]
    fn false_positive_rejects_programming_keywords() {
        assert!(is_false_positive("sha256"));
        assert!(is_false_positive("SHA256"));
        assert!(is_false_positive("encrypt"));
        assert!(is_false_positive("callback"));
    }

    #[test]
    fn false_positive_rejects_hex_constants() {
        assert!(is_false_positive("deadbeef"));
        assert!(is_false_positive("CAFEBABE"));
        assert!(is_false_positive("baadf00d"));
    }

    #[test]
    fn false_positive_allows_real_secrets() {
        assert!(!is_false_positive("kX9mP2nQ7sT3uV6wY1zA4bC5"));
        assert!(!is_false_positive("51Srsy8Am5gWouXUPqhopS7VEKcxIPjv"));
    }

    #[test]
    fn false_positive_rejects_low_entropy_hex_color() {
        // 6-char hex that looks like a CSS color (#aabbcc)
        assert!(is_false_positive("aabbcc"));
    }

    #[test]
    fn password_false_positive_not_detected() {
        // "password = localhost" should not trigger (programming keyword)
        let findings = check_line("password = localhost", 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::PasswordPattern),
            "False positive keyword 'localhost' as password value should be rejected"
        );
    }

    // ── D-24: URI credential tests ──────────────────────────────────────

    #[test]
    fn detect_uri_credentials_https() {
        let findings = check_line("https://admin:s3cretP4ss@db.acme-internal.net:5432/mydb", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::DbConnectionString
                    && f.description.contains("URI with embedded credentials")),
            "Should detect credentials in HTTPS URI"
        );
    }

    #[test]
    fn detect_uri_credentials_ftp() {
        let findings = check_line("ftp://deploy:hunter2abc@files.corp.net/releases", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("URI with embedded credentials")),
            "Should detect credentials in FTP URI"
        );
    }

    #[test]
    fn no_detect_uri_placeholder_password() {
        let findings = check_line("https://user:your-password-here@example.com/api", 1);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("URI with embedded credentials")),
            "Should not detect placeholder password in URI"
        );
    }

    #[test]
    fn no_detect_uri_without_credentials() {
        let findings = check_line("https://example.com/api/v1/data", 1);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("URI with embedded credentials")),
            "Should not flag URIs without credentials"
        );
    }

    // ── D-25: Webhook URL tests ─────────────────────────────────────────

    #[test]
    fn detect_slack_webhook() {
        let findings = check_line(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Slack Incoming Webhook"
            )),
            "Should detect Slack incoming webhook URL"
        );
    }

    #[test]
    fn detect_discord_webhook() {
        let findings = check_line(
            "https://discord.com/api/webhooks/123456789/abcdefghijklmnop",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Discord Webhook"
            )),
            "Should detect Discord webhook URL"
        );
    }

    #[test]
    fn detect_teams_webhook() {
        let findings = check_line(
            "https://outlook.office.com/webhook/xxxxx/IncomingWebhook/yyyyy",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Microsoft Teams Webhook"
            )),
            "Should detect Teams webhook URL"
        );
    }

    #[test]
    fn detect_telegram_bot_token() {
        let findings = check_line(
            "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Telegram Bot Token"
            )),
            "Should detect Telegram bot token URL"
        );
    }

    // ── D-26: Azure pattern tests ───────────────────────────────────────

    #[test]
    fn detect_azure_storage_connection_string() {
        let findings = check_line(
            "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123def456ghi789==;EndpointSuffix=core.windows.net",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure Storage"
            )),
            "Should detect Azure Storage connection string"
        );
    }

    #[test]
    fn detect_azure_sas_token() {
        let findings = check_line(
            "https://myaccount.blob.core.windows.net/container?sv=2021-06-08&se=2024-01-01&sig=abcdef123456",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure SAS Token"
            )),
            "Should detect Azure SAS token"
        );
    }

    #[test]
    fn no_detect_azure_without_key() {
        let findings = check_line("DefaultEndpointsProtocol=https;AccountName=myacct", 1);
        assert!(
            findings.iter().all(|f| !matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure Storage"
            )),
            "Should not detect Azure Storage without AccountKey"
        );
    }

    // ── D-27: AI provider token tests ───────────────────────────────────

    #[test]
    fn detect_deepseek_api_key() {
        let key = "dsk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "DeepSeek API Key"
            )),
            "Should detect DeepSeek API key"
        );
    }

    #[test]
    fn detect_groq_api_key() {
        let key = "gsk_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Groq API Key"
            )),
            "Should detect Groq API key"
        );
    }

    #[test]
    fn detect_replicate_api_token() {
        let key = "r8_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8W9";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Replicate API Token"
            )),
            "Should detect Replicate API token"
        );
    }

    #[test]
    fn detect_perplexity_api_key() {
        let key = "pplx-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Perplexity API Key"
            )),
            "Should detect Perplexity API key"
        );
    }

    // ── D-28: Unicode decoding tests ─────────────────────────────────────

    #[test]
    fn safe_prefix_never_splits_a_character() {
        assert_eq!(safe_prefix("abc", 10), "abc");
        assert_eq!(safe_prefix("abcdef", 3), "abc");
        // "—" is three bytes; a cut at byte 2 backs off to the boundary.
        assert_eq!(safe_prefix("a—b", 2), "a");
        assert_eq!(safe_prefix("a—b", 4), "a—");
        assert_eq!(safe_prefix("—", 0), "");
    }

    /// The exact shape of a production crash: a dissemination-control line
    /// whose 60-byte preview cut landed inside an em dash.
    #[test]
    fn marking_preview_survives_multibyte_text() {
        let line = "NOFORN distribution statement for the programme — see annex — more text here";
        let findings = check_line_with_context(line, 1, None);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("Dissemination")));
        for f in &findings {
            assert!(f.redacted_preview.chars().all(|c| c != '\u{FFFD}'));
        }
    }

    /// Every scanner entry point must tolerate multi-byte characters at every
    /// offset around every trigger keyword. This is the test that would have
    /// caught the crash above.
    #[test]
    fn scanners_never_panic_on_multibyte_text_near_triggers() {
        let triggers = [
            "AKIA",
            "eyJ",
            "0x",
            "NOFORN",
            "ORCON",
            "REL TO",
            "EXPORT CONTROLLED",
            "CONFIDENTIAL",
            "(CUI)",
            "(C)",
            "(S)",
            "TOP SECRET",
            "22 CFR 12",
            "15 CFR 73",
            "sk_live_",
            "ghp_",
            "xoxb-",
            "AC",
            "pat",
            "postgres://",
            "mongodb://",
            "-----BEGIN",
            "password=",
            "secret:",
            "token",
            "AIza",
            "SG.",
            "glpat-",
            "PROPRIETARY",
            "TRADE SECRET",
            "ITAR",
            "5KJvsngHeMpm48GZxPqh",
            "L1aW4aubDFB7yfras2S1",
        ];
        let fillers = ["—", "é", "日本", "🦔", "ß", "ø"];
        let mut lines = Vec::new();
        for trigger in triggers {
            for filler in fillers {
                for n in 0..70 {
                    let pad: String = std::iter::repeat_n(filler, n).collect();
                    lines.push(format!("{trigger}{pad}"));
                    lines.push(format!("{pad}{trigger}{pad}"));
                    lines.push(format!(
                        "{trigger}{}{filler}{}",
                        "A".repeat(n),
                        "A".repeat(70 - n)
                    ));
                    lines.push(format!("{trigger} = \"{}{filler}\"", "x".repeat(n)));
                }
            }
        }
        for (i, line) in lines.iter().enumerate() {
            let _ = check_line(line, i + 1);
            let _ = check_line_with_context(line, i + 1, None);
            let _ = check_base64_content(line, i + 1);
            let _ = check_unicode_obfuscated(line, i + 1);
            let _ = detect_line_context(line);
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        for chunk in refs.chunks(500) {
            let _ = check_multi_line(chunk);
        }
    }

    #[test]
    fn decode_unicode_escape_u() {
        // \u0041\u004b\u0049\u0041 = "AKIA"
        let input = r"\u0041\u004b\u0049\u0041IOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn decode_unicode_escape_x() {
        // \x41\x4b\x49\x41 = "AKIA"
        let input = r"\x41\x4bIAIOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn decode_url_encoding() {
        // %41%4b%49%41 = "AKIA"
        let input = "%41%4b%49%41IOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn detect_unicode_obfuscated_aws_key() {
        // AWS key with \u escapes on the prefix
        let line = r"key = \u0041\u004b\u0049\u0041IOSFODNN7EXAMPLE";
        let findings = check_unicode_obfuscated(line, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should detect AWS key through Unicode escapes"
        );
        assert!(findings[0].redacted_preview.starts_with("[unicode]"));
    }

    #[test]
    fn detect_url_encoded_password() {
        // password%3Dmysupersecretvalue (%3D = '=')
        let line = "config password%3Dmysupersecretvalue";
        let findings = check_unicode_obfuscated(line, 1);
        // After decoding: "config password=mysupersecretvalue"
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PasswordPattern),
            "Should detect password through URL encoding"
        );
    }

    #[test]
    fn no_false_positive_normal_text() {
        // Normal text with no escape sequences should return empty
        let line = "This is a normal line with no secrets";
        let findings = check_unicode_obfuscated(line, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_decode_invalid_escapes() {
        // Invalid escape sequences should not crash
        let line = r"\uGGGG \xZZ %ZZ normal text";
        let decoded = decode_unicode_escapes(line);
        // \uGGGG stays as-is, \xZZ stays, %ZZ stays
        assert!(decoded.contains("normal text"));
    }

    #[test]
    fn decode_mixed_escapes() {
        // Mix of \u, \x, and %XX
        let input = r"\u0048\x65llo%20World";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn decode_utf16_le() {
        // UTF-16 LE BOM + "AKIAIOSFODNN7EXAMPLE" in UTF-16 LE
        let text = "AKIAIOSFODNN7EXAMPLE";
        let mut bytes = vec![0xFF, 0xFE]; // BOM
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let decoded = decode_utf16(&bytes);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), text);
    }

    #[test]
    fn decode_utf16_be() {
        // UTF-16 BE BOM + "password=secret"
        let text = "password=secret";
        let mut bytes = vec![0xFE, 0xFF]; // BOM
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_be_bytes());
        }
        let decoded = decode_utf16(&bytes);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), text);
    }

    #[test]
    fn no_decode_without_bom() {
        // No BOM — should return None
        let bytes = b"Hello World";
        let decoded = decode_utf16(bytes);
        assert!(decoded.is_none());
    }

    #[test]
    fn has_unicode_escapes_detection() {
        assert!(has_unicode_escapes(r"foo \u0041 bar"));
        assert!(has_unicode_escapes(r"foo \x41 bar"));
        assert!(has_unicode_escapes("foo %41 bar"));
        assert!(!has_unicode_escapes("foo bar baz"));
        assert!(!has_unicode_escapes(r"foo \n bar")); // \n is not \uXXXX
    }

    // ── Marking previews never quote document content ───────────────────

    fn marking_previews(line: &str) -> Vec<(String, &'static str)> {
        check_line(line, 7)
            .into_iter()
            .filter_map(|f| match f.secret_type {
                ContentSecretType::SensitiveMarking { marking } => {
                    assert_eq!(f.line_number, 7, "line number must be kept");
                    Some((f.redacted_preview, marking))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn marking_previews_are_fixed_labels_without_document_text() {
        let cases: &[(&str, &str, bool)] = &[
            (
                "TOP SECRET//SI//EXAMPLECODEWORD//NOFORN",
                "[MARKING] classification banner (TOP SECRET level)",
                true,
            ),
            (
                "SECRET//SI//EXAMPLECODEWORD//NOFORN",
                "[MARKING] classification banner (SECRET level)",
                true,
            ),
            (
                "CONFIDENTIAL//EXAMPLECODEWORD",
                "[MARKING] classification banner (CONFIDENTIAL level)",
                true,
            ),
            ("CUI//SP-EXAMPLECODEWORD", "[MARKING] CUI designation", true),
            (
                "(TS//SI//EXAMPLECODEWORD) The source reported troop movements",
                "[PORTION] portion mark (TS)",
                true,
            ),
            (
                "(S//EXAMPLECODEWORD) The source reported troop movements",
                "[PORTION] portion mark (S)",
                true,
            ),
            (
                "(C) EXAMPLECODEWORD the source reported troop movements",
                "[PORTION] portion mark (C)",
                true,
            ),
            (
                "(CUI) EXAMPLECODEWORD the source reported",
                "[PORTION] portion mark (CUI)",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: NOFORN",
                "[MARKING] dissemination control NOFORN",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: ORCON",
                "[MARKING] dissemination control ORCON",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: REL TO USA, GBR",
                "[MARKING] dissemination control REL TO",
                true,
            ),
            (
                "EXAMPLECODEWORD data controlled under 22 CFR 120-130",
                "[MARKING] ITAR export-control notice",
                false,
            ),
            (
                "EXAMPLECODEWORD data controlled under 15 CFR 730-774",
                "[MARKING] EAR export-control notice",
                false,
            ),
            (
                "EXAMPLECODEWORD contains proprietary information of Acme",
                "[MARKING] corporate sensitivity label PROPRIETARY",
                false,
            ),
            (
                "EXAMPLECODEWORD is a trade secret of Acme",
                "[MARKING] corporate sensitivity label TRADE SECRET",
                false,
            ),
        ];
        for (line, expected, government) in cases {
            let previews = marking_previews(line);
            assert_eq!(previews.len(), 1, "one marking finding for {line:?}");
            let (preview, marking) = &previews[0];
            assert_eq!(preview, expected, "preview for {line:?}");
            assert!(
                !preview.contains("EXAMPLECODEWORD")
                    && !preview.contains("//SI")
                    && !preview.to_lowercase().contains("source")
                    && !preview.to_lowercase().contains("acme"),
                "preview leaks document text: {preview:?}"
            );
            assert_eq!(
                is_government_marking(marking),
                *government,
                "government classification flag for {marking:?}"
            );
        }
    }
}
