// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Tests for the imported Gitleaks rules. Every token here is synthetic:
//! built at run time from a fixed pseudo-random sequence in the shape of the
//! real format, so no real credential (and no literal that looks like one)
//! appears in the source.

use super::*;

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOWER_ALNUM: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &str = "0123456789abcdef";
const DIGITS: &str = "0123456789";
const B32_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Deterministic pseudo-random string over `alphabet`.
fn synth(alphabet: &str, len: usize, seed: u64) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chars[(x % chars.len() as u64) as usize]
        })
        .collect()
}

fn rule(id: &str) -> &'static GlRule {
    RULES
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no rule {id}"))
}

/// Ids of the rules that reported a finding on `line`.
fn hits(line: &str) -> Vec<&'static str> {
    let findings = check_line_gitleaks(line, 1);
    RULES
        .iter()
        .filter(|r| findings.iter().any(|f| f.description == r.description))
        .map(|r| r.id)
        .collect()
}

fn assert_finds(id: &str, line: &str, secret: &str, confidence: Confidence) {
    let r = rule(id);
    let findings = check_line_gitleaks(line, 7);
    let f = findings
        .iter()
        .find(|f| f.description == r.description)
        .unwrap_or_else(|| {
            panic!(
                "{id} did not match its synthetic sample (hits: {:?})",
                hits(line)
            )
        });
    assert_eq!(
        f.secret_type,
        ContentSecretType::ApiKey { service: r.service },
        "{id}"
    );
    assert_eq!(f.confidence, confidence, "{id} confidence");
    assert_eq!(f.line_number, 7);
    let expected: String = secret.chars().take(4).collect::<String>() + "****";
    assert_eq!(f.redacted_preview, expected, "{id} preview");
}

#[test]
fn every_generated_regex_compiles() {
    let mut failures = Vec::new();
    for r in RULES {
        if let Err(e) = Regex::new(r.regex) {
            failures.push(format!("{}: {e}", r.id));
        }
        for (k, a) in r.allowlists.iter().enumerate() {
            for re in a.regexes {
                if let Err(e) = Regex::new(re) {
                    failures.push(format!("{} allowlist {}: {e}", r.id, k + 1));
                }
            }
        }
    }
    for re in GLOBAL_ALLOWLIST.regexes {
        if let Err(e) = Regex::new(re) {
            failures.push(format!("global allowlist {re}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "regexes minire cannot compile:\n{}",
        failures.join("\n")
    );
}

#[test]
fn table_is_sane() {
    assert!(
        gitleaks_rule_count() >= 200,
        "only {} rules",
        gitleaks_rule_count()
    );
    assert_eq!(gitleaks_source_version(), "v8.30.1");
    let mut ids = std::collections::HashSet::new();
    for r in RULES {
        assert!(ids.insert(r.id), "duplicate rule {}", r.id);
        assert!(!r.keywords.is_empty(), "{} has no keywords", r.id);
        assert!(
            r.keywords.iter().all(|k| *k == k.to_ascii_lowercase()),
            "{}",
            r.id
        );
        assert!(!r.service.is_empty() && !r.description.is_empty());
        assert_ne!(r.id, "generic-api-key");
    }
}

#[test]
fn well_known_formats() {
    // Anthropic
    let s = format!(
        "{}{}AA",
        ["sk", "ant", "api03-"].join("-"),
        synth(ALNUM, 93, 1)
    );
    assert_finds(
        "anthropic-api-key",
        &format!("ANTHROPIC_API_KEY={s}"),
        &s,
        Confidence::Definitive,
    );

    // GitHub classic PAT
    let s = format!("{}{}", "ghp_", synth(ALNUM, 36, 2));
    assert_finds(
        "github-pat",
        &format!("token: {s}"),
        &s,
        Confidence::Definitive,
    );

    // Stripe
    let s = format!("{}_{}_{}", "sk", "live", synth(ALNUM, 24, 3));
    assert_finds(
        "stripe-access-token",
        &format!("stripe.api_key = \"{s}\""),
        &s,
        Confidence::High,
    );

    // Slack bot token
    let s = format!(
        "{}-{}-{}-{}",
        "xoxb",
        synth(DIGITS, 12, 4),
        synth(DIGITS, 13, 5),
        synth(ALNUM, 24, 6)
    );
    assert_finds(
        "slack-bot-token",
        &format!("SLACK_BOT_TOKEN={s}"),
        &s,
        Confidence::Definitive,
    );

    // Google Cloud API key
    let s = format!("{}{}", "AIza", synth(&(ALNUM.to_string() + "_-"), 35, 7));
    assert_finds(
        "gcp-api-key",
        &format!("const key = '{s}';"),
        &s,
        Confidence::Definitive,
    );

    // npm
    let s = format!("{}{}", "npm_", synth(LOWER_ALNUM, 36, 8));
    assert_finds(
        "npm-access-token",
        &format!("//registry.npmjs.org/:_authToken={s}"),
        &s,
        Confidence::Definitive,
    );

    // AWS access key id
    let s = format!("{}{}", "AKIA", synth(B32_UPPER, 16, 9));
    assert_finds(
        "aws-access-token",
        &format!("aws_access_key_id = {s}"),
        &s,
        Confidence::Definitive,
    );

    // OpenAI (legacy shape: sk- + 20 + marker + 20)
    let s = format!(
        "sk-{}{}FJ{}",
        synth(ALNUM, 20, 10),
        "T3Blbk",
        synth(ALNUM, 20, 11)
    );
    assert_finds(
        "openai-api-key",
        &format!("OPENAI_API_KEY=\"{s}\""),
        &s,
        Confidence::High,
    );

    // Heroku (keyword rule, UUID value)
    let u = format!(
        "{}-{}-{}-{}-{}",
        synth(HEX, 8, 12),
        synth(HEX, 4, 13),
        synth(HEX, 4, 14),
        synth(HEX, 4, 15),
        synth(HEX, 12, 16)
    );
    assert_finds(
        "heroku-api-key",
        &format!("HEROKU_API_KEY={u}"),
        &u,
        Confidence::High,
    );

    // GitLab PAT
    let s = format!("{}{}", "glpat-", synth(ALNUM, 20, 17));
    assert_finds(
        "gitlab-pat",
        &format!("GITLAB_TOKEN={s}"),
        &s,
        Confidence::Definitive,
    );

    // Shopify
    let s = format!("{}{}", "shpat_", synth(HEX, 32, 18));
    assert_finds(
        "shopify-access-token",
        &format!("X-Shopify-Access-Token: {s}"),
        &s,
        Confidence::Definitive,
    );

    // Twilio API key
    let s = format!("{}{}", "SK", synth(HEX, 32, 19));
    assert_finds(
        "twilio-api-key",
        &format!("TWILIO_API_KEY={s}"),
        &s,
        Confidence::High,
    );

    // SendGrid
    let s = format!("SG.{}.{}", synth(ALNUM, 22, 20), synth(ALNUM, 43, 21));
    assert_finds(
        "sendgrid-api-token",
        &format!("SENDGRID_API_KEY='{s}'"),
        &s,
        Confidence::High,
    );

    // DigitalOcean PAT
    let s = format!("{}{}", "dop_v1_", synth(HEX, 64, 22));
    assert_finds(
        "digitalocean-pat",
        &format!("DO_TOKEN={s}"),
        &s,
        Confidence::Definitive,
    );

    // Keyword-style rules: the value is only a secret next to the service name.
    let s = synth(LOWER_ALNUM, 32, 23);
    assert_finds(
        "algolia-api-key",
        &format!("ALGOLIA_ADMIN_KEY = \"{s}\""),
        &s,
        Confidence::High,
    );
    let s = synth(&(LOWER_ALNUM.to_string() + "_-"), 32, 24);
    assert_finds(
        "adafruit-api-key",
        &format!("adafruit_io_key: '{s}'"),
        &s,
        Confidence::High,
    );
}

#[test]
fn sonar_uses_its_secret_group() {
    let s = format!("{}{}", "squ_", synth(LOWER_ALNUM, 40, 25));
    assert_finds(
        "sonar-api-token",
        &format!("SONAR_TOKEN={s}"),
        &s,
        Confidence::High,
    );
}

#[test]
fn wrong_length_does_not_match() {
    let line = format!("token: {}{}", "ghp_", synth(ALNUM, 35, 2));
    assert!(!hits(&line).contains(&"github-pat"));
    let line = format!("{}{}", "AKIA", synth(B32_UPPER, 15, 9));
    assert!(!hits(&line).contains(&"aws-access-token"));
    // 31 characters after the keyword-style separator.
    let line = format!("ALGOLIA_KEY = \"{}\"", synth(LOWER_ALNUM, 31, 23));
    assert!(!hits(&line).contains(&"algolia-api-key"));
}

#[test]
fn inside_a_longer_word_does_not_match() {
    let s = format!(
        "{}{}AA",
        ["sk", "ant", "api03-"].join("-"),
        synth(ALNUM, 93, 1)
    );
    assert!(!hits(&format!("x{s}")).contains(&"anthropic-api-key"));
    let s = format!("{}{}", "AKIA", synth(B32_UPPER, 16, 9));
    assert!(!hits(&format!("X{s}")).contains(&"aws-access-token"));
    assert!(!hits(&format!("{s}X")).contains(&"aws-access-token"));
    // The algolia value runs into more characters, so it is not 32 long.
    let line = format!("ALGOLIA_KEY = {}xyz", synth(LOWER_ALNUM, 32, 23));
    assert!(!hits(&line).contains(&"algolia-api-key"));
}

#[test]
fn low_entropy_does_not_match() {
    let line = format!("token: {}{}", "ghp_", "a".repeat(36));
    assert!(!hits(&line).contains(&"github-pat"));
    let line = format!("{}{}", "AKIA", "A".repeat(16));
    assert!(!hits(&line).contains(&"aws-access-token"));
    let line = format!("DO_TOKEN={}{}", "dop_v1_", "0".repeat(64));
    assert!(!hits(&line).contains(&"digitalocean-pat"));
}

#[test]
fn allowlists_apply() {
    // AWS's documentation example ends in EXAMPLE and is allowlisted by the rule.
    assert!(!hits("aws_access_key_id = AKIAIOSFODNN7EXAMPLE").contains(&"aws-access-token"));
    // The global allowlist drops template placeholders such as ${VAR}.
    assert!(hits("ALGOLIA_KEY = ${ALGOLIA_KEY}").is_empty());
}

#[test]
fn keyword_is_required() {
    // The algolia value shape without the word "algolia" is not reported by it.
    let line = format!("SEARCH_KEY = \"{}\"", synth(LOWER_ALNUM, 32, 23));
    assert!(!hits(&line).contains(&"algolia-api-key"));
}

#[test]
fn ordinary_code_is_quiet() {
    let lines = [
        "fn main() { println!(\"hello, world\"); }",
        "let token = get_token_from_env(\"API_TOKEN\");",
        "const apiKey = process.env.STRIPE_SECRET_KEY;",
        "import { Octokit } from '@octokit/rest';",
        "password = os.environ['DB_PASSWORD']",
        "# Set ANTHROPIC_API_KEY in your shell before running.",
        "if key == null { return false; }",
        "SELECT id, name FROM users WHERE token_hash = $1;",
        "<add key=\"Password\" value=\"\" />",
    ];
    for l in lines {
        assert!(hits(l).is_empty(), "false positive on {l:?}: {:?}", hits(l));
    }
}

#[test]
fn preview_never_shows_more_than_four_characters() {
    let s = format!("{}{}", "ghp_", synth(ALNUM, 36, 2));
    for f in check_line_gitleaks(&format!("token: {s}"), 1) {
        assert!(f.redacted_preview.ends_with("****"));
        assert!(f.redacted_preview.chars().count() <= 8);
        assert!(!f.redacted_preview.contains(&s[4..8]) || s[4..8].contains('*'));
    }
}

#[test]
fn non_ascii_lines_are_safe() {
    let s = format!("{}{}", "ghp_", synth(ALNUM, 36, 2));
    let line = format!("clé = «{s}» 鍵 token");
    assert!(hits(&line).contains(&"github-pat"));
    let _ = check_line_gitleaks("é".repeat(5000).as_str(), 1);
}

// ── Audit regressions (2026-11-06) ──────────────────────────────────────

#[test]
fn global_allowlist_words_are_whole_secrets_only() {
    // `(?i)^true|false|null$` allowed any secret containing "false".
    assert!(GLOBAL_ALLOWLIST
        .regexes
        .contains(&"(?i)^(?:true|false|null)$"));
    let c = compiled();
    for word in ["true", "FALSE", "null"] {
        assert!(allowed(&c.global, word, word, word), "{word}");
    }
    let s = format!("q7xr{}falsek9pl4vn8ct3wz6yb1hd", "2m");
    assert!(!allowed(&c.global, &s, &s, &s));
}

#[test]
fn repeated_groups_do_not_become_the_secret() {
    let r = rule("microsoft-teams-webhook");
    assert!(!r.regex.contains("([a-z0-9]{4}-){3}"));
    let uuid = |seed: u64| {
        format!(
            "{}-{}-{}-{}-{}",
            synth(LOWER_ALNUM, 8, seed),
            synth(LOWER_ALNUM, 4, seed + 1),
            synth(LOWER_ALNUM, 4, seed + 2),
            synth(LOWER_ALNUM, 4, seed + 3),
            synth(LOWER_ALNUM, 12, seed + 4)
        )
    };
    let url = format!(
        "https://acme.webhook.office.com/webhookb2/{}@{}/IncomingWebhook/{}/{}",
        uuid(40),
        uuid(50),
        synth(LOWER_ALNUM, 32, 60),
        uuid(70)
    );
    // The whole URL is the secret, so the preview is its first characters.
    assert_finds(
        "microsoft-teams-webhook",
        &format!("TEAMS_URL={url}"),
        &url,
        Confidence::Definitive,
    );
}

#[test]
fn duplicate_rules_are_merged_and_spans_reported_once() {
    assert!(RULES.iter().all(|r| r.id != "bittrex-secret-key"));
    let line = format!("bittrex_key = \"{}\"", synth(LOWER_ALNUM, 32, 80));
    let f = check_line_gitleaks(&line, 1);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        f[0].secret_type,
        ContentSecretType::ApiKey {
            service: "Bittrex Access Key or Secret Key"
        }
    );
}

#[test]
fn confidence_overrides_apply() {
    let c = compiled();
    let conf = |id: &str| {
        let i = RULES.iter().position(|r| r.id == id).unwrap();
        c.rules[i].confidence
    };
    assert_eq!(conf("curl-auth-user"), Confidence::High);
    assert_eq!(conf("curl-auth-header"), Confidence::High);
    assert_eq!(conf("nuget-config-password"), Confidence::High);
    assert_eq!(conf("aws-access-token"), Confidence::Definitive);
}

#[test]
fn a_token_cut_by_a_window_edge_is_not_half_matched() {
    // curl-auth-user ends in `(?:\s|\z)`. Its keyword (`curl`) is at the
    // start, so its window ends WINDOW_AFTER bytes later, inside the value
    // below; without extending the window, `\z` would fire at the cut and
    // report a value the full line does not have (it ends in `)`, not a
    // space or the line end).
    let pad = " ".repeat(590);
    let value = synth(ALNUM, 150, 93);
    let line = format!("curl{pad} -u admin:{value}) ");
    assert!(
        !hits(&line).contains(&"curl-auth-user"),
        "matched a value cut by the window edge"
    );
    // The same value followed by a space is a real match.
    let line = format!("curl{pad} -u admin:{value} ");
    assert!(hits(&line).contains(&"curl-auth-user"));
}

#[test]
fn many_keyword_windows_on_one_line_are_all_searched() {
    // 40 separated `ghp_` keyword hits that are not tokens, then a real
    // one: more windows than the old cap of 16.
    let mut line = String::new();
    for _ in 0..40 {
        line.push_str(&format!("ghp_x{}", " ".repeat(900)));
    }
    let tok = format!("{}{}", "ghp_", synth(ALNUM, 36, 92));
    line.push_str(&format!("{tok} "));
    assert!(hits(&line).contains(&"github-pat"));
}

/// 200k lines of ordinary code; run with
/// `cargo test --release -p hedgehog_taint rules::tests::perf -- --nocapture`.
#[test]
fn perf_200k_lines() {
    let templates = [
        "    let token = auth::refresh_token(&client, &config.api_key)?;",
        "    if (secret_key == null || secret_key.length === 0) return false;",
        "const SLACK_CHANNEL = process.env.SLACK_CHANNEL || '#general'; // slack",
        "    def get_password(self, user_id: int) -> Optional[str]:",
        "    <add key=\"ServerUrl\" value=\"https://example.com/api\" />",
        "    for (let i = 0; i < keys.length; i++) { result.push(keys[i]); }",
        "  stripe_customer_id: string; // sk_test_ prefixed keys go in .env",
        "    logger.debug(\"twitter feed refreshed for {}\", account.handle);",
        "    \"eyebrow\": \"Key features\", \"aws_region\": \"eu-west-2\",",
        "SELECT key, value FROM settings WHERE github_org = $1 AND enabled;",
    ];
    let lines: Vec<String> = (0..200_000)
        .map(|i| format!("{} // {}", templates[i % templates.len()], i))
        .collect();
    // Compile the rules before timing.
    let _ = compiled();
    let start = std::time::Instant::now();
    let mut total = 0;
    for (i, l) in lines.iter().enumerate() {
        total += check_line_gitleaks(l, i).len();
    }
    let elapsed = start.elapsed();
    println!(
        "gitleaks rules: {} lines in {:.3} s ({} findings)",
        lines.len(),
        elapsed.as_secs_f64(),
        total
    );
    assert_eq!(total, 0, "ordinary code produced findings");
    if !cfg!(debug_assertions) {
        assert!(elapsed.as_secs_f64() < 2.0, "too slow: {elapsed:?}");
    }
}

// ── Audit regressions (2026-11-06, third and fourth audits) ──────────────
// Every token below is synthetic.

/// A synthetic JWT-shaped bearer token (three base64url parts).
fn synth_jwt(seed: u64) -> String {
    const B64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    format!(
        "eyJ{}.eyJ{}.{}",
        synth(B64URL, 30, seed),
        synth(B64URL, 60, seed + 1),
        synth(B64URL, 43, seed + 2)
    )
}

#[test]
fn curl_header_far_from_curl_is_found() {
    // "Copy as cURL": many headers before the Authorization one, which
    // starts more than 1000 bytes after `curl`.
    let mut line = String::from("curl 'https://api.acme-internal.net/v1/items?page=2'");
    for k in 0..30 {
        line.push_str(&format!(
            " -H 'x-trace-{k}: {}'",
            synth(LOWER_ALNUM, 24, 300 + k)
        ));
    }
    let at = line.len();
    line.push_str(&format!(
        " -H 'Authorization: Bearer {}' --compressed",
        synth_jwt(7)
    ));
    assert!(at > 1000, "header sits at byte {at}");
    assert!(
        hits(&line).contains(&"curl-auth-header"),
        "{:?}",
        hits(&line)
    );
}

#[test]
fn eighty_tokens_on_one_line_are_all_found() {
    let mut line = String::new();
    for k in 0..80u64 {
        let tok = format!("{}{}", "ghp_", synth(ALNUM, 36, 1000 + k));
        line.push_str(&format!("\"t{k}\":\"{tok}\",{}", " ".repeat(1500)));
    }
    let n = check_line_gitleaks(&line, 1)
        .iter()
        .filter(|f| f.redacted_preview.starts_with("ghp_"))
        .count();
    assert_eq!(n, 80);
}

#[test]
fn repeated_keyword_assignments_scan_in_linear_time() {
    // `adafruit='<32 chars>'; ` repeated to 360 KB: each value is a match,
    // so the old code (one merged window, anchors and a fresh budget per
    // search) was quadratic.
    let one = "adafruit='q7xr2mk9pl4vn8ct3wz6yb1hd5fj0gs2'; ";
    let line = one.repeat(360 * 1024 / one.len());
    let _ = compiled();
    let start = std::time::Instant::now();
    let found = check_line_gitleaks(&line, 1);
    let took = start.elapsed();
    assert!(!found.is_empty());
    if !cfg!(debug_assertions) {
        assert!(took < std::time::Duration::from_secs(1), "took {took:?}");
    }
}

#[test]
fn placeholder_allowlists_match_the_whole_password() {
    // curl-auth-user: `user:password` is a placeholder, a longer password
    // that starts with the word is not.
    assert!(!hits("curl -u alice:password https://192.0.2.10").contains(&"curl-auth-user"));
    assert!(hits("curl -u alice:passwordCedar42 https://192.0.2.10").contains(&"curl-auth-user"));
    assert!(!hits("curl -u \"alice:password\" https://192.0.2.10").contains(&"curl-auth-user"));
    assert!(!hits("curl -u admin:$API_PASS https://192.0.2.10").contains(&"curl-auth-user"));
    // nuget-config-password: Gitleaks' documented example passwords are
    // allowed, a longer password containing one is not.
    let ex = "<add key=\"Password\" value=\"33f!!lloppa\" />";
    assert!(!hits(ex).contains(&"nuget-config-password"));
    let real = format!(
        "<add key=\"Password\" value=\"33f!!lloppa{}\" />",
        synth(ALNUM, 8, 77)
    );
    assert!(
        hits(&real).contains(&"nuget-config-password"),
        "{:?}",
        hits(&real)
    );
}

#[test]
fn secret_is_the_first_non_empty_group_not_the_whole_match() {
    // lob-api-key nests (live|test) inside the secret group: the secret is
    // the outer group, never the variable name before it.
    let key = format!("live_{}", synth(HEX, 35, 41));
    assert_finds(
        "lob-api-key",
        &format!("LOB_API_KEY = \"{key}\""),
        &key,
        Confidence::High,
    );
    // curl-auth-user: the secret is the user:password argument, so an
    // earlier `X-Env:test` header never reads as a placeholder password.
    let pw = format!("MyRealProd{}", synth(ALNUM, 6, 12));
    let line = format!("curl -H \"X-Env:test\" https://api.acme-internal.net/v1 -u admin:{pw}");
    assert_finds("curl-auth-user", &line, "admin", Confidence::High);
}

#[test]
fn spans_report_the_secret_position() {
    let tok = format!("{}{}", "ghp_", synth(ALNUM, 36, 5));
    let line = format!("{{\"a\": \"{tok}\"}}");
    let f = check_line_gitleaks_spans(&line, 1);
    let (_, (s, e)) = f
        .iter()
        .find(|(x, _)| x.redacted_preview.starts_with("ghp_"))
        .expect("found");
    assert_eq!(&line[*s..*e], tok);
}
