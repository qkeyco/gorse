// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Where the CLI sends its own HTTPS calls: lease refresh, team report and
//! support upload.
//!
//! The default origin is `https://www.gorse.is`. The live site serves on
//! the `www` host and answers the bare `gorse.is` domain with a 307
//! redirect. Our HTTP client (ureq 2) is built with `.redirects(0)` at every
//! call site, and even with redirects enabled ureq 2 only re-sends 307/308
//! for GET, HEAD, OPTIONS and TRACE; a POST with a body gets the 307 handed
//! back as the response instead of being replayed. Either way a POST to the
//! bare domain never reaches the API, which is why the default uses `www`.
//!
//! `GORSE_API_ORIGIN` (or the older `HEDGEHOG_API_ORIGIN`) overrides the origin so an end-to-end test can point
//! the real binary at a staging deployment or a local listener.
//!
//! # Security
//!
//! The override only changes where the CLI sends its own lease refresh, team
//! report and support upload. It never carries secrets beyond what those
//! calls already carry (the stored lease as a bearer token, the machine id,
//! the report or support bundle the user chose to send), and the lease
//! signature check against the built-in issuer public key still applies, so
//! pointing the CLI at a hostile server cannot grant a licence: the server can
//! only refuse or hand back a lease that fails verification. Plain `http` is
//! accepted only for loopback hosts so a mistyped override cannot downgrade a
//! real deployment to cleartext.

const DEFAULT_ORIGIN: &str = "https://www.gorse.is";
#[cfg(test)]
const ORIGIN_ENV: &str = "GORSE_API_ORIGIN";

/// The origin the CLI talks to: `GORSE_API_ORIGIN` (else `HEDGEHOG_API_ORIGIN`)
/// when set and valid,
/// otherwise `https://www.gorse.is`. An invalid override is reported once
/// on stderr and ignored; this never panics.
pub fn api_origin() -> String {
    match crate::config::env_var_named("API_ORIGIN") {
        Some((name, value)) if !value.trim().is_empty() => match parse_origin(&value) {
            Ok(origin) => origin,
            Err(reason) => {
                eprintln!("warning: ignoring {name} ({reason}); using {DEFAULT_ORIGIN}");
                DEFAULT_ORIGIN.to_string()
            }
        },
        _ => DEFAULT_ORIGIN.to_string(),
    }
}

/// Join the configured origin with an absolute path such as `/api/refresh`.
pub fn api_url(path: &str) -> String {
    api_url_with(&api_origin(), path)
}

/// Join an already validated origin with an absolute path.
pub fn api_url_with(origin: &str, path: &str) -> String {
    let origin = origin.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{origin}/{path}")
}

/// Validate a candidate origin and return it with any trailing slash removed.
///
/// Accepted: an absolute URL with scheme `https`, or `http` when the host is
/// `localhost`, `127.0.0.1` or `[::1]`; an optional port; an optional path
/// prefix. Rejected: userinfo, query, fragment, whitespace, control
/// characters and empty hosts.
pub fn parse_origin(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("value is empty".into());
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("value contains whitespace or control characters".into());
    }
    let (scheme, rest) = value
        .split_once("://")
        .ok_or("value is not an absolute URL")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(format!(
            "scheme must be https (or http for loopback), got {scheme:?}"
        ));
    }
    if rest.contains('?') {
        return Err("a query string is not allowed".into());
    }
    if rest.contains('#') {
        return Err("a fragment is not allowed".into());
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, String::new()),
    };
    if authority.contains('@') {
        return Err("userinfo is not allowed".into());
    }
    if authority.is_empty() {
        return Err("host is missing".into());
    }
    let host = host_of(authority)?;
    if scheme == "http" && !is_loopback(&host) {
        return Err(format!(
            "http is only allowed for localhost, 127.0.0.1 or [::1], got {host:?}"
        ));
    }
    let path = path.trim_end_matches('/');
    Ok(format!(
        "{scheme}://{}{path}",
        authority.to_ascii_lowercase()
    ))
}

/// Extract the host from `host[:port]`, accepting bracketed IPv6 literals.
fn host_of(authority: &str) -> Result<String, String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or("unterminated IPv6 literal")?;
        if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Err("invalid IPv6 literal".into());
        }
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or("invalid characters after IPv6 host")?,
            ),
        };
        (format!("[{}]", inner.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err("host contains invalid characters".into());
        }
        (host.to_ascii_lowercase(), port)
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("port is not a number".into());
        }
        if port.parse::<u32>().map_or(true, |p| p == 0 || p > 65535) {
            return Err("port is out of range".into());
        }
    }
    Ok(host)
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Environment variables are process-wide; serialise the tests that set one.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(ORIGIN_ENV).ok();
        match value {
            Some(value) => std::env::set_var(ORIGIN_ENV, value),
            None => std::env::remove_var(ORIGIN_ENV),
        }
        let result = body();
        match previous {
            Some(value) => std::env::set_var(ORIGIN_ENV, value),
            None => std::env::remove_var(ORIGIN_ENV),
        }
        result
    }

    #[test]
    fn default_origin_uses_www() {
        with_env(None, || {
            assert_eq!(api_origin(), "https://www.gorse.is");
            assert_eq!(api_url("/api/refresh"), "https://www.gorse.is/api/refresh");
        });
        with_env(Some("   "), || {
            assert_eq!(api_origin(), "https://www.gorse.is");
        });
    }

    #[test]
    fn valid_https_override_is_used() {
        with_env(Some("https://staging.gorse.is"), || {
            assert_eq!(
                api_url("/api/team/report"),
                "https://staging.gorse.is/api/team/report"
            );
        });
        with_env(Some("https://preview-42.vercel.app:8443/base/"), || {
            assert_eq!(
                api_url("/api/support/upload"),
                "https://preview-42.vercel.app:8443/base/api/support/upload"
            );
        });
    }

    #[test]
    fn http_is_allowed_only_for_loopback() {
        assert_eq!(
            parse_origin("http://127.0.0.1:4321").unwrap(),
            "http://127.0.0.1:4321"
        );
        assert_eq!(
            parse_origin("http://localhost").unwrap(),
            "http://localhost"
        );
        assert_eq!(
            parse_origin("http://LOCALHOST:80").unwrap(),
            "http://localhost:80"
        );
        assert_eq!(
            parse_origin("http://[::1]:9000").unwrap(),
            "http://[::1]:9000"
        );
        assert!(parse_origin("http://gorse.is").is_err());
        assert!(parse_origin("http://127.0.0.2").is_err());
        assert!(parse_origin("http://localhost.evil.example").is_err());
        assert!(parse_origin("http://[::2]").is_err());
    }

    #[test]
    fn invalid_overrides_are_rejected() {
        for value in [
            "https://user:pw@gorse.is",
            "https://user@gorse.is",
            "https://gorse.is/?x=1",
            "https://gorse.is/#frag",
            "ftp://gorse.is",
            "gorse.is",
            "https://",
            "https://host name",
            "https://gorse.is:notaport",
            "https://gorse.is:0",
            "https://gorse.is:70000",
            "https://[::1",
            "file:///etc/passwd",
        ] {
            assert!(parse_origin(value).is_err(), "{value:?} must be rejected");
        }
    }

    #[test]
    fn invalid_override_falls_back_to_default_without_panicking() {
        with_env(Some("http://evil.example.com"), || {
            assert_eq!(api_origin(), "https://www.gorse.is");
        });
        with_env(Some("https://user@gorse.is"), || {
            assert_eq!(api_url("/api/refresh"), "https://www.gorse.is/api/refresh");
        });
    }

    #[test]
    fn trailing_slash_is_stripped() {
        assert_eq!(
            parse_origin("https://gorse.is/").unwrap(),
            "https://gorse.is"
        );
        assert_eq!(
            parse_origin("https://gorse.is/staging///").unwrap(),
            "https://gorse.is/staging"
        );
        assert_eq!(
            api_url_with("https://gorse.is/", "/api/refresh"),
            "https://gorse.is/api/refresh"
        );
        assert_eq!(
            api_url_with("https://gorse.is", "api/refresh"),
            "https://gorse.is/api/refresh"
        );
    }
}
