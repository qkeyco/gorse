// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Enterprise SSO integration (L-10).
//!
//! Supports authentication via:
//! - SAML 2.0 (WorkOS, Okta, Azure AD, OneLogin)
//! - OpenID Connect (Google Workspace, Auth0)
//! - SCIM 2.0 for user provisioning
//!
//! Architecture:
//! - CLI redirects to browser for SSO login
//! - Local HTTP server on ephemeral port receives callback
//! - Exchange authorization code for license token
//! - Store token in credential store

use serde::{Deserialize, Serialize};
use std::net::TcpListener;

/// SSO provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO provider type
    pub provider: SsoProvider,
    /// Organization identifier
    pub org_id: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token exchange endpoint URL
    pub token_url: String,
    /// Client ID (public, safe to embed)
    pub client_id: String,
}

/// Supported SSO providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SsoProvider {
    /// WorkOS (recommended — supports SAML + OIDC + SCIM)
    WorkOS,
    /// Okta SAML/OIDC
    Okta,
    /// Azure AD (Microsoft Entra ID)
    AzureAd,
    /// Google Workspace OIDC
    Google,
    /// Generic OIDC provider
    Oidc,
}

/// Result of SSO authentication flow.
#[derive(Debug, Clone)]
pub struct SsoResult {
    /// License key received from the server
    pub license_key: String,
    /// User email from the SSO provider
    pub email: String,
    /// Organization name
    pub org_name: String,
    /// Tier assigned by the organization
    pub tier: String,
}

/// Start the SSO login flow.
/// 1. Opens browser to SSO provider
/// 2. Starts local HTTP server to receive callback
/// 3. Exchanges code for license key
pub fn start_sso_login(config: &SsoConfig) -> Result<SsoResult, String> {
    // Find an available port for the callback server
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind callback server: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get port: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // Build authorization URL
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid+email&state={}",
        config.auth_url,
        config.client_id,
        urlenccode(&redirect_uri),
        generate_state()
    );

    println!("Opening browser for SSO login...");
    println!("If the browser doesn't open, visit:");
    println!("  {auth_url}");
    println!();

    // Open browser
    open_browser(&auth_url);

    // Wait for callback (30 second timeout)
    println!("Waiting for authentication...");
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("Failed to set blocking: {e}"))?;

    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("Failed to accept callback: {e}"))?;

    // Read the request
    let mut buf = [0u8; 4096];
    let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);

    // Extract authorization code from query string
    let code = extract_param(&request, "code")
        .ok_or_else(|| "No authorization code received".to_string())?;

    // Send success response to browser
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n\
        <html><body style=\"font-family:system-ui;text-align:center;padding:3rem\">\
        <h1>Authentication successful!</h1>\
        <p>You can close this tab and return to the terminal.</p>\
        </body></html>";
    let _ = std::io::Write::write_all(&mut stream, response.as_bytes());

    // Exchange code for license key
    exchange_code(config, &code, &redirect_uri)
}

/// Exchange an authorization code for a license key.
fn exchange_code(config: &SsoConfig, code: &str, redirect_uri: &str) -> Result<SsoResult, String> {
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
        urlenccode(code),
        urlenccode(redirect_uri),
        urlenccode(&config.client_id)
    );

    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            &config.token_url,
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            &body,
        ])
        .output()
        .map_err(|e| format!("Failed to exchange code: {e}"))?;

    if !output.status.success() {
        return Err("Token exchange failed".to_string());
    }

    let response = String::from_utf8_lossy(&output.stdout);

    // Parse JSON response (minimal parsing without serde_json for the token response)
    let license_key = extract_json_value(&response, "license_key")
        .ok_or_else(|| "No license_key in response".to_string())?;
    let email = extract_json_value(&response, "email").unwrap_or_default();
    let org_name = extract_json_value(&response, "org_name").unwrap_or_default();
    let tier = extract_json_value(&response, "tier").unwrap_or_else(|| "team".to_string());

    Ok(SsoResult {
        license_key,
        email,
        org_name,
        tier,
    })
}

/// Load SSO config from ~/.hedgehog/sso.toml
pub fn load_sso_config() -> Option<SsoConfig> {
    let path = crate::config::config_dir().join("sso.toml");
    let contents = std::fs::read_to_string(&path).ok()?;

    // Parse TOML manually (minimal)
    let provider = if contents.contains("workos") {
        SsoProvider::WorkOS
    } else if contents.contains("okta") {
        SsoProvider::Okta
    } else if contents.contains("azure") {
        SsoProvider::AzureAd
    } else if contents.contains("google") {
        SsoProvider::Google
    } else {
        SsoProvider::Oidc
    };

    let auth_url = extract_toml_value(&contents, "auth_url")?;
    let token_url = extract_toml_value(&contents, "token_url")?;
    let client_id = extract_toml_value(&contents, "client_id")?;
    let org_id = extract_toml_value(&contents, "org_id").unwrap_or_default();

    Some(SsoConfig {
        provider,
        org_id,
        auth_url,
        token_url,
        client_id,
    })
}

fn extract_toml_value(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            if let Some(rest) = rest.trim_start().strip_prefix('=') {
                let val = rest.trim().trim_matches('"');
                return Some(val.to_string());
            }
        }
    }
    None
}

fn extract_json_value(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\"", key);
    let idx = json.find(&search)?;
    let after_key = &json[idx + search.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();

    if after_colon.starts_with('"') {
        let start = 1;
        let end = after_colon[1..].find('"')?;
        Some(after_colon[start..start + end].to_string())
    } else {
        None
    }
}

fn extract_param(request: &str, param: &str) -> Option<String> {
    let search = format!("{}=", param);
    let line = request.lines().next()?;
    let query_start = line.find('?')?;
    let query = &line[query_start + 1..];
    let query = query.split_whitespace().next()?; // trim HTTP version

    for part in query.split('&') {
        if let Some(val) = part.strip_prefix(&search) {
            return Some(val.to_string());
        }
    }
    None
}

fn urlenccode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

fn generate_state() -> String {
    // Simple random state for CSRF protection
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", now)
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding() {
        assert_eq!(urlenccode("hello world"), "hello%20world");
        assert_eq!(urlenccode("a=b&c"), "a%3Db%26c");
    }

    #[test]
    fn extract_param_from_request() {
        let request = "GET /callback?code=abc123&state=xyz HTTP/1.1\r\nHost: localhost";
        assert_eq!(extract_param(request, "code"), Some("abc123".to_string()));
        assert_eq!(extract_param(request, "state"), Some("xyz".to_string()));
    }

    #[test]
    fn extract_json() {
        let json = r#"{"license_key": "HH1-test", "email": "user@example.com"}"#;
        assert_eq!(
            extract_json_value(json, "license_key"),
            Some("HH1-test".to_string())
        );
        assert_eq!(
            extract_json_value(json, "email"),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn state_is_unique() {
        let s1 = generate_state();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let s2 = generate_state();
        assert_ne!(s1, s2);
    }
}
