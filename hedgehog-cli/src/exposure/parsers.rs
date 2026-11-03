// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Small, dependency-free parsers for the configuration formats credential
//! discovery has to read: INI (AWS), a YAML subset (kubeconfig, gh hosts),
//! OpenSSH keys and certificates. None of them are general purpose; each
//! is just enough for the files Gorse inspects and all of them fail
//! closed on anything unexpected.

use base64::Engine;
use std::collections::BTreeMap;

// ─── INI ─────────────────────────────────────────────────────────────────────

/// Parsed INI: section name → (key → value). Keys are lower-cased.
pub type Ini = Vec<(String, BTreeMap<String, String>)>;

pub fn parse_ini(text: &str) -> Ini {
    let mut out: Ini = Vec::new();
    let mut current: Option<(String, BTreeMap<String, String>)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                out.push(section);
            }
            current = Some((line[1..line.len() - 1].trim().to_string(), BTreeMap::new()));
            continue;
        }
        // configparser (which the AWS CLI uses) accepts `key = value` and
        // `key: value`; whichever delimiter comes first separates the key.
        let delimiter = line.find(['=', ':']);
        if let Some((k, v)) = delimiter.map(|i| (&line[..i], &line[i + 1..])) {
            if let Some((_, map)) = current.as_mut() {
                map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    if let Some(section) = current.take() {
        out.push(section);
    }
    out
}

/// The sections of an INI text that hold a line the parser cannot read:
/// not blank, not a comment, not a `[section]` header, not `key = value` or
/// `key: value`, and not an indented continuation of the previous value.
/// Lines before the first section are reported under `""`. Each section is
/// listed once, in file order. [`parse_ini`] drops such lines silently;
/// callers use this to report the section as not interpreted.
pub fn ini_malformed_sections(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut after_key = false;
    for raw in text.lines() {
        let raw = raw.trim_start_matches('\u{feff}');
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_string();
            after_key = false;
            continue;
        }
        let continuation = after_key && raw.starts_with([' ', '\t']);
        let key_value = line
            .find(['=', ':'])
            .is_some_and(|i| !line[..i].trim().is_empty());
        if key_value {
            after_key = true;
        } else if !continuation && !out.contains(&current) {
            out.push(current.clone());
        }
    }
    out
}

// ─── netrc ───────────────────────────────────────────────────────────────────

/// One `machine` (or `default`) entry of a .netrc file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrcEntry {
    /// The machine name; `default` for the default entry, and
    /// `(before any machine)` for tokens that precede every entry.
    pub machine: String,
    pub login: Option<String>,
    /// `false` when the entry holds a token that is not a netrc keyword
    /// or a keyword without its value: the entry was not understood.
    pub well_formed: bool,
}

/// Parse a .netrc file into its entries. Comment lines (`#`) are skipped,
/// and `macdef` bodies run to the next blank line, as in ftp(1). Tokens the
/// format does not define mark the entry they appear in as not well formed
/// rather than being skipped silently.
pub fn parse_netrc(text: &str) -> Vec<NetrcEntry> {
    let mut entries: Vec<NetrcEntry> = Vec::new();
    let mut in_macdef = false;
    let mut pending: Option<&str> = None;
    let malformed_current = |entries: &mut Vec<NetrcEntry>| match entries.last_mut() {
        Some(e) => e.well_formed = false,
        None => entries.push(NetrcEntry {
            machine: "(before any machine)".into(),
            login: None,
            well_formed: false,
        }),
    };
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}');
        if in_macdef {
            if line.trim().is_empty() {
                in_macdef = false;
            }
            continue;
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        for token in line.split_whitespace() {
            if in_macdef {
                // The macro name; its body starts on the next line.
                break;
            }
            if let Some(keyword) = pending.take() {
                match keyword {
                    "machine" => entries.push(NetrcEntry {
                        machine: token.to_string(),
                        login: None,
                        well_formed: true,
                    }),
                    "login" => match entries.last_mut() {
                        Some(e) => e.login = Some(token.to_string()),
                        None => malformed_current(&mut entries),
                    },
                    _ => {
                        if entries.is_empty() {
                            malformed_current(&mut entries);
                        }
                    }
                }
                continue;
            }
            match token {
                "machine" | "login" | "password" | "account" => pending = Some(token),
                "default" => entries.push(NetrcEntry {
                    machine: "default".into(),
                    login: None,
                    well_formed: true,
                }),
                "macdef" => in_macdef = true,
                _ => malformed_current(&mut entries),
            }
        }
    }
    match pending {
        Some("machine") => entries.push(NetrcEntry {
            machine: "(unnamed)".into(),
            login: None,
            well_formed: false,
        }),
        Some(_) => malformed_current(&mut entries),
        None => {}
    }
    entries
}

// ─── YAML subset ─────────────────────────────────────────────────────────────

/// Minimal YAML value: enough for kubeconfig, gh hosts.yml and glab config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yaml {
    Str(String),
    Map(Vec<(String, Yaml)>),
    List(Vec<Yaml>),
    Null,
}

impl Yaml {
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Yaml::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn list(&self, key: &str) -> &[Yaml] {
        match self.get(key) {
            Some(Yaml::List(l)) => l,
            _ => &[],
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn entries(&self) -> &[(String, Yaml)] {
        match self {
            Yaml::Map(m) => m,
            _ => &[],
        }
    }
}

struct Line {
    indent: usize,
    text: String,
}

/// Parse a block-style YAML document. Supports maps, lists of scalars and
/// lists of maps, quoted scalars, inline `[]`/`{}` empties, comments, and
/// single-line flow collections (`key: {a: b, c: d}`, `key: [x, y]`,
/// nested, with quoted strings). Flow collections spanning several lines,
/// anchors, multi-line scalars and tags are not supported and are returned
/// as plain strings; callers that find no credential in a non-empty file
/// report it as a format they could not interpret.
pub fn parse_yaml(text: &str) -> Yaml {
    let lines: Vec<Line> = text
        .lines()
        .filter_map(|raw| {
            let without_comment = strip_comment(raw);
            let trimmed = without_comment.trim_end();
            if trimmed.trim().is_empty() || trimmed.trim() == "---" {
                return None;
            }
            let indent = trimmed.chars().take_while(|c| *c == ' ').count();
            Some(Line {
                indent,
                text: trimmed[indent..].to_string(),
            })
        })
        .collect();
    let mut pos = 0;
    parse_block(&lines, &mut pos, 0)
}

fn strip_comment(line: &str) -> &str {
    // A '#' starts a comment only at line start or after whitespace, and
    // not inside quotes.
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && (i == 0 || bytes[i - 1] == b' ') => {
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

fn parse_block(lines: &[Line], pos: &mut usize, indent: usize) -> Yaml {
    if *pos >= lines.len() {
        return Yaml::Null;
    }
    if lines[*pos].text.starts_with("- ") || lines[*pos].text == "-" {
        parse_list(lines, pos, lines[*pos].indent)
    } else {
        parse_map(lines, pos, indent.max(lines[*pos].indent))
    }
}

fn parse_map(lines: &[Line], pos: &mut usize, indent: usize) -> Yaml {
    let mut entries = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < indent || line.text.starts_with("- ") || line.text == "-" {
            break;
        }
        if line.indent > indent {
            // Unexpected deeper indent without a key: skip it.
            *pos += 1;
            continue;
        }
        let Some((key, rest)) = split_key(&line.text) else {
            *pos += 1;
            continue;
        };
        *pos += 1;
        let value = if rest.is_empty() {
            if *pos < lines.len()
                && (lines[*pos].indent > indent
                    || (lines[*pos].indent == indent && lines[*pos].text.starts_with("- ")))
            {
                parse_block(lines, pos, lines[*pos].indent)
            } else {
                Yaml::Null
            }
        } else {
            scalar(rest)
        };
        entries.push((key, value));
    }
    Yaml::Map(entries)
}

fn parse_list(lines: &[Line], pos: &mut usize, indent: usize) -> Yaml {
    let mut items = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent != indent || !(line.text.starts_with("- ") || line.text == "-") {
            if line.indent < indent {
                break;
            }
            if line.indent > indent {
                *pos += 1;
                continue;
            }
            break;
        }
        let rest = line.text[1..].trim_start();
        let item_indent = indent + 2;
        if rest.is_empty() {
            *pos += 1;
            items.push(parse_block(lines, pos, item_indent));
            continue;
        }
        if let Some((key, value_text)) = split_key(rest) {
            // Map item whose first key is on the dash line. Build a synthetic
            // first entry, then continue the map at the item indent.
            *pos += 1;
            let first_value = if value_text.is_empty() {
                if *pos < lines.len() && lines[*pos].indent > item_indent {
                    parse_block(lines, pos, lines[*pos].indent)
                } else {
                    Yaml::Null
                }
            } else {
                scalar(value_text)
            };
            let mut map_entries = vec![(key, first_value)];
            if *pos < lines.len()
                && lines[*pos].indent == item_indent
                && !lines[*pos].text.starts_with("- ")
            {
                if let Yaml::Map(more) = parse_map(lines, pos, item_indent) {
                    map_entries.extend(more);
                }
            }
            items.push(Yaml::Map(map_entries));
        } else {
            *pos += 1;
            items.push(scalar(rest));
        }
    }
    Yaml::List(items)
}

fn split_key(text: &str) -> Option<(String, &str)> {
    // key: value — the colon must be followed by space or end of line, and
    // must not be inside quotes (URLs like https://x are values, not keys).
    // A line that opens a flow collection is a value, not a key.
    if text.starts_with('{') || text.starts_with('[') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut in_quote: Option<u8> = None;
    for i in 0..bytes.len() {
        match (bytes[i], in_quote) {
            (b'"', None) | (b'\'', None) => in_quote = Some(bytes[i]),
            (c, Some(q)) if c == q => in_quote = None,
            (b':', None) if i + 1 == bytes.len() || bytes[i + 1] == b' ' => {
                let key = unquote(&text[..i]);
                if key.is_empty() {
                    return None;
                }
                return Some((key, text[i + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

fn scalar(text: &str) -> Yaml {
    let t = text.trim();
    if t == "[]" || t == "{}" || t == "~" || t == "null" {
        return Yaml::Null;
    }
    if (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']')) {
        if let Some(v) = parse_flow(t) {
            return v;
        }
    }
    Yaml::Str(unquote(t))
}

/// Deepest flow nesting accepted; anything deeper stays a plain string.
const FLOW_MAX_DEPTH: usize = 8;

/// Parse a single-line flow collection. `None` on anything malformed, so
/// the caller keeps the text as a string rather than guessing.
fn parse_flow(text: &str) -> Option<Yaml> {
    let chars: Vec<char> = text.chars().collect();
    let mut pos = 0;
    let value = flow_value(&chars, &mut pos, 0)?;
    flow_skip_ws(&chars, &mut pos);
    (pos == chars.len()).then_some(value)
}

fn flow_skip_ws(c: &[char], pos: &mut usize) {
    while *pos < c.len() && c[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn flow_value(c: &[char], pos: &mut usize, depth: usize) -> Option<Yaml> {
    if depth > FLOW_MAX_DEPTH {
        return None;
    }
    flow_skip_ws(c, pos);
    match c.get(*pos)? {
        '{' => flow_map(c, pos, depth),
        '[' => flow_seq(c, pos, depth),
        '"' | '\'' => flow_quoted(c, pos).map(Yaml::Str),
        _ => {
            let text = flow_plain(c, pos, false);
            Some(match text.as_str() {
                "" | "~" | "null" => Yaml::Null,
                _ => Yaml::Str(text),
            })
        }
    }
}

/// A plain scalar inside a flow collection: ends at `,`, `]` or `}`, and a
/// key also at a `:` followed by a space or a closing character.
fn flow_plain(c: &[char], pos: &mut usize, key: bool) -> String {
    let start = *pos;
    while *pos < c.len() {
        let ch = c[*pos];
        if matches!(ch, ',' | ']' | '}') {
            break;
        }
        if key
            && ch == ':'
            && c.get(*pos + 1)
                .is_none_or(|n| n.is_whitespace() || matches!(n, ',' | '}'))
        {
            break;
        }
        *pos += 1;
    }
    c[start..*pos].iter().collect::<String>().trim().to_string()
}

fn flow_quoted(c: &[char], pos: &mut usize) -> Option<String> {
    let quote = c[*pos];
    *pos += 1;
    let mut out = String::new();
    while *pos < c.len() {
        let ch = c[*pos];
        *pos += 1;
        if ch == quote {
            // '' inside single quotes is one quote.
            if quote == '\'' && c.get(*pos) == Some(&'\'') {
                out.push('\'');
                *pos += 1;
                continue;
            }
            return Some(out);
        }
        if quote == '"' && ch == '\\' {
            let escaped = *c.get(*pos)?;
            *pos += 1;
            out.push(match escaped {
                'n' => '\n',
                't' => '\t',
                other => other,
            });
            continue;
        }
        out.push(ch);
    }
    None
}

fn flow_map(c: &[char], pos: &mut usize, depth: usize) -> Option<Yaml> {
    *pos += 1; // '{'
    let mut entries = Vec::new();
    loop {
        flow_skip_ws(c, pos);
        match c.get(*pos)? {
            '}' => {
                *pos += 1;
                return Some(Yaml::Map(entries));
            }
            ',' => {
                *pos += 1;
                continue;
            }
            _ => {}
        }
        let key = match c[*pos] {
            '"' | '\'' => flow_quoted(c, pos)?,
            '{' | '[' => return None,
            _ => flow_plain(c, pos, true),
        };
        if key.is_empty() {
            return None;
        }
        flow_skip_ws(c, pos);
        let value = if c.get(*pos) == Some(&':') {
            *pos += 1;
            flow_value(c, pos, depth + 1)?
        } else {
            Yaml::Null
        };
        entries.push((key, value));
        flow_skip_ws(c, pos);
        match c.get(*pos)? {
            ',' => *pos += 1,
            '}' => {}
            _ => return None,
        }
    }
}

fn flow_seq(c: &[char], pos: &mut usize, depth: usize) -> Option<Yaml> {
    *pos += 1; // '['
    let mut items = Vec::new();
    loop {
        flow_skip_ws(c, pos);
        match c.get(*pos)? {
            ']' => {
                *pos += 1;
                return Some(Yaml::List(items));
            }
            ',' => {
                *pos += 1;
                continue;
            }
            _ => {}
        }
        items.push(flow_value(c, pos, depth + 1)?);
        flow_skip_ws(c, pos);
        match c.get(*pos)? {
            ',' => *pos += 1,
            ']' => {}
            _ => return None,
        }
    }
}

// ─── OpenSSH keys and certificates ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPrivateKeyInfo {
    pub format: &'static str,
    pub encrypted: Option<bool>,
}

/// Classify the text of a private key file without parsing the key.
pub fn inspect_ssh_private_key(text: &str) -> Option<SshPrivateKeyInfo> {
    let first = text.lines().find(|l| !l.trim().is_empty())?.trim();
    if first == "-----BEGIN OPENSSH PRIVATE KEY-----" {
        let body: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(|l| l.trim())
            .collect();
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .ok()
            .and_then(|blob| openssh_kdf_name(&blob))
            .map(|kdf| kdf != "none");
        return Some(SshPrivateKeyInfo {
            format: "openssh",
            encrypted,
        });
    }
    if first.starts_with("-----BEGIN ") && first.contains("PRIVATE KEY") {
        let encrypted = text.contains("Proc-Type: 4,ENCRYPTED") || first.contains("ENCRYPTED");
        return Some(SshPrivateKeyInfo {
            format: "pem",
            encrypted: Some(encrypted),
        });
    }
    if first.starts_with("PuTTY-User-Key-File") {
        let encrypted = text
            .lines()
            .any(|l| l.starts_with("Encryption:") && !l.contains("none"));
        return Some(SshPrivateKeyInfo {
            format: "putty",
            encrypted: Some(encrypted),
        });
    }
    None
}

fn openssh_kdf_name(blob: &[u8]) -> Option<String> {
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    if !blob.starts_with(MAGIC) {
        return None;
    }
    let mut cursor = Cursor::new(&blob[MAGIC.len()..]);
    let _cipher = cursor.string()?;
    let kdf = cursor.string()?;
    Some(String::from_utf8_lossy(kdf).to_string())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.data.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Some(u64::from_be_bytes(arr))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let s = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificateInfo {
    pub key_type: String,
    pub serial: u64,
    /// 1 = user certificate, 2 = host certificate.
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub extensions: Vec<String>,
    pub critical_options: Vec<String>,
}

/// Parse an OpenSSH certificate line (`ssh-ed25519-cert-v01@openssh.com AAAA… comment`).
pub fn parse_ssh_certificate(line: &str) -> Option<SshCertificateInfo> {
    let mut parts = line.split_whitespace();
    let key_type = parts.next()?;
    if !key_type.contains("-cert-") {
        return None;
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    let mut c = Cursor::new(&blob);
    let inner_type = String::from_utf8_lossy(c.string()?).to_string();
    let _nonce = c.string()?;
    // Public key fields differ per algorithm.
    if inner_type.contains("ed25519") {
        let _pk = c.string()?;
    } else if inner_type.contains("ecdsa") {
        let _curve = c.string()?;
        let _pk = c.string()?;
    } else if inner_type.contains("rsa") {
        let _e = c.string()?;
        let _n = c.string()?;
    } else {
        return None;
    }
    let serial = c.u64()?;
    let cert_type = c.u32()?;
    let key_id = String::from_utf8_lossy(c.string()?).to_string();
    let principals = parse_string_list(c.string()?);
    let valid_after = c.u64()?;
    let valid_before = c.u64()?;
    let critical_options = parse_name_list(c.string()?);
    let extensions = parse_name_list(c.string()?);
    Some(SshCertificateInfo {
        key_type: inner_type,
        serial,
        cert_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        extensions,
        critical_options,
    })
}

fn parse_string_list(buf: &[u8]) -> Vec<String> {
    let mut c = Cursor::new(buf);
    let mut out = Vec::new();
    while let Some(s) = c.string() {
        out.push(String::from_utf8_lossy(s).to_string());
    }
    out
}

/// name/data pairs: only the names are kept.
fn parse_name_list(buf: &[u8]) -> Vec<String> {
    let mut c = Cursor::new(buf);
    let mut out = Vec::new();
    while let Some(name) = c.string() {
        out.push(String::from_utf8_lossy(name).to_string());
        if c.string().is_none() {
            break;
        }
    }
    out
}

/// SHA256 fingerprint of a public key line, as `ssh-keygen -l` prints it.
pub fn ssh_public_key_fingerprint(line: &str) -> Option<String> {
    use sha2::Digest;
    let mut parts = line.split_whitespace();
    let _type = parts.next()?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    let digest = sha2::Sha256::digest(&blob);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_sections_and_keys() {
        let ini = parse_ini("[default]\naws_access_key_id = AKIAEXAMPLE\n; comment\n[profile prod]\nrole_arn=arn:aws:iam::123:role/Admin\nsource_profile = default\n");
        assert_eq!(ini.len(), 2);
        assert_eq!(ini[0].0, "default");
        assert_eq!(ini[0].1["aws_access_key_id"], "AKIAEXAMPLE");
        assert_eq!(ini[1].0, "profile prod");
        assert_eq!(ini[1].1["role_arn"], "arn:aws:iam::123:role/Admin");
    }

    const KUBECONFIG: &str = r#"apiVersion: v1
kind: Config
current-context: prod-admin
clusters:
- cluster:
    server: https://1.2.3.4:6443
    certificate-authority-data: QUJD
  name: prod
- name: dev
  cluster:
    server: https://dev.example.com
contexts:
- context:
    cluster: prod
    user: alice
    namespace: payments
  name: prod-admin
users:
- name: alice
  user:
    token: not-a-real-token-value
- name: bob
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args:
      - eks
      - get-token
      - --cluster-name
      - prod
"#;

    #[test]
    fn yaml_kubeconfig_shape() {
        let y = parse_yaml(KUBECONFIG);
        assert_eq!(y.str("current-context"), Some("prod-admin"));
        let clusters = y.list("clusters");
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].str("name"), Some("prod"));
        assert_eq!(
            clusters[0].get("cluster").unwrap().str("server"),
            Some("https://1.2.3.4:6443")
        );
        assert_eq!(clusters[1].str("name"), Some("dev"));
        assert_eq!(
            clusters[1].get("cluster").unwrap().str("server"),
            Some("https://dev.example.com")
        );
        let ctx = &y.list("contexts")[0];
        assert_eq!(ctx.str("name"), Some("prod-admin"));
        assert_eq!(
            ctx.get("context").unwrap().str("namespace"),
            Some("payments")
        );
        let users = y.list("users");
        assert_eq!(
            users[0].get("user").unwrap().str("token"),
            Some("not-a-real-token-value")
        );
        let exec = users[1].get("user").unwrap().get("exec").unwrap();
        assert_eq!(exec.str("command"), Some("aws"));
        let args: Vec<&str> = exec
            .list("args")
            .iter()
            .filter_map(|a| a.as_str())
            .collect();
        assert_eq!(args, vec!["eks", "get-token", "--cluster-name", "prod"]);
    }

    #[test]
    fn yaml_gh_hosts() {
        let y = parse_yaml("github.com:\n    user: alice\n    oauth_token: gho_notreal\n    git_protocol: https\n    users:\n        alice:\n            oauth_token: gho_notreal\nghe.example.com:\n    user: bob\n");
        assert_eq!(y.get("github.com").unwrap().str("user"), Some("alice"));
        assert_eq!(
            y.get("github.com").unwrap().str("oauth_token"),
            Some("gho_notreal")
        );
        assert_eq!(y.get("ghe.example.com").unwrap().str("user"), Some("bob"));
    }

    #[test]
    fn yaml_comments_quotes_and_empty_values() {
        let y = parse_yaml("a: \"x: y\" # comment\nb: 'q'\nc:\nd: []\n");
        assert_eq!(y.str("a"), Some("x: y"));
        assert_eq!(y.str("b"), Some("q"));
        assert_eq!(y.get("c"), Some(&Yaml::Null));
        assert_eq!(y.get("d"), Some(&Yaml::Null));
    }

    #[test]
    fn yaml_flow_collections_match_block_style() {
        let block = parse_yaml(
            "access-token: dop_v1_one\nauth-contexts:\n  work: dop_v1_two\n  \"home\": 'dop_v1_three'\ncontext: work\n",
        );
        let flow = parse_yaml(
            "access-token: dop_v1_one\nauth-contexts: {work: dop_v1_two, \"home\": 'dop_v1_three'}\ncontext: work\n",
        );
        assert_eq!(block, flow);
        assert_eq!(
            flow.get("auth-contexts").unwrap().str("home"),
            Some("dop_v1_three")
        );

        let y = parse_yaml(
            "args: [eks, \"get-token\", '--cluster-name']\nnested: {a: [x, y], b: {c: \"d, e\"}, url: https://h:6443}\nempty: {}\n",
        );
        let args: Vec<&str> = y.list("args").iter().filter_map(|a| a.as_str()).collect();
        assert_eq!(args, vec!["eks", "get-token", "--cluster-name"]);
        let nested = y.get("nested").unwrap();
        assert_eq!(nested.list("a").len(), 2);
        assert_eq!(nested.get("b").unwrap().str("c"), Some("d, e"));
        assert_eq!(nested.str("url"), Some("https://h:6443"));
        assert_eq!(y.get("empty"), Some(&Yaml::Null));

        // A list item that is a flow map is not split at its inner colon.
        let items = parse_yaml("items:\n- {name: a, token: b}\n- [1, 2]\n");
        assert_eq!(items.list("items")[0].str("token"), Some("b"));
        assert_eq!(
            items.list("items")[1],
            Yaml::List(vec![Yaml::Str("1".into()), Yaml::Str("2".into())])
        );

        // Malformed or multi-line flow stays a string: never a guess.
        assert_eq!(
            parse_yaml("a: {b: c\n").get("a"),
            Some(&Yaml::Str("{b: c".into()))
        );
        assert_eq!(
            parse_yaml("a: {b: c} d}\n").get("a"),
            Some(&Yaml::Str("{b: c} d}".into()))
        );
    }

    #[test]
    fn ini_accepts_colon_delimiter() {
        let ini = parse_ini(
            "[default]\naws_access_key_id: AKIAEXAMPLE\nrole_arn = arn:aws:iam::1:role/x\n",
        );
        assert_eq!(ini[0].1["aws_access_key_id"], "AKIAEXAMPLE");
        assert_eq!(ini[0].1["role_arn"], "arn:aws:iam::1:role/x");
    }

    #[test]
    fn yaml_garbage_does_not_panic() {
        for text in [
            "",
            ":",
            "- - -",
            "a:\n  - b:\n c",
            "\t\tx: y",
            "key: value\n- item",
            "[flow, seq]",
        ] {
            let _ = parse_yaml(text);
        }
    }

    #[test]
    fn ssh_private_key_classification() {
        let pem_enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            inspect_ssh_private_key(pem_enc).unwrap().encrypted,
            Some(true)
        );
        let pem_plain = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        assert_eq!(
            inspect_ssh_private_key(pem_plain).unwrap().encrypted,
            Some(false)
        );
        assert!(inspect_ssh_private_key("ssh-ed25519 AAAA comment").is_none());

        // Synthetic openssh-key-v1 header with kdf "bcrypt" and with "none".
        fn blob(kdf: &str) -> String {
            let mut b = b"openssh-key-v1\0".to_vec();
            for s in ["aes256-ctr", kdf] {
                b.extend((s.len() as u32).to_be_bytes());
                b.extend(s.as_bytes());
            }
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(b)
            )
        }
        assert_eq!(
            inspect_ssh_private_key(&blob("bcrypt")).unwrap().encrypted,
            Some(true)
        );
        assert_eq!(
            inspect_ssh_private_key(&blob("none")).unwrap().encrypted,
            Some(false)
        );
    }

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend((s.len() as u32).to_be_bytes());
        out.extend(s);
    }

    #[test]
    fn ssh_certificate_parse() {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519-cert-v01@openssh.com");
        put_string(&mut b, &[0u8; 32]); // nonce
        put_string(&mut b, &[1u8; 32]); // pk
        b.extend(42u64.to_be_bytes()); // serial
        b.extend(1u32.to_be_bytes()); // user cert
        put_string(&mut b, b"alice@laptop");
        let mut principals = Vec::new();
        put_string(&mut principals, b"alice");
        put_string(&mut principals, b"deploy");
        put_string(&mut b, &principals);
        b.extend(1_700_000_000u64.to_be_bytes());
        b.extend(1_700_003_600u64.to_be_bytes());
        put_string(&mut b, b""); // critical options
        let mut ext = Vec::new();
        put_string(&mut ext, b"permit-agent-forwarding");
        put_string(&mut ext, b"");
        put_string(&mut ext, b"permit-pty");
        put_string(&mut ext, b"");
        put_string(&mut b, &ext);
        put_string(&mut b, b""); // reserved
        put_string(&mut b, b"ca"); // signature key
        put_string(&mut b, b"sig");
        let line = format!(
            "ssh-ed25519-cert-v01@openssh.com {} alice@laptop",
            base64::engine::general_purpose::STANDARD.encode(&b)
        );
        let cert = parse_ssh_certificate(&line).unwrap();
        assert_eq!(cert.serial, 42);
        assert_eq!(cert.cert_type, 1);
        assert_eq!(cert.key_id, "alice@laptop");
        assert_eq!(cert.principals, vec!["alice", "deploy"]);
        assert_eq!(cert.valid_before, 1_700_003_600);
        assert_eq!(
            cert.extensions,
            vec!["permit-agent-forwarding", "permit-pty"]
        );
        assert!(parse_ssh_certificate("ssh-ed25519 AAAA").is_none());
        assert!(parse_ssh_certificate("ssh-ed25519-cert-v01@openssh.com AAAA").is_none());
    }

    #[test]
    fn ssh_fingerprint_matches_ssh_keygen_format() {
        // ssh-keygen -l on this key prints SHA256:... ; we only check shape and stability.
        let line =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test";
        let fp = ssh_public_key_fingerprint(line).unwrap();
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43);
        assert_eq!(fp, ssh_public_key_fingerprint(line).unwrap());
    }

    #[test]
    fn ini_malformed_sections_names_each_unreadable_section_once() {
        let text = "stray line\n[default]\nkey = v\n# comment\n; comment\n\n[prod]\naws_secret_access_key abc\nalso broken\n[nested]\ns3 =\n    max_concurrent_requests = 20\n    signature_version: s3v4\n[ok]\nk: v\n";
        assert_eq!(ini_malformed_sections(text), vec!["", "prod"]);
        // An indented line with no key before it is not a continuation.
        assert_eq!(ini_malformed_sections("[a]\n  orphan\n"), vec!["a"]);
        // `= value` has no key.
        assert_eq!(ini_malformed_sections("[a]\n= v\n"), vec!["a"]);
        assert!(ini_malformed_sections("\u{feff}[a]\nk = v\n").is_empty());
    }

    #[test]
    fn netrc_entries_and_malformed_entries() {
        let entries = parse_netrc(
            "# comment line\nmachine a.example.com login alice password x\nmacdef init\ncd /tmp\nput file\n\nmachine b.example.com\n  login bob\n  password y\n  account z\ndefault login anon password p\n",
        );
        let summary: Vec<(&str, Option<&str>, bool)> = entries
            .iter()
            .map(|e| (e.machine.as_str(), e.login.as_deref(), e.well_formed))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("a.example.com", Some("alice"), true),
                ("b.example.com", Some("bob"), true),
                ("default", Some("anon"), true),
            ]
        );
        let entries = parse_netrc("machine a login x passwd y\nmachine b login z\n");
        assert!(!entries[0].well_formed);
        assert!(entries[1].well_formed);
        let entries = parse_netrc("login x\n");
        assert_eq!(entries[0].machine, "(before any machine)");
        assert!(!entries[0].well_formed);
        let entries = parse_netrc("machine a login x\nmachine");
        assert_eq!(entries[1].machine, "(unnamed)");
        assert!(!entries[1].well_formed);
        let entries = parse_netrc("machine a login");
        assert!(!entries[0].well_formed);
    }
}
