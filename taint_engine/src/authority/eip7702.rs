// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! EIP-7702 (set-code transaction, type 0x04) analysis.
//!
//! An EIP-7702 authorization tuple lets an externally owned account install
//! a *delegation designator* (`0xef0100 || address`) as its code, so that
//! every call to the EOA executes the delegate's code with the EOA's storage
//! and balance. A signed authorization is therefore an account-control
//! operation: whoever chooses the delegate chooses what the wallet does.
//!
//! This module is strictly read-only. It parses authorization tuples (RLP,
//! full type-4 transactions and the JSON-ish shapes wallets print), inspects
//! an account's current code for an active delegation, and scores both
//! against a registry of reviewed delegate implementations.
//!
//! Invariants:
//! - Nothing here produces a signature or a transaction.
//! - Nothing here holds or reads a private key. Only public fields
//!   (chain id, delegate address, nonce, signature components) are kept.
//! - Malformed input returns [`ParseError`]; it never panics.
//! - No third-party dependencies: hex and RLP are implemented locally.

use super::scoring::Severity;
use super::Persistence;

/// Code prefix of an EIP-7702 delegation designator: `0xef0100`.
pub const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// Length of a delegation designator: 3-byte prefix + 20-byte address.
const DELEGATION_CODE_LEN: usize = DELEGATION_PREFIX.len() + 20;

/// Maximum nesting depth accepted by the RLP decoder. Authorization data is
/// at most three levels deep (transaction → authorization_list → tuple), so
/// this is generous while still bounding stack use on hostile input.
const MAX_RLP_DEPTH: usize = 16;

/// Maximum byte length of a signature component (`r` or `s`).
const MAX_SIGNATURE_COMPONENT_LEN: usize = 32;

/// One EIP-7702 authorization tuple:
/// `[chain_id, address, nonce, y_parity, r, s]`.
///
/// The signature components are optional so that an unsigned tuple (what a
/// wallet shows *before* asking for a signature) can be analysed too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// Chain the authorization is valid on; `0` means every chain.
    pub chain_id: u64,
    /// Delegate implementation the account's code will point at.
    pub address: [u8; 20],
    /// Account nonce the authorization is bound to.
    pub nonce: u64,
    pub y_parity: Option<u8>,
    /// Signature `r`, minimal big-endian bytes.
    pub r: Option<Vec<u8>>,
    /// Signature `s`, minimal big-endian bytes.
    pub s: Option<Vec<u8>>,
}

impl Authorization {
    /// `chain_id == 0` means the tuple is valid on any chain (EIP-7702).
    pub fn is_any_chain(&self) -> bool {
        self.chain_id == 0
    }

    /// Delegate address as 0x-prefixed lowercase hex.
    pub fn address_hex(&self) -> String {
        encode_hex(&self.address)
    }

    /// Both signature components are present.
    pub fn is_signed(&self) -> bool {
        self.r.is_some() && self.s.is_some()
    }
}

/// Why an input could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Hex text is malformed.
    Hex(String),
    /// RLP structure is malformed, truncated or non-canonical.
    Rlp(String),
    /// Structure is fine but a field has the wrong shape or value.
    Field(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Hex(m) => write!(f, "hex: {m}"),
            ParseError::Rlp(m) => write!(f, "rlp: {m}"),
            ParseError::Field(m) => write!(f, "field: {m}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Decode hex text into bytes. Accepts an optional `0x`/`0X` prefix, trims
/// surrounding whitespace, rejects odd length and non-hex characters.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, ParseError> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if body.len() & 1 == 1 {
        return Err(ParseError::Hex(format!("odd length ({})", body.len())));
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, ParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::Hex(format!(
            "invalid character {:?}",
            c as char
        ))),
    }
}

/// Encode bytes as 0x-prefixed lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse a 20-byte address from hex (with or without `0x`, any case).
fn address_from_hex(text: &str) -> Result<[u8; 20], ParseError> {
    let bytes = decode_hex(text)?;
    address_from_bytes(&bytes)
}

fn address_from_bytes(bytes: &[u8]) -> Result<[u8; 20], ParseError> {
    if bytes.len() != 20 {
        return Err(ParseError::Field(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// RLP (decoder only)
// ---------------------------------------------------------------------------

/// A decoded RLP item borrowing from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rlp<'a> {
    Bytes(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

impl<'a> Rlp<'a> {
    fn as_bytes(&self, what: &str) -> Result<&'a [u8], ParseError> {
        match self {
            Rlp::Bytes(b) => Ok(b),
            Rlp::List(_) => Err(ParseError::Field(format!(
                "{what}: expected bytes, found list"
            ))),
        }
    }

    fn as_list(&self, what: &str) -> Result<&[Rlp<'a>], ParseError> {
        match self {
            Rlp::List(items) => Ok(items),
            Rlp::Bytes(_) => Err(ParseError::Field(format!(
                "{what}: expected list, found bytes"
            ))),
        }
    }
}

/// Decode exactly one RLP item that must span the whole input.
fn rlp_decode_exact(input: &[u8]) -> Result<Rlp<'_>, ParseError> {
    let (item, used) = rlp_decode_item(input, 0)?;
    if used != input.len() {
        return Err(ParseError::Rlp(format!(
            "{} trailing byte(s) after item",
            input.len() - used
        )));
    }
    Ok(item)
}

/// Decode one item at the start of `input`; returns the item and the number
/// of bytes it occupied. Every slice access is bounds-checked so truncated
/// or garbage input yields `Err`, never a panic.
fn rlp_decode_item(input: &[u8], depth: usize) -> Result<(Rlp<'_>, usize), ParseError> {
    if depth > MAX_RLP_DEPTH {
        return Err(ParseError::Rlp("nesting too deep".to_string()));
    }
    let first = *input
        .first()
        .ok_or_else(|| ParseError::Rlp("unexpected end of input".to_string()))?;

    match first {
        0x00..=0x7f => Ok((Rlp::Bytes(&input[..1]), 1)),
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let payload = slice(input, 1, len)?;
            if len == 1 && payload[0] < 0x80 {
                return Err(ParseError::Rlp(
                    "non-canonical single byte string".to_string(),
                ));
            }
            Ok((Rlp::Bytes(payload), 1 + len))
        }
        0xb8..=0xbf => {
            let len_of_len = (first - 0xb7) as usize;
            let len = read_long_length(input, len_of_len)?;
            let payload = slice(input, 1 + len_of_len, len)?;
            Ok((Rlp::Bytes(payload), 1 + len_of_len + len))
        }
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            let payload = slice(input, 1, len)?;
            let items = rlp_decode_list_payload(payload, depth + 1)?;
            Ok((Rlp::List(items), 1 + len))
        }
        0xf8..=0xff => {
            let len_of_len = (first - 0xf7) as usize;
            let len = read_long_length(input, len_of_len)?;
            let payload = slice(input, 1 + len_of_len, len)?;
            let items = rlp_decode_list_payload(payload, depth + 1)?;
            Ok((Rlp::List(items), 1 + len_of_len + len))
        }
    }
}

/// Bounds-checked sub-slice `input[start..start+len]`.
fn slice(input: &[u8], start: usize, len: usize) -> Result<&[u8], ParseError> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| ParseError::Rlp("length overflow".to_string()))?;
    input.get(start..end).ok_or_else(|| {
        ParseError::Rlp(format!("truncated: need {end} bytes, have {}", input.len()))
    })
}

/// Read a long-form length (`len_of_len` big-endian bytes after the tag).
fn read_long_length(input: &[u8], len_of_len: usize) -> Result<usize, ParseError> {
    if len_of_len == 0 || len_of_len > std::mem::size_of::<usize>() {
        return Err(ParseError::Rlp(format!(
            "unsupported length-of-length {len_of_len}"
        )));
    }
    let len_bytes = slice(input, 1, len_of_len)?;
    if len_bytes[0] == 0 {
        return Err(ParseError::Rlp(
            "non-canonical length (leading zero)".to_string(),
        ));
    }
    let mut len: usize = 0;
    for b in len_bytes {
        len = (len << 8) | *b as usize;
    }
    if len < 56 {
        return Err(ParseError::Rlp(
            "non-canonical length (long form for short payload)".to_string(),
        ));
    }
    Ok(len)
}

fn rlp_decode_list_payload(payload: &[u8], depth: usize) -> Result<Vec<Rlp<'_>>, ParseError> {
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let (item, used) = rlp_decode_item(&payload[offset..], depth)?;
        items.push(item);
        offset += used;
    }
    Ok(items)
}

/// Interpret an RLP byte string as a minimal big-endian u64.
fn rlp_u64(item: &Rlp<'_>, what: &str) -> Result<u64, ParseError> {
    let bytes = item.as_bytes(what)?;
    bytes_to_u64(bytes, what)
}

fn bytes_to_u64(bytes: &[u8], what: &str) -> Result<u64, ParseError> {
    if bytes.len() > 8 {
        return Err(ParseError::Field(format!(
            "{what}: integer too large ({} bytes)",
            bytes.len()
        )));
    }
    if bytes.first() == Some(&0) {
        return Err(ParseError::Field(format!(
            "{what}: non-minimal integer (leading zero)"
        )));
    }
    let mut value: u64 = 0;
    for b in bytes {
        value = (value << 8) | *b as u64;
    }
    Ok(value)
}

/// Interpret an RLP byte string as a signature component.
fn rlp_signature_component(item: &Rlp<'_>, what: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = item.as_bytes(what)?;
    if bytes.len() > MAX_SIGNATURE_COMPONENT_LEN {
        return Err(ParseError::Field(format!(
            "{what}: signature component too long ({} bytes)",
            bytes.len()
        )));
    }
    if bytes.first() == Some(&0) {
        return Err(ParseError::Field(format!(
            "{what}: non-minimal integer (leading zero)"
        )));
    }
    Ok(bytes.to_vec())
}

fn authorization_from_rlp(item: &Rlp<'_>) -> Result<Authorization, ParseError> {
    let fields = item.as_list("authorization")?;
    if fields.len() != 3 && fields.len() != 6 {
        return Err(ParseError::Field(format!(
            "authorization tuple must have 3 or 6 items, got {}",
            fields.len()
        )));
    }
    let chain_id = rlp_u64(&fields[0], "chain_id")?;
    let address = address_from_bytes(fields[1].as_bytes("address")?)?;
    let nonce = rlp_u64(&fields[2], "nonce")?;

    let (y_parity, r, s) = if fields.len() == 6 {
        let parity = rlp_u64(&fields[3], "y_parity")?;
        if parity > u8::MAX as u64 {
            return Err(ParseError::Field(format!(
                "y_parity out of range: {parity}"
            )));
        }
        (
            Some(parity as u8),
            Some(rlp_signature_component(&fields[4], "r")?),
            Some(rlp_signature_component(&fields[5], "s")?),
        )
    } else {
        (None, None, None)
    };

    Ok(Authorization {
        chain_id,
        address,
        nonce,
        y_parity,
        r,
        s,
    })
}

/// Parse one authorization tuple from RLP bytes:
/// `[chain_id, address, nonce, y_parity, r, s]`. The last three items are
/// optional: an unsigned tuple has exactly 3 items.
pub fn parse_authorization_rlp(bytes: &[u8]) -> Result<Authorization, ParseError> {
    let item = rlp_decode_exact(bytes)?;
    authorization_from_rlp(&item)
}

/// Parse an RLP list of authorization tuples (the `authorization_list`
/// field of a type-4 transaction).
pub fn parse_authorization_list_rlp(bytes: &[u8]) -> Result<Vec<Authorization>, ParseError> {
    let item = rlp_decode_exact(bytes)?;
    authorization_list_from_rlp(&item)
}

fn authorization_list_from_rlp(item: &Rlp<'_>) -> Result<Vec<Authorization>, ParseError> {
    item.as_list("authorization_list")?
        .iter()
        .map(authorization_from_rlp)
        .collect()
}

/// Number of fields in a type-4 transaction payload before the signature.
const SET_CODE_TX_UNSIGNED_FIELDS: usize = 10;
/// Number of fields in a signed type-4 transaction payload.
const SET_CODE_TX_SIGNED_FIELDS: usize = 13;
/// Index of `authorization_list` in the transaction payload.
const SET_CODE_TX_AUTH_LIST_INDEX: usize = 9;

/// Parse a full type-0x04 transaction (`0x04 || rlp([...])`) and return its
/// authorization list. Fields per EIP-7702: `[chain_id, nonce,
/// max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, value,
/// data, access_list, authorization_list, signature_y_parity, signature_r,
/// signature_s]`. A missing trailing signature is tolerated.
pub fn parse_set_code_transaction(bytes: &[u8]) -> Result<Vec<Authorization>, ParseError> {
    match bytes.first() {
        Some(0x04) => {}
        Some(other) => {
            return Err(ParseError::Field(format!(
                "not a set-code transaction: type byte 0x{other:02x}, expected 0x04"
            )))
        }
        None => return Err(ParseError::Field("empty transaction".to_string())),
    }
    let item = rlp_decode_exact(&bytes[1..])?;
    let fields = item.as_list("transaction")?;
    if fields.len() < SET_CODE_TX_UNSIGNED_FIELDS || fields.len() > SET_CODE_TX_SIGNED_FIELDS {
        return Err(ParseError::Field(format!(
            "set-code transaction must have {SET_CODE_TX_UNSIGNED_FIELDS} to {SET_CODE_TX_SIGNED_FIELDS} fields, got {}",
            fields.len()
        )));
    }
    authorization_list_from_rlp(&fields[SET_CODE_TX_AUTH_LIST_INDEX])
}

// ---------------------------------------------------------------------------
// JSON-ish extraction
// ---------------------------------------------------------------------------

/// Parse an authorization as wallets and tooling print it, for example
/// `{"chainId": 1, "address": "0x…", "nonce": "0x5", "yParity": 0, "r": "0x…", "s": "0x…"}`.
///
/// Accepts `chainId`/`chain_id`, `address`, `nonce`, `yParity`/`y_parity`,
/// `r`, `s`, with decimal or 0x-hex values, quoted or bare, in any order.
/// This is a tolerant key/value extractor, not a JSON parser.
pub fn parse_authorization_json(text: &str) -> Result<Authorization, ParseError> {
    let chain_id = required_u64(text, "chainid", "chainId")?;
    let address_text = find_value(text, "address")
        .ok_or_else(|| ParseError::Field("missing address".to_string()))?;
    let address = address_from_hex(&address_text)?;
    let nonce = required_u64(text, "nonce", "nonce")?;

    let y_parity = match find_value(text, "yparity") {
        Some(v) => {
            let parity = parse_u64_value(&v, "yParity")?;
            if parity > u8::MAX as u64 {
                return Err(ParseError::Field(format!("yParity out of range: {parity}")));
            }
            Some(parity as u8)
        }
        None => None,
    };
    let r = match find_value(text, "r") {
        Some(v) => Some(parse_signature_component_value(&v, "r")?),
        None => None,
    };
    let s = match find_value(text, "s") {
        Some(v) => Some(parse_signature_component_value(&v, "s")?),
        None => None,
    };

    Ok(Authorization {
        chain_id,
        address,
        nonce,
        y_parity,
        r,
        s,
    })
}

fn required_u64(text: &str, normalized_key: &str, display: &str) -> Result<u64, ParseError> {
    let value = find_value(text, normalized_key)
        .ok_or_else(|| ParseError::Field(format!("missing {display}")))?;
    parse_u64_value(&value, display)
}

/// Parse a decimal or 0x-hex integer value into a u64.
fn parse_u64_value(value: &str, what: &str) -> Result<u64, ParseError> {
    let v = value.trim();
    if v.is_empty() {
        return Err(ParseError::Field(format!("{what}: empty value")));
    }
    if v.starts_with("0x") || v.starts_with("0X") {
        let hex = &v[2..];
        // Tolerate odd-length hex for integers ("0x5") by left-padding.
        let padded;
        let hex = if hex.len() & 1 == 1 {
            padded = format!("0{hex}");
            padded.as_str()
        } else {
            hex
        };
        let bytes = decode_hex(hex)?;
        let minimal = strip_leading_zeros(&bytes);
        return bytes_to_u64(minimal, what);
    }
    if !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::Field(format!(
            "{what}: not a decimal or hex integer"
        )));
    }
    v.parse::<u64>()
        .map_err(|_| ParseError::Field(format!("{what}: integer too large")))
}

/// Parse a signature component given as 0x-hex or decimal text into minimal
/// big-endian bytes.
fn parse_signature_component_value(value: &str, what: &str) -> Result<Vec<u8>, ParseError> {
    let v = value.trim();
    let bytes = if v.starts_with("0x") || v.starts_with("0X") {
        let hex = &v[2..];
        let padded;
        let hex = if hex.len() & 1 == 1 {
            padded = format!("0{hex}");
            padded.as_str()
        } else {
            hex
        };
        decode_hex(hex)?
    } else if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        decimal_to_bytes(v)
    } else {
        return Err(ParseError::Field(format!(
            "{what}: not a decimal or hex integer"
        )));
    };
    let minimal = strip_leading_zeros(&bytes).to_vec();
    if minimal.len() > MAX_SIGNATURE_COMPONENT_LEN {
        return Err(ParseError::Field(format!(
            "{what}: signature component too long ({} bytes)",
            minimal.len()
        )));
    }
    Ok(minimal)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// Convert an arbitrary-length decimal digit string to big-endian bytes.
/// Caller guarantees `digits` is non-empty ASCII digits.
fn decimal_to_bytes(digits: &str) -> Vec<u8> {
    // Little-endian accumulator: value = value * 10 + digit.
    let mut le: Vec<u8> = Vec::new();
    for d in digits.bytes() {
        let mut carry = (d - b'0') as u32;
        for limb in le.iter_mut() {
            let v = *limb as u32 * 10 + carry;
            *limb = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            le.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    le.reverse();
    le
}

/// Find the value belonging to `key` in JSON-ish text. Keys are matched
/// case-insensitively with underscores ignored, so `chainid` matches
/// `chainId`, `chain_id` and `CHAIN_ID`. The key must be a whole identifier
/// (so `r` does not match inside `address`), optionally quoted, and must be
/// followed by `:` or `=`. Values may be quoted or bare.
fn find_value(text: &str, normalized_key: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_ident_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident_byte(bytes[i]) {
            i += 1;
        }
        let ident = &text[start..i];
        if normalize_key(ident) != normalized_key {
            continue;
        }
        // Skip closing quote and whitespace, then require a separator.
        let mut j = i;
        if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
            j += 1;
        }
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || (bytes[j] != b':' && bytes[j] != b'=') {
            continue;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() {
            return None;
        }
        let value = if bytes[j] == b'"' || bytes[j] == b'\'' {
            let quote = bytes[j];
            let vstart = j + 1;
            let vend = bytes[vstart..].iter().position(|b| *b == quote)? + vstart;
            &text[vstart..vend]
        } else {
            let vstart = j;
            let mut vend = j;
            while vend < bytes.len() && !is_value_terminator(bytes[vend]) {
                vend += 1;
            }
            &text[vstart..vend]
        };
        return Some(value.to_string());
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_value_terminator(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b',' | b'}' | b']' | b')' | b';')
}

fn normalize_key(ident: &str) -> String {
    ident
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

// ---------------------------------------------------------------------------
// Current delegation (from eth_getCode)
// ---------------------------------------------------------------------------

/// What an account's current code says about delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationStatus {
    /// Empty code: a plain EOA, no delegation installed.
    None,
    /// Code is exactly a delegation designator.
    Delegated,
    /// Code exists but is not a delegation designator (a contract, or a
    /// designator with extra bytes).
    NotDelegationCode,
    /// Code was not retrieved.
    Unknown,
}

impl DelegationStatus {
    pub fn label(&self) -> &'static str {
        match self {
            DelegationStatus::None => "none",
            DelegationStatus::Delegated => "delegated",
            DelegationStatus::NotDelegationCode => "non-delegation code",
            DelegationStatus::Unknown => "unknown",
        }
    }
}

/// Result of inspecting account code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationState {
    pub status: DelegationStatus,
    /// The delegate implementation when `status == Delegated`.
    pub delegate: Option<[u8; 20]>,
    /// Length of the code that was inspected (0 when unknown).
    pub code_length: usize,
}

impl DelegationState {
    /// Delegate address as 0x-prefixed lowercase hex, when delegated.
    pub fn delegate_hex(&self) -> Option<String> {
        self.delegate.as_ref().map(|a| encode_hex(a))
    }

    fn unknown() -> Self {
        DelegationState {
            status: DelegationStatus::Unknown,
            delegate: None,
            code_length: 0,
        }
    }
}

/// Inspect account code as returned by `eth_getCode` (raw bytes).
///
/// - Exactly 23 bytes starting with [`DELEGATION_PREFIX`] → `Delegated`
///   with the 20-byte delegate.
/// - Empty → `None`.
/// - Anything else (including a designator followed by extra bytes) →
///   `NotDelegationCode`.
pub fn delegation_from_code(code: &[u8]) -> DelegationState {
    if code.is_empty() {
        return DelegationState {
            status: DelegationStatus::None,
            delegate: None,
            code_length: 0,
        };
    }
    if code.len() == DELEGATION_CODE_LEN && code.starts_with(&DELEGATION_PREFIX) {
        let mut delegate = [0u8; 20];
        delegate.copy_from_slice(&code[DELEGATION_PREFIX.len()..]);
        return DelegationState {
            status: DelegationStatus::Delegated,
            delegate: Some(delegate),
            code_length: code.len(),
        };
    }
    DelegationState {
        status: DelegationStatus::NotDelegationCode,
        delegate: None,
        code_length: code.len(),
    }
}

// ---------------------------------------------------------------------------
// Delegate registry
// ---------------------------------------------------------------------------

/// Trust classification of a delegate implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateTrust {
    /// Reviewed and approved by the user or organisation.
    Approved,
    /// On the deny list.
    KnownMalicious,
    /// Not reviewed either way.
    Unknown,
}

impl DelegateTrust {
    pub fn label(&self) -> &'static str {
        match self {
            DelegateTrust::Approved => "approved",
            DelegateTrust::KnownMalicious => "known malicious",
            DelegateTrust::Unknown => "unknown",
        }
    }
}

/// Built-in deny list of delegate implementations.
///
/// Intentionally empty: Gorse ships no hard-coded addresses. The list is
/// populated at runtime from configuration and threat feeds through
/// [`DelegateRegistry::add_malicious`] / [`DelegateRegistry::add_malicious_hex`].
const BUILT_IN_MALICIOUS: &[[u8; 20]] = &[];

/// Delegate implementations the user has reviewed, plus a deny list.
///
/// A deny-list match always wins over an approval.
#[derive(Debug, Clone, Default)]
pub struct DelegateRegistry {
    approved: Vec<[u8; 20]>,
    malicious: Vec<[u8; 20]>,
}

impl DelegateRegistry {
    /// Empty approved list; deny list seeded with the (intentionally empty)
    /// built-in list. See [`BUILT_IN_MALICIOUS`].
    pub fn new() -> Self {
        DelegateRegistry {
            approved: Vec::new(),
            malicious: BUILT_IN_MALICIOUS.to_vec(),
        }
    }

    pub fn add_approved(&mut self, addr: [u8; 20]) {
        if !self.approved.contains(&addr) {
            self.approved.push(addr);
        }
    }

    pub fn add_malicious(&mut self, addr: [u8; 20]) {
        if !self.malicious.contains(&addr) {
            self.malicious.push(addr);
        }
    }

    /// Add an approved delegate from hex (with or without `0x`, any case).
    pub fn add_approved_hex(&mut self, hex: &str) -> Result<(), ParseError> {
        self.add_approved(address_from_hex(hex)?);
        Ok(())
    }

    /// Add a malicious delegate from hex (with or without `0x`, any case).
    pub fn add_malicious_hex(&mut self, hex: &str) -> Result<(), ParseError> {
        self.add_malicious(address_from_hex(hex)?);
        Ok(())
    }

    pub fn classify(&self, addr: &[u8; 20]) -> DelegateTrust {
        if self.malicious.contains(addr) {
            DelegateTrust::KnownMalicious
        } else if self.approved.contains(addr) {
            DelegateTrust::Approved
        } else {
            DelegateTrust::Unknown
        }
    }

    pub fn approved_count(&self) -> usize {
        self.approved.len()
    }

    pub fn malicious_count(&self) -> usize {
        self.malicious.len()
    }
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

/// Assessment of a single authorization tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationAssessment {
    pub authorization: Authorization,
    pub trust: DelegateTrust,
    /// `chain_id == 0`: replayable on every chain.
    pub any_chain: bool,
    /// Both signature components present.
    pub signed: bool,
    /// `Some(true)` when the tuple's nonce equals the account's current
    /// nonce (so it is executable now); `None` when the current nonce is
    /// unknown.
    pub executable_now: Option<bool>,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

/// Assess an authorization against the registry and, optionally, the
/// account's current on-chain nonce.
///
/// Severity: `KnownMalicious` → Critical; `Unknown` delegate → High (it is
/// an account-control operation to an unreviewed implementation);
/// `Approved` → Medium when valid on any chain, otherwise Low.
pub fn assess_authorization(
    auth: &Authorization,
    registry: &DelegateRegistry,
    current_nonce: Option<u64>,
) -> AuthorizationAssessment {
    let trust = registry.classify(&auth.address);
    let any_chain = auth.is_any_chain();
    let signed = auth.is_signed();
    let executable_now = current_nonce.map(|n| n == auth.nonce);
    let delegate = auth.address_hex();
    let mut reasons = Vec::new();

    let severity = match trust {
        DelegateTrust::KnownMalicious => {
            reasons.push(format!(
                "delegate {delegate} is on the known-malicious list"
            ));
            Severity::Critical
        }
        DelegateTrust::Unknown => {
            reasons.push(format!(
                "delegate {delegate} has not been reviewed; an EIP-7702 authorization hands control of the account to it"
            ));
            Severity::High
        }
        DelegateTrust::Approved => {
            reasons.push(format!("delegate {delegate} is an approved implementation"));
            if any_chain {
                Severity::Medium
            } else {
                Severity::Low
            }
        }
    };

    if any_chain {
        reasons.push("chain_id 0: authorization is valid on every chain".to_string());
    } else {
        reasons.push(format!("bound to chain {}", auth.chain_id));
    }

    if signed {
        reasons.push("authorization is signed and can be submitted by anyone".to_string());
    } else {
        reasons.push("authorization is unsigned (not yet usable)".to_string());
    }

    match executable_now {
        Some(true) => reasons.push(format!(
            "nonce {} matches the account's current nonce: executable now",
            auth.nonce
        )),
        Some(false) => reasons.push(format!(
            "nonce {} does not match the account's current nonce: not executable at present",
            auth.nonce
        )),
        None => {
            reasons.push("current account nonce unknown: executability not checked".to_string())
        }
    }

    AuthorizationAssessment {
        authorization: auth.clone(),
        trust,
        any_chain,
        signed,
        executable_now,
        severity,
        reasons,
    }
}

/// Assessment of a wallet's *current* delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationAssessment {
    /// The wallet (EOA) that was inspected.
    pub address: [u8; 20],
    pub state: DelegationState,
    /// Trust of the installed delegate; `None` when nothing is delegated.
    pub trust: Option<DelegateTrust>,
    pub severity: Severity,
    pub persistence: Persistence,
    pub reasons: Vec<String>,
}

/// Assess a wallet's current delegation from its code (`eth_getCode`).
///
/// A historical authorization is not proof of an active delegation; only the
/// account's current code is. Pass `None` for `code` when it was not
/// retrieved.
///
/// - Delegated + KnownMalicious → Critical
/// - Delegated + Unknown → High
/// - Delegated + Approved → Low
/// - None → Low ("no delegation installed")
/// - NotDelegationCode → Medium ("account has non-delegation code")
/// - Unknown → Low ("code not checked")
///
/// Persistence is `Blockchain` when delegated, `Unknown` otherwise.
pub fn assess_delegation(
    address: [u8; 20],
    code: Option<&[u8]>,
    registry: &DelegateRegistry,
) -> DelegationAssessment {
    let state = match code {
        Some(bytes) => delegation_from_code(bytes),
        None => DelegationState::unknown(),
    };
    let wallet = encode_hex(&address);
    let mut reasons = Vec::new();

    let (trust, severity, persistence) = match state.status {
        DelegationStatus::Delegated => {
            let delegate = state.delegate.unwrap_or([0u8; 20]);
            let trust = registry.classify(&delegate);
            let delegate_hex = encode_hex(&delegate);
            let severity = match trust {
                DelegateTrust::KnownMalicious => {
                    reasons.push(format!(
                        "{wallet} is delegated to {delegate_hex}, which is on the known-malicious list"
                    ));
                    Severity::Critical
                }
                DelegateTrust::Unknown => {
                    reasons.push(format!(
                        "{wallet} is delegated to {delegate_hex}, an unreviewed implementation"
                    ));
                    Severity::High
                }
                DelegateTrust::Approved => {
                    reasons.push(format!(
                        "{wallet} is delegated to {delegate_hex}, an approved implementation"
                    ));
                    Severity::Low
                }
            };
            reasons.push("delegation persists on-chain until replaced or cleared".to_string());
            (Some(trust), severity, Persistence::Blockchain)
        }
        DelegationStatus::None => {
            reasons.push("no delegation installed".to_string());
            (None, Severity::Low, Persistence::Unknown)
        }
        DelegationStatus::NotDelegationCode => {
            reasons.push(format!(
                "account has non-delegation code ({} bytes)",
                state.code_length
            ));
            (None, Severity::Medium, Persistence::Unknown)
        }
        DelegationStatus::Unknown => {
            reasons.push("code not checked".to_string());
            (None, Severity::Low, Persistence::Unknown)
        }
    };

    DelegationAssessment {
        address,
        state,
        trust,
        severity,
        persistence,
        reasons,
    }
}

/// Signing-service policy: can the service be asked to sign an arbitrary
/// EIP-7702 authorization tuple?
///
/// - accepts arbitrary authorizations without independent approval → Critical
/// - accepts arbitrary authorizations but requires approval → High
/// - otherwise → Low
pub fn assess_signing_service_7702_policy(
    accepts_arbitrary_authorizations: bool,
    requires_independent_approval: bool,
) -> (Severity, Vec<String>) {
    let mut reasons = Vec::new();
    let severity = if accepts_arbitrary_authorizations && !requires_independent_approval {
        reasons.push(
            "signing service signs arbitrary EIP-7702 authorizations without independent approval: a compromised API credential can hand every managed account to an attacker-chosen delegate"
                .to_string(),
        );
        Severity::Critical
    } else if accepts_arbitrary_authorizations {
        reasons.push(
            "signing service signs arbitrary EIP-7702 authorizations but requires independent approval"
                .to_string(),
        );
        Severity::High
    } else {
        reasons.push("signing service does not sign arbitrary EIP-7702 authorizations".to_string());
        Severity::Low
    };
    (severity, reasons)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- tiny RLP encoder (tests only) ---------------------------------

    fn rlp_len(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            vec![offset + len as u8]
        } else {
            let mut be: Vec<u8> = len.to_be_bytes().to_vec();
            while be.first() == Some(&0) {
                be.remove(0);
            }
            let mut out = vec![offset + 55 + be.len() as u8];
            out.extend(be);
            out
        }
    }

    fn enc_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = rlp_len(data.len(), 0x80);
        out.extend_from_slice(data);
        out
    }

    fn enc_u64(v: u64) -> Vec<u8> {
        let mut be: Vec<u8> = v.to_be_bytes().to_vec();
        while be.first() == Some(&0) {
            be.remove(0);
        }
        enc_bytes(&be)
    }

    fn enc_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = rlp_len(payload.len(), 0xc0);
        out.extend(payload);
        out
    }

    fn addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn enc_auth(a: &Authorization) -> Vec<u8> {
        let mut items = vec![enc_u64(a.chain_id), enc_bytes(&a.address), enc_u64(a.nonce)];
        if let (Some(p), Some(r), Some(s)) = (a.y_parity, &a.r, &a.s) {
            items.push(enc_u64(p as u64));
            items.push(enc_bytes(r));
            items.push(enc_bytes(s));
        }
        enc_list(&items)
    }

    fn signed_auth(chain_id: u64, address: [u8; 20], nonce: u64) -> Authorization {
        Authorization {
            chain_id,
            address,
            nonce,
            y_parity: Some(1),
            r: Some(vec![0xaa; 32]),
            s: Some(vec![0x55; 32]),
        }
    }

    // --- hex ------------------------------------------------------------

    #[test]
    fn hex_decode_accepts_prefix_case_and_whitespace() {
        assert_eq!(decode_hex("0xAbCd").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(decode_hex("  abcd \n").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(decode_hex("0x").unwrap(), Vec::<u8>::new());
        assert!(matches!(decode_hex("0xabc"), Err(ParseError::Hex(_))));
        assert!(matches!(decode_hex("zz"), Err(ParseError::Hex(_))));
        assert_eq!(encode_hex(&[0x00, 0xef, 0x1a]), "0x00ef1a");
    }

    // --- RLP round trips -------------------------------------------------

    #[test]
    fn rlp_round_trip_signed_tuple() {
        let auth = signed_auth(1, addr(0x11), 7);
        let bytes = enc_auth(&auth);
        let parsed = parse_authorization_rlp(&bytes).unwrap();
        assert_eq!(parsed, auth);
        assert!(parsed.is_signed());
        assert!(!parsed.is_any_chain());
        assert_eq!(parsed.address_hex(), format!("0x{}", "11".repeat(20)));
    }

    #[test]
    fn rlp_unsigned_three_item_tuple() {
        let auth = Authorization {
            chain_id: 10,
            address: addr(0x22),
            nonce: 0,
            y_parity: None,
            r: None,
            s: None,
        };
        let parsed = parse_authorization_rlp(&enc_auth(&auth)).unwrap();
        assert_eq!(parsed, auth);
        assert!(!parsed.is_signed());
    }

    #[test]
    fn rlp_chain_id_zero_is_any_chain() {
        let auth = signed_auth(0, addr(0x33), 1);
        let parsed = parse_authorization_rlp(&enc_auth(&auth)).unwrap();
        assert!(parsed.is_any_chain());
    }

    #[test]
    fn rlp_large_values_and_long_form_lengths() {
        // Large chain id and nonce exercise multi-byte integers; a list of
        // many tuples exercises the long-form list length.
        let auth = signed_auth(0xffff_ffff_ffff_ffff, addr(0x44), 0x0123_4567_89ab);
        let parsed = parse_authorization_rlp(&enc_auth(&auth)).unwrap();
        assert_eq!(parsed, auth);

        let tuples: Vec<Vec<u8>> = (0..5)
            .map(|i| enc_auth(&signed_auth(1, addr(i), i as u64)))
            .collect();
        let list = enc_list(&tuples);
        assert!(list[0] >= 0xf8, "expected long-form list");
        let parsed = parse_authorization_list_rlp(&list).unwrap();
        assert_eq!(parsed.len(), 5);
        assert_eq!(parsed[3].address, addr(3));
    }

    #[test]
    fn rlp_rejects_wrong_shapes() {
        // 4 items: neither signed nor unsigned.
        let four = enc_list(&[enc_u64(1), enc_bytes(&addr(0x11)), enc_u64(1), enc_u64(0)]);
        assert!(matches!(
            parse_authorization_rlp(&four),
            Err(ParseError::Field(_))
        ));
        // 19-byte address.
        let short = enc_list(&[enc_u64(1), enc_bytes(&[0x11; 19]), enc_u64(1)]);
        assert!(matches!(
            parse_authorization_rlp(&short),
            Err(ParseError::Field(_))
        ));
        // 9-byte integer.
        let big = enc_list(&[enc_bytes(&[1u8; 9]), enc_bytes(&addr(0x11)), enc_u64(1)]);
        assert!(matches!(
            parse_authorization_rlp(&big),
            Err(ParseError::Field(_))
        ));
        // Leading-zero integer.
        let lz = enc_list(&[enc_bytes(&[0, 1]), enc_bytes(&addr(0x11)), enc_u64(1)]);
        assert!(matches!(
            parse_authorization_rlp(&lz),
            Err(ParseError::Field(_))
        ));
        // Bytes where a list is required.
        assert!(parse_authorization_rlp(&enc_bytes(&[1, 2, 3])).is_err());
        // Trailing garbage.
        let mut trailing = enc_auth(&signed_auth(1, addr(0x11), 1));
        trailing.push(0x00);
        assert!(matches!(
            parse_authorization_rlp(&trailing),
            Err(ParseError::Rlp(_))
        ));
    }

    #[test]
    fn rlp_truncated_and_garbage_inputs_return_err() {
        let good = enc_auth(&signed_auth(1, addr(0x11), 1));
        for cut in 0..good.len() {
            assert!(
                parse_authorization_rlp(&good[..cut]).is_err(),
                "cut at {cut}"
            );
            assert!(
                parse_authorization_list_rlp(&good[..cut]).is_err(),
                "list cut at {cut}"
            );
        }
        let garbage: [&[u8]; 9] = [
            &[],
            &[0xff],
            &[0xf8],
            &[0xf8, 0x00],
            &[0xb8, 0xff, 0x00],
            &[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xc1, 0xc1, 0xc1, 0xc1, 0xc1],
            &[0x81, 0x05],
            &[0x04],
        ];
        for g in garbage {
            assert!(parse_authorization_rlp(g).is_err(), "{g:?}");
            assert!(parse_authorization_list_rlp(g).is_err(), "{g:?}");
            assert!(parse_set_code_transaction(g).is_err(), "{g:?}");
        }
        // An empty list is a valid (empty) authorization list but not a tuple.
        assert_eq!(parse_authorization_list_rlp(&[0xc0]).unwrap(), Vec::new());
        assert!(parse_authorization_rlp(&[0xc0]).is_err());
        assert!(parse_set_code_transaction(&[0x04, 0xc0]).is_err());
        // Deep nesting must not overflow the stack.
        let deep: Vec<u8> = vec![0xc1; 10_000];
        assert!(parse_authorization_rlp(&deep).is_err());
        // Pseudo-random byte soup.
        let mut x: u32 = 0x1234_5678;
        for len in 1..200 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    (x & 0xff) as u8
                })
                .collect();
            let _ = parse_authorization_rlp(&buf);
            let _ = parse_authorization_list_rlp(&buf);
            let _ = parse_set_code_transaction(&buf);
        }
    }

    // --- full transaction ----------------------------------------------

    #[test]
    fn set_code_transaction_returns_two_authorizations() {
        let a1 = signed_auth(1, addr(0x11), 5);
        let a2 = signed_auth(0, addr(0x22), 0);
        let auth_list = enc_list(&[enc_auth(&a1), enc_auth(&a2)]);
        let fields = vec![
            enc_u64(1),              // chain_id
            enc_u64(9),              // nonce
            enc_u64(1_000_000_000),  // max_priority_fee_per_gas
            enc_u64(30_000_000_000), // max_fee_per_gas
            enc_u64(100_000),        // gas_limit
            enc_bytes(&addr(0x99)),  // destination
            enc_u64(0),              // value
            enc_bytes(&[]),          // data
            enc_list(&[]),           // access_list
            auth_list.clone(),       // authorization_list
            enc_u64(0),              // signature_y_parity
            enc_bytes(&[0xaa; 32]),  // signature_r
            enc_bytes(&[0x55; 32]),  // signature_s
        ];
        let mut tx = vec![0x04];
        tx.extend(enc_list(&fields));
        let parsed = parse_set_code_transaction(&tx).unwrap();
        assert_eq!(parsed, vec![a1.clone(), a2.clone()]);

        // Unsigned transaction (10 fields) is tolerated.
        let mut unsigned = vec![0x04];
        unsigned.extend(enc_list(&fields[..10]));
        assert_eq!(parse_set_code_transaction(&unsigned).unwrap(), vec![a1, a2]);

        // Wrong type byte.
        let mut wrong = tx.clone();
        wrong[0] = 0x02;
        assert!(matches!(
            parse_set_code_transaction(&wrong),
            Err(ParseError::Field(_))
        ));

        // Too few fields.
        let mut few = vec![0x04];
        few.extend(enc_list(&fields[..9]));
        assert!(parse_set_code_transaction(&few).is_err());

        // Truncations never panic.
        for cut in 0..tx.len() {
            assert!(parse_set_code_transaction(&tx[..cut]).is_err());
        }
    }

    // --- JSON-ish ---------------------------------------------------------

    #[test]
    fn json_camel_case_hex_values() {
        let text = r#"{"chainId": "0x1", "address": "0x1111111111111111111111111111111111111111", "nonce": "0x5", "yParity": "0x1", "r": "0x0aa", "s": "0x55"}"#;
        let a = parse_authorization_json(text).unwrap();
        assert_eq!(a.chain_id, 1);
        assert_eq!(a.address, addr(0x11));
        assert_eq!(a.nonce, 5);
        assert_eq!(a.y_parity, Some(1));
        assert_eq!(a.r, Some(vec![0xaa]));
        assert_eq!(a.s, Some(vec![0x55]));
    }

    #[test]
    fn json_snake_case_decimal_values_and_bare_tokens() {
        let text = "chain_id: 10, address: 2222222222222222222222222222222222222222, nonce: 42, y_parity: 0, r: 255, s: 65536";
        let a = parse_authorization_json(text).unwrap();
        assert_eq!(a.chain_id, 10);
        assert_eq!(a.address, addr(0x22));
        assert_eq!(a.nonce, 42);
        assert_eq!(a.y_parity, Some(0));
        assert_eq!(a.r, Some(vec![0xff]));
        assert_eq!(a.s, Some(vec![1, 0, 0]));
    }

    #[test]
    fn json_unsigned_and_missing_fields() {
        let unsigned = r#"{ "chainId": 0, "address": "0x3333333333333333333333333333333333333333", "nonce": 1 }"#;
        let a = parse_authorization_json(unsigned).unwrap();
        assert!(a.is_any_chain());
        assert!(!a.is_signed());
        assert_eq!(a.y_parity, None);

        assert!(matches!(
            parse_authorization_json(
                r#"{"address": "0x3333333333333333333333333333333333333333", "nonce": 1}"#
            ),
            Err(ParseError::Field(_))
        ));
        assert!(matches!(
            parse_authorization_json(r#"{"chainId": 1, "nonce": 1}"#),
            Err(ParseError::Field(_))
        ));
        // Bad address length.
        assert!(
            parse_authorization_json(r#"{"chainId": 1, "address": "0x1234", "nonce": 1}"#).is_err()
        );
        // Key "r" must not match inside "address" or "nonce".
        let no_r = r#"{"chainId": 1, "address": "0x3333333333333333333333333333333333333333", "nonce": 1, "s": "0x01"}"#;
        assert_eq!(parse_authorization_json(no_r).unwrap().r, None);
        // Large decimal r exercises the bignum path.
        let big = r#"{"chainId": 1, "address": "0x3333333333333333333333333333333333333333", "nonce": 1, "r": "340282366920938463463374607431768211456", "s": "1"}"#;
        let a = parse_authorization_json(big).unwrap();
        let mut expected = vec![1u8];
        expected.extend([0u8; 16]);
        assert_eq!(a.r, Some(expected)); // 2^128
    }

    #[test]
    fn decimal_to_bytes_conversion() {
        assert_eq!(decimal_to_bytes("0"), Vec::<u8>::new());
        assert_eq!(decimal_to_bytes("255"), vec![255]);
        assert_eq!(decimal_to_bytes("256"), vec![1, 0]);
        assert_eq!(
            decimal_to_bytes("18446744073709551616"),
            vec![1, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    // --- delegation from code -------------------------------------------

    #[test]
    fn delegation_from_code_four_statuses() {
        let none = delegation_from_code(&[]);
        assert_eq!(none.status, DelegationStatus::None);
        assert_eq!(none.delegate_hex(), None);

        let mut code = DELEGATION_PREFIX.to_vec();
        code.extend(addr(0x44));
        let delegated = delegation_from_code(&code);
        assert_eq!(delegated.status, DelegationStatus::Delegated);
        assert_eq!(delegated.delegate, Some(addr(0x44)));
        assert_eq!(
            delegated.delegate_hex().unwrap(),
            format!("0x{}", "44".repeat(20))
        );
        assert_eq!(delegated.code_length, 23);

        let mut extra = code.clone();
        extra.push(0x00);
        let not = delegation_from_code(&extra);
        assert_eq!(not.status, DelegationStatus::NotDelegationCode);
        assert_eq!(not.delegate, None);
        assert_eq!(not.code_length, 24);

        let contract = delegation_from_code(&[0x60, 0x80, 0x60, 0x40]);
        assert_eq!(contract.status, DelegationStatus::NotDelegationCode);

        // Wrong prefix with correct length.
        let mut wrong = vec![0xef, 0x01, 0x01];
        wrong.extend(addr(0x44));
        assert_eq!(
            delegation_from_code(&wrong).status,
            DelegationStatus::NotDelegationCode
        );

        let unknown = assess_delegation(addr(0x01), None, &DelegateRegistry::new());
        assert_eq!(unknown.state.status, DelegationStatus::Unknown);
    }

    // --- registry ---------------------------------------------------------

    #[test]
    fn registry_classification_and_hex_input() {
        let mut reg = DelegateRegistry::new();
        assert_eq!(
            reg.malicious_count(),
            0,
            "built-in deny list is intentionally empty"
        );
        assert_eq!(reg.classify(&addr(0x11)), DelegateTrust::Unknown);

        reg.add_approved_hex("0x1111111111111111111111111111111111111111")
            .unwrap();
        reg.add_malicious_hex("2222222222222222222222222222222222222222")
            .unwrap();
        reg.add_approved_hex("0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa")
            .unwrap();

        assert_eq!(reg.classify(&addr(0x11)), DelegateTrust::Approved);
        assert_eq!(reg.classify(&addr(0x22)), DelegateTrust::KnownMalicious);
        assert_eq!(reg.classify(&addr(0xaa)), DelegateTrust::Approved);
        assert_eq!(reg.classify(&addr(0x33)), DelegateTrust::Unknown);

        // Deny list wins over approval.
        reg.add_malicious(addr(0x11));
        assert_eq!(reg.classify(&addr(0x11)), DelegateTrust::KnownMalicious);

        // Duplicates are not stored twice.
        reg.add_approved(addr(0xaa));
        assert_eq!(reg.approved_count(), 2);

        assert!(matches!(
            reg.add_approved_hex("0x1234"),
            Err(ParseError::Field(_))
        ));
        assert!(matches!(
            reg.add_malicious_hex("0xzz"),
            Err(ParseError::Hex(_))
        ));
    }

    // --- assess_authorization --------------------------------------------

    #[test]
    fn assess_authorization_severities() {
        let mut reg = DelegateRegistry::new();
        reg.add_approved(addr(0x11));
        reg.add_malicious(addr(0x22));

        let malicious = assess_authorization(&signed_auth(1, addr(0x22), 0), &reg, None);
        assert_eq!(malicious.severity, Severity::Critical);
        assert_eq!(malicious.trust, DelegateTrust::KnownMalicious);
        assert!(malicious
            .reasons
            .iter()
            .any(|r| r.contains("known-malicious")));

        let unknown = assess_authorization(&signed_auth(1, addr(0x33), 0), &reg, None);
        assert_eq!(unknown.severity, Severity::High);
        assert_eq!(unknown.trust, DelegateTrust::Unknown);

        let approved = assess_authorization(&signed_auth(1, addr(0x11), 0), &reg, None);
        assert_eq!(approved.severity, Severity::Low);
        assert!(!approved.any_chain);

        let approved_any = assess_authorization(&signed_auth(0, addr(0x11), 0), &reg, None);
        assert_eq!(approved_any.severity, Severity::Medium);
        assert!(approved_any.any_chain);
        assert!(approved_any
            .reasons
            .iter()
            .any(|r| r.contains("every chain")));

        // Any-chain does not lower a malicious or unknown rating.
        assert_eq!(
            assess_authorization(&signed_auth(0, addr(0x22), 0), &reg, None).severity,
            Severity::Critical
        );
        assert_eq!(
            assess_authorization(&signed_auth(0, addr(0x33), 0), &reg, None).severity,
            Severity::High
        );
    }

    #[test]
    fn assess_authorization_signed_and_executable_flags() {
        let reg = DelegateRegistry::new();
        let auth = signed_auth(1, addr(0x11), 7);

        let now = assess_authorization(&auth, &reg, Some(7));
        assert_eq!(now.executable_now, Some(true));
        assert!(now.signed);
        assert!(now.reasons.iter().any(|r| r.contains("executable now")));

        let later = assess_authorization(&auth, &reg, Some(8));
        assert_eq!(later.executable_now, Some(false));

        let unknown = assess_authorization(&auth, &reg, None);
        assert_eq!(unknown.executable_now, None);

        let unsigned = Authorization {
            r: None,
            s: None,
            y_parity: None,
            ..auth.clone()
        };
        let a = assess_authorization(&unsigned, &reg, None);
        assert!(!a.signed);
        assert!(a.reasons.iter().any(|r| r.contains("unsigned")));
        assert_eq!(a.authorization, unsigned);
    }

    // --- assess_delegation -----------------------------------------------

    #[test]
    fn assess_delegation_every_status() {
        let mut reg = DelegateRegistry::new();
        reg.add_approved(addr(0x11));
        reg.add_malicious(addr(0x22));
        let wallet = addr(0x01);

        let code_for = |delegate: [u8; 20]| {
            let mut c = DELEGATION_PREFIX.to_vec();
            c.extend(delegate);
            c
        };

        let malicious = assess_delegation(wallet, Some(&code_for(addr(0x22))), &reg);
        assert_eq!(malicious.severity, Severity::Critical);
        assert_eq!(malicious.trust, Some(DelegateTrust::KnownMalicious));
        assert_eq!(malicious.persistence, Persistence::Blockchain);
        assert_eq!(malicious.address, wallet);

        let unknown = assess_delegation(wallet, Some(&code_for(addr(0x33))), &reg);
        assert_eq!(unknown.severity, Severity::High);
        assert_eq!(unknown.trust, Some(DelegateTrust::Unknown));
        assert_eq!(unknown.persistence, Persistence::Blockchain);

        let approved = assess_delegation(wallet, Some(&code_for(addr(0x11))), &reg);
        assert_eq!(approved.severity, Severity::Low);
        assert_eq!(approved.trust, Some(DelegateTrust::Approved));
        assert_eq!(approved.persistence, Persistence::Blockchain);
        assert_eq!(approved.state.delegate, Some(addr(0x11)));

        let none = assess_delegation(wallet, Some(&[]), &reg);
        assert_eq!(none.severity, Severity::Low);
        assert_eq!(none.trust, None);
        assert_eq!(none.persistence, Persistence::Unknown);
        assert!(none.reasons.iter().any(|r| r == "no delegation installed"));

        let contract = assess_delegation(wallet, Some(&[0x60, 0x80]), &reg);
        assert_eq!(contract.severity, Severity::Medium);
        assert_eq!(contract.state.status, DelegationStatus::NotDelegationCode);
        assert_eq!(contract.persistence, Persistence::Unknown);
        assert!(contract
            .reasons
            .iter()
            .any(|r| r.starts_with("account has non-delegation code")));

        let not_checked = assess_delegation(wallet, None, &reg);
        assert_eq!(not_checked.severity, Severity::Low);
        assert_eq!(not_checked.state.status, DelegationStatus::Unknown);
        assert_eq!(not_checked.persistence, Persistence::Unknown);
        assert!(not_checked.reasons.iter().any(|r| r == "code not checked"));
    }

    // --- signing service policy ------------------------------------------

    #[test]
    fn signing_service_policy() {
        let (sev, reasons) = assess_signing_service_7702_policy(true, false);
        assert_eq!(sev, Severity::Critical);
        assert!(!reasons.is_empty());

        let (sev, _) = assess_signing_service_7702_policy(true, true);
        assert_eq!(sev, Severity::High);

        let (sev, _) = assess_signing_service_7702_policy(false, false);
        assert_eq!(sev, Severity::Low);
        let (sev, _) = assess_signing_service_7702_policy(false, true);
        assert_eq!(sev, Severity::Low);
    }

    #[test]
    fn labels() {
        assert_eq!(DelegationStatus::Delegated.label(), "delegated");
        assert_eq!(DelegateTrust::KnownMalicious.label(), "known malicious");
        assert_eq!(ParseError::Rlp("x".into()).to_string(), "rlp: x");
    }
}
