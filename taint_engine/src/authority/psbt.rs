// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Read-only policy analysis of a Partially Signed Bitcoin Transaction
//! (BIP-174, PSBT version 0).
//!
//! This module is the "independent approver" view of a signing request. It
//! parses the unsigned transaction and the per-input UTXO information a PSBT
//! carries and checks what the signature would authorise against a
//! [`SigningPolicy`]: where the money goes, how much leaves the wallet, what
//! the fee is, and whether the signer can actually prove which outputs are
//! change.
//!
//! Invariants, enforced by construction:
//! - It NEVER signs, finalises or broadcasts anything.
//! - It NEVER reads, derives or holds private key material. Partial
//!   signatures and derivation entries are only noted as present or absent.
//! - It never panics on malformed input: every read is bounds-checked and a
//!   bad PSBT yields a [`ParseError`].
//!
//! Everything is std-only: base64, hex, SHA-256, base58check, bech32 and
//! bech32m are implemented here so the crate keeps its zero-dependency
//! guarantee.

use super::scoring::Severity;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a PSBT could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The text could not be decoded as base64 or hex.
    Encoding(String),
    /// The bytes do not start with the PSBT magic `psbt\xff`.
    Magic,
    /// The data ended in the middle of the named structure.
    Truncated(&'static str),
    /// The data decoded but violates the PSBT or transaction format.
    Invalid(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Encoding(why) => write!(f, "encoding error: {why}"),
            ParseError::Magic => write!(f, "not a PSBT (missing magic bytes)"),
            ParseError::Truncated(what) => write!(f, "truncated PSBT while reading {what}"),
            ParseError::Invalid(why) => write!(f, "invalid PSBT: {why}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Parsed model
// ---------------------------------------------------------------------------

/// Standard output script types we can turn into an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    OpReturn,
    Unknown,
}

impl ScriptKind {
    pub fn label(&self) -> &'static str {
        match self {
            ScriptKind::P2pkh => "P2PKH",
            ScriptKind::P2sh => "P2SH",
            ScriptKind::P2wpkh => "P2WPKH",
            ScriptKind::P2wsh => "P2WSH",
            ScriptKind::P2tr => "P2TR",
            ScriptKind::OpReturn => "OP_RETURN",
            ScriptKind::Unknown => "non-standard",
        }
    }
}

/// One output of the unsigned transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
    /// Derived address string when the script is a standard type, else None.
    /// Derived with mainnet prefixes at parse time; use
    /// [`address_for_script`] to derive for another network.
    pub address: Option<String>,
    pub script_kind: ScriptKind,
}

/// One input of the unsigned transaction plus what the PSBT says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub vout: u32,
    /// From witness_utxo (PSBT_IN_WITNESS_UTXO 0x01) or non_witness_utxo
    /// (PSBT_IN_NON_WITNESS_UTXO 0x00) when available.
    pub value_sats: Option<u64>,
    /// PSBT_IN_PARTIAL_SIG (0x02) present.
    pub has_partial_sig: bool,
    /// PSBT_IN_BIP32_DERIVATION (0x06) present.
    pub has_derivation: bool,
}

/// A parsed PSBT v0: the unsigned transaction and the facts an approver
/// needs. No signatures, keys or scripts beyond the output scriptPubKeys
/// are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Psbt {
    pub version: i32,
    pub locktime: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    /// Per output: true when PSBT_OUT_BIP32_DERIVATION (0x02) or
    /// PSBT_OUT_TAP_BIP32_DERIVATION (0x07) is present — the wallet claims
    /// this output as its own (change).
    pub output_is_ours: Vec<bool>,
}

impl Psbt {
    /// Sum of input values, or None if any input lacks UTXO information.
    pub fn total_input_sats(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for input in &self.inputs {
            total = total.checked_add(input.value_sats?)?;
        }
        Some(total)
    }

    /// Sum of output values (saturating; a real transaction never overflows).
    pub fn total_output_sats(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.value_sats))
    }

    /// Inputs minus outputs. None when any input value is unknown or the
    /// outputs exceed the inputs (which no valid transaction does).
    pub fn fee_sats(&self) -> Option<u64> {
        self.total_input_sats()?
            .checked_sub(self.total_output_sats())
    }

    /// Number of inputs that already carry at least one partial signature.
    pub fn fully_signed_inputs(&self) -> usize {
        self.inputs.iter().filter(|i| i.has_partial_sig).count()
    }
}

// ---------------------------------------------------------------------------
// Network and address derivation
// ---------------------------------------------------------------------------

/// Network for address derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Signet => "tb",
            Network::Regtest => "bcrt",
        }
    }
    fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            _ => 0x6f,
        }
    }
    fn p2sh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            _ => 0xc4,
        }
    }
}

/// Classify an output script by its exact standard template.
pub fn classify_script(script: &[u8]) -> ScriptKind {
    match script {
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if script.len() == 25 => ScriptKind::P2pkh,
        [0xa9, 0x14, .., 0x87] if script.len() == 23 => ScriptKind::P2sh,
        [0x00, 0x14, ..] if script.len() == 22 => ScriptKind::P2wpkh,
        [0x00, 0x20, ..] if script.len() == 34 => ScriptKind::P2wsh,
        [0x51, 0x20, ..] if script.len() == 34 => ScriptKind::P2tr,
        [0x6a, ..] => ScriptKind::OpReturn,
        _ => ScriptKind::Unknown,
    }
}

/// Derive the address for a standard output script on the given network.
/// Returns None for OP_RETURN and non-standard scripts.
pub fn address_for_script(script: &[u8], network: Network) -> Option<String> {
    match classify_script(script) {
        ScriptKind::P2pkh => {
            let mut payload = vec![network.p2pkh_version()];
            payload.extend_from_slice(&script[3..23]);
            Some(base58check(&payload))
        }
        ScriptKind::P2sh => {
            let mut payload = vec![network.p2sh_version()];
            payload.extend_from_slice(&script[2..22]);
            Some(base58check(&payload))
        }
        ScriptKind::P2wpkh | ScriptKind::P2wsh => {
            Some(bech32_encode(network.bech32_hrp(), 0, &script[2..]))
        }
        ScriptKind::P2tr => Some(bech32_encode(network.bech32_hrp(), 1, &script[2..])),
        ScriptKind::OpReturn | ScriptKind::Unknown => None,
    }
}

// --- SHA-256 (FIPS 180-4), std only -----------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (word, bytes) in w.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (k, wi) in SHA256_K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*k)
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 32];
    for (dst, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        dst.copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

// --- Base58Check -------------------------------------------------------------

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58check(payload: &[u8]) -> String {
    let checksum = double_sha256(payload);
    let mut data = payload.to_vec();
    data.extend_from_slice(&checksum[..4]);

    let zeros = data.iter().take_while(|b| **b == 0).count();
    // Little-endian base-58 digits of the big number.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        s.push('1');
    }
    for d in digits.iter().rev() {
        s.push(BASE58_ALPHABET[*d as usize] as char);
    }
    s
}

// --- Bech32 (BIP-173) / Bech32m (BIP-350) ------------------------------------

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn convert_8_to_5(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in bytes {
        acc = (acc << 8) | (*b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Encode a segwit address. Witness version 0 uses bech32, 1+ uses bech32m.
fn bech32_encode(hrp: &str, witness_version: u8, program: &[u8]) -> String {
    let mut data = vec![witness_version];
    data.extend(convert_8_to_5(program));

    let mut values: Vec<u8> = Vec::new();
    for c in hrp.bytes() {
        values.push(c >> 5);
    }
    values.push(0);
    for c in hrp.bytes() {
        values.push(c & 31);
    }
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0u8; 6]);

    let constant = if witness_version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    let pm = bech32_polymod(&values) ^ constant;

    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for d in &data {
        s.push(BECH32_CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        s.push(BECH32_CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Text decoders
// ---------------------------------------------------------------------------

fn decode_hex(text: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(ParseError::Encoding(
            "hex string has odd length".to_string(),
        ));
    }
    let nibble = |c: u8| -> Result<u8, ParseError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(ParseError::Encoding(format!(
                "invalid hex character {:?}",
                c as char
            ))),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

/// Strict standard-alphabet base64: no whitespace, no URL-safe alphabet,
/// length a multiple of four, `=` only as one or two trailing pad characters.
fn decode_base64(text: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(ParseError::Encoding("empty base64 input".to_string()));
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(ParseError::Encoding(
            "base64 length is not a multiple of four".to_string(),
        ));
    }
    let pad = bytes.iter().rev().take_while(|b| **b == b'=').count();
    if pad > 2 {
        return Err(ParseError::Encoding(
            "too many base64 padding characters".to_string(),
        ));
    }
    let body = &bytes[..bytes.len() - pad];
    let value = |c: u8| -> Result<u32, ParseError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a') as u32 + 26),
            b'0'..=b'9' => Ok((c - b'0') as u32 + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(ParseError::Encoding(format!(
                "invalid base64 character {:?}",
                c as char
            ))),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Leftover bits must be zero (canonical encoding).
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(ParseError::Encoding(
            "non-canonical base64 trailing bits".to_string(),
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Binary reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ParseError> {
        if n > self.remaining() {
            return Err(ParseError::Truncated(what));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, ParseError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16_le(&mut self, what: &'static str) -> Result<u16, ParseError> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32_le(&mut self, what: &'static str) -> Result<u32, ParseError> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64_le(&mut self, what: &'static str) -> Result<u64, ParseError> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Bitcoin CompactSize integer.
    fn varint(&mut self, what: &'static str) -> Result<u64, ParseError> {
        let first = self.u8(what)?;
        Ok(match first {
            0xfd => self.u16_le(what)? as u64,
            0xfe => self.u32_le(what)? as u64,
            0xff => self.u64_le(what)?,
            n => n as u64,
        })
    }

    /// A length-prefixed byte string. The declared length is checked against
    /// the remaining data before any allocation.
    fn varbytes(&mut self, what: &'static str) -> Result<&'a [u8], ParseError> {
        let len = self.varint(what)?;
        if len > self.remaining() as u64 {
            return Err(ParseError::Truncated(what));
        }
        self.take(len as usize, what)
    }
}

// ---------------------------------------------------------------------------
// Transaction parsing
// ---------------------------------------------------------------------------

struct RawInput {
    prev_txid: [u8; 32],
    vout: u32,
    script_sig_len: usize,
}

struct RawTx {
    version: i32,
    inputs: Vec<RawInput>,
    outputs: Vec<(u64, Vec<u8>)>,
    locktime: u32,
    /// Double-SHA256 of the non-witness serialisation, internal byte order.
    txid: [u8; 32],
}

/// Parse a serialised transaction. With `allow_witness`, the BIP-144
/// marker/flag and witness stacks are accepted and skipped; without it they
/// are rejected (an unsigned PSBT transaction must be legacy-serialised).
/// The whole slice must be consumed.
fn parse_tx(bytes: &[u8], allow_witness: bool, what: &'static str) -> Result<RawTx, ParseError> {
    let mut r = Reader::new(bytes);
    let version_bytes = r.take(4, what)?;
    let version = i32::from_le_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);

    let mut has_witness = false;
    if r.remaining() >= 2 && r.data[r.pos] == 0x00 && r.data[r.pos + 1] == 0x01 {
        if !allow_witness {
            return Err(ParseError::Invalid(format!(
                "{what}: unsigned transaction must not use witness serialisation"
            )));
        }
        r.take(2, what)?;
        has_witness = true;
    }

    let body_start = r.pos;
    let vin_count = r.varint(what)?;
    if vin_count == 0 {
        return Err(ParseError::Invalid(format!(
            "{what}: transaction has no inputs"
        )));
    }
    let mut inputs = Vec::new();
    for _ in 0..vin_count {
        let txid_slice = r.take(32, what)?;
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(txid_slice);
        let vout = r.u32_le(what)?;
        let script_sig = r.varbytes(what)?;
        let _sequence = r.u32_le(what)?;
        inputs.push(RawInput {
            prev_txid,
            vout,
            script_sig_len: script_sig.len(),
        });
    }
    let vout_count = r.varint(what)?;
    if vout_count == 0 {
        return Err(ParseError::Invalid(format!(
            "{what}: transaction has no outputs"
        )));
    }
    let mut outputs = Vec::new();
    for _ in 0..vout_count {
        let value = r.u64_le(what)?;
        let script = r.varbytes(what)?;
        outputs.push((value, script.to_vec()));
    }
    let body_end = r.pos;

    if has_witness {
        for _ in 0..inputs.len() {
            let items = r.varint(what)?;
            for _ in 0..items {
                r.varbytes(what)?;
            }
        }
    }

    let locktime_bytes = r.take(4, what)?;
    let locktime = u32::from_le_bytes([
        locktime_bytes[0],
        locktime_bytes[1],
        locktime_bytes[2],
        locktime_bytes[3],
    ]);

    if !r.is_empty() {
        return Err(ParseError::Invalid(format!(
            "{what}: trailing bytes after transaction"
        )));
    }

    let mut legacy = Vec::with_capacity(8 + body_end - body_start);
    legacy.extend_from_slice(version_bytes);
    legacy.extend_from_slice(&bytes[body_start..body_end]);
    legacy.extend_from_slice(locktime_bytes);
    let txid = double_sha256(&legacy);

    Ok(RawTx {
        version,
        inputs,
        outputs,
        locktime,
        txid,
    })
}

// ---------------------------------------------------------------------------
// PSBT parsing
// ---------------------------------------------------------------------------

const PSBT_MAGIC: &[u8; 5] = b"psbt\xff";

const GLOBAL_UNSIGNED_TX: u8 = 0x00;
const GLOBAL_VERSION: u8 = 0xfb;
const IN_NON_WITNESS_UTXO: u8 = 0x00;
const IN_WITNESS_UTXO: u8 = 0x01;
const IN_PARTIAL_SIG: u8 = 0x02;
const IN_BIP32_DERIVATION: u8 = 0x06;
const OUT_BIP32_DERIVATION: u8 = 0x02;
const OUT_TAP_BIP32_DERIVATION: u8 = 0x07;

/// Key/value entries of one PSBT map, borrowed from the input.
type KeyValueMap<'a> = Vec<(&'a [u8], &'a [u8])>;

/// Read one key/value map up to and including its 0x00 separator.
/// Duplicate keys are rejected as BIP-174 requires.
fn read_map<'a>(r: &mut Reader<'a>, what: &'static str) -> Result<KeyValueMap<'a>, ParseError> {
    let mut entries: KeyValueMap<'a> = Vec::new();
    loop {
        let key_len = r.varint(what)?;
        if key_len == 0 {
            return Ok(entries);
        }
        if key_len > r.remaining() as u64 {
            return Err(ParseError::Truncated(what));
        }
        let key = r.take(key_len as usize, what)?;
        let value = r.varbytes(what)?;
        if entries.iter().any(|(k, _)| *k == key) {
            return Err(ParseError::Invalid(format!("{what}: duplicate key")));
        }
        entries.push((key, value));
    }
}

/// Parse a raw PSBT (magic `psbt\xff`).
pub fn parse_psbt_bytes(bytes: &[u8]) -> Result<Psbt, ParseError> {
    if !bytes.starts_with(PSBT_MAGIC) {
        return Err(ParseError::Magic);
    }
    let mut r = Reader::new(bytes);
    r.take(PSBT_MAGIC.len(), "magic")?;

    // Global map.
    let global = read_map(&mut r, "global map")?;
    let mut unsigned_tx: Option<RawTx> = None;
    for (key, value) in &global {
        match key {
            [GLOBAL_UNSIGNED_TX] => {
                unsigned_tx = Some(parse_tx(value, false, "unsigned transaction")?);
            }
            [GLOBAL_VERSION] => {
                if value.len() != 4 {
                    return Err(ParseError::Invalid(
                        "global version must be 4 bytes".to_string(),
                    ));
                }
                let v = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                if v != 0 {
                    return Err(ParseError::Invalid(format!(
                        "PSBT version {v} is not supported (only v0)"
                    )));
                }
            }
            _ => {}
        }
    }
    let tx = unsigned_tx
        .ok_or_else(|| ParseError::Invalid("missing unsigned transaction".to_string()))?;
    if tx.inputs.iter().any(|i| i.script_sig_len != 0) {
        return Err(ParseError::Invalid(
            "unsigned transaction has non-empty scriptSig".to_string(),
        ));
    }

    // Input maps.
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        let map = read_map(&mut r, "input map")?;
        let mut value_from_non_witness: Option<u64> = None;
        let mut value_from_witness: Option<u64> = None;
        let mut has_partial_sig = false;
        let mut has_derivation = false;
        for (key, value) in &map {
            match key {
                [IN_NON_WITNESS_UTXO] => {
                    let prev = parse_tx(value, true, "non_witness_utxo")?;
                    if prev.txid != raw.prev_txid {
                        return Err(ParseError::Invalid(
                            "non_witness_utxo does not match the input's previous txid".to_string(),
                        ));
                    }
                    let out = prev.outputs.get(raw.vout as usize).ok_or_else(|| {
                        ParseError::Invalid(
                            "input vout is out of range for non_witness_utxo".to_string(),
                        )
                    })?;
                    value_from_non_witness = Some(out.0);
                }
                [IN_WITNESS_UTXO] => {
                    let mut wr = Reader::new(value);
                    let amount = wr.u64_le("witness_utxo")?;
                    let _script = wr.varbytes("witness_utxo")?;
                    if !wr.is_empty() {
                        return Err(ParseError::Invalid(
                            "witness_utxo has trailing bytes".to_string(),
                        ));
                    }
                    value_from_witness = Some(amount);
                }
                [IN_PARTIAL_SIG, ..] => has_partial_sig = true,
                [IN_BIP32_DERIVATION, ..] => has_derivation = true,
                _ => {}
            }
        }
        if let (Some(a), Some(b)) = (value_from_non_witness, value_from_witness) {
            if a != b {
                return Err(ParseError::Invalid(
                    "witness_utxo and non_witness_utxo disagree on the input value".to_string(),
                ));
            }
        }
        inputs.push(TxInput {
            prev_txid: raw.prev_txid,
            vout: raw.vout,
            value_sats: value_from_non_witness.or(value_from_witness),
            has_partial_sig,
            has_derivation,
        });
    }

    // Output maps.
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    let mut output_is_ours = Vec::with_capacity(tx.outputs.len());
    for (value_sats, script) in tx.outputs {
        let map = read_map(&mut r, "output map")?;
        let ours = map.iter().any(|(key, _)| {
            matches!(
                key,
                [OUT_BIP32_DERIVATION, ..] | [OUT_TAP_BIP32_DERIVATION, ..]
            )
        });
        output_is_ours.push(ours);
        let script_kind = classify_script(&script);
        let address = address_for_script(&script, Network::Mainnet);
        outputs.push(TxOutput {
            value_sats,
            script_pubkey: script,
            address,
            script_kind,
        });
    }

    if !r.is_empty() {
        return Err(ParseError::Invalid(
            "trailing bytes after the last output map".to_string(),
        ));
    }

    Ok(Psbt {
        version: tx.version,
        locktime: tx.locktime,
        inputs,
        outputs,
        output_is_ours,
    })
}

/// Parse a base64-encoded PSBT (the usual wallet interchange form).
pub fn parse_psbt_base64(text: &str) -> Result<Psbt, ParseError> {
    parse_psbt_bytes(&decode_base64(text.trim())?)
}

/// Parse a hex-encoded PSBT.
pub fn parse_psbt_hex(text: &str) -> Result<Psbt, ParseError> {
    parse_psbt_bytes(&decode_hex(text.trim())?)
}

/// Auto-detect: hex if all hex chars, else base64.
pub fn parse_psbt(text: &str) -> Result<Psbt, ParseError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Encoding("empty input".to_string()));
    }
    if trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        parse_psbt_hex(trimmed)
    } else {
        parse_psbt_base64(trimmed)
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Signing policy an independent approver would enforce. All limits are
/// optional; unset means not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigningPolicy {
    /// Allowed destination addresses; empty = unrestricted (which is itself
    /// a finding).
    pub allowed_destinations: Vec<String>,
    pub max_fee_sats: Option<u64>,
    pub max_fee_rate_sat_vb: Option<u64>,
    pub max_withdrawal_sats: Option<u64>,
    /// Require every non-destination output to carry derivation info proving
    /// it belongs to the wallet.
    pub require_change_validation: bool,
    /// Require outputs to be verified on a channel independent of the host
    /// that built the PSBT (hardware screen, second device, policy server).
    pub require_independent_output_verification: bool,
    /// Whether such an independent channel actually exists.
    pub independent_verification_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Violation {
    UnrestrictedDestinations,
    UnapprovedDestination,
    MissingChangeValidation,
    ExcessiveFee,
    ExcessiveFeeRate,
    WithdrawalLimitExceeded,
    NoIndependentOutputVerification,
    FeeUnknown,
    OpReturnPayload,
}

impl Violation {
    pub fn label(&self) -> &'static str {
        match self {
            Violation::UnrestrictedDestinations => "no destination allowlist",
            Violation::UnapprovedDestination => "unapproved destination",
            Violation::MissingChangeValidation => "change cannot be validated",
            Violation::ExcessiveFee => "fee exceeds limit",
            Violation::ExcessiveFeeRate => "fee rate exceeds limit",
            Violation::WithdrawalLimitExceeded => "withdrawal limit exceeded",
            Violation::NoIndependentOutputVerification => "no independent output verification",
            Violation::FeeUnknown => "fee cannot be determined",
            Violation::OpReturnPayload => "OP_RETURN data output",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Violation::UnapprovedDestination | Violation::WithdrawalLimitExceeded => {
                Severity::Critical
            }
            Violation::NoIndependentOutputVerification
            | Violation::UnrestrictedDestinations
            | Violation::MissingChangeValidation => Severity::High,
            Violation::ExcessiveFee | Violation::ExcessiveFeeRate | Violation::FeeUnknown => {
                Severity::Medium
            }
            Violation::OpReturnPayload => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFinding {
    pub violation: Violation,
    pub detail: String,
    pub output_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReport {
    pub findings: Vec<PolicyFinding>,
    /// Value of outputs the wallet does not claim as its own.
    pub external_outputs_sats: u64,
    /// Value of outputs carrying wallet derivation info.
    pub change_outputs_sats: u64,
    pub fee_sats: Option<u64>,
    /// Worst severity among the findings; None when there are none.
    pub severity: Option<Severity>,
}

/// Severity rank independent of the enum's declaration order.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 3,
        Severity::High => 2,
        Severity::Medium => 1,
        Severity::Low => 0,
    }
}

fn worst_severity(findings: &[PolicyFinding]) -> Option<Severity> {
    findings
        .iter()
        .map(|f| f.violation.severity())
        .max_by_key(|s| severity_rank(*s))
}

/// Compare an output address with an allowlist entry: case-insensitive for
/// bech32/bech32m (which is case-agnostic by design), exact for base58.
fn address_matches(derived: &str, allowed: &str) -> bool {
    if derived == allowed {
        return true;
    }
    let is_bech32 =
        derived.starts_with("bc1") || derived.starts_with("tb1") || derived.starts_with("bcrt1");
    is_bech32 && derived.eq_ignore_ascii_case(allowed.trim())
}

fn is_allowed(address: Option<&str>, policy: &SigningPolicy) -> bool {
    match address {
        Some(addr) => policy
            .allowed_destinations
            .iter()
            .any(|a| address_matches(addr, a)),
        None => false,
    }
}

/// Rough virtual size estimate used for the fee-rate check: overhead plus a
/// typical segwit input and output. Real sizes vary with script type and
/// signature count; this is a guard rail, not an accounting tool.
fn estimate_vsize(inputs: usize, outputs: usize) -> u64 {
    10 + (inputs as u64).saturating_mul(68) + (outputs as u64).saturating_mul(31)
}

/// Evaluate a PSBT against a policy for a given network (addresses are
/// derived with that network's prefixes and compared case-insensitively for
/// bech32, exactly for base58).
///
/// Rules:
/// - `allowed_destinations` empty => `UnrestrictedDestinations` (once).
/// - with a non-empty allowlist, every output that is not ours and not in
///   it => `UnapprovedDestination` (per output). OP_RETURN outputs are never
///   destinations; they produce `OpReturnPayload` instead.
/// - `require_change_validation` and an output exists that has no
///   derivation info and is not an allowed destination =>
///   `MissingChangeValidation` (once): the signer cannot prove where the
///   "change" is going.
/// - fee > `max_fee_sats` => `ExcessiveFee`; fee unknown (missing UTXO info)
///   while any fee limit is set => `FeeUnknown`.
/// - fee rate: vsize estimated as 10 + inputs*68 + outputs*31 and compared
///   with `max_fee_rate_sat_vb` => `ExcessiveFeeRate`.
/// - sum of non-ours outputs > `max_withdrawal_sats` => `WithdrawalLimitExceeded`.
/// - `require_independent_output_verification` without
///   `independent_verification_available` => `NoIndependentOutputVerification`.
pub fn evaluate_policy(psbt: &Psbt, policy: &SigningPolicy, network: Network) -> PolicyReport {
    let mut findings = Vec::new();
    let mut external_outputs_sats: u64 = 0;
    let mut change_outputs_sats: u64 = 0;
    let mut unvalidated_change = false;

    let allowlist_set = !policy.allowed_destinations.is_empty();
    if !allowlist_set {
        findings.push(PolicyFinding {
            violation: Violation::UnrestrictedDestinations,
            detail: "policy has no destination allowlist: any address can be paid".to_string(),
            output_index: None,
        });
    }

    for (index, output) in psbt.outputs.iter().enumerate() {
        let ours = psbt.output_is_ours.get(index).copied().unwrap_or(false);
        let address = address_for_script(&output.script_pubkey, network);
        let approved = is_allowed(address.as_deref(), policy);

        if ours && !approved {
            change_outputs_sats = change_outputs_sats.saturating_add(output.value_sats);
            continue;
        }
        external_outputs_sats = external_outputs_sats.saturating_add(output.value_sats);

        if output.script_kind == ScriptKind::OpReturn {
            findings.push(PolicyFinding {
                violation: Violation::OpReturnPayload,
                detail: format!(
                    "output {index} is an OP_RETURN data payload of {} bytes carrying {} sats",
                    output.script_pubkey.len().saturating_sub(1),
                    output.value_sats
                ),
                output_index: Some(index),
            });
            continue;
        }

        if !approved {
            unvalidated_change = true;
            if allowlist_set {
                let shown = address
                    .clone()
                    .unwrap_or_else(|| format!("{} script", output.script_kind.label()));
                findings.push(PolicyFinding {
                    violation: Violation::UnapprovedDestination,
                    detail: format!(
                        "output {index} pays {} sats to {shown}, not on the allowlist",
                        output.value_sats
                    ),
                    output_index: Some(index),
                });
            }
        }
    }

    if policy.require_change_validation && unvalidated_change {
        findings.push(PolicyFinding {
            violation: Violation::MissingChangeValidation,
            detail:
                "an output carries no wallet derivation info and is not an approved destination; \
                     the signer cannot prove it is change"
                    .to_string(),
            output_index: None,
        });
    }

    let fee_sats = psbt.fee_sats();
    let fee_limit_set = policy.max_fee_sats.is_some() || policy.max_fee_rate_sat_vb.is_some();
    match fee_sats {
        None if fee_limit_set => findings.push(PolicyFinding {
            violation: Violation::FeeUnknown,
            detail: "fee cannot be computed: an input has no witness_utxo or non_witness_utxo"
                .to_string(),
            output_index: None,
        }),
        None => {}
        Some(fee) => {
            if let Some(max) = policy.max_fee_sats {
                if fee > max {
                    findings.push(PolicyFinding {
                        violation: Violation::ExcessiveFee,
                        detail: format!("fee of {fee} sats exceeds the limit of {max} sats"),
                        output_index: None,
                    });
                }
            }
            if let Some(max_rate) = policy.max_fee_rate_sat_vb {
                let vsize = estimate_vsize(psbt.inputs.len(), psbt.outputs.len());
                if fee > max_rate.saturating_mul(vsize) {
                    findings.push(PolicyFinding {
                        violation: Violation::ExcessiveFeeRate,
                        detail: format!(
                            "fee of {fee} sats over an estimated {vsize} vbytes is about {} sat/vB, above the limit of {max_rate} sat/vB",
                            fee / vsize.max(1)
                        ),
                        output_index: None,
                    });
                }
            }
        }
    }

    if let Some(max) = policy.max_withdrawal_sats {
        if external_outputs_sats > max {
            findings.push(PolicyFinding {
                violation: Violation::WithdrawalLimitExceeded,
                detail: format!(
                    "{external_outputs_sats} sats leave the wallet, above the limit of {max} sats"
                ),
                output_index: None,
            });
        }
    }

    if policy.require_independent_output_verification && !policy.independent_verification_available
    {
        findings.push(PolicyFinding {
            violation: Violation::NoIndependentOutputVerification,
            detail: "outputs are only verified by the host that built the transaction".to_string(),
            output_index: None,
        });
    }

    let severity = worst_severity(&findings);
    PolicyReport {
        findings,
        external_outputs_sats,
        change_outputs_sats,
        fee_sats,
        severity,
    }
}

/// Describe a signing capability without a PSBT in hand: what a signer
/// governed by this policy would accept. A policy with no allowlist, no
/// independent verification or no change validation describes a signer that
/// will sign anything handed to it.
pub fn assess_signer_policy(policy: &SigningPolicy) -> PolicyReport {
    let mut findings = Vec::new();
    if policy.allowed_destinations.is_empty() {
        findings.push(PolicyFinding {
            violation: Violation::UnrestrictedDestinations,
            detail: "signer has no destination allowlist: it will pay any address".to_string(),
            output_index: None,
        });
    }
    if !(policy.require_independent_output_verification
        && policy.independent_verification_available)
    {
        let detail = if policy.require_independent_output_verification {
            "policy requires independent output verification but no independent channel is available"
        } else {
            "policy does not require outputs to be verified independently of the host"
        };
        findings.push(PolicyFinding {
            violation: Violation::NoIndependentOutputVerification,
            detail: detail.to_string(),
            output_index: None,
        });
    }
    if !policy.require_change_validation {
        findings.push(PolicyFinding {
            violation: Violation::MissingChangeValidation,
            detail: "policy does not require change outputs to prove they belong to the wallet"
                .to_string(),
            output_index: None,
        });
    }
    let severity = worst_severity(&findings);
    PolicyReport {
        findings,
        external_outputs_sats: 0,
        change_outputs_sats: 0,
        fee_sats: None,
        severity,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- tiny encoder helpers (test only) ---

    fn push_varint(out: &mut Vec<u8>, n: u64) {
        if n < 0xfd {
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        } else if n <= 0xffff_ffff {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }

    fn push_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
        push_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn push_kv(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
        push_varbytes(out, key);
        push_varbytes(out, value);
    }

    fn encode_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in entries {
            push_kv(&mut out, k, v);
        }
        out.push(0x00);
        out
    }

    /// Legacy-serialised transaction. `witness` (one stack per input) adds
    /// the BIP-144 marker/flag and witness section when present.
    fn encode_tx(
        version: i32,
        inputs: &[([u8; 32], u32, Vec<u8>)],
        outputs: &[(u64, Vec<u8>)],
        locktime: u32,
        witness: Option<&[Vec<Vec<u8>>]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_le_bytes());
        if witness.is_some() {
            out.push(0x00);
            out.push(0x01);
        }
        push_varint(&mut out, inputs.len() as u64);
        for (txid, vout, script_sig) in inputs {
            out.extend_from_slice(txid);
            out.extend_from_slice(&vout.to_le_bytes());
            push_varbytes(&mut out, script_sig);
            out.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
        }
        push_varint(&mut out, outputs.len() as u64);
        for (value, script) in outputs {
            out.extend_from_slice(&value.to_le_bytes());
            push_varbytes(&mut out, script);
        }
        if let Some(stacks) = witness {
            for stack in stacks {
                push_varint(&mut out, stack.len() as u64);
                for item in stack {
                    push_varbytes(&mut out, item);
                }
            }
        }
        out.extend_from_slice(&locktime.to_le_bytes());
        out
    }

    fn encode_psbt(
        unsigned_tx: &[u8],
        input_maps: &[Vec<(Vec<u8>, Vec<u8>)>],
        output_maps: &[Vec<(Vec<u8>, Vec<u8>)>],
    ) -> Vec<u8> {
        let mut out = PSBT_MAGIC.to_vec();
        out.extend(encode_map(&[(
            vec![GLOBAL_UNSIGNED_TX],
            unsigned_tx.to_vec(),
        )]));
        for m in input_maps {
            out.extend(encode_map(m));
        }
        for m in output_maps {
            out.extend(encode_map(m));
        }
        out
    }

    fn p2wpkh(program: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(program);
        s
    }

    fn witness_utxo(value: u64, script: &[u8]) -> Vec<u8> {
        let mut v = value.to_le_bytes().to_vec();
        push_varbytes(&mut v, script);
        v
    }

    fn derivation_key(key_type: u8) -> Vec<u8> {
        let mut k = vec![key_type, 0x02];
        k.extend_from_slice(&[0x33; 32]);
        k
    }

    fn derivation_value() -> Vec<u8> {
        // fingerprint + m/84'/0'/0'/1/0
        let mut v = vec![0xd3, 0x4d, 0xb3, 0x3f];
        for idx in [0x8000_0054u32, 0x8000_0000, 0x8000_0000, 1, 0] {
            v.extend_from_slice(&idx.to_le_bytes());
        }
        v
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn encode_base64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            s.push(T[(n >> 18) as usize & 63] as char);
            s.push(T[(n >> 12) as usize & 63] as char);
            s.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            s.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        s
    }

    // BIP-173 vector program for bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
    const EXTERNAL_PROGRAM: [u8; 20] = [
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3,
        0x23, 0xf1, 0x43, 0x3b, 0xd6,
    ];
    const EXTERNAL_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const CHANGE_PROGRAM: [u8; 20] = [0x11; 20];
    const INPUT_VALUE: u64 = 100_000;
    const EXTERNAL_VALUE: u64 = 50_000;
    const CHANGE_VALUE: u64 = 39_000;

    /// 1 input (witness_utxo 100k), 2 outputs: external P2WPKH 50k and
    /// change P2WPKH 39k with output derivation. Fee 11k.
    fn sample_psbt_bytes() -> Vec<u8> {
        let tx = encode_tx(
            2,
            &[([0xaa; 32], 1, vec![])],
            &[
                (EXTERNAL_VALUE, p2wpkh(&EXTERNAL_PROGRAM)),
                (CHANGE_VALUE, p2wpkh(&CHANGE_PROGRAM)),
            ],
            0,
            None,
        );
        let input_map = vec![
            (
                vec![IN_WITNESS_UTXO],
                witness_utxo(INPUT_VALUE, &p2wpkh(&[0x22; 20])),
            ),
            (derivation_key(IN_BIP32_DERIVATION), derivation_value()),
        ];
        let output_maps = vec![
            vec![],
            vec![(derivation_key(OUT_BIP32_DERIVATION), derivation_value())],
        ];
        encode_psbt(&tx, &[input_map], &output_maps)
    }

    fn sample_psbt() -> Psbt {
        parse_psbt_bytes(&sample_psbt_bytes()).expect("sample PSBT parses")
    }

    fn strict_policy() -> SigningPolicy {
        SigningPolicy {
            allowed_destinations: vec![EXTERNAL_ADDR.to_string()],
            max_fee_sats: Some(20_000),
            max_fee_rate_sat_vb: Some(500),
            max_withdrawal_sats: Some(1_000_000),
            require_change_validation: true,
            require_independent_output_verification: true,
            independent_verification_available: true,
        }
    }

    fn has(report: &PolicyReport, v: Violation) -> bool {
        report.findings.iter().any(|f| f.violation == v)
    }

    fn count(report: &PolicyReport, v: Violation) -> usize {
        report.findings.iter().filter(|f| f.violation == v).count()
    }

    // --- primitives ---

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Two-block message.
        assert_eq!(
            encode_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn base58check_vectors() {
        // P2PKH of twenty zero bytes: the well-known "1111...4oLvT2" address.
        let mut payload = vec![0x00];
        payload.extend_from_slice(&[0u8; 20]);
        assert_eq!(base58check(&payload), "1111111111111111111114oLvT2");
        // P2SH of twenty zero bytes.
        let mut payload = vec![0x05];
        payload.extend_from_slice(&[0u8; 20]);
        assert_eq!(base58check(&payload), "31h1vYVSYuKP6AhS86fbRdMw9XHieotbST");
    }

    #[test]
    fn bech32_vectors() {
        // BIP-173 P2WPKH.
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&EXTERNAL_PROGRAM);
        assert_eq!(
            address_for_script(&script, Network::Mainnet).as_deref(),
            Some(EXTERNAL_ADDR)
        );
        assert_eq!(classify_script(&script), ScriptKind::P2wpkh);

        // BIP-173 P2WSH on testnet.
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(
            &decode_hex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
                .unwrap(),
        );
        assert_eq!(
            address_for_script(&script, Network::Testnet).as_deref(),
            Some("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        );
        assert_eq!(classify_script(&script), ScriptKind::P2wsh);

        // BIP-350 P2TR (bech32m).
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(
            &decode_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        assert_eq!(
            address_for_script(&script, Network::Mainnet).as_deref(),
            Some("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
        );
        assert_eq!(classify_script(&script), ScriptKind::P2tr);

        // Regtest hrp.
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&EXTERNAL_PROGRAM);
        assert!(address_for_script(&script, Network::Regtest)
            .unwrap()
            .starts_with("bcrt1q"));
        assert!(address_for_script(&script, Network::Signet)
            .unwrap()
            .starts_with("tb1q"));
    }

    #[test]
    fn legacy_address_derivation() {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0u8; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(classify_script(&p2pkh), ScriptKind::P2pkh);
        assert_eq!(
            address_for_script(&p2pkh, Network::Mainnet).as_deref(),
            Some("1111111111111111111114oLvT2")
        );
        assert!(address_for_script(&p2pkh, Network::Testnet)
            .unwrap()
            .starts_with('m'));

        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0u8; 20]);
        p2sh.push(0x87);
        assert_eq!(classify_script(&p2sh), ScriptKind::P2sh);
        assert_eq!(
            address_for_script(&p2sh, Network::Mainnet).as_deref(),
            Some("31h1vYVSYuKP6AhS86fbRdMw9XHieotbST")
        );
        assert!(address_for_script(&p2sh, Network::Testnet)
            .unwrap()
            .starts_with('2'));

        assert_eq!(
            classify_script(&[0x6a, 0x04, 1, 2, 3, 4]),
            ScriptKind::OpReturn
        );
        assert_eq!(
            address_for_script(&[0x6a, 0x04, 1, 2, 3, 4], Network::Mainnet),
            None
        );
        assert_eq!(classify_script(&[0x51]), ScriptKind::Unknown);
        assert_eq!(classify_script(&[]), ScriptKind::Unknown);
    }

    #[test]
    fn hex_and_base64_decoders_are_strict() {
        assert_eq!(decode_hex("00ff7A").unwrap(), vec![0x00, 0xff, 0x7a]);
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());

        assert_eq!(decode_base64("cHNidP8=").unwrap(), b"psbt\xff");
        assert_eq!(decode_base64("YWJj").unwrap(), b"abc");
        assert_eq!(decode_base64("YWI=").unwrap(), b"ab");
        assert_eq!(decode_base64("YQ==").unwrap(), b"a");
        assert!(decode_base64("YQ").is_err(), "missing padding");
        assert!(decode_base64("YQ===").is_err());
        assert!(decode_base64("YW Jj").is_err(), "interior whitespace");
        assert!(decode_base64("YW-j").is_err(), "url-safe alphabet");
        assert!(decode_base64("").is_err());
        // Round trip the sample.
        let bytes = sample_psbt_bytes();
        assert_eq!(decode_base64(&encode_base64(&bytes)).unwrap(), bytes);
    }

    // --- parsing ---

    #[test]
    fn parses_sample_psbt() {
        let psbt = sample_psbt();
        assert_eq!(psbt.version, 2);
        assert_eq!(psbt.locktime, 0);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
        assert_eq!(psbt.inputs[0].prev_txid, [0xaa; 32]);
        assert_eq!(psbt.inputs[0].vout, 1);
        assert_eq!(psbt.inputs[0].value_sats, Some(INPUT_VALUE));
        assert!(psbt.inputs[0].has_derivation);
        assert!(!psbt.inputs[0].has_partial_sig);
        assert_eq!(psbt.fully_signed_inputs(), 0);

        assert_eq!(psbt.outputs[0].value_sats, EXTERNAL_VALUE);
        assert_eq!(psbt.outputs[0].script_kind, ScriptKind::P2wpkh);
        assert_eq!(psbt.outputs[0].address.as_deref(), Some(EXTERNAL_ADDR));
        assert_eq!(psbt.outputs[1].value_sats, CHANGE_VALUE);
        assert_eq!(psbt.output_is_ours, vec![false, true]);

        assert_eq!(psbt.total_input_sats(), Some(INPUT_VALUE));
        assert_eq!(psbt.total_output_sats(), EXTERNAL_VALUE + CHANGE_VALUE);
        assert_eq!(psbt.fee_sats(), Some(11_000));
    }

    #[test]
    fn parses_base64_hex_and_autodetect() {
        let bytes = sample_psbt_bytes();
        let expected = sample_psbt();
        let b64 = encode_base64(&bytes);
        assert!(b64.starts_with("cHNidP8"));
        assert_eq!(parse_psbt_base64(&b64).unwrap(), expected);
        assert_eq!(parse_psbt_base64(&format!("  {b64}\n")).unwrap(), expected);
        let hex = encode_hex(&bytes);
        assert_eq!(parse_psbt_hex(&hex).unwrap(), expected);
        assert_eq!(parse_psbt_hex(&hex.to_uppercase()).unwrap(), expected);
        assert_eq!(parse_psbt(&b64).unwrap(), expected);
        assert_eq!(parse_psbt(&hex).unwrap(), expected);
        assert!(matches!(parse_psbt(""), Err(ParseError::Encoding(_))));
        assert!(matches!(
            parse_psbt("not a psbt!"),
            Err(ParseError::Encoding(_))
        ));
        assert!(matches!(parse_psbt("deadbeef"), Err(ParseError::Magic)));
        assert!(matches!(parse_psbt_base64("AAAA"), Err(ParseError::Magic)));
    }

    #[test]
    fn partial_sig_and_tap_derivation_are_detected() {
        let tx = encode_tx(
            2,
            &[([0xaa; 32], 0, vec![])],
            &[(1_000, p2wpkh(&EXTERNAL_PROGRAM))],
            0,
            None,
        );
        let mut sig_key = vec![IN_PARTIAL_SIG, 0x02];
        sig_key.extend_from_slice(&[0x44; 32]);
        let input_map = vec![
            (
                vec![IN_WITNESS_UTXO],
                witness_utxo(2_000, &p2wpkh(&[0x22; 20])),
            ),
            (sig_key, vec![0x30, 0x01, 0x00]),
        ];
        let output_maps = vec![vec![(
            derivation_key(OUT_TAP_BIP32_DERIVATION),
            vec![0x00, 1, 2, 3, 4],
        )]];
        let psbt = parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &output_maps)).unwrap();
        assert!(psbt.inputs[0].has_partial_sig);
        assert!(!psbt.inputs[0].has_derivation);
        assert_eq!(psbt.fully_signed_inputs(), 1);
        assert_eq!(psbt.output_is_ours, vec![true]);
    }

    #[test]
    fn non_witness_utxo_with_segwit_prev_tx() {
        // Previous transaction: segwit-serialised with a two-item witness.
        let prev_outputs = vec![
            (10_000u64, p2wpkh(&[0x55; 20])),
            (250_000u64, p2wpkh(&[0x66; 20])),
        ];
        let prev_inputs = vec![([0x33; 32], 0u32, vec![])];
        let witness = vec![vec![vec![0x30; 71], vec![0x02; 33]]];
        let prev_segwit = encode_tx(2, &prev_inputs, &prev_outputs, 0, Some(&witness));
        let prev_legacy = encode_tx(2, &prev_inputs, &prev_outputs, 0, None);
        let prev_txid = double_sha256(&prev_legacy);

        let tx = encode_tx(
            2,
            &[(prev_txid, 1, vec![])],
            &[(200_000, p2wpkh(&EXTERNAL_PROGRAM))],
            0,
            None,
        );
        let input_map = vec![(vec![IN_NON_WITNESS_UTXO], prev_segwit.clone())];
        let psbt = parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &[vec![]])).unwrap();
        assert_eq!(psbt.inputs[0].value_sats, Some(250_000));
        assert_eq!(psbt.fee_sats(), Some(50_000));

        // Both utxo forms present and agreeing is fine.
        let input_map = vec![
            (vec![IN_NON_WITNESS_UTXO], prev_segwit.clone()),
            (
                vec![IN_WITNESS_UTXO],
                witness_utxo(250_000, &p2wpkh(&[0x66; 20])),
            ),
        ];
        assert!(parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &[vec![]])).is_ok());

        // Disagreeing values are rejected.
        let input_map = vec![
            (vec![IN_NON_WITNESS_UTXO], prev_segwit.clone()),
            (
                vec![IN_WITNESS_UTXO],
                witness_utxo(999, &p2wpkh(&[0x66; 20])),
            ),
        ];
        assert!(matches!(
            parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &[vec![]])),
            Err(ParseError::Invalid(_))
        ));

        // A prev tx whose txid does not match the input is rejected: this
        // is how a host would lie about the input value to hide a fee.
        let tx_wrong = encode_tx(
            2,
            &[([0x99; 32], 1, vec![])],
            &[(200_000, p2wpkh(&EXTERNAL_PROGRAM))],
            0,
            None,
        );
        let input_map = vec![(vec![IN_NON_WITNESS_UTXO], prev_segwit.clone())];
        assert!(matches!(
            parse_psbt_bytes(&encode_psbt(&tx_wrong, &[input_map], &[vec![]])),
            Err(ParseError::Invalid(_))
        ));

        // vout out of range.
        let tx_oob = encode_tx(
            2,
            &[(prev_txid, 7, vec![])],
            &[(200_000, p2wpkh(&EXTERNAL_PROGRAM))],
            0,
            None,
        );
        let input_map = vec![(vec![IN_NON_WITNESS_UTXO], prev_segwit)];
        assert!(matches!(
            parse_psbt_bytes(&encode_psbt(&tx_oob, &[input_map], &[vec![]])),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_structural_violations() {
        let outputs = vec![(1_000u64, p2wpkh(&EXTERNAL_PROGRAM))];

        // Non-empty scriptSig in the unsigned tx.
        let tx = encode_tx(2, &[([0xaa; 32], 0, vec![0x51])], &outputs, 0, None);
        assert!(matches!(
            parse_psbt_bytes(&encode_psbt(&tx, &[vec![]], &[vec![]])),
            Err(ParseError::Invalid(_))
        ));

        // Witness-serialised unsigned tx.
        let tx = encode_tx(2, &[([0xaa; 32], 0, vec![])], &outputs, 0, Some(&[vec![]]));
        assert!(matches!(
            parse_psbt_bytes(&encode_psbt(&tx, &[vec![]], &[vec![]])),
            Err(ParseError::Invalid(_))
        ));

        // Missing unsigned tx.
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend(encode_map(&[(vec![0x01], vec![0x00])]));
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Invalid(_))
        ));

        // Duplicate key in a map.
        let tx = encode_tx(2, &[([0xaa; 32], 0, vec![])], &outputs, 0, None);
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend(encode_map(&[
            (vec![GLOBAL_UNSIGNED_TX], tx.clone()),
            (vec![GLOBAL_UNSIGNED_TX], tx.clone()),
        ]));
        bytes.extend(encode_map(&[]));
        bytes.extend(encode_map(&[]));
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Invalid(_))
        ));

        // PSBT v2 declared.
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend(encode_map(&[
            (vec![GLOBAL_UNSIGNED_TX], tx.clone()),
            (vec![GLOBAL_VERSION], 2u32.to_le_bytes().to_vec()),
        ]));
        bytes.extend(encode_map(&[]));
        bytes.extend(encode_map(&[]));
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Invalid(_))
        ));

        // Trailing garbage after the last map.
        let mut bytes = encode_psbt(&tx, &[vec![]], &[vec![]]);
        bytes.push(0x00);
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Invalid(_))
        ));

        // Missing output map.
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend(encode_map(&[(vec![GLOBAL_UNSIGNED_TX], tx)]));
        bytes.extend(encode_map(&[]));
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Truncated(_))
        ));

        // Wrong magic.
        assert_eq!(parse_psbt_bytes(b"psbt\x00"), Err(ParseError::Magic));
        assert_eq!(parse_psbt_bytes(b""), Err(ParseError::Magic));
    }

    #[test]
    fn every_prefix_and_byte_flip_is_handled_without_panic() {
        let bytes = sample_psbt_bytes();
        for len in 0..bytes.len() {
            let result = parse_psbt_bytes(&bytes[..len]);
            assert!(result.is_err(), "prefix of {len} bytes should not parse");
        }
        assert!(parse_psbt_bytes(&bytes).is_ok());

        // Flip every byte to a few hostile values; the parser must return.
        for i in 0..bytes.len() {
            for v in [0x00u8, 0x01, 0xfd, 0xfe, 0xff] {
                let mut mutated = bytes.clone();
                mutated[i] = v;
                let _ = parse_psbt_bytes(&mutated);
            }
        }

        // Garbage of assorted shapes.
        let _ = parse_psbt_bytes(&[0xff; 64]);
        let _ = parse_psbt_bytes(b"psbt\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
        let _ = parse_psbt_bytes(b"psbt\xff\x01\x00\xfe\xff\xff\xff\xff");
        let _ = parse_psbt("cHNidP8BAHECAAAAAf////8=");
        let _ = parse_psbt("70736274ff");
    }

    #[test]
    fn huge_declared_lengths_do_not_allocate_or_panic() {
        // Global map key length claims 2^64-1 bytes.
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Truncated(_))
        ));

        // Unsigned tx claims 2^32 inputs.
        let mut tx = 2i32.to_le_bytes().to_vec();
        tx.push(0xfe);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend(encode_map(&[(vec![GLOBAL_UNSIGNED_TX], tx)]));
        assert!(matches!(
            parse_psbt_bytes(&bytes),
            Err(ParseError::Truncated(_))
        ));
    }

    // --- policy ---

    #[test]
    fn allowed_destination_passes_strict_policy() {
        let report = evaluate_policy(&sample_psbt(), &strict_policy(), Network::Mainnet);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.severity, None);
        assert_eq!(report.external_outputs_sats, EXTERNAL_VALUE);
        assert_eq!(report.change_outputs_sats, CHANGE_VALUE);
        assert_eq!(report.fee_sats, Some(11_000));

        // bech32 comparison is case-insensitive.
        let mut policy = strict_policy();
        policy.allowed_destinations = vec![EXTERNAL_ADDR.to_uppercase()];
        assert!(evaluate_policy(&sample_psbt(), &policy, Network::Mainnet)
            .findings
            .is_empty());
    }

    #[test]
    fn unapproved_destination_is_critical() {
        let mut policy = strict_policy();
        policy.allowed_destinations =
            vec!["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".to_string()];
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert_eq!(count(&report, Violation::UnapprovedDestination), 1);
        let finding = report
            .findings
            .iter()
            .find(|f| f.violation == Violation::UnapprovedDestination)
            .unwrap();
        assert_eq!(finding.output_index, Some(0));
        assert!(finding.detail.contains(EXTERNAL_ADDR));
        assert_eq!(report.severity, Some(Severity::Critical));
        // The unapproved output also means the change cannot be validated.
        assert!(has(&report, Violation::MissingChangeValidation));
        assert!(!has(&report, Violation::UnrestrictedDestinations));
    }

    #[test]
    fn network_changes_the_derived_address() {
        // A mainnet allowlist entry does not match on testnet.
        let report = evaluate_policy(&sample_psbt(), &strict_policy(), Network::Testnet);
        assert!(has(&report, Violation::UnapprovedDestination));
        let mut policy = strict_policy();
        policy.allowed_destinations =
            vec!["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string()];
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Testnet);
        assert!(
            !has(&report, Violation::UnapprovedDestination),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn withdrawal_limit_counts_only_external_outputs() {
        let mut policy = strict_policy();
        policy.max_withdrawal_sats = Some(EXTERNAL_VALUE);
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(!has(&report, Violation::WithdrawalLimitExceeded));

        policy.max_withdrawal_sats = Some(EXTERNAL_VALUE - 1);
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(has(&report, Violation::WithdrawalLimitExceeded));
        assert_eq!(report.severity, Some(Severity::Critical));
    }

    #[test]
    fn excessive_fee_and_fee_rate() {
        let mut policy = strict_policy();
        policy.max_fee_sats = Some(10_999);
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(has(&report, Violation::ExcessiveFee));
        assert!(!has(&report, Violation::ExcessiveFeeRate));
        assert_eq!(report.severity, Some(Severity::Medium));

        // vsize estimate: 10 + 68 + 62 = 140 vB; 11_000 sats is ~78 sat/vB.
        let mut policy = strict_policy();
        policy.max_fee_rate_sat_vb = Some(78);
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(
            has(&report, Violation::ExcessiveFeeRate),
            "{:?}",
            report.findings
        );
        policy.max_fee_rate_sat_vb = Some(79);
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(!has(&report, Violation::ExcessiveFeeRate));
    }

    #[test]
    fn fee_unknown_when_utxo_missing() {
        let tx = encode_tx(
            2,
            &[([0xaa; 32], 1, vec![])],
            &[(EXTERNAL_VALUE, p2wpkh(&EXTERNAL_PROGRAM))],
            0,
            None,
        );
        let psbt = parse_psbt_bytes(&encode_psbt(&tx, &[vec![]], &[vec![]])).unwrap();
        assert_eq!(psbt.inputs[0].value_sats, None);
        assert_eq!(psbt.fee_sats(), None);

        let report = evaluate_policy(&psbt, &strict_policy(), Network::Mainnet);
        assert!(has(&report, Violation::FeeUnknown));
        assert!(!has(&report, Violation::ExcessiveFee));
        assert_eq!(report.fee_sats, None);

        // No fee limits set: unknown fee is not a finding.
        let mut policy = strict_policy();
        policy.max_fee_sats = None;
        policy.max_fee_rate_sat_vb = None;
        let report = evaluate_policy(&psbt, &policy, Network::Mainnet);
        assert!(!has(&report, Violation::FeeUnknown));
    }

    #[test]
    fn missing_change_validation() {
        // Same transaction, but the change output has no derivation info.
        let tx = encode_tx(
            2,
            &[([0xaa; 32], 1, vec![])],
            &[
                (EXTERNAL_VALUE, p2wpkh(&EXTERNAL_PROGRAM)),
                (CHANGE_VALUE, p2wpkh(&CHANGE_PROGRAM)),
            ],
            0,
            None,
        );
        let input_map = vec![(
            vec![IN_WITNESS_UTXO],
            witness_utxo(INPUT_VALUE, &p2wpkh(&[0x22; 20])),
        )];
        let psbt = parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &[vec![], vec![]])).unwrap();
        assert_eq!(psbt.output_is_ours, vec![false, false]);

        let report = evaluate_policy(&psbt, &strict_policy(), Network::Mainnet);
        assert_eq!(count(&report, Violation::MissingChangeValidation), 1);
        assert!(has(&report, Violation::UnapprovedDestination));
        assert_eq!(report.external_outputs_sats, EXTERNAL_VALUE + CHANGE_VALUE);
        assert_eq!(report.change_outputs_sats, 0);

        let mut relaxed = strict_policy();
        relaxed.require_change_validation = false;
        let report = evaluate_policy(&psbt, &relaxed, Network::Mainnet);
        assert!(!has(&report, Violation::MissingChangeValidation));
    }

    #[test]
    fn unrestricted_destinations() {
        let mut policy = strict_policy();
        policy.allowed_destinations.clear();
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert_eq!(count(&report, Violation::UnrestrictedDestinations), 1);
        // Without an allowlist no output can be called unapproved.
        assert!(!has(&report, Violation::UnapprovedDestination));
        // The external output cannot be proven to be change either.
        assert!(has(&report, Violation::MissingChangeValidation));
        assert_eq!(report.severity, Some(Severity::High));
    }

    #[test]
    fn independent_verification_missing() {
        let mut policy = strict_policy();
        policy.independent_verification_available = false;
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(has(&report, Violation::NoIndependentOutputVerification));
        assert_eq!(report.severity, Some(Severity::High));

        policy.require_independent_output_verification = false;
        let report = evaluate_policy(&sample_psbt(), &policy, Network::Mainnet);
        assert!(!has(&report, Violation::NoIndependentOutputVerification));
    }

    #[test]
    fn op_return_is_flagged_but_never_a_destination() {
        let tx = encode_tx(
            2,
            &[([0xaa; 32], 1, vec![])],
            &[
                (EXTERNAL_VALUE, p2wpkh(&EXTERNAL_PROGRAM)),
                (0, vec![0x6a, 0x05, b'h', b'e', b'l', b'l', b'o']),
                (CHANGE_VALUE, p2wpkh(&CHANGE_PROGRAM)),
            ],
            0,
            None,
        );
        let input_map = vec![(
            vec![IN_WITNESS_UTXO],
            witness_utxo(INPUT_VALUE, &p2wpkh(&[0x22; 20])),
        )];
        let output_maps = vec![
            vec![],
            vec![],
            vec![(derivation_key(OUT_BIP32_DERIVATION), derivation_value())],
        ];
        let psbt = parse_psbt_bytes(&encode_psbt(&tx, &[input_map], &output_maps)).unwrap();
        assert_eq!(psbt.outputs[1].script_kind, ScriptKind::OpReturn);
        assert_eq!(psbt.outputs[1].address, None);

        let report = evaluate_policy(&psbt, &strict_policy(), Network::Mainnet);
        assert_eq!(count(&report, Violation::OpReturnPayload), 1);
        assert!(!has(&report, Violation::UnapprovedDestination));
        assert!(!has(&report, Violation::MissingChangeValidation));
        assert_eq!(report.severity, Some(Severity::Low));
    }

    #[test]
    fn assess_signer_policy_describes_a_blind_signer() {
        let report = assess_signer_policy(&SigningPolicy::default());
        assert!(has(&report, Violation::UnrestrictedDestinations));
        assert!(has(&report, Violation::NoIndependentOutputVerification));
        assert!(has(&report, Violation::MissingChangeValidation));
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.severity, Some(Severity::High));
        assert_eq!(report.fee_sats, None);

        let report = assess_signer_policy(&strict_policy());
        assert!(report.findings.is_empty());
        assert_eq!(report.severity, None);

        let mut policy = strict_policy();
        policy.independent_verification_available = false;
        let report = assess_signer_policy(&policy);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].violation,
            Violation::NoIndependentOutputVerification
        );
    }

    #[test]
    fn violation_metadata() {
        assert_eq!(
            Violation::UnapprovedDestination.severity(),
            Severity::Critical
        );
        assert_eq!(
            Violation::WithdrawalLimitExceeded.severity(),
            Severity::Critical
        );
        assert_eq!(
            Violation::NoIndependentOutputVerification.severity(),
            Severity::High
        );
        assert_eq!(
            Violation::UnrestrictedDestinations.severity(),
            Severity::High
        );
        assert_eq!(
            Violation::MissingChangeValidation.severity(),
            Severity::High
        );
        assert_eq!(Violation::ExcessiveFee.severity(), Severity::Medium);
        assert_eq!(Violation::ExcessiveFeeRate.severity(), Severity::Medium);
        assert_eq!(Violation::FeeUnknown.severity(), Severity::Medium);
        assert_eq!(Violation::OpReturnPayload.severity(), Severity::Low);
        assert!(!Violation::OpReturnPayload.label().is_empty());
        assert_eq!(
            format!("{}", ParseError::Magic),
            "not a PSBT (missing magic bytes)"
        );
    }
}
