// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Sign a published release: build SHA256SUMS.all over every asset of the
// private release, sign it with the Gorse release key (Ed25519) and upload
// both files so `gorse verify-download` can check a download offline.
//
//   node scripts/release/sign-release.ts vX.Y.Z                 sign and upload
//   node scripts/release/sign-release.ts vX.Y.Z --dry-run --out DIR
//   node scripts/release/sign-release.ts vX.Y.Z --verify-only  check what is published
//
// Signature format v2 binds the release tag into the signature: the signed
// bytes are `<tag>\n` followed by the exact bytes of SHA256SUMS.all, and the
// tag is repeated in the header so a verifier can check it against the tag
// it asked for. Without that, a stale but genuinely signed manifest could be
// served under an invented newer tag and would verify (audit finding). v1
// (signature over the manifest alone) is only parsed for --verify-only of
// releases older than v0.4.2; every new release is signed with v2.
//
// The private key is read from GORSE_RELEASE_SIGNING_KEY_FILE (default
// ~/.config/gorse-release/signing.key), PKCS#8 PEM. Its public half must be
// EXPECTED_PUBLIC_KEY_B64, the key compiled into the CLI; any other key is
// refused so a stale or wrong key file cannot publish a manifest the CLI
// rejects. Nothing here prints key material. No npm dependencies.
import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_PUBLIC_KEY_B64 = 'Dntss+6znmHXEgrCkvZy6GENQOA+bScwD5jtCYdraG0=';
export const MANIFEST_NAME = 'SHA256SUMS.all';
export const SIGNATURE_NAME = 'SHA256SUMS.all.sig';
export const SIGNATURE_FORMAT = 'gorse-release-signature';
export const SIGNATURE_VERSION = 2;
export const SIGNATURE_HEADER = `${SIGNATURE_FORMAT} v${SIGNATURE_VERSION}`;
// The first release signed with v2; everything before it carries a v1 signature.
export const FIRST_V2_TAG = 'v0.4.2';
export const PRIVATE_REPO = 'jamestagg/hedgehog';
export const DEFAULT_KEY_FILE = join(homedir(), '.config', 'gorse-release', 'signing.key');

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// Tags the script will look at (gh release view); pre-release suffixes allowed.
const TAG_PATTERN = /^v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/;
// Tags a v2 signature may bind: plain releases only, exactly what the CLI verifies.
const SIGNED_TAG_PATTERN = /^v\d+\.\d+\.\d+$/;
const HEX64 = /^[0-9a-f]{64}$/;
const MANIFEST_FILES = new Set([MANIFEST_NAME, SIGNATURE_NAME]);

export interface ManifestEntry { name: string; sha256: string }
export interface ParsedSignature { version: 1 | 2; keyId: string; tag?: string; signature: Buffer }
export interface VerifyOptions { allowV1?: boolean }

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export function isValidAssetName(name: string): boolean {
  return name.length > 0 && name.length <= 255 && !/[\s\0/\\]/.test(name) && name !== '.' && name !== '..' && !MANIFEST_FILES.has(name);
}

export function isSignableTag(tag: string): boolean { return SIGNED_TAG_PATTERN.test(tag); }

// Numeric comparison of two plain vX.Y.Z tags: negative, zero or positive.
export function compareTags(a: string, b: string): number {
  if (!isSignableTag(a) || !isSignableTag(b)) throw new Error(`Cannot compare tags ${JSON.stringify(a)} and ${JSON.stringify(b)}.`);
  const pa = a.slice(1).split('.').map(Number);
  const pb = b.slice(1).split('.').map(Number);
  for (let i = 0; i < 3; i += 1) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

// One line per asset, `<sha256>  <name>`, sorted by name byte-wise, LF only.
export function buildManifest(entries: readonly ManifestEntry[]): string {
  if (entries.length === 0) throw new Error('A release manifest needs at least one asset.');
  const seen = new Set<string>();
  for (const entry of entries) {
    if (!isValidAssetName(entry.name)) throw new Error(`Asset name cannot be listed in the manifest: ${JSON.stringify(entry.name)}`);
    if (!HEX64.test(entry.sha256)) throw new Error(`Digest for ${entry.name} is not 64 lowercase hex characters.`);
    if (seen.has(entry.name)) throw new Error(`Asset listed twice: ${entry.name}`);
    seen.add(entry.name);
  }
  return [...entries].sort((a, b) => compareBytes(a.name, b.name)).map(e => `${e.sha256}  ${e.name}\n`).join('');
}

// Strict inverse of buildManifest: rejects anything buildManifest would not emit.
export function parseManifest(text: string): ManifestEntry[] {
  if (text.length === 0 || !text.endsWith('\n')) throw new Error('Manifest must end with a newline.');
  if (/[^\x20-\x7e\n]/.test(text)) throw new Error('Manifest must be printable ASCII with LF line endings.');
  const lines = text.slice(0, -1).split('\n');
  const entries: ManifestEntry[] = [];
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  (\S+)$/.exec(line);
    if (!match || !isValidAssetName(match[2])) throw new Error(`Malformed manifest line: ${JSON.stringify(line)}`);
    entries.push({ name: match[2], sha256: match[1] });
  }
  if (buildManifest(entries) !== text) throw new Error('Manifest is not in canonical sorted form.');
  return entries;
}

export function publicKeyB64(privateKey: KeyObject): string {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Signing key must be an Ed25519 private key.');
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  if (spki.length !== 44 || !spki.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) throw new Error('Unexpected Ed25519 public key encoding.');
  return spki.subarray(12).toString('base64');
}

export function publicKeyFromB64(b64: string): KeyObject {
  const raw = Buffer.from(b64, 'base64');
  if (raw.length !== 32 || raw.toString('base64') !== b64) throw new Error('Public key must be 32 raw bytes in padded base64.');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function keyId(b64: string): string { return b64.slice(0, 8); }

export function assertExpectedKey(privateKey: KeyObject, expectedPublicKeyB64: string = EXPECTED_PUBLIC_KEY_B64): string {
  const actual = publicKeyB64(privateKey);
  if (actual !== expectedPublicKeyB64) {
    throw new Error(`Refusing to sign: the key file's public key (${keyId(actual)}...) is not the Gorse release key (${keyId(expectedPublicKeyB64)}...). ` +
      'A manifest signed with it would be rejected by every installed copy of gorse.');
  }
  return actual;
}

// The bytes a v2 signature covers: the tag, one LF, then the manifest verbatim.
export function signedBytes(tag: string, manifestBytes: Buffer): Buffer {
  if (!isSignableTag(tag)) throw new Error(`Tag ${JSON.stringify(tag)} cannot be signed: a signed tag is exactly vX.Y.Z.`);
  return Buffer.concat([Buffer.from(`${tag}\n`, 'ascii'), manifestBytes]);
}

// Returns the full text of SHA256SUMS.all.sig (always format v2). The key is
// checked against the expected public key first; tests pass their own
// throwaway key's public half.
export function signManifest(manifestBytes: Buffer, tag: string, privateKey: KeyObject, expectedPublicKeyB64: string = EXPECTED_PUBLIC_KEY_B64): string {
  const pub = assertExpectedKey(privateKey, expectedPublicKeyB64);
  const signature = sign(null, signedBytes(tag, manifestBytes), privateKey);
  if (signature.length !== 64) throw new Error('Ed25519 signature must be 64 bytes.');
  return `${SIGNATURE_HEADER} key=${keyId(pub)} tag=${tag}\n${signature.toString('base64')}\n`;
}

// Parses either format and reports which one it was. v1 is parsed so that
// --verify-only still works on releases older than v0.4.2; verifyManifest
// decides whether a v1 signature is acceptable.
export function parseSignature(text: string): ParsedSignature {
  const v2 = /^gorse-release-signature v2 key=([A-Za-z0-9+/]{8}) tag=(v\d+\.\d+\.\d+)\n([A-Za-z0-9+/]{86}==)\n$/.exec(text);
  const v1 = v2 ? null : /^gorse-release-signature v1 key=([A-Za-z0-9+/]{8})\n([A-Za-z0-9+/]{86}==)\n$/.exec(text);
  const match = v2 ?? v1;
  if (!match) throw new Error('Malformed signature file.');
  const signature = Buffer.from(match[match.length - 1], 'base64');
  if (signature.length !== 64) throw new Error('Signature must decode to 64 bytes.');
  return v2 ? { version: 2, keyId: v2[1], tag: v2[2], signature } : { version: 1, keyId: match[1], signature };
}

// Requires a v2 signature whose tag equals expectedTag, made with publicKey,
// over `<tag>\n` + manifestBytes. A v1 signature (over the manifest alone) is
// accepted only with allowV1, which the script sets for --verify-only of
// releases older than v0.4.2; nothing else should pass it.
export function verifyManifest(manifestBytes: Buffer, signatureText: string, publicKey: string, expectedTag: string, options: VerifyOptions = {}): ManifestEntry[] {
  if (typeof expectedTag !== 'string' || !TAG_PATTERN.test(expectedTag)) throw new Error('verifyManifest needs the release tag to check the signature against.');
  const parsed = parseSignature(signatureText);
  if (parsed.keyId !== keyId(publicKey)) throw new Error(`Signature was made with key ${parsed.keyId}, expected ${keyId(publicKey)}.`);
  let covered: Buffer;
  if (parsed.version === 2) {
    if (parsed.tag !== expectedTag) throw new Error(`Signature is bound to ${parsed.tag}, not ${expectedTag}: the manifest belongs to a different release.`);
    covered = signedBytes(expectedTag, manifestBytes);
  } else {
    if (!options.allowV1) throw new Error(`Signature is format v1 (not bound to a tag); ${expectedTag} needs a v2 signature. Re-sign the release.`);
    covered = manifestBytes;
  }
  if (!verify(null, covered, publicKeyFromB64(publicKey), parsed.signature)) throw new Error('Signature does not verify over the manifest.');
  return parseManifest(manifestBytes.toString('latin1'));
}

export function loadPrivateKey(file: string): KeyObject {
  let pem: Buffer;
  try { pem = readFileSync(file); } catch { throw new Error(`Cannot read the signing key file at ${file}.`); }
  try {
    const key = createPrivateKey({ key: pem, format: 'pem' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error();
    return key;
  } catch {
    throw new Error(`${file} is not an Ed25519 private key in PKCS#8 PEM.`);
  } finally { pem.fill(0); }
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

export async function hashDirectory(dir: string, names?: readonly string[]): Promise<ManifestEntry[]> {
  const list = names ?? readdirSync(dir).filter(name => !MANIFEST_FILES.has(name) && statSync(join(dir, name)).isFile());
  const entries: ManifestEntry[] = [];
  for (const name of list) entries.push({ name, sha256: await sha256File(join(dir, name)) });
  return entries;
}

// --- GitHub ---------------------------------------------------------------

function gh(args: string[], cwd?: string): string {
  const result = spawnSync('gh', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw new Error(`Cannot run gh: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`gh ${args.slice(0, 2).join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

export function listReleaseAssets(tag: string, repo: string = PRIVATE_REPO): string[] {
  const parsed = JSON.parse(gh(['release', 'view', tag, '--repo', repo, '--json', 'assets'])) as { assets?: { name?: unknown }[] };
  if (!Array.isArray(parsed.assets)) throw new Error('gh release view returned no asset list.');
  const names = parsed.assets.map(a => a.name).filter((n): n is string => typeof n === 'string');
  for (const name of names) if (!isValidAssetName(name) && !MANIFEST_FILES.has(name)) throw new Error(`Release has an asset the manifest cannot carry: ${JSON.stringify(name)}`);
  return names;
}

function downloadAsset(tag: string, name: string, dir: string, repo: string): void {
  gh(['release', 'download', tag, '--repo', repo, '--pattern', name, '--dir', dir, '--clobber']);
  if (!existsSync(join(dir, name))) throw new Error(`Downloaded ${name} but it is not in ${dir}.`);
}

// --- CLI ------------------------------------------------------------------

interface Options { tag: string; dryRun: boolean; verifyOnly: boolean; out?: string; keyFile: string; repo: string }

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Options {
  const options: Options = { tag: '', dryRun: false, verifyOnly: false, keyFile: env.GORSE_RELEASE_SIGNING_KEY_FILE || DEFAULT_KEY_FILE, repo: PRIVATE_REPO };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--verify-only') options.verifyOnly = true;
    else if (arg === '--out') { options.out = argv[i + 1]; i += 1; if (!options.out) throw new Error('--out needs a directory.'); }
    else if (arg === '--repo') { options.repo = argv[i + 1] ?? ''; i += 1; if (!/^[\w.-]+\/[\w.-]+$/.test(options.repo)) throw new Error('--repo needs owner/name.'); }
    else if (arg.startsWith('-')) throw new Error(`Unknown option ${arg}`);
    else if (options.tag) throw new Error('Only one tag can be given.');
    else options.tag = arg;
  }
  if (!TAG_PATTERN.test(options.tag)) throw new Error('Usage: sign-release.ts vX.Y.Z [--dry-run --out DIR | --verify-only]');
  if (options.dryRun && options.verifyOnly) throw new Error('--dry-run and --verify-only are exclusive.');
  if (options.dryRun && !options.out) throw new Error('--dry-run needs --out DIR for the manifest files.');
  if (options.out && !options.dryRun) throw new Error('--out is only used with --dry-run.');
  return options;
}

function report(label: string, entries: readonly ManifestEntry[]): void {
  process.stdout.write(`${label}\n`);
  for (const entry of entries) process.stdout.write(`  ${entry.sha256}  ${entry.name}\n`);
}

async function verifyPublished(options: Options, work: string): Promise<void> {
  const names = listReleaseAssets(options.tag, options.repo);
  for (const file of MANIFEST_FILES) {
    if (!names.includes(file)) throw new Error(`${options.tag} has no ${file}; run sign-release.ts ${options.tag} first.`);
    downloadAsset(options.tag, file, work, options.repo);
  }
  const manifestBytes = readFileSync(join(work, MANIFEST_NAME));
  const signatureText = readFileSync(join(work, SIGNATURE_NAME), 'latin1');
  // Only releases older than the first v2 release may still carry a v1 signature.
  const allowV1 = isSignableTag(options.tag) && compareTags(options.tag, FIRST_V2_TAG) < 0;
  const entries = verifyManifest(manifestBytes, signatureText, EXPECTED_PUBLIC_KEY_B64, options.tag, { allowV1 });
  const parsed = parseSignature(signatureText);
  const covered = entries.map(e => e.name).sort(compareBytes);
  const expected = names.filter(n => !MANIFEST_FILES.has(n)).sort(compareBytes);
  if (covered.join('\n') !== expected.join('\n')) {
    throw new Error(`Manifest covers [${covered.join(', ')}] but the release holds [${expected.join(', ')}]; re-sign the release.`);
  }
  for (const entry of entries) {
    downloadAsset(options.tag, entry.name, work, options.repo);
    const actual = await sha256File(join(work, entry.name));
    if (actual !== entry.sha256) throw new Error(`${entry.name} on the release does not match the signed manifest.`);
  }
  process.stdout.write(`Signing key: ${keyId(EXPECTED_PUBLIC_KEY_B64)} (verified)\n`);
  process.stdout.write(parsed.version === 2
    ? `Signature format: v2, bound to tag ${parsed.tag}\n`
    : `Signature format: v1 (legacy, not bound to a tag; accepted only because ${options.tag} predates ${FIRST_V2_TAG})\n`);
  report(`Covered assets of ${options.tag}, all hashes match:`, entries);
}

async function signRelease(options: Options, work: string): Promise<void> {
  // Load and check the key before touching the network so a wrong key fails fast.
  const privateKey = loadPrivateKey(options.keyFile);
  const pub = assertExpectedKey(privateKey);
  if (!isSignableTag(options.tag)) throw new Error(`${options.tag} cannot be signed: only plain vX.Y.Z tags carry a release signature.`);
  const names = listReleaseAssets(options.tag, options.repo).filter(n => !MANIFEST_FILES.has(n));
  if (names.length === 0) throw new Error(`${options.tag} has no assets to sign.`);
  const assets = join(work, 'assets');
  mkdirSync(assets);
  for (const name of names) downloadAsset(options.tag, name, assets, options.repo);
  const entries = await hashDirectory(assets, names);
  const manifest = buildManifest(entries);
  const manifestBytes = Buffer.from(manifest, 'ascii');
  const signatureText = signManifest(manifestBytes, options.tag, privateKey);
  verifyManifest(manifestBytes, signatureText, pub, options.tag);

  const outDir = options.dryRun ? resolve(options.out as string) : join(work, 'out');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, MANIFEST_NAME), manifestBytes, { mode: 0o644 });
  writeFileSync(join(outDir, SIGNATURE_NAME), signatureText, { encoding: 'ascii', mode: 0o644 });
  process.stdout.write(`Signing key: ${keyId(pub)}\n`);
  process.stdout.write(`Signature format: v2, bound to tag ${options.tag}\n`);
  report(`Covered assets of ${options.tag}:`, parseManifest(manifest));
  if (options.dryRun) {
    process.stdout.write(`Dry run: wrote ${MANIFEST_NAME} and ${SIGNATURE_NAME} to ${outDir}; nothing uploaded.\n`);
    return;
  }
  gh(['release', 'upload', options.tag, join(outDir, MANIFEST_NAME), join(outDir, SIGNATURE_NAME), '--clobber', '--repo', options.repo]);
  process.stdout.write(`Uploaded ${MANIFEST_NAME} and ${SIGNATURE_NAME} to ${options.repo} ${options.tag}.\n`);
}

export async function main(argv: readonly string[]): Promise<void> {
  const options = parseArgs(argv);
  const work = mkdtempSync(join(tmpdir(), 'gorse-sign-'));
  try {
    if (options.verifyOnly) await verifyPublished(options, work);
    else await signRelease(options, work);
  } finally { rmSync(work, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`sign-release: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
