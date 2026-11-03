// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Exercises the actual Swift validator with Node-generated Ed25519 fixtures.
// All files are private temporary fixtures; no installed state is changed.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const mac = process.platform === 'darwin';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const privateKey = createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7),
]), format: 'der', type: 'pkcs8' });
const issuer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
const payload = { tier: 'developer', email: 'synthetic@example.invalid', machine_id: 'fixture-machine', issued_at: 1000, expires_at: 87400 };
const key = (patch: Record<string, unknown> = {}) => {
  const bytes = Buffer.from(JSON.stringify({ ...payload, ...patch }));
  return 'HH1-' + Buffer.concat([bytes, sign(null, bytes, privateKey)]).toString('base64url');
};
let temporary: string;
let executable: string;

before(() => {
  if (!mac) return;
  temporary = realpathSync(mkdtempSync(join(tmpdir(), 'hedgehog-runtime-lease-')));
  executable = join(temporary, 'lease-tests');
  const harness = join(temporary, 'Harness.swift');
  writeFileSync(harness, String.raw`
import Foundation
import Darwin
@main struct Harness {
  static func main() {
    let args = CommandLine.arguments
    do {
      if args[1] == "identity" { print(try MachineID.get()); return }
      let issuer = Data(base64Encoded: args[2])!
      let timestamp = Date(timeIntervalSince1970: Double(args[4])!)
      if args[1] == "file" {
        let lease = LicenseManager.readLease(atHome: args[3], owner: getuid(), machineID: "fixture-machine", now: timestamp, issuer: issuer)
        print(lease?.tier.rawValue ?? 0)
      } else {
        let key = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8)!
        let lease = try args[1] == "production"
          ? LeaseVerifier.validate(key: key, machineID: args[3], now: timestamp)
          : LeaseVerifier.validate(key: key, machineID: args[3], now: timestamp, issuer: issuer)
        print(lease.tier.rawValue)
      }
    } catch { print("rejected") }
  }
}
`);
  const compilation = spawnSync('/usr/bin/swiftc', ['-parse-as-library', '-module-cache-path', join(temporary, 'cache'),
    join(root, 'esf_client/Sources/Shared/MachineID.swift'), join(root, 'esf_client/Sources/Shared/LicenseManager.swift'),
    harness, '-o', executable], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(compilation.status, 0, compilation.stderr || compilation.error?.message);
});
after(() => { if (temporary) rmSync(temporary, { recursive: true, force: true }); });

function run(mode: string, input = key(), machine = 'fixture-machine', now = 1000) {
  const result = spawnSync(executable, [mode, issuer, machine, String(now)], { input, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return result.stdout.trim();
}

const GRACE = 14 * 86400;

test('Node-signed short lease is verified by the compiled Swift runtime', { skip: !mac }, () => {
  assert.equal(run('validate'), '2');
  assert.equal(run('validate', key(), 'fixture-machine', 87399), '2');
  // The signed expiry starts a fortnight of renewal grace in which the tier
  // stays effective; the end of the grace is what ends the entitlement.
  assert.equal(run('validate', key(), 'fixture-machine', 87400), '2');
  assert.equal(run('validate', key(), 'fixture-machine', 87400 + GRACE - 1), '2');
  assert.equal(run('validate', key(), 'fixture-machine', 87400 + GRACE), 'rejected');
  assert.equal(run('production'), 'rejected', 'the runtime must not accept the test issuer');
  assert.equal(run('validate', key(), 'other-machine'), 'rejected');
});

test('signed but long, future, unknown or unbound leases are rejected', { skip: !mac }, () => {
  for (const patch of [{ expires_at: 87401 }, { issued_at: 1006 }, { issued_at: 0 },
    { machine_id: '' }, { tier: 'free' }, { extra: true }, { email: 'not-an-email' }]) {
    assert.equal(run('validate', key(patch)), 'rejected', JSON.stringify(patch));
  }
  const raw = Buffer.from(key().slice(4), 'base64url');
  raw[10] ^= 1;
  assert.equal(run('validate', 'HH1-' + raw.toString('base64url')), 'rejected');
});

test('private file reads accept valid data and reject unsafe coverage or permissions', { skip: !mac }, () => {
  const home = join(temporary, 'home');
  const directory = join(home, '.hedgehog');
  const file = join(directory, 'license.key');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(file, key(), { mode: 0o600 });
  const read = () => run('file', '', home);
  assert.equal(read(), '2');
  assert.equal(run('file', '', home, 87400), '2', 'inside the renewal grace');
  assert.equal(run('file', '', home, 87400 + GRACE), '0', 'after the renewal grace');
  chmodSync(file, 0o644); assert.equal(read(), '0'); chmodSync(file, 0o600);
  const other = join(home, 'linked-key');
  linkSync(file, other); assert.equal(read(), '0'); unlinkSync(other);
  unlinkSync(file); writeFileSync(other, key(), { mode: 0o600 });
  symlinkSync(other, file); assert.equal(read(), '0'); unlinkSync(file);
  writeFileSync(file, key(), { mode: 0o600 });
  chmodSync(directory, 0o777); assert.equal(read(), '0'); chmodSync(directory, 0o700);
  writeFileSync(file, 'x'.repeat(8193)); assert.equal(read(), '0');
  writeFileSync(file, key());
  const alias = join(temporary, 'home-link'); symlinkSync(home, alias);
  assert.equal(run('file', '', alias), '0');
});

test('macOS CLI and Swift compute the same hardware binding', { skip: !mac }, () => {
  const home = join(temporary, 'cli-home'); mkdirSync(home, { mode: 0o700 });
  const command = spawnSync(join(root, 'target/debug/gorse'), ['license', 'status', '--json'], {
    env: { ...process.env, HOME: home }, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(command.status, 0, command.stderr || command.error?.message);
  const status = JSON.parse(command.stdout);
  assert.equal(status.state, 'missing');
  assert.equal(status.tier, 'free');
  assert.equal(status.protection_tested, false);
  assert.equal(status.machine_id, run('identity'));
  assert.match(status.machine_id, /^[a-f0-9]{64}$/);
});
