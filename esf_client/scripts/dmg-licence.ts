#!/usr/bin/env node
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Attaches the end user licence agreement to a finished disk image as the
// classic macOS software licence agreement: Finder shows the text with Agree
// and Disagree buttons before the volume mounts, and Disagree ejects it.
//
//   node esf_client/scripts/dmg-licence.ts <image.dmg> <LICENSE>
//
// Run after `hdiutil convert` and before the image is code-signed, because
// udifrez rewrites the file. The resources are the ones Finder has read since
// classic Mac OS: an LPic table naming one language, a STR# with the button
// labels, and the licence as TEXT with carriage-return line endings in Mac
// Roman, which is why the LICENSE file must stay plain ASCII.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [image, licencePath] = process.argv.slice(2);
if (!image || !licencePath) {
  console.error('usage: dmg-licence.ts <image.dmg> <LICENSE>');
  process.exit(2);
}

const licence = readFileSync(licencePath, 'latin1');
if (/[^\x00-\x7f]/.test(licence)) {
  console.error(`${licencePath} must be plain ASCII for the Finder licence sheet`);
  process.exit(1);
}

function pascal(s: string): Buffer {
  const bytes = Buffer.from(s, 'latin1');
  if (bytes.length > 255) throw new Error(`string too long: ${s}`);
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}
function u16(n: number): Buffer { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }

// LPic: default language 0 (English), one entry: language 0, resource offset 0, not multibyte.
const lpic = Buffer.concat([u16(0), u16(1), u16(0), u16(0), u16(0)]);
const labels = ['English', 'Agree', 'Disagree', 'Print', 'Save...',
  'If you agree with the terms of this licence, press "Agree" to continue. If you do not agree, press "Disagree".'];
const strList = Buffer.concat([u16(labels.length), ...labels.map(pascal)]);
const text = Buffer.from(licence.replace(/\r?\n/g, '\r'), 'latin1');

function resource(name: string, data: Buffer): string {
  return `  <key>${name}</key>\n  <array>\n    <dict>\n      <key>Attributes</key><string>0x0000</string>\n      <key>Data</key><data>${data.toString('base64')}</data>\n      <key>ID</key><string>5000</string>\n      <key>Name</key><string>English</string>\n    </dict>\n  </array>\n`;
}
const plist = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n${resource('LPic', lpic)}${resource('STR#', strList)}${resource('TEXT', text)}</dict>\n</plist>\n`;

const dir = mkdtempSync(join(tmpdir(), 'dmg-licence-'));
try {
  const plistPath = join(dir, 'licence.plist');
  writeFileSync(plistPath, plist);
  const run = spawnSync('hdiutil', ['udifrez', '-xml', plistPath, '', image], { stdio: 'inherit' });
  if (run.status !== 0) process.exit(run.status ?? 1);
  const check = spawnSync('hdiutil', ['udifderez', '-xml', image], { encoding: 'utf8' });
  if (check.status !== 0 || !check.stdout.includes('<key>LPic</key>')) {
    console.error('licence resources were not written to the image');
    process.exit(1);
  }
  console.log(`Licence sheet attached to ${image} (${text.length} bytes of text)`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
