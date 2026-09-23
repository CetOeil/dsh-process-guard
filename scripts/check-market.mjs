#!/usr/bin/env node
/**
 * Repo check: would dsh-plugin.org list this package?
 *
 * The hub discovers plugins by scanning public GitHub repositories that carry
 * the `dsh-plugin` topic, and refuses a listing when the repository is not
 * public, the topic is missing, the README has no install command, or the entry
 * does not export `apply(ctx)`.
 *
 * This script owns only what nothing else covers: the README install command the
 * hub looks for, and the two GitHub-side steps it cannot check from here. The
 * manifest contract belongs to `check-bundle.mjs`, and the `apply(ctx)` export is
 * already load-bearing — `test/plugin.test.js` imports it by name, so a missing
 * export fails `npm test` at module load rather than needing a check here.
 *
 * Usage: node scripts/check-market.mjs
 */

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];
const warnings = [];
const notes = [];

const fail = (message) => failures.push(message);
const warn = (message) => warnings.push(message);

let manifest;
try {
  manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
} catch (error) {
  console.error(`check-market: cannot read package.json: ${error.message}`);
  process.exit(1);
}

// A missing README fails the install-command check below, which is the listing
// requirement it violates, so it is not reported a second time here.
let readme = '';
try {
  readme = readFileSync(join(root, 'README.md'), 'utf8');
} catch {
  /* reported by the install-command check */
}

// --- the hub's stated listing requirements ---------------------------------
const installCommand = `dsh plugin --profile web add ${manifest.name}`;
if (!readme.includes(installCommand)) {
  fail(`README.md must contain the copyable install command "${installCommand}"`);
}
if (!/license/i.test(readme)) fail('README.md must state the license so the listing can show it');

const keywords = Array.isArray(manifest.keywords) ? manifest.keywords : [];
if (!keywords.includes('dsh-plugin')) warn('keywords should include "dsh-plugin" so a registry search finds this package');
if (typeof manifest.license !== 'string' || !/^[A-Za-z0-9.+-]+$/.test(manifest.license)) {
  warn(`license ${JSON.stringify(manifest.license)} is not a plain SPDX id; the listing shows it verbatim`);
}

// --- what only a human can do ---------------------------------------------
const repository = String(typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url ?? '')
  .replace(/^git\+/, '')
  .replace(/\.git$/, '');
notes.push(`manual: add the "dsh-plugin" topic to ${repository || 'the GitHub repository'} (Settings -> Topics) — the hub scans it`);
notes.push('manual: set a GitHub repository description; the hub shows it in the listing');

// --- report ---------------------------------------------------------------
for (const note of notes) console.log(`check-market: ${note}`);
for (const message of warnings) console.warn(`check-market: warning: ${message}`);
for (const message of failures) console.error(`check-market: ERROR: ${message}`);
if (failures.length > 0) {
  console.error(`check-market: ${failures.length} problem(s) — dsh-plugin.org would not list this package`);
  process.exit(1);
}
console.log(`check-market: OK — ${manifest.name}@${manifest.version} satisfies the locally checkable listing requirements`);
