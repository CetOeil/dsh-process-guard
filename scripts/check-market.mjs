#!/usr/bin/env node
/**
 * Repo check: would dsh-plugin.org list this package?
 *
 * The hub discovers plugins by scanning public GitHub repositories that carry
 * the `dsh-plugin` topic, and it refuses a listing when any of four conditions
 * fails: the repository is not public, the topic is missing, the README has no
 * install command, or the entry does not export `apply(ctx)`. Three of those
 * are properties of the working tree and are checked here; the repository
 * visibility and the topic are GitHub-side and are printed as manual steps.
 *
 * Dependency-free, and it imports the entry point rather than grepping it, so a
 * renamed or non-exported `apply` cannot pass.
 *
 * Usage: node scripts/check-market.mjs
 */

import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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

const readmePath = join(root, 'README.md');
const readme = existsSync(readmePath) ? readFileSync(readmePath, 'utf8') : '';
if (readme.length === 0) fail('README.md is required: the hub generates the listing from it');

// --- the hub's stated listing requirements ---------------------------------
if (manifest.private === true) fail('private:true makes the repository unpublishable and unlistable');

const installCommand = `dsh plugin --profile web add ${manifest.name}`;
if (!readme.includes(installCommand)) {
  fail(`README.md must contain the copyable install command "${installCommand}"`);
}

const keywords = Array.isArray(manifest.keywords) ? manifest.keywords : [];
if (!keywords.includes('dsh-plugin')) {
  warn('keywords should include "dsh-plugin" so a registry search finds this package');
}

const patch = manifest.dsh?.bundle?.patch;
if (typeof patch !== 'string' || patch.length === 0) {
  fail('the hub installs the profile layer through dsh.bundle.patch, which is missing');
}

if (!/^MIT|Apache|BSD|ISC|GPL|MPL|Unlicense/i.test(String(manifest.license ?? ''))) {
  warn(`license ${JSON.stringify(manifest.license)} is unusual for a public listing; declare a standard SPDX id`);
}
if (!/license/i.test(readme)) fail('README.md must state the license so the listing can show it');

// --- the entry point the hub's spec requires ------------------------------
const entry = join(root, manifest.main ?? 'index.js');
if (!existsSync(entry)) {
  fail(`main points at ${manifest.main}, which does not exist`);
} else {
  let module;
  try {
    module = await import(pathToFileURL(entry).href);
  } catch (error) {
    fail(`${manifest.main} cannot be imported: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (module !== undefined) {
    if (typeof module.apply !== 'function') fail(`${manifest.main} must export apply(ctx) — the DSH plugin spec requires it`);
    if (typeof module.name !== 'string' || module.name.length === 0) fail(`${manifest.main} must export a non-empty plugin name`);
    else if (!readme.includes(module.name)) notes.push(`plugin name "${module.name}" does not appear in README.md`);
    if (!Array.isArray(module.inject)) warn('the entry point declares no inject list; the plugin may mount before its services exist');
  }
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
