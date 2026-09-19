#!/usr/bin/env node
/**
 * Repo check: does this package actually install as a DSH bundle?
 *
 * The loader's condition is exact — `dsh plugin` appends a dependency to
 * `dsh.profile.bundles` only when the installed package's manifest declares
 * `dsh.bundle.patch`. A typo there installs the package as an inert library with
 * a warning, which is a silent failure this script turns loud.
 *
 * Dependency-free by design, so CI needs no install step. When `js-yaml` happens
 * to be resolvable (a devDependency you add, or a dsh tree nearby) the patch file
 * is additionally parsed strictly; otherwise the script says so and falls back to
 * a structural check of the shape this package ships.
 *
 * Usage: node scripts/check-bundle.mjs
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];
const warnings = [];
const notes = [];

const fail = (message) => failures.push(message);
const warn = (message) => warnings.push(message);

/** Read and parse package.json. */
let manifest;
try {
  manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
} catch (error) {
  console.error(`check-bundle: cannot read package.json: ${error.message}`);
  process.exit(1);
}

// --- the install contract -------------------------------------------------
const patchRelative = manifest.dsh?.bundle?.patch;
if (typeof patchRelative !== 'string' || patchRelative.length === 0) {
  fail('package.json must declare dsh.bundle.patch — without it `dsh plugin add` installs this as a plain dependency, not a profile layer');
} else {
  const patchPath = join(root, patchRelative);
  if (!existsSync(patchPath)) fail(`dsh.bundle.patch points at ${patchRelative}, which does not exist`);
  else verifyPatch(patchPath);
}

// --- entry points ---------------------------------------------------------
for (const [label, relative] of [['main', manifest.main], ...Object.entries(manifest.exports ?? {})]) {
  if (typeof relative !== 'string') continue;
  const target = join(root, relative);
  if (!existsSync(target)) fail(`${label} points at ${relative}, which does not exist`);
  else if (!statSync(target).isFile()) fail(`${label} points at ${relative}, which is not a file`);
}

// --- published file set ---------------------------------------------------
const published = new Set(manifest.files ?? []);
for (const required of ['lib', patchRelative?.replace(/^\.\//, '')]) {
  if (required === undefined) continue;
  if (!published.has(required)) warn(`files[] does not list "${required}"; npm omits it only if it is also unreferenced`);
}

// --- metadata a harness host and the market read --------------------------
if (typeof manifest.engines?.dsh !== 'string') warn('engines.dsh is missing; the plugin market uses it to show host compatibility');
if (typeof manifest.engines?.node !== 'string') warn('engines.node is missing');
if (manifest.license === undefined) warn('license is missing');
if (/(^|\/)OWNER(\/|$)/.test(String(manifest.repository?.url ?? ''))) warn('repository.url still contains the OWNER placeholder — replace it before publishing');

/** Strict YAML via an optionally resolvable js-yaml, else a structural check. */
function verifyPatch(patchPath) {
  const parsed = tryParseYaml(patchPath);
  if (parsed === undefined) {
    const text = readFileSync(patchPath, 'utf8');
    const structural = /^-\s*insert:\s*$/m.test(text) && new RegExp(`^\\s*-\\s*id:\\s*\\S+\\s*$`, 'm').test(text) && new RegExp(`^\\s*name:\\s*['"]?${manifest.name}['"]?\\s*$`, 'm').test(text);
    notes.push(structural ? 'patch verified structurally (js-yaml unavailable): insert row with id + this package name' : 'patch verified structurally');
    if (!structural) fail(`${patchRelative} is not a patch layer with an "- insert:" entry naming "${manifest.name}"`);
    return;
  }
  notes.push('patch parsed strictly with js-yaml');
  if (!Array.isArray(parsed)) return fail(`${patchRelative} must be a YAML array of patch entries`);
  const rows = parsed.flatMap((entry) => (Array.isArray(entry?.insert) ? entry.insert : []));
  if (rows.length === 0) fail(`${patchRelative} declares no insert rows, so it mounts no plugin`);
  for (const row of rows) {
    if (typeof row?.id !== 'string' || row.id.length === 0) fail(`${patchRelative}: every insert row needs a non-empty string id`);
    const named = typeof row?.name === 'string' ? row.name : '';
    if (named !== manifest.name && !named.startsWith(`${manifest.name}/`)) {
      fail(`${patchRelative}: row name ${JSON.stringify(named)} must be "${manifest.name}" or a subpath of it, so Node resolves the installed package`);
    }
  }
}

/** Parse YAML with js-yaml from anywhere it can be resolved, or undefined. */
function tryParseYaml(patchPath) {
  const candidates = [import.meta.url, join(root, 'package.json'), ...String(process.env.DSH_JS_YAML ?? '').split(';').filter(Boolean).map((entry) => join(entry, 'package.json'))];
  for (const base of candidates) {
    try {
      const require = createRequire(base);
      const yaml = require('js-yaml');
      return yaml.load(readFileSync(patchPath, 'utf8'));
    } catch {
      /* try the next anchor */
    }
  }
  return undefined;
}

// --- report ---------------------------------------------------------------
for (const note of notes) console.log(`check-bundle: ${note}`);
for (const message of warnings) console.warn(`check-bundle: warning: ${message}`);
for (const message of failures) console.error(`check-bundle: ERROR: ${message}`);
if (failures.length > 0) {
  console.error(`check-bundle: ${failures.length} problem(s) — this package would not compose as a bundle`);
  process.exit(1);
}
console.log(`check-bundle: OK — ${manifest.name}@${manifest.version} declares dsh.bundle.patch -> ${patchRelative}`);
