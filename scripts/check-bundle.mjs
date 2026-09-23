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
import { dirname, join, resolve, sep } from 'node:path';
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
  const patchPath = resolve(root, patchRelative);
  if (patchPath !== root && !patchPath.startsWith(`${root}${sep}`)) fail(`dsh.bundle.patch must stay inside the package, got ${patchRelative}`);
  else if (!existsSync(patchPath)) fail(`dsh.bundle.patch points at ${patchRelative}, which does not exist`);
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
for (const required of ['lib', 'docs', 'examples', 'CHANGELOG.md', 'SECURITY.md', patchRelative?.replace(/^\.\//, '')]) {
  if (required === undefined) continue;
  if (!published.has(required)) fail(`files[] must list "${required}" so the documented package artifact is complete`);
}

// --- metadata a harness host and the market read --------------------------
if (typeof manifest.name !== 'string' || !/^(@[^/]+\/)?dsh[-\w]*$/i.test(manifest.name)) fail('name must be an npm-safe DSH package name');
if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) fail('version must be a valid publishable semver');
if (typeof manifest.description !== 'string' || manifest.description.trim().length === 0) fail('description is required');
if (typeof manifest.engines?.dsh !== 'string') warn('engines.dsh is missing; it records the minimum host this plugin was verified against');
else {
  // No tool evaluates a non-standard engine key — npm and pnpm only check
  // `node`/`npm` — and node-semver cannot express "any prerelease at or above
  // X", because a prerelease comparator only admits prereleases of its own
  // version tuple. `>=0.1.0-rc.6` alone therefore reports the verified host
  // (0.1.5-rc.3) as incompatible. The field is documentation; the enforced gate
  // is the runtime check in lib/index.js.
  const verified = semverSatisfies('0.1.5-rc.3', manifest.engines.dsh);
  if (verified === false) warn(`engines.dsh ${JSON.stringify(manifest.engines.dsh)} excludes 0.1.5-rc.3, the host this plugin is verified against`);
  else if (verified === true) notes.push(`engines.dsh ${JSON.stringify(manifest.engines.dsh)} admits the verified host 0.1.5-rc.3`);
  else notes.push('engines.dsh not evaluated (node-semver is not resolvable)');
}
if (typeof manifest.engines?.node !== 'string') warn('engines.node is missing');
if (manifest.license === undefined || !existsSync(join(root, 'LICENSE'))) fail('license metadata and a LICENSE file are required');
if (!existsSync(join(root, 'README.md'))) fail('README.md is required');
if (manifest.private === true) fail('private:true prevents publication');
if (manifest.publishConfig?.access !== 'public') fail('publishConfig.access must be "public"');
if (typeof manifest.scripts?.prepublishOnly !== 'string') fail('prepublishOnly must run release checks before npm publish');

const repositoryUrl = String(typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url ?? '');
const bugsUrl = String(typeof manifest.bugs === 'string' ? manifest.bugs : manifest.bugs?.url ?? '');
const homepageUrl = String(manifest.homepage ?? '');
for (const [field, url] of [['repository.url', repositoryUrl], ['bugs.url', bugsUrl], ['homepage', homepageUrl]]) {
  if (!/^https?:\/\/github\.com\//.test(url.replace(/^git\+/, ''))) fail(`${field} must point at the canonical GitHub repository`);
  if (/OWNER/i.test(url)) fail(`${field} still contains the OWNER placeholder`);
}

const serializedManifest = JSON.stringify(manifest);
if (/OWNER/.test(serializedManifest)) fail('package.json still contains an OWNER placeholder');

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

/**
 * Evaluate `engines.dsh` with node-semver when it is resolvable (npm ships it),
 * or undefined when it is not. The engine range is documentation rather than an
 * enforced gate — no tool reads a non-standard engine key — so an unresolvable
 * semver is a note, never a failure.
 *
 * @param version - the host version this package was verified against.
 * @param range - the declared `engines.dsh` range.
 * @returns true/false from node-semver, or undefined when it cannot be loaded.
 */
function semverSatisfies(version, range) {
  const candidates = [
    import.meta.url,
    join(root, 'package.json'),
    join(dirname(process.execPath), 'node_modules', 'npm', 'node_modules', 'package.json'),
    ...String(process.env.DSH_SEMVER ?? '').split(';').filter(Boolean).map((entry) => join(entry, 'package.json'))
  ];
  for (const base of candidates) {
    try {
      return createRequire(base)('semver').satisfies(version, range);
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
