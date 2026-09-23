#!/usr/bin/env node
/** Verify the exact npm artifact without creating a tarball. */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const npmArgs = ['pack', '--dry-run', '--json', '--ignore-scripts', '--cache', join(root, '.npm-cache')];

/**
 * Locate npm's CLI entry point so `npm pack` can run without a shell.
 *
 * `npm_execpath` is set whenever npm runs this script, which is the normal path
 * (`npm run check`). A direct `node scripts/check-package.mjs` has no such env,
 * and on Windows the `npm.cmd` shim cannot be spawned directly — Node refuses
 * `.cmd`/`.bat` without `shell: true` and fails with EINVAL — so npm's CLI is
 * resolved from beside the running Node instead. That keeps the fallback
 * shell-free; `shell: true` would emit DEP0190 on Node 24.
 *
 * @returns the CLI path, or undefined when npm is only reachable through PATH.
 */
function resolveNpmCli() {
  const fromEnv = process.env.npm_execpath;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv;
  const besideNode = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  return existsSync(besideNode) ? besideNode : undefined;
}

const npmCli = resolveNpmCli();
const command = npmCli === undefined ? 'npm' : process.execPath;
const args = npmCli === undefined ? npmArgs : [npmCli, ...npmArgs];
const packed = spawnSync(command, args, { cwd: root, encoding: 'utf8', windowsHide: true });

if (packed.error !== undefined) {
  console.error(`check-package: could not run npm pack: ${packed.error.message}`);
  process.exit(1);
}
if (packed.status !== 0) {
  if (packed.stdout.trim()) console.error(packed.stdout.trim());
  if (packed.stderr.trim()) console.error(packed.stderr.trim());
  console.error(`check-package: npm pack exited with status ${packed.status}`);
  process.exit(1);
}

let report;
try {
  [report] = JSON.parse(packed.stdout);
} catch (error) {
  console.error(`check-package: npm pack did not return JSON: ${error.message}`);
  if (packed.stdout.trim()) console.error(packed.stdout.trim());
  process.exit(1);
}

const paths = new Set((report.files ?? []).map((file) => file.path.replaceAll('\\', '/')));
const required = [
  'package.json',
  'README.md',
  'LICENSE',
  'CHANGELOG.md',
  'SECURITY.md',
  'cordis.patch.yml',
  'lib/index.js',
  'lib/matcher.js',
  'docs/DESIGN.md',
  'docs/PUBLISHING.md',
  'docs/agents-md-snippet.md',
  'examples/override.cordis.patch.yml'
];
const forbiddenPrefixes = ['.git/', '.github/', '.npm-cache/', 'scripts/', 'test/'];
const failures = [];

if (report.name !== manifest.name) failures.push(`artifact name is ${JSON.stringify(report.name)}, expected ${JSON.stringify(manifest.name)}`);
if (report.version !== manifest.version) failures.push(`artifact version is ${JSON.stringify(report.version)}, expected ${JSON.stringify(manifest.version)}`);
for (const path of required) if (!paths.has(path)) failures.push(`artifact is missing ${path}`);
for (const path of paths) {
  const forbidden = forbiddenPrefixes.find((prefix) => path.startsWith(prefix));
  if (forbidden !== undefined) failures.push(`artifact unexpectedly includes ${path}`);
}
if (!Number.isFinite(report.unpackedSize) || report.unpackedSize > 500_000) {
  failures.push(`artifact unpacked size ${report.unpackedSize} exceeds the 500 KB budget`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`check-package: ERROR: ${failure}`);
  process.exit(1);
}

console.log(`check-package: OK - ${manifest.name}@${manifest.version}, ${paths.size} files, ${report.unpackedSize} unpacked bytes`);
