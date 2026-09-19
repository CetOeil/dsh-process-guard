/**
 * Matcher corpus. Every `flag` case states why it must be refused; every `allow`
 * case states the safe shape it protects, including the exact safe patterns
 * documented in the README, so a future tightening of the regexes cannot quietly
 * start refusing recommended commands.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { DEFAULT_PROTECTED_IMAGES, evaluateCommand, maskViews, normalizeImage, splitSegments } from '../lib/matcher.js';

/** The unescalated cleanup step that closed the GUI window on 2026-09-18. */
const INCIDENT = 'Get-Process chrome,msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue';
/** The approved command that killed the window ~3s after the approval was recorded. */
const INCIDENT_APPROVED = 'Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue';
const SAFE_SCOPED = "Get-Process chrome | Where-Object { $_.CommandLine -like '*--headless*' } | Stop-Process -Force";

const DENY_CASES = [
  ['the unescalated incident command', INCIDENT, 'protected-image-kill'],
  ['the approved incident command', INCIDENT_APPROVED, 'protected-image-kill'],
  ['Stop-Process by image name', 'Stop-Process -Name msedge', 'protected-image-kill'],
  ['quoted image name is still an image name', 'Stop-Process -Name "chrome"', 'protected-image-kill'],
  ['taskkill by image name', 'taskkill /IM chrome.exe /F', 'protected-image-kill'],
  ['wmic delete by image name', 'wmic process where "name=\'chrome.exe\'" delete', 'protected-image-kill'],
  ['killall in a bash tool', 'killall chrome', 'protected-image-kill'],
  ['pkill -f in a bash tool', 'pkill -f chrome', 'protected-image-kill'],
  ['the harness server itself', 'Get-Process node | Stop-Process -Force', 'protected-image-kill'],
  ['the terminal hosting the harness', 'Stop-Process -Name WindowsTerminal', 'protected-image-kill'],
  ['the kill alias', 'kill -Name chrome', 'protected-image-kill'],
  ['method call on an enumeration', '(Get-Process chrome).Kill()', 'protected-image-kill'],
  ['a later statement in the same command', 'Start-Sleep 1; Stop-Process -Name firefox', 'protected-image-kill'],
  ['unfiltered enumeration', 'Get-Process | Stop-Process -Force', 'blanket-enumeration'],
  ['enumeration piped through a filter-less cmdlet', 'Get-CimInstance Win32_Process | Stop-Process -Force', 'blanket-enumeration'],
  ['wildcard selector', 'Stop-Process -Name *', 'blanket-wildcard'],
  ['taskkill wildcard', 'taskkill /F /IM *', 'blanket-wildcard'],
  ['a kill hidden behind Invoke-Expression', 'Invoke-Expression "Stop-Process -Name chrome"', 'indirect-execution'],
  ['a kill hidden behind iex', 'iex "killall msedge"', 'indirect-execution'],
  ['a kill hidden behind bash -c', 'bash -c "killall chrome"', 'indirect-execution'],
  ['a kill hidden behind cmd /c', 'cmd /c "taskkill /IM chrome.exe /F"', 'indirect-execution'],
  ['a kill hidden behind a nested shell', 'pwsh -Command "Stop-Process -Name chrome"', 'indirect-execution']
];

const ALLOW_CASES = [
  ['explicit PID', 'Stop-Process -Id 42', 'explicit-pid'],
  ['explicit PID on an enumeration', 'Get-Process -Id 42 | Stop-Process -Force', 'explicit-pid'],
  ['bash kill by PID', 'kill 4711', 'explicit-pid'],
  ['handle from Start-Process -PassThru', '$p = Start-Process chrome -PassThru\nif (-not $p.WaitForExit(25000)) { $p.Kill() }', 'handle-or-unprotected'],
  ['a verb inside a string literal is not a verb', 'Write-Output "Stop-Process -Name chrome"', 'no-match'],
  ['documentation text quoting the rule stays allowed', 'Write-Output "call Stop-Process -Name chrome to reproduce"', 'no-match'],
  ['an indirection primitive with no kill inside is not flagged', 'cmd /c "chrome --version"', 'no-match'],
  ['an indirection primitive aiming at an unprotected image is not flagged', 'iex "Stop-Process -Name notepad"', 'no-match'],
  ['an image named only in a comment', 'Stop-Process -Id 5 # chrome', 'explicit-pid'],
  ['an unprotected image', 'Stop-Process -Name notepad', 'handle-or-unprotected'],
  ['taskkill on an unprotected image', 'taskkill /IM notepad.exe /F', 'handle-or-unprotected'],
  ['headless-scoped filter (documented safe pattern)', SAFE_SCOPED, 'safe-scoped-filter'],
  ['reading processes without killing them', 'Get-Process chrome', 'no-match'],
  ['starting a headless browser', 'Start-Process chrome --headless=new --user-data-dir=$tmp', 'no-match'],
  ['empty command', '', 'no-match']
];

test('protected images cover browsers and the harness host tree', () => {
  for (const image of ['chrome', 'msedge', 'firefox', 'node', 'pwsh', 'windowsterminal']) {
    assert.ok(DEFAULT_PROTECTED_IMAGES.includes(image), `expected ${image} to be protected`);
  }
});

test('flags image-name terminations', async (t) => {
  for (const [label, command, rule] of DENY_CASES) {
    await t.test(label, () => {
      const verdict = evaluateCommand(command);
      assert.equal(verdict.kind, 'deny', `${label}: expected deny, got ${verdict.kind} (rule ${verdict.rule})`);
      assert.equal(verdict.rule, rule);
      assert.match(verdict.reason, /process-guard: blocked/);
    });
  }
});

test('allows explicit-PID, handle-based, and scoped-safe terminations', async (t) => {
  for (const [label, command, rule] of ALLOW_CASES) {
    await t.test(label, () => {
      const verdict = evaluateCommand(command);
      assert.equal(verdict.kind, 'allow', `${label}: expected allow, got ${verdict.kind} (rule ${verdict.rule})`);
      assert.equal(verdict.rule, rule);
    });
  }
});

test('the denial reason names the target and the safe alternative', () => {
  const verdict = evaluateCommand(INCIDENT);
  assert.match(verdict.reason, /"chrome", "msedge"/);
  assert.match(verdict.reason, /-PassThru/);
  assert.match(verdict.reason, /127\.0\.0\.1:3080/);
});

test('mode relabels a flag but never turns it into an allow', () => {
  assert.equal(evaluateCommand('Stop-Process -Name chrome', { mode: 'ask' }).kind, 'ask');
  assert.equal(evaluateCommand('Stop-Process -Name chrome', { mode: 'nonsense' }).kind, 'deny');
  assert.equal(evaluateCommand('Stop-Process -Id 42', { mode: 'ask' }).kind, 'allow');
});

test('safeFilterAllows can be switched off', () => {
  assert.equal(evaluateCommand(SAFE_SCOPED, { safeFilterAllows: false }).kind, 'deny');
});

test('protectedImages is replaceable', () => {
  assert.equal(evaluateCommand('Stop-Process -Name notepad', { protectedImages: ['notepad'] }).kind, 'deny');
  assert.equal(evaluateCommand('Stop-Process -Name chrome', { protectedImages: ['notepad'] }).kind, 'allow');
});

test('findings expose the matched statement for diagnostics', () => {
  const verdict = evaluateCommand('Start-Sleep 1; Stop-Process -Name firefox');
  assert.equal(verdict.findings.length, 1, 'statements without a kill verb produce no finding');
  assert.equal(verdict.findings[0].rule, 'protected-image-kill');
  assert.match(verdict.findings[0].excerpt, /firefox/);
});

test('maskViews keeps offsets aligned between both views', () => {
  const { noStrings, noComments } = maskViews('Stop-Process -Name "chrome" # node');
  assert.equal(noStrings.length, 'Stop-Process -Name "chrome" # node'.length);
  assert.equal(noComments.length, noStrings.length);
  assert.doesNotMatch(noStrings, /chrome/);
  assert.match(noComments, /chrome/);
  assert.doesNotMatch(noComments, /node/);
});

test('splitSegments keeps pipelines whole and drops blank statements', () => {
  const segments = splitSegments('Get-Process chrome | Stop-Process\n\n;  echo hi && echo bye');
  assert.equal(segments.length, 3);
  assert.match(segments[0].raw, /Get-Process chrome \| Stop-Process/);
});

test('normalizeImage strips case and an .exe suffix', () => {
  assert.equal(normalizeImage('  Chrome.EXE '), 'chrome');
});
