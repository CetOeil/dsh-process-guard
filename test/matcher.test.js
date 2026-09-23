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
const UNSAFE_NEGATED_FILTER = "Get-Process chrome | Where-Object { $_.CommandLine -notlike '*--headless*' } | Stop-Process -Force";
const ENCODED_KILL = Buffer.from('Stop-Process -Name chrome', 'utf16le').toString('base64');

const DENY_CASES = [
  ['the unescalated incident command', INCIDENT, 'protected-image-kill'],
  ['the approved incident command', INCIDENT_APPROVED, 'protected-image-kill'],
  ['Stop-Process by image name', 'Stop-Process -Name msedge', 'protected-image-kill'],
  ['the Stop-Process alias', 'spps -Name chrome', 'protected-image-kill'],
  ['the Get-Process and Stop-Process aliases', 'gps chrome | spps -Force', 'protected-image-kill'],
  ['the ps and kill PowerShell aliases', 'ps chrome | kill', 'protected-image-kill'],
  ['quoted image name is still an image name', 'Stop-Process -Name "chrome"', 'protected-image-kill'],
  ['taskkill by image name', 'taskkill /IM chrome.exe /F', 'protected-image-kill'],
  ['wmic delete by image name', 'wmic process where "name=\'chrome.exe\'" delete', 'protected-image-kill'],
  ['wmic call terminate by image name', 'wmic process where "name=\'chrome.exe\'" call terminate', 'protected-image-kill'],
  ['CIM termination by image name', 'Get-CimInstance Win32_Process -Filter "Name=\'chrome.exe\'" | Invoke-CimMethod -MethodName Terminate', 'protected-image-kill'],
  ['killall in a bash tool', 'killall chrome', 'protected-image-kill'],
  ['pkill -f in a bash tool', 'pkill -f chrome', 'protected-image-kill'],
  ['a cross-platform Chromium image', 'pkill google-chrome-stable', 'protected-image-kill'],
  ['the harness server itself', 'Get-Process node | Stop-Process -Force', 'protected-image-kill'],
  ['the terminal hosting the harness', 'Stop-Process -Name WindowsTerminal', 'protected-image-kill'],
  ['the kill alias', 'kill -Name chrome', 'protected-image-kill'],
  ['method call on an enumeration', '(Get-Process chrome).Kill()', 'protected-image-kill'],
  ['name-selected process saved before a method call', '$p = Get-Process chrome; $p.Kill()', 'protected-image-kill'],
  ['name-selected process converted to a PID later', '$p = Get-Process chrome; Stop-Process -Id $p.Id', 'protected-image-kill'],
  ['name-selected CIM process terminated later', '$p = Get-CimInstance Win32_Process -Filter "Name=\'chrome.exe\'"; Invoke-CimMethod -InputObject $p -MethodName Terminate', 'protected-image-kill'],
  ['a later statement in the same command', 'Start-Sleep 1; Stop-Process -Name firefox', 'protected-image-kill'],
  ['a multiline pipeline', 'Get-Process chrome |\n  Stop-Process -Force', 'protected-image-kill'],
  ['a PowerShell continued line', 'Get-Process chrome `\n  | Stop-Process -Force', 'protected-image-kill'],
  ['unfiltered enumeration', 'Get-Process | Stop-Process -Force', 'blanket-enumeration'],
  ['enumeration piped through a filter-less cmdlet', 'Get-CimInstance Win32_Process | Stop-Process -Force', 'blanket-enumeration'],
  ['wildcard selector', 'Stop-Process -Name *', 'blanket-wildcard'],
  ['quoted wildcard selector', "Stop-Process -Name '*'", 'blanket-wildcard'],
  ['wildcard name pattern', "Stop-Process -Name 'chr*'", 'blanket-wildcard'],
  ['positional wildcard name pattern', "Stop-Process 'chr*'", 'blanket-wildcard'],
  ['positional Get-Process wildcard', "Get-Process '*' | Stop-Process", 'blanket-wildcard'],
  ['taskkill wildcard', 'taskkill /F /IM *', 'blanket-wildcard'],
  ['quoted taskkill wildcard', 'taskkill /F /IM "*"', 'blanket-wildcard'],
  ['Unix process-group kill', 'kill -9 0', 'blanket-process-group'],
  ['Unix all-permitted-process kill', 'kill -TERM -- -1', 'blanket-process-group'],
  ['unquoted pkill regular expression', 'pkill chro.*', 'blanket-wildcard'],
  ['a kill hidden behind Invoke-Expression', 'Invoke-Expression "Stop-Process -Name chrome"', 'indirect-execution'],
  ['a kill hidden behind iex', 'iex "killall msedge"', 'indirect-execution'],
  ['a blanket kill hidden behind iex', 'iex "Get-Process | Stop-Process"', 'indirect-execution'],
  ['a kill hidden behind bash -c', 'bash -c "killall chrome"', 'indirect-execution'],
  ['a kill hidden behind cmd /c', 'cmd /c "taskkill /IM chrome.exe /F"', 'indirect-execution'],
  ['a wildcard kill hidden behind cmd /c', 'cmd /c "taskkill /IM * /F"', 'indirect-execution'],
  ['a kill hidden behind a nested shell', 'pwsh -Command "Stop-Process -Name chrome"', 'indirect-execution'],
  ['a PowerShell call-operator invocation', "& 'Stop-Process' -Name chrome", 'indirect-execution'],
  ['a Start-Process indirection', "Start-Process 'taskkill.exe' -ArgumentList '/IM chrome.exe /F'", 'indirect-execution'],
  ['a command substitution in a double-quoted string', 'echo "$(pkill chrome)"', 'indirect-execution'],
  ['a literal command assigned before Invoke-Expression', '$command = "Stop-Process -Name chrome"; iex $command', 'indirect-execution'],
  ['an encoded PowerShell command', `pwsh -EncodedCommand ${ENCODED_KILL}`, 'indirect-execution'],
  ['an encoded command behind another shell', `cmd /c "pwsh -EncodedCommand ${ENCODED_KILL}"`, 'indirect-execution'],
  ['a negated headless filter still targets the GUI browser', UNSAFE_NEGATED_FILTER, 'protected-image-kill'],

  // A wrapper command runs what follows it, so the verb is still an invocation.
  ['sudo before a name-based kill', 'sudo killall chrome', 'protected-image-kill'],
  ['sudo with its own options and a user', 'sudo -u root killall chrome', 'protected-image-kill'],
  ['sudo before a taskkill', 'sudo taskkill /IM chrome.exe /F', 'protected-image-kill'],
  ['doas before a name-based kill', 'doas killall chrome', 'protected-image-kill'],
  ['time before a name-based kill', 'time killall chrome', 'protected-image-kill'],
  ['timeout with a duration', 'timeout 5 killall chrome', 'protected-image-kill'],
  ['nohup before a name-based kill', 'nohup pkill chrome', 'protected-image-kill'],
  ['nice before a name-based kill', 'nice -n 5 killall chrome', 'protected-image-kill'],
  ['setsid before a name-based kill', 'setsid killall chrome', 'protected-image-kill'],
  ['stdbuf with its own option', 'stdbuf -o0 killall chrome', 'protected-image-kill'],
  ['xargs after a pipeline', 'ps aux | grep chrome | xargs killall', 'protected-image-kill'],
  ['busybox applet dispatch', 'busybox killall chrome', 'protected-image-kill'],
  ['exec before a name-based kill', 'exec killall chrome', 'protected-image-kill'],
  ['builtin before a name-based kill', 'builtin kill chrome', 'protected-image-kill'],
  ['command before a name-based kill', 'command killall chrome', 'protected-image-kill'],
  ['an environment-assignment prefix', 'FOO=1 killall chrome', 'protected-image-kill'],
  ['env with an assignment argument', 'env FOO=1 killall chrome', 'protected-image-kill'],
  ['env with an unset argument', 'env -u FOO killall chrome', 'protected-image-kill'],
  ['strace before a name-based kill', 'strace killall chrome', 'protected-image-kill'],
  ['a find -exec payload', 'find . -name "*.log" -exec killall chrome ;', 'protected-image-kill'],

  // Shell keywords end the previous clause, so the next word starts a command.
  ['a for loop body', 'for f in *; do killall chrome; done', 'protected-image-kill'],
  ['a while loop body', 'while true; do pkill chrome; done', 'protected-image-kill'],
  ['a then branch', 'if [ -f x ]; then killall chrome; fi', 'protected-image-kill'],
  ['an else branch', 'if true; then echo a; else pkill chrome; fi', 'protected-image-kill'],
  ['a negated command', '! killall chrome', 'protected-image-kill'],
  ['a batch for-loop body', "for /f %i in ('x') do taskkill /IM chrome.exe /F", 'protected-image-kill'],

  // Every shell that can run a command string, not just bash and sh.
  ['zsh -c payload', "zsh -c 'killall chrome'", 'indirect-execution'],
  ['dash -c payload', "dash -c 'killall chrome'", 'indirect-execution'],
  ['ksh -c payload', "ksh -c 'killall chrome'", 'indirect-execution'],
  ['fish -c payload', "fish -c 'killall chrome'", 'indirect-execution'],
  ['an absolute sh path', "/bin/sh -c 'killall chrome'", 'indirect-execution'],
  ['an interpreter running a shell command', 'python -c "import os; os.system(\'killall chrome\')"', 'indirect-execution'],
  ['node running a shell command', 'node -e "require(\'child_process\').execSync(\'killall chrome\')"', 'indirect-execution'],
  ['perl running a shell command', 'perl -e "system(\'killall chrome\')"', 'indirect-execution'],
  ['ruby running a shell command', 'ruby -e "system(\'killall chrome\')"', 'indirect-execution'],

  // A literal image name assigned to a variable is still that image name.
  ['an image name held in a variable', "$x = 'chrome'; Stop-Process -Name $x", 'protected-image-kill'],
  ['an image name in a double-quoted variable', '$x = "chrome"; Stop-Process -Name $x', 'protected-image-kill'],
  ['an image name variable in a taskkill', "$x = 'chrome.exe'; taskkill /IM $x /F", 'protected-image-kill'],
  ['an unquoted image name variable', '$x = chrome; Stop-Process -Name $x', 'protected-image-kill'],
  ['an image name variable inside a pipeline', "$x = 'chrome'; Get-Process -Name $x | Stop-Process", 'protected-image-kill'],

  // A name-selected process object stays name-selected through a later pipeline.
  ['a tracked process object piped into ForEach-Object', '$p = Get-Process chrome; $p | ForEach-Object { $_.Kill() }', 'protected-image-kill'],
  ['a tracked process object piped into the % alias', '$p = Get-Process chrome; $p | % { $_.Kill() }', 'protected-image-kill'],

  // A verb on a continued physical line still starts its own command.
  ['a kill after a comma continuation', '$a = 1,\nStop-Process -Name chrome', 'protected-image-kill'],
  ['a kill after a bash comma continuation', 'echo x,\npkill chrome', 'protected-image-kill'],

  // A filter that cannot exclude anything leaves the enumeration unfiltered.
  ['a constant filter clause', 'Get-Process | ? { 1 } | Stop-Process -Force', 'blanket-enumeration'],
  ['a $true filter clause', 'Get-Process | Where-Object { $true } | Stop-Process -Force', 'blanket-enumeration'],
  ['an always-true Id comparison', 'Get-Process | Where-Object { $_.Id -gt 0 } | Stop-Process -Force', 'blanket-enumeration'],
  ['a never-matching name comparison', "Get-Process | Where-Object { $_.Name -ne 'zzz' } | Stop-Process -Force", 'blanket-enumeration'],
  ['a bare property read as a filter', 'Get-Process | Where-Object { $_.ProcessName } | Stop-Process -Force', 'blanket-enumeration'],
  ['a wildcard-only CIM filter', 'Get-CimInstance Win32_Process -Filter "Name like \'%\'" | Invoke-CimMethod -MethodName Terminate', 'blanket-enumeration'],

  // Backticks are command substitution in every POSIX shell.
  ['a backtick substitution', 'echo `pkill chrome`', 'indirect-execution'],
  ['a bare backtick substitution', '`killall chrome`', 'indirect-execution'],
  ['a backtick substitution in a double-quoted string', 'echo "`pkill chrome`"', 'indirect-execution'],

  // PowerShell's parameter binder accepts any unambiguous prefix.
  ['an abbreviated encoded command', `pwsh -Encode ${ENCODED_KILL}`, 'indirect-execution'],
  ['a shorter encoded-command abbreviation', `pwsh -En ${ENCODED_KILL}`, 'indirect-execution'],
  ['an encoded command after a line continuation', `pwsh -enc \`\n${ENCODED_KILL}`, 'indirect-execution'],
  ['an abbreviated -Command', 'pwsh -Com "Stop-Process -Name chrome"', 'indirect-execution'],
  ['the Start-Process alias', "saps taskkill -ArgumentList '/IM chrome.exe /F'", 'indirect-execution'],
  ['a parenthesized call-operator literal', "& ('Stop-Process') -Name chrome", 'indirect-execution'],
  ['a quoted variable handed to Invoke-Expression', '$c = "Stop-Process -Name chrome"; iex "$c"', 'indirect-execution'],

  // A variable holding a blanket selector is still a blanket selector.
  ['a wildcard held in a variable', "$pattern = '*'; Stop-Process -Name $pattern", 'blanket-wildcard'],
  ['a glob held in a variable', "$pattern = 'chr*'; Stop-Process -Name $pattern", 'blanket-wildcard'],

  // Scope qualifiers and derived members do not detach a tracked handle.
  ['a scope-qualified use of a tracked handle', '$p = Get-Process chrome; $global:p.Kill()', 'protected-image-kill'],
  ['a scope-qualified assignment of a tracked handle', '$global:p = Get-Process chrome; $p.Kill()', 'protected-image-kill'],
  ['a tracked handle piped through a property', '$p = Get-Process chrome; $p.Id | Stop-Process', 'protected-image-kill'],
  ['a tracked handle introduced by Set-Variable', 'Set-Variable -Name p -Value (Get-Process chrome); $p.Kill()', 'protected-image-kill'],

  // A path prefix is the same command, on the wrapper and on the verb.
  ['an absolute path to sudo', '/usr/bin/sudo pkill chrome', 'protected-image-kill'],
  ['an absolute path to env', '/usr/bin/env killall chrome', 'protected-image-kill'],
  ['an absolute path to nohup', '/bin/nohup pkill chrome', 'protected-image-kill'],
  ['an absolute path to timeout', '/usr/bin/timeout 5 pkill chrome', 'protected-image-kill'],
  ['a path-qualified verb after sudo', 'sudo /usr/bin/killall chrome', 'protected-image-kill'],
  ['a path-qualified verb after env', 'env /usr/bin/pkill chrome', 'protected-image-kill'],

  // Launchers that run the command that follows them.
  ['su -c payload', 'su -c "killall chrome"', 'indirect-execution'],
  ['script -c payload', 'script -c "killall chrome"', 'indirect-execution'],
  ['wsl before a name-based kill', 'wsl killall chrome', 'protected-image-kill'],
  ['chroot before a name-based kill', 'chroot / killall chrome', 'protected-image-kill'],
  ['flock before a name-based kill', 'flock /tmp/lock killall chrome', 'protected-image-kill'],
  ['a duration argument to timeout', 'timeout 10s pkill chrome', 'protected-image-kill'],
  ['a minute duration argument to timeout', 'timeout 1m killall chrome', 'protected-image-kill'],

  // Rule precedence: a named protected image outranks the generic wildcard.
  ['a glob that names a protected image', "Stop-Process -Name 'chrome*'", 'protected-image-kill'],
  ['a subshell is not a glob', '(killall chrome)', 'protected-image-kill']
];

const ALLOW_CASES = [
  ['explicit PID', 'Stop-Process -Id 42', 'explicit-pid'],
  ['explicit PID on an enumeration', 'Get-Process -Id 42 | Stop-Process -Force', 'explicit-pid'],
  ['bash kill by PID', 'kill 4711', 'explicit-pid'],
  ['bash kill by PID after option terminator', 'kill -TERM -- 4711', 'explicit-pid'],
  ['handle from Start-Process -PassThru', '$p = Start-Process chrome -PassThru\nif (-not $p.WaitForExit(25000)) { $p.Kill() }', 'handle-or-unprotected'],
  ['a verb inside a string literal is not a verb', 'Write-Output "Stop-Process -Name chrome"', 'no-match'],
  ['documentation text quoting the rule stays allowed', 'Write-Output "call Stop-Process -Name chrome to reproduce"', 'no-match'],
  ['unquoted documentation arguments are not invocations', 'Write-Output taskkill chrome', 'no-match'],
  ['single-quoted command substitution is literal text', "Write-Output '$(pkill chrome)'", 'no-match'],
  ['an indirection primitive with no kill inside is not flagged', 'cmd /c "chrome --version"', 'no-match'],
  ['an indirection primitive aiming at an unprotected image is not flagged', 'iex "Stop-Process -Name notepad"', 'no-match'],
  ['a selected unprotected process enumeration', 'Get-Process notepad | Stop-Process', 'handle-or-unprotected'],
  ['a selected process after a common option', 'Get-Process -ErrorAction SilentlyContinue notepad | Stop-Process', 'handle-or-unprotected'],
  ['a selected unprotected process behind indirection', 'iex "Get-Process notepad | Stop-Process"', 'no-match'],
  ['an image named only in a comment', 'Stop-Process -Id 5 # chrome', 'explicit-pid'],
  ['an image used as an error-variable name is not a target', 'Stop-Process -Id 42 -ErrorVariable chrome', 'explicit-pid'],
  ['an unprotected image', 'Stop-Process -Name notepad', 'handle-or-unprotected'],
  ['taskkill on an unprotected image', 'taskkill /IM notepad.exe /F', 'handle-or-unprotected'],
  ['reading processes without killing them', 'Get-Process chrome', 'no-match'],
  ['starting a headless browser', 'Start-Process chrome --headless=new --user-data-dir=$tmp', 'no-match'],
  ['encoded-command documentation is not executed', `Write-Output "pwsh -EncodedCommand ${ENCODED_KILL}"`, 'no-match'],
  ['empty command', '', 'no-match'],

  // A command substitution is the only part of a quoted string that runs.
  ['a substitution beside the rule is not the rule', 'Write-Output "$(Get-Date) Stop-Process -Name chrome"', 'no-match'],
  ['prose about the rule next to a substitution', 'echo "today is $(date) and Stop-Process -Name chrome is banned"', 'no-match'],
  ['a single-quoted substitution is literal text', "Write-Output '$(Get-Date) Stop-Process -Name chrome'", 'no-match'],

  // An interpreter is only indirect when its payload actually kills something.
  ['an interpreter with a harmless payload', 'python -c "print(\'hello\')"', 'no-match'],
  ['node with a harmless payload', 'node -e "console.log(process.version)"', 'no-match'],

  // A tracked process object that is only read is not a kill.
  ['a tracked process object that is only inspected', '$p = Get-Process chrome; $p | Select-Object Id', 'no-match'],

  // Text that merely names a verb and an image is still text.
  ['an unquoted verb after a comma on one line', 'echo a, kill chrome', 'no-match'],
  ['a wrapper word that is an argument, not a wrapper', 'Write-Output time killall chrome', 'no-match'],

  // Documented limits, asserted so a future tightening has to update the docs.
  ['a dynamic image name read at runtime stays out of scope', 'Stop-Process -Name (Get-Content names.txt)', 'handle-or-unprotected'],
  ['remote execution cannot reach a local host process', 'ssh host killall chrome', 'no-match'],
  ['an inspector that does not execute its arguments', 'gdb -p 1 killall chrome', 'no-match'],

  // A variable name is not a process name.
  ['an error-variable named after an image', 'Stop-Process -Name notepad -ErrorVariable chrome', 'handle-or-unprotected'],
  ['an out-variable named after an image', 'Stop-Process -Name notepad -OutVariable chrome', 'handle-or-unprotected'],
  ['a variable test around an unprotected kill', 'if ($chrome) { Stop-Process -Name notepad }', 'handle-or-unprotected'],
  ['an unresolved variable as an image name', 'Stop-Process -Name $chrome', 'handle-or-unprotected'],

  // A real filter still counts as narrowing.
  ['a name filter narrows the enumeration', "Get-Process | Where-Object { $_.ProcessName -eq 'notepad' } | Stop-Process", 'handle-or-unprotected'],
  ['a bare-property name filter narrows the enumeration', "Get-Process | Where-Object ProcessName -eq 'notepad' | Stop-Process", 'handle-or-unprotected'],
  ['a targeted CIM filter narrows the enumeration', 'Get-CimInstance Win32_Process -Filter "Name=\'notepad.exe\'" | Remove-CimInstance', 'handle-or-unprotected']
];

/**
 * A pathological command must not stall the tool-call path. The guard runs
 * synchronously before every shell call, so a backtracking blow-up here is a
 * hang the model cannot cancel.
 */
test('a long command is evaluated in linear time', () => {
  const started = Date.now();
  const verdict = evaluateCommand(`Stop-Process -Name ${'a'.repeat(200_000)}`);
  const elapsed = Date.now() - started;
  assert.equal(verdict.kind, 'allow');
  assert.ok(elapsed < 2_000, `200 KB command took ${elapsed}ms`);
});

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

test('safe scoped-filter exception is explicit and rejects negative filters', () => {
  assert.equal(evaluateCommand(SAFE_SCOPED).kind, 'deny', 'the default does not treat command text as proof of ownership');
  assert.equal(evaluateCommand(SAFE_SCOPED, { safeFilterAllows: true }).rule, 'safe-scoped-filter');
  assert.equal(evaluateCommand(UNSAFE_NEGATED_FILTER, { safeFilterAllows: true }).kind, 'deny');
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
