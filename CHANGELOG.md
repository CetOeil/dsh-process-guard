# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-23

A correctness release for the matcher, driven by an adversarial review of
`lib/matcher.js` and a host-integration review against `dsh` 0.1.5-rc.3. Several
fixes close bypasses that returned `allow` for a command that terminates a
protected image.

### Fixed

- **Command position was wrong for wrapper prefixes.** The wrapper branch of the
  invocation check required trailing whitespace that `trim()` had already
  removed, so `sudo killall chrome`, `time pkill chrome`, `nohup`, `nice`,
  `setsid`, `command`, `env FOO=1`, `xargs`, `busybox`, `exec`, and `builtin`
  prefixes were all allowed. The check is now a token scan that also accepts
  shell keywords (`for …; do killall chrome; done`, `if …; then …; fi`), a
  `NAME=value` prefix, `find -exec`, path-qualified wrappers (`/usr/bin/sudo`),
  path-qualified verbs after a wrapper, and duration arguments (`timeout 10s`).
- **A `Where-Object`/`?` clause was treated as narrowing without being read.**
  `Get-Process | ? { 1 } | Stop-Process -Force` — the original incident with a
  filter that filters nothing — was allowed, as were `{ $true }`, `{ $_.Id -gt 0
  }`, `{ $_.Name -ne 'zzz' }`, `{ $_.ProcessName }`, and a wildcard-only CIM
  `-Filter`. A clause now counts only when it compares a process property against
  an operand that can exclude something.
- **Command substitution was searched on the wrong text.** `$(…)`/`@(…)` bodies
  are now inspected on their own, which closes the POSIX backtick form
  (`` echo `pkill chrome` ``) and removes a false positive: `Write-Output
  "$(Get-Date) Stop-Process -Name chrome"` is text again, not a kill.
- **Indirect-execution coverage.** Added `zsh`, `dash`, `ksh`, `ash`, `fish`,
  `su -c`, `script -c`, and the interpreters `python`/`perl`/`ruby`/`node`/`php`
  with `-c`/`-e`/`-r`/`--eval`; added PowerShell's unambiguous `-Command`
  prefixes (`-Com`); added the `saps` alias of `Start-Process`; added `wsl`,
  `chroot`, `flock`, `nsenter`, `unshare`, `strace`, and `ltrace` as launchers.
- **Encoded commands.** The decoder now accepts every prefix PowerShell's
  parameter binder accepts (`-Encode`, `-Encoded`, `-Enco`, `-En`) and a payload
  after a backtick line continuation.
- **Flow tracking.** A literal selector held in a variable is classified, so
  `$pattern = '*'; Stop-Process -Name $pattern` is a blanket kill; scope
  qualifiers are normalized (`$global:p` and `$p` are one variable);
  `Set-Variable -Name p -Value …` counts as an assignment; a tracked handle
  survives a derived member (`$p.Id | Stop-Process`) and a pipeline into
  `ForEach-Object { $_.Kill() }`; and a quoted variable handed to `iex` is
  followed.
- **Quadratic backtracking removed.** A 200 KB statement spent 21 s inside
  `NAMED_WILDCARD_SELECTOR`, synchronously on the tool-call path. Every
  quantifier in the selector regexes is now bounded; the same input takes ~10 ms
  and the corpus measures it.
- **False positives.** A protected image name inside a variable name or an
  `-ErrorVariable`/`-OutVariable` value no longer refuses an unprotected kill
  (`Stop-Process -Name notepad -ErrorVariable chrome`); `-name` under `find` is
  no longer read as a process selector; a subshell's `)` is no longer a glob; and
  a named protected image now outranks the generic wildcard rule, so
  `Stop-Process -Name 'chrome*'` reports `protected-image-kill`.
- `scripts/check-package.mjs` failed with `EINVAL` on Windows when
  `npm_execpath` was unset, because Node refuses to spawn a `.cmd` shim without a
  shell. It now resolves npm's CLI beside the running Node and stays shell-free.

### Added

- `scripts/check-market.mjs` (`npm run verify:market`), which checks the locally
  verifiable dsh-plugin.org listing requirements — a copyable install command in
  the README, an `apply(ctx)` export, a declared bundle patch, and a stated
  license — and prints the two GitHub-side steps it cannot check.
- `docs/PUBLISHING.md`, the verified listing and release checklist.
- 45 matcher corpus cases covering every defect above in both directions, plus a
  linear-time guard on a 200 KB command.

### Changed

- `engines.dsh` is now `>=0.1.0-rc.6 || >=0.1.5-rc.1`. The previous range
  evaluated **false** against `0.1.5-rc.3`, the host this plugin is verified
  against, because node-semver admits a prerelease only through a comparator with
  the same version tuple. The field is documentation, not a gate: npm and pnpm
  evaluate only the standard `node`/`npm` engine keys, and the enforced check is
  the runtime one. `check-bundle.mjs` now evaluates the range instead of claiming
  a consumer that does not exist.
- README, `docs/DESIGN.md`, and `SECURITY.md` correct the dsh-plugin.org
  submission process (automatic topic scan, no pull request), the literal
  `process-guard: blocked - …` reason string, the load-time log line, and the
  sandbox note.

## [0.1.0] - 2026-09-21

### Added

- `lib/matcher.js`: dependency-free command matcher that flags termination of
  protected processes selected by image name, wildcard/process-group kills, and
  unfiltered process enumerations, while allowing explicit-PID and owned-handle
  kills. It covers common PowerShell aliases, CIM/WMI termination, multiline
  pipelines, command substitution, literal indirection, and encoded PowerShell.
- `lib/index.js`: DeepSeek Harness bundle plugin registering the matcher on the
  tool-call path — through `ctx.tools.guard()` in `deny` mode (monotonic, cannot
  be force-allowed) or `ctx.on('tools/pre-execute')` in `ask` mode — plus an
  optional `systemPrompt` section that states the rule before a call is made.
- `cordis.patch.yml`: the bundle layer that mounts the plugin into a profile.
- Tests covering the matcher corpus (including the real command that caused the
  original incident) and plugin registration against a stub context.
- Cross-platform release checks, an exact npm artifact audit, and GitHub Actions
  workflows for CI and provenance-backed npm publication.
- Documentation: `README.md`, `docs/DESIGN.md`, `docs/agents-md-snippet.md`, and
  `examples/override.cordis.patch.yml`.

[Unreleased]: https://github.com/CetOeil/dsh-process-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/CetOeil/dsh-process-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CetOeil/dsh-process-guard/releases/tag/v0.1.0
