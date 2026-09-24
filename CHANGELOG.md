# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `publish.yml` now publishes over **trusted publishing (OIDC)** instead of a
  stored npm token. `NPM_TOKEN` and `setup-node`'s `registry-url` are both gone:
  `registry-url` writes an `.npmrc` with a `NODE_AUTH_TOKEN` placeholder, and
  that placeholder overrides npm's native OIDC exchange, so the job would fail
  on auth with nothing wrong with the trusted publisher.
- `docs/PUBLISHING.md` §5 now separates the three `PUT` failures that look alike
  and are not: a `403` naming 2FA (a token setting), a `403` saying "these
  credentials" (a different token setting — usually the stage-only permission,
  added 2026-09-18, or a package-scoped token that cannot cover a name with no
  published versions), and a `409` (transient; retry). It also records why 0.2.1
  needed a token at all: OIDC cannot publish a package's initial version
  (npm/cli#8544), and bypass-2FA tokens lose direct publishing in January 2027.

## [0.2.1] - 2026-09-24

The first installable release. 0.2.0 was published and then unpublished 53
minutes later, and npm never allows a name-and-version pair to be reused, so
`dsh-process-guard@0.2.0` can never be published again. This version ships the
same code, plus the documentation and release-check changes below.

### Changed

- Reduced the release checks from 364 to 287 lines with no loss of coverage,
  verified by mutation test: every assertion removed from one script is still
  caught by another in `npm run check`.
  - `check-bundle.mjs`: dropped the js-yaml strict-parse path. It was
    unreachable — the package is dependency-free by design, so `js-yaml` cannot
    resolve and every run already took the structural fallback it reported.
  - `check-market.mjs`: narrowed to the one requirement nothing else covers, the
    README install command, plus the two GitHub-side steps it prints. The
    manifest assertions it repeated (bundle patch, `private`, README presence,
    `main`) belong to `check-bundle.mjs`, and its `apply(ctx)` export check was
    already load-bearing: `test/plugin.test.js` imports that export by name.
  - `check-market.mjs`: the license check's regex anchored only its first
    alternative, so `^MIT|Apache|…` accepted any string containing "Apache".
    Replaced with a plain SPDX-shape test.

### Removed

- A third-party workspace name and private session-log coordinates from the
  incident write-up in `README.md` and `docs/DESIGN.md`. The causal chain that
  motivates the guard is unchanged; the identifiers are gone.

## [0.2.0] - 2026-09-23

**Not installable.** Published to npm at 16:50 UTC and unpublished at 17:42 UTC;
npm does not permit a name-and-version pair to be reused, so this version can
never be republished. See 0.2.1, which ships the same code.

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

This version was never published to npm. The first installable registry release
is 0.2.1, so `npm install dsh-process-guard@0.1.0` has nothing to resolve; the
entry is kept because the commit it describes is in the history.

[Unreleased]: https://github.com/CetOeil/dsh-process-guard/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/CetOeil/dsh-process-guard/releases/tag/v0.2.1
[0.2.0]: https://github.com/CetOeil/dsh-process-guard/commit/2ab8c44
[0.1.0]: https://github.com/CetOeil/dsh-process-guard/commit/62b7517
