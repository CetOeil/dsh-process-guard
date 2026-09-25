# dsh-process-guard

A [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) bundle that
refuses shell commands which terminate processes **by image name, wildcard,
process group, or unfiltered enumeration** — the failure mode that closes the
Harness GUI window in the middle of a turn.

The DSH Web GUI is a browser client on `http://127.0.0.1:3080`, and the harness
server is a `node` process. `Get-Process chrome | Stop-Process -Force` therefore
kills the harness's own host processes. This plugin inspects every shell tool
call before it runs and refuses that shape, while leaving explicit-PID kills and
`-PassThru` handle kills untouched.

```
Error: process-guard: blocked - this terminates "chrome", "msedge" after selecting
it by image name. That image may host the DSH GUI (http://127.0.0.1:3080), harness,
or terminal, so killing it can close the UI and interrupt the session. Kill only a
process you started: $p = Start-Process ... -PassThru; if (-not $p.WaitForExit(25000))
{ $p.Kill() }; or target a known PID with -Id.
```

## The incident this exists for

On 2026-09-18 a session running headless-Chrome screenshot verification cleaned
up between attempts with a blanket kill:

```powershell
Get-Process chrome,msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
```

That command terminated every Chrome process on the machine — including the one
hosting the DSH Web GUI. The window disappeared, the client connection dropped,
and the harness recorded the turn as `interrupted` with a tool result of
"outcome unknown". A later command, approved through the normal escalation
prompt, began *and* ended with the same blanket kill and produced the same result
about three seconds after the approval was recorded. The approval was incidental:
it was the gate that let the command run, not the cause.

The audit trail shows an `approval/asked` with no matching `approval/decided`,
followed by `turn/end … interrupted`, and the harness server itself never
crashed — which is exactly why this needs a guard on the tool path rather than a
fix somewhere else. `docs/DESIGN.md` records the full reasoning.

## What it does

| Command | Verdict |
|---|---|
| `Get-Process chrome \| Stop-Process -Force` | refused (`protected-image-kill`) |
| `Stop-Process -Name msedge`, `taskkill /IM chrome.exe /F`, `killall chrome`, `pkill -f chrome` | refused |
| `Get-Process node \| Stop-Process -Force`, `Stop-Process -Name WindowsTerminal` | refused |
| `Get-Process \| Stop-Process -Force`, `Stop-Process -Name '*'`, `taskkill /F /IM *`, `kill -9 0` | refused (blanket selection) |
| `spps -Name chrome`, `wmic … call terminate`, `Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" \| Invoke-CimMethod -MethodName Terminate` | refused |
| `sudo killall chrome`, `time pkill chrome`, `nohup killall chrome`, `xargs killall`, `FOO=1 killall chrome` | refused (the wrapper runs the command) |
| `for f in *; do killall chrome; done`, `if [ -f x ]; then killall chrome; fi` | refused (the keyword starts a command) |
| `Invoke-Expression "Stop-Process -Name chrome"`, `cmd /c "taskkill /IM * /F"`, `zsh -c 'killall chrome'`, `python -c "os.system('killall chrome')"`, literal `-EncodedCommand` | refused (`indirect-execution`) |
| `Stop-Process -Id 42`, `kill 4711` | allowed (`explicit-pid`) |
| `$p = Start-Process chrome -PassThru; … $p.Kill()` | allowed (handle you own) |
| `$p = Get-Process chrome; $p.Kill()`, `$p = Get-Process chrome; $p \| % { $_.Kill() }` | refused (the name-selected object is tracked across statements) |
| `$x = 'chrome'; Stop-Process -Name $x` | refused (a literal image name stays one through a variable) |
| `Get-Process chrome \| Where-Object { $_.CommandLine -like '*--headless*' } \| Stop-Process` | refused by default; allowed only with `safeFilterAllows: true` |
| `Get-Process notepad \| Stop-Process` | allowed (selected unprotected image, not a blanket enumeration) |
| `Stop-Process -Name notepad` | allowed (not a protected image) |
| `Write-Output "Stop-Process -Name chrome"` | allowed (text, not an invocation) |
| `Write-Output "$(Get-Date) Stop-Process -Name chrome"` | allowed (only the substitution runs, and it is not a kill) |
| `find . -name "*.log" -exec grep -l chrome {} \;` | allowed (`-name` here is `find`'s, not a process selector) |

It also contributes a short system-prompt section stating the rule, so the model
knows the constraint *before* it hits a refusal.

## Install

```sh
dsh plugin --profile web add dsh-process-guard
```

`dsh plugin` forwards to pnpm inside the profile and then appends the package to
`dsh.profile.bundles`, because the package declares `dsh.bundle.patch`. Confirm
the layer composed, then restart `dsh web`:

```sh
dsh --profile web --dump-config   # look for a "# == dsh-process-guard" layer
```

From a checkout, install the directory instead of the registry name:

```sh
dsh plugin --profile web add /path/to/dsh-process-guard
```

A git URL works too, and needs no build: the repository root *is* the package.

```sh
dsh plugin --profile web add git+https://github.com/CetOeil/dsh-process-guard.git
```

The plugin has **no runtime dependencies**, so installation needs no build step
and no pnpm `allowBuilds` authorization. It requires a harness whose `dsh-tools`
exposes `ctx.tools.guard()`; this release is verified against `dsh` 0.1.5-rc.3,
recorded as `engines.dsh`. Treat that field as documentation rather than a gate:
npm and pnpm only evaluate the standard `node`/`npm` engine keys, and node-semver
cannot express "any prerelease at or above X" — a prerelease comparator admits
only prereleases of its own version tuple, which is why the declared range lists
`0.1.5-rc.1` explicitly. The **enforced** gate is the runtime check: on a host
without `ctx.tools.guard()` the plugin throws at load instead of leaving an
apparently active but ineffective guard.

One pnpm 12 behaviour is worth knowing for the first days after a release: its
supply-chain release-age gate treats a freshly published version as too new. In
the default non-strict mode pnpm records the exception itself
(`minimumReleaseAgeExclude` in the profile's `pnpm-workspace.yaml`) and the
install proceeds; with `minimumReleaseAgeStrict: true` it stops at a prompt
instead. Either way the git install above is unaffected.

## Configuration

Defaults are the safe ones; the shipped `cordis.patch.yml` deliberately sets no
`config:` block. Override keys by copying the row into your own profile
`cordis.patch.yml` (see `examples/override.cordis.patch.yml`):

```yaml
- id: process-guard
  name: dsh-process-guard
  config:
    mode: ask                 # 'deny' (default) routes through ctx.tools.guard()
    additionalTools: [remote_shell]
    additionalProtectedImages: [custombrowser]
    safeFilterAllows: false   # default: require a PID or owned process handle
    announce: true            # add the system-prompt section
    enabled: true
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Set `false` to disable inspection entirely. |
| `tools` | common shell tool names | Replacement list of tools whose `command` argument is inspected. |
| `additionalTools` | `[]` | Tool names added to the default list. |
| `protectedImages` | cross-platform browsers + harness/terminal hosts | Replacement list of images that must never be killed by name. |
| `additionalProtectedImages` | `[]` | Image names added to the built-in protected list. |
| `mode` | `deny` | `deny` blocks the call; `ask` sends it to the approval prompt instead. |
| `safeFilterAllows` | `false` | Opt into the positive `CommandLine -like/-match '*--headless*'` or `--user-data-dir` exception. Negated or `-or` filters remain blocked. |
| `announce` | `true` | Contribute the system-prompt section. |

Use `additionalTools` and `additionalProtectedImages` for normal extension;
`tools` and `protectedImages` intentionally replace their defaults. Unknown keys,
mistyped booleans, invalid array entries, and empty safety lists are reported and
fall back to safe values, so a typo cannot quietly weaken the guard.

`mode: deny` is enforced through `ctx.tools.guard()`, which is *monotonic* — no
other guard can force-allow a call this one denied. `mode: ask` registers a
`tools/pre-execute` listener instead and lets you decide, with the reason shown.

## Verifying it works

1. Ask the agent to run `Stop-Process -Name chrome`. It must come back as
   `Error: process-guard: blocked - …` and no pwsh process may have spawned.
2. Ask it to run `Stop-Process -Id <some pid>` — that must still work.
3. On load the plugin also writes one host-log entry, `process-guard: deny mode on
   [pwsh, bash, terminal, …]; protected images: chrome, …`. It goes to the
   harness log, not necessarily to your terminal: cordis ships no console
   exporter, so treat the two behavioural checks above as the verification.

Local checks in this repository:

```sh
npm run check                     # tests + bundle + listing readiness + exact npm artifact
npm test                          # matcher corpus + plugin registration
npm run test:no-isolation         # constrained sandboxes that block piped children
npm run verify:market             # the README install command the hub looks for, plus manual steps
```

A sandbox that blocks piped child processes (both `npm test`, which spawns one
process per test file, and `npm run verify:package`, which runs `npm pack` as a
child) breaks `npm run check` for reasons unrelated to this package. Use
`npm run test:no-isolation` there, and run the three verification scripts
individually; only `verify:package` needs the wider permission.

## Limits — read this before trusting it

This is a **behavioral safety net, not a security boundary.** It is a static
heuristic over command text, and these bypass it:

- **Generated or separately stored commands** — a script written in one tool
  call and executed in the next, a command read from disk or the network, or a
  kill assembled from string fragments at runtime. `Stop-Process -Name
  (Get-Content names.txt)` is therefore allowed. Literal PowerShell
  `-EncodedCommand` payloads are decoded and inspected, and a literal image name
  held in a variable is resolved.
- **Anything outside the inspected tools** — a future process-management tool, an
  MCP server, or a skill that shells out on its own. The shipped `cordis` agent
  preset mounts `cordis_define` / `cordis_run`, which execute host JavaScript
  without ever calling `pwsh` or `bash`; a kill written there is not inspected.
- **Remote execution** — `ssh host killall chrome` runs on the other machine and
  cannot close this one's GUI, so it is not refused.
- **Renamed or copied binaries** — a kill aimed at an image name that is not in
  `protectedImages`.
- **Unmodeled process APIs** — direct native calls, a future shell primitive, or
  platform conventions absent from the matcher. Wrapper coverage is an explicit
  list (`sudo`, `time`, `nohup`, `xargs`, `busybox`, …), not a general model of
  which programs execute their arguments.

What it *does* cover is the realistic failure: an agent reaching for the obvious
name-based cleanup. Treat a refusal as a signal to use a narrower command, not as
proof that no destructive command can run.

## Disable or remove

```sh
dsh plugin --profile web remove dsh-process-guard
```

Or hot-disable it in your profile `cordis.patch.yml` without uninstalling:

```yaml
- id: process-guard
  disabled: true
```

## How this relates to general permission plugins

This plugin is narrow on purpose, and it is worth being clear about where it
sits. General DSH permission plugins exist and are good; none of them knows
anything about processes.

| Plugin | What it gates | Process termination |
|---|---|---|
| [`dsh-permission-rules`](https://github.com/PerryLink/dsh-permission-rules) | Declarative user-authored allow/deny/ask rules, plus a shipped high-risk baseline: `rm -rf /`, `mkfs`, `dd` to a device, `chmod -R 777`, setuid bits, `shutdown`/`reboot`, `git push --force`, `git reset --hard`, `curl \| sh`, fork bomb, sensitive paths | **No rule, no concept** |
| [`safety-net` / Barricade](https://github.com/JohnXu22786/safety-net) | 41 built-in rules over `fs/`, `git/`, `shell/`, `interp/`, `sys/` — destructive filesystem and repository operations | **No rule, no concept** |
| **this plugin** | Process termination selected by image name, wildcard, process group, or unfiltered enumeration | the whole point |

Both neighbours hook the `tools/pre-execute` waterfall. This plugin can use that
seam too (`mode: ask`), but its default is `ctx.tools.guard()`, which is
**monotonic** — no later guard or listener can force-allow a call another guard
denied. See `docs/DESIGN.md` §2 for why that property matters for a safety rule.

They **compose rather than conflict**: the guard stage runs after the
`tools/pre-execute` waterfall, so a general permission plugin decides first and
this one still gets its veto.

The honest caveat is mechanism, not coverage. Barricade's POSIX lexer,
segmenter and wrapper unwrapping are more capable than this plugin's text
matcher, which `docs/DESIGN.md` §7 admits is a heuristic. If a general gate ever
gains a process-termination family with host-topology knowledge, it would cover
this. Until then, the thing that is actually unique here is the **domain
knowledge** — that `chrome`, `msedge`, `firefox`, `node`, `pwsh`, `conhost` and
`WindowsTerminal` are the DSH host tree, and that a blanket selection is as
dangerous as a named one.

## Related

- `docs/DESIGN.md` — why the guard sits on the tool path, why not the sandbox
  seam, and the full list of known bypasses.
- `docs/PUBLISHING.md` — the verified dsh-plugin.org listing requirements and the
  release checklist.
- `docs/agents-md-snippet.md` — the same rule as prose, for users who prefer an
  `AGENTS.md` instruction over a plugin (or want both layers).
- `SECURITY.md` — what this does not protect against, and what to report.

## Contributing

```sh
npm run check         # tests, bundle contract, listing readiness, packed-file audit
```

Two rules keep the matcher honest: every new refusal rule needs a corpus case in
`test/matcher.test.js`, and every new rule needs at least one *allowed* case that
proves it does not swallow legitimate commands. `docs/DESIGN.md` §5 explains the
two-view masking and the command-position check the matcher depends on.

## Publishing

The release workflow publishes on a GitHub Release whose tag exactly matches
`v<package.json version>`, using **trusted publishing (OIDC)** — no npm token is
stored anywhere. Configure the package's trusted publisher on npmjs.com (GitHub
Actions, this repository, workflow `publish.yml`), then publish a release; the
workflow does the rest and the attestation comes with it.

Two details make that work, and both are easy to get wrong:

- `actions/setup-node` must **not** set `registry-url`. It writes an `.npmrc`
  containing a `NODE_AUTH_TOKEN` placeholder, and that placeholder overrides
  npm's native OIDC exchange — the job then fails on auth with nothing actually
  wrong with the trusted publisher.
- The job needs `id-token: write` (already set) and `--provenance` on the publish
  command, which is what drives the exchange.

For a manual publish from a workstation there is no attestation — `--provenance`
is a cloud-CI feature ("when publishing from a supported cloud CI/CD system",
per `npm publish --help`) — and it needs a credential npm is progressively
retiring, so prefer the release path:

```sh
npm run check
npm publish --access public
```

0.2.1 was the exception to all of this: trusted publishing cannot publish a
package's *initial* version, so the first release used a granular access token
instead. See `docs/PUBLISHING.md` §5 for the token traps that involves.

The npm name `dsh-process-guard` was unclaimed when this package was prepared.

Listing on [dsh-plugin.org](https://dsh-plugin.org) is **automatic and needs no
pull request**: the hub periodically scans public GitHub repositories carrying
the `dsh-plugin` topic, then reviews each one by hand. Its four stated
requirements are a public repository, that topic, a README containing
`dsh plugin --profile web add <package>`, and an `apply(ctx)` export.

`npm run verify:market` owns the install command — the requirement nothing else
covers — and prints the two GitHub-side steps it cannot check from here. The
manifest half of the contract is `npm run verify`, and the `apply(ctx)` export
needs no check: `test/plugin.test.js` imports it by name, so losing it fails
`npm test`. See `docs/PUBLISHING.md` for the full checklist.

The curated [`awesome-dsh-plugin`](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin)
list is a **separate** registry with a pull-request flow; it is optional. Its CI
requires the repository to be at least one day old and the entry to be the single
file `data/plugins/CetOeil__dsh-process-guard.yml`:

```yaml
url: https://github.com/CetOeil/dsh-process-guard
name: CetOeil/dsh-process-guard
category: security
description:
  en: Blocks DSH shell calls that terminate protected browser, terminal, or harness processes by image name, wildcard, process group, or unfiltered enumeration.
```

## License

MIT — see [LICENSE](./LICENSE).
