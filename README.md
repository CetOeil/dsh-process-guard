# dsh-process-guard

A [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) bundle that
refuses shell commands which terminate processes **by image name** — the failure
mode that closes the Harness GUI window in the middle of a turn.

The DSH Web GUI is a browser client on `http://127.0.0.1:3080`, and the harness
server is a `node` process. `Get-Process chrome | Stop-Process -Force` therefore
kills the harness's own host processes. This plugin inspects every shell tool
call before it runs and refuses that shape, while leaving explicit-PID kills and
`-PassThru` handle kills untouched.

```
Error: process-guard: blocked — this terminates "chrome", "msedge" by image name.
That image may be the browser hosting the DSH Web GUI (http://127.0.0.1:3080) or the
harness's own process, and killing it closes the GUI window and drops this session's
client connection. Kill only processes you started: $p = Start-Process ... -PassThru;
if (-not $p.WaitForExit(25000)) { $p.Kill() } — or target explicit PIDs with -Id.
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
| `Get-Process \| Stop-Process -Force`, `Stop-Process -Name *`, `taskkill /F /IM *` | refused (`blanket-enumeration` / `blanket-wildcard`) |
| `Invoke-Expression "Stop-Process -Name chrome"`, `cmd /c "taskkill /IM chrome.exe /F"` | refused (`indirect-execution`) |
| `Stop-Process -Id 42`, `kill 4711` | allowed (`explicit-pid`) |
| `$p = Start-Process chrome -PassThru; … $p.Kill()` | allowed (handle you own) |
| `Get-Process chrome \| Where-Object { $_.CommandLine -like '*--headless*' } \| Stop-Process` | allowed (scoped to your own headless instance) |
| `Stop-Process -Name notepad` | allowed (not a protected image) |
| `Write-Output "Stop-Process -Name chrome"` | allowed (text, not an invocation) |

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

The plugin has **no runtime dependencies**, so installation needs no build step
and no pnpm `allowBuilds` authorization. It requires a harness that exposes
`ctx.tools.guard()` (`dsh >= 0.1.0-rc.6`, the `engines.dsh` floor declared in
`package.json`). On an older host it logs an error and stays inactive rather than
pretending to protect anything.

## Configuration

Defaults are the safe ones; the shipped `cordis.patch.yml` deliberately sets no
`config:` block. Override keys by copying the row into your own profile
`cordis.patch.yml` (see `examples/override.cordis.patch.yml`):

```yaml
- id: process-guard
  name: dsh-process-guard
  config:
    mode: ask                 # 'deny' (default) routes through ctx.tools.guard()
    tools: [pwsh, bash]       # default: [pwsh, bash, terminal]
    protectedImages: [chrome, msedge, node]
    safeFilterAllows: true    # allow the --headless / --user-data-dir pattern
    announce: true            # add the system-prompt section
    enabled: true
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Set `false` to disable inspection entirely. |
| `tools` | `[pwsh, bash, terminal]` | Tool names whose `command` argument is inspected. |
| `protectedImages` | browsers + harness host tree | Image names that must never be killed by name. |
| `mode` | `deny` | `deny` blocks the call; `ask` sends it to the approval prompt instead. |
| `safeFilterAllows` | `true` | Keep the `--headless` / `--user-data-dir`-scoped pattern allowed. |
| `announce` | `true` | Contribute the system-prompt section. |

Unknown keys are reported through the logger rather than silently ignored, so a
typo cannot quietly weaken the guard.

`mode: deny` is enforced through `ctx.tools.guard()`, which is *monotonic* — no
other guard can force-allow a call this one denied. `mode: ask` registers a
`tools/pre-execute` listener instead and lets you decide, with the reason shown.

## Verifying it works

1. The plugin logs one line at load:
   `process-guard: deny mode on [pwsh, bash, terminal]; protected images: chrome, …`
2. Ask the agent to run `Stop-Process -Name chrome`. It must come back as
   `Error: process-guard: blocked — …` and no pwsh process may have spawned.
3. Ask it to run `Stop-Process -Id <some pid>` — that must still work.

Local checks in this repository:

```sh
npm test                          # node --test test/
npm run test:no-isolation         # constrained sandboxes that block piped children
```

## Limits — read this before trusting it

This is a **behavioral safety net, not a security boundary.** It is a static
heuristic over command text, and these bypass it:

- **Encoded or generated commands** — `powershell -EncodedCommand <base64>`, a
  script written in one tool call and executed in the next, or a kill assembled
  from string fragments at runtime.
- **Anything outside the inspected tools** — a future process-management tool, an
  MCP server, or a skill that shells out on its own.
- **Renamed or copied binaries** — a kill aimed at an image name that is not in
  `protectedImages`.
- **Other platforms' conventions** the patterns do not model.

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

## Related

- `docs/DESIGN.md` — why the guard sits on the tool path, why not the sandbox
  seam, and the full list of known bypasses.
- `docs/agents-md-snippet.md` — the same rule as prose, for users who prefer an
  `AGENTS.md` instruction over a plugin (or want both layers).
- `SECURITY.md` — what this does not protect against, and what to report.

## Contributing

```sh
npm run verify        # the bundle install contract
npm test              # the matcher corpus + plugin registration
```

Two rules keep the matcher honest: every new refusal rule needs a corpus case in
`test/matcher.test.js`, and every new rule needs at least one *allowed* case that
proves it does not swallow legitimate commands. `docs/DESIGN.md` §5 explains the
two-view masking the matcher depends on.

## Publishing checklist

The package is registry-ready, but two placeholders must be replaced first:

1. `package.json` → `repository`, `bugs`, `homepage` currently read `OWNER`.
2. `CHANGELOG.md` → the two comparison links at the bottom.

Then:

```sh
npm publish                        # prebuilt, no build step, no allowBuilds prompt
```

To appear in the community market, add one entry to the curated
[`awesome-dsh-plugin`](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin)
registry (the market reads `awesome-dsh-plugin.com/plugins.json`; do not open
plugin PRs against the market app itself).

## License

MIT — see [LICENSE](./LICENSE).
