# Design notes

Why this plugin looks the way it does, and what it deliberately does not do.

## 1. The failure being prevented

A turn ended because the harness killed its own client:

| Order | Event | Evidence |
|---|---|---|
| 1 | `Get-Process chrome,msedge \| Stop-Process -Force` runs as unescalated cleanup | the call returns successfully |
| 2 | the next step asks for an escalation; its result is stamped `TOOL_OUTCOME_UNKNOWN` and the turn ends `interrupted` | the client had already gone |
| 3 | an escalation is **asked** and then **approved** (`allowed-once`) for a command that begins and ends with the same blanket kill | the approval is recorded |
| 4 | that command succeeds (`exit=0`, screenshots written), but the client is already gone → `turn/end … interrupted` | the turn is still `interrupted` |

The GUI window is a `chrome.exe` process; the harness server survived both
events. So the bug is neither "the approval crashed the window" nor a harness
crash — it is a **command that cannot distinguish the user's browser from the
agent's headless one**.

## 2. Why the tool-call path

`dsh-tools` composes a call in this order:

```
tools/pre-execute waterfall  →  tools.guard() chain  →  tool body
                                                        └─ approvePwshEscalation()
```

Two consequences make this the right seam:

1. The guard runs **before the tool body**, and therefore before the sandbox
   escalation is requested — an approved escalation cannot launder a command that
   the guard refuses.
2. `ctx.tools.guard()` is documented as monotonic: *"any matching guard may deny
   by returning a reason, while no guard can force-allow a call another guard
   denied."* A safety rule wants exactly that property, which a plain waterfall
   listener does not guarantee (ordering against other plugins is not fixed).

## 3. Why not the other seams

- **The sandbox seam (`dsh-sandbox`, `dsh-pwsh-sandbox`):** its contract is
  file-effect policy (`writableRoots`, the three modes). Process termination is
  not a file effect; the confined cleanup run succeeded precisely because the
  sandbox has no opinion about it. Widening that contract to cover process kills
  would be a much larger change than this problem warrants.
- **A `PreToolUse` hook** (via `dsh-hooks-claude-code` / `dsh-hooks-codex`): works,
  and is the right choice if you want configuration-only deployment, but it costs
  a subprocess per matched call and the hook protocol does not honor
  `updatedInput`, so it can only deny or ask. `mode: ask` in this plugin offers
  the same decision without the subprocess.
- **An upstream patch to `dsh-tool-pwsh`:** the best long-term owner for a
  first-party rule, since it applies to every composition rather than one
  profile. This plugin exists because that path requires a harness release and
  the failure is already happening.
- **Prose only (`AGENTS.md`):** zero install cost and it shapes intent, but it
  cannot stop a command. See `docs/agents-md-snippet.md`; the two layers are
  complementary, not alternatives.

## 4. Why zero runtime dependencies

First-party plugins export a `schemastery` `Config` for validation and defaults.
This plugin deliberately does not: importing `@deepseek-ai/schemastery` would
couple a safety guard to the host's package tree, so a version skew between the
plugin's copy and the harness's copy becomes a way for the guard to fail at load
time. Config is normalized in-process instead: unknown keys, mistyped booleans,
bad array entries, and empty safety lists are reported and replaced with safe
defaults. This recovers the practical benefit without the coupling.

## 5. The matcher, and why it needs two views of the text

A single regex over the raw command cannot work in both directions: `Write-Output
"Stop-Process -Name chrome"` must not be treated as a kill, while `Stop-Process
-Name "chrome"` must be. So the matcher masks the command twice, preserving every
offset and newline:

| View | Blanked | Used for | Rationale |
|---|---|---|---|
| `noStrings` | quoted literals + comments | **verbs** | a verb inside a string is text, not an invocation |
| `noComments` | comments only | **targets, filters, selectors** | a quoted target and a quoted `'*--headless*'` filter are both real |

Comments (including PowerShell block comments) are removed from both, so
`Stop-Process -Id 5 # chrome` is not a protected-image kill. Segmentation is
computed from `noStrings`; it recognizes statement separators while preserving
escaped newlines, multiline script blocks, and pipelines split across lines.
The resulting offsets apply to both views and the raw text. Pipelines stay whole,
because `Get-Process chrome | Stop-Process` must be read as one unit.

The matcher also checks whether a verb occurs in command position. This keeps
`Write-Output taskkill chrome` as text while still recognizing a verb after a
pipeline, call operator, shell wrapper, assignment, or script-block boundary.
That check is an explicit model of *which programs run their arguments*: shell
keywords (`do`, `then`, `else`, `fi`), `NAME=value` prefixes, executing wrappers
(`sudo`, `time`, `nohup`, `xargs`, `env`, `busybox`, …), a shell's inline-code
form (`-c`, `-Command`, and PowerShell's unambiguous prefixes of it), `find
-exec`, and path-qualified spellings of all of them (`/usr/bin/sudo`). It is a
list, not an inference, so `ssh` is deliberately absent — it runs on another
machine, where it cannot close this one's GUI.

A wrapper's own options consume at most one following value, so
`sudo -u root killall chrome` and `timeout 10s pkill chrome` still resolve.
Over-consuming can only make the check stricter, never weaker.

Small state maps cover the cross-statement cases within one tool call:
name-selected process objects later killed through their variable, literal
command strings later passed to `Invoke-Expression`, and literal selector values
later handed to `-Name`. Variable names are normalized across PowerShell scope
qualifiers, so `$global:p` and `$p` are one variable, and a stored value is
classified once — which is why `$pattern = '*'; Stop-Process -Name $pattern` is
a blanket kill even though the wildcard never appears in the second statement.

Command substitution is searched on the substitution bodies alone, because that
is exactly what a shell executes: in `"$(date) Stop-Process -Name chrome"` the
substitution runs and the rest is literal text. Both `$(…)`/`@(…)` and the POSIX
backtick form are recognized; the backtick reading is also applied inside double
quotes, where PowerShell would instead read it as an escape. That trade is
deliberate — a body is only reported when it carries a kill verb plus a target,
so the cost lands in the fail-closed direction.

## 6. Rule precedence

1. `indirect-execution` — a protected or blanket termination behind a quoted
   shell, an interpreter (`python -c`, `node -e`), a command substitution, a
   call operator, a literal variable, or a decodable PowerShell
   `-EncodedCommand` (including its unambiguous abbreviations).
2. `protected-image-kill` — a protected image selected directly, through a
   process variable, or through a variable holding a literal image name. This
   outranks the blanket rules so a reason names the image it targets. The
   `--headless` / `--user-data-dir` filter exception is available only when
   `safeFilterAllows: true`; it is off by default and rejects negative or
   disjunctive filters.
3. `blanket-process-group`, `blanket-wildcard`, or `blanket-enumeration` — a kill
   aimed at a Unix process group, a wildcard selector (including one reached
   through a variable), or an enumeration with no PID, name, query, or narrowing
   filter. A `Where-Object`/`?` clause counts as narrowing only when it compares
   a process property against an operand that can exclude something: `{ 1 }`,
   `{ $true }`, `{ $_ }`, `{ $_.ProcessName }`, `{ $_.Name -ne 'zzz' }`, and
   `-like '*'` all leave every process in the pipeline and are therefore treated
   as no filter at all. A CIM `-Filter`/`-Query` must name and compare a process
   property for the same reason.
4. Otherwise `allow`, with the reason recorded as `explicit-pid`,
   `handle-or-unprotected`, `safe-scoped-filter`, or `no-match`.

`mode` only relabels a flag (`deny` → `ask`); it never converts a flag into an
allow. That asymmetry is deliberate: a configuration mistake can make the plugin
more intrusive, never silently weaker.

Every quantifier in the selector regexes is bounded. An unbounded `\S*` inside an
unbounded `[^|;\r\n]*` scan made the engine rescan the remainder from every
backtrack position, which is quadratic: a 200 KB statement took 21 s of
synchronous time on the tool-call path, blocking a turn the model cannot cancel.
The corpus now measures a 200 KB command so the bound cannot regress.

## 7. Known bypasses

Documented rather than papered over — each would need host-level knowledge (the
real client PID, or a syscall boundary) that an out-of-tree plugin does not have:

- A command assembled at runtime from fragments, read from a file or network
  response, or otherwise absent from the tool-call text. `Stop-Process -Name
  (Get-Content names.txt)` is allowed. Literal PowerShell `-EncodedCommand`
  values are decoded and inspected, and a literal selector assigned to a
  variable is resolved.
- A script written in one tool call and executed in the next: the guard sees two
  individually innocent commands.
- `Add-Type` / P/Invoke or another native API that targets a process without a
  protected image name appearing in the command.
- Image names absent from `protectedImages` (a renamed browser, a portable build).
- Tools other than the inspected `tools` list. The shipped `cordis` agent preset
  mounts `cordis_define` / `cordis_run`, which execute host JavaScript without
  calling `pwsh` or `bash`; an MCP process manager or a skill that shells out
  itself is the same shape.
- Remote execution. `ssh host killall chrome` runs on the other machine, so the
  wrapper list omits `ssh`; it cannot close this host's GUI. `wsl` is covered,
  because WSL interop can reach Windows processes.
- Wrapper coverage is enumerated, not inferred. A launcher that runs its
  arguments but is not named in `EXEC_WRAPPERS` is invisible until it is added.
- A semantic no-op filter that the heuristics cannot recognize as one. `{ $_.Id
  -gt 0 }` is rejected, but an equivalent comparison the matcher does not model
  still reads as narrowing.

A more precise design would compare the target against the live GUI client's PID
(derived from the connections on the web port, or injected into the tool
environment as a protected-PID variable). That belongs in the harness, where the
connection facts exist; the matcher here is the part that can be shipped today.

## 8. Testing strategy

`test/matcher.test.js` is a corpus: every refused case names the reason it must be
refused, and every allowed case names the safe shape it protects — including the
two commands from the original incident. `test/plugin.test.js` runs against a stub
context to assert *what gets registered* (`tools.guard` vs `tools/pre-execute`),
what the registered check answers, that a host without the API fails loudly
instead of silently, and that config typos surface as warnings.

`npm run check` also validates the bundle manifest, the dsh-plugin.org listing
requirements, and uses `npm pack --dry-run` to assert the exact publishable file
set. Under a sandbox that blocks piped child processes, two steps fail for
reasons unrelated to this package: `npm test` (Node's test runner spawns one
process per file) and `npm run verify:package` (it runs `npm pack` as a child).
Use `npm run test:no-isolation`, which runs the same files in a single process,
and run the verification scripts individually — only `verify:package` needs the
wider permission.

## 9. What the published artifact contains, and what it does not

`files[]` ships `lib`, `cordis.patch.yml`, `docs`, `examples`, `CHANGELOG.md`,
and `SECURITY.md`; npm adds `package.json`, `README.md`, and `LICENSE`. `test/`,
`scripts/`, and `.github/` stay out, and `scripts/check-package.mjs` fails the
build if any of them appears. The audit also still rejects `.npm-cache/`, which
nothing writes any more — it is a regression guard, not a description of the
current tree.

`npm pack` needs a cache, and `check-package.mjs` points it at the OS temp
directory rather than the working tree, so running the release checks leaves the
checkout exactly as it found it and never touches the user's real npm cache.

That means the published manifest still names `verify`, `test`, and
`prepublishOnly` scripts whose files are not in the artifact, so `npm run check`
inside an extracted tarball cannot work. That is deliberate: those scripts audit
the source checkout, `prepublishOnly` only ever runs from it, and shipping the
test corpus would put files in the artifact that no consumer executes. The
artifact audit is the contract; this is the trade it makes.
