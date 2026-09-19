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
time. Config is normalized in-process instead, with a warning per unknown or
mistyped key, which recovers the practical benefit (typos are visible) without
the coupling. Adopting a schema later is a small, self-contained change.

## 5. The matcher, and why it needs two views of the text

A single regex over the raw command cannot work in both directions: `Write-Output
"Stop-Process -Name chrome"` must not be treated as a kill, while `Stop-Process
-Name "chrome"` must be. So the matcher masks the command twice, preserving every
offset and newline:

| View | Blanked | Used for | Rationale |
|---|---|---|---|
| `noStrings` | quoted literals + comments | **verbs** | a verb inside a string is text, not an invocation |
| `noComments` | comments only | **targets, filters, selectors** | a quoted target and a quoted `'*--headless*'` filter are both real |

Comments are removed from both, so `Stop-Process -Id 5 # chrome` is not a
protected-image kill. Segmentation (newline, `;`, `&&`, `||`) is computed from
`noStrings`, where separators inside literals have already been blanked, and the
resulting offsets are applied to both views and to the raw text. Pipelines stay
whole, because `Get-Process chrome | Stop-Process` must be read as one unit.

## 6. Rule precedence

1. `indirect-execution` — a termination verb that is visible *only* inside a
   quoted literal, in the presence of `Invoke-Expression` / `iex` / `eval` /
   `cmd /c` / `bash|pwsh -c|-Command`.
2. `protected-image-kill` — a protected image named anywhere in the statement —
   unless the statement narrows with a filter that mentions `--headless` or
   `--user-data-dir`, which is the documented safe pattern (`safeFilterAllows`).
3. `blanket-wildcard` / `blanket-enumeration` — a kill verb applied to `-Name *`,
   `/IM *`, or an enumeration cmdlet with no PID selector.
4. Otherwise `allow`, with the reason recorded as `explicit-pid`,
   `handle-or-unprotected`, `safe-scoped-filter`, or `no-match`.

`mode` only relabels a flag (`deny` → `ask`); it never converts a flag into an
allow. That asymmetry is deliberate: a configuration mistake can make the plugin
more intrusive, never silently weaker.

## 7. Known bypasses

Documented rather than papered over — each would need host-level knowledge (the
real client PID, or a syscall boundary) that an out-of-tree plugin does not have:

- `powershell -EncodedCommand <base64>`, or any command assembled at runtime from
  fragments.
- A script written in one tool call and executed in the next: the guard sees two
  individually innocent commands.
- `Add-Type` / P/Invoke to call `TerminateProcess` directly.
- Image names absent from `protectedImages` (a renamed browser, a portable build).
- Tools other than the inspected `tools` list — an MCP process manager, a skill
  that shells out itself, or a future native process tool.

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

`npm test` uses the standard runner. Under a sandbox that blocks piped child
processes (Node's test runner spawns one per file), use
`npm run test:no-isolation`, which runs the same files in a single process.
