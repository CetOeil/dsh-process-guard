# AGENTS.md snippet — the rule as prose

For users who prefer instructions over a plugin, or who want both layers. Append
the block below to your user-global `~/.dsh/AGENTS.md` (loaded for every session
in every workspace) or to a project's `AGENTS.md`.

Prose shapes intent; it cannot stop a command. The plugin in this repository is
the enforced layer — see the README.

```markdown
## Never terminate processes by image name

The DSH Web GUI is a **browser client** (`http://127.0.0.1:3080`, opened in Chrome or Edge), and the
harness server runs as `node`. Killing processes by image name therefore kills the harness's own host
processes: the GUI window disappears, the session's client connection drops, and the turn is recorded
as `interrupted` with a tool result of "outcome unknown".

Never run these forms:

- `Get-Process chrome,msedge -ErrorAction SilentlyContinue | Stop-Process -Force`
- `Stop-Process -Name <image>` (including its `spps` / `kill` aliases) — for browsers such as `chrome`, `msedge`, `firefox`, `chromium`, `google-chrome`, `brave`, `vivaldi`, `opera`, and `msedgewebview2`
- `taskkill /IM chrome.exe /F`, `wmic process where "name='chrome.exe'" delete`, `pskill chrome`, `pkill chrome`, or `killall chrome`
- the same shape against `node`, `pwsh`, `powershell`, `conhost`, `WindowsTerminal` — `node` is the
  harness server itself, and the terminal hosts may be the harness's own window
- an unfiltered `Get-Process | Stop-Process -Force`
- wildcard or process-group forms such as `Stop-Process -Name '*'`, `taskkill /IM *`, or `kill -9 0`

Use these instead:

- Kill only processes you started: `$p = Start-Process ... -PassThru; if (-not $p.WaitForExit(25000)) { $p.Kill() }`
- Kill by explicit PID only: `Stop-Process -Id 1234`
- If a cleanup would match a browser, terminal, or `node` process you did not start, do not run it —
  ask the user instead. An image-name kill is never the only way to do the job.

## Headless browser verification

- Always pass a dedicated `--user-data-dir` so your headless instance is distinguishable from the
  user's browser.
- Clean up by PID from `-PassThru`, never by image name.
- Under the confined sandbox, a headless browser needs named-pipe access that the sandbox blocks, so
  `sandbox_permissions: danger-full-access` is legitimate here. That escalation is for the named-pipe
  access — it is not permission to kill browsers.
```
