# Security

## What this plugin is not

`dsh-process-guard` is a **behavioral safety net, not a security boundary.** It is
a static heuristic over the text of a shell command. It cannot stop a caller that
is actively trying to evade it, and it is not a substitute for process isolation,
containerization, or the harness's own sandbox.

Do not rely on it to contain untrusted code. Do rely on it to stop the realistic
accident: an agent reaching for `Get-Process chrome | Stop-Process -Force` as
cleanup because the harness's own GUI happens to be a Chrome window.

`README.md` lists the known bypasses (generated or separately stored commands,
native process APIs, remote execution, renamed binaries, and uninspected tools).
Literal PowerShell `-EncodedCommand` values are decoded and inspected, and a
literal selector assigned to a variable is resolved. If you find a bypass that is
not listed, that is a documentation gap worth reporting.

## Reporting

Open a regular issue for a missing rule, a false positive, or a bypass that is
not already documented. There is no private disclosure channel for this project,
and bypasses are not secrets: publishing them is what keeps the "safety net, not
a boundary" framing honest.

False positives are the higher-priority class of report. A guard that refuses
legitimate work gets uninstalled, and an uninstalled guard protects nothing.
Please include the exact command, the expected verdict, and the observed
`process-guard: blocked - …` reason line.
