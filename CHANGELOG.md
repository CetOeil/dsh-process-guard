# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-18

### Added

- `lib/matcher.js`: dependency-free command matcher that flags termination of
  processes selected by image name (or by an unfiltered process enumeration),
  while allowing explicit-PID kills, `-PassThru` handle kills, and filters that
  narrow to a headless instance or a dedicated `--user-data-dir`.
- `lib/index.js`: DeepSeek Harness bundle plugin registering the matcher on the
  tool-call path — through `ctx.tools.guard()` in `deny` mode (monotonic, cannot
  be force-allowed) or `ctx.on('tools/pre-execute')` in `ask` mode — plus an
  optional `systemPrompt` section that states the rule before a call is made.
- `cordis.patch.yml`: the bundle layer that mounts the plugin into a profile.
- Tests covering the matcher corpus (including the real command that caused the
  original incident) and plugin registration against a stub context.
- Documentation: `README.md`, `docs/DESIGN.md`, `docs/agents-md-snippet.md`, and
  `examples/override.cordis.patch.yml`.

[Unreleased]: https://github.com/OWNER/dsh-process-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/dsh-process-guard/releases/tag/v0.1.0
