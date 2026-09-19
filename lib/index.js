/**
 * dsh-process-guard — a DeepSeek Harness bundle that refuses shell commands
 * terminating processes by image name.
 *
 * Registered on the tool-call path in one of two ways, never both:
 *
 * - `mode: 'deny'` (default) uses `ctx.tools.guard()`. Guards are monotonic —
 *   "no guard can force-allow a call another guard denied" — and they run
 *   before the tool body, so an approved sandbox escalation cannot launder the
 *   command. The model sees `Error: process-guard: blocked — …`.
 * - `mode: 'ask'` uses `ctx.on('tools/pre-execute')` and returns
 *   `{ kind: 'ask', reason }`, routing the decision to the approval service so
 *   the user decides with the consequence spelled out.
 *
 * The plugin has no runtime dependencies: it never imports a host package, so it
 * keeps working across `@deepseek-ai/dsh-*` version drift. Config is validated
 * and defaulted in-process instead of through a schema export.
 *
 * @module dsh-process-guard
 */

import { DEFAULT_PROTECTED_IMAGES, DEFAULT_TOOLS, evaluateCommand } from './matcher.js';

export const name = 'process-guard';

/** The tools service must exist before the guard can be registered. */
export const inject = ['tools'];

/** Config keys this plugin understands; anything else is reported, not ignored. */
const KNOWN_KEYS = new Set(['enabled', 'tools', 'protectedImages', 'mode', 'safeFilterAllows', 'announce']);

const SECTION_TEXT = [
  'Process guard: commands that terminate processes by image name are refused before they run',
  '(`Stop-Process -Name chrome`, `taskkill /IM msedge.exe`, `killall`, an unfiltered `Get-Process | Stop-Process`).',
  'The DSH Web GUI is a browser client on 127.0.0.1:3080 and the harness server is `node`, so a blanket kill',
  'closes the GUI window and drops the session. Kill only processes you started',
  '(`Start-Process ... -PassThru`, then `$p.WaitForExit(...)` and `$p.Kill()`), or target explicit PIDs with `-Id`.',
  'A refusal is a policy decision you may report to the user; do not look for a way around it.'
].join(' ');

/**
 * Normalize user config, collecting a warning per questionable key.
 *
 * @param raw - the `config:` object from the plugin row (or undefined).
 * @param warn - sink for human-readable warnings.
 * @returns the effective configuration.
 */
export function normalizeConfig(raw, warn = () => {}) {
  const input = raw === null || typeof raw !== 'object' ? {} : raw;
  if (raw !== undefined && (raw === null || typeof raw !== 'object')) warn(`config must be an object, got ${typeof raw}; using defaults`);
  for (const key of Object.keys(input)) if (!KNOWN_KEYS.has(key)) warn(`unknown config key "${key}" ignored (known keys: ${[...KNOWN_KEYS].join(', ')})`);
  const tools = Array.isArray(input.tools) ? input.tools.filter((tool) => typeof tool === 'string' && tool.length > 0) : [...DEFAULT_TOOLS];
  if (input.tools !== undefined && !Array.isArray(input.tools)) warn('config.tools must be an array of tool names; using defaults');
  const protectedImages = Array.isArray(input.protectedImages)
    ? input.protectedImages.filter((image) => typeof image === 'string' && image.length > 0)
    : [...DEFAULT_PROTECTED_IMAGES];
  if (input.protectedImages !== undefined && !Array.isArray(input.protectedImages)) warn('config.protectedImages must be an array of image names; using defaults');
  if (input.mode !== undefined && input.mode !== 'deny' && input.mode !== 'ask') warn(`config.mode must be "deny" or "ask", got ${JSON.stringify(input.mode)}; using "deny"`);
  return {
    enabled: input.enabled !== false,
    tools,
    protectedImages,
    mode: input.mode === 'ask' ? 'ask' : 'deny',
    safeFilterAllows: input.safeFilterAllows !== false,
    announce: input.announce !== false
  };
}

/**
 * Decide one tool call.
 *
 * @param exec - the tool execution record (`name`, `arguments`).
 * @param config - the normalized configuration.
 * @returns the denial reason, or undefined to let the call proceed.
 */
function inspectCall(exec, config) {
  if (exec === null || typeof exec !== 'object') return undefined;
  if (!config.tools.includes(exec.name)) return undefined;
  const command = exec.arguments?.command;
  if (typeof command !== 'string' || command.trim().length === 0) return undefined;
  const verdict = evaluateCommand(command, config);
  return verdict.kind === 'allow' ? undefined : verdict.reason;
}

/**
 * Mount the guard and, optionally, the prompt-side rule.
 *
 * @param ctx - the plugin context; `tools` is guaranteed by `inject`.
 * @param config - raw `config:` object from the plugin row.
 */
export function apply(ctx, config) {
  const logger = ctx.logger;
  const effective = normalizeConfig(config, (message) => logger?.warn?.(`process-guard: ${message}`));

  if (!effective.enabled) {
    logger?.info?.('process-guard: disabled by config — commands are not inspected');
    return;
  }

  const guardAvailable = typeof ctx.tools?.guard === 'function';
  const waterfallAvailable = typeof ctx.on === 'function';
  if (effective.mode === 'deny' && !guardAvailable) {
    logger?.error?.('process-guard: ctx.tools.guard() is unavailable on this harness build — the guard is INACTIVE (requires dsh >= 0.1.0-rc.6)');
    return;
  }
  if (effective.mode === 'ask' && !waterfallAvailable) {
    logger?.error?.('process-guard: ctx.on() is unavailable on this harness build — the guard is INACTIVE');
    return;
  }

  if (effective.mode === 'deny') {
    ctx.tools.guard((exec) => inspectCall(exec, effective));
  } else {
    ctx.on('tools/pre-execute', async (exec, next) => {
      const reason = inspectCall(exec, effective);
      return reason === undefined ? next() : { kind: 'ask', reason };
    });
  }

  if (effective.announce) {
    const systemPrompt = ctx.get?.('systemPrompt');
    if (typeof systemPrompt?.section === 'function') {
      let order;
      try {
        order = systemPrompt.getSectionOrder?.('TOOL_PWSH');
      } catch {
        order = undefined;
      }
      systemPrompt.section({ name: 'process-guard', text: SECTION_TEXT, ...(order === undefined ? {} : { order }) });
    }
  }

  const images = effective.protectedImages.join(', ');
  logger?.info?.(`process-guard: ${effective.mode} mode on [${effective.tools.join(', ')}]; protected images: ${images}`);
}
