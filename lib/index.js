/**
 * dsh-process-guard — a DeepSeek Harness bundle that refuses shell commands
 * terminating processes by image name, wildcard, process group, or unfiltered
 * enumeration.
 *
 * Registered on the tool-call path in one of two ways, never both:
 *
 * - `mode: 'deny'` (default) uses `ctx.tools.guard()`. Guards are monotonic —
 *   "no guard can force-allow a call another guard denied" — and they run
 *   before the tool body, so an approved sandbox escalation cannot launder the
 *   command. The model sees `Error: process-guard: blocked - …`.
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

import { DEFAULT_PROTECTED_IMAGES, DEFAULT_TOOLS, evaluateCommand, normalizeImage } from './matcher.js';

export const name = 'process-guard';

/** The tools service must exist before the guard can be registered. */
export const inject = ['tools'];

/** Config keys this plugin understands; anything else is reported, not ignored. */
const KNOWN_KEYS = new Set(['enabled', 'tools', 'additionalTools', 'protectedImages', 'additionalProtectedImages', 'mode', 'safeFilterAllows', 'announce']);

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
  const validObject = raw !== null && typeof raw === 'object' && !Array.isArray(raw);
  const input = validObject ? raw : {};
  if (raw !== undefined && !validObject) warn(`config must be an object, got ${Array.isArray(raw) ? 'array' : typeof raw}; using defaults`);
  for (const key of Object.keys(input)) if (!KNOWN_KEYS.has(key)) warn(`unknown config key "${key}" ignored (known keys: ${[...KNOWN_KEYS].join(', ')})`);

  const stringArray = (key, defaults, { allowEmpty = false, normalize = (value) => value } = {}) => {
    const value = input[key];
    if (value === undefined) return [...defaults];
    if (!Array.isArray(value)) {
      warn(`config.${key} must be an array of non-empty strings; using defaults`);
      return [...defaults];
    }
    const accepted = value
      .filter((entry) => typeof entry === 'string' && entry.trim().length > 0)
      .map((entry) => normalize(entry.trim()));
    if (accepted.length !== value.length) warn(`config.${key} contains non-string or empty entries; invalid entries were ignored`);
    const unique = [...new Set(accepted)];
    if (unique.length === 0 && !allowEmpty) {
      warn(`config.${key} must not be empty; using defaults`);
      return [...defaults];
    }
    return unique;
  };

  const booleanOption = (key, defaultValue) => {
    if (input[key] === undefined) return defaultValue;
    if (typeof input[key] === 'boolean') return input[key];
    warn(`config.${key} must be a boolean; using ${JSON.stringify(defaultValue)}`);
    return defaultValue;
  };

  const tools = stringArray('tools', DEFAULT_TOOLS);
  const additionalTools = stringArray('additionalTools', [], { allowEmpty: true });
  const protectedImages = stringArray('protectedImages', DEFAULT_PROTECTED_IMAGES, { normalize: normalizeImage });
  const additionalProtectedImages = stringArray('additionalProtectedImages', [], { allowEmpty: true, normalize: normalizeImage });
  if (input.mode !== undefined && input.mode !== 'deny' && input.mode !== 'ask') warn(`config.mode must be "deny" or "ask", got ${JSON.stringify(input.mode)}; using "deny"`);
  return {
    enabled: booleanOption('enabled', true),
    tools: [...new Set([...tools, ...additionalTools])],
    protectedImages: [...new Set([...protectedImages, ...additionalProtectedImages])],
    mode: input.mode === 'ask' ? 'ask' : 'deny',
    safeFilterAllows: booleanOption('safeFilterAllows', false),
    announce: booleanOption('announce', true)
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
    throw new Error('process-guard: ctx.tools.guard() is unavailable on this harness build (requires dsh >= 0.1.0-rc.6)');
  }
  if (effective.mode === 'ask' && !waterfallAvailable) {
    throw new Error('process-guard: ctx.on() is unavailable on this harness build');
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
    if (typeof systemPrompt?.section === 'function' && typeof systemPrompt.getSectionOrder === 'function') {
      try {
        const order = systemPrompt.getSectionOrder('TOOL_PWSH');
        systemPrompt.section({ name: 'process-guard', text: SECTION_TEXT, order });
      } catch (error) {
        logger?.warn?.(`process-guard: system-prompt announcement skipped: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const images = effective.protectedImages.join(', ');
  logger?.info?.(`process-guard: ${effective.mode} mode on [${effective.tools.join(', ')}]; protected images: ${images}`);
}
