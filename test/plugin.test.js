/**
 * Plugin-level tests against a stub context: they prove what gets registered on
 * the tool-call path and what the registered check answers, without needing a
 * harness build. The real integration (a booted profile refusing a real call) is
 * documented in the README as the manual end-to-end check.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { apply, name, normalizeConfig } from '../lib/index.js';

const INCIDENT = 'Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue';
const SAFE = 'Stop-Process -Id 42';

/** Minimal stand-in for the plugin context. */
function stubContext({ withGuard = true, withWaterfall = true, withSystemPrompt = false } = {}) {
  const guards = [];
  const listeners = [];
  const sections = [];
  const logs = [];
  const systemPrompt = {
    section: (section) => {
      sections.push(section);
    },
    getSectionOrder: () => 50
  };
  const ctx = {
    logger: {
      info: (message) => logs.push(['info', message]),
      warn: (message) => logs.push(['warn', message]),
      error: (message) => logs.push(['error', message])
    },
    get: (service) => (service === 'systemPrompt' && withSystemPrompt ? systemPrompt : undefined),
    tools: withGuard
      ? {
          guard: (check) => {
            guards.push(check);
            return () => {};
          }
        }
      : {}
  };
  if (withWaterfall) {
    ctx.on = (event, handler) => {
      listeners.push({ event, handler });
      return () => {};
    };
  }
  return { ctx, guards, listeners, sections, logs };
}

const call = (command, toolName = 'pwsh') => ({ name: toolName, callId: 'call_1', arguments: { command } });

test('exports the bundle plugin surface', () => {
  assert.equal(name, 'process-guard');
});

test('deny mode registers exactly one guard and no waterfall listener', () => {
  const { ctx, guards, listeners } = stubContext();
  apply(ctx, undefined);
  assert.equal(guards.length, 1);
  assert.equal(listeners.length, 0);
});

test('the registered guard denies the incident command and allows safe ones', () => {
  const { ctx, guards } = stubContext();
  apply(ctx, {});
  const reason = guards[0](call(INCIDENT));
  assert.equal(typeof reason, 'string');
  assert.match(reason, /process-guard: blocked/);
  assert.match(reason, /chrome/);
  assert.equal(guards[0](call(SAFE)), undefined);
});

test('the guard ignores other tools, missing commands, and non-strings', () => {
  const { ctx, guards } = stubContext();
  apply(ctx, {});
  assert.equal(guards[0](call(INCIDENT, 'read')), undefined);
  assert.equal(guards[0]({ name: 'pwsh', arguments: {} }), undefined);
  assert.equal(guards[0]({ name: 'pwsh', arguments: { command: '   ' } }), undefined);
  assert.equal(guards[0]({ name: 'pwsh', arguments: { command: 42 } }), undefined);
  assert.equal(guards[0](undefined), undefined);
});

test('config.tools narrows the inspected tool set', () => {
  const { ctx, guards } = stubContext();
  apply(ctx, { tools: ['bash'] });
  assert.equal(guards[0](call(INCIDENT, 'pwsh')), undefined);
  assert.match(guards[0](call('killall chrome', 'bash')), /process-guard: blocked/);
});

test('ask mode registers a pre-execute listener that routes to approval', async () => {
  const { ctx, guards, listeners } = stubContext();
  apply(ctx, { mode: 'ask' });
  assert.equal(guards.length, 0);
  assert.equal(listeners.length, 1);
  assert.equal(listeners[0].event, 'tools/pre-execute');
  let nextCalled = false;
  const flagged = await listeners[0].handler(call(INCIDENT), () => {
    nextCalled = true;
    return { kind: 'allow' };
  });
  assert.equal(flagged.kind, 'ask');
  assert.match(flagged.reason, /process-guard: blocked/);
  assert.equal(nextCalled, false);
  const passed = await listeners[0].handler(call(SAFE), () => {
    nextCalled = true;
    return { kind: 'allow' };
  });
  assert.equal(passed.kind, 'allow');
  assert.equal(nextCalled, true);
});

test('announce adds a system-prompt section unless switched off', () => {
  const on = stubContext({ withSystemPrompt: true });
  apply(on.ctx, {});
  assert.equal(on.sections.length, 1);
  assert.equal(on.sections[0].name, 'process-guard');
  assert.match(on.sections[0].text, /image name/);
  const off = stubContext({ withSystemPrompt: true });
  apply(off.ctx, { announce: false });
  assert.equal(off.sections.length, 0);
});

test('a host without ctx.tools.guard() fails closed', () => {
  const { ctx } = stubContext({ withGuard: false });
  assert.throws(() => apply(ctx, {}), /ctx\.tools\.guard\(\) is unavailable/);
});

test('a host without ctx.on() fails closed in ask mode', () => {
  const { ctx } = stubContext({ withWaterfall: false });
  assert.throws(() => apply(ctx, { mode: 'ask' }), /ctx\.on\(\) is unavailable/);
});

test('enabled:false registers nothing', () => {
  const { ctx, guards, logs } = stubContext();
  apply(ctx, { enabled: false });
  assert.equal(guards.length, 0);
  assert.ok(logs.some(([level, message]) => level === 'info' && /disabled by config/.test(message)));
});

test('normalizeConfig warns instead of silently accepting typos', () => {
  const warnings = [];
  const config = normalizeConfig({ mode: 'block', tools: 'pwsh', protctedImages: ['chrome'] }, (message) => warnings.push(message));
  assert.equal(config.mode, 'deny');
  assert.ok(config.tools.includes('pwsh'));
  assert.ok(config.tools.includes('bash'));
  assert.ok(config.tools.includes('terminal'));
  assert.equal(warnings.length, 3, 'unknown key, non-array tools, invalid mode');
  assert.ok(warnings.some((message) => /unknown config key "protctedImages"/.test(message)));
  assert.ok(warnings.some((message) => /config.mode must be/.test(message)));
});

test('defaults protect the GUI browser and the harness server', () => {
  const config = normalizeConfig(undefined);
  assert.equal(config.enabled, true);
  assert.equal(config.mode, 'deny');
  assert.equal(config.safeFilterAllows, false);
  assert.ok(config.protectedImages.includes('chrome'));
  assert.ok(config.protectedImages.includes('node'));
});

test('config validates booleans and refuses empty safety lists', () => {
  const warnings = [];
  const config = normalizeConfig({
    enabled: 'false',
    announce: 0,
    safeFilterAllows: 'true',
    tools: [],
    protectedImages: ['', null]
  }, (message) => warnings.push(message));
  assert.equal(config.enabled, true);
  assert.equal(config.announce, true);
  assert.equal(config.safeFilterAllows, false);
  assert.ok(config.tools.length > 0);
  assert.ok(config.protectedImages.includes('chrome'));
  assert.ok(warnings.length >= 6);
});

test('additionalProtectedImages extends and normalizes the built-in list', () => {
  const config = normalizeConfig({ additionalProtectedImages: ['CustomBrowser.EXE', ' custombrowser '] });
  assert.ok(config.protectedImages.includes('chrome'));
  assert.equal(config.protectedImages.filter((image) => image === 'custombrowser').length, 1);
});

test('additionalTools extends the default inspected tool set', () => {
  const config = normalizeConfig({ additionalTools: ['remote_shell', 'remote_shell'] });
  assert.ok(config.tools.includes('pwsh'));
  assert.equal(config.tools.filter((tool) => tool === 'remote_shell').length, 1);
});
