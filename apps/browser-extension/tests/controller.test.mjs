import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createController, emptyState, buildLanguageRules, normalizeHost } from '../src/controller.js';

const resolveMode = (site, global, consent, route, capability) => {
  if (!capability) return 6;
  if ((site || global) !== 1 && !consent) return 4;
  if ((site || global) === 3 && !route) return 5;
  return site || global;
};

function harness(stored = undefined, overrides = {}) {
  const calls = [];
  let current = stored === undefined ? {} : { profilesV1: structuredClone(stored) };
  const api = {
    runtime: {
      id: 'test-extension',
      getURL: path => `moz-extension://test-extension/${path}`,
    },
    storage: { local: {
      get: async key => { calls.push(['storage.get', key]); return structuredClone(current); },
      set: async value => { calls.push(['storage.set', structuredClone(value)]); current = structuredClone(value); },
    } },
    permissions: { contains: async () => true },
    declarativeNetRequest: {
      getDynamicRules: async () => { calls.push(['rules.get']); return []; },
      updateDynamicRules: async change => { calls.push(['rules.update', change]); },
    },
    ...overrides,
  };
  return {
    controller: createController(api, resolveMode), calls,
    readStored: () => structuredClone(current.profilesV1),
    sender: { id: 'test-extension', url: 'moz-extension://test-extension/ui/popup.html' },
  };
}

const getState = { type: 'getState' };
const saveProfile = (baseRevision = 0) => ({
  type: 'saveProfile', baseRevision, confirmed: true,
  profile: { host: 'example.com', includeSubdomains: false, languageMode: 'manual', language: 'fr' },
});

test('reading on first open never writes storage or touches browser rules', async () => {
  const h = harness();
  const result = await h.controller.handle(getState, h.sender);

  assert.equal(result.ok, true);
  assert.deepEqual(result.state, emptyState());
  assert.deepEqual(h.calls, [['storage.get', 'profilesV1']]);
});

test('a stale revision cannot change persisted state or browser settings', async () => {
  const state = emptyState();
  state.revision = 8;
  const h = harness(state);

  await assert.rejects(h.controller.handle(saveProfile(7), h.sender), /conflict/);
  assert.deepEqual(h.readStored(), state);
  assert.deepEqual(h.calls, [['storage.get', 'profilesV1']]);
});

test('declined host access leaves the requested revision and dynamic rules untouched', async () => {
  const h = harness(undefined, { permissions: { contains: async () => false } });

  await assert.rejects(h.controller.handle(saveProfile(), h.sender), /permission_required/);
  assert.equal(h.readStored(), undefined);
  assert.deepEqual(h.calls, [['storage.get', 'profilesV1']]);
});

test('malformed persisted state fails closed without repair writes', async () => {
  const h = harness({ ...emptyState(), profiles: Array.from({ length: 101 }, () => ({})) });

  await assert.rejects(h.controller.handle(getState, h.sender), /storage_corrupt/);
  assert.deepEqual(h.calls, [['storage.get', 'profilesV1']]);
});

test('an interrupted apply leaves a recoverable pending revision', async () => {
  const h = harness(undefined, { declarativeNetRequest: {
    getDynamicRules: async () => [],
    updateDynamicRules: async () => { throw new Error('browser rejected rules'); },
  } });

  await assert.rejects(h.controller.handle(saveProfile(), h.sender), /apply_failed/);
  assert.equal(h.readStored().revision, 1);
  assert.equal(h.readStored().pending, true);
});

test('an untrusted sender cannot even read extension state', async () => {
  const h = harness();
  const attacker = { ...h.sender, url: 'https://attacker.example/' };

  await assert.rejects(h.controller.handle(getState, attacker), /untrusted_sender/);
  assert.deepEqual(h.calls, []);
});

test('the exact extension options page remains trusted when opened in a tab', async () => {
  const h = harness();
  const optionsSender = {
    id: h.sender.id,
    url: 'moz-extension://test-extension/ui/options.html',
    tab: { id: 17 },
  };

  assert.equal((await h.controller.handle(getState, optionsSender)).ok, true);
});

test('host normalization rejects URL syntax and non-host input', () => {
  assert.equal(normalizeHost('Example.COM.'), 'example.com');
  for (const value of ['https://example.com', 'user@example.com', 'a..b', '-bad.example', 'a/b']) {
    assert.throws(() => normalizeHost(value), /invalid_host/);
  }
});

test('manual language rules are scoped to the configured hostname', () => {
  const state = emptyState();
  state.global = { languageMode: 'system', language: 'en' };
  state.profiles = [{ host: 'example.com', includeSubdomains: true, languageMode: 'manual', language: 'fr' }];

  const rules = buildLanguageRules(state, resolveMode);
  assert.equal(rules.length, 1);
  assert.match(rules[0].condition.regexFilter, /\(\?:\[a-z0-9-\]\+\\\.\)\*example\\\.com/);
  assert.equal(rules[0].action.requestHeaders[0].value, 'fr');
});

test('host matching accepts a trailing dot and explicit port without matching lookalikes', () => {
  const state = emptyState();
  state.profiles = [{ host: 'example.com', includeSubdomains: false, languageMode: 'manual', language: 'fr' }];
  const rule = buildLanguageRules(state, resolveMode)[0];
  const matches = new RegExp(rule.condition.regexFilter);

  for (const url of ['https://example.com/', 'https://example.com./', 'https://example.com:443/']) {
    assert.match(url, matches);
  }
  for (const url of ['https://example.com.evil/', 'https://notexample.com/']) {
    assert.doesNotMatch(url, matches);
  }
  assert.ok(rule.condition.resourceTypes.includes('main_frame'));
});

test('an empty inactive language field does not block a system-mode site profile', async () => {
  const h = harness();
  const message = {
    type: 'saveProfile', baseRevision: 0, confirmed: true,
    profile: { host: 'example.com', includeSubdomains: false, languageMode: 'system', language: '' },
  };

  assert.deepEqual(await h.controller.handle(message, h.sender), { ok: true });
});

test('saving a site profile does not rewrite an already-owned WebRTC setting', async () => {
  const state = emptyState();
  state.webRtc = { owned: true, enabled: true };
  const writes = [];
  const setting = {
    get: async () => ({ value: 'disable_non_proxied_udp', levelOfControl: 'controlled_by_this_extension' }),
    set: async value => writes.push(['set', value]),
    clear: async value => writes.push(['clear', value]),
  };
  const h = harness(state, { privacy: { network: { webRTCIPHandlingPolicy: setting } } });

  await h.controller.handle(saveProfile(0), h.sender);
  assert.deepEqual(writes, []);
});

test('releasing WebRTC never clears a value changed by another controller', async () => {
  const state = emptyState();
  state.webRtc = { owned: true, enabled: false };
  state.pending = true;
  state.pendingWebRtc = true;
  const writes = [];
  const setting = {
    get: async () => ({ value: 'default_public_interface_only', levelOfControl: 'controllable_by_this_extension' }),
    set: async value => writes.push(['set', value]),
    clear: async value => writes.push(['clear', value]),
  };
  const h = harness(state, { privacy: { network: { webRTCIPHandlingPolicy: setting } } });

  await h.controller.recover();
  assert.deepEqual(writes, []);
  assert.equal(h.readStored().webRtc.owned, false);
});

test('a failed pending recovery leaves read-only settings access usable', async () => {
  const state = emptyState();
  state.pending = true;
  state.pendingWebRtc = true;
  state.webRtc.enabled = true;
  const h = harness(state, { permissions: { contains: async () => false } });

  await assert.rejects(h.controller.recover(), /permission_required/);
  const result = await h.controller.handle(getState, h.sender);
  assert.equal(result.ok, true);
  assert.equal(result.state.pending, true);
});

test('restoring WebRTC works while revoked host access blocks a separate language retry', async () => {
  const state = emptyState();
  state.global = { languageMode: 'manual', language: 'fr' };
  state.webRtc = { owned: true, enabled: true };
  state.pending = true;
  state.pendingLanguage = true;
  const writes = [];
  const h = harness(state, {
    permissions: { contains: async ({ origins }) => !origins },
    privacy: { network: { webRTCIPHandlingPolicy: {
      get: async () => ({ value: 'disable_non_proxied_udp', levelOfControl: 'controlled_by_this_extension' }),
      set: async value => writes.push(['set', value]),
      clear: async value => writes.push(['clear', value]),
    } } },
  });

  await h.controller.handle({ type: 'setWebRtc', baseRevision: 0, confirmed: true, enabled: false }, h.sender);
  assert.deepEqual(writes, [['clear', { scope: 'regular' }]]);
  assert.equal(h.readStored().pendingLanguage, true);
});

test('English and Russian catalogs contain every static UI translation key', async () => {
  const root = new URL('../src/', import.meta.url);
  const [english, russian] = await Promise.all(['en', 'ru'].map(async locale => JSON.parse(
    await readFile(new URL(`_locales/${locale}/messages.json`, root), 'utf8'),
  )));
  assert.deepEqual(Object.keys(russian).sort(), Object.keys(english).sort());

  const files = await readdir(new URL('ui/', root));
  const sources = await Promise.all(files
    .filter(name => name.endsWith('.js') || name.endsWith('.html'))
    .map(name => readFile(new URL(`ui/${name}`, root), 'utf8')));
  const keys = new Set();
  for (const source of sources) {
    for (const match of source.matchAll(/\btr\(\s*['"]([^'"]+)['"]/gu)) keys.add(match[1]);
    for (const match of source.matchAll(/\bdata-i18n=['"]([^'"]+)['"]/gu)) keys.add(match[1]);
    for (const match of source.matchAll(/\bdata-title=['"]([^'"]+)['"]/gu)) keys.add(match[1]);
  }
  for (const key of keys) assert.ok(english[key], `missing locale key: ${key}`);
});

test('the release WASM policy export is linked and drives the controller rules', async () => {
  const bytes = await readFile(new URL('../policy/target/wasm32-unknown-unknown/release/nrr_browser_policy.wasm', import.meta.url));
  const { instance } = await WebAssembly.instantiate(bytes);
  const resolve = instance.exports.resolve_mode;
  assert.equal(typeof resolve, 'function');
  assert.equal(resolve(2, 1, 0, 0, 1), 4);
  assert.equal(resolve(3, 1, 1, 0, 1), 5);
  assert.equal(resolve(2, 1, 1, 0, 1), 2);

  const state = emptyState();
  state.profiles = [{ host: 'example.com', includeSubdomains: false, languageMode: 'manual', language: 'fr' }];
  assert.equal(buildLanguageRules(state, resolve)[0].action.requestHeaders[0].value, 'fr');
});
