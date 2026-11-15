import assert from 'node:assert/strict';
import test from 'node:test';

test('disconnect while the native permission prompt is open cancels the pending connection', async () => {
  const nodes = new Map();
  const listeners = new Map();
  function node(id) {
    if (!nodes.has(id)) {
      const element = {
        id, disabled: false, hidden: false, value: '', checked: false, dataset: {},
        setAttribute() {}, replaceChildren() {}, append() {}, focus() {}, scrollIntoView() {},
        querySelectorAll() { return []; },
        addEventListener(type, callback) { listeners.set(`${id}:${type}`, callback); },
      };
      nodes.set(id, element);
    }
    return nodes.get(id);
  }
  const globalForm = node('global-form');
  globalForm.elements = { languageMode: node('global-mode'), language: node('global-language') };
  const profileForm = node('profile-form');
  profileForm.elements = { host: node('site-host'), languageMode: node('site-mode'),
    language: node('site-language'), includeSubdomains: node('include-subdomains') };
  node('webrtc-form').elements = { acknowledge: node('acknowledge') };
  globalThis.document = {
    documentElement: { dataset: {} }, body: { dataset: { title: 'options_title' } }, hidden: false,
    getElementById: node, querySelector: () => node('main'), querySelectorAll: () => [],
    addEventListener(type, callback) { listeners.set(`document:${type}`, callback); },
  };
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  const originalSetInterval = globalThis.setInterval;
  globalThis.setInterval = () => 1;
  const calls = [];
  let grantPermission;
  const permission = new Promise(resolve => { grantPermission = resolve; });
  globalThis.browser = {
    i18n: { getMessage: key => key, getUILanguage: () => 'en' },
    permissions: { request: () => permission },
    runtime: { sendMessage: async message => {
      calls.push(message.type);
      if (message.type === 'getState') return { ok: true, integration: 'disconnected',
        state: { revision: 0, pending: false, global: { languageMode: 'system', language: 'en' },
          profiles: [], webRtc: { enabled: false, owned: false } }, capabilities: { webRtc: true } };
      return { ok: true, integration: 'disconnected' };
    } },
  };
  try {
    await import('../src/ui/options.js');
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(listeners.has('connect-nrr:click'));
    globalForm.elements.language.value = 'unsaved input';
    const connecting = listeners.get('connect-nrr:click')({ currentTarget: node('connect-nrr') });
    await listeners.get('disconnect-nrr:click')();
    grantPermission(true);
    await connecting;
    assert.equal(globalForm.elements.language.value, 'unsaved input');
    assert.ok(calls.includes('disconnectNrr'));
    assert.ok(!calls.includes('connectNrr'), 'a cancelled permission prompt must not start the native host');
  } finally {
    globalThis.setInterval = originalSetInterval;
    delete globalThis.browser;
    delete globalThis.document;
    delete globalThis.localStorage;
  }
});
