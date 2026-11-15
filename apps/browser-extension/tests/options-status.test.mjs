import assert from 'node:assert/strict';
import test from 'node:test';

test('an open settings page reports a lost host without overwriting an unsaved edit', async () => {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, {
      id, disabled: false, hidden: false, value: '', checked: false, dataset: {},
      setAttribute() {}, replaceChildren() {}, append() {}, focus() {}, scrollIntoView() {},
      querySelectorAll: () => [], addEventListener() {},
    });
    return nodes.get(id);
  }
  node('global-form').elements = { languageMode: node('global-mode'), language: node('global-language') };
  node('profile-form').elements = { host: node('site-host'), languageMode: node('site-mode'),
    language: node('site-language'), includeSubdomains: node('include-subdomains') };
  node('webrtc-form').elements = { acknowledge: node('acknowledge') };
  globalThis.document = {
    documentElement: { dataset: {} }, body: { dataset: { title: 'options_title' } }, hidden: false,
    getElementById: node, querySelector: () => node('main'), querySelectorAll: () => [], addEventListener() {},
  };
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  let timer;
  let interval;
  const originalSetInterval = globalThis.setInterval;
  globalThis.setInterval = (callback, delay) => { timer = callback; interval = delay; return 1; };
  globalThis.browser = {
    i18n: { getMessage: key => key, getUILanguage: () => 'en' },
    permissions: { request: async () => true },
    runtime: { sendMessage: async message => {
      if (message.type === 'getState') return { ok: true, integration: 'host-responded-unverified',
        state: { revision: 0, pending: false, global: { languageMode: 'system', language: 'en' },
          profiles: [], webRtc: { enabled: false, owned: false } }, capabilities: { webRtc: true } };
      if (message.type === 'getIntegration') return { ok: true, integration: 'unavailable' };
      throw new Error(`unexpected request: ${message.type}`);
    } },
  };
  try {
    await import('../src/ui/options.js');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(node('connection').textContent, 'connection_host_responded_unverified');
    node('global-language').value = 'unsaved input';
    assert.equal(typeof timer, 'function', 'the open page must refresh the host status');
    assert.equal(interval, 3000);
    await timer();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(node('connection').textContent, 'connection_unavailable');
    assert.equal(node('global-language').value, 'unsaved input');
  } finally {
    globalThis.setInterval = originalSetInterval;
    delete globalThis.browser;
    delete globalThis.document;
    delete globalThis.localStorage;
  }
});
