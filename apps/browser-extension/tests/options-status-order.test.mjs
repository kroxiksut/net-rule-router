import assert from 'node:assert/strict';
import test from 'node:test';

test('a delayed older status cannot overwrite a newer unavailable state', async () => {
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
  const originalSetInterval = globalThis.setInterval;
  globalThis.setInterval = callback => { timer = callback; return 1; };
  const replies = [];
  globalThis.browser = {
    i18n: { getMessage: key => key, getUILanguage: () => 'en' },
    permissions: { request: async () => true },
    runtime: { sendMessage: message => {
      if (message.type === 'getState') return Promise.resolve({ ok: true, integration: 'disconnected',
        state: { revision: 0, pending: false, global: { languageMode: 'system', language: 'en' },
          profiles: [], webRtc: { enabled: false, owned: false } }, capabilities: { webRtc: true } });
      if (message.type === 'getIntegration') return new Promise(resolve => replies.push(resolve));
      throw new Error(`unexpected request: ${message.type}`);
    } },
  };
  try {
    await import('../src/ui/options.js');
    await new Promise(resolve => setImmediate(resolve));
    node('global-language').value = 'unsaved input';
    assert.equal(typeof timer, 'function');
    const older = timer();
    const newer = timer();
    assert.equal(replies.length, 2);
    replies[1]({ ok: true, integration: 'unavailable' });
    await newer;
    assert.equal(node('connection').textContent, 'connection_unavailable');
    replies[0]({ ok: true, integration: 'host-responded-unverified' });
    await older;
    assert.equal(node('connection').textContent, 'connection_unavailable');
    assert.equal(node('global-language').value, 'unsaved input');
  } finally {
    globalThis.setInterval = originalSetInterval;
    delete globalThis.browser;
    delete globalThis.document;
    delete globalThis.localStorage;
  }
});
