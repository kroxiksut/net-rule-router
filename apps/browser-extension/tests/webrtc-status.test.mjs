import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('browser setting readback never claims that WebRTC traffic was verified', async () => {
  const expectations = {
    en: { setting: /(?:browser.{0,45}setting|setting.{0,45}browser)/iu, unverified: /not (?:been )?verified/iu, overclaim: /non.proxied UDP (?:is )?restricted/iu },
    ru: { setting: /(?:браузер.{0,45}настро|настро.{0,45}браузер)/iu, unverified: /не проверен/iu, overclaim: /непроксируем.{0,20}UDP ограничен/iu },
  };
  const originalBrowser = globalThis.browser;
  const originalDocument = globalThis.document;
  try {
    for (const [locale, expected] of Object.entries(expectations)) {
      const catalog = JSON.parse(await readFile(new URL(`../src/_locales/${locale}/messages.json`, import.meta.url), 'utf8'));
      const elements = { 'webrtc-state': { dataset: {} }, notice: { dataset: {}, hidden: true } };
      globalThis.browser = { i18n: { getMessage: key => catalog[key]?.message || '' } };
      globalThis.document = { getElementById: id => elements[id] };
      const { renderWebRtc, setNotice } = await import(`../src/ui/common.js?${locale}`);
      renderWebRtc({ state: { webRtc: { enabled: true, owned: true } }, capabilities: { webRtc: true } });
      setNotice('webrtc_saved', 'success');
      for (const [surface, element] of Object.entries(elements)) {
        assert.match(element.textContent, expected.setting, `${locale} ${surface} must identify the browser setting`);
        assert.match(element.textContent, expected.unverified, `${locale} ${surface} must say the network result is unverified`);
        assert.doesNotMatch(element.textContent, expected.overclaim, `${locale} ${surface} must not assert UDP behavior`);
      }
    }
  } finally {
    globalThis.browser = originalBrowser;
    globalThis.document = originalDocument;
  }
});
