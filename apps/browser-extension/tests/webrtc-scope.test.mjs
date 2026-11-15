import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('WebRTC scope describes the requested setting without promising browser-wide traffic effects', async () => {
  const expectations = {
    en: { requested: /request.{0,80}(?:entire|whole).{0,30}browser profile/iu, incognito: /incognito/iu, overclaim: /this change affects every website/iu },
    ru: { requested: /запрашива.{0,80}всего профиля браузера/iu, incognito: /инкогнито/iu, overclaim: /изменение затронет все сайты/iu },
  };
  const originalBrowser = globalThis.browser;
  try {
    for (const [locale, expected] of Object.entries(expectations)) {
      const catalog = JSON.parse(await readFile(new URL(`../src/_locales/${locale}/messages.json`, import.meta.url), 'utf8'));
      globalThis.browser = { i18n: { getMessage: key => catalog[key]?.message || '' } };
      const { tr } = await import(`../src/ui/common.js?scope-${locale}`);
      const text = tr('webrtc_scope');
      assert.match(text, expected.requested, `${locale} must describe the scope as a requested browser setting`);
      assert.match(text, expected.incognito, `${locale} must mention possible incognito inheritance`);
      assert.doesNotMatch(text, expected.overclaim, `${locale} must not assert an effect on all sites`);
    }
  } finally {
    globalThis.browser = originalBrowser;
  }
});
