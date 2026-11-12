import { createController } from './controller.js';

const api = globalThis.browser || globalThis.chrome;
const controller = (async () => {
  const response = await fetch(api.runtime.getURL('policy.wasm'));
  const { instance } = await WebAssembly.instantiate(await response.arrayBuffer());
  // TODO: Add authenticated Native Messaging before exposing route profiles or synchronization.
  const result = createController(api, instance.exports.resolve_mode, {
    webRtc: !api.runtime.getURL('').startsWith('moz-extension:'),
  });
  if (api.storage.local.setAccessLevel) {
    await api.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  }
  // A failed recovery must leave settings accessible for an explicit repair.
  await result.recover().catch(() => {});
  return result;
})();

api.runtime.onMessage.addListener((message, sender, reply) => {
  controller.then(value => value.handle(message, sender))
    .then(reply, error => reply({ ok: false, error: error.message || 'apply_failed' }));
  return true;
});
