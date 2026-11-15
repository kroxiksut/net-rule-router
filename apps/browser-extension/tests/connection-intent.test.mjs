import assert from 'node:assert/strict';
import test from 'node:test';
import { createController } from '../src/controller.js';

test('disconnect in another window invalidates a pending permission prompt', async () => {
  let starts = 0;
  let stops = 0;
  const api = {
    runtime: { id: 'test-extension', getURL: path => `moz-extension://test-extension/${path}` },
    permissions: { contains: async () => true },
    storage: { local: { get: async () => ({}) } },
  };
  const connection = {
    connect: async () => { starts += 1; },
    disconnect: () => { stops += 1; },
    status: () => 'disconnected',
  };
  const controller = createController(api, () => 1, { webRtc: true }, connection);
  const windowA = { id: 'test-extension', url: 'moz-extension://test-extension/ui/options.html', tab: { id: 1 } };
  const windowB = { id: 'test-extension', url: 'moz-extension://test-extension/ui/options.html', tab: { id: 2 } };

  const pending = await controller.handle({ type: 'beginConnectNrr', confirmed: true }, windowA);
  assert.equal(typeof pending.intent, 'string');
  assert.match(pending.intent, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
  await controller.handle({ type: 'disconnectNrr', confirmed: true }, windowB);
  try {
    await controller.handle({ type: 'connectNrr', confirmed: true, intent: pending.intent }, windowA);
  } catch (error) {
    assert.match(error.message, /cancel|conflict/u);
  }

  assert.equal(stops, 1);
  assert.equal(starts, 0, 'a stale permission result must not start the host');
});
