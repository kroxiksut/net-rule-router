import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeConnection } from '../src/native-connection.js';

function harness() {
  const listeners = {};
  let calls = 0;
  let sent;
  const port = {
    onMessage: { addListener: handler => { listeners.message = handler; } },
    onDisconnect: { addListener: handler => { listeners.disconnect = handler; } },
    postMessage: message => { sent = message; },
    disconnect: () => { listeners.disconnect?.(); },
  };
  const api = { runtime: { connectNative: () => { calls += 1; return port; } } };
  return { connection: createNativeConnection(api), listeners, get calls() { return calls; }, get sent() { return sent; } };
}

test('opening the extension never launches the native host without a request', () => {
  const h = harness();
  assert.equal(h.connection.status(), 'disconnected');
  assert.equal(h.calls, 0);
});

test('an unexpected native reply never appears as an established connection', async () => {
  const h = harness();
  const result = h.connection.connect();
  h.listeners.message({ type: 'hello', protocol: 1, requestId: 'wrong', product: 'NetRuleRouter', service: 'unknown' });
  assert.equal(await result, 'incompatible');
  assert.equal(h.connection.status(), 'incompatible');
});

test('a host response reports only an unverified host and losing it clears the status', async () => {
  const h = harness();
  const result = h.connection.connect();
  h.listeners.message({ type: 'hello', protocol: 1, requestId: h.sent.requestId, product: 'NetRuleRouter', service: 'unknown' });
  assert.equal(await result, 'host-responded-unverified');
  h.listeners.disconnect();
  assert.equal(h.connection.status(), 'unavailable');
});
