const HOST = 'netrulerouter';
const TIMEOUT_MS = 5000;

export function createNativeConnection(api) {
  let state = 'disconnected';
  let activePort = null;
  let settle = null;

  function close(next) {
    const port = activePort;
    activePort = null;
    state = next;
    if (settle) {
      const finish = settle;
      settle = null;
      finish(next);
    }
    if (port) {
      try { port.disconnect(); } catch { /* The browser may already have closed it. */ }
    }
  }

  async function connect() {
    if (state === 'connecting' || state === 'host-responded-unverified') return state;
    let port;
    try {
      port = api.runtime.connectNative(HOST);
    } catch {
      state = 'unavailable';
      return state;
    }
    activePort = port;
    state = 'connecting';
    const requestId = globalThis.crypto.randomUUID();
    return new Promise(resolve => {
      const timer = setTimeout(() => close('unavailable'), TIMEOUT_MS);
      settle = result => { clearTimeout(timer); resolve(result); };
      port.onDisconnect.addListener(() => {
        // Reading lastError suppresses Chromium's unchecked-disconnect warning.
        void api.runtime.lastError;
        if (activePort !== port) return;
        activePort = null;
        state = 'unavailable';
        if (settle) {
          const finish = settle;
          settle = null;
          finish(state);
        }
      });
      port.onMessage.addListener(message => {
        if (activePort !== port || state !== 'connecting') return;
        if (!message || message.type !== 'hello' || message.protocol !== 1
            || message.requestId !== requestId || message.product !== 'NetRuleRouter'
            || message.service !== 'unknown') {
          close('incompatible');
          return;
        }
        state = 'host-responded-unverified';
        const finish = settle;
        settle = null;
        finish(state);
      });
      try {
        port.postMessage({ type: 'hello', protocol: 1, requestId });
      } catch {
        close('unavailable');
      }
    });
  }

  return { connect, disconnect: () => close('disconnected'), status: () => state };
}
