import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile, access } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = join(root, 'artifacts');
const extension = join(root, 'dist', 'chromium');
const executable = process.env.NRR_TEST_BROWSER;
if (!executable) throw new Error('Set NRR_TEST_BROWSER to the Chromium test executable.');
const deadline = Date.now() + 38_000;
const sockets = [];
const pause = milliseconds => new Promise(resolvePause => setTimeout(resolvePause, milliseconds));
const remaining = () => Math.max(1, deadline - Date.now());

async function poll(work, description) {
  while (Date.now() < deadline) {
    const result = await work();
    if (result) return result;
    await pause(100);
  }
  throw new Error(`Timed out: ${description}`);
}

async function connect(url) {
  const socket = new WebSocket(url);
  sockets.push(socket);
  const pending = new Map();
  let nextId = 1;
  await new Promise((resolveOpen, rejectOpen) => {
    const timer = setTimeout(() => rejectOpen(new Error('CDP connection timeout')), Math.min(5000, remaining()));
    socket.addEventListener('open', () => { clearTimeout(timer); resolveOpen(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); rejectOpen(new Error('CDP connection failed')); }, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) request.reject(new Error(JSON.stringify(message.error)));
    else request.resolve(message.result);
  });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error('CDP connection closed'));
    }
    pending.clear();
  });
  return (method, params = {}) => new Promise((resolveRequest, rejectRequest) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      rejectRequest(new Error(`CDP timeout: ${method}`));
    }, Math.min(8000, remaining()));
    pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

await access(executable);
await access(join(extension, 'manifest.json'));
await mkdir(artifacts, { recursive: true });
const profile = await mkdtemp(join(artifacts, 'browser-smoke-'));
const browser = spawn(executable, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, `--disable-extensions-except=${extension}`,
  `--load-extension=${extension}`, 'about:blank',
], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
let exited = false;
let launchError;
let diagnostic = '';
browser.on('error', error => { launchError = error; exited = true; });
browser.on('exit', () => { exited = true; });
browser.stderr.on('data', chunk => { diagnostic = (diagnostic + chunk).slice(-6000); });
let browserCdp;
try {
  const port = await poll(async () => {
    if (launchError) throw launchError;
    if (exited) throw new Error(`Browser exited before CDP startup: ${diagnostic}`);
    try {
      const value = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
      return /^\d+$/u.test(value) ? Number(value) : null;
    } catch (error) {
      if (['ENOENT', 'EBUSY'].includes(error.code)) return null;
      throw error;
    }
  }, 'browser debugging port');
  const endpoint = `http://127.0.0.1:${port}`;
  const get = async path => {
    const response = await fetch(`${endpoint}${path}`, { signal: AbortSignal.timeout(Math.min(3000, remaining())) });
    if (!response.ok) throw new Error(`CDP HTTP ${response.status}`);
    return response.json();
  };
  const version = await get('/json/version');
  browserCdp = await connect(version.webSocketDebuggerUrl);
  const worker = await poll(async () => (await get('/json/list')).find(target =>
    target.type === 'service_worker' && target.url.startsWith('chrome-extension:')), 'extension service worker');
  const extensionId = new URL(worker.url).hostname;
  const created = await browserCdp('Target.createTarget', { url: `chrome-extension://${extensionId}/ui/options.html` });
  const page = await poll(async () => (await get('/json/list')).find(target => target.id === created.targetId), 'options page');
  const pageCdp = await connect(page.webSocketDebuggerUrl);
  await pageCdp('Page.enable');
  await pageCdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 980, deviceScaleFactor: 1, mobile: false });
  await poll(async () => {
    const ready = await pageCdp('Runtime.evaluate', {
      expression: `location.pathname === '/ui/options.html' && document.readyState === 'complete' && typeof chrome.runtime.sendMessage === 'function'`,
      returnByValue: true,
    });
    return ready.result?.value === true;
  }, 'options document initialization');
  const result = await pageCdp('Runtime.evaluate', {
    expression: `(async () => {
      if (document.readyState === 'loading') await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve, { once: true }));
      const reply = await chrome.runtime.sendMessage({ type: 'getState' });
      if (!reply || reply.ok !== true) throw new Error(JSON.stringify(reply));
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      return { reply, url: location.href };
    })()`,
    awaitPromise: true, returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  if (result.result?.value?.reply?.ok !== true) throw new Error('Options page did not receive valid state');
  const screenshot = join(artifacts, 'options-smoke.png');
  try {
    const captured = await pageCdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    await writeFile(screenshot, Buffer.from(captured.data, 'base64'));
  } catch (error) {
    console.warn(`Screenshot unavailable: ${error.message}`);
  }
  console.log(JSON.stringify({ ok: true, browser: version.Browser, worker: worker.url,
    options: result.result.value.url, state: result.result.value.reply, screenshot }, null, 2));
} catch (error) {
  process.exitCode = 1;
  console.error(error.stack || error.message);
  if (diagnostic) console.error(diagnostic);
} finally {
  if (browserCdp && !exited) await browserCdp('Browser.close').catch(() => {});
  for (const socket of sockets) socket.close();
  for (let attempt = 0; attempt < 20 && !exited; attempt++) await pause(100);
  if (!exited) browser.kill();
  for (let attempt = 0; attempt < 10 && !exited; attempt++) await pause(100);
  // Only the disposable directory created by this invocation can be removed.
  if (exited && resolve(profile).startsWith(`${resolve(artifacts)}${sep}`)) {
    await rm(profile, { recursive: true, force: true }).catch(error => console.warn(`Profile retained: ${error.message}`));
  }
}
