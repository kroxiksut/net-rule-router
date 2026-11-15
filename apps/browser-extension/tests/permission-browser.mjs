import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.env.NRR_VISIBLE_ROOT;
const extension = process.env.NRR_VISIBLE_EXTENSION;
const executable = process.env.NRR_VISIBLE_EDGE;
if (!root || !extension || !executable) throw new Error('Set NRR_VISIBLE_ROOT, NRR_VISIBLE_EXTENSION and NRR_VISIBLE_EDGE');
const profile = path.join(root, 'profile');
const logPath = path.join(root, 'events.jsonl');
await mkdir(root, { recursive: true });
await mkdir(profile);
const log = event => appendFile(logPath, `${JSON.stringify(event)}\n`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const deadline = Date.now() + 65000;
const hits = [];
const server = createServer((req, res) => {
  hits.push({ path: req.url, language: req.headers['accept-language'] ?? null });
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('NRR isolated acceptance');
});
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
const port = server.address().port;
const child = spawn(executable, [
  `--user-data-dir=${profile}`, `--disable-extensions-except=${extension}`,
  `--load-extension=${extension}`, '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
  '--no-first-run', '--no-default-browser-check', `http://127.0.0.1:${port}/baseline`,
], { windowsHide: false, stdio: 'ignore' });
await writeFile(path.join(root, 'edge.pid'), String(child.pid));
let childExited = false;
child.once('exit', () => { childExited = true; });
const sockets = [];
async function poll(fn, label) {
  while (Date.now() < deadline && !childExited) {
    const result = await fn();
    if (result) return result;
    await sleep(200);
  }
  throw new Error(`Timed out: ${label}`);
}
async function connect(url) {
  const socket = new WebSocket(url);
  sockets.push(socket);
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP open timeout')), 3000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP open failed')); }, { once: true });
    });
  } catch (error) {
    socket.close();
    throw error;
  }
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const data = JSON.parse(event.data);
    const request = pending.get(data.id);
    if (!request) return;
    pending.delete(data.id);
    clearTimeout(request.timer);
    if (data.error) request.reject(new Error(data.error.message)); else request.resolve(data.result);
  });
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 3000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
  call.close = () => { socket.close(); const index = sockets.indexOf(socket); if (index >= 0) sockets.splice(index, 1); };
  return call;
}
let browser;
try {
  const debugPort = await poll(async () => {
    try { return Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]) || null; }
    catch (error) { if (['ENOENT', 'EBUSY'].includes(error.code)) return null; throw error; }
  }, 'debug port');
  const get = async pathname => {
    const response = await fetch(`http://127.0.0.1:${debugPort}${pathname}`, { signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw new Error(`CDP HTTP ${response.status}`);
    return response.json();
  };
  const version = await get('/json/version');
  browser = await connect(version.webSocketDebuggerUrl);
  await poll(async () => hits.some(hit => hit.path === '/baseline') || null, 'baseline request');
  const baseline = hits.find(hit => hit.path === '/baseline').language;
  if (!baseline) throw new Error('Browser did not send a baseline Accept-Language header');
  const worker = await poll(async () => {
    const targets = await get('/json/list');
    for (const target of targets.filter(item => item.type === 'service_worker' && /^chrome-extension:\/\/[^/]+\/background\.js$/u.test(item.url))) {
      let candidate;
      try {
        candidate = await connect(target.webSocketDebuggerUrl);
        await candidate('Runtime.enable');
        const result = await candidate('Runtime.evaluate', { expression: "globalThis.chrome?.i18n?.getMessage('app_name')", returnByValue: true });
        if (result.result?.value === 'NetRuleRouter') return target;
      } catch { /* The target can disappear while the list is being read. */ }
      finally { candidate?.close(); }
    }
    return null;
  }, 'NRR extension worker');
  const extensionId = new URL(worker.url).hostname;
  const { targetId } = await browser('Target.createTarget', { url: `chrome-extension://${extensionId}/ui/options.html` });
  const page = await poll(async () => (await get('/json/list')).find(item => item.id === targetId), 'options page');
  const cdp = await connect(page.webSocketDebuggerUrl);
  await cdp('Runtime.enable');
  await cdp('Page.enable');
  const evaluate = async expression => {
    const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  await poll(async () => await evaluate("document.readyState === 'complete' && !!document.querySelector('#profile-form') && !!globalThis.chrome?.permissions") || null, 'options initialization');
  await evaluate("chrome.runtime.sendMessage({type:'getState'})");
  await sleep(1000);
  await cdp('Page.bringToFront');
  const setup = await evaluate(`(() => {
    const original = chrome.permissions.request.bind(chrome.permissions);
    try {
      Object.defineProperty(chrome.permissions, 'request', { configurable: true, value: async function(details) {
        window.__permission = { details, active: navigator.userActivation?.isActive, state: 'pending' };
        try { const value = await original(details); Object.assign(window.__permission, { state: 'resolved', value }); return value; }
        catch (error) { Object.assign(window.__permission, { state: 'rejected', name: error?.name, message: error?.message }); throw error; }
      }});
    } catch (error) { return { patchError: error.message }; }
    const form = document.querySelector('#profile-form');
    form.elements.host.value = '127.0.0.1';
    form.elements.languageMode.value = 'manual';
    form.elements.languageMode.dispatchEvent(new Event('change', { bubbles: true }));
    form.elements.language.value = 'fr-CA';
    const button = form.querySelector('button[type="submit"]');
    button.scrollIntoView({ block: 'center' });
    const box = button.getBoundingClientRect();
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  })()`);
  if (setup.patchError) throw new Error(`Could not instrument permission: ${setup.patchError}`);
  await cdp('Input.dispatchMouseEvent', { type: 'mouseMoved', x: setup.x, y: setup.y });
  await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: setup.x, y: setup.y, button: 'left', clickCount: 1 });
  await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: setup.x, y: setup.y, button: 'left', clickCount: 1 });
  await log({ phase: 'permission_requested', edgePid: child.pid, host: '127.0.0.1', extensionId });
  const permission = await poll(async () => {
    const value = await evaluate('window.__permission ?? null');
    return value && value.state !== 'pending' ? value : null;
  }, 'permission prompt; grant it in the visible test browser');
  if (!permission.active || permission.state !== 'resolved' || permission.value !== true) {
    throw new Error(`Permission was not granted after a real click: ${JSON.stringify(permission)}`);
  }
  const profileApplied = await poll(async () => {
    const result = await evaluate("chrome.runtime.sendMessage({type:'getState'})");
    return result?.state?.profiles?.some(item => item.host === '127.0.0.1' && item.language === 'fr-CA') && !result.state.pending;
  }, 'manual profile applied');
  if (!profileApplied) throw new Error('Manual profile was not applied');
  await poll(async () => await evaluate("!document.querySelector('#profile-form button[type=submit]').disabled") || null, 'profile form ready');
  await browser('Target.createTarget', { url: `http://127.0.0.1:${port}/after-manual` });
  await poll(async () => hits.some(hit => hit.path === '/after-manual') || null, 'request after manual profile');
  const manual = hits.find(hit => hit.path === '/after-manual').language;
  if (manual !== 'fr-CA') throw new Error(`Manual profile was not reflected in the request: ${manual}`);
  const inherit = await evaluate(`(() => {
    const form = document.querySelector('#profile-form');
    form.elements.host.value = '127.0.0.1';
    form.elements.languageMode.value = 'inherit';
    form.elements.languageMode.dispatchEvent(new Event('change', { bubbles: true }));
    const button = form.querySelector('button[type="submit"]');
    button.scrollIntoView({ block: 'center' });
    const box = button.getBoundingClientRect();
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  })()`);
  await cdp('Page.bringToFront');
  await cdp('Input.dispatchMouseEvent', { type: 'mouseMoved', x: inherit.x, y: inherit.y });
  await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: inherit.x, y: inherit.y, button: 'left', clickCount: 1 });
  await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: inherit.x, y: inherit.y, button: 'left', clickCount: 1 });
  await poll(async () => {
    const result = await evaluate("chrome.runtime.sendMessage({type:'getState'})");
    return result?.state?.revision >= 2 && !result.state.pending && !result.state.profiles.some(item => item.host === '127.0.0.1');
  }, 'inheritance restored');
  await browser('Target.createTarget', { url: `http://127.0.0.1:${port}/after-inherit` });
  await poll(async () => hits.some(hit => hit.path === '/after-inherit') || null, 'request after inheritance');
  const inherited = hits.find(hit => hit.path === '/after-inherit').language;
  if (inherited !== baseline) throw new Error(`Browser language was not restored: ${inherited}`);
  await log({ phase: 'passed', browser: version.Browser, extensionId, baseline, manual, inherited, permission });
} catch (error) {
  await log({ error: error.stack || String(error), baseline: hits });
  process.exitCode = 1;
} finally {
  if (browser) await browser('Browser.close').catch(() => {});
  for (const socket of sockets) socket.close();
  for (let i = 0; i < 20 && !childExited; i++) await sleep(100);
  if (!childExited) child.kill();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
