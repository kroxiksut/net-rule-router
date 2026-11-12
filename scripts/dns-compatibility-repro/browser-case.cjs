// Run only on a test laptop. Every case owns a fresh Chrome profile.
const fs = require('node:fs');
const path = require('node:path');
const { isIP } = require('node:net');
const { spawn, spawnSync } = require('node:child_process');

const [caseDirectory, mode, targetName = 'secondary'] = process.argv.slice(2);
const hosts = { primary: 'api.ipify.org', secondary: 'ip.platipomiru.com', v6: 'api6.ipify.org', resolver: '1.1.1.1' };
if (!caseDirectory || !['secure', 'automatic', 'off'].includes(mode)
    || !Object.hasOwn(hosts, targetName) || !path.isAbsolute(caseDirectory)) {
  throw new Error('Usage: node browser-case.cjs ABSOLUTE_NEW_CASE_DIRECTORY secure|automatic|off [primary|secondary|v6|resolver]');
}
if (fs.existsSync(caseDirectory)) throw new Error('Case directory must not exist');
const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
if (!fs.statSync(chrome).isFile()) throw new Error('Expected installed Chrome executable is missing');
fs.mkdirSync(caseDirectory, { recursive: true });
const profile = path.join(caseDirectory, 'profile');
fs.mkdirSync(profile);
fs.writeFileSync(path.join(profile, 'Local State'), JSON.stringify({
  dns_over_https: { mode, templates: 'https://cloudflare-dns.com/dns-query' }
}), { flag: 'wx' });
const report = {
  mode, target: targetName, started: new Date().toISOString(), headless: true,
  savedPreferenceIsNotEffectivePolicyProof: true,
  result: 'unchecked', networkFailures: []
};
let browser, socket;
let finishing;
const pending = new Map();
let nextId = 0;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function call(method, params = {}, timeoutMs = 7000) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`CDP timeout: ${method}`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  browser = spawn(chrome, [
    '--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--log-net-log=${path.join(caseDirectory, 'netlog.json')}`,
    '--net-log-capture-mode=Default',
    `--user-data-dir=${profile}`, 'about:blank'
  ], { windowsHide: true, stdio: 'ignore' });
  let spawnError;
  browser.once('error', error => { spawnError = error; });
  const active = path.join(profile, 'DevToolsActivePort');
  const startupDeadline = Date.now() + 15000;
  let port;
  while (Date.now() < startupDeadline) {
    if (spawnError) throw spawnError;
    try { port = Number(fs.readFileSync(active, 'utf8').split(/\r?\n/)[0]); } catch {}
    if (Number.isInteger(port) && port > 0 && port < 65536) break;
    if (browser.exitCode !== null) throw new Error('Chrome exited during startup');
    await sleep(100);
  }
  if (!port) throw new Error('Chrome startup timeout');
  const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(5000) });
  const targets = await response.json();
  const target = targets.find(item => item.type === 'page');
  if (!target) throw new Error('No Chrome page target');
  const endpoint = new URL(target.webSocketDebuggerUrl);
  if (!['127.0.0.1', 'localhost'].includes(endpoint.hostname) || Number(endpoint.port) !== port) {
    throw new Error('Chrome returned a non-local debugger endpoint');
  }
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP connection timeout')), 5000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP connection failed')); }, { once: true });
  });
  socket.addEventListener('message', event => {
    const raw = String(event.data);
    if (raw.length > 4 * 1024 * 1024) {
      report.harnessError = 'CDP response exceeded the size bound';
      void finish().finally(() => process.exit(2));
      return;
    }
    let message;
    try { message = JSON.parse(raw); } catch {
      report.harnessError = 'Invalid CDP response';
      void finish().finally(() => process.exit(2));
      return;
    }
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(`CDP error: ${message.error.code}`));
      else waiter.resolve(message.result);
    } else if (message.method === 'Network.loadingFailed' && report.networkFailures.length < 32) {
      report.networkFailures.push({ at: new Date().toISOString(), error: String(message.params.errorText).slice(0, 128) });
    }
  });
  report.browser = await call('Browser.getVersion');
  await call('Network.enable');
  await call('Network.setCacheDisabled', { cacheDisabled: true });
  const host = hosts[targetName];
  report.host = host;
  const navigation = await call('Page.navigate', { url: `https://${host}/?format=json&nrr=${Date.now()}` }, 25000);
  report.navigationError = navigation.errorText || null;
  const deadline = Date.now() + 25000;
  while (Date.now() < deadline) {
    const value = await call('Runtime.evaluate', {
      expression: 'JSON.stringify({host:location.hostname,text:(document.body ? document.body.textContent : "").slice(0,1024)})',
      returnByValue: true
    });
    try {
      const page = JSON.parse(value.result.value);
      if (page.host === host) {
        report.pageText = page.text;
        report.result = 'page-returned-needs-address-review';
        const parsed = page.text.trim().startsWith('{') ? JSON.parse(page.text) : { ip: page.text.trim() };
        if (typeof parsed.ip === 'string' && parsed.ip.length <= 64 && isIP(parsed.ip) !== 0) {
          report.address = parsed.ip;
          report.result = 'external-address-returned';
          break;
        }
      }
    } catch {}
    await sleep(500);
  }
  const screenshot = await call('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(caseDirectory, 'page.png'), Buffer.from(screenshot.data, 'base64'));
}

const watchdog = setTimeout(() => {
  report.result = 'harness-timeout';
  void finish().finally(() => process.exit(2));
}, 60000);

function finish() {
  if (finishing) return finishing;
  finishing = (async () => {
    clearTimeout(watchdog);
    if (browser && browser.exitCode === null && browser.signalCode === null
        && socket && socket.readyState === WebSocket.OPEN) {
      const closeDeadline = Date.now() + 3000;
      try { await call('Browser.close', {}, 1000); } catch {}
      while (browser.exitCode === null && browser.signalCode === null && Date.now() < closeDeadline) {
        await sleep(50);
      }
    }
    for (const waiter of pending.values()) clearTimeout(waiter.timer);
    pending.clear();
    if (socket) socket.close();
    if (browser && browser.exitCode === null && browser.signalCode === null && Number.isInteger(browser.pid)) {
      report.browserForcedClosed = true;
      spawnSync('taskkill.exe', ['/PID', String(browser.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore', timeout: 5000 });
    }
    report.finished = new Date().toISOString();
    fs.writeFileSync(path.join(caseDirectory, 'report.json'), JSON.stringify(report, null, 2));
  })();
  return finishing;
}

main().catch(error => {
  report.harnessError = String(error.message).slice(0, 256);
  process.exitCode = 2;
}).finally(async () => {
  await finish();
  console.log(JSON.stringify({ result: report.result, report: path.join(caseDirectory, 'report.json') }));
});

for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  report.result = 'interrupted';
  void finish().finally(() => process.exit(130));
});
