'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');

const dir = process.argv[2];
const room = process.argv[3];
const profile = path.join(dir, 'chrome-profile');
const stop = path.join(dir, 'stop.flag');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
  fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(stop)) fs.rmSync(stop, { force: true });
  const url = `https://sfu.mirotalk.com/join?room=${encodeURIComponent(room)}&roomPassword=0&name=NRR-W8&audio=1&video=0&screen=0&notify=0&hide=1`;
  const chrome = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
    '--headless=new', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--log-net-log=${path.join(dir, 'chrome-netlog.json')}`,
    '--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream',
    '--autoplay-policy=no-user-gesture-required', url,
  ], { stdio: 'ignore' });
  console.log(`CHROME_PID=${chrome.pid}`);
  try {
    const portFile = path.join(profile, 'DevToolsActivePort');
    for (let n = 0; n < 150 && !fs.existsSync(portFile); n++) await delay(100);
    const port = Number(fs.readFileSync(portFile, 'utf8').split(/\r?\n/)[0]);
    await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('chrome://webrtc-internals')}`, { method: 'PUT' });
    for (let n = 0; n < 3600 && !fs.existsSync(stop); n++) await delay(1000);
  } finally {
    try { execFileSync('taskkill.exe', ['/PID', String(chrome.pid), '/T', '/F'], { timeout: 5000, stdio: 'ignore' }); } catch {}
    await delay(500);
    if (fs.existsSync(profile) && !fs.lstatSync(profile).isSymbolicLink() && fs.realpathSync(profile).startsWith(fs.realpathSync(dir) + path.sep)) {
      fs.rmSync(profile, { recursive: true, force: true });
    }
  }
})().catch(error => { console.error(error.stack || error.message); process.exit(1); });
