'use strict';
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
const profile = path.join(dir, 'chrome-profile');
const port = Number(fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split(/\r?\n/)[0]);

function evaluate(ws, expression) {
  return new Promise((resolve, reject) => {
    const id = 1;
    const timer = setTimeout(() => reject(new Error('evaluation timeout')), 10000);
    ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id !== id) return;
      clearTimeout(timer);
      resolve(message.result?.result?.value);
    };
    ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
  });
}

(async () => {
  const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const tab = tabs.find(item => item.url.startsWith('chrome://webrtc-internals'));
  if (!tab) throw new Error('webrtc-internals missing');
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  const expression = `(()=>{const out={};for(const [id,value] of Object.entries(window.peerConnectionDataStore||{})){const r=value.record_||{},s=r.stats||{},last=k=>{const p=s[k]?.dataPoints_;return p?.length?p[p.length-1].value:null},find=suffix=>Object.keys(s).find(k=>k.endsWith(suffix));const tk=find('-selectedCandidatePairId'),tp=tk?.slice(0,-'-selectedCandidatePairId'.length),pair=tk?last(tk):null,local=pair?last(pair+'-localCandidateId'):null,remote=pair?last(pair+'-remoteCandidateId'):null,c=x=>x?{address:last(x+'-address'),port:last(x+'-port'),protocol:last(x+'-protocol'),candidateType:last(x+'-candidateType'),relatedAddress:last(x+'-relatedAddress'),relatedPort:last(x+'-relatedPort')}:null;out[id]={iceState:tp?last(tp+'-iceState'):null,dtlsState:tp?last(tp+'-dtlsState'):null,bytesSent:tp?last(tp+'-bytesSent'):null,bytesReceived:tp?last(tp+'-bytesReceived'):null,pair:{id:pair,state:pair?last(pair+'-state'):null,nominated:pair?last(pair+'-nominated'):null,local:c(local),remote:c(remote)},configuration:(r.updateLog||[]).filter(e=>/create|config|ice/i.test(String(e.type))).slice(0,40).map(e=>({type:e.type,value:e.value}))}}return out})()`;
  const result = await evaluate(ws, expression);
  console.log(JSON.stringify(result));
  ws.close();
})().catch(error => { console.error(error.stack || error.message); process.exit(1); });
