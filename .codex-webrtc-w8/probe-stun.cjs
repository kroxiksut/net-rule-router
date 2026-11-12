'use strict';
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
const profile = path.join(dir, 'chrome-profile');
const port = Number(fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split(/\r?\n/)[0]);

(async () => {
  const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const tab = tabs.find(item => item.url.startsWith('https://sfu.mirotalk.com/'));
  if (!tab) throw new Error('MiroTalk target missing');
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  const expression = `(async()=>{
    const pc=new RTCPeerConnection({iceServers:[{urls:['stun:stun.l.google.com:19302']}]});
    window.__nrrStunProbe=pc;
    pc.createDataChannel('probe');
    const candidates=[];
    pc.onicecandidate=e=>{if(e.candidate)candidates.push({candidate:e.candidate.candidate,address:e.candidate.address,port:e.candidate.port,protocol:e.candidate.protocol,type:e.candidate.type,relatedAddress:e.candidate.relatedAddress,relatedPort:e.candidate.relatedPort})};
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(resolve=>{if(pc.iceGatheringState==='complete')return resolve();const timer=setTimeout(resolve,15000);pc.addEventListener('icegatheringstatechange',()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timer);resolve()}},{once:false})});
    return {origin:location.origin,iceGatheringState:pc.iceGatheringState,candidates};
  })()`;
  const id = 1;
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('probe timeout')), 25000);
    ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id !== id) return;
      clearTimeout(timer);
      if (message.result?.exceptionDetails) reject(new Error('probe evaluation failed'));
      else resolve(message.result?.result?.value);
    };
    ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true, awaitPromise: true } }));
  });
  console.log(JSON.stringify(result));
  ws.close();
})().catch(error => { console.error(error.stack || error.message); process.exit(1); });
