"use strict";

const el = id => document.getElementById(id);
const MAX_EVENTS = 512;
const MAX_SDP = 65536;
let active = null;
let report = null;
let busy = false;

function record(run, kind, data = {}) {
  if (report !== run.report) return;
  const event = { at: new Date().toISOString(), elapsedMs: Math.round(performance.now() - run.start), kind, ...data };
  if (report.events.length === MAX_EVENTS) {
    report.events.shift();
    report.discardedEvents++;
  }
  report.events.push(event);
  el("log").textContent = report.events.slice(-24).map(item => JSON.stringify(item)).join("\n");
}

function candidate(item) {
  if (!item) return null;
  const fields = ["address", "port", "protocol", "candidateType", "type", "tcpType", "relayProtocol", "relatedAddress", "relatedPort"];
  return Object.fromEntries(fields.filter(key => item[key] !== undefined).map(key =>
    [key, typeof item[key] === "string" ? item[key].slice(0, 256) : item[key]]));
}

function stop(reason = "stopped") {
  const run = active;
  if (!run) return;
  active = null;
  clearInterval(run.interval);
  clearTimeout(run.deadline);
  run.pc.close();
  run.finishGather?.();
  record(run, "stop", { reason, sent: run.sent, received: run.received });
  el("status").textContent = reason;
}

function configuration() {
  const raw = el("servers").value;
  if (raw.length > 4096) throw new Error("ICE URL list exceeds limit");
  const urls = raw.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  if (urls.length > 8 || urls.some(value => value.length > 256 || !/^(stun|turn|turns):[^\s@]+$/.test(value))) {
    throw new Error("Use at most 8 STUN/TURN URLs without embedded credentials");
  }
  const username = el("username").value;
  const credential = el("credential").value;
  if (username.length > 256 || credential.length > 256) throw new Error("TURN credentials exceed limit");
  const policy = el("policy").value;
  if (!["all", "relay"].includes(policy)) throw new Error("Invalid ICE policy");
  if (policy === "relay" && !urls.some(value => /^turns?:/.test(value))) throw new Error("Relay policy requires a TURN URL");
  return {
    iceServers: urls.map(url => /^turns?:/.test(url) ? { urls: url, username, credential } : { urls: url }),
    iceTransportPolicy: policy,
    iceCandidatePoolSize: 0,
  };
}

function attachChannel(run, channel) {
  if (run.channel) {
    channel.close();
    return;
  }
  run.channel = channel;
  channel.onopen = () => record(run, "data-open");
  channel.onclose = () => record(run, "data-close");
  channel.onerror = () => record(run, "data-error");
  channel.onmessage = event => {
    if (typeof event.data !== "string" || event.data.length > 128) {
      channel.close();
      record(run, "oversized-or-binary-data-rejected");
      return;
    }
    run.received++;
  };
}

async function sample(run) {
  if (active !== run || run.sampling) return;
  run.sampling = true;
  try {
    const stats = await run.pc.getStats();
    if (active !== run) return;
    let selected = false;
    let examined = 0;
    for (const item of stats.values()) {
      if (++examined > 512) break;
      if (item.type !== "transport" || !item.selectedCandidatePairId) continue;
      const pair = stats.get(item.selectedCandidatePairId);
      if (!pair) continue;
      selected = true;
      record(run, "selected-pair", {
        local: candidate(stats.get(pair.localCandidateId)),
        remote: candidate(stats.get(pair.remoteCandidateId)),
        state: pair.state, bytesSent: pair.bytesSent, bytesReceived: pair.bytesReceived,
        sent: run.sent, received: run.received,
      });
    }
    if (!selected && !run.selectionUnavailable) {
      record(run, "selection-not-reported", { note: "No selected pair yet, or this browser does not expose the statistic" });
      run.selectionUnavailable = true;
    }
    if (selected) run.selectionUnavailable = false;
    if (run.channel?.readyState === "open" && run.channel.bufferedAmount < 4096) {
      run.channel.send(`nrr-webrtc:${++run.sent}`);
    }
  } catch (error) {
    record(run, "stats-error", { message: String(error.message).slice(0, 256) });
  } finally {
    run.sampling = false;
  }
}

function begin() {
  const config = configuration();
  const seconds = Number(el("duration").value);
  if (!Number.isInteger(seconds) || seconds < 10 || seconds > 300) throw new Error("Run time must be 10–300 seconds");
  stop("replaced by new run");
  const pc = new RTCPeerConnection(config);
  report = {
    schema: 1, case: el("case").value.slice(0, 80), startedAt: new Date().toISOString(),
    browser: navigator.userAgent.slice(0, 512), origin: location.origin,
    icePolicy: config.iceTransportPolicy, serverCount: config.iceServers.length,
    durationSeconds: seconds, discardedEvents: 0, events: [],
  };
  const run = { pc, report, start: performance.now(), sent: 0, received: 0 };
  active = run;
  el("local").value = "";
  el("log").textContent = "";
  el("status").textContent = "Gathering / waiting for signalling";
  pc.onicecandidate = event => {
    if (event.candidate) record(run, "candidate", candidate(event.candidate));
    else record(run, "gathering-complete");
  };
  pc.onicecandidateerror = event => record(run, "ice-error", { code: event.errorCode });
  pc.oniceconnectionstatechange = () => record(run, "ice-state", { state: pc.iceConnectionState });
  pc.onconnectionstatechange = () => {
    record(run, "connection-state", { state: pc.connectionState });
    if (active === run) el("status").textContent = pc.connectionState;
  };
  pc.ondatachannel = event => attachChannel(run, event.channel);
  run.interval = setInterval(() => { void sample(run); }, 1000);
  run.deadline = setTimeout(() => stop("run time limit reached"), seconds * 1000);
  record(run, "start");
  return run;
}

async function localDescription(run, description) {
  await run.pc.setLocalDescription(description);
  if (active !== run) return;
  await new Promise(resolve => {
    let timer;
    const finish = () => {
      clearTimeout(timer);
      run.pc.removeEventListener("icegatheringstatechange", changed);
      run.finishGather = null;
      resolve();
    };
    const changed = () => { if (run.pc.iceGatheringState === "complete") finish(); };
    run.finishGather = finish;
    run.pc.addEventListener("icegatheringstatechange", changed);
    timer = setTimeout(() => { record(run, "gathering-timeout"); finish(); }, 15000);
    changed();
  });
  if (active !== run) return;
  const sdp = run.pc.localDescription?.sdp || "";
  if (sdp.length > MAX_SDP || new TextEncoder().encode(sdp).length > MAX_SDP) throw new Error("Local SDP exceeds limit");
  el("local").value = sdp;
  record(run, "local-sdp-ready", { type: description.type, gatheringState: run.pc.iceGatheringState });
}

function remoteDescription(type) {
  const sdp = el("remote").value;
  if (!sdp || sdp.length > MAX_SDP || new TextEncoder().encode(sdp).length > MAX_SDP) throw new Error("Paste remote SDP, at most 64 KiB");
  return { type, sdp };
}

async function action(work) {
  if (busy) return;
  busy = true;
  for (const id of ["offer", "answer", "apply"]) el(id).disabled = true;
  try { await work(); }
  catch (error) {
    if (active) record(active, "operation-error", { name: error.name });
    stop("operation failed");
    el("status").textContent = `${error.name}: ${String(error.message).slice(0, 256)}`;
  } finally {
    busy = false;
    for (const id of ["offer", "answer", "apply"]) el(id).disabled = false;
  }
}

el("offer").onclick = () => action(async () => {
  const run = begin();
  attachChannel(run, run.pc.createDataChannel("nrr-probe", { ordered: false, maxRetransmits: 0 }));
  await localDescription(run, await run.pc.createOffer());
});
el("answer").onclick = () => action(async () => {
  const description = remoteDescription("offer");
  const run = begin();
  await run.pc.setRemoteDescription(description);
  await localDescription(run, await run.pc.createAnswer());
});
el("apply").onclick = () => action(async () => {
  if (!active) throw new Error("Start an offer first");
  await active.pc.setRemoteDescription(remoteDescription("answer"));
});
el("stop").onclick = () => stop();
el("export").onclick = () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "nrr-webrtc-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
window.addEventListener("pagehide", () => stop("page closed"));
