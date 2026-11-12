#!/usr/bin/env python3
import json, pathlib, subprocess, sys, time, urllib.parse, urllib.request

root = pathlib.Path(sys.argv[1]).resolve()
room = sys.argv[2]
session = None

def request(method, url, payload=None, timeout=15):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read()
    return json.loads(body) if body else {}

root.mkdir(parents=True, exist_ok=True)
stop = root / 'stop.flag'
if stop.exists():
    stop.unlink()
log = open(root / 'geckodriver.log', 'wb')
gecko = subprocess.Popen(['geckodriver', '--port', '4445', '--log', 'info'], stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            request('GET', 'http://127.0.0.1:4445/status', timeout=1)
            break
        except Exception:
            time.sleep(.1)
    created = request('POST', 'http://127.0.0.1:4445/session', {'capabilities': {'alwaysMatch': {
        'browserName': 'firefox',
        'moz:firefoxOptions': {'args': ['-headless'], 'prefs': {
            'media.navigator.streams.fake': True,
            'media.navigator.permission.disabled': True,
            'media.autoplay.default': 0,
            'media.volume_scale': '0.0',
        }},
    }}}, timeout=30)
    session = created.get('value', {}).get('sessionId') or created.get('sessionId')
    url = f'https://sfu.mirotalk.com/join?room={urllib.parse.quote(room)}&roomPassword=0&name=NRR-Ubuntu-W8&audio=0&video=0&screen=0&notify=0&hide=1'
    request('POST', f'http://127.0.0.1:4445/session/{session}/url', {'url': url}, timeout=30)
    print('UBUNTU_PEER_STARTED', flush=True)
    for _ in range(3600):
        if stop.exists():
            break
        time.sleep(1)
finally:
    if session:
        try:
            request('DELETE', f'http://127.0.0.1:4445/session/{session}')
        except Exception:
            pass
    gecko.terminate()
    try:
        gecko.wait(timeout=5)
    except Exception:
        gecko.kill()
    log.close()
