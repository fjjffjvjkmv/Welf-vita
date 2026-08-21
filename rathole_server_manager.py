from __future__ import annotations
import asyncio, json, os, shutil, signal
from pathlib import Path
from rathole_control import STATE, FILE, load

BASE = Path(os.environ.get('RATHOLE_DIR','/data/rathole'))
BIN = Path(os.environ.get('RATHOLE_BIN','/usr/local/bin/rathole'))
CFG = BASE / 'server.toml'
PROCESS = None
LAST = ''


def q(v):
    return '"' + str(v).replace('\\','\\\\').replace('"','\\"') + '"'

def render():
    st = STATE['settings']
    lines = [
        '[server]',
        f"bind_addr = {q('0.0.0.0:' + str(int(st['server_bind_port'])))}",
        f"heartbeat_interval = {max(5, int(st.get('heartbeat_interval',15)))}",
        '',
        '[server.transport]',
        f"type = {q(st.get('transport','tcp'))}",
        '',
        '[server.transport.tcp]',
        f"nodelay = {str(bool(st.get('nodelay',True))).lower()}",
        f"keepalive_secs = {max(5,int(st.get('keepalive_secs',20)))}",
        f"keepalive_interval = {max(3,int(st.get('keepalive_interval',8)))}",
    ]
    # WebSocket is intentionally transported as raw TCP by Rathole; no HTTP parsing is inserted in the data path.
    for t in STATE['tunnels'].values():
        if not t.get('enabled',True):
            continue
        name = ''.join(c if c.isalnum() or c=='_' else '_' for c in t['id'])
        lines += [
            '',
            f'[server.services.{name}]',
            'type = "tcp"',
            f"token = {q(t['token'])}",
            f"bind_addr = {q('0.0.0.0:' + str(int(t['public_port'])))}",
            f"nodelay = {str(bool(t.get('nodelay',True))).lower()}",
        ]
    return '\n'.join(lines)+'\n'

async def apply_once():
    global PROCESS, LAST
    if not BIN.exists():
        return
    cfg = render()
    digest = __import__('hashlib').sha256(cfg.encode()).hexdigest()
    if digest == LAST and PROCESS and PROCESS.poll() is None:
        return
    BASE.mkdir(parents=True, exist_ok=True)
    tmp = CFG.with_suffix('.tmp')
    tmp.write_text(cfg, encoding='utf-8')
    tmp.replace(CFG)
    if PROCESS and PROCESS.poll() is None:
        PROCESS.send_signal(signal.SIGTERM)
        try: PROCESS.wait(timeout=3)
        except Exception: PROCESS.kill()
    env = os.environ.copy()
    env.setdefault('RUST_LOG', os.environ.get('RATHOLE_LOG','info'))
    PROCESS = __import__('subprocess').Popen([str(BIN), '--server', str(CFG)], env=env)
    LAST = digest

async def run():
    await load()
    while True:
        try: await apply_once()
        except Exception as e: print('[rathole-server]', e, flush=True)
        await asyncio.sleep(2)
