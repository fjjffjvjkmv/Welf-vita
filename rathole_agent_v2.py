#!/usr/bin/env python3
"""Zero-inbound Rathole agent for Linux nodes.

One bootstrap command installs this file + a systemd service. Afterwards the
agent talks outbound to the RVG panel and applies all port-forwarding changes
from the panel. No inbound management port is required on the Iran host.
"""
from __future__ import annotations

import json, os, platform, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path

PANEL_URL = os.environ.get("RVG_PANEL_URL", "").rstrip("/")
NODE_ID = os.environ.get("RVG_NODE_ID", "")
NODE_TOKEN = os.environ.get("RVG_NODE_TOKEN", "")
BASE = Path(os.environ.get("RVG_AGENT_DIR", "/opt/rvg-rathole"))
BIN = BASE / "rathole"
CONF = BASE / "client.toml"
STATE = BASE / "agent-state.json"
POLL = float(os.environ.get("RVG_AGENT_POLL", "3"))


def http_json(path: str, payload: dict | None = None):
    import subprocess
    body = "" if payload is None else json.dumps(payload, ensure_ascii=False)
    url = f"{PANEL_URL}{path}"
    cmd = [
        "curl", "-sS", "--fail-with-body",
        "--connect-timeout", "10", "--max-time", "20",
        "-X", "POST" if payload is not None else "GET",
        "-H", "Accept: application/json",
        "-H", "Content-Type: application/json",
        "-H", "User-Agent: RVG-Rathole-Agent/2.0",
        "-H", f"X-RVG-Node-Id: {NODE_ID}",
        "-H", f"X-RVG-Node-Token: {NODE_TOKEN}",
        "-w", "\n__RVG_HTTP_STATUS__:%{http_code}",
        url,
    ]
    if payload is not None:
        cmd += ["--data-binary", body]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out, err = proc.stdout or "", (proc.stderr or "").strip()
    marker="__RVG_HTTP_STATUS__:"
    status=None
    if marker in out:
        out, status_s = out.rsplit(marker,1)
        try: status=int(status_s.strip().splitlines()[0])
        except Exception: status=None
    if proc.returncode != 0:
        detail=(out.strip()+" | "+err).strip(" |")
        raise RuntimeError(f"HTTP {status or proc.returncode}: {detail[:600]}")
    try:
        return int(status or 200), json.loads(out or "{}")
    except Exception as e:
        raise RuntimeError(f"Invalid JSON from panel (HTTP {status}): {out[:500]}") from e

def toml_s(s: str) -> str:
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def make_config(snapshot: dict) -> str:
    server = snapshot["server"]
    st = snapshot.get("settings", {})
    lines = [
        "[client]",
        f"remote_addr = {toml_s(str(server['host']) + ':' + str(int(server['port'])))}",
        f"heartbeat_timeout = {max(10, int(st.get('heartbeat_interval', 15)) * 3)}",
        f"retry_interval = {max(1, int(st.get('retry_interval', 1)))}",
        "",
        "[client.transport]",
        f"type = {toml_s(st.get('transport', 'tcp'))}",
        "",
        "[client.transport.tcp]",
        f"nodelay = {str(bool(st.get('nodelay', True))).lower()}",
        f"keepalive_secs = {max(5, int(st.get('keepalive_secs', 20)))}",
        f"keepalive_interval = {max(3, int(st.get('keepalive_interval', 8)))}",
    ]
    # WebSocket uses Rathole transport type "tcp"; the WebSocket handshake/data stays transparent end-to-end.
    for t in snapshot.get("tunnels", []):
        name = ''.join(c if c.isalnum() or c == '_' else '_' for c in t['id'])
        lines += [
            "",
            f"[client.services.{name}]",
            "type = \"tcp\"",
            f"token = {toml_s(t['token'])}",
            f"local_addr = {toml_s(str(t['local_host']) + ':' + str(t['local_port']))}",
            f"nodelay = {str(bool(t.get('nodelay', True))).lower()}",
        ]
    return "\n".join(lines) + "\n"


def restart_client(cfg: str):
    BASE.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="client-", suffix=".toml", dir=BASE)
    os.close(fd)
    Path(tmp).write_text(cfg, encoding="utf-8")
    os.replace(tmp, CONF)
    subprocess.run(["systemctl", "restart", "rvg-rathole"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if not PANEL_URL or not NODE_ID or not NODE_TOKEN:
        print("Missing RVG_PANEL_URL/RVG_NODE_ID/RVG_NODE_TOKEN", file=sys.stderr)
        return 2
    print(f"[agent] v2 starting | panel={PANEL_URL} | node={NODE_ID}", flush=True)
    applied = 0
    while True:
        try:
            try:
                client_active = subprocess.run(
                    ["systemctl", "is-active", "rvg-rathole"],
                    capture_output=True, text=True, timeout=3
                ).stdout.strip() == "active"
            except Exception:
                client_active = False
            meta = {
                "agent_version": "2.1",
                "hostname": socket.gethostname(),
                "platform": f"{platform.system()} {platform.release()}",
                "public_ip": "",
                "applied_revision": applied,
                "rathole_client_active": client_active,
            }
            status, snap = http_json("/api/rathole/agent/next", meta)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            revision = int(snap.get("revision", 0))
            print(f"[agent] heartbeat OK | revision={revision} | tunnels={len(snap.get('tunnels', []))}", flush=True)
            if revision != applied:
                cfg = make_config(snap)
                restart_client(cfg)
                applied = revision
                Path(STATE).write_text(json.dumps({"applied_revision": applied}), encoding="utf-8")
        except Exception as e:
            print(f"[agent] {e}", file=sys.stderr)
        time.sleep(POLL)


if __name__ == "__main__":
    raise SystemExit(main())
