"""RVG Rathole control plane.

The browser/UI never carries user traffic. It only creates desired-state records.
The Iran-side agent polls this control plane over HTTPS and applies the desired
Rathole client configuration locally. The actual application traffic remains
inside Rathole's TCP data path.
"""
from __future__ import annotations

import asyncio
import hashlib
import base64
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

DATA_DIR = Path(__import__("os").environ.get("DATA_DIR", "/data"))
FILE = DATA_DIR / "rathole_control.json"
LOCK = asyncio.Lock()
STATE: dict[str, Any] = {"nodes": {}, "tunnels": {}, "settings": {}}

DEFAULT_SETTINGS = {
    "server_bind_port": int(__import__("os").environ.get("RATHOLE_SERVER_PORT", "23333")),
    "public_base_port": int(__import__("os").environ.get("RATHOLE_PUBLIC_PORT", "443")),
    "transport": "tcp",
    "nodelay": True,
    "keepalive_secs": 20,
    "keepalive_interval": 8,
    "retry_interval": 1,
    "heartbeat_interval": 15,
    "cloudflare_ipv4": ["103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13","104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18","162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20","190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"],
    "cloudflare_ipv6": ["2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"],
    "cloudflare_https_only": True,
    "server_public_host": "",
    "server_public_port": 0,
    "server_public_proxy_id": "",
    "server_public_application_port": 0,
}
STATE["settings"].update(DEFAULT_SETTINGS)


def _now() -> float:
    return time.time()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def load() -> None:
    global STATE
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if FILE.exists():
            raw = json.loads(FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                STATE = raw
                STATE.setdefault("nodes", {})
                STATE.setdefault("tunnels", {})
                STATE.setdefault("settings", {})
                for k, v in DEFAULT_SETTINGS.items():
                    STATE["settings"].setdefault(k, v)
    except Exception:
        STATE = {"nodes": {}, "tunnels": {}, "settings": dict(DEFAULT_SETTINGS)}


async def save() -> None:
    async with LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(STATE, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(FILE)


def public_settings() -> dict:
    return dict(STATE["settings"])


def _node_signing_secret() -> bytes:
    import os
    secret = os.environ.get("SECRET_KEY", "").strip()
    if secret:
        return secret.encode("utf-8")
    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    secret_file = data_dir / ".rvg_secret"
    try:
        if secret_file.exists():
            value = secret_file.read_text(encoding="utf-8").strip()
            if value:
                return value.encode("utf-8")
    except Exception:
        pass
    return b"rvg-node-secret-change-me"

def _issue_node_token(node_id: str, version: int = 1) -> str:
    payload=f"{node_id}.{int(version)}".encode("utf-8")
    sig=hmac.new(_node_signing_secret(),payload,hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload+b"."+sig).decode().rstrip("=")

def _verify_node_token(node_id: str, token: str, expected_version: int) -> bool:
    try:
        raw=base64.urlsafe_b64decode(str(token)+"="*((-len(str(token)))%4))
        prefix,version_b,sig=raw.split(b".",2)
        if prefix.decode("utf-8") != str(node_id): return False
        if int(version_b.decode("utf-8")) != int(expected_version): return False
        payload=prefix+b"."+version_b
        expected=hmac.new(_node_signing_secret(),payload,hashlib.sha256).digest()
        return hmac.compare_digest(sig,expected)
    except Exception:
        return False

def create_node(label: str) -> dict:
    node_id=secrets.token_hex(8)
    version=1
    STATE["nodes"][node_id]={
        "node_id":node_id,
        "label":label or f"Iran {node_id[:6]}",
        "credential_version":version,
        "created_at":_now(),
        "last_seen":0,
        "agent_version":"",
        "hostname":"",
        "platform":"",
        "public_ip":"",
        "applied_revision":0,
        "desired_revision":0,
    }
    return {"node_id":node_id,"token":_issue_node_token(node_id,version),"label":STATE["nodes"][node_id]["label"]}

def rotate_node_token(node_id: str) -> str:
    node=STATE["nodes"].get(node_id)
    if not node: raise ValueError("node not found")
    version=int(node.get("credential_version",1))+1
    node["credential_version"]=version
    return _issue_node_token(node_id,version)

def auth_node(node_id: str, token: str) -> dict | None:
    node=STATE["nodes"].get(node_id)
    if not node:
        return None
    version=int(node.get("credential_version",1))
    if _verify_node_token(node_id, token, version):
        return node
    legacy_hash=str(node.get("token_hash","") or "")
    if legacy_hash and hmac.compare_digest(legacy_hash, _token_hash(token)):
        return node
    return None


def node_snapshot(node_id: str) -> dict:
    tunnels = [dict(t) for t in STATE["tunnels"].values() if t.get("node_id") == node_id and t.get("enabled", True)]
    return {
        "revision": int(STATE["nodes"][node_id].get("desired_revision", 0)),
        "server": {
            "host": STATE["settings"].get("server_public_host") or __import__("os").environ.get("RATHOLE_PUBLIC_HOST", ""),
            "port": int(STATE["settings"].get("server_public_port") or STATE["settings"]["server_bind_port"]),
        },
        "settings": public_settings(),
        "tunnels": tunnels,
    }


def touch_node(node_id: str, meta: dict) -> None:
    node = STATE["nodes"].get(node_id)
    if not node:
        return
    node.update({
        "last_seen": _now(),
        "agent_version": str(meta.get("agent_version", ""))[:64],
        "hostname": str(meta.get("hostname", ""))[:128],
        "platform": str(meta.get("platform", ""))[:128],
        "public_ip": str(meta.get("public_ip", ""))[:64],
        "rathole_client_active": bool(meta.get("rathole_client_active", False)),
        "applied_revision": int(meta.get("applied_revision", node.get("applied_revision", 0))),
    })


def bump_node(node_id: str) -> None:
    if node_id in STATE["nodes"]:
        STATE["nodes"][node_id]["desired_revision"] = int(STATE["nodes"][node_id].get("desired_revision", 0)) + 1


def add_tunnel(node_id: str, name: str, local_host: str, local_port: int, public_port: int, nodelay: bool = True,
               protocol: str = "tcp", websocket_path: str = "/") -> dict:
    if node_id not in STATE["nodes"]:
        raise ValueError("node not found")
    if not (1 <= int(local_port) <= 65535 and 1 <= int(public_port) <= 65535):
        raise ValueError("invalid port")
    protocol = str(protocol or "tcp").strip().lower()
    if protocol not in {"tcp", "websocket"}:
        raise ValueError("protocol must be tcp or websocket")
    websocket_path = str(websocket_path or "/").strip()
    if not websocket_path.startswith("/"):
        websocket_path = "/" + websocket_path
    if len(websocket_path) > 256:
        raise ValueError("websocket_path too long")
    used_ports = {int(t.get("public_port", -1)) for t in STATE["tunnels"].values() if t.get("enabled", True)}
    # 0 means "auto". If the requested service port is already occupied, pick the next free port.
    if int(public_port) == 0:
        public_port = 443
    if int(public_port) in used_ports:
        candidate = int(public_port) + 1
        while candidate in used_ports and candidate <= 65535:
            candidate += 1
        if candidate > 65535:
            raise ValueError("no free public port available")
        public_port = candidate
    tid = secrets.token_hex(8)
    token = secrets.token_urlsafe(24)
    STATE["tunnels"][tid] = {
        "id": tid,
        "node_id": node_id,
        "name": name or f"tunnel-{tid[:6]}",
        "local_host": local_host or "127.0.0.1",
        "local_port": int(local_port),
        "public_port": int(public_port),
        "protocol": protocol,
        "websocket_path": websocket_path if protocol == "websocket" else "",
        "token": token,
        "nodelay": bool(nodelay),
        "enabled": True,
        "created_at": _now(),
        "proxy_id": "",
        "proxy_domain": "",
        "proxy_port": 0,
        "external_host": "",
        "external_port": 0,
        "external_scheme": "",
        "external_path": "",
        "connection_status": "not-configured",
        "last_ping_ms": None,
        "last_ping_at": 0,
        "last_ping_error": "",
        "link_id": "",
        "config_domain": "",
        "origin_host": "",
        "origin_port": 443,
        "dns_mode": "manual_cname",
    }
    bump_node(node_id)
    return dict(STATE["tunnels"][tid])


def bind_external(tunnel_id: str, host: str, port: int, scheme: str = "tcp", path: str = "/") -> dict:
    t = STATE["tunnels"].get(tunnel_id)
    if not t:
        raise ValueError("tunnel not found")
    host = str(host or "").strip()
    if not host or len(host) > 253:
        raise ValueError("invalid external host")
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError("invalid external port")
    scheme = str(scheme or "tcp").strip().lower()
    if scheme not in {"tcp", "http", "https", "ws", "wss"}:
        raise ValueError("invalid external scheme")
    path = str(path or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    t["external_host"] = host
    t["external_port"] = port
    t["external_scheme"] = scheme
    t["external_path"] = path if scheme in {"ws","wss","http","https"} else ""
    t["connection_status"] = "configured"
    t["last_ping_error"] = ""
    bump_node(t["node_id"])
    return dict(t)

def record_ping(tunnel_id: str, ok: bool, latency_ms: float | None = None, error: str = "") -> dict:
    t = STATE["tunnels"].get(tunnel_id)
    if not t:
        raise ValueError("tunnel not found")
    t["last_ping_at"] = _now()
    t["last_ping_ms"] = round(float(latency_ms), 2) if latency_ms is not None else None
    t["last_ping_error"] = str(error or "")[:500]
    t["connection_status"] = "online" if ok else "error"
    return dict(t)

def delete_tunnel(tunnel_id: str) -> bool:
    t = STATE["tunnels"].pop(tunnel_id, None)
    if not t:
        return False
    bump_node(t["node_id"])
    return True


def update_settings(patch: dict) -> dict:
    allowed = {
        "server_bind_port", "public_base_port", "transport", "nodelay",
        "keepalive_secs", "keepalive_interval", "retry_interval", "heartbeat_interval",
        "cloudflare_ipv4", "cloudflare_ipv6", "cloudflare_https_only",
    }
    for k, v in patch.items():
        if k not in allowed:
            continue
        if k.endswith("port") or k in {"keepalive_secs", "keepalive_interval", "retry_interval", "heartbeat_interval"}:
            v = int(v)
        elif k in {"nodelay", "cloudflare_https_only"}:
            v = bool(v)
        elif k in {"cloudflare_ipv4", "cloudflare_ipv6"}:
            if not isinstance(v, list):
                raise ValueError(f"{k} must be a list")
            v = [str(x).strip() for x in v if str(x).strip()][:500]
        elif k == "transport":
            if v not in {"tcp"}:
                raise ValueError("transport must be tcp or noise")
        STATE["settings"][k] = v
    for nid in STATE["nodes"]:
        bump_node(nid)
    return public_settings()
