import subprocess
import sys

_PACKAGES = [
    "fastapi==0.104.1",
    "uvicorn[standard]==0.24.0",
    "uvloop>=0.19.0",
    "httptools>=0.6.0",
    "httpx[http2]==0.25.1",
    "websockets==12.0",
    "aiofiles>=23.2.1",
    "cryptography>=39.0.0",
]

def _install_packages():
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *_PACKAGES],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(f"[STARTUP] خطا در نصب پکیج‌ها:\n{e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)

# _install_packages()  # deps preinstalled for local test

import asyncio
import json
import os
import hashlib
import secrets
import sys
import time
import central
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path
import bottokentcpproxy
from protocol.mtproto import mtproto
from typing import Optional
import base64
import botgeneratedomin

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import rathole_control

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Gateway")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="RVG Gateway - codebox", docs_url=None, redoc_url=None)

# وقتی مستقیم با `python main.py` اجرا میشه، این ماژول با نام "__main__" ثبت
# میشه نه "main". چون protocol/vless/vless.py و protocol/trojan/trojan.py با
# `from main import (...)` به این فایل رفرنس می‌دن، بدون این خط پایتون مجبور
# میشه کل main.py رو یک‌بار دیگه از صفر به‌عنوان ماژول جداگانه‌ی "main" اجرا کنه
# که باعث circular import و کرش میشه. با alias کردن sys.modules، هر دو اسم
# به همین نمونه‌ی در حال اجرا اشاره می‌کنن.
sys.modules.setdefault("main", sys.modules[__name__])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "rvg_state.json"
SECRET_FILE = DATA_DIR / ".rvg_secret"
SAVE_LOCK = asyncio.Lock()


def _get_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            val = SECRET_FILE.read_text(encoding="utf-8").strip()
            if val:
                return val
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        logger.info("SECRET_KEY جدید ساخته و در دیسک ذخیره شد (پایدار بین ری‌استارت‌ها).")
        return new_secret
    except Exception as e:
        logger.warning(f"عدم امکان ذخیره‌ی SECRET_KEY روی دیسک: {e} — از مقدار موقت استفاده می‌شود.")
        return secrets.token_urlsafe(32)


def get_host_scheme():
    return "https" if os.environ.get("RAILWAY_PUBLIC_DOMAIN") else "http"

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _get_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}


async def load_state():
    global LINKS, AUTH, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            NODE_KEYS.update(data.get("node_keys", {}))
            for nid, n in (data.get("nodes") or {}).items():
                NODES[nid] = _normalize_node(n)
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            logger.info(
                f"State loaded: {len(LINKS)} links, {len(SUBS)} subs, "
                f"{len(NODES)} nodes, {len(NODE_KEYS)} node keys"
            )
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "node_keys": dict(NODE_KEYS),
                "nodes": dict(NODES),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")


# ── Debounced save ─────────────────────────────────────────────────────────────
# هر بار که یک کانکشن (trojan/vless/shadowsocks/xhttp) بسته میشه، schedule_save()
# صدا زده میشه به‌جای save_state() مستقیم. اگه صدها کانکشن در ثانیه باز و بسته بشن
# (که برای WebSocket-based transportها عادیه)، save_state() قبلی باعث میشد به همون
# تعداد، کل state سریالایز و روی دیسک نوشته بشه و event loop تک‌هسته‌ای رو مسدود کنه.
# اینجا چندین درخواست ذخیره‌سازی که در بازه‌ی SAVE_DEBOUNCE_SECONDS اتفاق بیفتن،
# در یک نوشتن واحد روی دیسک ادغام میشن.
SAVE_DEBOUNCE_SECONDS = 2.0
_save_pending = False
_save_dirty_again = False


async def schedule_save():
    """نسخه‌ی debounce شده‌ی save_state — برای صدا زدن مکرر و پرتعداد (هر بسته شدن کانکشن) امن است."""
    global _save_pending, _save_dirty_again
    if _save_pending:
        _save_dirty_again = True
        return
    _save_pending = True
    try:
        while True:
            _save_dirty_again = False
            await asyncio.sleep(SAVE_DEBOUNCE_SECONDS)
            await save_state()
            if not _save_dirty_again:
                break
    finally:
        _save_pending = False

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()

# ── Node linking (اتصال چند پنل به هم) ────────────────────────────────────────
# NODE_KEYS: کلیدهایی که *این* پنل صادر کرده. هر کلید به یک پنل دیگه اجازه میده
#            دیتای این پنل رو بخونه و روی کانفیگ‌هاش بنویسه (سمت inbound).
# NODES:     پنل‌هایی که *این* پنل بهشون وصل شده و دیتاشون رو ادغام می‌کنه (سمت outbound).
NODE_KEYS: dict = {}
NODE_KEYS_LOCK = asyncio.Lock()
NODES: dict = {}
NODES_LOCK = asyncio.Lock()
_NODE_CACHE: dict = {}          # node_id -> {"at": float, "data": dict}
NODE_CACHE_TTL = 8.0
NODE_KEY_PREFIX = "rvg-"
NODE_KEY_HEADER = "X-RVG-Node-Key"
NODE_SHARE_PARTS = ("usage", "links", "subs", "requests", "logs")

PROTOCOLS = (
    "vless-ws", "xhttp-packet-up", "xhttp-stream-up",
    "trojan-ws", "trojan-xhttp-packet-up", "trojan-xhttp-stream-up",
    "mtproto", "shadowsocks",
)
DEFAULT_PROTOCOL = "vless-ws"

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })


# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "rvg_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "123456"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    asyncio.create_task(central.heartbeat_loop())
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    await _restart_mtproto_instances()
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"RVG Gateway v9.2 started on port {CONFIG['port']}")

async def _restart_mtproto_instances():
    async with LINKS_LOCK:
        targets = [
            (uid, d) for uid, d in LINKS.items()
            if d.get("protocol") == "mtproto" and d.get("active", True)
        ]
    for uid, d in targets:
        try:
            inst = await mtproto.start_instance(
                uid,
                secret=d.get("mtproto_secret"),
                domain=d.get("mtproto_domain", mtproto.DEFAULT_FAKE_TLS_DOMAIN),
                preferred_port=d.get("mtproto_port"),
                force_port=d.get("mtproto_manual_port", False),
                ad_tag=d.get("ad_tag"),
            )
            old_port = d.get("mtproto_port")
            async with LINKS_LOCK:
                LINKS[uid]["mtproto_port"] = inst["port"]
                LINKS[uid]["mtproto_secret"] = inst["secret"]

            if (d.get("mtproto_proxy_id") and inst["port"] != old_port
                    and not d.get("mtproto_manual_port", False)):
                asyncio.create_task(_reattach_mtproto_public_proxy(
                    uid, inst["port"], d.get("mtproto_proxy_id"), d.get("label", "")
                ))
        except Exception as exc:
            logger.error(f"ری‌استارت خودکار MTProto ناموفق برای {uid[:8]}: {exc}")

async def _mtproto_usage_callback(uuid: str, n_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n_bytes
        stats["total_bytes"] += n_bytes
        hourly_traffic[now_ir().strftime("%H:00")] += n_bytes
    return True

mtproto.set_usage_callback(_mtproto_usage_callback)

async def _attach_mtproto_public_proxy(uid: str, application_port: int, label: str):
    try:
        pub = await bottokentcpproxy.create_public_proxy_for_port(application_port)
    except Exception as exc:
        logger.warning(f"TCP Proxy عمومی برای {uid[:8]} ناموفق بود: {exc}")
        async with LINKS_LOCK:
            if uid in LINKS:
                LINKS[uid]["mtproto_public_pending"] = False
        log_activity("link", f"ساخت TCP Proxy عمومی برای «{label}» ناموفق بود: {exc}", "err")
        return
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["mtproto_public_host"] = pub["domain"]
            LINKS[uid]["mtproto_public_port"] = pub["port"]
            LINKS[uid]["mtproto_proxy_id"] = pub["id"]
            LINKS[uid]["mtproto_public_pending"] = False
    asyncio.create_task(save_state())
    log_activity("link", f"TCP Proxy عمومی «{label}» آماده شد ({pub['domain']}:{pub['port']})", "ok")

async def _reattach_mtproto_public_proxy(uid: str, new_port: int, old_proxy_id: Optional[str], label: str):
    if old_proxy_id:
        await bottokentcpproxy.delete_public_proxy(old_proxy_id)
    await _attach_mtproto_public_proxy(uid, new_port, label)

# ===== تابع جدید برای به‌روزرسانی ad_tag روی پروکسی =====
async def _update_mtproto_ad_tag(uuid: str, ad_tag: str):
    try:
        # اسنپ‌شات اولیه‌ی لینک قبل از هر کاری - برای مقایسه‌ی پورت قدیم/جدید لازم است
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link:
                return
            old_port = link.get("mtproto_port")
            old_proxy_id = link.get("mtproto_proxy_id")
            manual_port = link.get("mtproto_manual_port", False)
            label = link.get("label", "")
            secret = link.get("mtproto_secret")
            domain = link.get("mtproto_domain", mtproto.DEFAULT_FAKE_TLS_DOMAIN)

        await mtproto.stop_instance(uuid)

        try:
            # force_port=True همیشه: چون تازه instance رو stop کردیم، پورت قدیمی
            # قطعاً باید آزاد باشه. اگر force_port=False بذاریم و پورت به هر دلیلی
            # (مثلاً TIME_WAIT) هنوز آزاد نشده بود، mtg یک پورت داخلی جدید و تصادفی
            # انتخاب می‌کند و TCP Proxy عمومی روی Railway (که آدرسش را کاربر در
            # @MTProxybot ثبت کرده) دیگر به mtg جدید اشاره نمی‌کند — دقیقاً همین
            # چیزی بود که باعث می‌شد تبلیغ (ad_tag) کار نکند.
            inst = await mtproto.start_instance(
                uuid,
                secret=secret,
                domain=domain,
                preferred_port=old_port,
                force_port=True,
                ad_tag=ad_tag,
            )
        except RuntimeError as exc:

            logger.warning(
                f"MTProto[{uuid[:8]}]: گرفتن دوباره‌ی پورت قبلی {old_port} برای "
                f"ad_tag ناموفق بود ({exc})، تلاش با پورت جدید..."
            )
            inst = await mtproto.start_instance(
                uuid,
                secret=secret,
                domain=domain,
                preferred_port=None,
                force_port=False,
                ad_tag=ad_tag,
            )

        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link:
                # لینک در حین ری‌استارت حذف شده؛ instance تازه‌ساز را متوقف کن
                asyncio.create_task(mtproto.stop_instance(uuid))
                return
            link["mtproto_port"] = inst["port"]
            link["mtproto_secret"] = inst["secret"]
            link["mtproto_domain"] = inst["domain"]
            link["ad_tag"] = ad_tag
            link["ad_tag_status"] = "done"
            link["ad_tag_link"] = generate_share_link(
                uuid, get_host(), remark=public_link_label(uuid, link), protocol="mtproto"
            )

        if old_proxy_id and inst["port"] != old_port and not manual_port:
            asyncio.create_task(_reattach_mtproto_public_proxy(
                uuid, inst["port"], old_proxy_id, label
            ))

        asyncio.create_task(save_state())
        logger.info(
            f"MTProto[{uuid[:8]}]: ad_tag به‌روز شد، instance ری‌استارت شد "
            f"(port={inst['port']}, تغییر پورت={inst['port'] != old_port})"
        )
        log_activity("link", f"تبلیغ کانال برای «{label}» با موفقیت اعمال شد", "ok")

    except Exception as exc:
        logger.error(f"خطا در به‌روزرسانی ad_tag برای {uuid[:8]}: {exc}")
        async with LINKS_LOCK:
            if uuid in LINKS:
                LINKS[uuid]["active"] = False
                LINKS[uuid]["ad_tag_status"] = "error"
        log_activity("link", f"به‌روزرسانی ad_tag برای «{LINKS.get(uuid,{}).get('label','')}» ناموفق بود", "err")
        asyncio.create_task(save_state())


@app.on_event("shutdown")
async def shutdown():
    await save_state()
    await mtproto.stop_all()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
_LEGACY_DEFAULT_LABELS = {
    "", "rvg", "rvg subscription", "rvg-all", "configuration", "config",
    "link", "new link", "لینک جدید", "کانفیگ", "کانفیگ جدید", "گروه جدید",
}


def default_public_label(seed: str) -> str:
    """Return a stable seven-character lowercase identifier for a user/profile."""
    digest = hashlib.sha256(str(seed).encode("utf-8")).digest()
    return "".join(_LABEL_ALPHABET[byte % len(_LABEL_ALPHABET)] for byte in digest[:7])


def clean_public_label(value: object, seed: str) -> str:
    """Keep custom names, but remove legacy RVG branding and fill empty names safely."""
    label = str(value or "").strip()
    lowered = label.lower()
    if lowered.startswith("rvg-"):
        label = label[4:].strip()
    elif lowered.startswith("rvg "):
        label = label[4:].strip()
    if not label or label.lower() in _LEGACY_DEFAULT_LABELS:
        return default_public_label(seed)
    return label[:60]


def public_link_label(uid: str, link: dict | None = None) -> str:
    return clean_public_label((link or {}).get("label", ""), uid)


def public_announcement(value: object) -> str:
    """Return only intentional public notes, never server/account placeholder values."""
    note = str(value or "").strip()
    if note.lower() in {"", "root", "admin", "administrator", "rvg"}:
        return ""
    return note[:200]


def client_display_label(seed: str, link: dict | None = None) -> str:
    """Build the client-visible URI name: hash/name | remaining traffic | remaining time.

    V2RayNG and compatible clients display the URI fragment as the configuration
    title.  The fixed emoji delimiters keep the title compact and recognisable:
    `abcdefg|📊408.37MB|⌛35D`.
    """
    data = link or {}
    base = clean_public_label(data.get("label", ""), seed)
    limit = max(int(data.get("limit_bytes") or 0), 0)
    used = max(int(data.get("used_bytes") or 0), 0)
    # Client titles stay compact, e.g. `408.37MB`, matching the reference UI.
    remaining_volume = "∞" if limit <= 0 else fmt_bytes(max(limit - used, 0)).replace(" ", "")

    expires_at = data.get("expires_at")
    remaining_time = "∞"
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at))
            now = datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.now()
            seconds = max(0, (expiry - now).total_seconds())
            remaining_time = f"{int((seconds + 86399) // 86400)}D"
        except (TypeError, ValueError):
            remaining_time = "—"
    return f"{base}|📊{remaining_volume}|⌛{remaining_time}"


def rewrite_share_remark(uri: str, label: str) -> str:
    """Replace a URI fragment label without changing connection parameters."""
    if not uri or uri.startswith("tg://"):
        return uri
    base = uri.split("#", 1)[0]
    return f"{base}#{quote(label)}"


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def tunnel_for_link(link_id: str) -> dict | None:
    """Return the active Rathole tunnel bound to this config/link."""
    try:
        from rathole_control import STATE as RATHOLE_STATE
        for t in RATHOLE_STATE.get("tunnels", {}).values():
            if t.get("enabled", True) and str(t.get("link_id") or "") == str(link_id):
                return t
    except Exception:
        pass
    return None

def public_config_endpoint(link_id: str, fallback_host: str, fallback_port: int = 443) -> tuple[str, int]:
    """Return the host and externally reachable port for a client config.

    A custom configuration domain is only an alias for Railway's TCP proxy;
    Railway assigns the public port independently of the internal Rathole
    service port. Publishing both values prevents generated 3x-ui-compatible
    links from silently reverting to ``:443`` after a tunnel is attached.
    """
    t = tunnel_for_link(link_id)
    configured_host = str((t or {}).get("config_domain") or "").strip().rstrip(".")
    railway_host = str((t or {}).get("proxy_domain") or "").strip().rstrip(".")
    published_port = int((t or {}).get("proxy_port") or 0)
    return configured_host or railway_host or fallback_host, published_port or int(fallback_port)


def public_config_host(link_id: str, fallback_host: str) -> str:
    """Compatibility helper for callers that need only the public host."""
    return public_config_endpoint(link_id, fallback_host)[0]


def generate_share_link(uuid: str, host: str, remark: str = "", protocol: str = DEFAULT_PROTOCOL) -> str:
    link = LINKS.get(uuid) or {}
    host, public_port = public_config_endpoint(uuid, host)
    # The client-visible title always follows the user/configuration name policy,
    # even for legacy callers that used to pass an `RVG-...` remark.
    remark = client_display_label(uuid, link) if link else clean_public_label(remark, uuid)
    alpn = link.get("alpn", "h2")
    fp = link.get("fingerprint", "chrome")

    if protocol == "mtproto":
        port = link.get("mtproto_port")
        secret = link.get("mtproto_secret")
        if not port or not secret:
            return f"tg://proxy?server={host}&port=0&secret=not_ready#{quote(remark)}"
        pub_host = link.get("mtproto_public_host")
        pub_port = link.get("mtproto_public_port")
        final_host = pub_host or host
        final_port = pub_port or public_port or port
        return f"{mtproto.generate_mtproto_link(final_host, final_port, secret).split('#', 1)[0]}#{quote(remark)}"

    if protocol == "shadowsocks":
        cipher = link.get("ss_cipher", DEFAULT_CIPHER)
        password = link.get("ss_password", "")
        return generate_ss_link(host, public_port, cipher, password, remark)

    if protocol == "trojan-ws":
        params = {
            "security": "tls", "type": "ws", "host": host,
            "path": "/trojan-ws", "sni": host, "fp": fp, "alpn": alpn,
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"trojan://{uuid}@{host}:{public_port}?{query}#{quote(remark)}"

    if protocol.startswith("trojan-xhttp-"):
        mode = protocol.replace("trojan-xhttp-", "")
        path = f"/txhttp-siz10/{mode}/{uuid}"
        params = {
            "security": "tls", "type": "xhttp", "mode": mode, "host": host,
            "path": path, "sni": host, "fp": fp, "alpn": alpn,
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"trojan://{uuid}@{host}:{public_port}?{query}#{quote(remark)}"

    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn,
        }
    else:
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn,
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{public_port}?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def build_sub_headers(label: str, used_bytes: int, limit_bytes: int, expires_at: str | None, support_url: str = "") -> dict:
    total = limit_bytes if limit_bytes > 0 else 0
    expire_ts = 0
    if expires_at:
        try:
            expire_ts = int(datetime.fromisoformat(expires_at).timestamp())
        except Exception:
            expire_ts = 0
    userinfo = f"upload=0; download={used_bytes}; total={total}; expire={expire_ts}"
    title_b64 = base64.b64encode(label.encode("utf-8")).decode()
    return {
        "profile-title": f"base64:{title_b64}",
        "subscription-userinfo": userinfo,
        "profile-update-interval": "6",
        # `profile-web-page-url` is the standard portal/Website header.  Do not
        # emit `support-url`, otherwise compatible clients label the same link
        # as Support instead of Website/Open web page.
        "profile-web-page-url": support_url,
    }

# شناسه‌های رایج User-Agent کلاینت‌های سابسکریپشن. URL واحد در مرورگر
# صفحهٔ HTML می‌دهد و برای این کلاینت‌ها همچنان feed استاندارد برمی‌گرداند.
SUBSCRIPTION_CLIENT_USER_AGENTS = (
    "v2rayng", "v2rayn", "v2box", "sing-box", "singbox", "shadowrocket",
    "clash", "mihomo", "hiddify", "nekoray", "nekobox", "surfboard",
    "stash", "loon", "quantumult", "kitsunebi", "happ", "v2raytun",
    "npvtunnel", "npv", "incy", "streisand",
)


def should_render_subscription_page(request: Request) -> bool:
    """Return True only for an actual browser navigation to a subscription URL.

    Some clients use generic clients such as okhttp and therefore do not expose
    a product-specific User-Agent.  Browser document headers are a safer signal;
    everything else receives the standard subscription feed.
    """
    if request.query_params.get("view", "").lower() in {"raw", "text", "base64", "subscription"}:
        return False
    user_agent = request.headers.get("User-Agent", "").lower()
    if any(client in user_agent for client in SUBSCRIPTION_CLIENT_USER_AGENTS):
        return False
    accept = request.headers.get("Accept", "").lower()
    fetch_destination = request.headers.get("Sec-Fetch-Dest", "").lower()
    if fetch_destination and fetch_destination != "document":
        return False
    # A normal URL bar navigation advertises HTML. Subscription clients commonly
    # advertise */*, text/plain, application/json, or no Accept header at all.
    return "text/html" in accept


def build_3x_sub_page_data(
    *,
    subscription_id: str,
    label: str,
    host: str,
    enabled: bool,
    used_bytes: int,
    limit_bytes: int,
    expires_at: str | None,
    links: list[str],
    emails: list[str] | None = None,
    is_online: bool = False,
    announcement: str = "",
    base_path: str = "/sub",
) -> dict:
    """Build the `window.__SUB_PAGE_DATA__` view model used by 3x-ui SubPage.

    RVG keeps this view model beside its API response so the public page, the
    browser and external integrations agree on one subscription state.
    """
    expire_epoch = 0
    if expires_at:
        try:
            expire_epoch = int(datetime.fromisoformat(expires_at).timestamp())
        except (TypeError, ValueError):
            expire_epoch = 0
    upload_bytes = 0
    remained_bytes = max(limit_bytes - used_bytes, 0) if limit_bytes > 0 else 0
    sub_url = f"https://{host}{base_path}/{subscription_id}"
    return {
        "host": host,
        "basePath": base_path,
        "sId": subscription_id,
        "enabled": enabled,
        "isOnline": is_online,
        "download": fmt_bytes(used_bytes),
        "upload": fmt_bytes(upload_bytes),
        "total": fmt_bytes(limit_bytes) if limit_bytes > 0 else "∞",
        "used": fmt_bytes(used_bytes),
        "remained": fmt_bytes(remained_bytes) if limit_bytes > 0 else "",
        "expire": expire_epoch,
        "lastOnline": 0,
        "datepicker": "gregorian",
        "downloadByte": used_bytes,
        "uploadByte": upload_bytes,
        "usedByte": used_bytes,
        "totalByte": limit_bytes,
        "subUrl": sub_url,
        "subFeedUrl": f"{sub_url}?view=raw",
        "subJsonUrl": "",
        "subClashUrl": "",
        "subTitle": label,
        # The same concrete subscription URL is the only public reference.
        # Keep the historical key for older consumers and expose the semantic
        # Website key for current subscription-page integrations.
        "subWebsiteUrl": sub_url,
        "subSupportUrl": sub_url,
        "announce": announcement,
        "links": links,
        "result": links,
        "emails": emails or [label for _ in links],
    }


def public_base_url(request: Request) -> str:
    configured=(os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RAILWAY_PUBLIC_BASE_URL") or "").strip()
    if configured: return configured.rstrip("/")
    proto=(request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
    host=request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"

# ── Node linking helpers ──────────────────────────────────────────────────────
def _b64u_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode().rstrip("=")


def _b64u_decode(s: str) -> str:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad).decode("utf-8")


def build_node_key(host: str, secret: str) -> str:
    """کلید خودکفا: دامنه‌ی این پنل داخل خودِ کلید کدگذاری میشه."""
    return f"{NODE_KEY_PREFIX}{_b64u_encode(host)}.{secret}"


def parse_node_key(key: str) -> tuple[str, str]:
    """برمی‌گرداند (host, secret). در صورت نامعتبر بودن ValueError می‌دهد."""
    key = (key or "").strip()
    if not key.startswith(NODE_KEY_PREFIX):
        raise ValueError("کلید باید با rvg- شروع شود")
    body = key[len(NODE_KEY_PREFIX):]
    if "." not in body:
        raise ValueError("ساختار کلید نامعتبر است")
    host_part, secret = body.split(".", 1)
    if not secret:
        raise ValueError("بخش سکرت کلید خالی است")
    try:
        host = _b64u_decode(host_part).strip()
    except Exception:
        raise ValueError("دامنه‌ی داخل کلید قابل خواندن نیست")
    if not host or "/" in host or " " in host:
        raise ValueError("دامنه‌ی داخل کلید نامعتبر است")
    return host, secret


def _node_scheme(host: str) -> str:
    # فقط برای تست محلی http مجاز است؛ در بقیه‌ی موارد اجباراً https
    return "http" if host.startswith(("localhost", "127.0.0.1")) else "https"


def _normalize_node(n: dict) -> dict:
    share = n.get("share") or {}
    return {
        "label": str(n.get("label") or n.get("host") or "نود")[:60],
        "host": str(n.get("host") or ""),
        "key": str(n.get("key") or ""),
        "enabled": bool(n.get("enabled", True)),
        "merge_dashboard": bool(n.get("merge_dashboard", True)),
        "share": {p: bool(share.get(p, p != "logs")) for p in NODE_SHARE_PARTS},
        "created_at": n.get("created_at") or datetime.now().isoformat(),
        "last_sync_at": n.get("last_sync_at"),
        "last_error": n.get("last_error"),
        "peer_version": n.get("peer_version"),
    }


def _node_public(node_id: str, n: dict) -> dict:
    """نسخه‌ی امن برای فرانت‌اند — کلید خام بیرون نمی‌رود."""
    out = {k: v for k, v in n.items() if k != "key"}
    out["node_id"] = node_id
    out["key_preview"] = (n.get("key") or "")[:14] + "…"
    return out


async def _node_request(node: dict, method: str, path: str, *,
                        params: dict | None = None,
                        json_body: dict | None = None,
                        timeout: float = 10.0) -> httpx.Response:
    host = node["host"]
    url = f"{_node_scheme(host)}://{host}{path}"
    client = http_client or httpx.AsyncClient()
    return await client.request(
        method, url,
        params=params, json=json_body,
        headers={NODE_KEY_HEADER: node["key"]},
        timeout=timeout, follow_redirects=False,
    )


async def require_node_key(request: Request) -> str:
    """احراز هویت پنل مقابل با هدر X-RVG-Node-Key (بدون کوکی سشن)."""
    raw = (request.headers.get(NODE_KEY_HEADER) or "").strip()
    if not raw:
        raise HTTPException(status_code=401, detail="node key missing")
    try:
        _, secret = parse_node_key(raw)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid node key")
    matched = None
    async with NODE_KEYS_LOCK:
        for key_id, entry in NODE_KEYS.items():
            if entry.get("revoked"):
                continue
            if secrets.compare_digest(str(entry.get("secret", "")), secret):
                matched = key_id
                break
        if matched is None:
            raise HTTPException(status_code=401, detail="unknown or revoked node key")
        entry = NODE_KEYS[matched]
        entry["last_used_at"] = datetime.now().isoformat()
        entry["use_count"] = int(entry.get("use_count", 0)) + 1
    asyncio.create_task(schedule_save())
    return matched

# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                }
                asyncio.create_task(save_state())
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "Subscription Gateway", "version": "9.2", "status": "active", "channel": ""}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription (single link) ────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link:
        raise HTTPException(status_code=404, detail="not found")

    host = get_host()
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    display_label = public_link_label(uuid, link)
    subscription_url = f"https://{host}/sub/{uuid}"
    vless = generate_share_link(uuid, host, remark=display_label, protocol=proto)
    active = is_link_allowed(link)
    active_connections = sum(1 for connection in connections.values() if connection.get("uuid") == uuid)
    page_data = build_3x_sub_page_data(
        subscription_id=uuid,
        label=display_label,
        host=host,
        enabled=active,
        used_bytes=int(link.get("used_bytes") or 0),
        limit_bytes=int(link.get("limit_bytes") or 0),
        expires_at=link.get("expires_at"),
        links=[vless],
        emails=[display_label],
        is_online=active_connections > 0,
        announcement=public_announcement(link.get("note", "")),
    )

    # این همان URLی است که کاربر از پنل کپی می‌کند. در مرورگر صفحهٔ پروداکشن
    # نمایش داده می‌شود؛ در کلاینت‌های VPN feed قدیمی بدون تغییر باقی می‌ماند.
    if should_render_subscription_page(request):
        from subscription_page import get_public_page_html
        return HTMLResponse(content=get_public_page_html(uuid, subscription_type="single", page_data=page_data))

    if not active:
        raise HTTPException(status_code=404, detail="not found or inactive")
    content = base64.b64encode(vless.encode()).decode()
    client_title = client_display_label(uuid, link)
    headers = build_sub_headers(client_title, link.get("used_bytes", 0), link.get("limit_bytes", 0), link.get("expires_at"), subscription_url)
    return Response(content=content, media_type="text/plain", headers=headers)

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK:
        allowed = [d for d in LINKS.values() if is_link_allowed(d)]
        lines = [
            generate_share_link(uid, host, remark=public_link_label(uid, d), protocol=d.get("protocol", DEFAULT_PROTOCOL))
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
        total_used = sum(d.get("used_bytes", 0) for d in allowed)
        total_limit = sum(d.get("limit_bytes", 0) for d in allowed)
        expiries = [d["expires_at"] for d in allowed if d.get("expires_at")]
    nearest_exp = min(expiries) if expiries else None
    content = base64.b64encode("\n".join(lines).encode()).decode()
    headers = build_sub_headers("all-configurations", total_used, total_limit, nearest_exp, f"https://{host}/sub-all")
    return Response(content=content, media_type="text/plain", headers=headers)

# ══════════════════════════════════════════════════════════════════════════════
# SUB GROUP endpoints (بدون تغییر)
# ══════════════════════════════════════════════════════════════════════════════

async def _create_sub_core(body: dict) -> dict:
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    # Empty group names receive the same stable, lowercase seven-letter policy.
    name = clean_public_label(body.get("name"), sub_id)
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
            "node_link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    return await _create_sub_core(body)

@app.post("/api/node/subs")
async def node_create_sub(request: Request, key_id: str = Depends(require_node_key)):
    await _require_node_manage(key_id)
    body = await request.json()
    return await _create_sub_core(body)

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    host = get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        node_link_ids = s.get("node_link_ids", [])
        foreign_links = s.get("foreign_links", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        total_used += sum(int(fl.get("used_bytes") or 0) for fl in foreign_links)
        result.append({
            "sub_id": sid,
            **s,
            "node_link_ids": node_link_ids,
            "foreign_links": foreign_links,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids) + len(node_link_ids) + len(foreign_links),
            "active_count": active_count + len(foreign_links),
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
        if "node_link_ids" in body:
            s["node_link_ids"] = [str(x) for x in body["node_link_ids"] if "::" in str(x)]
        if "foreign_links" in body:
            fl = body["foreign_links"] if isinstance(body["foreign_links"], list) else []
            clean = []
            for it in fl:
                if not isinstance(it, dict) or not it.get("vless_link"):
                    continue
                clean.append({
                    "key": str(it.get("key") or "")[:120],
                    "label": str(it.get("label") or "کانفیگ")[:60],
                    "vless_link": str(it.get("vless_link"))[:2000],
                    "used_bytes": int(it.get("used_bytes") or 0),
                    "source": str(it.get("source") or "")[:60],
                })
            s["foreign_links"] = clean
    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return {"ok": True}

# ── مدیریت گروه از راه دور (توسط پنل مرکزی روی این نود) ──────────────────────
@app.patch("/api/node/subs/{sub_id}")
async def node_update_sub(sub_id: str, request: Request, key_id: str = Depends(require_node_key)):
    peer = await _require_node_manage(key_id)
    result = await update_sub(sub_id, request, None)
    log_activity("node", f"گروه {sub_id[:8]} از راه دور توسط «{peer}» ویرایش شد", "warn")
    return result

@app.delete("/api/node/subs/{sub_id}")
async def node_delete_sub(sub_id: str, key_id: str = Depends(require_node_key)):
    peer = await _require_node_manage(key_id)
    result = await delete_sub(sub_id, None)
    log_activity("node", f"گروه {sub_id[:8]} از راه دور توسط «{peer}» حذف شد", "err")
    return result

@app.post("/api/node/subs/{sub_id}/links")
async def node_assign_link_to_sub(sub_id: str, request: Request, key_id: str = Depends(require_node_key)):
    await _require_node_manage(key_id)
    return await assign_link_to_sub(sub_id, request, None)

# ── Public sub-group subscription file ───────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    # یک URL واحد برای کاربر و کلاینت نگه می‌داریم: مرورگر صفحهٔ پروفایل را می‌بیند،
    # اما اپلیکیشن‌های VPN همان feed استاندارد Base64 را دریافت می‌کنند.
    if should_render_subscription_page(request):
        from subscription_page import get_public_page_html
        return HTMLResponse(content=get_public_page_html(uuid_key))

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")
    host = get_host()
    link_ids = sub.get("link_ids", [])
    node_link_ids = sub.get("node_link_ids", [])
    async with LINKS_LOCK:
        lines = []
        allowed_links = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                lines.append(generate_share_link(lid, host, remark=public_link_label(lid, link), protocol=link.get("protocol", DEFAULT_PROTOCOL)))
                allowed_links.append(link)
        total_used = sum(l.get("used_bytes", 0) for l in allowed_links)
        total_limit = sum(l.get("limit_bytes", 0) for l in allowed_links)
        expiries = [l["expires_at"] for l in allowed_links if l.get("expires_at")]
    if node_link_ids:
        async with NODES_LOCK:
            nodes_snap = {nid: dict(n) for nid, n in NODES.items()}
        needed_nodes = list({ref.split("::", 1)[0] for ref in node_link_ids if "::" in ref})
        needed_nodes = [nid for nid in needed_nodes if nid in nodes_snap]
        snapshots = await asyncio.gather(
            *(_fetch_node_snapshot(nid, nodes_snap[nid], fresh=True) for nid in needed_nodes),
            return_exceptions=True,
        )
        snap_by_node = dict(zip(needed_nodes, snapshots))
        for ref in node_link_ids:
            if "::" not in ref:
                continue
            nid, uid = ref.split("::", 1)
            snap = snap_by_node.get(nid)
            if not snap or isinstance(snap, Exception):
                continue
            node_link = next((l for l in (snap.get("links") or []) if l.get("uuid") == uid), None)
            if not node_link or not node_link.get("vless_link"):
                continue
            if not node_link.get("active", True):
                continue
            if node_link.get("expired"):
                continue
            lb = node_link.get("limit_bytes", 0)
            if lb > 0 and node_link.get("used_bytes", 0) >= lb:
                continue
            node_label = client_display_label(uid, node_link)
            lines.append(rewrite_share_remark(node_link["vless_link"], node_label))
            total_used += node_link.get("used_bytes", 0)
            total_limit += node_link.get("limit_bytes", 0)
            if node_link.get("expires_at"):
                expiries.append(node_link["expires_at"])
    for fl in sub.get("foreign_links", []):
        vl = fl.get("vless_link")
        if not vl:
            continue
        foreign_label = client_display_label(str(fl.get("key") or vl), fl)
        lines.append(rewrite_share_remark(vl, foreign_label))
        total_used += int(fl.get("used_bytes") or 0)
    nearest_exp = min(expiries) if expiries else None
    content = base64.b64encode("\n".join(lines).encode()).decode()
    group_label = clean_public_label(sub.get("name"), uuid_key)
    group_url = f"https://{host}/sub-group/{uuid_key}"
    group_client_title = client_display_label(uuid_key, {"label": group_label, "used_bytes": total_used, "limit_bytes": total_limit, "expires_at": nearest_exp})
    headers = build_sub_headers(group_client_title, total_used, total_limit, nearest_exp, group_url)
    return Response(content=content, media_type="text/plain", headers=headers)

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}
# ── Backup / Restore ──────────────────────────────────────────────────────────
@app.get("/api/backup/export")
async def backup_export(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links_snap = dict(LINKS)
    async with SUBS_LOCK:
        subs_snap = dict(SUBS)
    async with NODE_KEYS_LOCK:
        node_keys_snap = dict(NODE_KEYS)
    async with NODES_LOCK:
        nodes_snap = dict(NODES)
    data = {
        "kind": "rvg-backup",
        "version": "9.2",
        "exported_at": datetime.now().isoformat(),
        "host": get_host(),
        "links": links_snap,
        "subs": subs_snap,
        "node_keys": node_keys_snap,
        "nodes": nodes_snap,
        "password_hash": AUTH["password_hash"],
    }
    content = json.dumps(data, ensure_ascii=False, indent=2)
    filename = f"rvg-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    log_activity("system", "فایل بکاپ دانلود شد", "info")
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/backup/import")
async def backup_import(request: Request, _=Depends(require_auth)):
    body = await request.json()
    data = body.get("data")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="فایل بکاپ نامعتبر است")

    new_links = data.get("links")
    new_subs = data.get("subs")
    new_pw_hash = data.get("password_hash")
    keep_password = bool(body.get("keep_current_password", True))

    if not isinstance(new_links, dict) or not isinstance(new_subs, dict):
        raise HTTPException(status_code=400, detail="ساختار فایل بکاپ نامعتبر است")

    # همه‌ی instance های فعلی MTProto رو متوقف کن قبل از جایگزینی
    try:
        await mtproto.stop_all()
    except Exception as exc:
        logger.warning(f"توقف MTProto قبل از ایمپورت ناموفق بود: {exc}")

    async with LINKS_LOCK:
        LINKS.clear()
        LINKS.update(new_links)
    async with SUBS_LOCK:
        SUBS.clear()
        SUBS.update(new_subs)

    # نودها و کلیدهای نود اختیاری‌اند (بکاپ‌های قدیمی این کلیدها را ندارند)
    new_node_keys = data.get("node_keys")
    if isinstance(new_node_keys, dict):
        async with NODE_KEYS_LOCK:
            NODE_KEYS.clear()
            NODE_KEYS.update(new_node_keys)
    new_nodes = data.get("nodes")
    if isinstance(new_nodes, dict):
        async with NODES_LOCK:
            NODES.clear()
            for nid, n in new_nodes.items():
                if isinstance(n, dict):
                    NODES[nid] = _normalize_node(n)
        _NODE_CACHE.clear()

    if not keep_password and new_pw_hash:
        AUTH["password_hash"] = new_pw_hash
        async with SESSIONS_LOCK:
            SESSIONS.clear()
            # سشن فعلی رو نگه می‌داریم که کاربر لاگ‌اوت نشه
            token = request.cookies.get(SESSION_COOKIE)
            if token:
                SESSIONS[token] = time.time() + SESSION_TTL

    await save_state()

    try:
        await _restart_mtproto_instances()
    except Exception as exc:
        logger.error(f"راه‌اندازی مجدد MTProto بعد از ایمپورت ناموفق بود: {exc}")

    log_activity("system", "بکاپ با موفقیت روی پنل بازیابی شد", "ok")
    return {"ok": True, "links_count": len(LINKS), "subs_count": len(SUBS), "nodes_count": len(NODES)}
    

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
    }

@app.post("/api/bot-tcp-proxy/start")
async def api_bot_tcp_proxy_start(request: Request, _=Depends(require_auth)):
    body = await request.json()
    token = str(body.get("token", "")).strip()
    port = int(body.get("port") or CONFIG["port"])
    mode = str(body.get("mode") or "blacklist")
    target_domains = body.get("target_domains") or []
    extra_blacklist_domains = body.get("extra_blacklist_domains") or []
    try:
        bottokentcpproxy.start_job(
            token, port, mode=mode,
            target_domains=target_domains,
            extra_blacklist_domains=extra_blacklist_domains,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    log_activity(
        "system",
        "ساخت TCP Proxy" + (" (جستجوی دامنه‌ی دلخواه)" if mode == "whitelist" else " (بلک‌لیست)") + " آغاز شد",
        "info",
    )
    return {"ok": True}

@app.post("/api/bot-tcp-proxy/stop")
async def api_bot_tcp_proxy_stop(_=Depends(require_auth)):
    stopped = bottokentcpproxy.stop_job()
    if stopped:
        log_activity("system", "ساخت TCP Proxy ربات متوقف شد", "warn")
    return {"ok": True, "stopped": stopped}

@app.get("/api/bot-tcp-proxy/status")
async def api_bot_tcp_proxy_status(_=Depends(require_auth)):
    return bottokentcpproxy.get_status()


@app.post("/api/domain-gen/start")
async def api_domain_gen_start(request: Request, _=Depends(require_auth)):
    body = await request.json()
    token = str(body.get("token", "")).strip()
    port = int(body.get("port") or CONFIG["port"])
    count = int(body.get("count") or 10)
    try:
        botgeneratedomin.start_job(token, port, target_count=count)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    log_activity("system", f"ساخت {count} دامنه آغاز شد", "info")
    return {"ok": True}

@app.post("/api/domain-gen/stop")
async def api_domain_gen_stop(_=Depends(require_auth)):
    stopped = botgeneratedomin.stop_job()
    if stopped:
        log_activity("system", "ساخت دامنه متوقف شد", "warn")
    return {"ok": True, "stopped": stopped}

@app.get("/api/domain-gen/status")
async def api_domain_gen_status(_=Depends(require_auth)):
    return botgeneratedomin.get_status()

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections (with IP) ────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca
    for uid, link in snap.items():
        if link.get("protocol") == "mtproto":
            label = link.get("label", "نامشخص")
            for c in mtproto.get_instance_connections(uid):
                ip = c["ip"]
                g = grouped.get(ip)
                if g is None:
                    g = {
                        "ip": ip, "sessions": 0, "bytes": 0,
                        "labels": set(), "transports": set(),
                        "first_connected_at": None, "last_connected_at": None,
                    }
                    grouped[ip] = g
                g["sessions"] += 1
                g["labels"].add(label)
                g["transports"].add("mtproto")
    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)
    return {
        "connections": result,
        "count": len(result),
        "raw_count": len(connections),
    }

# ── Link Management ───────────────────────────────────────────────────────────
async def _create_link_core(body: dict) -> dict:
    # A fresh, lowercase seven-letter identifier is used when the operator leaves
    # the title empty.  A typed title remains fully editable and takes priority.
    uid = generate_uuid()
    label = clean_public_label(body.get("label"), uid)
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    alpn_val = str(body.get("alpn") or "h2,http/1.1").strip()[:60]
    fp_val = str(body.get("fingerprint") or "chrome").strip()[:20]
    if fp_val not in ("chrome", "firefox", "ios"):
        fp_val = "chrome"

    link_data = {
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "created_at": datetime.now().isoformat(),
        "alpn": alpn_val,
        "fingerprint": fp_val,
        "active": True,
        "expires_at": expires_at,
        "note": note,
        "is_default": False,
        "sub_id": sub_id,
        "protocol": protocol,
        "ad_tag": None,
    }

    if protocol == "mtproto":
        raw_port = body.get("mtproto_port")
        manual_port = int(raw_port) if raw_port not in (None, "", 0, "0") else None
        if manual_port is not None and not (1 <= manual_port <= 65535):
            raise HTTPException(status_code=400, detail="شماره پورت نامعتبر است")
        raw_domain = (body.get("mtproto_domain") or "").strip()
        domain = raw_domain if raw_domain else mtproto.DEFAULT_FAKE_TLS_DOMAIN
        try:
            inst = await mtproto.start_instance(
                uid,
                domain=domain,
                preferred_port=manual_port,
                force_port=manual_port is not None,
                ad_tag=None,
            )
        except RuntimeError as exc:
            logger.error(f"راه‌اندازی MTProto ناموفق برای {uid[:8]}: {exc}")
            raise HTTPException(status_code=409, detail=str(exc))
        except Exception as exc:
            logger.error(f"راه‌اندازی MTProto ناموفق برای {uid[:8]}: {exc}")
            raise HTTPException(status_code=502, detail=f"راه‌اندازی MTProto ناموفق: {exc}")
        link_data["mtproto_port"] = inst["port"]
        link_data["mtproto_secret"] = inst["secret"]
        link_data["mtproto_domain"] = inst["domain"]
        link_data["mtproto_manual_port"] = manual_port is not None
        if manual_port is None and bottokentcpproxy.has_saved_token():
            link_data["mtproto_public_pending"] = True
            asyncio.create_task(_attach_mtproto_public_proxy(uid, inst["port"], label))


    if protocol == "shadowsocks":
        ss_cipher = body.get("ss_cipher") or DEFAULT_CIPHER
        if ss_cipher not in CIPHERS:
            ss_cipher = DEFAULT_CIPHER
        link_data["ss_cipher"] = ss_cipher
        link_data["ss_password"] = secrets.token_urlsafe(16)
    
    async with LINKS_LOCK:
        LINKS[uid] = link_data

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_share_link(uid, host, remark=label, protocol=protocol),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    return await _create_link_core(body)

@app.post("/api/node/links")
async def node_create_link(request: Request, key_id: str = Depends(require_node_key)):
    await _require_node_manage(key_id)
    body = await request.json()
    # sub_id در اینجا به گروهِ محلیِ همین نود اشاره دارد (نه پنل مرکزی)؛ اگر معتبر نباشد نادیده گرفته می‌شود
    return await _create_link_core(body)

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        display_label = public_link_label(uid, d)
        tun = tunnel_for_link(uid)
        effective_host = public_config_host(uid, host)
        result.append({
            "uuid": uid,
            **d,
            "label": display_label,
            "protocol": proto,
            "expired": is_link_expired(d),
            "config_domain": effective_host,
            "tunnel_id": tun.get("id") if tun else "",
            "origin_host": tun.get("origin_host", "") if tun else "",
            "origin_port": tun.get("origin_port", 0) if tun else 0,
            "published_host": tun.get("proxy_domain", "") if tun else "",
            "published_port": tun.get("proxy_port", 0) if tun else 0,
            "vless_link": generate_share_link(uid, host, remark=display_label, protocol=proto),
            "sub_url": f"https://{host}/sub/{uid}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    mtproto_action = None
    new_sub = "UNCHANGED"

    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")

        if "active" in body:
            new_active = bool(body["active"])
            changed = new_active != link.get("active", True)
            link["active"] = new_active
            log_activity("link", f"کانفیگ «{label}» {'فعال' if new_active else 'غیرفعال'} شد", "ok" if new_active else "warn")
            if changed and link.get("protocol") == "mtproto":
                mtproto_action = ("start" if new_active else "stop", dict(link))

        if "label" in body:
            # Clearing a label restores the stable hash; entering a title replaces it.
            link["label"] = clean_public_label(body["label"], uid)
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "alpn" in body:
            alpn_val = str(body["alpn"]).strip()[:60]
            if alpn_val:
                link["alpn"] = alpn_val
        if "fingerprint" in body:
            fp_val = str(body["fingerprint"]).strip()
            link["fingerprint"] = fp_val if fp_val in ("chrome", "firefox", "ios") else "chrome"
        if any(k in body for k in ("label", "note", "limit_value", "expires_days", "alpn", "fingerprint")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    if mtproto_action:
        action, snap = mtproto_action
        if action == "stop":
            await mtproto.stop_instance(uid)
        else:
            try:
                old_port = snap.get("mtproto_port")
                inst = await mtproto.start_instance(
                    uid,
                    secret=snap.get("mtproto_secret"),
                    domain=snap.get("mtproto_domain", mtproto.DEFAULT_FAKE_TLS_DOMAIN),
                    preferred_port=snap.get("mtproto_port"),
                    force_port=snap.get("mtproto_manual_port", False),
                    ad_tag=snap.get("ad_tag"),
                )
                async with LINKS_LOCK:
                    if uid in LINKS:
                        LINKS[uid]["mtproto_port"] = inst["port"]
                        LINKS[uid]["mtproto_secret"] = inst["secret"]
                if (snap.get("mtproto_proxy_id") and inst["port"] != old_port
                        and not snap.get("mtproto_manual_port", False)):
                    asyncio.create_task(_reattach_mtproto_public_proxy(
                        uid, inst["port"], snap.get("mtproto_proxy_id"), snap.get("label", "")
                    ))
            except Exception as exc:
                logger.error(f"روشن کردن MTProto ناموفق برای {uid[:8]}: {exc}")
                async with LINKS_LOCK:
                    if uid in LINKS:
                        LINKS[uid]["active"] = False
                log_activity("link", f"روشن کردن پروکسی تلگرام «{label}» ناموفق بود", "err")
                asyncio.create_task(save_state())
                raise HTTPException(status_code=502, detail=f"روشن کردن پروکسی تلگرام ناموفق بود: {exc}")

    asyncio.create_task(save_state())
    return {"ok": True}
    
# ===== Endpoint جدید برای به‌روزرسانی ad_tag =====
@app.patch("/api/links/{uid}/ad-tag")
async def update_ad_tag(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    ad_tag = str(body.get("ad_tag", "")).strip()
    if not ad_tag:
        raise HTTPException(status_code=400, detail="ad_tag نمی‌تواند خالی باشد")

    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        if link.get("protocol") != "mtproto":
            raise HTTPException(status_code=400, detail="این کانفیگ MTProto نیست")
        link["ad_tag_status"] = "pending"   # ← جدید

    asyncio.create_task(_update_mtproto_ad_tag(uid, ad_tag))
    log_activity("link", f"درخواست به‌روزرسانی ad_tag برای «{link.get('label','')}» ثبت شد", "info")
    return {"ok": True, "message": "ad_tag در حال اعمال است، پروکسی ری‌استارت می‌شود"}


# اندپوینت جدید برای پول کردن وضعیت
@app.get("/api/links/{uid}/ad-tag/status")
async def get_ad_tag_status(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        return {
            "status": link.get("ad_tag_status", "idle"),
            "link": link.get("ad_tag_link"),
            "ad_tag": link.get("ad_tag"),
        }

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        proto = LINKS[uid].get("protocol")
        proxy_id = LINKS[uid].get("mtproto_proxy_id")
        del LINKS[uid]
    if proto == "mtproto":
        await mtproto.stop_instance(uid)
        if proxy_id:
            asyncio.create_task(bottokentcpproxy.delete_public_proxy(proxy_id))
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}

# ══════════════════════════════════════════════════════════════════════════════
# Node linking — inbound (این پنل صادرکننده‌ی کلید است)
# احراز هویت این بخش با هدر X-RVG-Node-Key انجام می‌شود، نه کوکی سشن.
# ══════════════════════════════════════════════════════════════════════════════
def _parse_parts(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip() in NODE_SHARE_PARTS}


@app.post("/api/node/handshake")
async def node_handshake(request: Request, key_id: str = Depends(require_node_key)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with NODE_KEYS_LOCK:
        pw_hash = (NODE_KEYS.get(key_id) or {}).get("password_hash")
    if pw_hash:
        given = str(body.get("password") or "")
        if not given:
            raise HTTPException(status_code=401, detail="PASSWORD_REQUIRED")
        if hash_password(given) != pw_hash:
            raise HTTPException(status_code=401, detail="PASSWORD_INVALID")
    peer_host = str(body.get("host") or "").strip()[:120] or client_ip(request)
    async with NODE_KEYS_LOCK:
        entry = NODE_KEYS.get(key_id)
        if entry is not None:
            first_time = not entry.get("peer_host")
            entry["peer_host"] = peer_host
            label = entry.get("label") or key_id[:8]
        else:
            first_time, label = False, key_id[:8]
    if first_time:
        log_activity("node", f"پنل «{peer_host}» با کلید «{label}» متصل شد", "ok")
    async with LINKS_LOCK:
        links_count = len(LINKS)
    async with SUBS_LOCK:
        subs_count = len(SUBS)
    return {
        "ok": True,
        "host": get_host(),
        "version": get_current_version(),
        "links_count": links_count,
        "subs_count": subs_count,
    }


@app.get("/api/node/snapshot")
async def node_snapshot(request: Request, _key_id: str = Depends(require_node_key)):
    """فقط بخش‌هایی که هم درخواست شده و هم برای این کلید مجاز است برگردانده می‌شود."""
    parts = _parse_parts(request.query_params.get("parts"))
    async with NODE_KEYS_LOCK:
        entry = NODE_KEYS.get(_key_id) or {}
        allowed = {p for p in NODE_SHARE_PARTS if (entry.get("share") or {}).get(p, p != "logs")}
    parts &= allowed
    out: dict = {"host": get_host(), "version": get_current_version(), "parts": sorted(parts)}
    if "links" in parts:
        out["links"] = (await list_links(None))["links"]
    if "subs" in parts:
        out["subs"] = (await list_subs(None))["subs"]
    if "logs" in parts:
        out["logs"] = (await get_activity(None))["logs"][-60:]
    if parts & {"usage", "requests"}:
        s = await get_stats(None)
        stats_out = {
            "uptime": s["uptime"],
            "links_count": s["links_count"],
            "active_links": s["active_links"],
            "subs_count": s["subs_count"],
        }
        if "usage" in parts:
            stats_out["total_bytes"] = stats["total_bytes"]
            stats_out["total_traffic_mb"] = s["total_traffic_mb"]
            stats_out["hourly"] = s["hourly"]
            stats_out["active_connections"] = s["active_connections"]
        if "requests" in parts:
            stats_out["total_requests"] = s["total_requests"]
            stats_out["total_errors"] = s["total_errors"]
        out["stats"] = stats_out
    return out


async def _require_node_manage(key_id: str) -> str:
    async with NODE_KEYS_LOCK:
        entry = NODE_KEYS.get(key_id) or {}
        peer = entry.get("peer_host") or "نود"
        allowed = bool(entry.get("can_manage", False))
    if not allowed:
        raise HTTPException(status_code=403, detail="این کلید اجازه‌ی ویرایش/حذف کانفیگ را ندارد")
    return peer


@app.patch("/api/node/links/{uid}")
async def node_update_link(uid: str, request: Request, key_id: str = Depends(require_node_key)):
    peer = await _require_node_manage(key_id)
    result = await update_link(uid, request, None)
    log_activity("node", f"کانفیگ {uid[:8]} از راه دور توسط «{peer}» ویرایش شد", "warn")
    return result


@app.delete("/api/node/links/{uid}")
async def node_delete_link(uid: str, key_id: str = Depends(require_node_key)):
    peer = await _require_node_manage(key_id)
    result = await delete_link(uid, None)
    log_activity("node", f"کانفیگ {uid[:8]} از راه دور توسط «{peer}» حذف شد", "err")
    return result

# ══════════════════════════════════════════════════════════════════════════════
# Node linking — outbound (این پنل به نودهای دیگر وصل می‌شود)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/nodes/keys")
async def list_node_keys(_=Depends(require_auth)):
    host = get_host()
    async with NODE_KEYS_LOCK:
        snap = dict(NODE_KEYS)
    out = []
    for key_id, e in snap.items():
        out.append({
            "key_id": key_id,
            "label": e.get("label", ""),
            "key": build_node_key(e.get("issued_host") or host, e.get("secret", "")),
            "created_at": e.get("created_at"),
            "revoked": bool(e.get("revoked")),
            "share": {p: bool((e.get("share") or {}).get(p, p != "logs")) for p in NODE_SHARE_PARTS},
            "can_manage": bool(e.get("can_manage", False)),
            "has_password": e.get("password_hash") is not None,
            "last_used_at": e.get("last_used_at"),
            "peer_host": e.get("peer_host"),
            "use_count": int(e.get("use_count", 0)),
        })
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"keys": out, "host": host}


def _node_key_share(body_share) -> dict:
    """دسترسی‌های خواندن هر کلید؛ پیش‌فرض مثل خروجی نود: همه فعال جز لاگ‌ها."""
    src = body_share if isinstance(body_share, dict) else {}
    return {p: bool(src.get(p, p != "logs")) for p in NODE_SHARE_PARTS}


@app.post("/api/nodes/keys")
async def create_node_key(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    label = (str(body.get("label") or "").strip() or f"کلید {len(NODE_KEYS) + 1}")[:60]
    share = _node_key_share(body.get("share"))
    can_manage = bool(body.get("can_manage", False))
    password = str(body.get("password") or "").strip()
    host = get_host()
    key_id = generate_uuid()
    secret = secrets.token_urlsafe(24)
    async with NODE_KEYS_LOCK:
        NODE_KEYS[key_id] = {
            "label": label,
            "secret": secret,
            "issued_host": host,
            "created_at": datetime.now().isoformat(),
            "revoked": False,
            "share": share,
            "can_manage": can_manage,
            "password_hash": hash_password(password) if password else None,
            "last_used_at": None,
            "peer_host": None,
            "use_count": 0,
        }
    asyncio.create_task(save_state())
    log_activity("node", f"کلید نود «{label}» ساخته شد", "ok")
    return {
        "ok": True, "key_id": key_id, "label": label,
        "key": build_node_key(host, secret), "share": share, "can_manage": can_manage,
    }


@app.patch("/api/nodes/keys/{key_id}")
async def update_node_key(key_id: str, request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with NODE_KEYS_LOCK:
        entry = NODE_KEYS.get(key_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="key not found")
        if "label" in body:
            entry["label"] = (str(body.get("label") or "").strip() or entry["label"])[:60]
        if "share" in body:
            cur = entry.get("share") or {}
            src = body.get("share") if isinstance(body.get("share"), dict) else {}
            entry["share"] = {p: bool(src.get(p, cur.get(p, p != "logs"))) for p in NODE_SHARE_PARTS}
        if "can_manage" in body:
            entry["can_manage"] = bool(body.get("can_manage"))
        if "password" in body:
            pw = str(body.get("password") or "").strip()
            entry["password_hash"] = hash_password(pw) if pw else None
        if "enabled" in body:
            entry["revoked"] = not bool(body.get("enabled"))
        label = entry.get("label", key_id[:8])
        revoked = entry["revoked"]
    asyncio.create_task(save_state())
    log_activity("node", f"کلید نود «{label}» {'غیرفعال شد' if revoked else 'به‌روزرسانی شد'}",
                 "warn" if revoked else "ok")
    return {"ok": True, "key_id": key_id}


@app.delete("/api/nodes/keys/{key_id}")
async def revoke_node_key(key_id: str, _=Depends(require_auth)):
    async with NODE_KEYS_LOCK:
        entry = NODE_KEYS.get(key_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="key not found")
        label = entry.get("label", key_id[:8])
        del NODE_KEYS[key_id]
    asyncio.create_task(save_state())
    log_activity("node", f"کلید نود «{label}» حذف شد", "warn")
    return {"ok": True, "revoked": key_id}


@app.get("/api/nodes/aggregate")
async def nodes_aggregate(request: Request, _=Depends(require_auth)):
    fresh = request.query_params.get("fresh") in ("1", "true", "yes")
    async with NODES_LOCK:
        snap = {nid: dict(n) for nid, n in NODES.items()}
    targets = [(nid, n) for nid, n in snap.items() if n.get("enabled", True)]
    results = await asyncio.gather(
        *(_fetch_node_snapshot(nid, n, fresh=fresh) for nid, n in targets),
        return_exceptions=True,
    )

    nodes_out: list[dict] = []
    for (nid, n), res in zip(targets, results):
        base = _node_public(nid, n)
        if isinstance(res, Exception):
            base.update({"online": False, "error": str(res)[:200]})
        else:
            base.update(res)
        nodes_out.append(base)
    for nid, n in snap.items():
        if not n.get("enabled", True):
            nodes_out.append({**_node_public(nid, n), "online": False, "error": None, "disabled": True})

    local = await get_stats(None)
    async with LINKS_LOCK:
        local_used = sum(l.get("used_bytes", 0) for l in LINKS.values())
    totals = {
        "local_used_bytes": local_used,
        "local_requests": local["total_requests"],
        "local_links": local["links_count"],
        "local_active_links": local["active_links"],
        "local_subs": local["subs_count"],
        "local_connections": local["active_connections"],
        "node_used_bytes": 0, "node_requests": 0, "node_links": 0,
        "node_active_links": 0, "node_subs": 0, "node_connections": 0,
        "nodes_total": len(snap), "nodes_online": 0,
    }
    for n in nodes_out:
        if not n.get("online"):
            continue
        totals["nodes_online"] += 1
        share = n.get("share") or {}
        st = n.get("stats") or {}
        if share.get("usage"):
            totals["node_used_bytes"] += int(st.get("total_bytes") or 0)
            totals["node_connections"] += int(st.get("active_connections") or 0)
        if share.get("requests"):
            totals["node_requests"] += int(st.get("total_requests") or 0)
        if share.get("links"):
            links = n.get("links") or []
            totals["node_links"] += len(links)
            totals["node_active_links"] += sum(1 for l in links if l.get("active") and not l.get("expired"))
        if share.get("subs"):
            totals["node_subs"] += len(n.get("subs") or [])
    totals["used_bytes"] = totals["local_used_bytes"] + totals["node_used_bytes"]
    totals["used_fmt"] = fmt_bytes(totals["used_bytes"])
    totals["node_used_fmt"] = fmt_bytes(totals["node_used_bytes"])
    totals["requests"] = totals["local_requests"] + totals["node_requests"]
    totals["links"] = totals["local_links"] + totals["node_links"]
    totals["active_links"] = totals["local_active_links"] + totals["node_active_links"]
    totals["subs"] = totals["local_subs"] + totals["node_subs"]
    totals["connections"] = totals["local_connections"] + totals["node_connections"]
    return {"nodes": nodes_out, "totals": totals}


async def _fetch_node_snapshot(node_id: str, node: dict, *, fresh: bool = False) -> dict:
    """اسنپ‌شات یک نود را با کش کوتاه‌مدت می‌گیرد. فقط بخش‌های تیک‌خورده منتقل می‌شوند."""
    share = node.get("share") or {}
    parts = sorted(p for p in NODE_SHARE_PARTS if share.get(p))
    cache_key = f"{node_id}|{','.join(parts)}"
    cached = _NODE_CACHE.get(cache_key)
    if not fresh and cached and (time.time() - cached["at"]) < NODE_CACHE_TTL:
        return cached["data"]
    if not parts:
        return {"online": True, "error": None, "stats": {}, "links": [], "subs": [], "logs": []}
    try:
        r = await _node_request(node, "GET", "/api/node/snapshot", params={"parts": ",".join(parts)})
        if r.status_code == 401:
            raise RuntimeError("کلید نود روی پنل مقابل ابطال شده است")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        payload = r.json()
    except Exception as exc:
        msg = str(exc)[:200] or exc.__class__.__name__
        async with NODES_LOCK:
            if node_id in NODES:
                NODES[node_id]["last_error"] = msg
        return {"online": False, "error": msg, "stats": {}, "links": [], "subs": [], "logs": []}

    now_iso = datetime.now().isoformat()
    async with NODES_LOCK:
        if node_id in NODES:
            NODES[node_id]["last_sync_at"] = now_iso
            NODES[node_id]["last_error"] = None
            NODES[node_id]["peer_version"] = payload.get("version")
    data = {
        "online": True,
        "error": None,
        "last_sync_at": now_iso,
        "peer_version": payload.get("version"),
        "stats": payload.get("stats") or {},
        "links": payload.get("links") or [],
        "subs": payload.get("subs") or [],
        "logs": payload.get("logs") or [],
    }
    _NODE_CACHE[cache_key] = {"at": time.time(), "data": data}
    asyncio.create_task(schedule_save())
    return data


@app.get("/api/nodes")
async def list_nodes(_=Depends(require_auth)):
    async with NODES_LOCK:
        snap = {nid: dict(n) for nid, n in NODES.items()}
    out = [_node_public(nid, n) for nid, n in snap.items()]
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"nodes": out, "count": len(out)}


@app.post("/api/nodes/connect")
async def connect_node(request: Request, _=Depends(require_auth)):
    body = await request.json()
    key = str(body.get("key") or "").strip()
    try:
        host, _secret = parse_node_key(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if host == get_host():
        raise HTTPException(status_code=400, detail="این کلید مربوط به همین پنل است")
    async with NODES_LOCK:
        for nid, n in NODES.items():
            if n.get("host") == host:
                raise HTTPException(status_code=409, detail=f"این پنل قبلاً به‌عنوان «{n.get('label')}» متصل شده است")

    node_password = str(body.get("password") or "").strip()
    candidate = {"host": host, "key": key}
    try:
        r = await _node_request(candidate, "POST", "/api/node/handshake",
                                json_body={"host": get_host(), "version": get_current_version(),
                                           "password": node_password})
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"اتصال به {host} برقرار نشد: {str(exc)[:160]}")
    if r.status_code == 401:
        detail = ""
        try:
            detail = r.json().get("detail") or ""
        except Exception:
            pass
        if detail == "PASSWORD_REQUIRED":
            raise HTTPException(status_code=401, detail="این نود رمز دارد؛ رمز را وارد کنید")
        if detail == "PASSWORD_INVALID":
            raise HTTPException(status_code=401, detail="رمز نود اشتباه است")
        raise HTTPException(status_code=401, detail="کلید توسط پنل مقابل پذیرفته نشد (ابطال‌شده یا نامعتبر)")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"پاسخ نامعتبر از {host}: HTTP {r.status_code}")
    info = r.json()

    label = (str(body.get("label") or "").strip() or info.get("host") or host)[:60]
    node_id = generate_uuid()
    node = _normalize_node({
        "label": label, "host": host, "key": key,
        "peer_version": info.get("version"),
        "last_sync_at": datetime.now().isoformat(),
    })
    async with NODES_LOCK:
        NODES[node_id] = node
    _NODE_CACHE.clear()
    asyncio.create_task(save_state())
    log_activity("node", f"به نود «{label}» ({host}) متصل شد", "ok")
    return {"ok": True, "node": _node_public(node_id, node), "peer": info}


@app.patch("/api/nodes/{node_id}")
async def update_node(node_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        if "label" in body:
            node["label"] = (str(body["label"]).strip() or node["host"])[:60]
        if "enabled" in body:
            node["enabled"] = bool(body["enabled"])
        if "merge_dashboard" in body:
            node["merge_dashboard"] = bool(body["merge_dashboard"])
        share = body.get("share")
        if isinstance(share, dict):
            for p in NODE_SHARE_PARTS:
                if p in share:
                    node["share"][p] = bool(share[p])
        snap = dict(node)
    _NODE_CACHE.clear()
    asyncio.create_task(save_state())
    return {"ok": True, "node": _node_public(node_id, snap)}


@app.delete("/api/nodes/{node_id}")
async def disconnect_node(node_id: str, _=Depends(require_auth)):
    async with NODES_LOCK:
        node = NODES.pop(node_id, None)
    if node is None:
        raise HTTPException(status_code=404, detail="node not found")
    _NODE_CACHE.clear()
    asyncio.create_task(save_state())
    log_activity("node", f"اتصال نود «{node.get('label')}» قطع شد", "warn")
    return {"ok": True, "disconnected": node_id}


async def _proxy_node_link_write(node_id: str, uid: str, method: str,
                                 json_body: dict | None = None) -> dict:
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        snap = dict(node)
    try:
        r = await _node_request(snap, method, f"/api/node/links/{uid}", json_body=json_body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"نود پاسخ نداد: {str(exc)[:160]}")
    if r.status_code >= 400:
        detail = f"HTTP {r.status_code}"
        try:
            detail = r.json().get("detail") or detail
        except Exception:
            pass
        raise HTTPException(status_code=r.status_code, detail=detail)
    _NODE_CACHE.clear()
    return r.json() if r.content else {"ok": True}


@app.post("/api/nodes/{node_id}/subs")
async def proxy_node_create_sub(node_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        snap = dict(node)
    try:
        r = await _node_request(snap, "POST", "/api/node/subs", json_body=body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"نود پاسخ نداد: {str(exc)[:160]}")
    if r.status_code >= 400:
        detail = f"HTTP {r.status_code}"
        try:
            detail = r.json().get("detail") or detail
        except Exception:
            pass
        raise HTTPException(status_code=r.status_code, detail=detail)
    _NODE_CACHE.clear()
    return r.json()


async def _proxy_node_sub_write(node_id: str, sub_id: str, method: str,
                                 json_body: dict | None = None) -> dict:
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        snap = dict(node)
    try:
        r = await _node_request(snap, method, f"/api/node/subs/{sub_id}", json_body=json_body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"نود پاسخ نداد: {str(exc)[:160]}")
    if r.status_code >= 400:
        detail = f"HTTP {r.status_code}"
        try:
            detail = r.json().get("detail") or detail
        except Exception:
            pass
        raise HTTPException(status_code=r.status_code, detail=detail)
    _NODE_CACHE.clear()
    return r.json() if r.content else {"ok": True}


@app.patch("/api/nodes/{node_id}/subs/{sub_id}")
async def proxy_node_update_sub(node_id: str, sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    return await _proxy_node_sub_write(node_id, sub_id, "PATCH", json_body=body)


@app.delete("/api/nodes/{node_id}/subs/{sub_id}")
async def proxy_node_delete_sub(node_id: str, sub_id: str, _=Depends(require_auth)):
    return await _proxy_node_sub_write(node_id, sub_id, "DELETE")


@app.post("/api/nodes/{node_id}/subs/{sub_id}/links")
async def proxy_node_assign_link_to_sub(node_id: str, sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        snap = dict(node)
    try:
        r = await _node_request(snap, "POST", f"/api/node/subs/{sub_id}/links", json_body=body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"نود پاسخ نداد: {str(exc)[:160]}")
    if r.status_code >= 400:
        detail = f"HTTP {r.status_code}"
        try:
            detail = r.json().get("detail") or detail
        except Exception:
            pass
        raise HTTPException(status_code=r.status_code, detail=detail)
    _NODE_CACHE.clear()
    return r.json() if r.content else {"ok": True}


@app.post("/api/nodes/{node_id}/links")
async def proxy_node_create_link(node_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        node = NODES.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="node not found")
        snap = dict(node)
    try:
        r = await _node_request(snap, "POST", "/api/node/links", json_body=body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"نود پاسخ نداد: {str(exc)[:160]}")
    if r.status_code >= 400:
        detail = f"HTTP {r.status_code}"
        try:
            detail = r.json().get("detail") or detail
        except Exception:
            pass
        raise HTTPException(status_code=r.status_code, detail=detail)
    _NODE_CACHE.clear()
    return r.json()


@app.patch("/api/nodes/{node_id}/links/{uid}")
async def proxy_node_update_link(node_id: str, uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    return await _proxy_node_link_write(node_id, uid, "PATCH", json_body=body)


@app.delete("/api/nodes/{node_id}/links/{uid}")
async def proxy_node_delete_link(node_id: str, uid: str, _=Depends(require_auth)):
    return await _proxy_node_link_write(node_id, uid, "DELETE")

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay
# ══════════════════════════════════════════════════════════════════════════════
from protocol.vless.vless import (
    RELAY_BUF,
    parse_vless_header,
    check_and_use,
    relay_ws_to_tcp,
    relay_tcp_to_ws,
)
from protocol.vless.websocket import websocket_tunnel

from protocol.trojan.websocket import trojan_ws_tunnel

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)
app.add_api_websocket_route("/trojan-ws", trojan_ws_tunnel)
from protocol.shadowsocks.shadowsocks import generate_ss_link, derive_key, CIPHERS, DEFAULT_CIPHER
from protocol.shadowsocks.websocket import shadowsocks_ws_tunnel
app.add_api_websocket_route("/ss-ws", shadowsocks_ws_tunnel)

# ══════════════════════════════════════════════════════════════════════════════
# XHTTP
# ══════════════════════════════════════════════════════════════════════════════
# نکته: مطابق نسخه‌ی مرجع (xhttp_siz10.py) مود stream-one حذف شده؛ فقط
# packet-up و stream-up فعال هستن. روترهای stream-one دیگه include نمی‌شن.
from protocol.vless.xhttpstreamon import router as xhttp_downlink_router
from protocol.vless.xhttpstreamup import router as xhttp_streamup_router
from protocol.vless.xhttshadpacketup import router as xhttp_packetup_router
app.include_router(xhttp_downlink_router)
app.include_router(xhttp_streamup_router)
app.include_router(xhttp_packetup_router)

from protocol.trojan.xhttpstreamon import router as trojan_xhttp_downlink_router
from protocol.trojan.xhttpstreamup import router as trojan_xhttp_streamup_router
from protocol.trojan.xhttshadpacketup import router as trojan_xhttp_packetup_router
app.include_router(trojan_xhttp_downlink_router)
app.include_router(trojan_xhttp_streamup_router)
app.include_router(trojan_xhttp_packetup_router)

# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from subscription_page import get_public_page_html
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))



@app.get("/api/public/single/{uuid}")
async def public_single_subscription_data(uuid: str):
    """Return browser-facing data for the public `/sub/{uuid}` profile page."""
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link:
        raise HTTPException(status_code=404, detail="not found")

    host = get_host()
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    display_label = public_link_label(uuid, link)
    used_bytes = int(link.get("used_bytes") or 0)
    limit_bytes = int(link.get("limit_bytes") or 0)
    active_connections = sum(1 for connection in connections.values() if connection.get("uuid") == uuid)
    vless_link = generate_share_link(uuid, host, remark=display_label, protocol=proto)
    active = is_link_allowed(link)
    page_data = build_3x_sub_page_data(
        subscription_id=uuid,
        label=display_label,
        host=host,
        enabled=active,
        used_bytes=used_bytes,
        limit_bytes=limit_bytes,
        expires_at=link.get("expires_at"),
        links=[vless_link],
        emails=[display_label],
        is_online=active_connections > 0,
        announcement=public_announcement(link.get("note", "")),
    )

    return {
        "locked": False,
        "contract_version": "3x-ui-subpage/v1",
        "subPageData": page_data,
        "subscription_id": uuid,
        "name": display_label,
        "desc": public_announcement(link.get("note", "")),
        "sub_url": f"https://{host}/sub/{uuid}",
        "total_used": used_bytes,
        "total_limit": limit_bytes,
        "expiry_date": link.get("expires_at"),
        "uploaded_bytes": 0,
        "last_online": None,
        "active_connections": active_connections,
        "links": [{
            "uuid": uuid,
            "label": display_label,
            "active": active,
            "protocol": proto,
            "used_bytes": used_bytes,
            "limit_bytes": limit_bytes,
            "expiry_date": link.get("expires_at"),
            "vless_link": vless_link,
        }],
    }


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    # ۱. احراز هویت و دریافت داده‌ها (همان منطق قبلی شما)
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = get_host()
    link_ids = sub.get("link_ids", [])
    node_link_ids = sub.get("node_link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)

    links_out = []
    active_conns = 0
    
    # ۲. ساخت لیست کانفیگ‌ها
    for lid in link_ids:
        link = snap.get(lid)
        if not link: continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": public_link_label(lid, link),
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "limit_bytes": link.get("limit_bytes", 0),
            "expiry_date": link.get("expires_at"),
            "vless_link": generate_share_link(lid, host, remark=public_link_label(lid, link), protocol=proto),
        })

    # ۲.۵ کانفیگ‌های نودهای دیگر
    if node_link_ids:
        async with NODES_LOCK:
            nodes_snap = {nid: dict(n) for nid, n in NODES.items()}
        needed_nodes = list({ref.split("::", 1)[0] for ref in node_link_ids if "::" in ref})
        needed_nodes = [nid for nid in needed_nodes if nid in nodes_snap]
        snapshots = await asyncio.gather(
            *(_fetch_node_snapshot(nid, nodes_snap[nid], fresh=True) for nid in needed_nodes),
            return_exceptions=True,
        )
        snap_by_node = dict(zip(needed_nodes, snapshots))
        for ref in node_link_ids:
            if "::" not in ref:
                continue
            nid, uid = ref.split("::", 1)
            node_snap = snap_by_node.get(nid)
            if not node_snap or isinstance(node_snap, Exception):
                continue
            node_link = next((l for l in (node_snap.get("links") or []) if l.get("uuid") == uid), None)
            if not node_link or not node_link.get("vless_link"):
                continue
            lb = node_link.get("limit_bytes", 0)
            allowed = bool(node_link.get("active", True)) and not node_link.get("expired") and not (lb > 0 and node_link.get("used_bytes", 0) >= lb)
            links_out.append({
                "uuid": nid + "::" + uid,
                "label": clean_public_label(node_link.get("label"), uid),
                "active": allowed,
                "protocol": node_link.get("protocol", DEFAULT_PROTOCOL),
                "used_bytes": node_link.get("used_bytes", 0),
                "limit_bytes": node_link.get("limit_bytes", 0),
                "expiry_date": node_link.get("expires_at"),
                "vless_link": rewrite_share_remark(node_link["vless_link"], client_display_label(uid, node_link)),
            })

    # ۲.۶ کانفیگ‌های ایستا (foreign_links) — مثلاً کانفیگ‌های پنل مرکزی که روی
    # یک نود اضافه شده‌اند؛ چون این نود به پنل مرکزی دسترسی برگشتی ندارد،
    # این کانفیگ‌ها به‌صورت اسنپ‌شات (لینک آماده) ذخیره و همینجا نمایش داده می‌شوند.
    for fl in sub.get("foreign_links", []):
        vl = fl.get("vless_link")
        if not vl:
            continue
        links_out.append({
            "uuid": fl.get("key") or vl,
            "label": clean_public_label(fl.get("label"), str(fl.get("key") or vl)),
            "active": True,
            "protocol": fl.get("protocol", DEFAULT_PROTOCOL),
            "used_bytes": fl.get("used_bytes", 0),
            "limit_bytes": 0,
            "expiry_date": fl.get("expires_at"),
            "vless_link": rewrite_share_remark(vl, client_display_label(str(fl.get("key") or vl), fl)),
        })

    # ۳. تشخیص کلاینت یا مرورگر
    user_agent = request.headers.get("User-Agent", "").lower()
    is_client = any(ua in user_agent for ua in ["v2rayng", "v2rayn", "shadowrocket", "clash", "surfboard", "nekoray"])

    if is_client:
        # اگر کلاینت است: فقط لینک‌های فعال را به صورت Base64 برگردان
        raw_links = "\n".join([l["vless_link"] for l in links_out if l["active"]])
        encoded_data = base64.b64encode(raw_links.encode("utf-8")).decode("utf-8")
        return Response(content=encoded_data, media_type="text/plain")

    # ۴. برای صفحهٔ عمومی، خلاصهٔ داده‌ها را یک‌بار در backend نیز محاسبه می‌کنیم.
    # قالب مرورگر از همین پاسخ استفاده می‌کند و همچنان برای داده‌های قدیمی سازگار می‌ماند.
    total_used = sum(int(link.get("used_bytes") or 0) for link in links_out)
    total_limit = sum(int(link.get("limit_bytes") or 0) for link in links_out if int(link.get("limit_bytes") or 0) > 0)
    expiries = [link.get("expiry_date") for link in links_out if link.get("expiry_date")]
    nearest_expiry = min(expiries) if expiries else None

    # ۵. اگر مرورگر است: دیتای کامل JSON را برگردان
    return {
        "locked": False,
        "subscription_id": uuid_key,
        "name": sub["name"],
        "desc": public_announcement(sub.get("desc", "")),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "total_used": total_used,
        "total_limit": total_limit,
        "expiry_date": nearest_expiry,
        "uploaded_bytes": 0,
        "last_online": None,
        "active_connections": active_conns,
        "links": links_out,
    }

# ══════════════════════════════════════════════════════════════════════════════
# Version / Auto-Update
# ══════════════════════════════════════════════════════════════════════════════
from updater import (
    get_current_version, get_current_version_info,
    get_latest_version_info, perform_update,
    update_log, update_state, load_update_history,
    REPO, BRANCH, is_newer_version,
)

@app.get("/api/version")
async def api_version(_=Depends(require_auth)):
    current_info = get_current_version_info()
    latest_info = await get_latest_version_info()
    latest_ver = latest_info.get("version")
    update_available = is_newer_version(latest_ver, current_info["version"]) if latest_ver else False
    return {
        "repo": REPO,
        "branch": BRANCH,
        "current": current_info,
        "latest": latest_info,
        "update_available": update_available,
    }

@app.get("/api/update-history")
async def api_update_history(_=Depends(require_auth)):
    return {"history": load_update_history()}

@app.get("/api/update-log")
async def api_update_log(_=Depends(require_auth)):
    return {"running": update_state["running"], "progress": update_state["progress"], "logs": list(update_log)[-100:]}

@app.post("/api/update")
async def api_update(_=Depends(require_auth)):
    if update_state["running"]:
        raise HTTPException(status_code=409, detail="بروزرسانی در حال اجراست")
    update_log.append({"time": time.time(), "msg": "درخواست بروزرسانی ثبت شد، در صف اجرا..."})

    async def _run():
        ok = False
        try:
            ok = await perform_update()
        except Exception as exc:
            import traceback as tb
            update_log.append({"time": time.time(), "msg": f"❌ خطای بحرانی: {exc}"})
            update_log.append({"time": time.time(), "msg": tb.format_exc()[-800:]})
            update_state["running"] = False
        try:
            await save_state()
            log_activity("system", "بروزرسانی پنل " + ("موفق" if ok else "ناموفق") + " بود", "ok" if ok else "err")
        except Exception:
            pass
        if ok:
            update_log.append({"time": time.time(), "msg": "در حال راه‌اندازی مجدد پروسه (بدون خاموش‌شدن کانتینر)..."})
            await asyncio.sleep(1.5)
            try:
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as exc:
                update_log.append({"time": time.time(), "msg": f"❌ execv شکست خورد: {exc} — fallback به exit"})
                os._exit(0)

    task = asyncio.create_task(_run())

    def _on_done(t: asyncio.Task):
        if t.cancelled():
            return
        exc = t.exception()
        if exc:
            update_log.append({"time": time.time(), "msg": f"❌ Task crash: {exc}"})
            update_state["running"] = False

    task.add_done_callback(_on_done)
    log_activity("system", "درخواست بروزرسانی پنل ثبت شد", "info")
    return {"ok": True, "started": True}


# ── Rathole control plane ─────────────────────────────────────────────────────
@app.get("/api/rathole/status")
async def rathole_status(_=Depends(require_auth)):
    from rathole_control import STATE, public_settings
    now = time.time()
    nodes = []
    for n in STATE["nodes"].values():
        x = dict(n)
        age = (now - float(x.get("last_seen", 0))) if x.get("last_seen") else None
        x["last_seen_age"] = round(age, 1) if age is not None else None
        x["online"] = bool(age is not None and age < 45)
        x.pop("token_hash", None)
        nodes.append(x)
    tunnels = [dict(t) for t in STATE["tunnels"].values()]
    for t in tunnels:
        t.pop("token", None)
    st = dict(STATE["settings"])
    control_host, control_port, control_mode = rathole_control.control_endpoint()
    return {"settings": public_settings(), "nodes": nodes, "tunnels": tunnels,
            "railway": bottokentcpproxy.railway_prerequisite_status(),
            "server": {
                "host": control_host,
                "port": int(control_port or 0),
                "control_port": int(st.get("server_bind_port")),
                "control_ready": bool(control_host and control_port),
                "control_mode": control_mode,
                "control_proxy_id": st.get("server_public_proxy_id","") if control_mode == "automatic" else "manual",
            }}


@app.get("/api/rathole/railway/status")
async def rathole_railway_status(_=Depends(require_auth)):
    """Return a token-free Railway readiness report for the authenticated UI."""
    return {"ok": True, "railway": bottokentcpproxy.railway_prerequisite_status()}


@app.put("/api/rathole/control-endpoint")
async def rathole_save_manual_control_endpoint(request: Request, _=Depends(require_auth)):
    """Record a Railway TCP proxy created manually in the Railway dashboard."""
    body = await request.json()
    try:
        endpoint = rathole_control.configure_manual_control_endpoint(
            str(body.get("host") or ""),
            int(body.get("port") or 0),
        )
        await rathole_control.save()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_activity("rathole", f"endpoint کنترل دستی ثبت شد: {endpoint['host']}:{endpoint['port']}", "ok")
    return {"ok": True, "endpoint": endpoint}


@app.put("/api/rathole/railway/token")
async def rathole_save_railway_token(request: Request, _=Depends(require_auth)):
    """Persist an administrator-supplied Railway API token with mode 0600.

    The token is never echoed back to the browser; callers receive only the
    readiness state needed to continue creating Railway TCP proxies.
    """
    body = await request.json()
    token = str(body.get("token") or "").strip()
    if len(token) < 16 or len(token) > 4096:
        raise HTTPException(status_code=400, detail="توکن Railway نامعتبر یا خالی است")
    try:
        bottokentcpproxy.save_token(token)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    status = bottokentcpproxy.railway_prerequisite_status()
    log_activity("rathole", "توکن Railway برای TCP Proxy ذخیره شد", "ok")
    return {"ok": True, "railway": status}


async def _ensure_rathole_control_proxy() -> dict:
    """Resolve the Rathole control path in manual or automatic publication mode."""
    st = rathole_control.STATE["settings"]
    port = int(st.get("server_bind_port") or 23333)
    if str(st.get("publication_mode") or "manual") == "manual":
        host, proxy_port, _ = rathole_control.control_endpoint()
        if not host or not proxy_port:
            raise RuntimeError(
                f"ابتدا در Railway یک TCP Proxy برای پورت داخلی {port} بسازید و hostname و port آن را در «اتصال دو سرور» ثبت کنید"
            )
        return {
            "ok": True,
            "host": host,
            "port": int(proxy_port),
            "internal_port": port,
            "proxy_id": "manual",
            "manual": True,
        }
    stored_port = int(st.get("server_public_application_port") or 0)
    if (
        stored_port == port
        and st.get("server_public_host")
        and st.get("server_public_port")
    ):
        return {
            "ok": True,
            "host": st["server_public_host"],
            "port": int(st["server_public_port"]),
            "internal_port": port,
            "proxy_id": st.get("server_public_proxy_id", ""),
            "reused": True,
        }
    railway = bottokentcpproxy.railway_prerequisite_status()
    if not railway["has_token"]:
        raise RuntimeError("توکن Railway تنظیم نشده است؛ در بخش «دسترسی Railway» یک API Token ذخیره کنید")
    if not railway["context_ready"]:
        raise RuntimeError(railway["context_error"])
    old_proxy = st.get("server_public_proxy_id", "")
    if old_proxy:
        try:
            await bottokentcpproxy.delete_public_proxy(old_proxy)
        except Exception:
            pass
    proxy = await bottokentcpproxy.create_public_proxy_for_port(port)
    st["server_public_host"] = proxy["domain"]
    st["server_public_port"] = int(proxy["port"])
    st["server_public_proxy_id"] = proxy.get("id") or ""
    st["server_public_application_port"] = port
    for nid in rathole_control.STATE["nodes"]:
        rathole_control.bump_node(nid)
    await rathole_control.save()
    return {
        "ok": True,
        "host": proxy["domain"],
        "port": int(proxy["port"]),
        "internal_port": port,
        "proxy_id": proxy.get("id") or "",
        "reused": False,
    }

@app.post("/api/rathole/bootstrap")
async def rathole_bootstrap(request: Request, _=Depends(require_auth)):
    try:
        return await _ensure_rathole_control_proxy()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/rathole/nodes")
async def rathole_create_node(request: Request, _=Depends(require_auth)):
    body = await request.json()
    result = rathole_control.create_node(str(body.get("label", ""))[:64])
    await rathole_control.save()
    log_activity("rathole", f"نود جدید ساخته شد: {result['label']}", "ok")
    base = public_base_url(request)
    return {"ok": True, **result, "install_command":
            f"curl -fsSL {base}/static/install-rathole-agent.sh | bash -s -- {base} {result['node_id']} {result['token']}"}

@app.post("/api/rathole/nodes/{node_id}/install-command")
async def rathole_node_install_command(node_id: str, request: Request, _=Depends(require_auth)):
    node = rathole_control.STATE["nodes"].get(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    token = rathole_control.rotate_node_token(node_id)
    await rathole_control.save()
    base = public_base_url(request)
    command = f"curl -fsSL {base}/static/install-rathole-agent.sh | bash -s -- {base} {node_id} {token}"
    return {"ok": True, "node_id": node_id, "label": node.get("label",""), "install_command": command}

@app.delete("/api/rathole/nodes/{node_id}")
async def rathole_delete_node(node_id: str, _=Depends(require_auth)):
    if node_id not in rathole_control.STATE["nodes"]:
        raise HTTPException(status_code=404, detail="node not found")
    rathole_control.STATE["nodes"].pop(node_id, None)
    for tid in list(rathole_control.STATE["tunnels"]):
        if rathole_control.STATE["tunnels"][tid].get("node_id") == node_id:
            t = rathole_control.STATE["tunnels"].pop(tid)
            if t.get("proxy_id"):
                try: await bottokentcpproxy.delete_public_proxy(t["proxy_id"])
                except Exception: pass
    await rathole_control.save()
    return {"ok": True}

@app.post("/api/rathole/tunnels")
async def rathole_create_tunnel(request: Request, _=Depends(require_auth)):
    body = await request.json()
    node_id = str(body.get("node_id") or "").strip()
    if not node_id:
        raise HTTPException(status_code=400, detail="نود ایران انتخاب نشده است")
    node = rathole_control.STATE["nodes"].get(node_id)
    if not node:
        raise HTTPException(status_code=400, detail="نود ایران پیدا نشد")
    age = (time.time() - float(node.get("last_seen", 0))) if node.get("last_seen") else 999999
    if age > 60:
        raise HTTPException(status_code=409, detail="نود ایران آنلاین نیست یا heartbeat آن قدیمی است")

    # A tunnel cannot work without the Rathole control endpoint.
    try:
        control = await _ensure_rathole_control_proxy()
    except Exception as e:
        raise HTTPException(status_code=409, detail=f"مسیر کنترل Rathole آماده نیست: {e}")

    local_host = str(body.get("local_host") or "127.0.0.1").strip()[:253]
    local_port = int(body.get("local_port") or 0)
    if not (1 <= local_port <= 65535):
        raise HTTPException(status_code=400, detail="پورت محلی نامعتبر است")

    config_domain = str(body.get("config_domain") or "").strip().lower()
    origin_host = str(body.get("origin_host") or "").strip()
    if config_domain and (" " in config_domain or "/" in config_domain or ":" in config_domain):
        raise HTTPException(status_code=400, detail="دامنه کانفیگ نامعتبر است")
    if origin_host and len(origin_host) > 253:
        raise HTTPException(status_code=400, detail="Origin نامعتبر است")

    try:
        t = rathole_control.add_tunnel(
            node_id,
            str(body.get("name",""))[:64],
            local_host,
            local_port,
            int(body.get("public_port") or 0),
            bool(body.get("nodelay", True)),
            str(body.get("protocol", "tcp")),
            str(body.get("websocket_path", "/")),
        )
        state_tunnel = rathole_control.STATE["tunnels"].get(t["id"])
        if state_tunnel is not None:
            state_tunnel["link_id"] = str(body.get("link_id") or "")
            state_tunnel["config_domain"] = str(body.get("config_domain") or "").strip().lower()
            state_tunnel["origin_host"] = str(body.get("origin_host") or "").strip()
            state_tunnel["origin_port"] = int(body.get("origin_port") or 443)
            state_tunnel["dns_mode"] = str(body.get("dns_mode") or "manual_cname").strip()

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        publish_mode = str(rathole_control.STATE["settings"].get("publication_mode") or "manual")
        if publish_mode == "manual":
            manual_host, manual_port = rathole_control.validate_public_endpoint(
                str(body.get("manual_public_host") or ""),
                int(body.get("manual_public_port") or 0),
            )
            proxy = {
                "id": "",
                "domain": manual_host,
                "port": manual_port,
                "application_port": int(t["public_port"]),
            }
        else:
            proxy = await bottokentcpproxy.create_public_proxy_for_port(int(t["public_port"]))
        state_tunnel = rathole_control.STATE["tunnels"].get(t["id"])
        if state_tunnel is not None:
            state_tunnel.update({
                "proxy_id": proxy.get("id") or "",
                "proxy_domain": proxy.get("domain") or "",
                "proxy_port": int(proxy.get("port") or 0),
                "publication_mode": publish_mode,
            })

        ext_host = str(body.get("external_host") or "").strip()
        ext_port = int(body.get("external_port") or 0)
        ext_scheme = str(body.get("external_scheme") or "tcp").strip().lower()
        ext_path = str(body.get("external_path") or "/").strip()
        if ext_host:
            rathole_control.bind_external(
                t["id"], ext_host, ext_port or int(proxy.get("port") or 0),
                ext_scheme, ext_path
            )
    except Exception as e:
        rathole_control.STATE["tunnels"].pop(t["id"], None)
        await rathole_control.save()
        raise HTTPException(status_code=400, detail=f"ساخت مسیر انتشار ناموفق بود: {e}")

    await rathole_control.save()
    log_activity("rathole", f"تونل ساخته شد: {t['name']} [{t.get('protocol','tcp')}] :{t['public_port']} → {local_host}:{local_port}", "ok")
    safe_tunnel={k:v for k,v in rathole_control.STATE["tunnels"][t["id"]].items() if k!="token"}
    if safe_tunnel.get("protocol")=="websocket" and safe_tunnel.get("proxy_domain") and safe_tunnel.get("proxy_port"):
        domain=safe_tunnel["proxy_domain"]; port=int(safe_tunnel["proxy_port"]); path=safe_tunnel.get("websocket_path") or "/"
        scheme="wss" if port==443 else "ws"
        safe_tunnel["websocket_url"]=f"{scheme}://{domain}:{port}{path}"
    safe_tunnel["config_domain"] = safe_tunnel.get("config_domain") or ""
    safe_tunnel["origin_host"] = safe_tunnel.get("origin_host") or ""
    safe_tunnel["origin_port"] = int(safe_tunnel.get("origin_port") or 443)
    safe_tunnel["dns_target"] = safe_tunnel.get("proxy_domain") or ""
    safe_tunnel["dns_instruction"] = (
        f"CNAME {safe_tunnel['config_domain']} -> {safe_tunnel['dns_target']}"
        if safe_tunnel.get("config_domain") and safe_tunnel.get("dns_target")
        else ""
    )
    return {"ok":True,"tunnel":safe_tunnel,"control":control}

@app.patch("/api/rathole/tunnels/{tunnel_id}/route")
async def rathole_route_tunnel(tunnel_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    t = rathole_control.STATE["tunnels"].get(tunnel_id)
    if not t:
        raise HTTPException(status_code=404, detail="tunnel not found")
    link_id = str(body.get("link_id") or t.get("link_id") or "").strip()
    config_domain = str(body.get("config_domain") or "").strip().lower()
    origin_host = str(body.get("origin_host") or "").strip()
    origin_port = int(body.get("origin_port") or 443)
    if config_domain and (" " in config_domain or "/" in config_domain or ":" in config_domain):
        raise HTTPException(status_code=400, detail="دامنه کانفیگ نامعتبر است")
    if origin_host and len(origin_host) > 253:
        raise HTTPException(status_code=400, detail="Origin نامعتبر است")
    t["link_id"] = link_id
    t["config_domain"] = config_domain
    t["origin_host"] = origin_host
    t["origin_port"] = origin_port
    t["dns_mode"] = str(body.get("dns_mode") or t.get("dns_mode") or "manual_cname")
    rathole_control.bump_node(t["node_id"])
    await rathole_control.save()
    safe={k:v for k,v in t.items() if k!="token"}
    safe["dns_target"]=t.get("proxy_domain","")
    safe["dns_instruction"] = f"CNAME {config_domain} -> {t.get('proxy_domain','')}" if config_domain and t.get("proxy_domain") else ""
    return {"ok":True,"tunnel":safe}

@app.post("/api/rathole/tunnels/{tunnel_id}/bind")
async def rathole_bind_external(tunnel_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    try:
        t = rathole_control.bind_external(
            tunnel_id,
            str(body.get("host","")).strip(),
            int(body.get("port")),
            str(body.get("scheme","tcp")),
            str(body.get("path","/")),
        )
        await rathole_control.save()
        log_activity("rathole", f"اتصال خارجی برای «{t.get('name','')}» تنظیم شد: {t['external_host']}:{t['external_port']}", "ok")
        safe = {k:v for k,v in t.items() if k != "token"}
        return {"ok": True, "tunnel": safe}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/rathole/tunnels/{tunnel_id}/ping")
async def rathole_ping_external(tunnel_id: str, request: Request, _=Depends(require_auth)):
    t = rathole_control.STATE["tunnels"].get(tunnel_id)
    if not t:
        raise HTTPException(status_code=404, detail="tunnel not found")
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    host = str(body.get("host") or t.get("external_host") or "").strip()
    port = int(body.get("port") or t.get("external_port") or t.get("proxy_port") or 0)
    if not host or not port:
        raise HTTPException(status_code=400, detail="external host/port is not configured")
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        latency = (time.perf_counter() - start) * 1000.0
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        t = rathole_control.record_ping(tunnel_id, True, latency, "")
        await rathole_control.save()
        return {"ok": True, "latency_ms": round(latency, 2), "host": host, "port": port, "status": t.get("connection_status")}
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        t = rathole_control.record_ping(tunnel_id, False, latency, str(e))
        await rathole_control.save()
        return {"ok": False, "latency_ms": round(latency, 2), "host": host, "port": port, "error": str(e), "status": t.get("connection_status")}

@app.delete("/api/rathole/tunnels/{tunnel_id}")
async def rathole_delete_tunnel(tunnel_id: str, _=Depends(require_auth)):
    t = rathole_control.STATE["tunnels"].get(tunnel_id)
    if not t:
        raise HTTPException(status_code=404, detail="tunnel not found")
    if t.get("proxy_id"):
        try:
            await bottokentcpproxy.delete_public_proxy(t["proxy_id"])
        except Exception:
            pass
    rathole_control.delete_tunnel(tunnel_id)
    await rathole_control.save()
    return {"ok": True}

@app.patch("/api/rathole/settings")
async def rathole_update_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    requested_transport = str(body.get("transport") or rathole_control.STATE["settings"].get("transport") or "tcp").strip().lower()
    if requested_transport == "noise":
        outdated = [
            str(node.get("label") or node_id)
            for node_id, node in rathole_control.STATE["nodes"].items()
            if not rathole_control.node_supports_noise(node)
        ]
        if outdated:
            joined = "، ".join(outdated[:5])
            raise HTTPException(
                status_code=409,
                detail=f"برای فعال‌سازی Noise ابتدا عامل Rathole این نودها را با فرمان نصب جدید به نسخهٔ 2.2 ارتقا بدهید: {joined}",
            )
    old_port = int(rathole_control.STATE["settings"].get("server_bind_port") or 23333)
    try:
        settings = rathole_control.update_settings(body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    new_port = int(settings.get("server_bind_port") or old_port)
    port_changed = new_port != old_port

    # A manual Railway TCP Proxy targets one internal port. Clear the recorded
    # endpoint if that target changes so a node never reconnects to the wrong port.
    if port_changed and settings.get("publication_mode") == "manual":
        rathole_control.STATE["settings"]["server_manual_host"] = ""
        rathole_control.STATE["settings"]["server_manual_port"] = 0

    # Changing the Rathole control port invalidates the old Railway public proxy.
    # Clear its metadata first, then optionally recreate it automatically.
    if port_changed:
        old_proxy_id = rathole_control.STATE["settings"].get("server_public_proxy_id", "")
        if old_proxy_id:
            try:
                await bottokentcpproxy.delete_public_proxy(old_proxy_id)
            except Exception:
                pass
        rathole_control.STATE["settings"]["server_public_proxy_id"] = ""
        rathole_control.STATE["settings"]["server_public_host"] = ""
        rathole_control.STATE["settings"]["server_public_port"] = 0
        rathole_control.STATE["settings"]["server_public_application_port"] = 0
        for nid in rathole_control.STATE["nodes"]:
            rathole_control.bump_node(nid)

    await rathole_control.save()

    # If a Railway TCP Proxy token is already configured, rebuild the control
    # proxy immediately so the UI change is a real deployment change, not only
    # a saved number.
    bootstrap = None
    if port_changed and bottokentcpproxy.load_token():
        try:
            proxy = await bottokentcpproxy.create_public_proxy_for_port(new_port)
            rathole_control.STATE["settings"]["server_public_host"] = proxy["domain"]
            rathole_control.STATE["settings"]["server_public_port"] = int(proxy["port"])
            rathole_control.STATE["settings"]["server_public_proxy_id"] = proxy.get("id") or ""
            rathole_control.STATE["settings"]["server_public_application_port"] = new_port
            for nid in rathole_control.STATE["nodes"]:
                rathole_control.bump_node(nid)
            await rathole_control.save()
            bootstrap = {
                "ok": True,
                "host": proxy["domain"],
                "port": proxy["port"],
                "internal_port": new_port,
                "proxy_id": proxy.get("id"),
            }
        except Exception as e:
            await rathole_control.save()
            raise HTTPException(status_code=400, detail=f"پورت Rathole ذخیره شد اما ساخت Proxy جدید ناموفق بود: {e}")

    return {"ok": True, "settings": rathole_control.public_settings(), "port_changed": port_changed, "bootstrap": bootstrap}

@app.post("/api/rathole/agent/next")
async def rathole_agent_next(request: Request):
    node_id = request.headers.get("X-RVG-Node-Id", "")
    token = request.headers.get("X-RVG-Node-Token", "")
    node = rathole_control.auth_node(node_id, token)
    if not node:
        raise HTTPException(status_code=401, detail="invalid node credentials")
    try:
        meta = await request.json()
    except Exception:
        meta = {}
    rathole_control.touch_node(node_id, meta)
    await rathole_control.save()
    snap = rathole_control.node_snapshot(node_id)
    snap["revision"] = int(node.get("desired_revision", 0))
    return snap

@app.post("/api/rathole/agent/ping")
async def rathole_agent_ping(request: Request):
    node_id = request.headers.get("X-RVG-Node-Id", "")
    token = request.headers.get("X-RVG-Node-Token", "")
    node = rathole_control.auth_node(node_id, token)
    if not node:
        raise HTTPException(status_code=401, detail="invalid node credentials")
    rathole_control.touch_node(node_id, {"agent_version":"2.0","hostname":"","platform":"","public_ip":""})
    await rathole_control.save()
    return {"ok": True, "node_id": node_id, "revision": int(node.get("desired_revision", 0)),
            "last_seen": node.get("last_seen")}

@app.get("/api/rathole/agent/version")
async def rathole_agent_version():
    return {"ok": True, "agent_api": 2, "min_agent": "2.0"}

@app.get("/api/rathole/agent/health")
async def rathole_agent_health():
    return {"ok": True, "service": "rathole-agent-api", "agent_version": "2.0"}

@app.get("/static/rathole_agent_v2.py")
async def rathole_agent_v2_file():
    path = Path(__file__).with_name("rathole_agent_v2.py")
    if not path.exists():
        raise HTTPException(status_code=404)
    return Response(path.read_text(encoding="utf-8"), media_type="text/plain")

@app.get("/static/rathole_agent.py")
async def rathole_agent_file():
    path = Path(__file__).with_name("rathole_agent.py")
    if not path.exists(): raise HTTPException(status_code=404)
    return Response(path.read_text(encoding="utf-8"), media_type="text/plain")

@app.get("/static/install-rathole-agent.sh")
async def rathole_agent_installer():
    path = Path(__file__).with_name("install-rathole-agent.sh")
    if not path.exists(): raise HTTPException(status_code=404)
    return Response(path.read_text(encoding="utf-8"), media_type="text/plain")

@app.on_event("startup")
async def rathole_startup():
    await rathole_control.load()
    if os.environ.get("RATHOLE_ENABLE_SERVER", "1") == "1":
        try:
            import rathole_server_manager
            asyncio.create_task(rathole_server_manager.run())
        except Exception as exc:
            logger.warning("Rathole server manager disabled: %s", exc)

# ── HTML Pages ───────────────────────────────────────────────────────────────
from pages import LOGIN_HTML, DASHBOARD_HTML

# ── Central: Announcements & Support ─────────────────────────────────────────
@app.get("/api/announcements")
async def api_announcements(_=Depends(require_auth)):
    return {"announcements": await central.fetch_announcements()}

@app.post("/api/announcements/view")
async def api_announcements_view(request: Request, _=Depends(require_auth)):
    body = await request.json()
    ids = body.get("ids", [])
    if not isinstance(ids, list):
        raise HTTPException(status_code=400, detail="invalid ids")
    await central.report_announcement_views([str(i) for i in ids][:100])
    return {"ok": True}

@app.get("/api/support/messages")
async def api_support_messages(_=Depends(require_auth)):
    messages, blocked = await central.fetch_support_messages()
    return {"messages": messages, "blocked": blocked}

@app.post("/api/support/send")
async def api_support_send(request: Request, _=Depends(require_auth)):
    body = await request.json()
    msg = str(body.get("message", "")).strip()[:2000]
    if not msg:
        raise HTTPException(status_code=400, detail="پیام خالی است")
    result = await central.send_support_message(msg)
    if result.get("blocked"):
        raise HTTPException(status_code=403, detail="شما توسط پشتیبانی بلاک شده‌اید")
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error") or "ارتباط با سرور مرکزی برقرار نشد")
    return {"ok": True}

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=CONFIG["port"],
        log_level="info",
        workers=1,
        loop="auto",         # uvloop رو در صورت نصب بودن استفاده می‌کنه، وگرنه بدون کرش fallback می‌کنه
        http="auto",
    )
