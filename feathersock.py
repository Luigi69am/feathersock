#!/usr/bin/env python3
"""
Feathersock v1.1.0 — A featherweight Shadowsocks server with a web admin panel.

Features:
  • Shadowsocks AEAD (AES-256-GCM / ChaCha20-Poly1305)
  • Multi-IP fallback with fast DNS (all A records)
  • TLS-style fragmentation of first 8KB to bypass DPI
  • Per-user quota, expiry, enable/disable
  • Web admin panel + subscription endpoint
  • Per-user public status page (/u/<token>) with config, remaining quota & time
  • Admin panel: renew user days/quota in one click (English UI)
  • Optional UDP relay
  • Optional uvloop + aiofastnet acceleration

Usage:
  python3 feathersock.py                      # run with config.json
  python3 feathersock.py --version            # show version
  python3 feathersock.py --generate-config    # create starter config.json
  FEATHERSOCK_CONFIG=/path/to.json python3 feathersock.py

Requires: pip3 install cryptography
Optional: pip3 install uvloop aiofastnet

License: MIT — see LICENSE
"""
import sys

__version__ = "1.1.0"

# --- Fast CLI path (runs before heavy imports and config loading) ---
if __name__ == "__main__" and len(sys.argv) > 1:
    _cmd = sys.argv[1]
    if _cmd in ("-v", "--version"):
        print(f"Feathersock v{__version__}")
        sys.exit(0)
    if _cmd in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if _cmd in ("-g", "--generate-config"):
        import json as _json
        import secrets as _secrets
        from pathlib import Path as _Path
        _p = _Path("config.json")
        if _p.exists():
            print(f"❌ {_p} already exists. Remove it first.", file=sys.stderr)
            sys.exit(1)
        _cfg = {
            "public_host": "REPLACE_WITH_YOUR_IP_OR_DOMAIN",
            "admin_user": "admin",
            "admin_pass": _secrets.token_urlsafe(24),
            "listen_port": 14755,
            "sub_port": 8080,
        }
        _p.write_text(_json.dumps(_cfg, indent=2) + "\n", encoding="utf-8")
        print(f"✅ Created {_p}")
        print(f"   admin_user: {_cfg['admin_user']}")
        print(f"   admin_pass: {_cfg['admin_pass']}")
        print("   → Edit 'public_host' before starting.")
        sys.exit(0)
    if _cmd not in ("-c", "--config"):
        print(f"Unknown argument: {_cmd}. Use --help.", file=sys.stderr)
        sys.exit(2)
    if _cmd in ("-c", "--config") and len(sys.argv) > 2:
        import os as _os
        _os.environ["FEATHERSOCK_CONFIG"] = sys.argv[2]

# --- Imports ---
import asyncio
import base64
import hashlib
import html
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# --- Optional performance libraries ---
try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    UVLOOP_AVAILABLE = False

try:
    import aiofastnet
    AIOFASTNET_AVAILABLE = True
except ImportError:
    AIOFASTNET_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("FATAL: pip3 install cryptography", file=sys.stderr)
    sys.exit(1)


# --- CPU feature detection ---
def has_aesni():
    try:
        with open("/proc/cpuinfo") as f:
            return "aes" in f.read()
    except Exception:
        return False


_has_aesni = has_aesni()


# --- Config loading ---
DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 14755,
    "public_host": "",
    "admin_user": "admin",
    "admin_pass": "",
    "name_prefix": "Feathersock",
    "users_file": "users.txt",
    "traffic_file": "traffic.txt",
    "cipher": "auto",
    "sub_enabled": True,
    "sub_port": 8080,
    "flush_interval": 5,
    "idle_timeout": 1800,
    "first_byte_timeout": 30,
    "max_connections": 800,
    "debug": False,
    "auto_tune": True,
    # speed
    "read_chunk": 131072,
    "drain_threshold": 4194304,
    "sock_buf": 8388608,
    "mss_clamp": 1360,
    # fragmentation
    "frag_enabled": True,
    "frag_size": 1024,
    "frag_burst_limit": 8192,
    "frag_delay_ms": 0,
    # keepalive
    "tcp_keepidle": 60,
    "tcp_keepintvl": 15,
    "tcp_keepcnt": 4,
    # connect fallback
    "connect_timeout_per_ip": 4,
    "connect_timeout_total": 15,
    # dns
    "dns_upstreams": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "dns_timeout": 2,
    "dns_cache_ttl": 120,
    "dns_cache_cleanup_sec": 30,
    "dns_healthcheck_sec": 30,
    "dns_max_fail_before_flush": 3,
}


def _load_config():
    cfg = dict(DEFAULT_CONFIG)
    path = Path(os.environ.get("FEATHERSOCK_CONFIG", "config.json"))

    if path.exists():
        try:
            user_cfg = json.loads(path.read_text("utf-8"))
        except Exception as e:
            print(f"❌ Invalid config {path}: {e}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(user_cfg, dict):
            print(f"❌ {path} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        user_cfg = {k: v for k, v in user_cfg.items() if not k.startswith("_")}
        cfg.update(user_cfg)
    elif not os.environ.get("FEATHERSOCK_PUBLIC_HOST"):
        print(f"❌ Config file not found: {path}", file=sys.stderr)
        print("   Create one:  python3 feathersock.py --generate-config", file=sys.stderr)
        sys.exit(1)

    env_map = [
        ("FEATHERSOCK_PUBLIC_HOST", "public_host", str),
        ("FEATHERSOCK_ADMIN_USER", "admin_user", str),
        ("FEATHERSOCK_ADMIN_PASS", "admin_pass", str),
        ("FEATHERSOCK_LISTEN_HOST", "listen_host", str),
        ("FEATHERSOCK_LISTEN_PORT", "listen_port", int),
        ("FEATHERSOCK_SUB_PORT", "sub_port", int),
        ("FEATHERSOCK_DEBUG", "debug", lambda v: v.lower() in ("1", "true", "yes", "on")),
    ]
    for env_key, cfg_key, cast in env_map:
        if env_key in os.environ:
            try:
                cfg[cfg_key] = cast(os.environ[env_key])
            except Exception as e:
                print(f"❌ Invalid {env_key}: {e}", file=sys.stderr)
                sys.exit(1)

    if not cfg["public_host"] or str(cfg["public_host"]).startswith("REPLACE_"):
        print("❌ 'public_host' is not set.", file=sys.stderr)
        print("   Edit config.json or set FEATHERSOCK_PUBLIC_HOST.", file=sys.stderr)
        sys.exit(1)

    if not cfg["admin_pass"] or cfg["admin_pass"] == "admin":
        print("❌ 'admin_pass' must be set and must not be 'admin'.", file=sys.stderr)
        print("   Edit config.json or set FEATHERSOCK_ADMIN_PASS.", file=sys.stderr)
        sys.exit(1)

    if cfg["cipher"] == "auto":
        cfg["cipher"] = "aes-256-gcm" if _has_aesni else "chacha20-ietf-poly1305"

    return cfg


CONFIG = _load_config()
CIPHER_CLS = AESGCM if CONFIG["cipher"] == "aes-256-gcm" else ChaCha20Poly1305
CIPHER_NAME = CONFIG["cipher"]
KEY_LEN, SALT_LEN, TAG_LEN, MAX_PAYLOAD = 32, 32, 16, 0x3FFF

# =============================================================
START_TIME = time.time()
_stats = defaultdict(int)
_recent = deque(maxlen=100)
_logbuf = deque(maxlen=500)
_traffic_cache = {}
_traffic_pending = defaultdict(int)
_users_cache = {}
_dns_cache = {}
_dns_health = {}
_dns_consecutive_fail = 0
_tuning_report = {}
_outbound_report = {}
_sysctl_script = ""
_resolv_warning = ""

def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, file=sys.stderr, flush=True)
    _logbuf.append(line)

def dbg(m):
    if CONFIG["debug"]:
        log(f"DBG {m}")

def now():
    return int(time.time())

def fmt_bytes(b):
    b = float(b)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f} {u}"
        b /= 1024
    return f"{b:.2f} PB"

def fmt_time(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "Never"

def atomic_write(path, text):
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, p)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        raise

def _enc(s):
    return urllib.parse.quote(str(s), safe="")

def _dec(s):
    return urllib.parse.unquote(s)

# =============================================================
# DNS: all A records, try each
# =============================================================
def build_dns_query(domain, qtype=1):
    txid = secrets.randbelow(65536)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q = b""
    for part in domain.split("."):
        if not part:
            continue
        if len(part) > 63:
            return None
        q += bytes([len(part)]) + part.encode("ascii", errors="ignore")
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + q

def parse_dns_all_a(resp):
    ips = []
    try:
        if len(resp) < 12:
            return ips
        ancount = struct.unpack(">H", resp[6:8])[0]
        if ancount == 0:
            return ips
        pos = 12
        while pos < len(resp):
            if resp[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            if resp[pos] == 0:
                pos += 1
                break
            pos += 1 + resp[pos]
        pos += 4
        for _ in range(ancount):
            while pos < len(resp):
                if resp[pos] & 0xC0 == 0xC0:
                    pos += 2
                    break
                if resp[pos] == 0:
                    pos += 1
                    break
                pos += 1 + resp[pos]
            if pos + 10 > len(resp):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(resp[pos:pos + 4]))
            pos += rdlen
    except Exception:
        pass
    return ips

async def query_one_upstream(query, upstream):
    loop = asyncio.get_running_loop()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect((upstream, 53))
        await loop.sock_sendall(sock, query)
        try:
            resp = await asyncio.wait_for(
                loop.sock_recv(sock, 65536),
                timeout=CONFIG["dns_timeout"])
            _dns_health[upstream] = "OK"
            return resp
        except asyncio.TimeoutError:
            _dns_health[upstream] = "TIMEOUT"
            return None
    except asyncio.CancelledError:
        raise
    except Exception:
        _dns_health[upstream] = "ERROR"
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

async def query_dns_parallel(query):
    tasks = [asyncio.create_task(query_one_upstream(query, u))
             for u in CONFIG["dns_upstreams"]]
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            try:
                r = t.result()
            except Exception:
                r = None
            if r:
                for p in pending:
                    p.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                return r
    return None

async def resolve_domain_all(domain):
    global _dns_consecutive_fail
    domain = domain.lower().strip(".")
    if not domain:
        return []

    try:
        socket.inet_aton(domain)
        return [domain]
    except Exception:
        pass

    key = (domain, 1)
    if key in _dns_cache:
        ips, exp = _dns_cache[key]
        if exp > time.time() and ips:
            _stats["dns_cached"] += 1
            return ips
        _dns_cache.pop(key, None)

    query = build_dns_query(domain, 1)
    if not query:
        return []

    resp = await query_dns_parallel(query)
    if resp:
        ips = parse_dns_all_a(resp)
        if ips:
            _stats["dns_queries"] += 1
            _dns_cache[key] = (ips, time.time() + CONFIG["dns_cache_ttl"])
            _dns_consecutive_fail = 0
            return ips

    _stats["dns_failed"] += 1
    _dns_consecutive_fail += 1
    if _dns_consecutive_fail >= CONFIG["dns_max_fail_before_flush"]:
        n = len(_dns_cache)
        _dns_cache.clear()
        _dns_consecutive_fail = 0
        log(f"⚠️  DNS: flushed cache ({n} entries) after consecutive failures")
    return []

async def connect_with_fallback(domain_or_ip, port):
    try:
        socket.inet_aton(domain_or_ip)
        ips = [domain_or_ip]
    except Exception:
        ips = await resolve_domain_all(domain_or_ip)

    if not ips:
        raise OSError(f"DNS fail: {domain_or_ip}")

    per_ip = CONFIG["connect_timeout_per_ip"]
    total = CONFIG["connect_timeout_total"]
    start = time.time()
    last_err = None

    for ip in ips:
        if time.time() - start > total:
            break
        remaining = min(per_ip, total - (time.time() - start))
        if remaining <= 0:
            break
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=remaining)
            tune_socket(w.get_extra_info("socket"))
            return r, w, ip
        except Exception as e:
            last_err = e
            continue

    raise OSError(f"All IPs failed for {domain_or_ip}: {last_err}")

async def dns_healthcheck_loop():
    while True:
        await asyncio.sleep(CONFIG["dns_healthcheck_sec"])
        q = build_dns_query("cloudflare.com", 1)
        if q:
            await query_dns_parallel(q)

async def dns_cache_cleanup_loop():
    while True:
        await asyncio.sleep(CONFIG["dns_cache_cleanup_sec"])
        t = time.time()
        expired = [k for k, (_, exp) in _dns_cache.items() if exp < t]
        for k in expired:
            _dns_cache.pop(k, None)

# =============================================================
# Auto-tune
# =============================================================
def auto_tune():
    global _sysctl_script, _resolv_warning
    if not CONFIG["auto_tune"]:
        return
    settings = {
        "net.ipv4.tcp_congestion_control": "bbr",
        "net.core.default_qdisc": "fq",
        "net.ipv4.tcp_fastopen": "3",
        "net.ipv4.tcp_mtu_probing": "1",
        "net.core.rmem_max": "33554432",
        "net.core.wmem_max": "33554432",
        "net.ipv4.tcp_rmem": "4096 131072 33554432",
        "net.ipv4.tcp_wmem": "4096 65536 33554432",
        "net.ipv4.tcp_slow_start_after_idle": "0",
        "net.ipv4.tcp_keepalive_time": str(CONFIG["tcp_keepidle"]),
        "net.ipv4.tcp_keepalive_intvl": str(CONFIG["tcp_keepintvl"]),
        "net.ipv4.tcp_keepalive_probes": str(CONFIG["tcp_keepcnt"]),
    }
    for k, v in settings.items():
        try:
            r = subprocess.run(["sudo", "-n", "sysctl", "-w", f"{k}={v}"],
                               capture_output=True, timeout=3)
            _tuning_report[k] = r.returncode == 0
        except Exception:
            _tuning_report[k] = False
    applied = sum(1 for v in _tuning_report.values() if v)
    log(f"auto-tune: {applied}/{len(settings)} applied")

    if applied < len(settings):
        lines = ["sudo tee /etc/sysctl.d/99-feathersock.conf > /dev/null <<'EOF'"]
        for k, v in settings.items():
            lines.append(f"{k} = {v}")
        lines += ["EOF", "sudo sysctl -p /etc/sysctl.d/99-feathersock.conf"]
        _sysctl_script = "\n".join(lines)
        try:
            Path("/tmp/feathersock-tune.sh").write_text(_sysctl_script, encoding="utf-8")
            os.chmod("/tmp/feathersock-tune.sh", 0o755)
        except Exception:
            pass

    try:
        resolv = Path("/etc/resolv.conf").read_text()
        if not any(d in resolv for d in ("1.1.1.1", "8.8.8.8", "9.9.9.9")):
            _resolv_warning = "/etc/resolv.conf uses non-public DNS."
    except Exception:
        pass

async def test_outbound_async():
    tests = [
        ("1.1.1.1", 53, "DNS"),
        ("1.1.1.1", 443, "HTTPS"),
        ("8.8.8.8", 443, "Google"),
        ("github.com", 443, "GitHub"),
        ("www.instagram.com", 443, "Instagram"),
    ]
    for host, port, name in tests:
        try:
            r, w, ip = await connect_with_fallback(host, port)
            _outbound_report[f"{name}:{port}"] = f"OK ({ip})"
            w.close()
        except Exception as e:
            _outbound_report[f"{name}:{port}"] = type(e).__name__
    ok = sum(1 for v in _outbound_report.values() if v.startswith("OK"))
    log(f"outbound: {ok}/{len(tests)} reachable")

def tune_socket(sock):
    if sock is None or not hasattr(sock, "setsockopt"):
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CONFIG["sock_buf"])
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CONFIG["sock_buf"])
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, CONFIG["tcp_keepidle"])
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, CONFIG["tcp_keepintvl"])
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, CONFIG["tcp_keepcnt"])
        except Exception:
            pass
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, CONFIG["mss_clamp"])
        except Exception:
            pass
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 5)
        except Exception:
            pass
    except Exception:
        pass

def should_drain(writer):
    t = getattr(writer, "transport", None)
    if t is None:
        return True
    try:
        return t.get_write_buffer_size() > CONFIG["drain_threshold"]
    except Exception:
        return True

async def close_writer(w, timeout=2.0):
    if w is None:
        return
    try:
        w.close()
        await asyncio.wait_for(w.wait_closed(), timeout=timeout)
    except Exception:
        pass

# =============================================================
# Fragmentation: only the first burst
# =============================================================
async def send_first_burst(writer, data, is_first_flag):
    if not is_first_flag[0]:
        writer.write(data)
        if should_drain(writer):
            await writer.drain()
        return

    burst = data[:CONFIG["frag_burst_limit"]]
    rest = data[CONFIG["frag_burst_limit"]:]
    size = CONFIG["frag_size"]
    for i in range(0, len(burst), size):
        writer.write(burst[i:i + size])
    if rest:
        writer.write(rest)
    if should_drain(writer):
        await writer.drain()
    is_first_flag[0] = False

# =============================================================
# Crypto
# =============================================================
def evp_bytes_to_key(password: bytes, key_len: int) -> bytes:
    m = b""
    prev = b""
    while len(m) < key_len:
        prev = hashlib.md5(prev + password).digest()
        m += prev
    return m[:key_len]

def derive_subkey(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA1(), length=KEY_LEN,
                salt=salt, info=b"ss-subkey").derive(master_key)

_NONCES = tuple(i.to_bytes(12, "little") for i in range(65536))

class SSPipe:
    __slots__ = ("cipher", "nonce")

    def __init__(self, subkey: bytes, start_nonce: int = 0):
        self.cipher = CIPHER_CLS(subkey)
        self.nonce = start_nonce

    def _next(self):
        n = self.nonce
        self.nonce = n + 1
        return _NONCES[n] if n < 65536 else n.to_bytes(12, "little")

    def enc_chunk(self, data) -> bytes:
        ln = len(data).to_bytes(2, "big")
        c1 = self.cipher.encrypt(self._next(), ln, None)
        c2 = self.cipher.encrypt(self._next(), bytes(data), None)
        return c1 + c2

    def dec_len(self, enc: bytes) -> int:
        return int.from_bytes(self.cipher.decrypt(self._next(), enc, None), "big")

    def dec_payload(self, enc: bytes) -> bytes:
        return self.cipher.decrypt(self._next(), enc, None)

# =============================================================
# Users / Traffic / Sessions
# =============================================================
def load_users():
    global _users_cache
    _users_cache = {}
    p = Path(CONFIG["users_file"])
    if not p.exists():
        log("no users.txt")
        return
    for ln in p.read_text("utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("|")
        if len(parts) != 7:
            continue
        try:
            uid = int(parts[0])
            _users_cache[uid] = {
                "id": uid,
                "name": _dec(parts[1]),
                "password": _dec(parts[2]),
                "master_key": evp_bytes_to_key(_dec(parts[2]).encode(), KEY_LEN),
                "quota_bytes": int(parts[3]),
                "expires_at": int(parts[4]),
                "enabled": int(parts[5]),
                "created_at": int(parts[6]),
            }
        except Exception as e:
            log(f"skip: {e}")
    log(f"loaded {len(_users_cache)} users")

def save_users():
    lines = ["|".join([str(u["id"]), _enc(u["name"]), _enc(u["password"]),
                       str(u["quota_bytes"]), str(u["expires_at"]), str(u["enabled"]),
                       str(u["created_at"])])
             for u in sorted(_users_cache.values(), key=lambda x: x["id"])]
    atomic_write(CONFIG["users_file"], "\n".join(lines) + ("\n" if lines else ""))

def create_user(name, password, quota_gb, days):
    for u in _users_cache.values():
        if u["name"] == name:
            raise ValueError("exists")
    uid = (max(_users_cache) + 1) if _users_cache else 1
    _users_cache[uid] = {
        "id": uid,
        "name": name,
        "password": password,
        "master_key": evp_bytes_to_key(password.encode(), KEY_LEN),
        "quota_bytes": int(quota_gb * 1024**3) if quota_gb else 0,
        "expires_at": now() + int(days * 86400) if days else 0,
        "enabled": 1,
        "created_at": now(),
    }
    _traffic_cache[uid] = 0
    save_users()
    save_traffic()
    log(f"created #{uid}")
    return uid

def update_user(uid, **kw):
    u = _users_cache.get(uid)
    if not u:
        return
    for k in ("name", "password", "quota_bytes", "expires_at", "enabled"):
        if k in kw:
            u[k] = kw[k]
            if k == "password":
                u["master_key"] = evp_bytes_to_key(kw[k].encode(), KEY_LEN)
    save_users()

def delete_user(uid):
    _users_cache.pop(uid, None)
    _traffic_cache.pop(uid, None)
    _traffic_pending.pop(uid, None)
    save_users()
    save_traffic()

def get_user(uid):
    return _users_cache.get(uid)

def all_users():
    return sorted(_users_cache.values(), key=lambda x: x["id"])

def is_expired(u):
    return bool(u["expires_at"]) and now() > u["expires_at"]

def is_over_quota(u):
    q = u["quota_bytes"]
    return q > 0 and _traffic_cache.get(u["id"], 0) >= q

def used_of(u):
    return _traffic_cache.get(u["id"], 0)

def user_token(u):
    raw = f"{u['id']}|{u['password']}".encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:18]).decode().rstrip("=")

def find_user_by_token(token):
    if not token:
        return None
    for u in all_users():
        exp = user_token(u)
        if len(exp) == len(token) and secrets.compare_digest(exp, token):
            return u
    return None

def renew_user(uid, add_days, add_gb):
    """
    Extend a user's expiry and/or quota.
      - add_days > 0: if expires_at > 0, extend from max(now, expires_at);
                      if expires_at == 0 (unlimited), skipped.
      - add_gb   > 0: if quota_bytes > 0, add GB; if quota_bytes == 0 (unlimited), skipped.
    Returns dict of applied changes (may be empty).
    """
    u = get_user(uid)
    if not u:
        return {}
    kw = {}
    applied = {}
    if add_days and add_days > 0 and u["expires_at"] > 0:
        base = max(now(), u["expires_at"])
        new_exp = base + int(add_days * 86400)
        kw["expires_at"] = new_exp
        applied["days"] = int(add_days)
    if add_gb and add_gb > 0 and u["quota_bytes"] > 0:
        extra = int(round(add_gb * 1024**3))
        if extra > 0:
            kw["quota_bytes"] = u["quota_bytes"] + extra
            applied["gb"] = round(extra / 1024**3, 2)
    if kw:
        update_user(uid, **kw)
    return applied

def load_traffic():
    global _traffic_cache
    _traffic_cache = {}
    p = Path(CONFIG["traffic_file"])
    if not p.exists():
        return
    for ln in p.read_text("utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("|")
        if len(parts) != 2:
            continue
        try:
            _traffic_cache[int(parts[0])] = int(parts[1])
        except Exception:
            pass

def save_traffic():
    lines = [f"{uid}|{b}" for uid, b in sorted(_traffic_cache.items())]
    atomic_write(CONFIG["traffic_file"], "\n".join(lines) + ("\n" if lines else ""))

def traffic_add(uid, n):
    if n <= 0:
        return
    _traffic_cache[uid] = _traffic_cache.get(uid, 0) + n
    _traffic_pending[uid] += n

def traffic_flush():
    if not _traffic_pending:
        return
    save_traffic()
    _traffic_pending.clear()

async def flush_loop():
    while True:
        await asyncio.sleep(CONFIG["flush_interval"])
        try:
            traffic_flush()
        except Exception as e:
            log(f"flush: {e}")

sessions = {}

def new_session():
    t = secrets.token_urlsafe(32)
    sessions[t] = now() + 3600
    return t

def check_session_from_cookie(headers):
    raw = headers.get("cookie", "")
    if not raw:
        return False
    token = None
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("session="):
            token = part[8:]
            break
    if not token:
        return False
    exp = sessions.get(token)
    if exp and exp > now():
        return True
    sessions.pop(token, None)
    return False

# =============================================================
# HTTP helpers
# =============================================================
REASONS = {200: "OK", 204: "No Content", 302: "Found", 400: "Bad", 401: "Unauth", 404: "NF", 500: "Err"}

async def send_response(writer, status, ctype, body, extra=None, head_only=False):
    if isinstance(body, str):
        body = body.encode("utf-8")
    if status == 204:
        head = ["HTTP/1.1 204 No Content", "Connection: close"]
        if extra:
            head.extend(extra)
        out = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1")
    else:
        if ctype.startswith("text/") and "charset=" not in ctype.lower():
            ctype += "; charset=utf-8"
        head = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}",
                f"Content-Type: {ctype}", f"Content-Length: {len(body)}",
                "Connection: close"]
        if extra:
            head.extend(extra)
        out = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1")
        if not head_only:
            out += body
    try:
        writer.write(out)
        await writer.drain()
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass

LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#0f0f13;color:#eee;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#1a1a24;padding:2rem;border-radius:12px;min-width:300px}
input{width:100%;padding:.6rem;margin:.3rem 0;background:#0f0f13;
border:1px solid #333;color:#eee;border-radius:6px}
button{width:100%;padding:.6rem;background:#4c6ef5;color:#fff;border:0;
border-radius:6px;cursor:pointer}</style></head><body><div class="card">
<h2>Feathersock</h2>__ERROR__<form method="POST" action="/login">
<input name="username" placeholder="User" required autofocus>
<input name="password" type="password" placeholder="Pass" required>
<button>Sign in</button></form></div></body></html>"""

DASH_HEAD = """<!doctype html><html><head><meta charset="utf-8"><title>Feathersock</title>
<style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#0f0f13;
color:#eee;margin:0;padding:2rem}h1{font-size:1.3rem;margin:0}
a{color:#748ffc;text-decoration:none}a:hover{text-decoration:underline}
.header{display:flex;justify-content:space-between;margin-bottom:1.5rem;align-items:center}
.card{background:#1a1a24;padding:1.5rem;border-radius:10px;margin-bottom:1.5rem}
.card h3{margin-top:0}input,select{padding:.5rem;background:#0f0f13;border:1px solid #333;
color:#eee;border-radius:6px}button{padding:.5rem 1rem;background:#4c6ef5;color:#fff;
border:0;border-radius:6px;cursor:pointer;font-size:.9rem}
button.danger{background:#e03131}button.success{background:#2f9e44}
button.renew{background:#7c3aed}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.5rem;
border-bottom:1px solid #2a2a35;vertical-align:top}th{color:#999;font-size:.8rem}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem}
.badge.on{background:#2f9e4433;color:#51cf66}.badge.off{background:#e0313133;color:#ff6b6b}
.badge.over{background:#f59f0033;color:#ffd43b}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
textarea{width:100%;height:80px;background:#0f0f13;color:#eee;border:1px solid #333;
border-radius:6px;padding:.5rem;font-family:monospace;font-size:.8rem}
pre{background:#0f0f13;padding:1rem;border-radius:6px;overflow:auto;font-size:.8rem;margin:0}
.stat{display:inline-block;margin-right:2rem;margin-bottom:.5rem}
.stat b{display:block;color:#888;font-size:.75rem;text-transform:uppercase}
.stat span{font-size:1.2rem;color:#51cf66}
.ok{background:#2f9e4433;border-left:3px solid #51cf66;padding:.75rem;border-radius:6px;margin:.5rem 0}
.warn{background:#f59f0033;border-left:3px solid #f59f00;padding:.75rem;border-radius:6px;margin:.5rem 0}
code{background:#0f0f13;padding:.15rem .4rem;border-radius:4px;font-size:.85rem}
.renew-form{display:flex;gap:.25rem;align-items:center;margin-top:.3rem;flex-wrap:wrap}
.renew-form input{width:52px;padding:.15rem .3rem;font-size:.75rem;border:1px solid #333;
background:#0f0f13;color:#eee;border-radius:4px}
.renew-form button{padding:.15rem .5rem;font-size:.75rem;background:#7c3aed}
.renew-form span{font-size:.7rem;color:#888}
</style></head><body>"""

def make_link(u):
    userinfo = f"{CIPHER_NAME}:{u['password']}"
    enc = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
    name = urllib.parse.quote(f"{CONFIG['name_prefix']}-{u['name']}")
    return f"ss://{enc}@{CONFIG['public_host']}:{CONFIG['listen_port']}#{name}"

def build_subscription():
    links = []
    for u in all_users():
        if not u["enabled"]:
            continue
        userinfo = f"{CIPHER_NAME}:{u['password']}"
        enc = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
        name = urllib.parse.quote(f"{CONFIG['name_prefix']}-{u['name']}")
        links.append(f"ss://{enc}@{CONFIG['public_host']}:{CONFIG['listen_port']}#{name}")
    return base64.b64encode("\n".join(links).encode()).decode()

# --- Per-user public page ---
def user_info_dict(u, token):
    used = used_of(u)
    q = u["quota_bytes"]
    remaining = max(0, q - used) if q > 0 else None
    exp = u["expires_at"]
    secs_left = max(0, exp - now()) if exp else None
    active = bool(u["enabled"]) and not is_expired(u) and not is_over_quota(u)
    return {
        "id": u["id"],
        "name": u["name"],
        "enabled": bool(u["enabled"]),
        "active": active,
        "used_bytes": used,
        "quota_bytes": q,
        "remaining_bytes": remaining,
        "expires_at": exp,
        "expires_at_iso": (datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
                           if exp else None),
        "seconds_left": secs_left,
        "ss_link": make_link(u),
        "page_url": f"http://{CONFIG['public_host']}:{CONFIG['sub_port']}/u/{token}",
        "sub_url": f"http://{CONFIG['public_host']}:{CONFIG['sub_port']}/u/{token}/sub",
    }

def user_page_html(u, token):
    link = make_link(u)
    used = used_of(u)
    q = u["quota_bytes"]
    remaining = max(0, q - used) if q > 0 else None
    exp = u["expires_at"]

    if is_expired(u):
        status_html = '<span class="badge off">منقضی شده</span>'
    elif not u["enabled"]:
        status_html = '<span class="badge off">غیرفعال</span>'
    elif q > 0 and used >= q:
        status_html = '<span class="badge over">اتمام حجم</span>'
    else:
        status_html = '<span class="badge on">فعال</span>'

    if exp:
        secs_left = max(0, exp - now())
        days_left = secs_left // 86400
        hours_left = (secs_left % 86400) // 3600
        time_left = ("منقضی شده" if secs_left <= 0
                     else f"{days_left} روز و {hours_left} ساعت")
        exp_str = fmt_time(exp)
    else:
        time_left = "نامحدود"
        exp_str = "—"

    remaining_str = "نامحدود" if remaining is None else fmt_bytes(remaining)

    if q > 0:
        pct = min(100, int(used * 100 / q))
        color = "#e03131" if pct >= 90 else ("#f59f00" if pct >= 70 else "#4c6ef5")
        bar = (f'<div style="background:#0f0f13;height:12px;border-radius:6px;'
               f'overflow:hidden;margin:.75rem 0"><div style="width:{pct}%;'
               f'height:100%;background:{color}"></div></div>')
        usage_line = (f'{fmt_bytes(used)} از {fmt_bytes(q)} '
                      f'({pct}% مصرف شده) — باقی‌مانده: <b>{fmt_bytes(remaining)}</b>')
    else:
        bar = ""
        usage_line = f'{fmt_bytes(used)} مصرف شده (حجم نامحدود)'

    sub_url = f"http://{CONFIG['public_host']}:{CONFIG['sub_port']}/u/{token}/sub"
    head = DASH_HEAD.replace("<html>", '<html dir="rtl" lang="fa">', 1)

    return head + f'''<div class="header">
    <h1>🪶 {html.escape(u["name"])}</h1>
    <span>{status_html}</span>
    </div>
    <div class="card"><h3>وضعیت حساب</h3>
    {bar}
    <p style="color:#bbb;font-size:.9rem">{usage_line}</p>
    <div class="stat"><b>حجم باقی‌مانده</b><span>{remaining_str}</span></div>
    <div class="stat"><b>زمان باقی‌مانده</b><span>{time_left}</span></div>
    <div class="stat"><b>تاریخ انقضا</b><span>{exp_str}</span></div>
    </div>
    <div class="card"><h3>کانفیگ اتصال</h3>
    <textarea readonly onclick="this.select()" style="height:60px">{html.escape(link)}</textarea>
    <p style="color:#888;font-size:.8rem">این لینک را کپی کرده و در کلاینت Shadowsocks خود وارد کنید.</p>
    </div>
    <div class="card"><h3>لینک اشتراک اختصاصی</h3>
    <code style="word-break:break-all">{html.escape(sub_url)}</code>
    <p style="color:#888;font-size:.8rem">با هر بار بازکردن این صفحه، آمار به‌روز نمایش داده می‌شود.</p>
    </div>
    </body></html>'''

def dashboard_html():
    p = ['<div class="header"><h1>🪶 Feathersock</h1>'
         f'<span style="color:#888">{CIPHER_NAME}</span> '
         '<a href="/diag">diag</a> · <a href="/logout">Logout</a></div>']
    total = sum(_traffic_cache.values())
    p.append(f'''<div class="card">
    <div class="stat"><b>Uptime</b><span>{int(time.time() - START_TIME)}s</span></div>
    <div class="stat"><b>Total</b><span>{fmt_bytes(total)}</span></div>
    <div class="stat"><b>Users</b><span>{len(_users_cache)}</span></div>
    <div class="stat"><b>Auth OK</b><span>{_stats["ss_auth_ok"]}</span></div>
    <div class="stat"><b>DNS</b><span>{_stats["dns_queries"]}</span></div>
    <div class="stat"><b>Cached</b><span>{_stats["dns_cached"]}</span></div>
    </div>''')
    p.append(f'''<div class="card"><h3>⚡ Client Setup</h3>
    <div class="ok"><b>UDP Relay ON</b> (critical for CDN video)</div>
    <div class="ok"><b>Bypass OFF</b> (LAN, China, etc.)</div>
    <div class="ok"><b>Proxy/Global mode</b></div>
    <p style="color:#888;font-size:.85rem">Server: <b>{CONFIG['public_host']}:{CONFIG['listen_port']}</b></p>
    </div>''')
    p.append('''<div class="card"><h3>Create User</h3>
    <form method="POST" action="/add" class="row">
    <input name="name" placeholder="Name" required>
    <input name="password" placeholder="Password" style="width:200px">
    <label>GB <input name="quota" type="number" min="0" step="0.1" value="10" style="width:70px"></label>
    <label>Days <input name="days" type="number" min="0" value="30" style="width:60px"></label>
    <button class="success">Create</button></form></div>''')
    p.append('<div class="card"><h3>Users</h3><table><thead><tr>'
             '<th>Name</th><th>Status</th><th>Usage</th><th>Expires</th><th>Actions / Renew</th>'
             '</tr></thead><tbody>')
    if not _users_cache:
        p.append('<tr><td colspan="5" style="text-align:center;color:#666">No users.</td></tr>')
    for u in all_users():
        uid = u["id"]
        used = used_of(u)
        q = u["quota_bytes"]
        if is_expired(u):
            st = '<span class="badge off">Expired</span>'
        elif not u["enabled"]:
            st = '<span class="badge off">Disabled</span>'
        elif q > 0 and used >= q:
            st = '<span class="badge over">Over</span>'
        else:
            st = '<span class="badge on">Active</span>'
        qh = f'{fmt_bytes(used)} / {fmt_bytes(q)}' if q else f'{fmt_bytes(used)} / ∞'
        nm = html.escape(u["name"])
        tok = user_token(u)
        p.append(f'''<tr><td>{nm}</td><td>{st}</td><td>{qh}</td>
        <td>{fmt_time(u["expires_at"])}</td>
        <td>
          <a href="/config/{uid}">config</a> ·
          <a href="/u/{tok}" target="_blank">public</a> ·
          <form method="POST" action="/reset/{uid}" style="display:inline"
          onsubmit="return confirm('Reset?')"><button style="padding:.2rem .4rem;font-size:.75rem">Reset</button></form> ·
          <form method="POST" action="/toggle/{uid}" style="display:inline">
          <button style="padding:.2rem .4rem;font-size:.75rem">{"Off" if u["enabled"] else "On"}</button></form> ·
          <form method="POST" action="/delete/{uid}" style="display:inline"
          onsubmit="return confirm('Delete?')"><button class="danger" style="padding:.2rem .4rem;font-size:.75rem">Del</button></form>
          <form method="POST" action="/renew/{uid}" class="renew-form"
                onsubmit="return confirm('Renew this user?')">
            <span>+</span>
            <input name="add_days" type="number" min="0" value="30" title="Add days">
            <span>d</span>
            <input name="add_gb" type="number" min="0" step="0.1" value="0" title="Add GB">
            <span>GB</span>
            <button class="renew">Renew</button>
          </form>
        </td></tr>''')
    p.append("</tbody></table></div></body></html>")
    return DASH_HEAD + "".join(p)

def config_html(u):
    link = html.escape(make_link(u))
    tok = user_token(u)
    main_base = f"http://{CONFIG['public_host']}:{CONFIG['listen_port']}/u/{tok}"
    sub_base = f"http://{CONFIG['public_host']}:{CONFIG['sub_port']}/u/{tok}"
    sub_url = f"http://{CONFIG['public_host']}:{CONFIG['sub_port']}/sub"
    uid = u["id"]
    return DASH_HEAD + f'''<div class="header">
    <h1>{html.escape(u["name"])}</h1><a href="/">← Back</a></div>
    <div class="card"><h3>Link</h3>
    <textarea readonly onclick="this.select()">{link}</textarea>
    <p style="color:#888;font-size:.85rem">Pass: <code>{html.escape(u["password"])}</code></p></div>
    <div class="card"><h3>Renew</h3>
    <form method="POST" action="/renew/{uid}" class="row"
          onsubmit="return confirm('Renew this user?')">
      <label>Days <input name="add_days" type="number" min="0" value="30" style="width:80px"></label>
      <label>GB <input name="add_gb" type="number" min="0" step="0.1" value="0" style="width:80px"></label>
      <button class="renew">Renew</button>
    </form>
    <p style="color:#888;font-size:.8rem">
      If the user's quota or time is <b>unlimited (0)</b>, renew is skipped.
      To convert unlimited to limited, create a new user or delete + recreate.
    </p>
    </div>
    <div class="card"><h3>Per-user page</h3>
    <p style="margin:.25rem 0">Main port: <code>{html.escape(main_base)}</code></p>
    <p style="margin:.25rem 0">Sub port:&nbsp; <code>{html.escape(sub_base)}</code></p>
    <p style="margin:.25rem 0">JSON: <code>{html.escape(main_base)}/json</code></p>
    <p style="margin:.25rem 0">Sub:&nbsp;&nbsp;&nbsp;&nbsp; <code>{html.escape(main_base)}/sub</code></p>
    <p style="color:#888;font-size:.8rem">No login required — the token is the secret.</p>
    </div>
    <div class="card"><h3>Global Sub URL</h3><code>{html.escape(sub_url)}</code></div>
    </body></html>'''

# =============================================================
# HTTP handler
# =============================================================
async def handle_http(reader, writer, first5):
    _stats["http_conn"] += 1
    data = first5
    try:
        while b"\r\n\r\n" not in data and len(data) < 65536:
            c = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not c:
                break
            data += c
    except Exception:
        return
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].decode("latin-1").split(" ", 2)
        if len(parts) < 2:
            await send_response(writer, 400, "text/plain", "Bad")
            return
        method = parts[0].upper()
        raw_path = parts[1]
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().lower().decode()] = v.strip().decode("latin-1")
    except Exception:
        await send_response(writer, 400, "text/plain", "Bad")
        return

    if method == "POST":
        cl = int(headers.get("content-length", "0") or 0)
        while len(body) < cl:
            try:
                c = await asyncio.wait_for(reader.read(cl - len(body)), timeout=10)
            except Exception:
                break
            if not c:
                break
            body += c
    try:
        form = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
    except Exception:
        form = {}

    path = raw_path.split("?", 1)[0].split("#", 1)[0].strip()
    while "//" in path:
        path = path.replace("//", "/")
    if path.endswith("/") and path != "/":
        path = path.rstrip("/") or "/"
    if not path.startswith("/"):
        path = "/" + path

    if path == "/health":
        await send_response(writer, 200, "application/json", json.dumps({
            "ok": True, "users": len(_users_cache), "uptime": int(time.time() - START_TIME)}))
        return
    if path == "/sub":
        await send_response(writer, 200, "text/plain", build_subscription())
        return
    if path == "/favicon.ico":
        await send_response(writer, 204, "text/plain", b"")
        return

    # --- Per-user public page (no admin login) ---
    if path.startswith("/u/"):
        parts_u = path[3:].strip("/").split("/")
        token = parts_u[0] if parts_u else ""
        u = find_user_by_token(token)
        if not u:
            await send_response(writer, 404, "text/plain", "Not found")
            return
        sub = parts_u[1] if len(parts_u) > 1 else ""
        if sub == "sub":
            if not u["enabled"] or is_expired(u) or is_over_quota(u):
                await send_response(writer, 200, "text/plain", "")
            else:
                body_b64 = base64.b64encode(make_link(u).encode()).decode()
                await send_response(writer, 200, "text/plain", body_b64)
            return
        if sub == "json":
            info = user_info_dict(u, token)
            await send_response(writer, 200, "application/json",
                                json.dumps(info, ensure_ascii=False, indent=2))
            return
        if sub:
            await send_response(writer, 404, "text/plain", "Not found")
            return
        await send_response(writer, 200, "text/html", user_page_html(u, token))
        return

    if path == "/diag":
        await send_response(writer, 200, "application/json", json.dumps({
            "uptime_sec": int(time.time() - START_TIME),
            "cipher": CIPHER_NAME,
            "has_aesni": _has_aesni,
            "users": len(_users_cache),
            "stats": dict(_stats),
            "dns_health": _dns_health,
            "dns_cache_size": len(_dns_cache),
            "tuning": _tuning_report,
            "outbound": _outbound_report,
            "recent": [[c[0], c[1], c[2]] for c in list(_recent)[-20:]],
            "logs": list(_logbuf)[-30:]}, ensure_ascii=False, indent=2))
        return
    if path == "/sysctl":
        await send_response(writer, 200, "text/plain", _sysctl_script or "# all applied")
        return

    if path == "/login" and method == "POST":
        u = form.get("username", [""])[0]
        p = form.get("password", [""])[0]
        if secrets.compare_digest(u, CONFIG["admin_user"]) and \
           secrets.compare_digest(p, CONFIG["admin_pass"]):
            t = new_session()
            c = f"session={t}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"
            await send_response(writer, 302, "text/plain", "",
                                ["Location: /", f"Set-Cookie: {c}"])
        else:
            await send_response(writer, 200, "text/html",
                                LOGIN_HTML.replace("__ERROR__", '<div class="err">Invalid</div>'))
        return
    if path == "/logout":
        raw = headers.get("cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("session="):
                sessions.pop(part[8:], None)
                break
        await send_response(writer, 302, "text/plain", "",
                            ["Location: /", "Set-Cookie: session=; Path=/; HttpOnly; Max-Age=0"])
        return
    if not check_session_from_cookie(headers):
        await send_response(writer, 200, "text/html", LOGIN_HTML.replace("__ERROR__", ""))
        return

    if path in ("/", "/index.html"):
        try:
            content = dashboard_html()
        except Exception as e:
            content = f"<h1>Err</h1><pre>{html.escape(str(e))}</pre>"
        await send_response(writer, 200, "text/html", content, head_only=(method == "HEAD"))
        return

    if path == "/add" and method == "POST":
        name = form.get("name", [""])[0].strip()
        pwd = form.get("password", [""])[0].strip()
        try:
            q = float(form.get("quota", ["0"])[0] or 0)
        except ValueError:
            q = 0
        try:
            d = int(form.get("days", ["0"])[0] or 0)
        except ValueError:
            d = 0
        if not name:
            await send_response(writer, 400, "text/plain", "Name req")
            return
        if not pwd:
            pwd = secrets.token_urlsafe(16)
        try:
            uid = create_user(name, pwd, q, d)
        except ValueError:
            await send_response(writer, 400, "text/plain", "Exists")
            return
        await send_response(writer, 302, "text/plain", "", [f"Location: /config/{uid}"])
        return

    parts = path.strip("/").split("/")
    if len(parts) == 2:
        action, sid = parts
        try:
            uid = int(sid)
        except ValueError:
            await send_response(writer, 400, "text/plain", "Bad")
            return
        if action == "config" and method == "GET":
            u = get_user(uid)
            if not u:
                await send_response(writer, 404, "text/plain", "NF")
                return
            await send_response(writer, 200, "text/html", config_html(u))
            return
        if action == "toggle" and method == "POST":
            u = get_user(uid)
            if u:
                update_user(uid, enabled=0 if u["enabled"] else 1)
            await send_response(writer, 302, "text/plain", "", ["Location: /"])
            return
        if action == "delete" and method == "POST":
            delete_user(uid)
            await send_response(writer, 302, "text/plain", "", ["Location: /"])
            return
        if action == "reset" and method == "POST":
            _traffic_cache[uid] = 0
            _traffic_pending.pop(uid, None)
            save_traffic()
            await send_response(writer, 302, "text/plain", "", ["Location: /"])
            return
        if action == "renew" and method == "POST":
            try:
                add_days = int(form.get("add_days", ["0"])[0] or 0)
            except ValueError:
                add_days = 0
            try:
                add_gb = float(form.get("add_gb", ["0"])[0] or 0)
            except ValueError:
                add_gb = 0
            applied = renew_user(uid, add_days, add_gb)
            if applied:
                bits = []
                if "days" in applied:
                    bits.append(f"+{applied['days']}d")
                if "gb" in applied:
                    bits.append(f"+{applied['gb']}GB")
                log(f"renew #{uid} {' '.join(bits)}")
            await send_response(writer, 302, "text/plain", "", ["Location: /"])
            return

    await send_response(writer, 404, "text/plain", f"Not found: {path}")

# =============================================================
# SS TCP handler
# =============================================================
def identify_user(salt, enc_len):
    n0 = _NONCES[0]
    for u in _users_cache.values():
        try:
            cipher = CIPHER_CLS(derive_subkey(u["master_key"], salt))
            ln = int.from_bytes(cipher.decrypt(n0, enc_len, None), "big")
            if 0 < ln <= MAX_PAYLOAD:
                return u, cipher, ln
        except Exception:
            continue
    return None, None, 0

async def handle_ss(reader, writer, initial):
    _stats["ss_conn"] += 1
    w_t = None
    try:
        leftover = b""
        if len(initial) < SALT_LEN:
            salt = initial + await asyncio.wait_for(
                reader.readexactly(SALT_LEN - len(initial)),
                timeout=CONFIG["first_byte_timeout"])
        elif len(initial) > SALT_LEN:
            salt = initial[:SALT_LEN]
            leftover = initial[SALT_LEN:]
        else:
            salt = initial

        needed = 2 + TAG_LEN
        if len(leftover) < needed:
            enc_len = leftover + await asyncio.wait_for(
                reader.readexactly(needed - len(leftover)),
                timeout=CONFIG["first_byte_timeout"])
            leftover = b""
        else:
            enc_len = leftover[:needed]
            leftover = leftover[needed:]

        user, cipher, ln = identify_user(salt, enc_len)
        if not user or not user["enabled"] or is_expired(user) or is_over_quota(user):
            _stats["ss_auth_fail"] += 1
            _recent.append((now(), "?", "AUTH_FAIL"))
            return
        _stats["ss_auth_ok"] += 1
        uid = user["id"]

        needed = ln + TAG_LEN
        if len(leftover) < needed:
            payload_enc = leftover + await asyncio.wait_for(
                reader.readexactly(needed - len(leftover)), timeout=15)
        else:
            payload_enc = leftover[:needed]

        try:
            target_data = cipher.decrypt(_NONCES[1], payload_enc, None)
        except Exception as e:
            _recent.append((now(), "?", f"PAYLOAD: {e}"))
            return
        if len(target_data) < 2:
            return

        atyp = target_data[0]
        if atyp == 0x01:
            addr = socket.inet_ntoa(target_data[1:5])
            port = struct.unpack(">H", target_data[5:7])[0]
            early = target_data[7:]
            host_label = addr
        elif atyp == 0x03:
            dl = target_data[1]
            domain = target_data[2:2 + dl].decode(errors="replace")
            port = struct.unpack(">H", target_data[2 + dl:4 + dl])[0]
            early = target_data[4 + dl:]
            host_label = domain
            addr = domain
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, target_data[1:17])
            port = struct.unpack(">H", target_data[17:19])[0]
            early = target_data[19:]
            host_label = addr
        else:
            return

        try:
            r_t, w_t, used_ip = await connect_with_fallback(addr, port)
            _stats["target_ok"] += 1
            _recent.append((now(), "?", f"{user['name']} → {host_label}:{port} ✅ ({used_ip})"))
        except Exception as e:
            _stats["target_fail"] += 1
            _recent.append((now(), "?", f"{host_label}:{port} {type(e).__name__}"))
            return

        w_salt = os.urandom(SALT_LEN)
        w_pipe = SSPipe(derive_subkey(user["master_key"], w_salt))
        writer.write(w_salt)
        await writer.drain()
        if early:
            w_t.write(early)

        r_pipe = SSPipe(derive_subkey(user["master_key"], salt), start_nonce=2)
        quota = user["quota_bytes"]
        first_burst = [True]

        async def c2t():
            local = 0
            last_flush = time.time()
            try:
                while True:
                    if quota > 0 and _traffic_cache.get(uid, 0) >= quota:
                        return
                    ln_enc = await asyncio.wait_for(
                        reader.readexactly(2 + TAG_LEN),
                        timeout=CONFIG["idle_timeout"])
                    cln = r_pipe.dec_len(ln_enc)
                    if cln <= 0 or cln > MAX_PAYLOAD:
                        return
                    pay_enc = await asyncio.wait_for(
                        reader.readexactly(cln + TAG_LEN),
                        timeout=CONFIG["idle_timeout"])
                    data = r_pipe.dec_payload(pay_enc)
                    local += len(data)
                    w_t.write(data)
                    if should_drain(w_t):
                        await w_t.drain()
                    if time.time() - last_flush > 0.5:
                        traffic_add(uid, local)
                        local = 0
                        last_flush = time.time()
            except Exception:
                return
            finally:
                if local:
                    traffic_add(uid, local)

        async def t2c():
            local = 0
            last_flush = time.time()
            try:
                while True:
                    if quota > 0 and _traffic_cache.get(uid, 0) >= quota:
                        return
                    data = await asyncio.wait_for(
                        r_t.read(CONFIG["read_chunk"]),
                        timeout=CONFIG["idle_timeout"])
                    if not data:
                        return
                    local += len(data)
                    out = bytearray()
                    for i in range(0, len(data), MAX_PAYLOAD):
                        out += w_pipe.enc_chunk(data[i:i + MAX_PAYLOAD])
                    await send_first_burst(writer, bytes(out), first_burst)
                    if time.time() - last_flush > 0.5:
                        traffic_add(uid, local)
                        local = 0
                        last_flush = time.time()
            except Exception:
                return
            finally:
                if local:
                    traffic_add(uid, local)

        t_c2t = asyncio.create_task(c2t())
        t_t2c = asyncio.create_task(t2c())
        try:
            await asyncio.wait([t_c2t, t_t2c], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t_c2t, t_t2c):
                if not t.done():
                    t.cancel()
            await asyncio.gather(t_c2t, t_t2c, return_exceptions=True)
    except Exception as e:
        dbg(f"ss: {type(e).__name__}: {e!r}")
    finally:
        await close_writer(writer)
        await close_writer(w_t)

# =============================================================
# SS UDP relay
# =============================================================
async def handle_ss_udp(data, addr, transport):
    try:
        if len(data) < SALT_LEN + TAG_LEN:
            return
        salt = data[:SALT_LEN]
        encrypted = data[SALT_LEN:]

        n0 = _NONCES[0]
        user = None
        for u in _users_cache.values():
            try:
                CIPHER_CLS(derive_subkey(u["master_key"], salt)).decrypt(n0, encrypted, None)
                user = u
                break
            except Exception:
                continue
        if not user or not user["enabled"] or is_expired(user) or is_over_quota(user):
            return

        cipher = CIPHER_CLS(derive_subkey(user["master_key"], salt))
        plain = cipher.decrypt(n0, encrypted, None)
        if len(plain) < 1:
            return

        atyp = plain[0]
        if atyp == 0x01:
            addr_str = socket.inet_ntoa(plain[1:5])
            port = struct.unpack(">H", plain[5:7])[0]
            payload = plain[7:]
            header_len = 7
        elif atyp == 0x03:
            dl = plain[1]
            addr_str = plain[2:2 + dl].decode(errors="replace")
            port = struct.unpack(">H", plain[2 + dl:4 + dl])[0]
            payload = plain[4 + dl:]
            header_len = 4 + dl
        elif atyp == 0x04:
            addr_str = socket.inet_ntop(socket.AF_INET6, plain[1:17])
            port = struct.unpack(">H", plain[17:19])[0]
            payload = plain[19:]
            header_len = 19
        else:
            return

        try:
            socket.inet_aton(addr_str)
            ips = [addr_str]
        except Exception:
            ips = await resolve_domain_all(addr_str)
        if not ips:
            return

        loop = asyncio.get_running_loop()
        resp = None
        for ip in ips[:3]:
            sock = None
            try:
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect((ip, port))
                await loop.sock_sendall(sock, payload)
                resp = await asyncio.wait_for(
                    loop.sock_recv(sock, 65536), timeout=3)
                break
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
        if not resp:
            _recent.append((now(), str(addr), f"UDP {addr_str}:{port} timeout"))
            return

        resp_addr = plain[:header_len]
        full = resp_addr + resp
        w_salt = os.urandom(SALT_LEN)
        w_cipher = CIPHER_CLS(derive_subkey(user["master_key"], w_salt))
        enc = w_cipher.encrypt(n0, full, None)
        transport.sendto(w_salt + enc, addr)
        traffic_add(user["id"], len(payload) + len(resp))
        _stats["ss_udp_relay"] += 1
    except Exception as e:
        dbg(f"udp: {type(e).__name__}: {e}")

class SSUdpProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(handle_ss_udp(data, addr, self.transport))

    def error_received(self, exc):
        dbg(f"ss udp: {exc}")

# =============================================================
# Dispatcher
# =============================================================
conn_sem = asyncio.Semaphore(CONFIG["max_connections"])

async def dispatch(reader, writer):
    tune_socket(writer.get_extra_info("socket"))
    _stats["total_conn"] += 1
    async with conn_sem:
        try:
            first = await asyncio.wait_for(
                reader.readexactly(1), timeout=CONFIG["first_byte_timeout"])
        except Exception:
            await close_writer(writer)
            return
        if first in b"GPHDO":
            try:
                rest = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            except Exception:
                await close_writer(writer)
                return
            combined = first + rest
            if combined[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI"):
                try:
                    await handle_http(reader, writer, combined)
                except Exception:
                    pass
                return
            try:
                await handle_ss(reader, writer, combined)
            except Exception:
                pass
            return
        try:
            await handle_ss(reader, writer, first)
        except Exception:
            pass

# =============================================================
# Subscription server
# =============================================================
def subscription_http_thread():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path.split("?", 1)[0]

            if p in ("/sub", "/sub.txt"):
                c = build_subscription()
                self._send(c.encode(), "text/plain; charset=utf-8")
                return

            if p.startswith("/u/"):
                parts_u = p[3:].strip("/").split("/")
                token = parts_u[0] if parts_u else ""
                u = find_user_by_token(token)
                if not u:
                    self.send_response(404)
                    self.end_headers()
                    return
                sub = parts_u[1] if len(parts_u) > 1 else ""
                if sub == "sub":
                    if not u["enabled"] or is_expired(u) or is_over_quota(u):
                        self._send(b"", "text/plain; charset=utf-8")
                    else:
                        body_b64 = base64.b64encode(make_link(u).encode()).decode()
                        self._send(body_b64.encode(), "text/plain; charset=utf-8")
                    return
                if sub == "json":
                    info = user_info_dict(u, token)
                    self._send(json.dumps(info, ensure_ascii=False, indent=2).encode(),
                               "application/json; charset=utf-8")
                    return
                if sub:
                    self.send_response(404)
                    self.end_headers()
                    return
                self._send(user_page_html(u, token).encode(), "text/html; charset=utf-8")
                return

            self.send_response(404)
            self.end_headers()

        def _send(self, data, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    try:
        s = HTTPServer(("0.0.0.0", CONFIG["sub_port"]), H)
        log(f"Sub: http://0.0.0.0:{CONFIG['sub_port']}/sub")
        s.serve_forever()
    except Exception as e:
        log(f"Sub: {e}")

# =============================================================
# Main
# =============================================================
def install_signals(loop):
    def _shutdown():
        log("shutdown")
        traffic_flush()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except Exception:
            pass

async def main():
    log(f"=== Feathersock v{__version__} ===")
    log(f"CPU: {'AES-NI' if _has_aesni else 'no AES-NI'} → {CIPHER_NAME}")
    auto_tune()
    load_users()
    load_traffic()

    asyncio.create_task(flush_loop())
    asyncio.create_task(test_outbound_async())
    asyncio.create_task(dns_healthcheck_loop())
    asyncio.create_task(dns_cache_cleanup_loop())
    if CONFIG["sub_enabled"]:
        threading.Thread(target=subscription_http_thread, daemon=True).start()

    loop = asyncio.get_running_loop()
    install_signals(loop)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CONFIG["sock_buf"])
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CONFIG["sock_buf"])
        lsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 5)
    except Exception:
        pass
    try:
        lsock.bind((CONFIG["listen_host"], CONFIG["listen_port"]))
        lsock.listen(1024)
        lsock.setblocking(False)
    except OSError as e:
        log(f"FATAL bind: {e}")
        try:
            for t in asyncio.all_tasks(loop):
                t.cancel()
            loop.run_until_complete(
                asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True))
        except Exception:
            pass
        sys.exit(1)

    try:
        await loop.create_datagram_endpoint(
            lambda: SSUdpProtocol(),
            local_addr=(CONFIG["listen_host"], CONFIG["listen_port"]),
        )
        log(f"SS UDP relay on {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    except Exception as e:
        log(f"⚠️  UDP failed: {e}")

    server = await asyncio.start_server(dispatch, sock=lsock)
    log(f"LISTENING TCP {CONFIG['listen_host']}:{CONFIG['listen_port']}")
    log(f"Panel: http://{CONFIG['public_host']}:{CONFIG['listen_port']}/")
    log(f"Sub:   http://{CONFIG['public_host']}:{CONFIG['sub_port']}/sub")
    log(f"User pages: http://{CONFIG['public_host']}:{CONFIG['sub_port']}/u/<token>")
    log(f"Speed: read_chunk={CONFIG['read_chunk']} frag_burst={CONFIG['frag_burst_limit']}")

    async with server:
        await server.serve_forever()

def run_server():
    """Launch with the best available event loop. Compatible with Python 3.9+."""
    if AIOFASTNET_AVAILABLE:
        try:
            aiofastnet.install_policy()
            log("✅ aiofastnet enabled (transport/TLS layer optimized)")
        except Exception as e:
            log(f"⚠️  aiofastnet.install_policy failed: {e} — continuing with standard asyncio")

    try:
        if UVLOOP_AVAILABLE:
            loop = uvloop.new_event_loop()
            log("⚡ Event loop: uvloop")
        else:
            loop = asyncio.new_event_loop()
            log("🐢 Event loop: standard asyncio")
    except Exception as e:
        log(f"⚠️  loop create failed: {e} — falling back to asyncio")
        loop = asyncio.new_event_loop()

    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        log("bye")
    except SystemExit:
        pass
    except Exception as e:
        log(f"FATAL: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            loop.close()
        except Exception:
            pass

if __name__ == "__main__":
    run_server()
