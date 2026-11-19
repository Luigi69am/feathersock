<div align="center">

# 🪶 Feathersock

**A featherweight Shadowsocks server with a built-in web admin panel — all in a single Python file.**

Runs on the smallest VPS you can find. No database, no framework, no Xray.

[Features](#-features) · [Comparison](#-why-feathersock-over-xray--v2ray) · [Quick Start](#-quick-start) · [Config](#️-configuration) · [Deploy](#-deploy-with-systemd)

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Size](https://img.shields.io/badge/size-~70%20KB-lightgrey)

</div>

---

> ⚠️ **Disclaimer:** This software is provided for educational and personal privacy use. Circumventing state censorship may be illegal in your jurisdiction. You are solely responsible for how you use it.

---

## 📑 Table of Contents

1. [Features](#-features)
2. [Minimum Requirements](#-minimum-requirements)
3. [Why Feathersock over Xray / V2Ray](#-why-feathersock-over-xray--v2ray)
4. [Quick Start](#-quick-start)
5. [User Management](#-user-management)
6. [Client Setup](#-client-setup)
7. [Configuration](#️-configuration)
8. [CLI Reference](#-cli-reference)
9. [Deploy with systemd](#-deploy-with-systemd)
10. [Docker](#-docker-optional)
11. [Optional Acceleration](#-optional-acceleration)
12. [Monitoring & Debugging](#-monitoring--debugging)
13. [Security Notes](#-security-notes)
14. [Troubleshooting](#-troubleshooting)
15. [Contributing](#-contributing)
16. [License](#-license)

---

## ✨ Features

### Lightweight by design
- 🐜 **Single file, ~70 KB** — no external daemon, no compiled binaries.
- 💾 **Runs on 128 MB RAM / 1 vCPU** — idle footprint is roughly **35–50 MB**.
- 🐧 **Pure Python, pure Linux** — no kernel modules, no Docker, no root required for ports ≥ 1024.

### Built-in management
- 🖥 **Web admin panel** — create, edit, enable/disable, delete users from any browser.
- 📊 **Live traffic accounting** — per-user usage, quota, and expiry, persisted every 5 seconds.
- 📦 **Subscription URL** — one link for every device, auto-updating in most clients.
- 📝 **Human-readable state** — users in `users.txt`, traffic in `traffic.txt`. Easy to back up, easy to inspect.

### Networking & evasion
- 🔐 **Shadowsocks AEAD** — AES-256-GCM (hardware-accelerated with AES-NI) or ChaCha20-Poly1305.
- 🧠 **Smart DNS with multi-IP fallback** — resolves *all* A records and races them; one dead CDN IP won't kill a connection.
- 🛡 **DPI evasion** — fragments only the **first 8 KB** of each connection, so throughput is unaffected.
- 📡 **UDP relay** — for games, voice, and some streaming (uses the same port).

### Performance
- ⚡ **Optional acceleration** — drop-in `uvloop` + `aiofastnet` give up to **2–4×** throughput. Falls back to stock asyncio automatically.
- 🚀 **Auto-tune** — tries to enable BBR, `fq` qdisc, TCP Fast Open, and larger socket buffers at startup (works if you have `sudo`).

---

## 📋 Minimum Requirements

| Resource | Minimum | Comfortable |
|---|---|---|
| OS | Any Linux (macOS works for testing) | Debian 12 / Ubuntu 22.04 |
| RAM | **128 MB** | 256 MB |
| vCPU | **0.5 core** | 1 core |
| Disk | **60 MB** free | 200 MB |
| Python | **3.9+** | 3.11+ |
| Network | 1 public TCP port (UDP on same port optional) | — |

That's it. No database, no Docker, no root, no kernel modules.

---

## 🥊 Why Feathersock over Xray / V2Ray

Xray is a fantastic general-purpose tool. Feathersock is a **focused** one — it does Shadowsocks + a control panel, and it does that with a much smaller footprint. If you need VLESS/Reality/XTLS, use Xray. If you want to run a small Shadowsocks service on a $1 VPS and manage it from your browser, Feathersock is the lighter choice.

| | **Feathersock** | **Xray / V2Ray** |
|---|---|---|
| File size | **~70 KB** single `.py` | 20–40 MB static binary |
| Idle RAM | **~35–50 MB** | 60–120 MB |
| RAM at 100 concurrent clients | **~80–150 MB** | 200–500 MB |
| Minimum vCPU | **0.5 core** | 1 core |
| Disk footprint (with deps) | **~50 MB** | ~80–120 MB |
| Dependencies | Python 3.9+ | none |
| Setup time (first user) | **~2 minutes** | 10–30 minutes |
| Config complexity | 3 required fields | 20+ fields typical |
| Web admin panel | **Built-in** | 3rd-party (X-UI etc.) |
| User / quota management | **Built-in** | needs panel + DB |
| Subscription URL | **Built-in** | needs panel |
| Protocols | Shadowsocks AEAD | VLESS, VMess, Trojan, SS, Reality, XTLS… |
| DPI evasion | TLS-style fragmentation | Reality, uTLS, XTLS |

> Figures are approximate and depend on traffic, cipher, and OS. Measure yourself on `/diag`.

---

## 🚀 Quick Start

### Step 1 — Clone

```bash
git clone https://github.com/Luigi69am/feathersock.git
cd feathersock
```

### Step 2 — Install dependencies

```bash
pip3 install -r requirements.txt
```

> Only `cryptography` is mandatory. `uvloop` and `aiofastnet` are optional.

### Step 3 — Generate config

```bash
python3 feathersock.py --generate-config
```

This creates `config.json` and prints a **random admin password**. Copy it immediately — it is not shown again.

### Step 4 — Edit config

```bash
nano config.json
```

Set at minimum `public_host` to your server's public IP:

```json
{
  "public_host": "203.0.113.10",
  "admin_user": "admin",
  "admin_pass": "the-random-password-that-was-printed",
  "listen_port": 14755,
  "sub_port": 8080
}
```

### Step 5 — Run

```bash
python3 feathersock.py
```

Expected output:

```
[19:38:05] ✅ aiofastnet enabled (transport/TLS layer optimized)
[19:38:05] ⚡ Event loop: uvloop
[19:38:05] === Feathersock v1.0.0 ===
[19:38:05] CPU: AES-NI → aes-256-gcm
[19:38:05] auto-tune: 12/12 applied
[19:38:05] loaded 0 users
[19:38:05] LISTENING TCP 0.0.0.0:14755
[19:38:05] Panel: http://203.0.113.10:14755/
[19:38:05] Sub:   http://203.0.113.10:8080/sub
```

### Step 6 — Open the panel

Browse to:

```
http://YOUR_IP:14755/
```

Sign in with the `admin_user` / `admin_pass` from `config.json`.

---

## 👤 User Management

### Create a user

In the panel, use the **Create User** form:

| Field | Description |
|---|---|
| **Name** | Unique username |
| **Password** | Shadowsocks password. Leave blank to auto-generate |
| **GB** | Traffic quota in GB. `0` = unlimited |
| **Days** | Validity in days. `0` = never expires |

Clicking **Create** takes you straight to that user's config page.

### User config page

- **Link** — the `ss://` link to import in a client
- **Pass** — the user's password (for your records)
- **Sub URL** — the subscription URL for all devices

### Row actions

| Action | Effect |
|---|---|
| **config** | Show link and password |
| **Reset** | Reset traffic usage to zero |
| **Off / On** | Temporarily disable / re-enable |
| **Del** | Permanently delete |

### Status badges

| Badge | Meaning |
|---|---|
| 🟢 **Active** | Enabled and healthy |
| 🔴 **Expired** | Past expiry date |
| 🔴 **Disabled** | Manually disabled |
| 🟡 **Over** | Traffic quota exhausted |

---

## 📱 Client Setup

### Option A — Direct link

1. In the panel, click **config** next to a user.
2. Copy the `ss://...` link.
3. In your client, choose **Import from clipboard** or **Add from URL**.

### Option B — Subscription URL (recommended)

1. Copy the subscription URL: `http://YOUR_IP:8080/sub`
2. In your client, go to **Subscription** → **Add** → paste the URL.
3. The client auto-adds all enabled users and refreshes periodically.

### Recommended clients

| Platform | Client |
|---|---|
| Android | [v2rayNG](https://github.com/2dust/v2rayNG), NekoBox, Shadowsocks |
| iOS | Shadowrocket, Streisand |
| Windows | [v2rayN](https://github.com/2dust/v2rayN), Clash Verge, Shadowsocks-windows |
| macOS | ClashX, ShadowsocksX-NG |
| Linux | sing-box, Clash Meta |

> **Tip:** In the client, choose **Global** or **Proxy** mode — not **Bypass**. For YouTube and streaming, also enable **UDP relay**.

---

## ⚙️ Configuration

Copy [`config.example.json`](config.example.json) to `config.json` and edit.

### Required fields

| Key | Description |
|---|---|
| `public_host` | Your server's public IP or domain |
| `admin_pass` | Admin panel password — **must not be `admin`** |

### Commonly tweaked

| Key | Default | Description |
|---|---|---|
| `listen_port` | `14755` | TCP port to listen on |
| `sub_port` | `8080` | Port for the subscription HTTP server |
| `admin_user` | `admin` | Panel username |
| `cipher` | `"auto"` | `aes-256-gcm`, `chacha20-ietf-poly1305`, or `auto` |
| `debug` | `false` | Verbose logging |
| `auto_tune` | `true` | Try BBR / sysctl tweaks on startup |
| `max_connections` | `800` | Max simultaneous TCP connections |
| `idle_timeout` | `1800` | Seconds before an idle connection is closed |
| `dns_upstreams` | `["1.1.1.1", "8.8.8.8", "9.9.9.9"]` | Resolvers for multi-IP fallback |

### Environment overrides

Useful for Docker or systemd:

```bash
export FEATHERSOCK_PUBLIC_HOST=203.0.113.10
export FEATHERSOCK_ADMIN_PASS=$(openssl rand -base64 24)
python3 feathersock.py
```

Supported: `FEATHERSOCK_PUBLIC_HOST`, `FEATHERSOCK_ADMIN_USER`, `FEATHERSOCK_ADMIN_PASS`, `FEATHERSOCK_LISTEN_HOST`, `FEATHERSOCK_LISTEN_PORT`, `FEATHERSOCK_SUB_PORT`, `FEATHERSOCK_DEBUG`, `FEATHERSOCK_CONFIG`.

---

## 🖥 CLI Reference

```text
python3 feathersock.py                    # run with config.json
python3 feathersock.py --version          # show version
python3 feathersock.py --help             # show help
python3 feathersock.py --generate-config  # create starter config.json
python3 feathersock.py -c custom.json     # use a custom config path
```

---

## 🐧 Deploy with systemd

```bash
# 1. Create a system user
sudo useradd -r -s /bin/false feathersock

# 2. Copy files
sudo mkdir -p /opt/feathersock
sudo cp feathersock.py config.json /opt/feathersock/
sudo chown -R feathersock:feathersock /opt/feathersock
sudo chmod 600 /opt/feathersock/config.json

# 3. Install the service
sudo cp systemd/feathersock.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now feathersock

# 4. Follow logs
sudo journalctl -u feathersock -f
```

The bundled service file grants `CAP_NET_BIND_SERVICE` so you can bind to ports below 1024 (e.g. 443) without running the whole service as root.

---

## 🐳 Docker (optional)

```bash
docker build -t feathersock .
docker run -d --name feathersock \
  -p 14755:14755/tcp -p 14755:14755/udp -p 8080:8080 \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v $(pwd)/data:/app/data \
  feathersock
```

Or with Compose:

```bash
docker compose up -d
```

> In Docker, point `users_file` and `traffic_file` in `config.json` to `/app/data/...` so they persist across restarts.

---

## ⚡ Optional Acceleration

For maximum throughput on the same hardware:

```bash
pip3 install uvloop aiofastnet
```

At startup the log tells you which loop was chosen:

- `🚀 aiofastnet + uvloop` — best
- `⚡ uvloop` — good
- `🐢 standard asyncio` — still works, slower

Check OpenSSL linkage for `aiofastnet`:

```bash
python3 -c "import aiofastnet; print(aiofastnet.OPENSSL_DYN_LIBS)"
```

If it prints `None`, `aiofastnet` is on a fallback engine — usually because Python was installed via `uv`. Use the system Python to avoid this.

---

## 📊 Monitoring & Debugging

| Endpoint | Purpose |
|---|---|
| `GET /diag` | JSON with uptime, stats, DNS health, outbound reachability, recent connections, logs |
| `GET /health` | Simple liveness check |
| `GET /sysctl` | The sysctl script the auto-tuner *would* apply — run it manually if `sudo` isn't available |

---

## 🔒 Security Notes

- **Set a strong `admin_pass`.** The panel has no rate limiting.
- **Put HTTPS in front of the panel** (Caddy, Nginx) if you expose it publicly. Feathersock speaks plain HTTP for the panel.
- **Back up `users.txt` and `traffic.txt`** — they contain all user data.
- **Never commit `config.json`, `users.txt`, or `traffic.txt`** — they are in `.gitignore`.
- **Rotate `admin_pass` periodically** and after any suspected compromise.

---

## 🩺 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `❌ 'public_host' is not set` | Edit `config.json` or set `FEATHERSOCK_PUBLIC_HOST` |
| `FATAL bind: Address already in use` | Another process is using `listen_port` |
| `⚠️ UDP failed` | Port is TCP-only, or UDP is blocked upstream |
| Clients can't connect | Firewall, wrong `public_host`, or ISP blocking |
| Slow speeds | Install `uvloop` + `aiofastnet`; check `/diag` → `outbound` |

---

## 🤝 Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Please **never** include real IPs, passwords, or user data in bug reports.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Made with 🪶 for people who just want a small, fast proxy.

</div>
