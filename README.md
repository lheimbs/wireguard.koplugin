# wireguard.koplugin

A [KOReader](https://github.com/koreader/koreader) plugin that routes all
network traffic through a [WireGuard](https://www.wireguard.com/) VPN tunnel
using [wireproxy](https://github.com/whyvl/wireproxy) as a local SOCKS5 proxy.

Supports **Android 4.4 and later** as well as other Linux-based KOReader platforms.

---

## Features

- **Enable/Disable toggle** — Start or stop the VPN from the KOReader main menu.
- **File pickers** — Use KOReader's built-in path chooser to select both the
  `wireproxy` binary and your WireGuard `.conf` file.
- **Automatic config patching** — The plugin writes a temporary copy of your
  WireGuard config and appends a `[Socks5]` section automatically.
- **Proxy environment setup** — Sets `http_proxy`, `https_proxy` and `ALL_PROXY`
  so that KOReader's HTTP stack routes through the tunnel.
- **Autostart** — Optionally restart the tunnel when KOReader opens.
- **Troubleshooting menu** — View live status, test the SOCKS5 port, inspect
  wireproxy and plugin logs, view the active config, force-restart, and clear logs.
- **Detailed debug logging** — All plugin events are written to a rotating log
  in KOReader's cache directory.

---

## Installation

1. Copy the `wireguard.koplugin` directory into KOReader's `plugins/` folder:
   ```
   <KOReader data dir>/plugins/wireguard.koplugin/
   ```
2. Restart KOReader.

The plugin will appear as **WireGuard VPN** under *More tools* in the main menu.

---

## Setup

### 1 — Obtain a wireproxy binary

Download (or cross-compile) a `wireproxy` binary for your device's CPU
architecture from the [wireproxy releases page](https://github.com/whyvl/wireproxy/releases):

| Device / OS | Architecture |
|-------------|-------------|
| Most Android phones / tablets | `arm64` or `arm` |
| x86 Android emulator | `386` or `amd64` |
| Kobo / Kindle (ARM) | `arm` |

Copy the binary to your device (e.g. `/sdcard/wireproxy`).

### 2 — Prepare a WireGuard config

Create a standard WireGuard `.conf` file, for example:

```ini
[Interface]
PrivateKey = <your private key>
Address    = 10.13.13.2/32
DNS        = 1.1.1.1

[Peer]
PublicKey  = <server public key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint   = vpn.example.com:51820
```

You do **not** need to add a `[Socks5]` section — the plugin adds it automatically.

### 3 — Configure and enable

1. Open KOReader → **Menu → More tools → WireGuard VPN**.
2. Tap **Select wireproxy binary…** and navigate to the binary.
3. Tap **Select WireGuard config file…** and navigate to your `.conf` file.
4. Optionally adjust **SOCKS5 Port** (default: `1080`).
5. Tap **Enable WireGuard VPN**.

---

## How it works

```
KOReader HTTP request
       │
       ▼
  http_proxy=socks5h://127.0.0.1:1080
       │
       ▼
wireproxy (local SOCKS5 proxy on port 1080)
       │   (WireGuard kernel/userspace tunnel)
       ▼
   WireGuard peer (VPN server)
       │
       ▼
   Internet
```

1. The plugin reads your WireGuard config and appends:
   ```ini
   [Socks5]
   BindAddress = 127.0.0.1:<port>
   ```
   to a temporary copy stored in KOReader's cache directory.

2. It launches `wireproxy` as a background process with that config and stores
   its PID so it can be stopped cleanly later.

3. It sets the `http_proxy`, `https_proxy`, and `ALL_PROXY` environment
   variables to `socks5h://127.0.0.1:<port>` via the C `setenv()` syscall,
   so all subsequent HTTP/HTTPS requests from KOReader go through the tunnel.

4. On disable (or KOReader exit) the environment variables are cleared and
   wireproxy is terminated gracefully (SIGTERM → SIGKILL if needed).

---

## Troubleshooting

All items are in **WireGuard VPN → Troubleshooting**:

| Item | Description |
|------|-------------|
| Show VPN Status | PID, port, paths, autostart flag |
| Test SOCKS5 Port N | Checks whether the local port is open with `nc` |
| Show wireproxy Log | Last 4 KB of wireproxy stdout/stderr |
| Show Plugin Log | Last 4 KB of the plugin's own debug log |
| Show Active Config | Redacted copy of the runtime config |
| Force Restart | Stop then start wireproxy |
| Clear Logs | Delete both log files |

Log files are stored in KOReader's cache directory:

```
<KOReader data>/cache/wireguard_wireproxy.log   ← wireproxy output
<KOReader data>/cache/wireguard_plugin.log      ← plugin debug log
```

---

## Requirements

- KOReader with LuaJIT (standard KOReader builds include this).
- A `wireproxy` binary compiled for your device architecture.
- A valid WireGuard `.conf` file.
- `nc` (netcat) available on the device — used only for the SOCKS5 port test;
  present by default on Android via BusyBox.

---

## License

MIT — see [LICENSE](LICENSE).
