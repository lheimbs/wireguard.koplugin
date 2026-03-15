# wireguard.koplugin

A [KOReader](https://github.com/koreader/koreader) plugin that routes all
network traffic through a [WireGuard](https://www.wireguard.com/) VPN tunnel
using [wireproxy](https://github.com/whyvl/wireproxy) as a local HTTP CONNECT
proxy.

---

## Android version requirements

The plugin behaviour differs significantly between Android versions due to the
**W^X (Write XOR Execute) policy** introduced in Android 10 (API 29).

### Android 10 and later — custom KOReader build required

Android 10+ forbids executing binaries from any app-writable path (`/sdcard`,
app cache, etc.).  The only permitted location is the app's
`nativeLibraryDir`, which the system installer mounts with execute permission.

**What this means**: the `wireproxy` binary must be compiled for
`GOOS=android GOARCH=arm64`, renamed `libwireproxy.so`, placed in the APK's
`jniLibs/` directory, and installed as part of a **custom KOReader build**.
A sideloaded binary on `/sdcard` will fail silently with `EACCES`.

Build the binary:
```bash
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" ./cmd/wireproxy
```

In KOReader's build system (`make/android.mk`):
```makefile
# Stored as a .so to satisfy the W^X policy on Android 10+
cp -v $(WIREPROXY_BIN) $(ANDROID_LIBS)/libwireproxy.so
```

At runtime the plugin retrieves the path via the Android API:
```lua
local hasAndroid, android = pcall(require, "android")
if hasAndroid and android.nativeLibraryDir then
    local path = android.nativeLibraryDir .. "/libwireproxy.so"
end
```

> **Note**: `GOOS=android` (not `GOOS=linux`) is required so wireproxy skips
> Landlock and other sandbox calls that are either absent or blocked by the
> app's seccomp filter on Android kernels.  A `GOOS=linux` arm64 binary will
> die silently on the first blocked syscall.

### Android 4.4 – 9 — sideloaded binary works

Older Android versions do not enforce W^X, so a binary copied to `/sdcard`
or another writable path can be `exec()`-ed directly.  A standard
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0` build is sufficient.  No custom
KOReader build is needed.

---

## Features

- **Enable/Disable toggle** — Start or stop the VPN from the KOReader main menu.
- **File pickers** — Use KOReader's built-in path chooser to select your
  WireGuard `.conf` file and an optional `wireproxy` fallback binary.
- **Automatic config patching** — The plugin writes a temporary copy of your
  WireGuard config and appends an `[http]` section automatically.
- **HTTP CONNECT proxy** — Sets KOReader's `NetworkMgr` HTTP proxy to
  `http://127.0.0.1:<port>` and monkey-patches `socket.http.request` to
  handle HTTPS via a proper CONNECT + TLS tunnel.
- **Autostart** — Optionally restart the tunnel when KOReader opens.
- **Troubleshooting menu** — View live status, test the proxy port, inspect
  wireproxy and plugin logs, view the active config, force-restart, and clear
  logs.
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

| Platform | How to get the binary |
|----------|-----------------------|
| **Android 10+** | Build with `GOOS=android GOARCH=arm64`; include in a custom KOReader APK as `libwireproxy.so` (see above) |
| **Android 4.4–9** | Download or build for `linux/arm64`; copy to `/sdcard/wireproxy` |
| **x86 Android emulator** | `linux/amd64` binary on a writable path |
| **Kobo / Kindle (ARM)** | `linux/arm` binary |

Download pre-built binaries from the
[wireproxy releases page](https://github.com/whyvl/wireproxy/releases).

On Android 10+ builds that bundle `libwireproxy.so`, KOReader uses the bundled
library from `android.nativeLibraryDir` automatically.  Any binary selected
through the UI is kept as a fallback path only.

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

You do **not** need to add an `[http]` section — the plugin adds it
automatically.

### 3 — Configure and enable

1. Open KOReader → **Menu → More tools → WireGuard VPN**.
2. Tap **Select wireproxy binary…** and navigate to the binary (Android 4.4–9
   and non-Android only; skip on Android 10+ with a bundled build).
3. Tap **Select WireGuard config file…** and navigate to your `.conf` file.
4. Optionally adjust **Proxy Port** (default: `1080`).
5. Tap **Enable WireGuard VPN**.

---

## How it works

```
KOReader HTTP/HTTPS request
         │
         ▼
  NetworkMgr HTTP proxy = http://127.0.0.1:1080
         │
         ▼  (HTTP requests: forwarded as-is)
         │  (HTTPS requests: CONNECT tunnel + TLS, via monkey-patched http.request)
         │
         ▼
wireproxy (local HTTP CONNECT proxy on port 1080)
         │   (WireGuard userspace tunnel)
         ▼
   WireGuard peer (VPN server)
         │
         ▼
      Internet
```

1. The plugin reads your WireGuard config and appends:
   ```ini
   [http]
   BindAddress = 127.0.0.1:<port>
   ```
   to a temporary copy stored in KOReader's cache directory.

2. It launches `wireproxy` as a background process with that config and stores
   its PID so it can be stopped cleanly later.

3. It sets the HTTP proxy via `NetworkMgr:setHTTPProxy("http://127.0.0.1:<port>")`.
   LuaSocket's `http.PROXY` is set to this value, routing plain HTTP traffic
   through wireproxy automatically.

4. Because LuaSocket's `socket.http` cannot perform HTTPS via HTTP CONNECT
   natively (it uses forward-proxy mode instead of a CONNECT tunnel),
   `socket.http.request` is monkey-patched to intercept `https://` requests,
   open a TCP connection to the proxy, send a `CONNECT host:443` request,
   then perform a TLS handshake (with SNI) over the established tunnel.

5. On disable (or KOReader exit) the proxy setting is cleared and wireproxy
   is terminated gracefully (SIGTERM → SIGKILL if needed).

---

## Android binary execution — technical background

### W^X policy (Android 10+)

Android 10 enforces that no file from a writable path may be `exec()`-ed.
Violations fail with `EACCES` and produce no error output, making them hard
to diagnose.  The fix is to ship the binary inside the APK's `jniLibs/`
directory (named `lib<name>.so`), which the package installer places in the
app's `nativeLibraryDir` with execute permission.

### Architecture mismatch

An arm64 KOReader process inherits an arm64 seccomp BPF filter.  Running a
32-bit ARM binary under it causes an instant `SIGSYS` on the child's first
syscall — the process dies with no log output.  Always build wireproxy for
`GOARCH=arm64` on arm64 devices.

### Blocked syscalls (`GOOS=android` vs `GOOS=linux`)

wireproxy includes sandboxing code (Landlock, pledge, unveil) that issues
syscalls either absent from Android kernels or blocked by the app's seccomp
filter.  Building with `GOOS=android` lets wireproxy detect the platform at
runtime and skip those code paths, preventing a silent `SIGSYS` crash.

### Quick reference

| Problem | Symptom | Fix |
|---------|---------|-----|
| W^X policy violation | `EACCES` on exec, silent failure | Bundle as `.so` in `jniLibs/`; custom KOReader build |
| 32-bit binary in 64-bit process | Instant silent death | Build with `GOARCH=arm64` |
| Blocked syscall (Landlock, etc.) | `SIGSYS`, silent death | Build with `GOOS=android` |

---

## Proxy networking — technical background

### Why HTTP CONNECT and not SOCKS5

LuaSocket's `socket.http` supports only plain `http://` and `https://` proxy
schemes.  Setting `http.PROXY` to a `socks5h://` URL causes a nil-index crash
inside `socket/http.lua` because `SCHEMES["socks5h"]` is undefined.

### Why HTTPS needs a monkey-patch

`socket.http`'s proxy support uses forward-proxy mode: it rewrites the request
URI to an absolute URL (`GET https://host/path HTTP/1.1`) and sends it to the
proxy.  HTTP CONNECT proxies (including wireproxy) expect `CONNECT host:443`
for HTTPS, not a forwarded plain-HTTP request, so HTTPS connections would time
out without the patch.

### Quick reference

| Problem | Symptom | Fix |
|---------|---------|-----|
| Wrong proxy scheme | Crash: `attempt to index nil` in `http.lua:223` | Use `http://…` only; set via `NetworkMgr:setHTTPProxy()` |
| HTTPS timeout via HTTP proxy | Connection timeout | Monkey-patch `http.request` to do CONNECT + TLS |
| Missing SNI | `tlsv1 alert internal error` | Set `servername` in `ssl.wrap` and call `ts:sni()` |
| Reachability check bypasses proxy | Server unreachable despite working proxy | Replace `socket.tcp():connect()` probe with HTTP CONNECT probe |

---

## Troubleshooting

All items are in **WireGuard VPN → Troubleshooting**:

| Item | Description |
|------|-------------|
| Show VPN Status | PID, port, paths, autostart flag |
| Test Proxy Port N | Checks whether the local port is open |
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
- **Android 10+**: a custom KOReader APK that bundles `libwireproxy.so`
  (built with `GOOS=android GOARCH=arm64`).
- **Android 4.4–9 / non-Android**: a `wireproxy` binary compiled for your
  device architecture, placed anywhere accessible on the filesystem.
- A valid WireGuard `.conf` file.

---

## License

MIT — see [LICENSE](LICENSE).
