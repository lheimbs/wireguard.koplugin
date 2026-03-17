--[[
WireGuard VPN Plugin for KOReader
Routes all network traffic through a WireGuard VPN tunnel using wireproxy
as a local HTTP CONNECT proxy. Supports Android 4.4+.

Usage:
  1. Select your wireproxy binary via the menu.
  2. Select your WireGuard .conf file via the menu.
  3. Toggle "Enable WireGuard VPN" to start the tunnel.

The plugin will append an [http] section to the WireGuard config (writing
a modified copy to a temp path) and launch wireproxy as a background process.
It then configures KOReader's HTTP proxy (via NetworkMgr) so that LuaSocket
and all HTTP traffic routes through the tunnel.
--]]

local WidgetContainer = require("ui/widget/container/widgetcontainer")
local UIManager = require("ui/uimanager")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local ConfirmBox = require("ui/widget/confirmbox")
local PathChooser = require("ui/widget/pathchooser")
local FileChooser = require("ui/widget/filechooser")
local LuaSettings = require("luasettings")
local DataStorage = require("datastorage")
local logger = require("logger")
local ffiutil = require("ffi/util")
local lfs = require("libs/libkoreader-lfs")
local util = require("util")
local Device = require("device")
local NetworkMgr = require("ui/network/manager")
local _ = require("gettext")
local hasAndroid, android = pcall(require, "android")

-- ---------------------------------------------------------------------------
-- Module-level FFI setup for setenv/unsetenv (Linux/Android)
-- ---------------------------------------------------------------------------
local ffi = require("ffi")
-- Guard against re-definition if the module is reloaded.
pcall(function()
    ffi.cdef([[
        int setenv(const char *name, const char *value, int overwrite);
        int unsetenv(const char *name);
    ]])
end)
-- Even if pcall fails (already defined), ffi.C.setenv is still accessible.

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------
local PLUGIN_NAME        = "wireguard"
local DEFAULT_PROXY_PORT  = 1080

-- DataStorage does not expose getCacheDir(); cache lives under data dir.
local DATA_DIR           = DataStorage:getDataDir()
local CACHE_DIR          = DATA_DIR .. "/cache"
local PID_FILE           = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.pid"
local RUNTIME_CONF_FILE  = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.conf"
local WIREPROXY_LOG_FILE = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.log"
local PLUGIN_LOG_FILE    = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_plugin.log"
-- Installed binary lives in the exec-capable data directory.  /sdcard is
-- mounted noexec on Android so we always copy the binary here first.
local DEFAULT_INSTALLED_BINARY = CACHE_DIR .. "/wireproxy"
local EXEC_DIR_CANDIDATES = {
    CACHE_DIR,
    "/data/data/org.koreader.launcher/files",
    "/data/data/org.koreader.launcher.fdroid/files",
    "/data/data/com.github.koreader/files",
    "/data/data/org.koreader.launcher.debug/files",
}
local BUNDLED_WIREPROXY_LIB = "libwireproxy.so"
local MAX_LOG_TAIL_BYTES = 4096   -- bytes shown in the log viewer
local STOP_WAIT_LOOPS    = 20     -- × 100 ms = 2 s graceful wait
local KILL_WAIT_LOOPS    = 10     -- × 100 ms = 1 s after SIGKILL

-- ---------------------------------------------------------------------------
-- Plugin class
-- ---------------------------------------------------------------------------
local WireGuard = WidgetContainer:extend{
    name        = PLUGIN_NAME,
    is_doc_only = false,
}

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------

function WireGuard:init()
    -- Load persisted settings
    local settings_path = DataStorage:getSettingsDir() .. "/" .. PLUGIN_NAME .. ".lua"
    self.settings = LuaSettings:open(settings_path)

    self.wireproxy_binary = self.settings:readSetting("wireproxy_binary") or ""
    self.installed_binary = self.settings:readSetting("installed_binary") or DEFAULT_INSTALLED_BINARY
    self.wireguard_config = self.settings:readSetting("wireguard_config") or ""
    self.proxy_port       = self.settings:readSetting("proxy_port") or DEFAULT_PROXY_PORT
    self.autostart        = self.settings:isTrue("autostart")

    self:_log("INFO", "Plugin initialized")
    self:_log("DEBUG", string.format(
        "Settings — binary=%q  config=%q  port=%d  autostart=%s",
        self.wireproxy_binary, self.wireguard_config,
        self.proxy_port, tostring(self.autostart)))
    self:_log("DEBUG", "Installed binary path: " .. tostring(self.installed_binary))
    if hasAndroid and android and android.nativeLibraryDir then
        self:_log("DEBUG", "Android nativeLibraryDir: " .. android.nativeLibraryDir)
        local bundled_path = self:_getBundledWireproxyPath()
        self:_log("DEBUG", "Bundled wireproxy " .. (bundled_path and ("found at " .. bundled_path) or "not found"))
    end

    -- Register to main menu
    if self.ui and self.ui.menu then
        self.ui.menu:registerToMainMenu(self)
    end

    -- Auto-start if the user left VPN enabled last session
    if self.autostart then
        self:_log("INFO", "Autostart enabled — starting wireproxy")
        UIManager:nextTick(function()
            local ok, err = self:_startWireproxy()
            if not ok then
                self:_log("WARN", "Autostart failed: " .. (err or "unknown"))
            end
        end)
    end
end

-- ---------------------------------------------------------------------------
-- Settings helpers
-- ---------------------------------------------------------------------------

function WireGuard:_saveSettings()
    self.settings:saveSetting("wireproxy_binary", self.wireproxy_binary)
    self.settings:saveSetting("installed_binary", self.installed_binary)
    self.settings:saveSetting("wireguard_config",  self.wireguard_config)
    self.settings:saveSetting("proxy_port",        self.proxy_port)
    if self.autostart then
        self.settings:makeTrue("autostart")
    else
        self.settings:makeFalse("autostart")
    end
    self.settings:flush()
    self:_log("DEBUG", "Settings flushed to disk")
end

-- Called by KOReader before exit to persist in-memory state.
function WireGuard:onFlushSettings()
    self:_saveSettings()
end

-- ---------------------------------------------------------------------------
-- Logging
-- ---------------------------------------------------------------------------

--- Write a timestamped line to the plugin log file and KOReader's logger.
function WireGuard:_log(level, message)
    local ts   = os.date("%Y-%m-%d %H:%M:%S")
    local line = string.format("[%s] [%s] %s\n", ts, level, tostring(message))

    -- Mirror to KOReader's built-in logger
    if level == "ERROR" then
        logger.err("WireGuard:", message)
    elseif level == "WARN" then
        logger.warn("WireGuard:", message)
    elseif level == "DEBUG" then
        logger.dbg("WireGuard:", message)
    else
        logger.info("WireGuard:", message)
    end

    -- Append to plugin log file (best-effort; ignore write errors)
    local f = io.open(PLUGIN_LOG_FILE, "a")
    if f then
        f:write(line)
        f:close()
    end
end

--- Read the last MAX_LOG_TAIL_BYTES bytes of a log file.
local function _readLogTail(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local size = f:seek("end") or 0
    local start = math.max(0, size - MAX_LOG_TAIL_BYTES)
    f:seek("set", start)
    local content = f:read("*a")
    f:close()
    return content
end

-- ---------------------------------------------------------------------------
-- Process management
-- ---------------------------------------------------------------------------

--- Return the PID stored in the PID file, or nil.
function WireGuard:_readPID()
    local f = io.open(PID_FILE, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    if not content or content == "" then return nil end
    local pid
    for line in content:gmatch("[^\r\n]+") do
        local n = tonumber(line)
        if n then pid = n end
    end
    return pid
end

local _pidExists

--- Return true when the wireproxy process is alive.
function WireGuard:_isRunning()
    local pid = self:_readPID()
    if not pid then return false end
    return _pidExists(pid)
end

--- Send a signal to a process.  Returns true on success.
local function _sendSignal(sig, pid)
    local sig_num = ({ TERM = 15, KILL = 9 })[sig]
    if not sig_num then
        return false
    end
    return ffi.C.kill(pid, sig_num) == 0
end

local function _pidStatus(pid)
    if not pid then return false, nil end
    if ffi.C.kill(pid, 0) == 0 then
        return true, 0
    end
    local err = ffi.errno()
    -- EPERM means the process exists but we are not allowed to signal it.
    if err == ffi.C.EPERM then
        return true, err
    end
    return false, err
end

function _pidExists(pid)
    local alive = _pidStatus(pid)
    return alive
end

local function _readCommandOutput(cmd)
    local f = io.popen(cmd)
    if not f then return "" end
    local out = f:read("*a") or ""
    f:close()
    return out:gsub("%s+$", "")
end

local function _basename(path)
    return path and path:match("([^/]+)$") or nil
end

local function _runShellWithOutput(cmd)
    local tmp = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_diag.tmp"
    os.remove(tmp)
    local rc = os.execute(string.format("%s >%q 2>&1", cmd, tmp))
    local out = _readLogTail(tmp) or ""
    os.remove(tmp)
    return rc, out
end

local function _commandExists(name)
    return os.execute(string.format("command -v %q >/dev/null 2>&1", name)) == 0
end

function WireGuard:_findWireproxyPid(binary_path)
    local name = _basename(binary_path) or "wireproxy"
    local out = _readCommandOutput(string.format("pidof %q 2>/dev/null", name))
    local pid
    for token in out:gmatch("%d+") do
        pid = tonumber(token)
    end
    return pid
end

function WireGuard:_isProxyPortReachable()
    if not _commandExists("nc") then
        self:_log("DEBUG", "nc not available; skipping proxy port probe")
        return false
    end
    return os.execute(string.format("nc -z -w 1 127.0.0.1 %d >/dev/null 2>&1", self.proxy_port)) == 0
end

function WireGuard:_logStartupDiagnostics(binary_path, pid)
    local name = _basename(binary_path) or "wireproxy"
    self:_log("DEBUG", "--- wireproxy startup diagnostics begin ---")
    local checks = {
        { "which-sh", "command -v sh || true" },
        { "which-nc", "command -v nc || true" },
        { "binary-ls", string.format("ls -ahl %q || true", binary_path) },
        { "config-ls", string.format("ls -ahl %q || true", RUNTIME_CONF_FILE) },
        { "pidfile-ls", string.format("ls -ahl %q || true", PID_FILE) },
        { "pidfile-cat", string.format("cat %q || true", PID_FILE) },
        { "ps-wireproxy", "ps -A 2>/dev/null | grep -i wireproxy || true" },
        { "pidof", string.format("pidof %q 2>/dev/null || true", name) },
        { "configtest", string.format("%q -n -c %q || true", binary_path, RUNTIME_CONF_FILE) },
        { "log-head", string.format("head -n 40 %q || true", WIREPROXY_LOG_FILE) },
    }
    if pid then
        table.insert(checks, { "ps-pid", string.format("ps -A 2>/dev/null | grep -E '^[[:space:]]*%d[[:space:]]' || true", pid) })
    end
    for _, check in ipairs(checks) do
        local rc, out = _runShellWithOutput(check[2])
        self:_log("DEBUG", string.format("diag[%s] rc=%s", check[1], tostring(rc)))
        if out ~= "" then
            self:_log("DEBUG", string.format("diag[%s] output:\n%s", check[1], out))
        end
    end
    self:_log("DEBUG", "--- wireproxy startup diagnostics end ---")
end

--- Build the modified wireproxy config and write it to RUNTIME_CONF_FILE.
--- Returns true on success, or false + error message.
function WireGuard:_buildConfig()
    self:_log("DEBUG", "Reading WireGuard config: " .. self.wireguard_config)
    local f = io.open(self.wireguard_config, "r")
    if not f then
        return false, _("Cannot open WireGuard config file:\n") .. self.wireguard_config
    end
    local cfg = f:read("*a")
    f:close()

    -- If an [http] section is already present, update its BindAddress.
    -- Otherwise append a new section.
    if cfg:match("%[http%]") then
        cfg = cfg:gsub(
            "(BindAddress%s*=%s*)[^\n]*",
            string.format("%%1127.0.0.1:%d", self.proxy_port),
            1)
        self:_log("DEBUG", "Updated existing [http] BindAddress")
    else
        cfg = cfg .. string.format("\n[http]\nBindAddress = 127.0.0.1:%d\n",
                                   self.proxy_port)
        self:_log("DEBUG", "Appended [http] section with port " .. self.proxy_port)
    end

    local out = io.open(RUNTIME_CONF_FILE, "w")
    if not out then
        return false, _("Cannot write runtime config to:\n") .. RUNTIME_CONF_FILE
    end
    out:write(cfg)
    out:close()
    self:_log("INFO", "Runtime config written: " .. RUNTIME_CONF_FILE)
    return true
end

function WireGuard:_getBundledWireproxyPath()
    if hasAndroid and android and android.nativeLibraryDir then
        local bundled_path = android.nativeLibraryDir .. "/" .. BUNDLED_WIREPROXY_LIB
        if util.pathExists(bundled_path) then
            return bundled_path
        end
    end
    return nil
end

function WireGuard:_resolveWireproxyBinary()
    local bundled_path = self:_getBundledWireproxyPath()
    if bundled_path then
        return bundled_path, true
    end
    return self.installed_binary, false
end

--- Validate prerequisites.  Returns true or false + message.
function WireGuard:_checkPrereqs()
    local binary_path, is_bundled = self:_resolveWireproxyBinary()
    if not is_bundled and self.wireproxy_binary == "" then
        return false, _("wireproxy binary is not configured.\nPlease select it from the WireGuard menu.")
    end
    if self.wireguard_config == "" then
        return false, _("WireGuard config file is not configured.\nPlease select it from the WireGuard menu.")
    end
    if not util.pathExists(binary_path) then
        if is_bundled then
            return false, _("Bundled wireproxy library not found:\n") .. binary_path
        end
        return false, _("wireproxy binary not installed.\nPlease use \"Select wireproxy binary…\" again.")
    end
    if os.execute(string.format("[ -x %q ]", binary_path)) ~= 0 then
        if is_bundled then
            return false, _("Bundled wireproxy is not executable:\n") .. binary_path
        end
        return false, _("Installed wireproxy binary is not executable:\n") .. binary_path
    end
    if not util.pathExists(self.wireguard_config) then
        return false, _("WireGuard config not found:\n") .. self.wireguard_config
    end
    return true
end

--- Configure KOReader's HTTP proxy to route traffic through the local tunnel.
--- Uses NetworkMgr so LuaSocket's http.PROXY is set correctly.
function WireGuard:_applyProxyEnv(enable)
    local proxy_url = string.format("http://127.0.0.1:%d", self.proxy_port)
    if enable then
        self:_log("INFO", "Setting HTTP proxy → " .. proxy_url)
        NetworkMgr:setHTTPProxy(proxy_url)
        self:_patchHttpForProxy()
    else
        self:_log("INFO", "Clearing HTTP proxy")
        self:_unpatchHttpForProxy()
        NetworkMgr:setHTTPProxy(nil)
        G_reader_settings:delSetting("http_proxy")
        G_reader_settings:delSetting("http_proxy_enabled")
    end
end

--- Monkey-patch socket.http.request to support HTTPS via HTTP CONNECT proxy.
---
--- LuaSocket's http module only does forward-proxy requests (sending the full
--- URL to the proxy), which works for plain http:// targets but not https://.
--- For https:// we must send HTTP CONNECT to the proxy, establish the TLS
--- tunnel ourselves, then send the normal relative-path request through it.
function WireGuard:_patchHttpForProxy()
    local ok, http = pcall(require, "socket.http")
    if not ok then return end
    if http._wireguard_patched then return end

    local ok_ssl, ssl = pcall(require, "ssl")
    if not ok_ssl then
        self:_log("WARN", "ssl module not available; HTTPS through proxy will timeout")
        return
    end

    local socket_lib = require("socket")
    local url_mod    = require("socket.url")
    local ltn12      = require("ltn12")
    local orig       = http.request

    http._wireguard_original_request = orig
    http._wireguard_patched          = true

    local log = function(level, msg) self:_log(level, "http-patch: " .. msg) end

    http.request = socket_lib.protect(function(reqt, body)
        local target_url = type(reqt) == "string" and reqt
                           or (type(reqt) == "table" and reqt.url) or ""

        -- Only intercept HTTPS requests when proxy is active and no custom create
        if not http.PROXY
            or not target_url:match("^https://")
            or (type(reqt) == "table" and reqt.create)
        then
            return orig(reqt, body)
        end

        local parsed   = url_mod.parse(target_url)
        local tgt_host = parsed.host
        local tgt_port = tonumber(parsed.port) or 443

        -- Build a path-only URI (servers behind a CONNECT tunnel expect this)
        local path_uri = parsed.path or "/"
        if parsed.params then path_uri = path_uri .. ";" .. parsed.params end
        if parsed.query  then path_uri = path_uri .. "?" .. parsed.query  end

        -- Factory: returns a fresh socket wrapper each time create() is called.
        -- The wrapper's connect() establishes the CONNECT tunnel then TLS.
        local function make_connect_socket()
            local raw = socket_lib.tcp()
            local tls = nil

            local w = setmetatable({}, {
                __index = function(_, k)
                    local d = tls or raw
                    local v = d[k]
                    if type(v) == "function" then
                        return function(_, ...) return v(d, ...) end
                    end
                    return v
                end,
            })

            function w:settimeout(t)
                raw:settimeout(t)
                if tls then tls:settimeout(t) end
                return 1
            end

            function w:connect(proxy_h, proxy_p)
                -- 1. TCP to proxy
                local c_ok, c_err = raw:connect(proxy_h, proxy_p)
                if not c_ok then
                    log("ERROR", string.format("TCP→proxy %s:%s failed: %s",
                        proxy_h, proxy_p, tostring(c_err)))
                    return nil, c_err
                end
                log("DEBUG", string.format("TCP→proxy OK; sending CONNECT %s:%d",
                    tgt_host, tgt_port))

                -- 2. HTTP CONNECT request
                raw:send(string.format(
                    "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
                    tgt_host, tgt_port, tgt_host, tgt_port))

                -- 3. Read status line
                local line, l_err = raw:receive("*l")
                if not line then
                    log("ERROR", "no response from proxy: " .. tostring(l_err))
                    return nil, l_err or "proxy no response"
                end
                local code = tonumber(line:match("HTTP/%S+ (%d+)"))
                if code ~= 200 then
                    log("ERROR", "CONNECT rejected: " .. tostring(line))
                    return nil, "HTTP CONNECT failed: " .. tostring(line)
                end
                -- Drain remaining proxy headers
                repeat
                    line, l_err = raw:receive("*l")
                    if not line then return nil, l_err or "proxy header error" end
                until line == ""

                log("DEBUG", "CONNECT tunnel established; starting TLS handshake")

                -- 4. TLS over the tunnel
                local ts, ts_err = ssl.wrap(raw, {
                    mode       = "client",
                    protocol   = "any",
                    verify     = "none",
                    options    = {"all"},
                    servername = tgt_host,  -- SNI
                })
                if not ts then
                    log("ERROR", "ssl.wrap failed: " .. tostring(ts_err))
                    return nil, ts_err or "ssl.wrap failed"
                end
                -- Set SNI via method call as well (LuaSec API variant)
                if ts.sni then ts:sni(tgt_host) end
                local hs_ok, hs_err = ts:dohandshake()
                if not hs_ok then
                    log("ERROR", "TLS handshake failed: " .. tostring(hs_err))
                    return nil, hs_err or "TLS handshake failed"
                end
                tls = ts
                log("DEBUG", string.format("TLS to %s:%d OK", tgt_host, tgt_port))
                return 1
            end

            return w
        end

        -- Build request table with our create + explicit path URI
        local new_req
        if type(reqt) == "string" then
            local t = {}
            new_req = {
                url    = reqt,
                sink   = ltn12.sink.table(t),
                target = t,
                uri    = path_uri,
                create = make_connect_socket,
            }
            if body then
                new_req.source  = ltn12.source.string(body)
                new_req.headers = {
                    ["content-length"] = #body,
                    ["content-type"]   = "application/x-www-form-urlencoded",
                }
                new_req.method = "POST"
            end
            local _, code, headers, status = orig(new_req)
            return table.concat(t), code, headers, status
        else
            new_req = {}
            for k, v in pairs(reqt) do new_req[k] = v end
            new_req.create = make_connect_socket
            new_req.uri    = path_uri
            return orig(new_req)
        end
    end)

    self:_log("INFO", "socket.http patched: HTTPS tunnelled via HTTP CONNECT")
end

--- Restore the original socket.http.request.
function WireGuard:_unpatchHttpForProxy()
    local ok, http = pcall(require, "socket.http")
    if not ok then return end
    if http._wireguard_original_request then
        http.request = http._wireguard_original_request
        http._wireguard_original_request = nil
        http._wireguard_patched          = nil
        self:_log("INFO", "socket.http.request restored")
    end
end

--- Start wireproxy.  Returns true on success, or false + error string.
function WireGuard:_startWireproxy()
    local ok, err = self:_checkPrereqs()
    if not ok then return false, err end
    local binary_path, is_bundled = self:_resolveWireproxyBinary()

    if self:_isRunning() then
        self:_log("WARN", "wireproxy is already running — skipping start")
        return true
    end

    if is_bundled then
        self:_log("INFO", "Using bundled wireproxy: " .. binary_path)
    else
        -- Ensure the installed binary is executable (belt-and-suspenders guard).
        os.execute(string.format("chmod +x %q 2>/dev/null", binary_path))
    end

    -- Show file permissions
    os.execute(string.format("ls -ahl %q >%q", binary_path, WIREPROXY_LOG_FILE))

    -- Build the runtime config.
    ok, err = self:_buildConfig()
    if not ok then return false, err end

    -- Launch wireproxy in the background.
    -- The shell writes the PID to PID_FILE and redirects all output to the log.
    local cmd
    local has_custom_ld_library_path = false
    if is_bundled and hasAndroid and android and android.nativeLibraryDir then
        self:_log("DEBUG", "Setting LD_LIBRARY_PATH to " .. android.nativeLibraryDir)
        pcall(ffi.C.setenv, "LD_LIBRARY_PATH", android.nativeLibraryDir, 1)
        has_custom_ld_library_path = true
        cmd = string.format(
            "%q -c %q >%q 2>&1 </dev/null & echo $! >%q",
            binary_path,
            RUNTIME_CONF_FILE,
            WIREPROXY_LOG_FILE,
            PID_FILE)
    else
        cmd = string.format(
            "%q -c %q >%q 2>&1 </dev/null & echo $! >%q",
            binary_path,
            RUNTIME_CONF_FILE,
            WIREPROXY_LOG_FILE,
            PID_FILE)
    end
    self:_log("DEBUG", "Launching wireproxy: " .. cmd)

    local ret = os.execute(cmd)
    if has_custom_ld_library_path then
        pcall(ffi.C.unsetenv, "LD_LIBRARY_PATH")
    end
    if ret ~= 0 then
        self:_logStartupDiagnostics(binary_path, nil)
        return false, _("os.execute failed while starting wireproxy (exit code ") .. tostring(ret) .. ")"
    end

    -- Give the process a moment to initialise.
    ffiutil.sleep(1)
    local pid = self:_readPID()
    self:_log("DEBUG", "PID file after launch: " .. tostring(pid))

    local running = false
    for _ = 1, 20 do
        if self:_isRunning() then
            running = true
            break
        end
        ffiutil.sleep(0.1)
    end

    if not running then
        local recovered_pid = self:_findWireproxyPid(binary_path)
        if recovered_pid and _pidExists(recovered_pid) then
            local f = io.open(PID_FILE, "w")
            if f then
                f:write(tostring(recovered_pid), "\n")
                f:close()
            end
            pid = recovered_pid
            running = true
            self:_log("INFO", "Recovered running wireproxy PID via pidof: " .. tostring(recovered_pid))
        end
    end

    if not running and self:_isProxyPortReachable() then
        running = true
        self:_log("INFO", "HTTP proxy port became reachable even though PID checks failed")
    end

    if not running then
        self:_logStartupDiagnostics(binary_path, pid)
        local log_tail = _readLogTail(WIREPROXY_LOG_FILE) or ""
        if pid then
            local _, err = _pidStatus(pid)
            self:_log("DEBUG", "PID liveness check failed for PID " .. tostring(pid) ..
                " errno=" .. tostring(err))
        end
        self:_log("DEBUG", "pidof output: " ..
            _readCommandOutput(string.format("pidof %q 2>/dev/null", _basename(binary_path) or "wireproxy")))
        self:_log("ERROR", "wireproxy failed to start. Log tail:\n" .. log_tail)
        return false,
            _("wireproxy process died immediately after launch.\n\n") ..
            _("Last log output:\n") .. log_tail
    end

    self:_log("INFO", string.format("wireproxy running (PID %s)", tostring(pid)))

    -- Route KOReader traffic through the tunnel.
    self:_applyProxyEnv(true)
    return true
end

--- Stop wireproxy.  Returns true when the process is gone.
function WireGuard:_stopWireproxy()
    -- Always clear proxy settings first so KOReader falls back to direct.
    self:_applyProxyEnv(false)

    local pid = self:_readPID()
    if not pid then
        local binary_path = self:_resolveWireproxyBinary()
        pid = self:_findWireproxyPid(binary_path)
        if not pid then
            self:_log("INFO", "No PID file found and no running wireproxy process detected")
            return true
        end
        self:_log("INFO", "Recovered PID from pidof for stop: " .. tostring(pid))
    end

    if not _pidExists(pid) then
        os.remove(PID_FILE)
        self:_log("INFO", "wireproxy was already stopped")
        return true
    end

    -- Graceful SIGTERM
    _sendSignal("TERM", pid)
    for _ = 1, STOP_WAIT_LOOPS do
        if not _pidExists(pid) then break end
        ffiutil.sleep(0.1)
    end

    -- Force SIGKILL if still alive
    if _pidExists(pid) then
        self:_log("WARN", "wireproxy did not stop gracefully — sending SIGKILL")
        _sendSignal("KILL", pid)
        for _ = 1, KILL_WAIT_LOOPS do
            if not _pidExists(pid) then break end
            ffiutil.sleep(0.1)
        end
    end

    local stopped = not _pidExists(pid)
    if stopped then
        os.remove(PID_FILE)
        self:_log("INFO", "wireproxy stopped successfully")
    else
        self:_log("ERROR", "wireproxy could not be stopped (PID " .. tostring(pid) .. ")")
    end
    return stopped
end

-- ---------------------------------------------------------------------------
-- UI helpers
-- ---------------------------------------------------------------------------

--- Show an InfoMessage; pass `warn=true` for the warning icon.
local function _info(text, warn, timeout)
    UIManager:show(InfoMessage:new{
        icon    = warn and "notice-warning" or nil,
        text    = text,
        timeout = timeout,
    })
end

--- Toggle the VPN on/off and give the user feedback.
function WireGuard:_toggle()
    if self:_isRunning() then
        self:_log("INFO", "User toggled VPN off")
        local stopped = self:_stopWireproxy()
        self.autostart = false
        self:_saveSettings()
        _info(
            stopped and _("WireGuard VPN disabled.") or _("WireGuard VPN may not have stopped cleanly — check logs."),
            not stopped, 2)
    else
        self:_log("INFO", "User toggled VPN on")
        local ok, err = self:_startWireproxy()
        if ok then
            self.autostart = true
            self:_saveSettings()
            _info(_("WireGuard VPN enabled."), false, 2)
        else
            _info(_("Failed to start WireGuard VPN:\n\n") .. (err or _("Unknown error")), true)
        end
    end
end

-- ---------------------------------------------------------------------------
-- PathChooser wrappers
-- ---------------------------------------------------------------------------

local function _getPickerStartPath(saved_path)
    if saved_path and saved_path ~= "" then
        local parent = saved_path:match("^(.*)/[^/]+$")
        if parent and util.pathExists(parent) then
            return parent
        end
    end
    local home_dir = G_reader_settings:readSetting("home_dir") or Device.home_dir
    if home_dir and util.pathExists(home_dir) then
        return home_dir
    end
    return DataStorage:getDataDir()
end

local function _showUnfilteredPathChooser(opts)
    local saved_show_filter = FileChooser.show_filter
    local restored = false
    local function restoreFilter()
        if not restored then
            FileChooser.show_filter = saved_show_filter
            restored = true
        end
    end

    local onConfirm = opts.onConfirm
    opts.onConfirm = function(path)
        restoreFilter()
        if onConfirm then
            onConfirm(path)
        end
    end

    local close_callback = opts.close_callback
    opts.close_callback = function(...)
        restoreFilter()
        if close_callback then
            close_callback(...)
        end
    end

    FileChooser.show_filter = {}
    UIManager:show(PathChooser:new(opts))
end

local function _copyFile(source_path, destination_path)
    local source = io.open(source_path, "rb")
    if not source then
        return false, "source open failed"
    end
    local destination = io.open(destination_path, "wb")
    if not destination then
        source:close()
        return false, "destination open failed"
    end
    while true do
        local chunk = source:read(64 * 1024)
        if not chunk then break end
        destination:write(chunk)
    end
    source:close()
    destination:close()
    return true
end

function WireGuard:_installBinaryToExecutableDir(source_binary)
    self:_log("DEBUG", "Installing wireproxy from source: " .. tostring(source_binary))
    for _, target_dir in ipairs(EXEC_DIR_CANDIDATES) do
        self:_log("DEBUG", "Trying install directory: " .. target_dir)
        if lfs.attributes(target_dir, "mode") ~= "directory" then
            self:_log("DEBUG", "Skipping missing directory: " .. target_dir)
        else
            local destination = target_dir .. "/wireproxy"
            local copied, copy_err = _copyFile(source_binary, destination)
            if not copied then
                self:_log("DEBUG", string.format("Copy failed to %s: %s", destination, tostring(copy_err)))
            else
                local chmod_ret = os.execute(string.format("chmod +x %q 2>/dev/null", destination))
                local permissions = lfs.attributes(destination, "permissions") or "unknown"
                local has_exec_bit = permissions:find("x", 1, true) ~= nil
                self:_log("DEBUG", string.format(
                    "Install probe dir=%s chmod_ret=%s perms=%s exec_bit=%s",
                    target_dir, tostring(chmod_ret), tostring(permissions), tostring(has_exec_bit)))
                if has_exec_bit then
                    self:_log("INFO", "Selected executable install path: " .. destination)
                    return destination
                end
            end
        end
    end
    return nil, _("No executable install directory found for wireproxy.")
end

--- Open a PathChooser to let the user select the wireproxy binary.
--- The chosen file is copied to the first exec-capable data directory:
--- cache first, then known package /data/data/.../files fallbacks.
function WireGuard:_pickBinary()
    local start_path = _getPickerStartPath(self.wireproxy_binary)
    self:_log("DEBUG", "Opening binary picker at: " .. tostring(start_path))
    if self:_getBundledWireproxyPath() then
        _info(_("Bundled wireproxy is available on Android.\nSelecting a binary sets only a fallback path."), false, 4)
    end

    _showUnfilteredPathChooser{
        title          = _("Select wireproxy binary"),
        select_directory = false,
        select_file    = true,
        show_files     = true,
        show_unsupported = true,
        file_filter    = function() return true end,
        path           = start_path,
        onConfirm      = function(chosen_path)
            if not chosen_path or chosen_path == "" then return end
            local installed_path, err = self:_installBinaryToExecutableDir(chosen_path)
            if not installed_path then
                self:_log("ERROR", "wireproxy install failed: " .. tostring(err))
                _info(_("Failed to install executable wireproxy binary.\n\n") .. (err or _("Unknown error")), true)
                return
            end

            -- Remember the source path so the picker re-opens in the same dir.
            self.wireproxy_binary = chosen_path
            self.installed_binary = installed_path
            self:_saveSettings()
            self:_log("INFO", "wireproxy source binary set to: " .. chosen_path)
            self:_log("INFO", "wireproxy installed binary set to: " .. installed_path)
            _info(string.format(
                _("wireproxy binary installed to:\n%s"),
                installed_path), false, 4)
        end,
    }
end

--- Open a PathChooser to let the user select the WireGuard .conf file.
function WireGuard:_pickConfig()
    local start_path = _getPickerStartPath(self.wireguard_config)
    self:_log("DEBUG", "Opening config picker at: " .. tostring(start_path))

    _showUnfilteredPathChooser{
        title          = _("Select WireGuard config file"),
        select_directory = false,
        select_file    = true,
        show_files     = true,
        show_unsupported = true,
        file_filter    = function() return true end,
        path           = start_path,
        onConfirm      = function(chosen_path)
            if chosen_path and chosen_path ~= "" then
                self.wireguard_config = chosen_path
                self:_saveSettings()
                self:_log("INFO", "WireGuard config set to: " .. chosen_path)
                _info(string.format(_("WireGuard config set to:\n%s"), chosen_path), false, 3)
            end
        end,
    }
end

--- Show an InputDialog so the user can change the HTTP proxy port.
function WireGuard:_editPort()
    local dialog
    dialog = InputDialog:new{
        title       = _("HTTP Proxy Port"),
        description = _("Port wireproxy will listen on (default: 1080)."),
        input       = tostring(self.proxy_port),
        input_type  = "number",
        buttons     = {
            {
                {
                    text     = _("Cancel"),
                    callback = function() UIManager:close(dialog) end,
                },
                {
                    text             = _("Save"),
                    is_enter_default = true,
                    callback         = function()
                        local v = tonumber(dialog:getInputText())
                        if v and v >= 1 and v <= 65535 then
                            self.proxy_port = v
                            self:_saveSettings()
                            self:_log("INFO", "HTTP proxy port changed to " .. v)
                            _info(string.format(_("HTTP proxy port set to %d."), v), false, 2)
                        else
                            _info(_("Invalid port — must be 1–65535."), true, 3)
                        end
                        UIManager:close(dialog)
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

-- ---------------------------------------------------------------------------
-- Troubleshooting helpers
-- ---------------------------------------------------------------------------

function WireGuard:_showStatus()
    local pid     = self:_readPID()
    local running = self:_isRunning()
    local active_binary = self:_resolveWireproxyBinary()
    local bundled_binary = self:_getBundledWireproxyPath()
    UIManager:show(InfoMessage:new{
        text = table.concat({
            string.format(_("Status:       %s"), running and _("Running ✓") or _("Stopped")),
            string.format(_("PID:          %s"), pid and tostring(pid) or _("N/A")),
            string.format(_("HTTP proxy port: %d"), self.proxy_port),
            string.format(_("Autostart:    %s"), self.autostart and _("Yes") or _("No")),
            "",
            string.format(_("Installed binary:\n  %s"), util.pathExists(self.installed_binary) and self.installed_binary or _("(not installed)")),
            string.format(_("Bundled binary:\n  %s"), bundled_binary or _("(not found)")),
            string.format(_("Active binary:\n  %s"), active_binary or _("(unknown)")),
            string.format(_("Source binary:\n  %s"), self.wireproxy_binary  ~= "" and self.wireproxy_binary  or _("(not set)")),
            string.format(_("Config:\n  %s"), self.wireguard_config  ~= "" and self.wireguard_config  or _("(not set)")),
            string.format(_("Runtime conf:\n  %s"), RUNTIME_CONF_FILE),
        }, "\n"),
    })
end

function WireGuard:_showWireproxyLog()
    local content = _readLogTail(WIREPROXY_LOG_FILE)
    UIManager:show(InfoMessage:new{
        text = (content and content ~= "")
            and content
            or _("wireproxy log is empty or not yet created.\nStart the VPN first."),
    })
end

function WireGuard:_showPluginLog()
    local content = _readLogTail(PLUGIN_LOG_FILE)
    UIManager:show(InfoMessage:new{
        text = (content and content ~= "")
            and content
            or _("Plugin log is empty."),
    })
end

function WireGuard:_showActiveConfig()
    local f = io.open(RUNTIME_CONF_FILE, "r")
    if not f then
        _info(_("No runtime config found.\nStart the VPN first."), true)
        return
    end
    local cfg = f:read("*a")
    f:close()
    -- Redact PrivateKey for display
    local redacted = cfg:gsub("(PrivateKey%s*=%s*)[^\n]+", "%1<redacted>")
    UIManager:show(InfoMessage:new{ text = redacted })
end

function WireGuard:_testHTTPProxy()
    if not self:_isRunning() then
        _info(_("WireGuard VPN is not running."), true)
        return
    end
    -- Use nc (netcat) — available on Android 4.4+ via busybox
    local cmd = string.format(
        "nc -z -w 2 127.0.0.1 %d 2>/dev/null; echo $?",
        self.proxy_port)
    local f = io.popen(cmd)
    local out = f and f:read("*a") or ""
    if f then f:close() end

    local exit = out:match("(%d+)%s*$")
    self:_log("DEBUG", string.format("HTTP proxy port-check exit=%s", tostring(exit)))

    if exit == "0" then
        _info(string.format(_("HTTP proxy is reachable on port %d. ✓"), self.proxy_port), false, 3)
    else
        _info(string.format(
            _("HTTP proxy is NOT reachable on port %d.\n\nwireproxy may still be starting up or the config has an error — check the wireproxy log."),
            self.proxy_port), true)
    end
end

function WireGuard:_forceRestart()
    UIManager:show(ConfirmBox:new{
        text       = _("Force-restart the WireGuard VPN?"),
        ok_text    = _("Restart"),
        cancel_text = _("Cancel"),
        ok_callback = function()
            self:_log("INFO", "Force restart requested by user")
            self:_stopWireproxy()
            ffiutil.sleep(1)
            local ok, err = self:_startWireproxy()
            if ok then
                _info(_("WireGuard VPN restarted. ✓"), false, 2)
            else
                _info(_("Restart failed:\n\n") .. (err or _("Unknown error")), true)
            end
        end,
    })
end

function WireGuard:_clearLogs()
    UIManager:show(ConfirmBox:new{
        text        = _("Delete all WireGuard log files?"),
        ok_text     = _("Delete"),
        cancel_text = _("Cancel"),
        ok_callback = function()
            os.remove(PLUGIN_LOG_FILE)
            os.remove(WIREPROXY_LOG_FILE)
            self:_log("INFO", "Logs cleared by user")
            _info(_("Logs cleared."), false, 2)
        end,
    })
end

-- ---------------------------------------------------------------------------
-- Menu
-- ---------------------------------------------------------------------------

function WireGuard:_troubleshootingMenu()
    return {
        {
            text             = _("Show VPN Status"),
            keep_menu_open   = true,
            callback         = function() self:_showStatus() end,
        },
        {
            text_func        = function()
                return string.format(_("Test HTTP Proxy Port %d"), self.proxy_port)
            end,
            keep_menu_open   = true,
            callback         = function() self:_testHTTPProxy() end,
        },
        {
            text             = _("Show wireproxy Log"),
            keep_menu_open   = true,
            callback         = function() self:_showWireproxyLog() end,
        },
        {
            text             = _("Show Plugin Log"),
            keep_menu_open   = true,
            callback         = function() self:_showPluginLog() end,
        },
        {
            text             = _("Show Active Config"),
            keep_menu_open   = true,
            callback         = function() self:_showActiveConfig() end,
        },
        {
            text             = _("Force Restart"),
            keep_menu_open   = true,
            callback         = function() self:_forceRestart() end,
        },
        {
            text             = _("Clear Logs"),
            keep_menu_open   = true,
            callback         = function() self:_clearLogs() end,
        },
    }
end

function WireGuard:addToMainMenu(menu_items)
    menu_items.wireguard = {
        text         = _("WireGuard VPN"),
        sorting_hint = "more_tools",
        -- Use sub_item_table_func so the enable/disable text refreshes each
        -- time the user opens the submenu.
        sub_item_table_func = function()
            return {
                -- ── Enable / Disable ─────────────────────────────────────
                {
                    text_func = function()
                        return self:_isRunning()
                            and _("Disable WireGuard VPN")
                            or  _("Enable WireGuard VPN")
                    end,
                    checked_func = function()
                        return self:_isRunning()
                    end,
                    callback = function()
                        self:_toggle()
                    end,
                },
                -- ── Configuration ────────────────────────────────────────
                {
                    text_func        = function()
                        return self:_getBundledWireproxyPath()
                            and _("Select wireproxy binary fallback…")
                            or _("Select wireproxy binary…")
                    end,
                    keep_menu_open   = true,
                    callback         = function() self:_pickBinary() end,
                },
                {
                    text             = _("Select WireGuard config file…"),
                    keep_menu_open   = true,
                    callback         = function() self:_pickConfig() end,
                },
                {
                    text_func        = function()
                        return string.format(_("HTTP Proxy Port: %d"), self.proxy_port)
                    end,
                    keep_menu_open   = true,
                    callback         = function() self:_editPort() end,
                },
                -- ── Troubleshooting ──────────────────────────────────────
                {
                    text           = _("Troubleshooting"),
                    sub_item_table = self:_troubleshootingMenu(),
                },
                -- ── About ────────────────────────────────────────────────
                {
                    text           = _("About WireGuard Plugin"),
                    separator      = true,
                    keep_menu_open = true,
                    callback       = function()
                        UIManager:show(InfoMessage:new{
                            text = _(
                                "WireGuard VPN Plugin\n\n" ..
                                "Tunnels KOReader's network traffic through a " ..
                                "WireGuard VPN using wireproxy (github.com/whyvl/wireproxy) " ..
                                "as a local HTTP CONNECT proxy.\n\n" ..
                                "Setup:\n" ..
                                "  1. Obtain a wireproxy binary for your device\n" ..
                                "     architecture (ARM, ARM64, x86, x86_64).\n" ..
                                "  2. Copy your WireGuard .conf file to the device.\n" ..
                                "  3. Use this menu to point the plugin to both files.\n" ..
                                "  4. Toggle 'Enable WireGuard VPN'.\n\n" ..
                                "The plugin appends an [http] section to a\n" ..
                                "temporary copy of your config and launches\n" ..
                                "wireproxy in the background.  KOReader's HTTP\n" ..
                                "proxy is configured via NetworkMgr so that\n" ..
                                "LuaSocket routes through the tunnel.\n\n" ..
                                "Supports Android 4.4 and later."
                            ),
                        })
                    end,
                },
            }
        end,
    }
end

-- ---------------------------------------------------------------------------
-- Lifecycle events
-- ---------------------------------------------------------------------------

--- Called by KOReader when it is about to exit.
function WireGuard:onExit()
    if self:_isRunning() then
        self:_log("INFO", "KOReader exiting — stopping wireproxy")
        self:_stopWireproxy()
    end
    self:_saveSettings()
end

--- Called when the plugin is closed / unloaded (e.g., plugin manager).
function WireGuard:onClose()
    self:_log("DEBUG", "Plugin closed (wireproxy not stopped automatically)")
end

return WireGuard
