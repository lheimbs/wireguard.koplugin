--[[
WireGuard VPN Plugin for KOReader
Routes all network traffic through a WireGuard VPN tunnel using wireproxy
as a local SOCKS5 proxy. Supports Android 4.4+.

Usage:
  1. Select your wireproxy binary via the menu.
  2. Select your WireGuard .conf file via the menu.
  3. Toggle "Enable WireGuard VPN" to start the tunnel.

The plugin will append a [Socks5] section to the WireGuard config (writing
a modified copy to a temp path) and launch wireproxy as a background process.
It then sets http_proxy/https_proxy/ALL_PROXY environment variables so that
KOReader's network stack routes through the SOCKS5 tunnel.
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
local util = require("util")
local Device = require("device")
local _ = require("gettext")

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
local DEFAULT_SOCKS5_PORT = 1080

-- DataStorage does not expose getCacheDir(); cache lives under data dir.
local DATA_DIR           = DataStorage:getDataDir()
local CACHE_DIR          = DATA_DIR .. "/cache"
local PID_FILE           = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.pid"
local RUNTIME_CONF_FILE  = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.conf"
local WIREPROXY_LOG_FILE = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_wireproxy.log"
local PLUGIN_LOG_FILE    = CACHE_DIR .. "/" .. PLUGIN_NAME .. "_plugin.log"
-- Installed binary lives in the exec-capable data directory.  /sdcard is
-- mounted noexec on Android so we always copy the binary here first.
local INSTALLED_BINARY   = DATA_DIR .. "/wireproxy"
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
    self.wireguard_config = self.settings:readSetting("wireguard_config") or ""
    self.socks5_port      = self.settings:readSetting("socks5_port") or DEFAULT_SOCKS5_PORT
    self.autostart        = self.settings:isTrue("autostart")

    self:_log("INFO", "Plugin initialized")
    self:_log("DEBUG", string.format(
        "Settings — binary=%q  config=%q  port=%d  autostart=%s",
        self.wireproxy_binary, self.wireguard_config,
        self.socks5_port, tostring(self.autostart)))

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
    self.settings:saveSetting("wireguard_config",  self.wireguard_config)
    self.settings:saveSetting("socks5_port",       self.socks5_port)
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
    local s = f:read("*l")
    f:close()
    return s and tonumber(s) or nil
end

--- Return true when the wireproxy process is alive.
function WireGuard:_isRunning()
    local pid = self:_readPID()
    if not pid then return false end
    return util.pathExists("/proc/" .. tostring(pid))
end

--- Send a signal to a process.  Returns true on success.
local function _sendSignal(sig, pid)
    return os.execute(string.format("kill -%s %d 2>/dev/null", sig, pid)) == 0
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

    -- If a [Socks5] section is already present, update its BindAddress.
    -- Otherwise append a new section.
    if cfg:match("%[Socks5%]") then
        cfg = cfg:gsub(
            "(BindAddress%s*=%s*)[^\n]*",
            string.format("%%1127.0.0.1:%d", self.socks5_port),
            1)
        self:_log("DEBUG", "Updated existing [Socks5] BindAddress")
    else
        cfg = cfg .. string.format("\n[Socks5]\nBindAddress = 127.0.0.1:%d\n",
                                   self.socks5_port)
        self:_log("DEBUG", "Appended [Socks5] section with port " .. self.socks5_port)
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

--- Validate prerequisites.  Returns true or false + message.
function WireGuard:_checkPrereqs()
    if self.wireproxy_binary == "" then
        return false, _("wireproxy binary is not configured.\nPlease select it from the WireGuard menu.")
    end
    if self.wireguard_config == "" then
        return false, _("WireGuard config file is not configured.\nPlease select it from the WireGuard menu.")
    end
    -- Check the installed copy (in the exec-capable data directory), not the
    -- original source which may be on a noexec mount such as /sdcard.
    if not util.pathExists(INSTALLED_BINARY) then
        return false, _("wireproxy binary not installed.\nPlease use \"Select wireproxy binary\226\128\166\" again.")
    end
    if not util.pathExists(self.wireguard_config) then
        return false, _("WireGuard config not found:\n") .. self.wireguard_config
    end
    return true
end

--- Set or clear proxy-related environment variables so KOReader's network
--- stack routes through the local SOCKS5 tunnel.
function WireGuard:_applyProxyEnv(enable)
    local proxy_url = string.format("socks5h://127.0.0.1:%d", self.socks5_port)
    local vars = {
        "ALL_PROXY", "all_proxy",
        "http_proxy", "HTTP_PROXY",
        "https_proxy", "HTTPS_PROXY",
    }
    if enable then
        self:_log("INFO", "Setting proxy env vars → " .. proxy_url)
        for _, name in ipairs(vars) do
            pcall(ffi.C.setenv, name, proxy_url, 1)
        end
        -- Also store in KOReader global settings for any plugin that reads it.
        G_reader_settings:saveSetting("http_proxy",  proxy_url)
        G_reader_settings:saveSetting("https_proxy", proxy_url)
    else
        self:_log("INFO", "Clearing proxy env vars")
        for _, name in ipairs(vars) do
            pcall(ffi.C.unsetenv, name)
        end
        G_reader_settings:delSetting("http_proxy")
        G_reader_settings:delSetting("https_proxy")
    end
end

--- Start wireproxy.  Returns true on success, or false + error string.
function WireGuard:_startWireproxy()
    local ok, err = self:_checkPrereqs()
    if not ok then return false, err end

    if self:_isRunning() then
        self:_log("WARN", "wireproxy is already running — skipping start")
        return true
    end

    -- Ensure the installed binary is executable (belt-and-suspenders guard).
    os.execute(string.format("chmod +x %q 2>/dev/null", INSTALLED_BINARY))

    -- Show file permissions
    os.execute(string.format("ls -ahl %q >%q", INSTALLED_BINARY, WIREPROXY_LOG_FILE))

    -- Build the runtime config.
    ok, err = self:_buildConfig()
    if not ok then return false, err end

    -- Launch wireproxy in the background.
    -- The shell writes the PID to PID_FILE and redirects all output to the log.
    local cmd = string.format(
        "%q -c %q >>%q 2>&1 & echo $! >>%q",
        INSTALLED_BINARY,
        RUNTIME_CONF_FILE,
        WIREPROXY_LOG_FILE,
        PID_FILE)
    self:_log("DEBUG", "Launching wireproxy: " .. cmd)

    local ret = os.execute(cmd)
    if ret ~= 0 then
        return false, _("os.execute failed while starting wireproxy (exit code ") .. tostring(ret) .. ")"
    end

    -- Give the process a moment to initialise.
    ffiutil.sleep(1)

    if not self:_isRunning() then
        local log_tail = _readLogTail(WIREPROXY_LOG_FILE) or ""
        self:_log("ERROR", "wireproxy failed to start. Log tail:\n" .. log_tail)
        return false,
            _("wireproxy process died immediately after launch.\n\n") ..
            _("Last log output:\n") .. log_tail
    end

    local pid = self:_readPID()
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
        -- Try a name-based kill as a fallback (best-effort).
        os.execute("pkill -f wireproxy 2>/dev/null; true")
        self:_log("INFO", "No PID file found; attempted name-based stop")
        return true
    end

    if not util.pathExists("/proc/" .. tostring(pid)) then
        os.remove(PID_FILE)
        self:_log("INFO", "wireproxy was already stopped")
        return true
    end

    -- Graceful SIGTERM
    _sendSignal("TERM", pid)
    for _ = 1, STOP_WAIT_LOOPS do
        if not util.pathExists("/proc/" .. tostring(pid)) then break end
        ffiutil.sleep(0.1)
    end

    -- Force SIGKILL if still alive
    if util.pathExists("/proc/" .. tostring(pid)) then
        self:_log("WARN", "wireproxy did not stop gracefully — sending SIGKILL")
        _sendSignal("KILL", pid)
        for _ = 1, KILL_WAIT_LOOPS do
            if not util.pathExists("/proc/" .. tostring(pid)) then break end
            ffiutil.sleep(0.1)
        end
    end

    local stopped = not util.pathExists("/proc/" .. tostring(pid))
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

--- Open a PathChooser to let the user select the wireproxy binary.
--- The chosen file is copied to INSTALLED_BINARY (an exec-capable location
--- inside KOReader's data directory) and made executable.  /sdcard and other
--- external storage locations are mounted noexec on Android, so the binary
--- must live in the data directory to be launchable.
function WireGuard:_pickBinary()
    local start_path = _getPickerStartPath(self.wireproxy_binary)
    self:_log("DEBUG", "Opening binary picker at: " .. tostring(start_path))

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

            -- Copy to the exec-capable data directory.
            local cp_ret = os.execute(
                string.format("cp %q %q 2>/dev/null", chosen_path, INSTALLED_BINARY))
            if cp_ret ~= 0 then
                self:_log("ERROR", "Failed to copy binary: " .. chosen_path)
                _info(string.format(
                    _("Failed to copy binary.\n\nSource:\n%s\n\nDestination:\n%s"),
                    chosen_path, INSTALLED_BINARY), true)
                return
            end

            -- Make the installed copy executable.
            local chmod_ret = os.execute(
                string.format("chmod +x %q 2>/dev/null", INSTALLED_BINARY))
            if chmod_ret ~= 0 then
                self:_log("ERROR", "chmod +x failed on: " .. INSTALLED_BINARY)
                _info(string.format(
                    _("Binary copied but chmod +x failed.\nDestination:\n%s"),
                    INSTALLED_BINARY), true)
                return
            end

            -- Remember the source path so the picker re-opens in the same dir.
            self.wireproxy_binary = chosen_path
            self:_saveSettings()
            self:_log("INFO", "wireproxy binary installed to: " .. INSTALLED_BINARY)
            _info(string.format(
                _("wireproxy binary installed to:\n%s\n\nRepeat this step to update the binary."),
                INSTALLED_BINARY), false, 4)
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

--- Show an InputDialog so the user can change the SOCKS5 proxy port.
function WireGuard:_editPort()
    local dialog
    dialog = InputDialog:new{
        title       = _("SOCKS5 Proxy Port"),
        description = _("Port wireproxy will listen on (default: 1080)."),
        input       = tostring(self.socks5_port),
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
                            self.socks5_port = v
                            self:_saveSettings()
                            self:_log("INFO", "SOCKS5 port changed to " .. v)
                            _info(string.format(_("SOCKS5 port set to %d."), v), false, 2)
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
    UIManager:show(InfoMessage:new{
        text = table.concat({
            string.format(_("Status:       %s"), running and _("Running ✓") or _("Stopped")),
            string.format(_("PID:          %s"), pid and tostring(pid) or _("N/A")),
            string.format(_("SOCKS5 port:  %d"), self.socks5_port),
            string.format(_("Autostart:    %s"), self.autostart and _("Yes") or _("No")),
            "",
            string.format(_("Installed binary:\n  %s"), util.pathExists(INSTALLED_BINARY) and INSTALLED_BINARY or _("(not installed)")),
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

function WireGuard:_testSOCKS5()
    if not self:_isRunning() then
        _info(_("WireGuard VPN is not running."), true)
        return
    end
    -- Use nc (netcat) — available on Android 4.4+ via busybox
    local cmd = string.format(
        "nc -z -w 2 127.0.0.1 %d 2>/dev/null; echo $?",
        self.socks5_port)
    local f = io.popen(cmd)
    local out = f and f:read("*a") or ""
    if f then f:close() end

    local exit = out:match("(%d+)%s*$")
    self:_log("DEBUG", string.format("SOCKS5 port-check exit=%s", tostring(exit)))

    if exit == "0" then
        _info(string.format(_("SOCKS5 proxy is reachable on port %d. ✓"), self.socks5_port), false, 3)
    else
        _info(string.format(
            _("SOCKS5 proxy is NOT reachable on port %d.\n\nwireproxy may still be starting up or the config has an error — check the wireproxy log."),
            self.socks5_port), true)
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
                return string.format(_("Test SOCKS5 Port %d"), self.socks5_port)
            end,
            keep_menu_open   = true,
            callback         = function() self:_testSOCKS5() end,
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
                    text             = _("Select wireproxy binary…"),
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
                        return string.format(_("SOCKS5 Port: %d"), self.socks5_port)
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
                                "as a local SOCKS5 proxy.\n\n" ..
                                "Setup:\n" ..
                                "  1. Obtain a wireproxy binary for your device\n" ..
                                "     architecture (ARM, ARM64, x86, x86_64).\n" ..
                                "  2. Copy your WireGuard .conf file to the device.\n" ..
                                "  3. Use this menu to point the plugin to both files.\n" ..
                                "  4. Toggle 'Enable WireGuard VPN'.\n\n" ..
                                "The plugin appends a [Socks5] section to a\n" ..
                                "temporary copy of your config and launches\n" ..
                                "wireproxy in the background.  http_proxy,\n" ..
                                "https_proxy and ALL_PROXY environment variables\n" ..
                                "are set so KOReader routes through the tunnel.\n\n" ..
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
