--[[
WireProxy VPN Plugin for KOReader
Enables WireGuard-based tunneling via wireproxy on Android devices (including
Android 4.4) that have no WireGuard kernel support.

Setup:
  1. Download a wireproxy ARM binary and save it on the device (e.g.
     /sdcard/Download/wireproxy).
  2. Create wg0.conf in this plugin's directory with your WireGuard credentials
     and a [Socks5] or [HTTPServer] section pointing at 127.0.0.1:<port>.
  3. Use Menu → WireProxy VPN → Select wireproxy binary… to pick the binary.
     It will be copied to KOReader's data directory and made executable.
  4. Use Menu → WireProxy VPN → Start to launch the tunnel.
  5. In KOReader's Network settings, set the HTTP proxy to match the bind
     address configured in wg0.conf (e.g. 127.0.0.1:8080).
--]]

local WidgetContainer = require("ui/widget/container/widgetcontainer")
local UIManager       = require("ui/uimanager")
local InfoMessage     = require("ui/widget/infomessage")
local PathChooser     = require("ui/widget/pathchooser")
local FileChooser     = require("ui/widget/filechooser")
local DataStorage     = require("datastorage")
local util            = require("util")
local _               = require("gettext")

-- ---------------------------------------------------------------------------
-- Path constants
-- ---------------------------------------------------------------------------

-- Directory that holds the plugin's own files (main.lua, wg0.conf, …).
-- Derived from this source file's location so it works regardless of where
-- the user has placed their KOReader plugins directory.
local PLUGIN_DIR = (debug.getinfo(1, "S").source or ""):match("@(.+)/[^/]+$") or "."

-- Paths inside KOReader's data directory (exec-capable on Android).
local DATA_DIR    = DataStorage:getDataDir()
local BINARY_PATH = DATA_DIR .. "/wireproxy"
local LOG_PATH    = DATA_DIR .. "/wireproxy.log"

-- The user-edited WireGuard + wireproxy config lives in the plugin directory.
local CONF_PATH = PLUGIN_DIR .. "/wg0.conf"

-- ---------------------------------------------------------------------------
-- Plugin class
-- ---------------------------------------------------------------------------

local WireProxy = WidgetContainer:extend{
    name        = "wireproxy",
    is_doc_only = false,
}

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------

function WireProxy:init()
    if self.ui and self.ui.menu then
        self.ui.menu:registerToMainMenu(self)
    end
end

-- ---------------------------------------------------------------------------
-- Process helpers
-- ---------------------------------------------------------------------------

--- Return true when a wireproxy process is currently alive.
function WireProxy:_isRunning()
    -- pgrep is available on Android via BusyBox/toybox; fall back to the
    -- /proc scan when it is absent.
    local f = io.popen("pgrep -f wireproxy 2>/dev/null")
    if f then
        local out = f:read("*a")
        f:close()
        if out and out:match("%d") then
            return true
        end
    end
    -- Fallback: scan /proc for a matching cmdline entry.
    local proc = io.popen("grep -rl wireproxy /proc/[0-9]*/cmdline 2>/dev/null | head -1")
    if proc then
        local line = proc:read("*a")
        proc:close()
        return line and line ~= ""
    end
    return false
end

--- Kill all wireproxy processes by name.  Best-effort; does not fail.
local function _killWireproxy()
    os.execute("pkill -f wireproxy 2>/dev/null; true")
    -- Also try the POSIX kill-by-name via killall (present on many Androids).
    os.execute("killall wireproxy 2>/dev/null; true")
end

-- ---------------------------------------------------------------------------
-- Binary selection
-- ---------------------------------------------------------------------------

--- Open KOReader's file picker starting at /sdcard (or the data dir as
--- fallback), then copy the chosen file to BINARY_PATH and chmod +x it.
function WireProxy:_selectBinary()
    local start_path = "/sdcard"
    if not util.pathExists(start_path) then
        start_path = DATA_DIR
    end

    -- Temporarily clear the file-type filter so all files are shown.
    local saved_filter = FileChooser.show_filter
    local filter_restored = false
    local function restoreFilter()
        if not filter_restored then
            FileChooser.show_filter = saved_filter
            filter_restored = true
        end
    end

    FileChooser.show_filter = {}
    UIManager:show(PathChooser:new{
        title            = _("Select wireproxy binary"),
        select_directory = false,
        select_file      = true,
        show_files       = true,
        show_unsupported = true,
        file_filter      = function() return true end,
        path             = start_path,
        onConfirm        = function(chosen_path)
            restoreFilter()
            if not chosen_path or chosen_path == "" then return end
            -- Copy the binary to the exec-capable data directory.
            local cp_ret = os.execute(
                string.format("cp %q %q 2>/dev/null", chosen_path, BINARY_PATH))
            if cp_ret ~= 0 then
                UIManager:show(InfoMessage:new{
                    icon = "notice-warning",
                    text = string.format(
                        _("Failed to copy binary.\n\nSource: %s\nDestination: %s"),
                        chosen_path, BINARY_PATH),
                })
                return
            end
            -- Make the copy executable (mandatory on Android — /sdcard is noexec).
            local chmod_ret = os.execute(
                string.format("chmod +x %q 2>/dev/null", BINARY_PATH))
            if chmod_ret ~= 0 then
                UIManager:show(InfoMessage:new{
                    icon = "notice-warning",
                    text = string.format(
                        _("Binary copied but chmod +x failed.\nDestination: %s"),
                        BINARY_PATH),
                })
                return
            end
            UIManager:show(InfoMessage:new{
                text    = string.format(
                    _("wireproxy binary installed to:\n%s\n\nThis step only needs to be done once."),
                    BINARY_PATH),
                timeout = 4,
            })
        end,
        close_callback = function()
            restoreFilter()
        end,
    })
end

-- ---------------------------------------------------------------------------
-- Start / Stop / Status
-- ---------------------------------------------------------------------------

--- Launch wireproxy with wg0.conf.
function WireProxy:_start()
    -- Check that the binary has been installed.
    if not util.pathExists(BINARY_PATH) then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = _("wireproxy binary not found.\n\nPlease use \"Select wireproxy binary\226\128\166\" first."),
        })
        return
    end

    -- Check that the user has created wg0.conf in the plugin directory.
    if not util.pathExists(CONF_PATH) then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = string.format(
                _("wg0.conf not found.\n\nCreate it at:\n%s\n\nRefer to the wireproxy README for the required format."),
                CONF_PATH),
        })
        return
    end

    -- Kill any previously running instance to avoid port conflicts.
    _killWireproxy()

    -- Launch wireproxy in the background, redirecting output to the log.
    local cmd = string.format(
        "%q -c %q >>%q 2>&1 &",
        BINARY_PATH, CONF_PATH, LOG_PATH)
    os.execute(cmd)

    -- Brief pause to let wireproxy initialise before reporting status.
    os.execute("sleep 1")

    if not self:_isRunning() then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = string.format(
                _("wireproxy started but exited immediately.\n\nCheck the log for errors:\n%s"),
                LOG_PATH),
        })
        return
    end

    -- Determine the proxy address from wg0.conf (best-effort; fall back to
    -- the common default so the message is always informative).
    local proxy_addr = "127.0.0.1:8080"
    local f = io.open(CONF_PATH, "r")
    if f then
        local cfg = f:read("*a")
        f:close()
        -- Match BindAddress in either a [Socks5] or [HTTPServer] section.
        local addr = cfg:match("BindAddress%s*=%s*(%S+)")
        if addr then
            proxy_addr = addr
        end
    end

    UIManager:show(InfoMessage:new{
        text = string.format(
            _("WireProxy VPN started.\n\nSet KOReader's HTTP proxy to:\n%s\n\n(Menu → Network → Proxy Settings)"),
            proxy_addr),
        timeout = 6,
    })
end

--- Kill all wireproxy processes.
function WireProxy:_stop()
    _killWireproxy()
    UIManager:show(InfoMessage:new{
        text    = _("WireProxy VPN stopped."),
        timeout = 2,
    })
end

--- Show whether wireproxy is currently running.
function WireProxy:_showStatus()
    local running = self:_isRunning()
    UIManager:show(InfoMessage:new{
        text = running
            and _("WireProxy VPN status: Running ✓")
            or  _("WireProxy VPN status: Not running"),
        timeout = 3,
    })
end

-- ---------------------------------------------------------------------------
-- Menu
-- ---------------------------------------------------------------------------

function WireProxy:addToMainMenu(menu_items)
    menu_items.wireproxy = {
        text         = _("WireProxy VPN"),
        sorting_hint = "more_tools",
        sub_item_table = {
            {
                text           = _("Select wireproxy binary…"),
                keep_menu_open = true,
                callback       = function() self:_selectBinary() end,
            },
            {
                text           = _("Start"),
                keep_menu_open = true,
                callback       = function() self:_start() end,
            },
            {
                text           = _("Stop"),
                keep_menu_open = true,
                callback       = function() self:_stop() end,
            },
            {
                text           = _("Status"),
                keep_menu_open = true,
                callback       = function() self:_showStatus() end,
            },
        },
    }
end

return WireProxy
