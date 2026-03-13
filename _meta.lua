local _ = require("gettext")
return {
    name = "wireguard",
    fullname = _("WireGuard VPN"),
    description = _([[Routes all network traffic through a WireGuard VPN tunnel using wireproxy as a local SOCKS5 proxy. Requires a wireproxy binary and a WireGuard configuration file.]]),
}
