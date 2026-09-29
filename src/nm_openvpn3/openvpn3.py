# SPDX-License-Identifier: GPL-2.0-or-later
"""Thin client for the OpenVPN 3 Linux D-Bus services.

Talks to the services directly over the system bus instead of using the
`openvpn3` Python module shipped with openvpn3-linux.
"""

import json
import time

from gi.repository import Gio, GLib

CONFIG_SVC = "net.openvpn.v3.configuration"
CONFIG_PATH = "/net/openvpn/v3/configuration"
SESSIONS_SVC = "net.openvpn.v3.sessions"
SESSIONS_PATH = "/net/openvpn/v3/sessions"
LOG_SVC = "net.openvpn.v3.log"
BACKENDS_IF = "net.openvpn.v3.backends"
NETCFG_SVC = "net.openvpn.v3.netcfg"
NETCFG_PATH = "/net/openvpn/v3/netcfg"
PROPS_IF = "org.freedesktop.DBus.Properties"

CALL_TIMEOUT_MS = 30_000
ACTIVATION_WAIT_S = 10

# StatusMajor
MAJOR_CFG_ERROR = 1
MAJOR_CONNECTION = 2
MAJOR_SESSION = 3
MAJOR_PKCS11 = 4
MAJOR_PROCESS = 5

# StatusMinor
CFG_ERROR = 1
CFG_OK = 2
CFG_INLINE_MISSING = 3
CFG_REQUIRE_USER = 4
CONN_INIT = 5
CONN_CONNECTING = 6
CONN_CONNECTED = 7
CONN_DISCONNECTING = 8
CONN_DISCONNECTED = 9
CONN_FAILED = 10
CONN_AUTH_FAILED = 11
CONN_RECONNECTING = 12
CONN_PAUSING = 13
CONN_PAUSED = 14
CONN_RESUMING = 15
CONN_DONE = 16
SESS_NEW = 17
SESS_BACKEND_COMPLETED = 18
SESS_REMOVED = 19
SESS_AUTH_USERPASS = 20
SESS_AUTH_CHALLENGE = 21
SESS_AUTH_URL = 22
PROC_STARTED = 27
PROC_STOPPED = 28
PROC_KILLED = 29

# ClientAttentionType
ATTN_CREDENTIALS = 1
ATTN_PKCS11 = 2
ATTN_ACCESS_PERM = 3

# ClientAttentionGroup
GRP_USER_PASSWORD = 1
GRP_HTTP_PROXY_CREDS = 2
GRP_PK_PASSPHRASE = 3
GRP_CHALLENGE_STATIC = 4
GRP_CHALLENGE_DYNAMIC = 5
GRP_CHALLENGE_AUTH_PENDING = 6
GRP_PKCS11_SIGN = 7
GRP_PKCS11_DECRYPT = 8
GRP_OPEN_URL = 9


class Client:
    def __init__(self, bus=None):
        self.bus = bus or Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    def call(self, service, path, iface, method, args=None, reply=None):
        # A service started by D-Bus activation owns its name a moment before
        # it exports its objects; retry that window instead of failing.
        deadline = time.monotonic() + ACTIVATION_WAIT_S
        while True:
            try:
                res = self.bus.call_sync(service, path, iface, method, args, reply,
                                         Gio.DBusCallFlags.NONE, CALL_TIMEOUT_MS, None)
                return res.unpack() if res is not None else None
            except GLib.Error as e:
                starting = Gio.DBusError.get_remote_error(e) in (
                    "org.freedesktop.DBus.Error.UnknownMethod",
                    "org.freedesktop.DBus.Error.UnknownObject") and "does not exist" in e.message
                if not starting or time.monotonic() > deadline:
                    raise
                time.sleep(0.2)

    def get(self, service, path, iface, prop):
        (value,) = self.call(service, path, PROPS_IF, "Get", GLib.Variant("(ss)", (iface, prop)),
                             GLib.VariantType("(v)"))
        return value

    def import_config(self, name, text):
        """Import a single-use, non-persistent config; returns its object path."""
        (path,) = self.call(CONFIG_SVC, CONFIG_PATH, CONFIG_SVC, "Import",
                            GLib.Variant("(ssbb)", (name, text, True, False)),
                            GLib.VariantType("(o)"))
        return path

    def remove_config(self, path):
        self.call(CONFIG_SVC, path, CONFIG_SVC, "Remove")

    def new_tunnel(self, config_path):
        (path,) = self.call(SESSIONS_SVC, SESSIONS_PATH, SESSIONS_SVC, "NewTunnel",
                            GLib.Variant("(o)", (config_path,)), GLib.VariantType("(o)"))
        return Session(self, path)

    def netcfg_dns(self, device):
        """DNS servers and search domains netcfg holds for the device."""
        (paths,) = self.call(NETCFG_SVC, NETCFG_PATH, NETCFG_SVC, "FetchInterfaceList",
                             None, GLib.VariantType("(ao)"))
        for p in paths:
            if self.get(NETCFG_SVC, p, NETCFG_SVC, "device_name") == device:
                return (list(self.get(NETCFG_SVC, p, NETCFG_SVC, "dns_name_servers")),
                        list(self.get(NETCFG_SVC, p, NETCFG_SVC, "dns_search_domains")))
        return [], []


NETCFG_CONFIG = "/var/lib/openvpn3/netcfg.json"


def netcfg_manages_dns(path=NETCFG_CONFIG):
    """Whether openvpn3-netcfg is configured to apply DNS settings at all."""
    try:
        with open(path) as f:
            # The file is JSON with // comment lines.
            text = "".join(line for line in f if not line.lstrip().startswith("//"))
    except FileNotFoundError:
        return False
    cfg = json.loads(text) if text.strip() else {}
    return bool(cfg.get("systemd_resolved") or cfg.get("resolv_conf"))


class Session:
    IFACE = SESSIONS_SVC

    def __init__(self, client, path):
        self.client = client
        self.path = path
        self._subs = []

    def _call(self, method, args=None, reply=None):
        return self.client.call(SESSIONS_SVC, self.path, self.IFACE, method, args, reply)

    def prop(self, name):
        return self.client.get(SESSIONS_SVC, self.path, self.IFACE, name)

    def ready(self):
        self._call("Ready")

    def connect(self):
        self._call("Connect")

    def disconnect(self):
        self._call("Disconnect")

    def pending_inputs(self):
        """List of (type, group, id, name, description, hidden) waiting for input."""
        (groups,) = self._call("UserInputQueueGetTypeGroup", None, GLib.VariantType("(a(uu))"))
        slots = []
        for t, g in groups:
            (ids,) = self._call("UserInputQueueCheck", GLib.Variant("(uu)", (t, g)),
                                GLib.VariantType("(au)"))
            for i in ids:
                slots.append(self._call("UserInputQueueFetch", GLib.Variant("(uuu)", (t, g, i)),
                                        GLib.VariantType("(uuussb)")))
        return slots

    def provide(self, t, g, i, value):
        self._call("UserInputProvide", GLib.Variant("(uuus)", (t, g, i, value)))

    def log_forward(self, enable):
        """Makes this D-Bus client a recipient of the session's signals.

        The session manager sends StatusChange/Log only to registered
        front-ends, not as a broadcast.
        """
        self._call("LogForward", GLib.Variant("(b)", (enable,)))

    def access_grant(self, uid):
        self._call("AccessGrant", GLib.Variant("(u)", (uid,)))
