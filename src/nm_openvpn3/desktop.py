# SPDX-License-Identifier: GPL-2.0-or-later
"""Reaching the user sitting at the desktop from the root service.

Web based VPN logins need a browser. The service runs as root outside any
user session, so it asks logind for the active graphical session and opens
the URL through that user's systemd manager, which carries the session's
display environment. The browser is started by xdg-desktop-portal: a
browser spawned directly (xdg-open) would live in the transient unit and be
killed with it.
"""

import subprocess

from gi.repository import Gio, GLib

LOGIND = "org.freedesktop.login1"
PROPS = "org.freedesktop.DBus.Properties"


class NoDesktopUser(Exception):
    pass


def _get(bus, path, iface, prop):
    (value,) = bus.call_sync(LOGIND, path, PROPS, "Get", GLib.Variant("(ss)", (iface, prop)),
                             GLib.VariantType("(v)"), Gio.DBusCallFlags.NONE, 5000, None).unpack()
    return value


def active_user(bus=None):
    """User name of the active session on seat0, or raise NoDesktopUser."""
    bus = bus or Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    session_id, session_path = _get(bus, "/org/freedesktop/login1/seat/seat0",
                                    "org.freedesktop.login1.Seat", "ActiveSession")
    if not session_id or session_path == "/":
        raise NoDesktopUser("no active desktop session")
    if _get(bus, session_path, "org.freedesktop.login1.Session", "Type") not in ("wayland", "x11"):
        raise NoDesktopUser("the active session is not graphical")
    return _get(bus, session_path, "org.freedesktop.login1.Session", "Name")


def portal_command(url):
    """gdbus call asking xdg-desktop-portal to open url; arguments are GVariant text."""
    return ["gdbus", "call", "--session",
            "--dest", "org.freedesktop.portal.Desktop",
            "--object-path", "/org/freedesktop/portal/desktop",
            "--method", "org.freedesktop.portal.OpenURI.OpenURI",
            "''", GLib.Variant("s", url).print_(False), "{}"]


def open_url(url, bus=None):
    """Opens url in the desktop user's default browser; returns the user name."""
    user = active_user(bus)
    subprocess.run(["systemd-run", f"--machine={user}@.host", "--user", "--collect", "--quiet",
                    "--wait", "--pipe", "--", *portal_command(url)],
                   check=True, timeout=30, stdout=subprocess.DEVNULL)
    return user
