# SPDX-License-Identifier: GPL-2.0-or-later
"""The GTK 4 editor page, loaded through libnm like GNOME Settings does.

Needs a display; run under a headless GDK backend (e.g. broadway).
"""

import base64
import os

import gi
import pytest

gi.require_version("NM", "1.0")
gi.require_version("Gtk", "4.0")
from gi.repository import NM  # noqa: E402

PLUGIN_DIR = os.environ.get("OPENVPN3_PLUGIN_DIR")
SERVICE = "org.freedesktop.NetworkManager.openvpn3"
PROFILE = "client\nremote vpn.example.net 1194\nauth-user-pass\n"

# GTK 4.14 reports success from init_check() without any display and then
# crashes, so require one to be configured explicitly.
HAVE_DISPLAY = any(os.environ.get(v) for v in ("DISPLAY", "WAYLAND_DISPLAY", "BROADWAY_DISPLAY"))
if HAVE_DISPLAY:
    from gi.repository import Gtk  # noqa: E402
    HAVE_DISPLAY = Gtk.init_check()

if os.environ.get("OPENVPN3_EDITOR_TEST_REQUIRED") and not (PLUGIN_DIR and HAVE_DISPLAY):
    raise RuntimeError("editor test required but no plugin build or display available")

pytestmark = pytest.mark.skipif(not (PLUGIN_DIR and HAVE_DISPLAY),
                                reason="needs the built plugin and a display")


def connection():
    con = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, "office")
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, "vpn")
    con.add_setting(s_con)
    s_vpn = NM.SettingVpn.new()
    s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, SERVICE)
    s_vpn.add_data_item("profile", base64.b64encode(PROFILE.encode()).decode())
    s_vpn.add_data_item("username", "testuser")
    s_vpn.add_data_item("password-flags", "1")
    con.add_setting(s_vpn)
    return con


def entries(widget):
    found, child = [], widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Entry):
            found.append(child)
        found.extend(entries(child))
        child = child.get_next_sibling()
    return found


def labels(widget):
    found, child = [], widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Label):
            found.append(child.get_text())
        found.extend(labels(child))
        child = child.get_next_sibling()
    return found


@pytest.fixture(scope="module")
def plugin():
    return NM.VpnEditorPlugin.load(os.path.join(PLUGIN_DIR, "libnm-vpn-plugin-openvpn3.so"), SERVICE)


def test_editor_shows_and_saves(plugin):
    con = connection()
    editor = plugin.get_editor(con)
    widget = editor.get_widget()
    assert "vpn.example.net" in labels(widget)
    user, password = entries(widget)
    assert user.get_text() == "testuser"

    changed = []
    editor.connect("changed", lambda *_: changed.append(True))
    user.set_text("otheruser")
    assert changed

    out = connection()
    assert editor.update_connection(out)
    s_vpn = out.get_setting_vpn()
    assert s_vpn.get_data_item("username") == "otheruser"
    assert base64.b64decode(s_vpn.get_data_item("profile")).decode() == PROFILE
    assert s_vpn.get_data_item("password-flags") == "1"
    assert s_vpn.get_secret("password") is None


def test_editor_requires_a_profile(plugin):
    con = connection()
    con.get_setting_vpn().remove_data_item("profile")
    editor = plugin.get_editor(con)
    with pytest.raises(gi.repository.GLib.Error):
        editor.update_connection(connection())
