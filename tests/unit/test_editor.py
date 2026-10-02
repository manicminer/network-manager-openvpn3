# SPDX-License-Identifier: GPL-2.0-or-later
"""The editor page, loaded through libnm like GNOME Settings (GTK 4) or
nm-connection-editor (GTK 3) do. OPENVPN3_EDITOR_GTK=3 selects GTK 3; one
process can only load one GTK.

Needs a display; run under a headless GDK backend (e.g. broadway).
"""

import base64
import os

import gi
import pytest

gi.require_version("NM", "1.0")
GTK = os.environ.get("OPENVPN3_EDITOR_GTK", "4")
gi.require_version("Gtk", f"{GTK}.0")
from gi.repository import NM  # noqa: E402

PLUGIN_DIR = os.environ.get("OPENVPN3_PLUGIN_DIR")
SERVICE = "org.freedesktop.NetworkManager.openvpn3"
PROFILE = "client\nremote vpn.example.net 1194\nauth-user-pass\n"

# GTK 4.14 reports success from init_check() without any display and then
# crashes, so require one to be configured explicitly.
HAVE_DISPLAY = any(os.environ.get(v) for v in ("DISPLAY", "WAYLAND_DISPLAY", "BROADWAY_DISPLAY"))
if HAVE_DISPLAY:
    from gi.repository import Gtk  # noqa: E402
    HAVE_DISPLAY = Gtk.init_check() if GTK == "4" else Gtk.init_check(None)[0]

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


def children(widget):
    if GTK == "3":
        return widget.get_children() if isinstance(widget, Gtk.Container) else []
    found, child = [], widget.get_first_child()
    while child is not None:
        found.append(child)
        child = child.get_next_sibling()
    return found


def walk(widget):
    for child in children(widget):
        yield child
        yield from walk(child)


def entries(widget):
    # Grid children come back in reverse attach order on GTK 3.
    found = [w for w in walk(widget) if isinstance(w, Gtk.Entry)]
    return sorted(found, key=lambda w: widget.child_get_property(w, "top-attach")) if GTK == "3" else found


def labels(widget):
    return [w.get_text() for w in walk(widget) if isinstance(w, Gtk.Label)]


@pytest.fixture(scope="module")
def plugin():
    return NM.VpnEditorPlugin.load(os.path.join(PLUGIN_DIR, "libnm-vpn-plugin-openvpn3.so"), SERVICE)


def test_editor_shows_and_saves(plugin):
    con = connection()
    editor = plugin.get_editor(con)
    widget = editor.get_widget()
    assert "vpn.example.net" in labels(widget)
    user, password, cert_pass = entries(widget)
    assert user.get_text() == "testuser"
    assert user.get_visible() and password.get_visible()
    assert not cert_pass.get_visible()  # the profile has no private key

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


def test_editor_key_passphrase_for_pkcs12(plugin):
    con = connection()
    s_vpn = con.get_setting_vpn()
    s_vpn.add_data_item("profile", base64.b64encode(
        b"client\nremote vpn.example.net\n<pkcs12>\nAAAA\n</pkcs12>\n").decode())
    s_vpn.remove_data_item("password-flags")
    editor = plugin.get_editor(con)
    user, password, cert_pass = entries(editor.get_widget())
    assert cert_pass.get_visible() and not user.get_visible()
    cert_pass.set_text("p12pass")
    out = connection()
    assert editor.update_connection(out)
    s_out = out.get_setting_vpn()
    assert s_out.get_data_item("username") is None
    assert s_out.get_data_item("cert-pass-flags") == "1"


# -- profiles kept with the connection's secrets ------------------------------


def secret_connection(flags="1", with_secret=True, profile=PROFILE):
    con = connection()
    s_vpn = con.get_setting_vpn()
    s_vpn.remove_data_item("profile")
    s_vpn.add_data_item("profile-storage", "secret")
    s_vpn.add_data_item("profile-flags", flags)
    if with_secret:
        s_vpn.add_secret("profile", base64.b64encode(profile.encode()).decode())
    return con


def test_editor_reads_a_profile_from_the_secrets(plugin):
    editor = plugin.get_editor(secret_connection())
    assert "vpn.example.net" in labels(editor.get_widget())


def test_editor_keeps_the_secret_layout_and_flags(plugin):
    for flags in ("1", "0"):
        editor = plugin.get_editor(secret_connection(flags=flags))
        out = NM.SimpleConnection.new()
        assert editor.update_connection(out)
        s_out = out.get_setting_vpn()
        assert s_out.get_data_item("profile") is None
        assert s_out.get_data_item("profile-storage") == "secret"
        assert s_out.get_data_item("profile-flags") == flags
        assert base64.b64decode(s_out.get_secret("profile")).decode() == PROFILE


def test_editor_refuses_to_save_over_a_profile_it_could_not_read(plugin):
    editor = plugin.get_editor(secret_connection(with_secret=False))
    out = NM.SimpleConnection.new()
    with pytest.raises(gi.repository.GLib.Error):
        editor.update_connection(out)
    # Nothing was written: the stored profile is still the one in the keyring.
    assert out.get_setting_vpn() is None


def test_editor_explains_an_unavailable_profile(plugin):
    editor = plugin.get_editor(secret_connection(with_secret=False))
    text = " ".join(labels(editor.get_widget()))
    assert "secret" in text.lower() or "keyring" in text.lower()


def test_editor_leaves_legacy_connections_alone(plugin):
    editor = plugin.get_editor(connection())
    out = NM.SimpleConnection.new()
    assert editor.update_connection(out)
    s_out = out.get_setting_vpn()
    assert base64.b64decode(s_out.get_data_item("profile")).decode() == PROFILE
    assert s_out.get_data_item("profile-storage") is None
    assert s_out.get_secret("profile") is None


def test_editor_never_reads_a_profile_in_an_unknown_layout(plugin):
    con = connection()  # has a legacy profile data item
    con.get_setting_vpn().add_data_item("profile-storage", "v2-whatever")
    editor = plugin.get_editor(con)
    assert "vpn.example.net" not in labels(editor.get_widget())
    with pytest.raises(gi.repository.GLib.Error):
        editor.update_connection(NM.SimpleConnection.new())


def test_editor_reads_absent_flags_as_system_storage(plugin):
    # NetworkManager reads a secret without flags as NONE; keeping the profile
    # as AgentOwned here would move an unattended connection into a wallet.
    con = secret_connection(flags="1")
    con.get_setting_vpn().remove_data_item("profile-flags")
    editor = plugin.get_editor(con)
    out = NM.SimpleConnection.new()
    assert editor.update_connection(out)
    assert out.get_setting_vpn().get_data_item("profile-flags") == "0"


def test_editor_explains_an_unknown_layout(plugin):
    con = connection()
    con.get_setting_vpn().add_data_item("profile-storage", "v2-whatever")
    editor = plugin.get_editor(con)
    assert "v2-whatever" in " ".join(labels(editor.get_widget()))


@pytest.mark.parametrize("flags", ["2", "4", "6", "garbage", "", "-1"])
def test_editor_refuses_flags_that_would_never_store_the_profile(plugin, flags):
    # The old code passed these straight to a g_return_if_fail(), which left
    # the new setting without any profile at all and still reported success,
    # so saving silently threw the connection's profile away.
    editor = plugin.get_editor(secret_connection(flags=flags))
    out = NM.SimpleConnection.new()
    with pytest.raises(gi.repository.GLib.Error):
        editor.update_connection(out)
    assert out.get_setting_vpn() is None


def test_editor_explains_flags_that_would_never_store_the_profile(plugin):
    editor = plugin.get_editor(secret_connection(flags="2"))
    assert "profile-flags" in " ".join(labels(editor.get_widget()))


def test_editor_shows_a_remote_kept_in_a_connection_block(plugin):
    con = connection()
    con.get_setting_vpn().add_data_item("profile", base64.b64encode(
        b"client\n<connection>\nremote vpn.example.net 1194 udp\n"
        b"auth-user-pass\n</connection>\n").decode())
    editor = plugin.get_editor(con)
    widget = editor.get_widget()
    assert "vpn.example.net" in labels(widget)
    user, password, _cert_pass = entries(widget)
    assert user.get_visible() and password.get_visible()
    assert editor.update_connection(NM.SimpleConnection.new())


def test_editor_still_saves_a_connection_whose_flags_are_fine(plugin):
    # The refusal above must be about the flags, not about secret mode.
    editor = plugin.get_editor(secret_connection(flags="0"))
    out = NM.SimpleConnection.new()
    assert editor.update_connection(out)
    assert out.get_setting_vpn().get_data_item("profile-flags") == "0"
