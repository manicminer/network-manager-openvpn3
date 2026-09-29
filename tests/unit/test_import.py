# SPDX-License-Identifier: GPL-2.0-or-later
"""Import/export through the built libnm plugin, the way nmcli uses it."""

import base64
import os

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

PLUGIN_DIR = os.environ.get("OPENVPN3_PLUGIN_DIR")
pytestmark = pytest.mark.skipif(not PLUGIN_DIR, reason="needs the built plugin (meson test)")

SERVICE = "org.freedesktop.NetworkManager.openvpn3"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBsyntheticTESTDATA\n-----END CERTIFICATE-----\n"


@pytest.fixture(scope="module")
def plugin():
    path = os.path.join(PLUGIN_DIR, "libnm-vpn-plugin-openvpn3.so")
    return NM.VpnEditorPlugin.load(path, SERVICE)


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def vpn(con):
    s = con.get_setting_vpn()
    return s, base64.b64decode(s.get_data_item("profile")).decode()


def test_plugin_properties(plugin):
    assert plugin.props.service == SERVICE
    caps = plugin.get_capabilities()
    assert caps & NM.VpnEditorPluginCapability.IMPORT
    assert caps & NM.VpnEditorPluginCapability.EXPORT


def test_inline_credentials_move_into_connection(plugin, tmp_path):
    path = write(tmp_path, "office.ovpn",
                 "client\nremote vpn.example.net 1194\n"
                 "<auth-user-pass>\ntestuser\ns3cret\n</auth-user-pass>\n"
                 f"<ca>\n{PEM}</ca>\n")
    con = plugin.import_(path)
    s, config = vpn(con)
    assert con.get_id() == "office"
    assert s.get_service_type() == SERVICE
    assert s.get_data_item("username") == "testuser"
    assert s.get_secret("password") == "s3cret"
    assert s.get_data_item("password-flags") in (None, "0")
    assert "s3cret" not in config and "testuser" not in config
    assert "auth-user-pass\n" in config
    assert f"<ca>\n{PEM}</ca>\n" in config


def test_credentials_block_followed_by_other_block(plugin, tmp_path):
    path = write(tmp_path, "a.ovpn",
                 "client\nremote 192.0.2.1\n<auth-user-pass>\ntestuser\npw\n</auth-user-pass>\n"
                 f"<ca>\n{PEM}</ca>\n")
    s, config = vpn(plugin.import_(path))
    assert s.get_data_item("username") == "testuser"
    assert s.get_secret("password") == "pw"
    assert "<ca>" in config


def test_referenced_files_are_inlined(plugin, tmp_path):
    (tmp_path / "keys").mkdir()
    write(tmp_path, "keys/ca.crt", PEM)
    write(tmp_path, "keys/ta.key", "-----BEGIN OpenVPN Static key V1-----\n00ff\n-----END OpenVPN Static key V1-----\n")
    write(tmp_path, "creds.txt", "testuser\npw-from-file\n")
    path = write(tmp_path, "files.ovpn",
                 "client\nremote vpn.example.net 443 tcp\nca keys/ca.crt\n"
                 "tls-auth \"keys/ta.key\" 1\nauth-user-pass creds.txt\n")
    s, config = vpn(plugin.import_(path))
    assert "ca keys/ca.crt" not in config
    assert f"<ca>\n{PEM}</ca>\n" in config
    assert "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----" in config
    assert "key-direction 1\n" in config
    assert s.get_data_item("username") == "testuser"
    assert s.get_secret("password") == "pw-from-file"
    assert "creds.txt" not in config


def test_prompted_password_is_agent_owned(plugin, tmp_path):
    path = write(tmp_path, "p.ovpn", "client\nremote vpn.example.net\nauth-user-pass\n")
    s, _ = vpn(plugin.import_(path))
    assert s.get_secret("password") is None
    assert s.get_data_item("password-flags") == str(int(NM.SettingSecretFlags.AGENT_OWNED))
    assert s.get_data_item("challenge-response-flags") == str(int(NM.SettingSecretFlags.NOT_SAVED))


def test_certificate_only_profile_has_no_password(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n")
    s, config = vpn(plugin.import_(path))
    assert "auth-user-pass" not in config
    assert s.get_data_item("username") is None


def test_commented_directive_is_not_credentials(plugin, tmp_path):
    path = write(tmp_path, "k.ovpn", "client\nremote vpn.example.net\n#auth-user-pass\n")
    s, config = vpn(plugin.import_(path))
    assert "\nauth-user-pass\n" not in config
    assert s.get_data_item("password-flags") is None


@pytest.mark.parametrize("text,msg", [
    ("client\nremote vpn.example.net\npkcs12 bundle.p12\n", "PKCS#12"),
    ("client\nremote vpn.example.net\n<ca>\nabc\n", "Unterminated"),
    ("dev tun\nremote vpn.example.net\n", "Not an OpenVPN client profile"),
    ("client\nremote vpn.example.net\nca missing.crt\n", "Cannot read file"),
])
def test_invalid_profiles(plugin, tmp_path, text, msg):
    path = write(tmp_path, "bad.ovpn", text)
    with pytest.raises(GLib.Error, match=msg):
        plugin.import_(path)


def test_wrong_extension_is_rejected(plugin, tmp_path):
    path = write(tmp_path, "profile.txt", "client\nremote vpn.example.net\n")
    with pytest.raises(GLib.Error):
        plugin.import_(path)


def test_export_omits_credentials(plugin, tmp_path):
    src = write(tmp_path, "e.ovpn",
                "client\nremote vpn.example.net\n<auth-user-pass>\ntestuser\npw\n</auth-user-pass>\n")
    con = plugin.import_(src)
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, con)
    text = open(out).read()
    assert "pw" not in text.split("remote vpn.example.net")[1]
    assert "auth-user-pass\n" in text
    assert plugin.get_suggested_filename(con) == "e.ovpn"
    # Round trip keeps the profile.
    again = plugin.import_(out)
    assert vpn(again)[1] == vpn(con)[1]


def test_stored_values_are_single_line(plugin, tmp_path):
    # Some settings backends (netplan) mangle multi-line values.
    path = write(tmp_path, "m.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n")
    s = plugin.import_(path).get_setting_vpn()
    for key in s.get_data_keys():
        assert "\n" not in s.get_data_item(key)
