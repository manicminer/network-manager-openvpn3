# SPDX-License-Identifier: GPL-2.0-or-later
"""Import/export through the built libnm plugin, the way nmcli uses it."""

import base64
import os
import stat

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
    ("client\nremote vpn.example.net\npkcs12 missing.p12\n", "Cannot read file"),
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


def test_pkcs12_file_is_embedded(plugin, tmp_path):
    from pkihelp import p12
    data, _, _ = p12()
    (tmp_path / "client.p12").write_bytes(data)
    path = write(tmp_path, "p.ovpn", "client\nremote vpn.example.net\npkcs12 client.p12\n")
    s, config = vpn(plugin.import_(path))
    assert "pkcs12 client.p12" not in config
    b64 = config.split("<pkcs12>\n")[1].split("</pkcs12>")[0]
    assert base64.b64decode("".join(b64.split())) == data
    assert s.get_data_item("cert-pass-flags") == str(int(NM.SettingSecretFlags.AGENT_OWNED))


def test_encrypted_key_needs_passphrase(plugin, tmp_path):
    from pkihelp import pem_key
    write(tmp_path, "client.key", pem_key(b"keypass"))
    path = write(tmp_path, "k.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\ncert c.crt\nkey client.key\n")
    write(tmp_path, "c.crt", PEM)
    s, config = vpn(plugin.import_(path))
    assert "ENCRYPTED PRIVATE KEY" in config
    assert s.get_data_item("cert-pass-flags") == str(int(NM.SettingSecretFlags.AGENT_OWNED))


def test_plain_key_needs_no_passphrase(plugin, tmp_path):
    from pkihelp import pem_key
    path = write(tmp_path, "n.ovpn", f"client\nremote vpn.example.net\n<key>\n{pem_key()}</key>\n")
    s, _ = vpn(plugin.import_(path))
    assert s.get_data_item("cert-pass-flags") is None


# -- <connection> is a scope of options, not an opaque payload ----------------
#
# A client config may keep its only remote, and the files it references, inside
# one or more <connection> blocks.  Treating the block as an opaque blob made
# such a profile "not an OpenVPN client profile" and left its file references
# dangling, so the import was not self-contained.

TLS_KEY = "-----BEGIN OpenVPN Static key V1-----\n00ff\n-----END OpenVPN Static key V1-----\n"


def test_remote_only_inside_a_connection_block_is_accepted(plugin, tmp_path):
    path = write(tmp_path, "b.ovpn",
                 "client\n<connection>\nremote vpn.example.net 1194 udp\n</connection>\n")
    s, config = vpn(plugin.import_(path))
    assert "<connection>" in config and "</connection>" in config
    assert "remote vpn.example.net 1194 udp" in config


def test_files_referenced_inside_a_connection_block_are_inlined(plugin, tmp_path):
    (tmp_path / "keys").mkdir()
    write(tmp_path, "keys/ca.crt", PEM)
    write(tmp_path, "keys/ta.key", TLS_KEY)
    path = write(tmp_path, "b.ovpn",
                 "client\n<connection>\nremote vpn.example.net 443 tcp\n"
                 "ca keys/ca.crt\ntls-auth \"keys/ta.key\" 1\n</connection>\n")
    s, config = vpn(plugin.import_(path))
    assert "ca keys/ca.crt" not in config and "keys/ta.key" not in config
    assert f"<ca>\n{PEM}</ca>\n" in config
    assert "<tls-auth>\n" + TLS_KEY + "</tls-auth>\n" in config
    assert "key-direction 1\n" in config
    # Still inside the block they were written in.
    block = config.split("<connection>\n")[1].split("</connection>")[0]
    assert "<ca>" in block and "<tls-auth>" in block


def test_repeated_connection_blocks_keep_their_order_and_their_files(plugin, tmp_path):
    write(tmp_path, "one.crt", PEM)
    write(tmp_path, "two.key", TLS_KEY)
    path = write(tmp_path, "b.ovpn",
                 "client\n"
                 "<connection>\nremote first.example.net 1194 udp\nca one.crt\n</connection>\n"
                 "<connection>\nremote second.example.net 443 tcp\ntls-crypt two.key\n</connection>\n")
    s, config = vpn(plugin.import_(path))
    blocks = config.split("<connection>\n")[1:]
    assert len(blocks) == 2
    assert "first.example.net" in blocks[0] and PEM in blocks[0]
    assert "second.example.net" in blocks[1] and TLS_KEY in blocks[1]
    assert config.index("first.example.net") < config.index("second.example.net")


def test_an_inline_payload_nested_in_a_connection_block_stays_opaque(plugin, tmp_path):
    # The lines of a certificate are not directives, wherever the block sits.
    body = ("client\n<connection>\nremote vpn.example.net 1194\n"
            "<ca>\n-----BEGIN CERTIFICATE-----\nremote not-a-directive.example.com\n"
            "-----END CERTIFICATE-----\n</ca>\n</connection>\n")
    path = write(tmp_path, "b.ovpn", body)
    s, config = vpn(plugin.import_(path))
    assert "remote not-a-directive.example.com" in config  # preserved verbatim
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    # The remote the editor and the service see is the real one.
    again = plugin.import_(out)
    assert "vpn.example.net" in vpn(again)[1]


def test_unknown_directives_inside_a_connection_block_survive(plugin, tmp_path):
    path = write(tmp_path, "b.ovpn",
                 "client\n<connection>\nremote vpn.example.net 1194\n"
                 "some-future-directive 7 'quoted arg'\n</connection>\n")
    s, config = vpn(plugin.import_(path))
    assert "some-future-directive 7 'quoted arg'" in config


def test_a_connection_block_profile_needs_nothing_from_disk_afterwards(plugin, tmp_path):
    import shutil
    src = tmp_path / "src"
    src.mkdir()
    (src / "ca.crt").write_text(PEM)
    (src / "ta.key").write_text(TLS_KEY)
    (src / "creds.txt").write_text("testuser\npw-from-file\n")
    path = write(src, "b.ovpn",
                 "client\nauth-user-pass creds.txt\n"
                 "<connection>\nremote vpn.example.net 1194\nca ca.crt\n"
                 "tls-auth ta.key 1\n</connection>\n")
    con = plugin.import_(path)
    shutil.rmtree(src)
    s, config = vpn(con)
    assert PEM in config and TLS_KEY in config
    assert s.get_data_item("username") == "testuser"
    assert s.get_secret("password") == "pw-from-file"
    assert "creds.txt" not in config and "ca.crt" not in config
    # Everything it needs is in the text itself: it re-parses with no files.
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, con)
    assert vpn(plugin.import_(out))[1] == config


def test_an_unterminated_connection_block_is_rejected(plugin, tmp_path):
    path = write(tmp_path, "b.ovpn", "client\n<connection>\nremote vpn.example.net 1194\n")
    with pytest.raises(GLib.Error, match="Unterminated"):
        plugin.import_(path)


def test_a_profile_with_no_remote_anywhere_is_still_rejected(plugin, tmp_path):
    path = write(tmp_path, "b.ovpn", "client\n<connection>\nproto udp\n</connection>\n")
    with pytest.raises(GLib.Error, match="Not an OpenVPN client profile"):
        plugin.import_(path)


# -- profiles kept with the connection's secrets ------------------------------

STORAGE_SECRET = "secret"


def to_secret_mode(con, flags=NM.SettingSecretFlags.AGENT_OWNED, keep_secret=True):
    """Moves an imported connection to the secret profile layout."""
    s = con.get_setting_vpn()
    profile = s.get_data_item("profile")
    s.remove_data_item("profile")
    s.add_data_item("profile-storage", STORAGE_SECRET)
    s.set_secret_flags("profile", flags)
    if keep_secret:
        s.add_secret("profile", profile)
    return con


def test_import_still_produces_a_legacy_profile(plugin, tmp_path):
    # Other clients read vpn.data['profile']; the Plasma editor is the one
    # that migrates a connection to the secret layout.
    path = write(tmp_path, "l.ovpn", "client\nremote vpn.example.net\n")
    s = plugin.import_(path).get_setting_vpn()
    assert s.get_data_item("profile")
    assert s.get_data_item("profile-storage") is None


def test_export_refuses_a_secret_mode_profile(plugin, tmp_path):
    src = write(tmp_path, "s.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n")
    con = to_secret_mode(plugin.import_(src))
    out = str(tmp_path / "out.ovpn")
    with pytest.raises(GLib.Error, match="secret"):
        plugin.export(out, con)
    assert not os.path.exists(out)


def test_export_of_a_legacy_profile_still_works(plugin, tmp_path):
    src = write(tmp_path, "s.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n")
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(src))


def test_export_refuses_an_unknown_profile_layout(plugin, tmp_path):
    # The data item belongs to whatever layout the connection used before the
    # one it now declares; exporting it would write a stale profile out.
    src = write(tmp_path, "s.ovpn", f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n")
    con = plugin.import_(src)
    con.get_setting_vpn().add_data_item("profile-storage", "v2-whatever")
    out = str(tmp_path / "out.ovpn")
    with pytest.raises(GLib.Error, match="layout"):
        plugin.export(out, con)
    assert not os.path.exists(out)


# -- what the legacy export writes, and with which permissions ----------------


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def key_profile(tmp_path, name="k.ovpn"):
    from pkihelp import pem_key
    return write(tmp_path, name,
                 "client\nremote vpn.example.net\n"
                 "<auth-user-pass>\ntestuser\npw-in-profile\n</auth-user-pass>\n"
                 f"<ca>\n{PEM}</ca>\n<key>\n{pem_key()}</key>\n")


def test_export_writes_a_private_file(plugin, tmp_path):
    # The exported profile is self-contained, so it carries the private key.
    con = plugin.import_(key_profile(tmp_path))
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, con)
    assert "PRIVATE KEY" in open(out).read()
    assert mode_of(out) == 0o600


def test_export_omits_passwords_but_not_inlined_key_material(plugin, tmp_path):
    con = plugin.import_(key_profile(tmp_path))
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, con)
    text = open(out).read()
    assert "pw-in-profile" not in text and "testuser" not in text
    assert "auth-user-pass\n" in text
    assert "BEGIN PRIVATE KEY" in text


def test_export_tightens_an_existing_world_readable_file(plugin, tmp_path):
    con = plugin.import_(key_profile(tmp_path))
    out = tmp_path / "out.ovpn"
    out.write_text("left over from an older export\n")
    out.chmod(0o644)
    assert plugin.export(str(out), con)
    assert mode_of(out) == 0o600
    assert "left over" not in out.read_text()


def test_export_replaces_a_symlink_rather_than_writing_through_it(plugin, tmp_path):
    con = plugin.import_(key_profile(tmp_path))
    target = tmp_path / "somebody-elses-file"
    target.write_text("untouched\n")
    target.chmod(0o644)
    link = tmp_path / "out.ovpn"
    link.symlink_to(target)
    assert plugin.export(str(link), con)
    assert target.read_text() == "untouched\n"
    assert mode_of(target) == 0o644
    assert not link.is_symlink()
    assert mode_of(link) == 0o600


def test_export_leaves_no_temporary_file_behind(plugin, tmp_path):
    con = plugin.import_(key_profile(tmp_path, "k.ovpn"))
    d = tmp_path / "out"
    d.mkdir()
    assert plugin.export(str(d / "out.ovpn"), con)
    assert [p.name for p in d.iterdir()] == ["out.ovpn"]


def test_a_failed_export_leaves_nothing_behind(plugin, tmp_path):
    con = plugin.import_(key_profile(tmp_path))
    d = tmp_path / "out"
    d.mkdir()
    with pytest.raises(GLib.Error):
        plugin.export(str(d / "missing" / "out.ovpn"), con)
    assert list(d.iterdir()) == []
