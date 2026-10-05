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


# -- comments are dropped on import -------------------------------------------
#
# openvpn3 ignores comments, and the profile inside a connection is no longer a
# file anybody opens in an editor, so carrying them over only clutters the
# clients that show the profile as a table of entries.  What counts as a
# comment is what OpenVPN 2 and openvpn3 agree is one; see comment_start() in
# properties/ovpn-import.c for the two lexers this follows.


def test_full_line_comments_are_dropped(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "# a hash comment\n"
                 "client\n"
                 "; a semicolon comment\n"
                 "    # an indented comment\n"
                 "remote vpn.example.net 1194\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net 1194\n"


def test_inline_comments_are_dropped(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net 1194 # the main one\n"
                 "dev tun\t; and one after a tab\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net 1194\ndev tun\n"


def test_the_order_of_what_is_left_survives(plugin, tmp_path):
    # Nothing is sorted or deduplicated; only the formatting goes.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "\n"
                 "# first\n"
                 "remote b.example.net\n"
                 "remote a.example.net\n"
                 "remote b.example.net\n"
                 "\n"
                 "some-directive-we-have-never-heard-of 1 2 3 # why not\n")
    _, config = vpn(plugin.import_(path))
    assert config == ("client\n"
                      "remote b.example.net\n"
                      "remote a.example.net\n"
                      "remote b.example.net\n"
                      "some-directive-we-have-never-heard-of 1 2 3\n")


def test_comments_inside_a_connection_block_are_dropped(plugin, tmp_path):
    # <connection> is a scope of options, so its lines are directives and the
    # comments among them are comments.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "<connection>\n"
                 "# the failover entry\n"
                 "remote fallback.example.net 1194 udp # via the proxy\n"
                 "http-proxy proxy.example.net 8080\n"
                 "</connection>\n")
    _, config = vpn(plugin.import_(path))
    assert config == ("client\n"
                      "<connection>\n"
                      "remote fallback.example.net 1194 udp\n"
                      "http-proxy proxy.example.net 8080\n"
                      "</connection>\n")


def test_a_quoted_or_escaped_hash_is_a_value_not_a_comment(plugin, tmp_path):
    # Truncating any of these would silently change what the option means.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 'setenv a "# inside double quotes"\n'
                 "setenv b '; inside single quotes'\n"
                 "setenv c value#glued-to-a-word\n"
                 "setenv d \\#escaped\n")
    _, config = vpn(plugin.import_(path))
    assert 'setenv a "# inside double quotes"\n' in config
    assert "setenv b '; inside single quotes'\n" in config
    assert "setenv c value#glued-to-a-word\n" in config
    assert "setenv d \\#escaped\n" in config


def test_opaque_block_payloads_are_never_touched(plugin, tmp_path):
    # A certificate, a key or an unknown payload is content, not directives:
    # a '#' in there is part of the data.
    body = ("-----BEGIN CERTIFICATE-----\n"
            "# not a comment, just base64 that looks like one\n"
            "A;B#C\n"
            "-----END CERTIFICATE-----\n")
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\n"
                 f"<ca>\n{body}</ca>\n"
                 "<some-future-payload>\n# kept\n</some-future-payload>\n")
    _, config = vpn(plugin.import_(path))
    assert f"<ca>\n{body}</ca>\n" in config
    assert "<some-future-payload>\n# kept\n</some-future-payload>\n" in config


def test_private_key_material_is_byte_for_byte(plugin, tmp_path):
    from pkihelp import pem_key
    key = pem_key()
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net # here\n"
                 f"<key>\n{key}</key>\n")
    _, config = vpn(plugin.import_(path))
    assert f"<key>\n{key}</key>\n" in config


def test_a_password_that_looks_like_a_comment_survives(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\n"
                 "<auth-user-pass>\nalice\n#hunter2 ; really\n</auth-user-pass>\n")
    s, config = vpn(plugin.import_(path))
    assert s.get_data_item("username") == "alice"
    assert s.get_secret("password") == "#hunter2 ; really"
    assert config == "client\nremote vpn.example.net\nauth-user-pass\n"


def test_a_credentials_file_whose_password_looks_like_a_comment_survives(plugin, tmp_path):
    write(tmp_path, "creds.txt", "alice\n; not a comment\n")
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\nauth-user-pass creds.txt # read at import\n")
    s, config = vpn(plugin.import_(path))
    assert s.get_secret("password") == "; not a comment"
    assert config == "client\nremote vpn.example.net\nauth-user-pass\n"


def test_crlf_and_a_missing_final_newline(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "# intro\r\nclient\r\nremote vpn.example.net # here\r\ndev tun")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net\ndev tun\n"


def test_a_comment_only_profile_is_still_refused(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn", "# client\n; remote vpn.example.net\n")
    with pytest.raises(GLib.Error, match="Not an OpenVPN client profile"):
        plugin.import_(path)


def test_a_comment_cannot_close_an_inline_block(plugin, tmp_path):
    # openvpn3 matches a closing tag against the raw line, so "</ca> # done"
    # does not close <ca> for it either.  Refusing the profile is the only
    # honest answer: the alternative is storing one openvpn3 will not load.
    path = write(tmp_path, "c.ovpn",
                 f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca> # done\n")
    with pytest.raises(GLib.Error, match="Unterminated"):
        plugin.import_(path)


def test_a_comment_cannot_close_a_connection_scope(plugin, tmp_path):
    # <connection> is a scope for the directives inside it, but it is still a
    # block, and openvpn3 matches every closing tag against the raw line.  A
    # comment after one leaves the block open for openvpn3, so it has to leave
    # it open here too rather than store a profile openvpn3 will not load.
    path = write(tmp_path, "c.ovpn",
                 "client\n<connection>\nremote vpn.example.net 1194\n</connection> # done\n")
    with pytest.raises(GLib.Error, match="Unterminated"):
        plugin.import_(path)


def test_a_comment_on_a_tag_line_is_dropped_and_the_tag_still_opens(plugin, tmp_path):
    # openvpn3 strips the comment before deciding whether the line is a tag.
    path = write(tmp_path, "c.ovpn",
                 f"client\nremote vpn.example.net\n<ca> # the CA\n{PEM}</ca>\n")
    _, config = vpn(plugin.import_(path))
    assert config == f"client\nremote vpn.example.net\n<ca>\n{PEM}</ca>\n"


def test_a_commented_profile_survives_an_export_and_reimport(plugin, tmp_path):
    # Export writes the stored profile out as it stands, so what import left
    # is what a second import gets: dropping comments has to be idempotent.
    path = write(tmp_path, "c.ovpn",
                 "# intro\nclient\nremote vpn.example.net 1194 # the main one\n"
                 f"<ca>\n{PEM}</ca>\n")
    first = vpn(plugin.import_(path))[1]
    assert "#" not in first.replace(PEM, "")
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    assert open(out).read() == first
    assert vpn(plugin.import_(out))[1] == first


def test_an_escaped_apostrophe_inside_single_quotes_is_not_a_comment(plugin, tmp_path):
    # The one place the two lexers part company over quoting: openvpn3 lets a
    # backslash escape the apostrophe and stays inside the single quote, so
    # the hash is part of the value, while OpenVPN 2 does not escape inside
    # single quotes, so for it the quote ends there and a comment follows.
    # They disagree, so nothing is cut -- cutting would destroy the value
    # openvpn3, the one that reads the stored profile, sees.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 "setenv a 'x\\' # literal'\n"
                 "setenv b 'y\\' ; literal'\n"
                 "<connection>\n"
                 "remote fallback.example.net\n"
                 "setenv c 'z\\' # literal'\n"
                 "</connection>\n")
    _, config = vpn(plugin.import_(path))
    assert "setenv a 'x\\' # literal'\n" in config
    assert "setenv b 'y\\' ; literal'\n" in config
    assert "setenv c 'z\\' # literal'\n" in config


def test_escaped_whitespace_before_a_comment_is_part_of_the_value(plugin, tmp_path):
    # "value\ " is a value with a space on its end for both lexers; only the
    # unescaped whitespace after it separates the comment.  Trimming both
    # would change the value and leave a dangling backslash behind.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 "setenv a value\\  # the comment\n"
                 "setenv b other\\\t\t; the comment\n"
                 "<connection>\n"
                 "remote fallback.example.net\n"
                 "setenv c inner\\  # the comment\n"
                 "</connection>\n")
    _, config = vpn(plugin.import_(path))
    assert "setenv a value\\ \n" in config
    assert "setenv b other\\\t\n" in config
    assert "setenv c inner\\ \n" in config
    assert "#" not in config and ";" not in config


def test_an_escaped_backslash_before_a_comment_is_not_an_escape(plugin, tmp_path):
    # Two backslashes are one literal backslash, so the whitespace after them
    # is a separator again and goes with the comment.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 "setenv a value\\\\ # the comment\n")
    _, config = vpn(plugin.import_(path))
    assert "setenv a value\\\\\n" in config


def test_escaped_trailing_whitespace_survives_an_export_and_reimport(plugin, tmp_path):
    # The first pass leaves "setenv a value\ " -- a value with a space on its
    # end.  Every later pass trims the line it reads before anything else, so
    # that is where the escape has to be honoured too: otherwise the second
    # import hands openvpn3 a bare backslash before the newline.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 "setenv a value\\  # the comment\n"
                 "setenv b other\\\t\t; the comment\n"
                 "<connection>\n"
                 "remote fallback.example.net\n"
                 "setenv c inner\\  # the comment\n"
                 "</connection>\n")
    first = vpn(plugin.import_(path))[1]
    assert "setenv a value\\ \n" in first

    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    assert open(out).read() == first
    second = vpn(plugin.import_(out))[1]
    assert second == first
    assert "setenv a value\\ \n" in second
    assert "setenv b other\\\t\n" in second
    assert "setenv c inner\\ \n" in second
    assert "setenv a value\\\n" not in second


def test_unicode_whitespace_in_a_value_is_not_a_separator(plugin, tmp_path):
    # A directive line separates its words with ASCII whitespace; U+00A0 and
    # the other Unicode separators are literal bytes of the value in front of
    # them.  So the separator run a comment is cut with stops at one, and one
    # cannot start the word a comment has to begin.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "remote vpn.example.net\n"
                 "setenv a value  # the comment\n"
                 "setenv b value  ; the comment\n"
                 "setenv c value # not a comment\n")
    first = vpn(plugin.import_(path))[1]
    assert "setenv a value \n" in first
    assert "setenv b value \n" in first
    assert "setenv c value # not a comment\n" in first
    # And a second pass changes nothing more.
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    assert vpn(plugin.import_(out))[1] == first


def test_a_commented_closing_tag_does_not_become_a_scope_boundary(plugin, tmp_path):
    # openvpn3 matches every closing tag against the raw line, so this line is
    # not a boundary for it and the scope runs on to the real closer below.
    # Cutting the comment off would emit a boundary openvpn3 does not see and
    # push "remote b" out of the scope -- on a profile that would then no
    # longer balance.  The line is kept exactly as it came instead.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "<connection>\n"
                 "remote a.example.net\n"
                 "</connection> # not a closer\n"
                 "remote b.example.net\n"
                 "</connection>\n")
    first = vpn(plugin.import_(path))[1]
    assert first == ("client\n"
                     "<connection>\n"
                     "remote a.example.net\n"
                     "</connection> # not a closer\n"
                     "remote b.example.net\n"
                     "</connection>\n")
    # Exactly one scope, and "remote b" is still inside it.
    assert first.count("<connection>\n") == 1
    assert first.count("</connection>\n") == 1
    # A second pass changes nothing more.
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    assert vpn(plugin.import_(out))[1] == first


def test_a_commented_closing_tag_at_the_top_level_is_kept(plugin, tmp_path):
    # The same line with no scope open: still not a closing tag for openvpn3,
    # so still not turned into one here.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "</connection> ; not a closer\n"
                 "remote vpn.example.net\n")
    first = vpn(plugin.import_(path))[1]
    assert "</connection> ; not a closer\n" in first
    assert "</connection>\n" not in first


# -- blank lines are dropped on import ----------------------------------------
#
# For the same reason comments are: a line that is only whitespace tells
# openvpn3 nothing, and the profile inside a connection is not a file whose
# layout anybody reads any more.  A client that renders it as a table of
# entries would get a row that means nothing and that no edit can reach.
#
# "Blank" is ASCII whitespace only, which is what g_ascii_isspace() -- and
# openvpn3's own lexer -- counts; see strip_separators() in
# properties/ovpn-import.c.  The lines of an inline payload are content rather
# than formatting and are never inspected.


def test_blank_lines_are_dropped(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "\n"
                 "client\n"
                 "\n"
                 "\n"
                 "remote vpn.example.net 1194\n"
                 "\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net 1194\n"


def test_whitespace_only_lines_are_dropped(plugin, tmp_path):
    # A line of ASCII whitespace is formatting whichever characters it is
    # made of.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "   \n"
                 "\t\n"
                 " \t \f \n"
                 "remote vpn.example.net\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net\n"


def test_a_vertical_tab_is_not_whitespace(plugin, tmp_path):
    # g_ascii_isspace(), which is what every line here is stripped with, does
    # not count '\v' -- unlike C's isspace().  So a line of them is a value
    # rather than formatting and stays, and the editor's own reader has to draw
    # the line in exactly the same place or the two disagree about which lines
    # a profile has.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "\v\n"
                 "remote vpn.example.net\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\n\v\nremote vpn.example.net\n"


def test_a_blank_line_is_dropped_whatever_the_comment_around_it(plugin, tmp_path):
    # A line that is only a comment leaves nothing behind, and the blank line
    # it sat next to leaves nothing behind either: neither reappears as the
    # other.
    path = write(tmp_path, "c.ovpn",
                 "# intro\n"
                 "\n"
                 "client\n"
                 "   # indented\n"
                 "\n"
                 "remote vpn.example.net\t# here\n"
                 "\n"
                 "; outro\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net\n"


def test_blank_lines_inside_a_connection_scope_are_dropped(plugin, tmp_path):
    # <connection> is a scope of options, so its lines are directives and the
    # blank ones among them are formatting just the same.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 "<connection>\n"
                 "\n"
                 "remote fallback.example.net 1194 udp\n"
                 "   \n"
                 "http-proxy proxy.example.net 8080\n"
                 "\n"
                 "</connection>\n")
    _, config = vpn(plugin.import_(path))
    assert config == ("client\n"
                      "<connection>\n"
                      "remote fallback.example.net 1194 udp\n"
                      "http-proxy proxy.example.net 8080\n"
                      "</connection>\n")


def test_blank_lines_inside_an_opaque_payload_are_kept(plugin, tmp_path):
    # A certificate, a key or an unknown payload is content, not formatting:
    # a blank line in there is a byte of the data, leading and trailing ones
    # included.
    body = ("\n"
            "-----BEGIN CERTIFICATE-----\n"
            "\n"
            "MIIBsyntheticTESTDATA\n"
            "-----END CERTIFICATE-----\n"
            "\n")
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\n"
                 f"<ca>\n{body}</ca>\n"
                 "<some-future-payload>\n\nkept\n   \n</some-future-payload>\n")
    _, config = vpn(plugin.import_(path))
    assert f"<ca>\n{body}</ca>\n" in config
    # The line of spaces is still a line of the payload.  Its trailing
    # whitespace goes the way every payload line's always has -- g_strchomp,
    # unchanged by this -- and what is left is the blank line itself.
    assert "<some-future-payload>\n\nkept\n\n</some-future-payload>\n" in config


def test_private_key_material_keeps_its_blank_lines(plugin, tmp_path):
    from pkihelp import pem_key
    key = pem_key()
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\n"
                 f"<key>\n\n{key}\n</key>\n")
    _, config = vpn(plugin.import_(path))
    assert f"<key>\n\n{key}\n</key>\n" in config


def test_an_empty_password_in_an_inline_credentials_block_survives(plugin, tmp_path):
    # The blank second line of the block is the password, not formatting: it
    # has to reach take_credentials() as the empty password it is, rather than
    # be swallowed so that the line below it becomes the password.
    path = write(tmp_path, "c.ovpn",
                 "client\nremote vpn.example.net\n"
                 "<auth-user-pass>\nalice\n\n</auth-user-pass>\n")
    s, config = vpn(plugin.import_(path))
    assert s.get_data_item("username") == "alice"
    assert s.get_secret("password") is None
    assert config == "client\nremote vpn.example.net\nauth-user-pass\n"


def test_a_unicode_whitespace_only_line_is_not_blank(plugin, tmp_path):
    # U+00A0 and the other Unicode separators separate nothing for openvpn3,
    # so a line made of them is a value rather than formatting and stays.
    path = write(tmp_path, "c.ovpn",
                 "client\n"
                 " \n"
                 "remote vpn.example.net\n")
    _, config = vpn(plugin.import_(path))
    assert config == "client\n \nremote vpn.example.net\n"


def test_crlf_blank_lines_are_dropped(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn",
                 "client\r\n\r\nremote vpn.example.net\r\n \r\ndev tun")
    _, config = vpn(plugin.import_(path))
    assert config == "client\nremote vpn.example.net\ndev tun\n"


def test_a_blank_only_profile_is_still_refused(plugin, tmp_path):
    path = write(tmp_path, "c.ovpn", "\n   \n\t\n\n")
    with pytest.raises(GLib.Error, match="Not an OpenVPN client profile"):
        plugin.import_(path)


def test_a_blank_line_cannot_close_a_block(plugin, tmp_path):
    # Dropping blank lines must not reach into an unterminated payload and
    # make it look closed: the profile is still refused.
    path = write(tmp_path, "c.ovpn",
                 f"client\nremote vpn.example.net\n<ca>\n{PEM}\n\n")
    with pytest.raises(GLib.Error, match="Unterminated"):
        plugin.import_(path)


def test_a_profile_with_blank_lines_survives_an_export_and_reimport(plugin, tmp_path):
    # Export writes the stored profile out as it stands, so what import left is
    # what a second import gets: dropping blank lines has to be idempotent,
    # including inside a scope and around an opaque payload.
    path = write(tmp_path, "c.ovpn",
                 "\nclient\n\nremote vpn.example.net 1194\n\n"
                 "<connection>\n\nremote fallback.example.net\n\n</connection>\n"
                 f"<ca>\n\n{PEM}\n</ca>\n\n")
    first = vpn(plugin.import_(path))[1]
    assert first == ("client\n"
                     "remote vpn.example.net 1194\n"
                     "<connection>\n"
                     "remote fallback.example.net\n"
                     "</connection>\n"
                     f"<ca>\n\n{PEM}\n</ca>\n")
    out = str(tmp_path / "out.ovpn")
    assert plugin.export(out, plugin.import_(path))
    assert open(out).read() == first
    assert vpn(plugin.import_(out))[1] == first
