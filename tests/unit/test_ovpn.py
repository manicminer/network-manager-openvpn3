# SPDX-License-Identifier: GPL-2.0-or-later
from nm_openvpn3 import ovpn

PROFILE = """\
client
dev tun
# remote commented.example.com 1
remote vpn.example.net 1194 udp
remote vpn2.example.net
auth-user-pass
static-challenge "Enter OTP" 1
<ca>
-----BEGIN CERTIFICATE-----
remote not-a-directive.example.com
-----END CERTIFICATE-----
</ca>
"""


def test_needs_user_pass():
    assert ovpn.needs_user_pass(PROFILE)
    assert not ovpn.needs_user_pass("client\nremote vpn.example.net\n")


def test_first_remote_skips_comments():
    assert ovpn.first_remote(PROFILE) == ("vpn.example.net", "1194")
    assert ovpn.first_remote("remote 192.0.2.10\n") == ("192.0.2.10", None)
    assert ovpn.first_remote("client\n") is None


def test_inline_blocks_are_not_directives():
    text = "<ca>\nauth-user-pass\n</ca>\nclient\n"
    assert not ovpn.needs_user_pass(text)


def test_static_challenge():
    sc = ovpn.static_challenge(PROFILE)
    assert sc == ovpn.StaticChallenge("Enter OTP", True)
    assert ovpn.static_challenge("client\n") is None


# -- <connection> is a scope of options, not an opaque payload ----------------

BLOCKS = """\
client
<connection>
remote vpn1.example.net 1194 udp
<ca>
-----BEGIN CERTIFICATE-----
remote not-a-directive.example.com
-----END CERTIFICATE-----
</ca>
</connection>
<connection>
remote vpn2.example.net 443 tcp
auth-user-pass
static-challenge "Enter OTP" 1
</connection>
"""


def test_directives_inside_a_connection_block_are_directives():
    assert ovpn.first_remote(BLOCKS) == ("vpn1.example.net", "1194")
    assert ovpn.needs_user_pass(BLOCKS)
    assert ovpn.static_challenge(BLOCKS) == ovpn.StaticChallenge("Enter OTP", True)


def test_inline_payloads_nested_in_a_connection_block_stay_opaque():
    assert [name for name, _ in ovpn._directives(BLOCKS)].count("ca") == 1
    assert ovpn.first_remote(BLOCKS) != ("not-a-directive.example.com", None)


def test_a_connection_block_is_still_reported_as_a_block():
    names = [name for name, _ in ovpn._directives(BLOCKS)]
    assert names.count("connection") == 2


def test_an_unmatched_closing_tag_is_kept_as_a_directive():
    # Nothing here validates profiles; an odd line must survive as itself.
    assert [name for name, _ in ovpn._directives("client\n</connection>\n")] \
        == ["client", "</connection>"]
