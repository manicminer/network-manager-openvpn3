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
