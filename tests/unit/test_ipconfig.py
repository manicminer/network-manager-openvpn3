# SPDX-License-Identifier: GPL-2.0-or-later
import ipaddress
import socket
import sys

from nm_openvpn3 import ipconfig

ADDR = [{
    "ifname": "tun7", "mtu": 1400,
    "addr_info": [
        {"family": "inet", "local": "198.51.100.6", "prefixlen": 24, "scope": "global"},
        {"family": "inet6", "local": "2001:db8:1::6", "prefixlen": 64, "scope": "global"},
        {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
    ],
}]

ROUTES4 = [
    {"dst": "198.51.100.0/24", "protocol": "kernel", "scope": "link"},
    {"dst": "0.0.0.0/1", "gateway": "198.51.100.1", "protocol": "static"},
    {"dst": "128.0.0.0/1", "gateway": "198.51.100.1", "protocol": "static"},
    {"dst": "203.0.113.0/24", "protocol": "static"},
    {"dst": "192.0.2.53", "protocol": "static"},
]

ROUTES6 = [
    {"dst": "2001:db8:1::/64", "protocol": "kernel"},
    {"dst": "default", "gateway": "2001:db8:1::1", "protocol": "static"},
    {"dst": "fe80::/64", "protocol": "kernel"},
]


def u32(ip):
    return int.from_bytes(socket.inet_aton(ip), sys.byteorder)


def state():
    mtu, v4, v6 = ipconfig.parse_links(ADDR)
    r4, d4 = ipconfig.parse_routes(ROUTES4, 4)
    r6, d6 = ipconfig.parse_routes(ROUTES6, 6)
    return ipconfig.TunnelState(
        "tun7", mtu,
        ipconfig.FamilyConfig(*v4, routes=r4, has_default=d4, dns=["192.0.2.53"]),
        ipconfig.FamilyConfig(*v6, routes=r6, has_default=d6, dns=["2001:db8::53"]),
        ["corp.example.com"])


def test_parse_links_skips_link_local():
    mtu, v4, v6 = ipconfig.parse_links(ADDR)
    assert mtu == 1400
    assert v4 == ("198.51.100.6", 24)
    assert v6 == ("2001:db8:1::6", 64)


def test_parse_routes():
    r4, d4 = ipconfig.parse_routes(ROUTES4, 4)
    assert r4 == [("0.0.0.0", 1, "198.51.100.1"), ("128.0.0.0", 1, "198.51.100.1"),
                  ("203.0.113.0", 24, None), ("192.0.2.53", 32, None)]
    assert not d4
    r6, d6 = ipconfig.parse_routes(ROUTES6, 6)
    assert r6 == []
    assert d6


def test_split_dns():
    assert ipconfig.split_dns(["192.0.2.53", "2001:db8::53"]) == (["192.0.2.53"], ["2001:db8::53"])


def test_general_config():
    cfg = ipconfig.general_config(state(), "203.0.113.10").unpack()
    assert cfg == {"tundev": "tun7", "has-ip4": True, "has-ip6": True, "mtu": 1400,
                   "gateway": u32("203.0.113.10")}
    cfg6 = ipconfig.general_config(state(), "2001:db8::10").unpack()
    assert bytes(cfg6["gateway"]) == ipaddress.IPv6Address("2001:db8::10").packed


def test_ip4_config():
    cfg = ipconfig.ip4_config(state()).unpack()
    assert cfg["address"] == u32("198.51.100.6")
    assert cfg["prefix"] == 24
    assert cfg["never-default"] is True
    assert cfg["dns"] == [u32("192.0.2.53")]
    assert cfg["domains"] == ["corp.example.com"]
    assert cfg["routes"][0] == [u32("0.0.0.0"), 1, u32("198.51.100.1"), 0]
    assert cfg["routes"][2] == [u32("203.0.113.0"), 24, 0, 0]


def test_ip6_config():
    cfg = ipconfig.ip6_config(state()).unpack()
    assert bytes(cfg["address"]) == ipaddress.IPv6Address("2001:db8:1::6").packed
    assert cfg["never-default"] is False
    assert [bytes(d) for d in cfg["dns"]] == [ipaddress.IPv6Address("2001:db8::53").packed]
    assert "domains" not in cfg


def test_netcfg_manages_dns(tmp_path):
    from nm_openvpn3 import openvpn3 as ov3
    f = tmp_path / "netcfg.json"
    assert not ov3.netcfg_manages_dns(str(f))
    f.write_text('{\n\t//  Option --systemd-resolved :: Systemd-resolved in use\n\t"systemd_resolved" : true\n}\n')
    assert ov3.netcfg_manages_dns(str(f))
    f.write_text("{}\n")
    assert not ov3.netcfg_manages_dns(str(f))
