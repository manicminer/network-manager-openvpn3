# SPDX-License-Identifier: GPL-2.0-or-later
"""Build NetworkManager VPN IP configuration from the tunnel's live state.

openvpn3-netcfg configures the tun device itself (addresses, routes, DNS).
NetworkManager then re-applies whatever the plugin reports on the same
interface, so we report exactly what is already there: the kernel state of
the device plus the DNS settings netcfg holds for it.
"""

import ipaddress
import json
import socket
import subprocess
import sys
from dataclasses import dataclass, field

from gi.repository import GLib


@dataclass
class FamilyConfig:
    address: str | None = None
    prefix: int | None = None
    routes: list = field(default_factory=list)  # (network, prefix, gateway|None)
    has_default: bool = False
    dns: list = field(default_factory=list)


@dataclass
class TunnelState:
    device: str
    mtu: int | None
    ip4: FamilyConfig
    ip6: FamilyConfig
    domains: list


def _ip_json(*args):
    out = subprocess.run(["ip", "-j", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else []


def parse_links(addr_json):
    """Extract (mtu, ip4 (addr, prefix), ip6 (addr, prefix)) from `ip -j addr`."""
    mtu, v4, v6 = None, None, None
    for link in addr_json:
        mtu = link.get("mtu", mtu)
        for a in link.get("addr_info", []):
            if a.get("scope") != "global":
                continue
            if a.get("family") == "inet" and v4 is None:
                v4 = (a["local"], int(a["prefixlen"]))
            elif a.get("family") == "inet6" and v6 is None:
                v6 = (a["local"], int(a["prefixlen"]))
    return mtu, v4, v6


def parse_routes(route_json, family):
    """Return (routes, has_default) from `ip -j route show dev X`.

    Kernel prefix routes are skipped, NetworkManager derives them from the
    address itself.
    """
    routes, has_default = [], False
    for r in route_json:
        if r.get("protocol") == "kernel":
            continue
        if r.get("type", "unicast") != "unicast":
            continue
        dst = r.get("dst")
        if dst == "default":
            has_default = True
            continue
        net = ipaddress.ip_network(dst if "/" in dst else f"{dst}/{32 if family == 4 else 128}",
                                   strict=False)
        if net.prefixlen == 0:
            has_default = True
            continue
        routes.append((str(net.network_address), net.prefixlen, r.get("gateway")))
    return routes, has_default


def split_dns(servers):
    v4, v6 = [], []
    for s in servers:
        ip = ipaddress.ip_address(s)
        (v4 if ip.version == 4 else v6).append(str(ip))
    return v4, v6


def snapshot(device, dns_servers, dns_domains):
    mtu, v4, v6 = parse_links(_ip_json("addr", "show", "dev", device))
    r4, d4 = parse_routes(_ip_json("-4", "route", "show", "dev", device), 4)
    r6, d6 = parse_routes(_ip_json("-6", "route", "show", "dev", device), 6)
    dns4, dns6 = split_dns(dns_servers)
    ip4 = FamilyConfig(*(v4 or (None, None)), routes=r4, has_default=d4, dns=dns4)
    ip6 = FamilyConfig(*(v6 or (None, None)), routes=r6, has_default=d6, dns=dns6)
    return TunnelState(device, mtu, ip4, ip6, list(dns_domains))


def _u32(ip):
    """IPv4 address as a guint32 in network byte order, as libnm expects."""
    return int.from_bytes(socket.inet_aton(ip), sys.byteorder)


def _ay(ip):
    return GLib.Variant("ay", ipaddress.IPv6Address(ip).packed)


def general_config(state, gateway):
    cfg = {
        "tundev": GLib.Variant("s", state.device),
        "has-ip4": GLib.Variant("b", state.ip4.address is not None),
        "has-ip6": GLib.Variant("b", state.ip6.address is not None),
    }
    if state.mtu:
        cfg["mtu"] = GLib.Variant("u", state.mtu)
    if gateway:
        gw = ipaddress.ip_address(gateway)
        cfg["gateway"] = GLib.Variant("u", _u32(str(gw))) if gw.version == 4 else _ay(str(gw))
    return GLib.Variant("a{sv}", cfg)


def ip4_config(state):
    c = state.ip4
    cfg = {
        "address": GLib.Variant("u", _u32(c.address)),
        "prefix": GLib.Variant("u", c.prefix),
        "never-default": GLib.Variant("b", not c.has_default),
        "routes": GLib.Variant("aau", [[_u32(n), p, _u32(g) if g else 0, 0] for n, p, g in c.routes]),
    }
    if c.dns:
        cfg["dns"] = GLib.Variant("au", [_u32(d) for d in c.dns])
    if state.domains:
        cfg["domains"] = GLib.Variant("as", state.domains)
    return GLib.Variant("a{sv}", cfg)


def ip6_config(state):
    c = state.ip6
    zero = bytes(16)
    routes = [(ipaddress.IPv6Address(n).packed, p,
               ipaddress.IPv6Address(g).packed if g else zero, 0) for n, p, g in c.routes]
    cfg = {
        "address": _ay(c.address),
        "prefix": GLib.Variant("u", c.prefix),
        "never-default": GLib.Variant("b", not c.has_default),
        "routes": GLib.Variant("a(ayuayu)", routes),
    }
    if c.dns:
        cfg["dns"] = GLib.Variant("aay", [ipaddress.IPv6Address(d).packed for d in c.dns])
    if state.domains and state.ip4.address is None:
        cfg["domains"] = GLib.Variant("as", state.domains)
    return GLib.Variant("a{sv}", cfg)
