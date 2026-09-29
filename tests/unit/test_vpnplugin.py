# SPDX-License-Identifier: GPL-2.0-or-later
"""The VPN plugin D-Bus contract, exercised over a private bus."""

import time

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

from nm_openvpn3 import vpnplugin  # noqa: E402

BUS_NAME = "org.freedesktop.NetworkManager.openvpn3.Test"
S = NM.VpnServiceState


class Recorder(vpnplugin.VpnPlugin):
    def __init__(self, *a, **kw):
        self.calls = []
        self.need = None
        self.connect_error = None
        super().__init__(*a, **kw)

    def do_connect(self, connection, interactive):
        self.calls.append(("connect", connection.get_id(), interactive))
        if self.connect_error:
            raise self.connect_error

    def do_need_secrets(self, connection):
        return self.need

    def do_new_secrets(self, connection):
        self.calls.append(("new_secrets", connection.get_setting_vpn().get_secret("password")))

    def do_disconnect(self):
        self.calls.append(("disconnect",))


@pytest.fixture
def env():
    bus_env = Gio.TestDBus.new(Gio.TestDBusFlags.NONE)
    bus_env.up()
    try:
        server = Gio.DBusConnection.new_for_address_sync(
            bus_env.get_bus_address(),
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION)
        client = Gio.DBusConnection.new_for_address_sync(
            bus_env.get_bus_address(),
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION)
        loop = GLib.MainLoop()
        plugin = Recorder(BUS_NAME, loop, bus=server, watch_peer=False)
        signals = []
        client.signal_subscribe(None, vpnplugin.IFACE, None, vpnplugin.PATH, None, 0,
                                lambda *a: signals.append((a[4], a[5].unpack())))
        pump()
        yield plugin, client, signals
        server.close_sync(None)
        client.close_sync(None)
    finally:
        bus_env.down()


def pump():
    ctx = GLib.MainContext.default()
    for _ in range(50):
        while ctx.iteration(False):
            pass
        time.sleep(0.002)


def call(client, method, args=None, iface=vpnplugin.IFACE):
    # Client and service share this thread: call asynchronously and run the
    # main context until the reply arrives.
    box = []
    client.call(BUS_NAME, vpnplugin.PATH, iface, method, args, None,
                Gio.DBusCallFlags.NONE, 2000, None, lambda c, r: box.append(r))
    ctx = GLib.MainContext.default()
    while not box:
        ctx.iteration(True)
    res = client.call_finish(box[0])
    pump()
    return res.unpack() if res is not None else None


def connection_variant(password=None):
    con = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, "test-vpn")
    s_con.set_property(NM.SETTING_CONNECTION_UUID, "3a1b8e5c-7f1e-4c62-9d3c-8f7d5a2b1c00")
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, "vpn")
    con.add_setting(s_con)
    s_vpn = NM.SettingVpn.new()
    s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn3")
    if password:
        s_vpn.add_secret("password", password)
    con.add_setting(s_vpn)
    return con.to_dbus(NM.ConnectionSerializationFlags.ALL)


def states(signals):
    return [S(v[0]) for name, v in signals if name == "StateChanged"]


def test_connect_config_started(env):
    plugin, client, signals = env
    call(client, "ConnectInteractive", GLib.Variant.new_tuple(connection_variant(), GLib.Variant("a{sv}", {})))
    assert plugin.calls == [("connect", "test-vpn", True)]
    assert plugin.state == S.STARTING

    plugin.set_config(GLib.Variant("a{sv}", {"tundev": GLib.Variant("s", "tun7"),
                                              "has-ip4": GLib.Variant("b", True),
                                              "has-ip6": GLib.Variant("b", False)}))
    assert plugin.state == S.STARTING
    plugin.set_ip4_config(GLib.Variant("a{sv}", {"prefix": GLib.Variant("u", 24)}))
    pump()
    assert plugin.state == S.STARTED
    ip4 = [v[0] for name, v in signals if name == "Ip4Config"][0]
    assert ip4["tundev"] == "tun7" and ip4["prefix"] == 24
    assert states(signals) == [S.STARTING, S.STARTED]
    (state,) = call(client, "Get", GLib.Variant("(ss)", (vpnplugin.IFACE, "State")),
                    iface="org.freedesktop.DBus.Properties")
    assert state == int(S.STARTED)


def test_need_secrets(env):
    plugin, client, _ = env
    assert call(client, "NeedSecrets", GLib.Variant.new_tuple(connection_variant())) == ("",)
    plugin.need = "vpn"
    assert call(client, "NeedSecrets", GLib.Variant.new_tuple(connection_variant())) == ("vpn",)


def test_failure_is_reported_once(env):
    plugin, client, signals = env
    call(client, "Connect", GLib.Variant.new_tuple(connection_variant()))
    plugin.failure(NM.VpnPluginFailure.LOGIN_FAILED)
    pump()
    failures = [v[0] for name, v in signals if name == "Failure"]
    assert failures == [int(NM.VpnPluginFailure.LOGIN_FAILED)]
    assert plugin.calls[-1] == ("disconnect",)
    assert states(signals) == [S.STARTING, S.STOPPING, S.STOPPED]


def test_disconnect_while_starting_reports_connect_failed(env):
    plugin, client, signals = env
    call(client, "Connect", GLib.Variant.new_tuple(connection_variant()))
    call(client, "Disconnect")
    assert [v[0] for name, v in signals if name == "Failure"] == [int(NM.VpnPluginFailure.CONNECT_FAILED)]
    assert plugin.state == S.STOPPED


def test_second_connect_is_rejected(env):
    plugin, client, _ = env
    args = GLib.Variant.new_tuple(connection_variant())
    call(client, "Connect", args)
    with pytest.raises(GLib.Error, match="WrongState"):
        call(client, "Connect", args)


def test_connect_error_returns_dbus_error(env):
    plugin, client, signals = env
    plugin.connect_error = vpnplugin.PluginError("BadArguments", "no profile")
    with pytest.raises(GLib.Error, match="BadArguments"):
        call(client, "Connect", GLib.Variant.new_tuple(connection_variant()))
    assert plugin.state == S.STOPPED


def test_secrets_round_trip(env):
    plugin, client, signals = env
    call(client, "ConnectInteractive", GLib.Variant.new_tuple(connection_variant(), GLib.Variant("a{sv}", {})))
    plugin.request_secrets("Enter PIN", ["challenge-response", "x-vpn-message:Enter PIN"])
    pump()
    assert ("SecretsRequired", ("Enter PIN", ["challenge-response", "x-vpn-message:Enter PIN"])) in signals
    call(client, "NewSecrets", GLib.Variant.new_tuple(connection_variant("pw")))
    assert plugin.calls[-1] == ("new_secrets", "pw")
