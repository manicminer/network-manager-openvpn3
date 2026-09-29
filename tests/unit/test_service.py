# SPDX-License-Identifier: GPL-2.0-or-later
import base64

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from nm_openvpn3 import ipconfig, service  # noqa: E402
from nm_openvpn3 import openvpn3 as ov3  # noqa: E402

PROFILE = "client\ndev tun\nremote vpn.example.net 1194\nauth-user-pass\n"
SESSION_PATH = "/net/openvpn/v3/sessions/test0"


def make_connection(password="s3cret", username="testuser", config=PROFILE):
    con = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, "test-vpn")
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_VPN_SETTING_NAME)
    con.add_setting(s_con)
    s_vpn = NM.SettingVpn.new()
    s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, service.SERVICE_NAME)
    s_vpn.add_data_item(service.KEY_PROFILE, base64.b64encode(config.encode()).decode())
    if username:
        s_vpn.add_data_item(service.KEY_USERNAME, username)
    if password:
        s_vpn.add_secret(service.KEY_PASSWORD, password)
    con.add_setting(s_vpn)
    return con


class FakeBus:
    def __init__(self):
        self.handlers = {}

    def signal_subscribe(self, _svc, _iface, member, _path, _arg0, _flags, cb):
        sid = len(self.handlers) + 1
        self.handlers[sid] = (member, cb)
        return sid

    def signal_unsubscribe(self, sid):
        del self.handlers[sid]

    def emit(self, member, path, params):
        for m, cb in list(self.handlers.values()):
            if m == member:
                cb(None, None, path, None, member, params)


class FakeSession:
    def __init__(self, client):
        self.client = client
        self.path = SESSION_PATH
        self.calls = []
        self.inputs = []
        self.provided = {}
        self.need_creds = False

    def prop(self, name):
        return {"status": (ov3.MAJOR_SESSION, ov3.SESS_NEW, ""),
                "device_name": "tun7",
                "connected_to": ("tcp", "203.0.113.10", 1194)}[name]

    def log_forward(self, enable):
        pass

    def ready(self):
        self.calls.append("ready")
        if self.need_creds and len(self.provided) < len(self.inputs):
            raise GLib.Error.new_literal(GLib.quark_from_string("test"),
                                         "net.openvpn.v3.error.ready: Missing user credentials", 1)

    def connect(self):
        self.calls.append("connect")

    def disconnect(self):
        self.calls.append("disconnect")

    def pending_inputs(self):
        return [s for s in self.inputs if s[2] not in self.provided]

    def provide(self, t, g, i, value):
        self.provided[i] = value


class FakeClient:
    def __init__(self):
        self.bus = FakeBus()
        self.session = FakeSession(self)
        self.imported = []

    def import_config(self, name, text):
        self.imported.append((name, text))
        return "/net/openvpn/v3/configuration/cfg0"

    def new_tunnel(self, _path):
        return self.session

    def netcfg_dns(self, _device):
        return ["192.0.2.53"], ["corp.example.com"]


class FakePlugin:
    """Mirrors VpnPlugin: failure() and disconnect() end in the tunnel's stop()."""

    def __init__(self):
        self.events = []
        self.tunnel = None

    def set_config(self, v):
        self.events.append(("config", v.unpack()))

    def set_ip4_config(self, v):
        self.events.append(("ip4", v.unpack()))

    def set_ip6_config(self, v):
        self.events.append(("ip6", v.unpack()))

    def failure(self, reason):
        self.events.append(("failure", reason))
        self.tunnel.stop()

    def disconnect(self):
        self.events.append(("disconnect",))
        self.tunnel.stop()

    def request_secrets(self, message, hints):
        self.events.append(("secrets", message, hints))


@pytest.fixture(autouse=True)
def fake_snapshot(monkeypatch):
    def snap(device, dns, domains):
        return ipconfig.TunnelState(
            device, 1400,
            ipconfig.FamilyConfig("198.51.100.6", 24, [], False, dns),
            ipconfig.FamilyConfig(), domains)
    monkeypatch.setattr(ipconfig, "snapshot", snap)


def start(con, interactive=False):
    client, plugin = FakeClient(), FakePlugin()
    t = service.Tunnel(plugin, client, con, interactive)
    plugin.tunnel = t
    t.start()
    return t, client, plugin


def status(client, major, minor, msg=""):
    client.bus.emit("StatusChange", SESSION_PATH, GLib.Variant("(uus)", (major, minor, msg)))


USERPASS = [(ov3.ATTN_CREDENTIALS, ov3.GRP_USER_PASSWORD, 0, "username", "Auth User name", False),
            (ov3.ATTN_CREDENTIALS, ov3.GRP_USER_PASSWORD, 1, "password", "Auth Password", True)]


def test_connect_flow_reports_config():
    t, client, plugin = start(make_connection())
    assert client.imported == [("test-vpn", PROFILE)]
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_OK)
    assert client.session.calls == ["ready", "connect"]
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_CONNECTED)
    kinds = [e[0] for e in plugin.events]
    assert kinds == ["config", "ip4"]
    assert plugin.events[0][1]["tundev"] == "tun7"
    assert plugin.events[1][1]["domains"] == ["corp.example.com"]


def test_credentials_are_provided():
    t, client, plugin = start(make_connection())
    client.session.inputs = list(USERPASS)
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert client.session.provided == {0: "testuser", 1: "s3cret"}
    assert client.session.calls[-1] == "connect"


def test_missing_password_noninteractive_fails():
    t, client, plugin = start(make_connection(password=None))
    client.session.inputs = list(USERPASS)
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert ("failure", NM.VpnPluginFailure.LOGIN_FAILED) in plugin.events
    assert "disconnect" in client.session.calls


def test_challenge_asks_nm_then_continues():
    t, client, plugin = start(make_connection(), interactive=True)
    client.session.inputs = list(USERPASS) + [
        (ov3.ATTN_CREDENTIALS, ov3.GRP_CHALLENGE_DYNAMIC, 2, "dynamic_challenge", "Enter PIN", False)]
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    secrets = [e for e in plugin.events if e[0] == "secrets"]
    assert secrets == [("secrets", "Enter PIN", ["challenge-response", "x-challenge-echo"])]
    assert "connect" not in client.session.calls

    con = make_connection()
    con.get_setting_vpn().add_secret(service.KEY_CHALLENGE, "123456")
    t.new_secrets(con)
    assert client.session.provided[2] == "123456"
    assert client.session.calls[-1] == "connect"


def test_auth_failed_reports_login_failure():
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_OK)
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_AUTH_FAILED, "bad password")
    assert plugin.events == [("failure", NM.VpnPluginFailure.LOGIN_FAILED)]
    assert client.bus.handlers == {}
    assert client.session.calls[-1] == "disconnect"


def test_drop_after_connect_only_disconnects():
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_OK)
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_CONNECTED)
    plugin.events.clear()
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_FAILED)
    assert plugin.events == [("disconnect",)]


def test_reconnect_resends_config():
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_OK)
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_CONNECTED)
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_RECONNECTING)
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_CONNECTED)
    assert [e[0] for e in plugin.events] == ["config", "ip4", "config", "ip4"]


def test_web_auth_is_rejected():
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_SESSION, ov3.SESS_AUTH_URL, "https://vpn.example.net/auth")
    assert plugin.events[0] == ("failure", NM.VpnPluginFailure.LOGIN_FAILED)


def test_signals_for_other_sessions_are_ignored():
    t, client, plugin = start(make_connection())
    client.bus.emit("StatusChange", "/net/openvpn/v3/sessions/other",
                    GLib.Variant("(uus)", (ov3.MAJOR_CONNECTION, ov3.CONN_AUTH_FAILED, "")))
    assert plugin.events == []


def test_stop_disconnects_and_unsubscribes():
    t, client, plugin = start(make_connection())
    t.stop()
    assert client.session.calls == ["disconnect"]
    assert client.bus.handlers == {}
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_DISCONNECTED)
    assert plugin.events == []


def test_duplicate_status_is_handled_once():
    t, client, plugin = start(make_connection())
    client.session.inputs = list(USERPASS)
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert client.session.calls.count("connect") == 1


def test_missing_credentials_without_queued_inputs_waits():
    t, client, plugin = start(make_connection())
    client.session.need_creds = True
    client.session.inputs = list(USERPASS)
    client.session.provided = {}
    # Ready() reports missing credentials but nothing is queued yet.
    client.session.pending_inputs = lambda: []
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_OK)
    assert client.session.calls == ["ready"]
    assert plugin.events == []
