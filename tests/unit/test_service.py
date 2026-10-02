# SPDX-License-Identifier: GPL-2.0-or-later
import base64

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from nm_openvpn3 import ipconfig, service  # noqa: E402
from nm_openvpn3 import openvpn3 as ov3  # noqa: E402
from nm_openvpn3 import profile_storage as ps  # noqa: E402

PROFILE = "client\ndev tun\nremote vpn.example.net 1194\nauth-user-pass\n"
CERT_PROFILE = "client\ndev tun\nremote vpn.example.net 1194\n"
SESSION_PATH = "/net/openvpn/v3/sessions/test0"


def make_connection(password="s3cret", username="testuser", config=PROFILE, cert_pass=None,
                    challenge=None, storage="data", profile_flags="1"):
    """A VPN connection.

    @storage picks the profile layout: "data" is the legacy public profile,
    "secret" the one where the whole profile is a NetworkManager secret; any
    other value is written as the profile-storage marker verbatim.
    @config None leaves the profile unavailable (in secret mode: locked).
    """
    con = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, "test-vpn")
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_VPN_SETTING_NAME)
    con.add_setting(s_con)
    s_vpn = NM.SettingVpn.new()
    s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, service.SERVICE_NAME)
    if storage != "data":
        s_vpn.add_data_item(ps.KEY_PROFILE_STORAGE, storage)
        if profile_flags is not None:
            s_vpn.add_data_item(ps.KEY_PROFILE_FLAGS, profile_flags)
        if config is not None:
            s_vpn.add_secret(ps.KEY_PROFILE, base64.b64encode(config.encode()).decode())
    elif config is not None:
        s_vpn.add_data_item(service.KEY_PROFILE, base64.b64encode(config.encode()).decode())
    if username:
        s_vpn.add_data_item(service.KEY_USERNAME, username)
    if password:
        s_vpn.add_secret(service.KEY_PASSWORD, password)
    if cert_pass:
        s_vpn.add_secret(service.KEY_CERT_PASS, cert_pass)
    if challenge:
        s_vpn.add_secret(service.KEY_CHALLENGE, challenge)
    con.add_setting(s_vpn)
    return con


def bare_plugin():
    """A Plugin without the D-Bus machinery; enough for the pure decisions."""
    plugin = service.Plugin.__new__(service.Plugin)
    plugin.client_factory = FakeClient
    plugin.tunnel = None
    return plugin


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


def test_web_auth_opens_browser_and_waits(monkeypatch):
    opened = []
    monkeypatch.setattr(service.desktop, "open_url", lambda url: opened.append(url) or "testuser")
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_SESSION, ov3.SESS_AUTH_URL, "https://vpn.example.net/auth?state=x")
    assert opened == ["https://vpn.example.net/auth?state=x"]
    assert plugin.events == []
    status(client, ov3.MAJOR_CONNECTION, ov3.CONN_CONNECTED)
    assert [e[0] for e in plugin.events] == ["config", "ip4"]


def test_web_auth_without_desktop_fails(monkeypatch):
    def no_user(url):
        raise service.desktop.NoDesktopUser("no active desktop session")
    monkeypatch.setattr(service.desktop, "open_url", no_user)
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_SESSION, ov3.SESS_AUTH_URL, "https://vpn.example.net/auth")
    assert plugin.events == [("failure", NM.VpnPluginFailure.LOGIN_FAILED)]


def test_web_auth_rejects_non_https(monkeypatch):
    monkeypatch.setattr(service.desktop, "open_url", lambda url: pytest.fail("must not open"))
    t, client, plugin = start(make_connection())
    status(client, ov3.MAJOR_SESSION, ov3.SESS_AUTH_URL, "file:///etc/shadow")
    assert plugin.events == [("failure", NM.VpnPluginFailure.LOGIN_FAILED)]


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


def test_portal_command_quotes_url():
    cmd = service.desktop.portal_command("https://vpn.example.net/start?state=a'b&x=1")
    arg = cmd[-2]
    assert GLib.Variant.parse(None, arg, None, None).unpack() == "https://vpn.example.net/start?state=a'b&x=1"
    assert cmd[cmd.index("--method") + 1] == "org.freedesktop.portal.OpenURI.OpenURI"


PK_SLOT = [(ov3.ATTN_CREDENTIALS, ov3.GRP_PK_PASSPHRASE, 2, "pk_passphrase", "Private key passphrase", True)]


def test_pkcs12_is_expanded_before_import():
    from pkihelp import p12
    from test_pki import profile_with
    data, _, _ = p12()
    t, client, plugin = start(make_connection(config=profile_with(data), password=None, cert_pass="p12pass"))
    (_, imported), = client.imported
    assert "<pkcs12>" not in imported and "BEGIN PRIVATE KEY" in imported


def test_pkcs12_wrong_passphrase_asks_then_starts(monkeypatch):
    from pkihelp import p12
    from test_pki import profile_with
    data, _, _ = p12()
    idle = []
    monkeypatch.setattr(service.GLib, "idle_add", lambda fn: idle.append(fn))
    t, client, plugin = start(make_connection(config=profile_with(data), password=None, cert_pass="wrong"),
                              interactive=True)
    assert client.imported == []
    idle[0]()
    assert plugin.events == [("secrets", "Private key passphrase", ["cert-pass"])]
    t.new_secrets(make_connection(config=profile_with(data), password=None, cert_pass="p12pass"))
    assert len(client.imported) == 1


def test_pkcs12_wrong_passphrase_noninteractive_is_an_error():
    from pkihelp import p12
    from test_pki import profile_with
    data, _, _ = p12()
    with pytest.raises(service.PluginError):
        start(make_connection(config=profile_with(data), password=None, cert_pass="wrong"))


def test_pk_passphrase_slot_is_answered():
    t, client, plugin = start(make_connection(cert_pass="keypass"))
    client.session.inputs = list(USERPASS) + PK_SLOT
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert client.session.provided == {0: "testuser", 1: "s3cret", 2: "keypass"}


# -- the profile as a NetworkManager secret -----------------------------------


def test_connect_uses_the_secret_profile():
    t, client, plugin = start(make_connection(storage="secret"))
    assert client.imported == [("test-vpn", PROFILE)]


def test_connect_without_the_secret_profile_fails_closed():
    plugin = bare_plugin()
    with pytest.raises(service.PluginError) as e:
        plugin.do_connect(make_connection(config=None, storage="secret"), interactive=False)
    assert "secret" in str(e.value)
    assert plugin.tunnel is None


def test_connect_without_any_profile_still_reports_the_old_error():
    plugin = bare_plugin()
    with pytest.raises(service.PluginError, match="no OpenVPN profile"):
        plugin.do_connect(make_connection(config=None), interactive=False)


def test_connect_rejects_a_profile_that_is_never_stored():
    plugin = bare_plugin()
    with pytest.raises(service.PluginError):
        plugin.do_connect(make_connection(storage="secret", profile_flags="2"), interactive=False)


def test_need_secrets_asks_for_the_locked_profile_first():
    # Everything else is already there and the profile would not even need a
    # password: the profile is still what is missing.
    con = make_connection(config=None, storage="secret", password="s3cret")
    assert bare_plugin().do_need_secrets(con) == NM.SETTING_VPN_SETTING_NAME


def test_need_secrets_then_uses_the_reconstructed_profile():
    plugin = bare_plugin()
    assert plugin.do_need_secrets(make_connection(storage="secret")) is None
    assert plugin.do_need_secrets(
        make_connection(storage="secret", password=None)) == NM.SETTING_VPN_SETTING_NAME
    assert plugin.do_need_secrets(
        make_connection(storage="secret", config=CERT_PROFILE, password=None)) is None


def test_need_secrets_is_unchanged_for_legacy_profiles():
    plugin = bare_plugin()
    assert plugin.do_need_secrets(make_connection()) is None
    assert plugin.do_need_secrets(make_connection(password=None)) == NM.SETTING_VPN_SETTING_NAME


def test_need_secrets_reports_a_corrupt_secret_profile():
    con = make_connection(storage="secret")
    con.get_setting_vpn().add_secret(ps.KEY_PROFILE, "@@ not base64 @@")
    with pytest.raises(service.PluginError, match="corrupt"):
        bare_plugin().do_need_secrets(con)


def test_challenge_round_trip_keeps_the_secret_profile():
    t, client, plugin = start(make_connection(storage="secret"), interactive=True)
    client.session.inputs = list(USERPASS) + [
        (ov3.ATTN_CREDENTIALS, ov3.GRP_CHALLENGE_DYNAMIC, 2, "dynamic_challenge", "Enter PIN", False)]
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert [e for e in plugin.events if e[0] == "secrets"]

    # NetworkManager hands back only what the agent just produced.
    only_challenge = make_connection(config=None, storage="secret", password=None,
                                     username=None, challenge="123456")
    t.new_secrets(only_challenge)
    assert t.config == PROFILE
    assert client.session.provided == {0: "testuser", 1: "s3cret", 2: "123456"}


def test_a_later_secrets_round_does_not_blank_the_legacy_profile():
    t, client, plugin = start(make_connection(), interactive=True)
    t.new_secrets(make_connection(config=None, password=None, username=None, challenge="1"))
    assert t.config == PROFILE
    assert t.username == "testuser"
    assert t.password == "s3cret"


# -- a storage layout this version does not know ------------------------------


def test_connect_refuses_an_unknown_profile_storage():
    con = make_connection(storage="v2-whatever", profile_flags=None)
    # A leftover public copy from before the connection moved: using it would
    # connect with a stale profile.
    con.get_setting_vpn().add_data_item(service.KEY_PROFILE,
                                        base64.b64encode(b"client\nremote stale 1\n").decode())
    plugin = bare_plugin()
    with pytest.raises(service.PluginError) as e:
        plugin.do_connect(con, interactive=False)
    assert "v2-whatever" in str(e.value)
    assert plugin.tunnel is None


def test_need_secrets_refuses_an_unknown_profile_storage():
    con = make_connection(storage="v2-whatever", profile_flags=None)
    with pytest.raises(service.PluginError, match="v2-whatever"):
        bare_plugin().do_need_secrets(con)


def test_need_secrets_reports_bad_secret_flags_instead_of_crashing():
    # An unguarded int() here would leave the D-Bus call without a reply.
    con = make_connection(password=None)
    con.get_setting_vpn().add_data_item("password-flags", "nonsense")
    with pytest.raises(service.PluginError) as e:
        bare_plugin().do_need_secrets(con)
    assert e.value.name == "BadArguments"


# -- what a later secrets round may and may not overwrite ---------------------


def test_an_explicitly_empty_credential_is_not_the_old_one():
    # The user cleared the password; "keep the previous value unless a new one
    # arrives" must mean "unless the key is absent", not "unless it is empty".
    t, client, plugin = start(make_connection(), interactive=True)
    con = make_connection(password=None, username=None, config=None)
    con.get_setting_vpn().add_secret(service.KEY_PASSWORD, "")
    t.new_secrets(con)
    assert t.password == ""
    assert t.config == PROFILE
    assert t.username == "testuser"


def test_an_absent_credential_keeps_the_previous_one():
    t, client, plugin = start(make_connection(cert_pass="keypass"), interactive=True)
    t.new_secrets(make_connection(config=None, password=None, username=None))
    assert t.password == "s3cret"
    assert t.cert_pass == "keypass"


def test_a_consumed_one_time_code_is_not_replayed():
    t, client, plugin = start(make_connection(challenge="123456"), interactive=True)
    client.session.inputs = list(USERPASS) + [
        (ov3.ATTN_CREDENTIALS, ov3.GRP_CHALLENGE_DYNAMIC, 2, "dynamic_challenge", "Enter PIN", False)]
    client.session.need_creds = True
    status(client, ov3.MAJOR_CONNECTION, ov3.CFG_REQUIRE_USER)
    assert client.session.provided[2] == "123456"
    assert t.challenge is None

    # A second round of secrets without a fresh code must not reuse the old
    # one: the server has already seen it.
    client.session.provided.pop(2)
    t.new_secrets(make_connection(config=None, password=None, username=None))
    assert t.challenge is None
    assert 2 not in client.session.provided
    assert [e for e in plugin.events if e[0] == "secrets"]


# -- profiles that keep their remote in a <connection> block ------------------

BLOCK_PROFILE = ("client\n<connection>\nremote vpn.example.net 1194 udp\n"
                 "auth-user-pass\n</connection>\n")


def test_connect_handles_a_profile_whose_options_are_in_a_connection_block():
    t, client, plugin = start(make_connection(config=BLOCK_PROFILE))
    assert client.imported == [("test-vpn", BLOCK_PROFILE)]


def test_a_username_is_still_required_when_auth_is_in_a_connection_block():
    plugin = bare_plugin()
    with pytest.raises(service.PluginError, match="username"):
        plugin.do_connect(make_connection(config=BLOCK_PROFILE, username=None), interactive=False)


def test_need_secrets_sees_auth_user_pass_in_a_connection_block():
    plugin = bare_plugin()
    assert plugin.do_need_secrets(
        make_connection(config=BLOCK_PROFILE, password=None)) == NM.SETTING_VPN_SETTING_NAME
    assert plugin.do_need_secrets(make_connection(config=BLOCK_PROFILE)) is None


def test_an_explicitly_empty_one_time_code_is_not_the_old_one():
    t, client, plugin = start(make_connection(challenge="123456"), interactive=True)
    con = make_connection(config=None, password=None, username=None)
    con.get_setting_vpn().add_secret(service.KEY_CHALLENGE, "")
    t.new_secrets(con)
    assert t.challenge == ""
