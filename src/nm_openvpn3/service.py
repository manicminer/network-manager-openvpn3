# SPDX-License-Identifier: GPL-2.0-or-later
"""NetworkManager VPN service plugin driving OpenVPN 3 Linux sessions."""

import logging
import urllib.parse

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from . import desktop, ipconfig, ovpn, pki  # noqa: E402
from . import openvpn3 as ov3  # noqa: E402
from . import profile_storage  # noqa: E402
from .vpnplugin import PluginError, VpnPlugin  # noqa: E402

log = logging.getLogger("nm-openvpn3")

SERVICE_NAME = "org.freedesktop.NetworkManager.openvpn3"

# The profile is base64: multi-line values do not survive every settings
# backend (netplan escapes newlines twice).  It lives either in the data items
# or, self-contained private key material and all, in the secrets; see
# profile_storage.
KEY_PROFILE = profile_storage.KEY_PROFILE
KEY_USERNAME = "username"
KEY_PASSWORD = "password"
KEY_CHALLENGE = "challenge-response"
KEY_CERT_PASS = "cert-pass"

HINT_CHALLENGE_ECHO = "x-challenge-echo"

get_profile = profile_storage.get_profile
_secret_flags = profile_storage.secret_flags


def _keep(new, old):
    """@new unless the connection did not carry the value at all."""
    return old if new is None else new


def require_profile(s_vpn):
    """The profile, or a D-Bus error saying why there is none."""
    config = get_profile(s_vpn)  # refuses an unknown profile-storage layout
    if config:
        return config
    if profile_storage.missing_reason(s_vpn) == profile_storage.LOCKED:
        raise PluginError("BadArguments", profile_storage.LOCKED_MESSAGE)
    raise PluginError("BadArguments", "The connection has no OpenVPN profile")


def _url_host(url):
    return urllib.parse.urlsplit(url).hostname or "?"


class Tunnel:
    """One openvpn3 session backing one NetworkManager activation."""

    def __init__(self, plugin, client, connection, interactive):
        self.plugin = plugin
        self.client = client
        self.interactive = interactive
        self.config_path = None
        self.session = None
        self.connect_started = False
        self.connected_once = False
        self.stopping = False
        self._last_status = None
        self._sub_ids = []
        self.config = None
        self.username = None
        self.password = None
        self.challenge = None
        self.cert_pass = None
        self.update_connection(connection)

    def update_connection(self, connection):
        """Takes over what the connection carries, keeping the rest.

        NewSecrets hands us whatever the agent has just produced -- a one-time
        code, a retried passphrase -- and nothing else.  Dropping the profile
        or the password at that point would tear down an activation that is
        halfway through authenticating.

        "Nothing else" means the key is *absent*, which is what is kept.  A
        key that is there and empty is an answer: the user cleared the
        password, and reusing the old one would authenticate with a credential
        they just removed.
        """
        s_vpn = connection.get_setting_vpn()
        self.name = connection.get_id()
        self.config = _keep(get_profile(s_vpn), self.config)
        self.username = _keep(s_vpn.get_data_item(KEY_USERNAME), self.username)
        self.password = _keep(s_vpn.get_secret(KEY_PASSWORD), self.password)
        self.cert_pass = _keep(s_vpn.get_secret(KEY_CERT_PASS), self.cert_pass)
        # A one-time code is consumed once (set to None again when used); only
        # a value the agent actually sent replaces it.
        self.challenge = _keep(s_vpn.get_secret(KEY_CHALLENGE), self.challenge)

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        try:
            profile = self._profile_for_openvpn3()
        except pki.WrongPassphrase:
            if not self.interactive:
                raise PluginError("BadArguments", "Wrong or missing passphrase for the PKCS#12 bundle")
            # Ask once Connect has returned; the session starts in new_secrets().
            GLib.idle_add(self._ask_cert_pass)
            return
        except pki.InvalidBundle as e:
            raise PluginError("BadArguments", str(e))
        self._start_session(profile)

    def _ask_cert_pass(self):
        self._ask([KEY_CERT_PASS], "Private key passphrase")
        return GLib.SOURCE_REMOVE

    def _profile_for_openvpn3(self):
        if pki.has_pkcs12(self.config):
            return pki.expand_pkcs12(self.config, self.cert_pass)
        return self.config

    def _start_session(self, profile):
        self.config_path = self.client.import_config(self.name, profile)
        # Subscribe before NewTunnel: early status changes must not be lost.
        # StatusChange reaches us through the log service once LogForward is
        # enabled; AttentionRequired is broadcast by the session manager.
        bus = self.client.bus
        for sender, iface, sig in ((ov3.LOG_SVC, ov3.BACKENDS_IF, "StatusChange"),
                                   (ov3.SESSIONS_SVC, ov3.SESSIONS_SVC, "StatusChange"),
                                   (ov3.SESSIONS_SVC, ov3.SESSIONS_SVC, "AttentionRequired")):
            self._sub_ids.append(bus.signal_subscribe(sender, iface, sig, None, None,
                                                      0, self._on_signal))
        self.session = self.client.new_tunnel(self.config_path)
        log.info("session %s created", self.session.path)
        self.session.log_forward(True)
        major, minor, msg = self.session.prop("status")
        self._on_status(major, minor, msg)

    def stop(self):
        if self.stopping:
            return
        self.stopping = True
        if self.session is not None:
            try:
                self.session.disconnect()
            except GLib.Error as e:
                # The session is already gone when the backend exited on its own.
                log.info("disconnect: %s", e.message)
        self._cleanup()

    def _cleanup(self):
        for sid in self._sub_ids:
            self.client.bus.signal_unsubscribe(sid)
        self._sub_ids.clear()

    # -- openvpn3 events ---------------------------------------------------

    def _on_signal(self, _conn, _sender, path, _iface, signal, params):
        if self.session is None or path != self.session.path:
            return
        try:
            if signal == "StatusChange":
                self._on_status(*params.unpack())
            elif signal == "AttentionRequired":
                t, g, _msg = params.unpack()
                log.info("attention required: type=%d group=%d", t, g)
        except Exception as e:
            # A GLib callback cannot propagate: fail the activation so the
            # user sees it instead of a connection stuck in "connecting".
            log.exception("handling %s failed", signal)
            self._fail(NM.VpnPluginFailure.CONNECT_FAILED, f"Internal error: {e}")

    def _on_status(self, major, minor, msg):
        # The same change can arrive twice: once from the session manager
        # and once forwarded by the log service.
        if (major, minor, msg) == self._last_status:
            return
        self._last_status = (major, minor, msg)
        is_url = major == ov3.MAJOR_SESSION and minor == ov3.SESS_AUTH_URL
        # The login URL carries a one-time token: keep it out of the journal.
        log.info("status %d/%d %s", major, minor, _url_host(msg) if is_url else msg)
        if self.stopping:
            return
        if is_url:
            self._open_login_url(msg)
        elif minor == ov3.CFG_OK and not self.connect_started:
            self._ready_and_connect()
        elif minor == ov3.CFG_REQUIRE_USER:
            self._provide_inputs()
        elif major == ov3.MAJOR_CONNECTION and minor == ov3.CONN_CONNECTED:
            self._report_connected()
        elif major == ov3.MAJOR_CONNECTION and minor == ov3.CONN_AUTH_FAILED:
            self._fail(NM.VpnPluginFailure.LOGIN_FAILED, msg or "Authentication failed")
        elif (major == ov3.MAJOR_CONNECTION
              and minor in (ov3.CONN_FAILED, ov3.CONN_DISCONNECTED, ov3.CONN_DONE)) \
                or (major == ov3.MAJOR_PROCESS and minor in (ov3.PROC_STOPPED, ov3.PROC_KILLED)) \
                or major == ov3.MAJOR_CFG_ERROR:
            self._fail(NM.VpnPluginFailure.CONNECT_FAILED, msg or "Connection failed")

    def _open_login_url(self, url):
        """Web based login: open the server's URL in the desktop user's browser."""
        if urllib.parse.urlsplit(url).scheme != "https":
            self._fail(NM.VpnPluginFailure.LOGIN_FAILED, "The server asked to open a non-https login URL")
            return
        try:
            user = desktop.open_url(url)
        except desktop.NoDesktopUser as e:
            self._fail(NM.VpnPluginFailure.LOGIN_FAILED, f"Web based login needs a browser: {e}")
            return
        log.info("opened the login page on %s for %s, waiting for the server", _url_host(url), user)

    def _ready_and_connect(self):
        try:
            self.session.ready()
        except GLib.Error as e:
            remote = e.message or ""
            if "Missing user credentials" in remote:
                self._provide_inputs()
                return
            if "not ready" in remote:
                # Backend still starting: CFG_OK or CFG_REQUIRE_USER follows.
                return
            raise
        self.connect_started = True
        log.info("backend ready, connecting")
        self.session.connect()

    def _provide_inputs(self):
        slots = self.session.pending_inputs()
        if not slots:
            # Nothing queued yet; openvpn3 announces it with CFG_REQUIRE_USER.
            return
        log.info("backend asks for %s", ", ".join(s[3] for s in slots))
        for t, g, i, name, description, hidden in slots:
            if t != ov3.ATTN_CREDENTIALS:
                self._fail(NM.VpnPluginFailure.LOGIN_FAILED,
                           f"Unsupported authentication request: {description}")
                return
            value = self._value_for(g, name, description, hidden)
            if value is None:
                return  # waiting for NetworkManager secrets
            self.session.provide(t, g, i, value)
        self.connect_started = False
        self._ready_and_connect()

    def _value_for(self, group, name, description, hidden):
        if group == ov3.GRP_USER_PASSWORD and name == "username":
            if self.username:
                return self.username
            self._fail(NM.VpnPluginFailure.LOGIN_FAILED, "No username configured")
            return None
        if group == ov3.GRP_USER_PASSWORD and name == "password":
            if self.password:
                return self.password
            return self._ask([KEY_PASSWORD], description)
        if group == ov3.GRP_PK_PASSPHRASE:
            if self.cert_pass:
                return self.cert_pass
            return self._ask([KEY_CERT_PASS], description)
        if group in (ov3.GRP_CHALLENGE_STATIC, ov3.GRP_CHALLENGE_DYNAMIC):
            if self.challenge:
                value, self.challenge = self.challenge, None
                return value
            hints = [KEY_CHALLENGE]
            if not hidden:
                hints.append(HINT_CHALLENGE_ECHO)
            return self._ask(hints, description)
        self._fail(NM.VpnPluginFailure.LOGIN_FAILED,
                   f"Unsupported authentication request: {description}")
        return None

    def _ask(self, hints, message):
        log.info("requesting secrets from NetworkManager: %s", ", ".join(hints))
        if not self.interactive:
            self._fail(NM.VpnPluginFailure.LOGIN_FAILED,
                       f"Interactive authentication required: {message}")
            return None
        # NetworkManager adds the message to the hints itself (x-vpn-message:).
        self.plugin.request_secrets(message, hints)
        return None

    def new_secrets(self, connection):
        self.update_connection(connection)
        if self.session is None:
            # Waiting for the PKCS#12 passphrase before any session exists.
            try:
                profile = self._profile_for_openvpn3()
            except pki.WrongPassphrase:
                self._fail(NM.VpnPluginFailure.LOGIN_FAILED, "Wrong passphrase for the PKCS#12 bundle")
                return
            self._start_session(profile)
            return
        self._provide_inputs()

    def _report_connected(self):
        device = self.session.prop("device_name")
        _proto, server, _port = self.session.prop("connected_to")
        dns, domains = self.client.netcfg_dns(device)
        if not dns and not ov3.netcfg_manages_dns():
            log.warning("openvpn3 does not manage DNS, pushed DNS servers are ignored; "
                        "enable it with: openvpn3-admin netcfg-service --config-set systemd-resolved 1")
        state = ipconfig.snapshot(device, dns, domains)
        log.info("connected on %s", device)
        self.plugin.set_config(ipconfig.general_config(state, server))
        if state.ip4.address:
            self.plugin.set_ip4_config(ipconfig.ip4_config(state))
        if state.ip6.address:
            self.plugin.set_ip6_config(ipconfig.ip6_config(state))
        self.connected_once = True

    def _fail(self, reason, message):
        log.warning("%s", message)
        if self.stopping:
            return
        # Both paths end in do_disconnect() -> stop(), which tears the session down.
        if self.connected_once:
            self.plugin.disconnect()
        else:
            self.plugin.failure(reason)


class Plugin(VpnPlugin):
    def __init__(self, bus_name, loop, client_factory=ov3.Client, **kwargs):
        super().__init__(bus_name, loop, **kwargs)
        self.client_factory = client_factory
        self.tunnel = None

    def do_connect(self, connection, interactive):
        s_vpn = connection.get_setting_vpn()
        profile_storage.profile_flags(s_vpn)  # rejects a profile nobody stores
        config = require_profile(s_vpn)
        if ovpn.needs_user_pass(config) and not s_vpn.get_data_item(KEY_USERNAME):
            raise PluginError("BadArguments", "The profile requires a username")
        self.tunnel = Tunnel(self, self.client_factory(), connection, interactive)
        self.tunnel.start()

    def do_need_secrets(self, connection):
        s_vpn = connection.get_setting_vpn()
        profile_storage.profile_flags(s_vpn)  # rejects a profile nobody stores
        config = get_profile(s_vpn) or ""
        if profile_storage.missing_reason(s_vpn) == profile_storage.LOCKED:
            # Which credentials are needed is a property of the profile, so
            # there is nothing sensible to ask for until we have it.
            return NM.SETTING_VPN_SETTING_NAME

        def missing(key):
            return not s_vpn.get_secret(key) \
                and not _secret_flags(s_vpn, key) & NM.SettingSecretFlags.NOT_REQUIRED

        if ovpn.needs_user_pass(config) and missing(KEY_PASSWORD):
            return NM.SETTING_VPN_SETTING_NAME
        if missing(KEY_CERT_PASS):
            try:
                if pki.needs_passphrase(config):
                    return NM.SETTING_VPN_SETTING_NAME
            except pki.InvalidBundle as e:
                raise PluginError("BadArguments", str(e))
        return None

    def do_new_secrets(self, connection):
        self.tunnel.new_secrets(connection)

    def do_disconnect(self):
        if self.tunnel is not None:
            self.tunnel.stop()
            self.tunnel = None
