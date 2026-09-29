# SPDX-License-Identifier: GPL-2.0-or-later
"""The org.freedesktop.NetworkManager.VPN.Plugin D-Bus service.

libnm's NMVpnServicePlugin cannot be subclassed from Python correctly: the
GIR data for its need_secrets vfunc and secrets_required() mistypes string
array/out arguments. This module implements the same small D-Bus contract
directly with Gio and follows libnm's state handling.
"""

import logging

import gi

gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

log = logging.getLogger("nm-openvpn3")

PATH = "/org/freedesktop/NetworkManager/VPN/Plugin"
IFACE = "org.freedesktop.NetworkManager.VPN.Plugin"
ERROR_PREFIX = "org.freedesktop.NetworkManager.VPN.Error."
NM_BUS_NAME = "org.freedesktop.NetworkManager"

QUIT_TIMEOUT_S = 180

INTROSPECTION = f"""
<node>
  <interface name="{IFACE}">
    <method name="Connect"><arg name="connection" type="a{{sa{{sv}}}}" direction="in"/></method>
    <method name="ConnectInteractive">
      <arg name="connection" type="a{{sa{{sv}}}}" direction="in"/>
      <arg name="details" type="a{{sv}}" direction="in"/>
    </method>
    <method name="NeedSecrets">
      <arg name="settings" type="a{{sa{{sv}}}}" direction="in"/>
      <arg name="setting_name" type="s" direction="out"/>
    </method>
    <method name="Disconnect"/>
    <method name="NewSecrets"><arg name="connection" type="a{{sa{{sv}}}}" direction="in"/></method>
    <property name="State" type="u" access="read"/>
    <signal name="StateChanged"><arg name="state" type="u"/></signal>
    <signal name="SecretsRequired"><arg name="message" type="s"/><arg name="secrets" type="as"/></signal>
    <signal name="Config"><arg name="config" type="a{{sv}}"/></signal>
    <signal name="Ip4Config"><arg name="ip4config" type="a{{sv}}"/></signal>
    <signal name="Ip6Config"><arg name="ip6config" type="a{{sv}}"/></signal>
    <signal name="LoginBanner"><arg name="banner" type="s"/></signal>
    <signal name="Failure"><arg name="reason" type="u"/></signal>
  </interface>
</node>
"""

# Keys libnm copies from Config into Ip4Config for older daemons.
_COMPAT_KEYS = ("banner", "tundev", "gateway", "mtu")


class PluginError(Exception):
    """Reported to NetworkManager as org.freedesktop.NetworkManager.VPN.Error.<name>."""

    def __init__(self, name, message):
        super().__init__(message)
        self.name = name


class VpnPlugin:
    """Subclasses implement do_connect, do_need_secrets, do_new_secrets, do_disconnect."""

    def __init__(self, bus_name, loop, bus=None, watch_peer=True):
        self.bus = bus or Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.loop = loop
        self.state = NM.VpnServiceState.INIT
        self._config = None
        self._got_ip4 = self._got_ip6 = False
        self._quit_id = 0
        self._watch_id = 0
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        # GLib >= 2.84 has register_object_with_closures2; the older call is
        # deprecated there but the only one on older releases.
        register = getattr(self.bus, "register_object_with_closures2", None) or self.bus.register_object
        self._reg_id = register(PATH, node.interfaces[0], self._on_call, self._on_get_property, None)
        Gio.bus_own_name_on_connection(self.bus, bus_name, Gio.BusNameOwnerFlags.DO_NOT_QUEUE,
                                       None, self._on_name_lost)
        if watch_peer:
            self._watch_id = Gio.bus_watch_name_on_connection(
                self.bus, NM_BUS_NAME, Gio.BusNameWatcherFlags.NONE, None, self._on_nm_vanished)
        self._schedule_quit()

    # -- process lifetime --------------------------------------------------

    def _on_name_lost(self, _conn, name):
        log.error("could not own bus name %s", name)
        self.loop.quit()

    def _on_nm_vanished(self, _conn, _name):
        log.info("NetworkManager left the bus, exiting")
        if self.state in (NM.VpnServiceState.STARTING, NM.VpnServiceState.STARTED):
            self.disconnect()
        self.loop.quit()

    def _schedule_quit(self):
        self._cancel_quit()
        self._quit_id = GLib.timeout_add_seconds(QUIT_TIMEOUT_S, self._quit_idle)

    def _cancel_quit(self):
        if self._quit_id:
            GLib.source_remove(self._quit_id)
            self._quit_id = 0

    def _quit_idle(self):
        self._quit_id = 0
        log.info("idle, exiting")
        self.loop.quit()
        return GLib.SOURCE_REMOVE

    # -- state -------------------------------------------------------------

    def _set_state(self, state):
        if state == self.state:
            return
        self.state = state
        self._emit("StateChanged", GLib.Variant("u", int(state)))
        if state == NM.VpnServiceState.STARTING:
            self._cancel_quit()
        elif state == NM.VpnServiceState.STOPPED:
            # Same as libnm with a watched peer: one process per activation.
            GLib.idle_add(self._quit_idle)

    def _emit(self, signal, *args):
        """Emits a signal; args are GLib.Variant values."""
        self.bus.emit_signal(None, PATH, IFACE, signal, GLib.Variant.new_tuple(*args))

    def _maybe_started(self):
        cfg = self._config.unpack() if self._config is not None else {}
        want4 = cfg.get("has-ip4", self._got_ip4)
        want6 = cfg.get("has-ip6", False)
        if want4 == self._got_ip4 and want6 == self._got_ip6:
            self._set_state(NM.VpnServiceState.STARTED)

    # -- API used by the implementation --------------------------------------

    def set_config(self, config):
        self._config = config
        self._got_ip4 = self._got_ip6 = False
        self._emit("Config", config)
        self._maybe_started()

    def set_ip4_config(self, ip4):
        self._got_ip4 = True
        merged = {k: ip4.lookup_value(k, None) for k in ip4.keys()}
        if self._config is not None:
            for key in _COMPAT_KEYS:
                value = self._config.lookup_value(key, None)
                if value is not None and key not in merged:
                    merged[key] = value
        self._emit("Ip4Config", GLib.Variant("a{sv}", merged))
        self._maybe_started()

    def set_ip6_config(self, ip6):
        self._got_ip6 = True
        self._emit("Ip6Config", ip6)
        self._maybe_started()

    def request_secrets(self, message, hints):
        self._emit("SecretsRequired", GLib.Variant("s", message), GLib.Variant("as", list(hints)))

    def failure(self, reason):
        """Reports why the connection failed and stops it."""
        if self.state in (NM.VpnServiceState.STOPPING, NM.VpnServiceState.STOPPED):
            return
        self._emit("Failure", GLib.Variant("u", int(reason)))
        self._stop()

    def disconnect(self):
        if self.state in (NM.VpnServiceState.STOPPING, NM.VpnServiceState.STOPPED):
            return
        if self.state == NM.VpnServiceState.STARTING:
            self._emit("Failure", GLib.Variant("u", int(NM.VpnPluginFailure.CONNECT_FAILED)))
        self._stop()

    def _stop(self):
        self._set_state(NM.VpnServiceState.STOPPING)
        self.do_disconnect()
        self._set_state(NM.VpnServiceState.STOPPED)

    # -- D-Bus -------------------------------------------------------------

    def _on_get_property(self, _conn, _sender, _path, _iface, name):
        if name == "State":
            return GLib.Variant("u", int(self.state))
        return None

    def _on_call(self, _conn, _sender, _path, _iface, method, params, invocation):
        try:
            result = self._dispatch(method, params)
        except PluginError as e:
            invocation.return_dbus_error(ERROR_PREFIX + e.name, str(e))
            return
        except GLib.Error as e:
            invocation.return_dbus_error(ERROR_PREFIX + "Failed", e.message)
            return
        invocation.return_value(result)

    @staticmethod
    def _connection(variant):
        try:
            return NM.SimpleConnection.new_from_dbus(variant)
        except GLib.Error as e:
            raise PluginError("BadArguments", f"Invalid connection: {e.message}")

    def _dispatch(self, method, params):
        if method in ("Connect", "ConnectInteractive"):
            if self.state not in (NM.VpnServiceState.INIT, NM.VpnServiceState.STOPPED):
                raise PluginError("WrongState", "A connection is already active")
            connection = self._connection(params.get_child_value(0))
            self._got_ip4 = self._got_ip6 = False
            self._config = None
            self._set_state(NM.VpnServiceState.STARTING)
            try:
                self.do_connect(connection, interactive=(method == "ConnectInteractive"))
            except (PluginError, GLib.Error) as e:
                log.warning("connect failed: %s", e)
                self._set_state(NM.VpnServiceState.STOPPED)
                raise
            return None
        if method == "NeedSecrets":
            setting = self.do_need_secrets(self._connection(params.get_child_value(0)))
            if setting:
                self._schedule_quit()
            return GLib.Variant("(s)", (setting or "",))
        if method == "NewSecrets":
            if self.state != NM.VpnServiceState.STARTING:
                raise PluginError("WrongState", "No connection in progress")
            self.do_new_secrets(self._connection(params.get_child_value(0)))
            return None
        if method == "Disconnect":
            if self.state in (NM.VpnServiceState.STOPPING, NM.VpnServiceState.STOPPED):
                raise PluginError("WrongState", "No VPN connection is active")
            self.disconnect()
            return None
        raise PluginError("Failed", f"Unknown method {method}")
