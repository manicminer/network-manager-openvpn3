# SPDX-License-Identifier: GPL-2.0-or-later
"""Where the OpenVPN profile of a connection is stored.

A profile is self-contained: every certificate, private key and shared TLS key
the connection needs is inlined into it.  Keeping that in ``vpn.data`` puts
private key material into ordinary connection data: the keyfile itself is
root-owned and 0600, but NetworkManager hands connection data to every client
allowed to read the connection's settings over D-Bus, and it is kept in
whatever backend the distribution uses.  Secrets are gated instead -- they are
only given out to the owning agent or on an explicit request for them.  So a
connection may hand the whole profile to NetworkManager as a *secret*; the
secret agent then stores it wherever it stores secrets (KWallet for Plasma, the
keyring for GNOME), or NetworkManager owns it itself for unattended activation.

Two layouts exist and they are mutually exclusive:

===========  =================================================  =================
mode         ``vpn.data``                                       ``vpn.secrets``
===========  =================================================  =================
legacy       ``profile`` = base64 profile                       --
secret       ``profile-storage`` = ``secret``,                  ``profile`` =
             ``profile-flags`` = ``1`` (agent/wallet) or        base64 profile
             ``0`` (NetworkManager-owned, unattended)
===========  =================================================  =================

``profile-flags`` is not a private invention: NetworkManager keeps the secret
flags of a VPN secret ``x`` in ``vpn.data["x-flags"]``, so the marker is simply
the standard flags key of the ``profile`` secret.  Absent flags therefore mean
what they mean to NetworkManager -- ``NONE``, system-owned -- and a writer that
wants the wallet says so explicitly.

Properties this buys:

* Unknown sensitive directives are protected too -- there is no whitelist of
  "interesting" keys to get wrong, and no reassembly step that could drop one.
* ``profile-storage`` makes "the profile is locked or the agent is gone"
  distinguishable from "this connection has no profile".
* In secret mode the public copy is *removed*, so no stale plaintext profile
  can be used by accident, and a plugin that predates this module simply finds
  no profile and fails closed.
* A ``profile-storage`` value this version does not know is refused outright:
  the data item that goes with it is a leftover of whatever layout the
  connection used before, so reading it would connect with a stale profile.
* A profile is never written back to ``vpn.data`` as a fallback.
"""

import base64
import binascii

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from .vpnplugin import PluginError  # noqa: E402

KEY_PROFILE = "profile"
KEY_PROFILE_STORAGE = "profile-storage"
KEY_PROFILE_FLAGS = KEY_PROFILE + "-flags"

STORAGE_SECRET = "secret"

# The only two flags a profile can carry: it must be retrievable on activation.
# NOT_SAVED and NOT_REQUIRED would describe a profile nobody can reconstruct.
STORABLE_FLAGS = (NM.SettingSecretFlags.NONE, NM.SettingSecretFlags.AGENT_OWNED)

# Every flag NetworkManager defines; anything else is not a flags value.
_FLAGS_MASK = int(NM.SettingSecretFlags.AGENT_OWNED
                  | NM.SettingSecretFlags.NOT_SAVED
                  | NM.SettingSecretFlags.NOT_REQUIRED)

# missing_reason()/stored_profile() answers.
LOCKED = "locked"
ABSENT = "absent"
UNSUPPORTED = "unsupported"

LOCKED_MESSAGE = ("The OpenVPN profile of this connection is stored as a secret "
                  "and was not provided")


def encode(text):
    """Profile text -> the stored representation.

    Base64 because multi-line values do not survive every settings backend
    (netplan escapes newlines twice).
    """
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode(value):
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise PluginError("BadArguments", "The stored OpenVPN profile is corrupt")


def unsupported_message(marker):
    return (f"The connection stores its OpenVPN profile in a layout this version "
            f"does not know ({KEY_PROFILE_STORAGE}={marker})")


def stored_profile(get_data, get_secret):
    """The stored (still base64) profile and why there is none.

    @get_data and @get_secret look a key up in the connection's data items and
    secrets.  This is the one place that decides which layout a connection
    uses; the auth dialog shares it by passing the ``dict.get`` of the maps
    NetworkManager wrote to its stdin.

    Returns ``(value, None)`` or ``(None, reason)``, reason being LOCKED,
    ABSENT or UNSUPPORTED.
    """
    marker = get_data(KEY_PROFILE_STORAGE) or ""
    if marker and marker != STORAGE_SECRET:
        return None, UNSUPPORTED
    # In secret mode, deliberately not falling back to the data item: a
    # profile left there by an older version of this connection is stale.
    value = (get_secret(KEY_PROFILE) if marker else get_data(KEY_PROFILE)) or None
    if value:
        return value, None
    return None, LOCKED if marker else ABSENT


def is_secret_mode(s_vpn):
    return bool(s_vpn) and s_vpn.get_data_item(KEY_PROFILE_STORAGE) == STORAGE_SECRET


def _stored(s_vpn):
    if not s_vpn:
        return None, ABSENT
    return stored_profile(s_vpn.get_data_item, s_vpn.get_secret)


def _reject_unsupported(s_vpn):
    if s_vpn and _stored(s_vpn)[1] == UNSUPPORTED:
        raise PluginError("BadArguments",
                          unsupported_message(s_vpn.get_data_item(KEY_PROFILE_STORAGE)))


def get_profile(s_vpn):
    """The profile text, or None when it is not available right now."""
    stored, reason = _stored(s_vpn)
    if reason == UNSUPPORTED:
        raise PluginError("BadArguments",
                          unsupported_message(s_vpn.get_data_item(KEY_PROFILE_STORAGE)))
    return decode(stored) if stored else None


def missing_reason(s_vpn):
    """None when the profile is there, else LOCKED, ABSENT or UNSUPPORTED.

    LOCKED means the connection does have a profile but the secret has not
    been handed to us -- the agent is not running, the wallet is closed, or
    NetworkManager did not ask for secrets yet.
    """
    return _stored(s_vpn)[1]


def parse_flags(value, key):
    """@value as secret flags, or a D-Bus error naming @key.

    Reached from the NeedSecrets handler, so it must not raise anything
    NetworkManager would see as a missing reply.  NM.SettingSecretFlags() does
    not reject out of range numbers (it turns -1 into every flag), hence the
    explicit mask.
    """
    try:
        number = int(value)
    except ValueError:
        number = -1
    if not 0 <= number <= _FLAGS_MASK:
        # The value itself is a data item, never the secret it describes.
        raise PluginError("BadArguments", f"The connection has an invalid {key}-flags value")
    return NM.SettingSecretFlags(number)


def profile_flags(s_vpn):
    """Secret flags of the profile; NONE for a legacy public profile."""
    _reject_unsupported(s_vpn)
    if not is_secret_mode(s_vpn):
        return NM.SettingSecretFlags.NONE
    value = s_vpn.get_data_item(KEY_PROFILE_FLAGS)
    if value is None:
        # NetworkManager reads a secret without flags as NONE, system-owned.
        # Guessing AGENT_OWNED here would hand an unattended connection's
        # profile to the user's wallet the next time anything saved it.
        return NM.SettingSecretFlags.NONE
    flags = parse_flags(value, KEY_PROFILE)
    if flags not in STORABLE_FLAGS:
        raise PluginError("BadArguments",
                          f"The OpenVPN profile is marked {KEY_PROFILE_FLAGS}={value}, "
                          "which would never store it")
    return flags


def secret_flags(s_vpn, key):
    """Flags of any VPN secret.

    NM.Setting.get_secret_flags() is not callable from Python (the out argument
    lacks an annotation); VPN secret flags live in the data items.
    """
    value = s_vpn.get_data_item(key + "-flags") if s_vpn else None
    return parse_flags(value, key) if value else NM.SettingSecretFlags.NONE


def set_profile(s_vpn, text, flags=NM.SettingSecretFlags.AGENT_OWNED):
    """Stores @text in @s_vpn, switching layout as needed.

    @flags None selects the legacy public layout; otherwise the secret layout
    with those flags.  Leaves no copy behind in the layout it did not pick.
    """
    if flags is None:
        s_vpn.remove_secret(KEY_PROFILE)
        s_vpn.remove_data_item(KEY_PROFILE_STORAGE)
        s_vpn.remove_data_item(KEY_PROFILE_FLAGS)
        s_vpn.add_data_item(KEY_PROFILE, encode(text))
        return
    flags = NM.SettingSecretFlags(int(flags))
    if flags not in STORABLE_FLAGS:
        raise ValueError(f"A profile cannot be stored with secret flags {int(flags)}")
    s_vpn.remove_data_item(KEY_PROFILE)
    s_vpn.add_data_item(KEY_PROFILE_STORAGE, STORAGE_SECRET)
    s_vpn.add_data_item(KEY_PROFILE_FLAGS, str(int(flags)))
    s_vpn.add_secret(KEY_PROFILE, encode(text))
