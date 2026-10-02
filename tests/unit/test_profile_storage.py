# SPDX-License-Identifier: GPL-2.0-or-later
import base64

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from nm_openvpn3 import profile_storage as ps  # noqa: E402
from nm_openvpn3.vpnplugin import PluginError  # noqa: E402

PROFILE = "client\ndev tun\nremote vpn.example.net 1194\nauth-user-pass\n"
B64 = base64.b64encode(PROFILE.encode()).decode()


def vpn_setting(data=None, secrets=None):
    s_vpn = NM.SettingVpn.new()
    s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn3")
    for k, v in (data or {}).items():
        s_vpn.add_data_item(k, v)
    for k, v in (secrets or {}).items():
        s_vpn.add_secret(k, v)
    return s_vpn


def legacy():
    return vpn_setting(data={ps.KEY_PROFILE: B64})


def secret_mode(flags="1", profile=B64, storage=ps.STORAGE_SECRET):
    data = {ps.KEY_PROFILE_STORAGE: storage}
    if flags is not None:
        data[ps.KEY_PROFILE_FLAGS] = flags
    return vpn_setting(data=data, secrets={ps.KEY_PROFILE: profile} if profile is not None else None)


# -- reading -----------------------------------------------------------------


def test_legacy_profile_is_read_from_data():
    s_vpn = legacy()
    assert not ps.is_secret_mode(s_vpn)
    assert ps.get_profile(s_vpn) == PROFILE
    assert ps.missing_reason(s_vpn) is None


def test_secret_profile_is_read_from_secrets():
    s_vpn = secret_mode()
    assert ps.is_secret_mode(s_vpn)
    assert ps.get_profile(s_vpn) == PROFILE
    assert ps.missing_reason(s_vpn) is None


def test_secret_mode_never_falls_back_to_a_stale_public_copy():
    s_vpn = secret_mode(profile=None)
    s_vpn.add_data_item(ps.KEY_PROFILE, base64.b64encode(b"client\nremote stale 1\n").decode())
    assert ps.get_profile(s_vpn) is None
    assert ps.missing_reason(s_vpn) == "locked"


def test_missing_legacy_profile_is_absent_not_locked():
    s_vpn = vpn_setting()
    assert ps.get_profile(s_vpn) is None
    assert ps.missing_reason(s_vpn) == "absent"


def test_corrupt_profile_is_an_error_in_both_modes():
    for s_vpn in (vpn_setting(data={ps.KEY_PROFILE: "not base64 at all!"}),
                  secret_mode(profile="not base64 at all!")):
        with pytest.raises(PluginError) as e:
            ps.get_profile(s_vpn)
        assert "corrupt" in str(e.value)


def test_profile_that_is_not_utf8_is_corrupt():
    s_vpn = secret_mode(profile=base64.b64encode(b"\xff\xfe\x00").decode())
    with pytest.raises(PluginError):
        ps.get_profile(s_vpn)


# -- an unknown storage layout fails closed ----------------------------------


def test_unknown_storage_marker_never_falls_back_to_the_data_profile():
    # A layout written by a newer version of the contract.  Its data item may
    # well be a leftover; reading it would connect with a stale profile.
    s_vpn = secret_mode(profile=None, storage="v2-whatever")
    s_vpn.add_data_item(ps.KEY_PROFILE, base64.b64encode(b"client\nremote stale 1\n").decode())
    assert ps.missing_reason(s_vpn) == "unsupported"
    with pytest.raises(PluginError) as e:
        ps.get_profile(s_vpn)
    assert "v2-whatever" in str(e.value)


def test_unknown_storage_marker_is_not_classified_as_secret_mode():
    s_vpn = secret_mode(storage="v2-whatever")
    assert not ps.is_secret_mode(s_vpn)
    with pytest.raises(PluginError):
        ps.profile_flags(s_vpn)


def test_an_empty_storage_marker_is_the_legacy_layout():
    s_vpn = vpn_setting(data={ps.KEY_PROFILE_STORAGE: "", ps.KEY_PROFILE: B64})
    assert ps.get_profile(s_vpn) == PROFILE
    assert ps.missing_reason(s_vpn) is None


# -- the shared read helper the auth dialog uses ------------------------------


def test_stored_profile_reads_plain_maps():
    assert ps.stored_profile({ps.KEY_PROFILE: B64}.get, {}.get) == (B64, None)
    secret = {ps.KEY_PROFILE_STORAGE: ps.STORAGE_SECRET}
    assert ps.stored_profile(secret.get, {ps.KEY_PROFILE: B64}.get) == (B64, None)
    assert ps.stored_profile(secret.get, {}.get) == (None, "locked")
    assert ps.stored_profile({}.get, {}.get) == (None, "absent")
    assert ps.stored_profile({ps.KEY_PROFILE_STORAGE: "v2"}.get,
                             {}.get) == (None, "unsupported")
    stale = {ps.KEY_PROFILE_STORAGE: ps.STORAGE_SECRET, ps.KEY_PROFILE: B64}
    assert ps.stored_profile(stale.get, {}.get) == (None, "locked")


# -- flags -------------------------------------------------------------------


def test_wallet_mode_flags_are_agent_owned():
    assert ps.profile_flags(secret_mode(flags="1")) == NM.SettingSecretFlags.AGENT_OWNED


def test_system_mode_flags_are_none():
    assert ps.profile_flags(secret_mode(flags="0")) == NM.SettingSecretFlags.NONE


def test_absent_flags_mean_system_owned_not_agent_owned():
    # NetworkManager treats a secret without flags as NONE: system-owned.
    # Reading absent flags as AgentOwned would move a system-owned profile
    # into the user's wallet the first time anything saved the connection.
    s_vpn = vpn_setting(data={ps.KEY_PROFILE_STORAGE: ps.STORAGE_SECRET}, secrets={ps.KEY_PROFILE: B64})
    assert ps.profile_flags(s_vpn) == NM.SettingSecretFlags.NONE


def test_writers_still_default_to_agent_owned():
    s_vpn = vpn_setting()
    ps.set_profile(s_vpn, PROFILE)
    assert s_vpn.get_data_item(ps.KEY_PROFILE_FLAGS) == "1"


def test_a_profile_that_is_never_stored_is_rejected():
    # NotSaved(2)/NotRequired(4) cannot describe a profile: it could never be
    # reconstructed.  Reject loudly rather than producing an empty tunnel.
    for bad in ("2", "4", "garbage"):
        with pytest.raises(PluginError):
            ps.profile_flags(secret_mode(flags=bad))


# -- flags of the ordinary secrets -------------------------------------------


def test_secret_flags_reads_the_data_item():
    s_vpn = vpn_setting(data={"password-flags": "2"})
    assert ps.secret_flags(s_vpn, "password") == NM.SettingSecretFlags.NOT_SAVED
    assert ps.secret_flags(s_vpn, "cert-pass") == NM.SettingSecretFlags.NONE
    assert ps.secret_flags(None, "password") == NM.SettingSecretFlags.NONE


def test_secret_flags_rejects_a_value_that_is_not_a_number():
    # Reached from the NeedSecrets D-Bus handler: a ValueError there would
    # leave the call without a reply at all.
    for bad in ("nonsense", "1.5", "-1", "0x1"):
        s_vpn = vpn_setting(data={"password-flags": bad})
        with pytest.raises(PluginError) as e:
            ps.secret_flags(s_vpn, "password")
        assert e.value.name == "BadArguments"
        assert "password-flags" in str(e.value)


def test_secret_flags_errors_do_not_quote_the_secret():
    s_vpn = vpn_setting(data={"password-flags": "nonsense"}, secrets={"password": "s3cret"})
    with pytest.raises(PluginError) as e:
        ps.secret_flags(s_vpn, "password")
    assert "s3cret" not in str(e.value)


# -- writing (used by tests and by other clients of the contract) -------------


def test_set_secret_profile_removes_the_public_copy():
    s_vpn = legacy()
    ps.set_profile(s_vpn, PROFILE, NM.SettingSecretFlags.AGENT_OWNED)
    assert s_vpn.get_data_item(ps.KEY_PROFILE) is None
    assert s_vpn.get_data_item(ps.KEY_PROFILE_STORAGE) == ps.STORAGE_SECRET
    assert s_vpn.get_data_item(ps.KEY_PROFILE_FLAGS) == "1"
    assert s_vpn.get_secret(ps.KEY_PROFILE) == B64
    assert ps.get_profile(s_vpn) == PROFILE


def test_set_legacy_profile_removes_the_secret_markers():
    s_vpn = secret_mode()
    ps.set_profile(s_vpn, PROFILE, None)
    assert s_vpn.get_data_item(ps.KEY_PROFILE) == B64
    assert s_vpn.get_data_item(ps.KEY_PROFILE_STORAGE) is None
    assert s_vpn.get_data_item(ps.KEY_PROFILE_FLAGS) is None
    assert s_vpn.get_secret(ps.KEY_PROFILE) is None


def test_set_profile_rejects_flags_that_do_not_store():
    with pytest.raises(ValueError):
        ps.set_profile(vpn_setting(), PROFILE, NM.SettingSecretFlags.NOT_SAVED)


def test_round_trip_of_a_profile_with_a_private_key():
    body = PROFILE + "<key>\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n</key>\n"
    s_vpn = vpn_setting()
    ps.set_profile(s_vpn, body, NM.SettingSecretFlags.AGENT_OWNED)
    assert ps.get_profile(s_vpn) == body
    # Nothing sensitive is left in the public data map.
    for key in (ps.KEY_PROFILE, ps.KEY_PROFILE_STORAGE, ps.KEY_PROFILE_FLAGS, "password", "cert-pass"):
        value = s_vpn.get_data_item(key) or ""
        assert "PRIVATE KEY" not in value
        assert base64.b64encode(body.encode()).decode() not in value
