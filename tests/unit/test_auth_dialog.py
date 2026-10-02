# SPDX-License-Identifier: GPL-2.0-or-later
import base64
import importlib.machinery
import importlib.util
import io
import os

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib  # noqa: E402

PATH = os.path.join(os.path.dirname(__file__), "..", "..", "auth-dialog", "nm-openvpn3-auth-dialog.in")
loader = importlib.machinery.SourceFileLoader("auth_dialog", PATH)
spec = importlib.util.spec_from_loader("auth_dialog", loader)
ad = importlib.util.module_from_spec(spec)
loader.exec_module(ad)

PROFILE = base64.b64encode(b"client\nremote vpn.example.net\nauth-user-pass\n").decode()
CERT_ONLY = base64.b64encode(b"client\nremote vpn.example.net\n").decode()


def stdin(data, secrets=()):
    out = "".join(f"DATA_KEY={k}\nDATA_VAL={v}\n\n" for k, v in data.items())
    out += "".join(f"SECRET_KEY={k}\nSECRET_VAL={v}\n\n" for k, v in dict(secrets).items())
    return io.BytesIO((out + "DONE\n\nQUIT\n").encode())


def test_read_vpn_details():
    data, secrets = ad.read_vpn_details(stdin({"profile": PROFILE, "username": "testuser"},
                                              {"password": "pw"}))
    assert data == {"profile": PROFILE, "username": "testuser"}
    assert secrets == {"password": "pw"}


def test_read_vpn_details_requires_done():
    try:
        ad.read_vpn_details(io.BytesIO(b"DATA_KEY=a\nDATA_VAL=b\n"))
    except ValueError:
        return
    raise AssertionError("missing DONE accepted")


def test_plan_asks_for_missing_password():
    _, fields = ad.plan({"profile": PROFILE, "password-flags": "1"}, {}, [], False)
    assert [(f.key, f.echo, f.should_ask) for f in fields] == [("password", False, True)]


def test_plan_keeps_saved_password_unless_reprompt():
    _, fields = ad.plan({"profile": PROFILE}, {"password": "pw"}, [], False)
    assert not fields[0].should_ask and fields[0].value == "pw"
    _, fields = ad.plan({"profile": PROFILE}, {"password": "pw"}, [], True)
    assert fields[0].should_ask


def test_plan_not_saved_always_asks():
    _, fields = ad.plan({"profile": PROFILE, "password-flags": "2"}, {"password": "pw"}, [], False)
    assert fields[0].should_ask


def test_plan_certificate_only_needs_nothing():
    assert ad.plan({"profile": CERT_ONLY}, {}, [], False) == (None, [])


def test_plan_challenge_from_hints():
    msg, fields = ad.plan({"profile": PROFILE}, {}, ["challenge-response", "x-challenge-echo",
                                                     "x-vpn-message:Enter PIN"], False)
    assert msg == "Enter PIN"
    assert [(f.key, f.label, f.echo) for f in fields] == [("challenge-response", "Enter PIN", True)]


def test_external_ui_keyfile(capsys):
    _, fields = ad.plan({"profile": PROFILE, "password-flags": "1"}, {}, [], False)
    ad.external_ui("office", None, fields)
    kf = GLib.KeyFile()
    text = capsys.readouterr().out
    kf.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.NONE)
    assert kf.get_integer("VPN Plugin UI", "Version") == 2
    assert "office" in kf.get_string("VPN Plugin UI", "Description")
    assert kf.get_boolean("password", "IsSecret")
    assert kf.get_boolean("password", "ShouldAsk")
    assert not kf.get_boolean("password", "ForceEcho")


def test_external_ui_echo_challenge_is_still_secret(capsys):
    _, fields = ad.plan({"profile": PROFILE}, {}, ["challenge-response", "x-challenge-echo"], False)
    ad.external_ui("office", "Enter PIN", fields)
    kf = GLib.KeyFile()
    text = capsys.readouterr().out
    kf.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.NONE)
    assert kf.get_boolean("challenge-response", "IsSecret")
    assert kf.get_boolean("challenge-response", "ForceEcho")


def test_plan_asks_for_key_passphrase():
    from pkihelp import pem_key
    prof = base64.b64encode(f"client\nremote vpn.example.net\n<key>\n{pem_key(b'k')}</key>\n".encode()).decode()
    _, fields = ad.plan({"profile": prof, "cert-pass-flags": "1"}, {}, [], False)
    assert [(f.key, f.should_ask) for f in fields] == [("cert-pass", True)]


def test_plan_cert_pass_hint():
    _, fields = ad.plan({"profile": PROFILE}, {}, ["cert-pass"], False)
    assert [f.key for f in fields] == ["cert-pass"]


# -- the profile stored as a secret ------------------------------------------

SECRET_DATA = {"profile-storage": "secret", "profile-flags": "1"}


def test_plan_reads_the_profile_from_the_secrets():
    from pkihelp import pem_key
    body = f"client\nremote vpn.example.net\n<key>\n{pem_key(b'k')}</key>\n"
    data = dict(SECRET_DATA, **{"cert-pass-flags": "1"})
    _, fields = ad.plan(data, {"profile": base64.b64encode(body.encode()).decode()}, [], False)
    assert [(f.key, f.should_ask) for f in fields] == [("cert-pass", True)]


def test_plan_explains_a_locked_profile_instead_of_asking():
    # Which credentials this connection needs is a property of the profile,
    # so with the profile locked there is nothing sensible to type in here.
    msg, fields = ad.plan(SECRET_DATA, {}, [], False)
    assert fields == []
    assert "profile" in msg.lower()
    assert "wallet" in msg.lower() or "keyring" in msg.lower()


def test_plan_ignores_a_stale_public_profile_in_secret_mode():
    # The data item is left over from before the connection moved to the
    # keyring; it must not be the stale profile that decides what to ask for.
    data = dict(SECRET_DATA, profile=CERT_ONLY)
    msg, fields = ad.plan(data, {}, [], False)
    assert fields == []
    assert "profile" in msg.lower()


def test_plan_still_prompts_when_the_service_asked_for_a_named_secret():
    # A locked profile does not stop the retry the service asked for.
    _, fields = ad.plan(SECRET_DATA, {}, ["cert-pass"], False)
    assert [f.key for f in fields] == ["cert-pass"]
    _, fields = ad.plan(SECRET_DATA, {}, ["challenge-response"], False)
    assert [f.key for f in fields] == ["challenge-response"]


def test_plan_explains_an_unknown_storage_layout():
    msg, fields = ad.plan({"profile-storage": "v2-whatever", "profile": PROFILE}, {}, [], False)
    assert fields == []
    assert "profile" in msg.lower()
    assert ad.profile_unavailable({"profile-storage": "v2-whatever", "profile": PROFILE}, {})


def test_an_unavailable_profile_is_not_echoed_in_the_explanation(capsys):
    msg, fields = ad.plan(SECRET_DATA, {"profile": PROFILE}, [], False)
    ad.external_ui("office", msg, fields)
    assert PROFILE not in capsys.readouterr().out


def test_profile_unavailable_is_false_once_the_profile_is_there():
    assert not ad.profile_unavailable(SECRET_DATA, {"profile": PROFILE})
    assert not ad.profile_unavailable({"profile": PROFILE}, {})
    # A legacy connection with no profile at all is a different problem; the
    # prompt still asks, as it always did.
    assert not ad.profile_unavailable({}, {})


def test_plan_never_asks_for_the_profile_itself():
    _, fields = ad.plan(SECRET_DATA, {"profile": PROFILE}, [], False)
    assert "profile" not in [f.key for f in fields]


def test_the_profile_is_not_echoed_back(capsys):
    _, fields = ad.plan(SECRET_DATA, {"profile": PROFILE, "password": "pw"}, [], False)
    ad.external_ui("office", None, fields)
    assert PROFILE not in capsys.readouterr().out


def test_plan_still_reads_a_legacy_profile_from_the_data():
    assert ad.plan({"profile": CERT_ONLY}, {}, [], False) == (None, [])


# -- shared contract helpers --------------------------------------------------


def test_the_helper_uses_the_shared_storage_contract():
    from nm_openvpn3 import profile_storage as ps
    assert ad.KEY_PROFILE == ps.KEY_PROFILE
    assert ad.KEY_PROFILE_STORAGE == ps.KEY_PROFILE_STORAGE
    assert ad.STORAGE_SECRET == ps.STORAGE_SECRET


def test_auth_inspection_sees_inside_a_connection_block():
    body = ("client\n<connection>\nremote vpn.example.net 1194 udp\n"
            "auth-user-pass\n</connection>\n")
    data = {"profile": base64.b64encode(body.encode()).decode()}
    _, fields = ad.plan(data, {}, [], False)
    assert [f.key for f in fields] == ["password"]


def test_auth_inspection_ignores_text_inside_an_inline_payload():
    body = ("client\nremote vpn.example.net\n<ca>\n-----BEGIN CERTIFICATE-----\n"
            "auth-user-pass\n-----END CERTIFICATE-----\n</ca>\n")
    data = {"profile": base64.b64encode(body.encode()).decode()}
    assert ad.plan(data, {}, [], False) == (None, [])


def test_bad_secret_flags_do_not_turn_into_every_flag():
    # NM.SettingSecretFlags(-1) is every flag, NotRequired included, which
    # would silently skip the field instead of asking for it.
    _, fields = ad.plan({"profile": PROFILE, "password-flags": "-1"}, {}, [], False)
    assert [f.key for f in fields] == ["password"]
    _, fields = ad.plan({"profile": PROFILE, "password-flags": "nonsense"}, {}, [], False)
    assert [f.key for f in fields] == ["password"]
