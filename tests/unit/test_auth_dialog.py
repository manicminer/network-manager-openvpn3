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
