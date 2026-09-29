# SPDX-License-Identifier: GPL-2.0-or-later
import base64

import pytest
from cryptography import x509

from nm_openvpn3 import pki
from pkihelp import p12, pem, pem_key


def profile_with(data, ca=None):
    b64 = base64.b64encode(data).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    extra = f"<ca>\n{ca}</ca>\n" if ca else ""
    return f"client\nremote vpn.example.net\n{extra}<pkcs12>\n{lines}\n</pkcs12>\nverb 3\n"


def test_expand_with_passphrase():
    data, ca, cert = p12()
    out = pki.expand_pkcs12(profile_with(data), "p12pass")
    assert "<pkcs12>" not in out
    assert f"<cert>\n{pem(cert)}</cert>" in out
    assert "-----BEGIN PRIVATE KEY-----" in out
    assert f"<ca>\n{pem(ca)}</ca>" in out
    assert out.endswith("verb 3\n")


def test_profile_ca_wins_and_chain_goes_to_extra_certs():
    data, ca, _ = p12()
    out = pki.expand_pkcs12(profile_with(data, ca="PROFILE-CA\n"), "p12pass")
    assert "<ca>\nPROFILE-CA\n</ca>" in out
    assert f"<extra-certs>\n{pem(ca)}</extra-certs>" in out


def test_wrong_and_missing_passphrase():
    data, _, _ = p12()
    with pytest.raises(pki.WrongPassphrase):
        pki.expand_pkcs12(profile_with(data), "nope")
    assert pki.needs_passphrase(profile_with(data))


def test_bundle_without_password():
    data, _, cert = p12(password=None)
    config = profile_with(data)
    assert not pki.needs_passphrase(config)
    out = pki.expand_pkcs12(config, None)
    assert x509.load_pem_x509_certificate(out.split("<cert>\n")[1].split("</cert>")[0].encode()) == cert


def test_invalid_bundle():
    with pytest.raises(pki.InvalidBundle):
        pki.expand_pkcs12("client\n<pkcs12>\n!!!\n</pkcs12>\n", "x")


def test_encrypted_pem_key_detection():
    assert pki.needs_passphrase(f"client\n<key>\n{pem_key(b'keypass')}</key>\n")
    assert not pki.needs_passphrase(f"client\n<key>\n{pem_key()}</key>\n")
    assert not pki.needs_passphrase("client\nremote vpn.example.net\n")
