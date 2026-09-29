# SPDX-License-Identifier: GPL-2.0-or-later
"""Client key material that openvpn3 cannot use as stored.

openvpn3 does not read PKCS#12. The profile keeps the bundle as a base64
<pkcs12> block; right before handing the profile to openvpn3 the bundle is
decrypted and replaced by PEM <cert>, <key> and CA blocks. The decrypted key
only exists in this process and in openvpn3's single-use configuration.
"""

import base64
import binascii
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

_BLOCK = r"^<{tag}>\s*$\n(.*?)^</{tag}>\s*$\n?"
_PKCS12 = re.compile(_BLOCK.format(tag="pkcs12"), re.M | re.S)
_KEY = re.compile(_BLOCK.format(tag="key"), re.M | re.S)
_CA = re.compile(_BLOCK.format(tag="ca"), re.M | re.S)


class WrongPassphrase(Exception):
    pass


class InvalidBundle(Exception):
    pass


def has_pkcs12(config):
    return _PKCS12.search(config) is not None


def has_encrypted_key(config):
    m = _KEY.search(config)
    return bool(m) and ("ENCRYPTED PRIVATE KEY" in m.group(1) or "Proc-Type: 4,ENCRYPTED" in m.group(1))


def _bundle(config):
    try:
        return base64.b64decode("".join(_PKCS12.search(config).group(1).split()), validate=True)
    except binascii.Error as e:
        raise InvalidBundle(f"The PKCS#12 bundle in the profile is not valid base64: {e}")


def _load(data, passphrase):
    # A bundle without a password may be encrypted with an empty one.
    candidates = [passphrase.encode()] if passphrase else [None, b""]
    last = None
    for pw in candidates:
        try:
            return pkcs12.load_key_and_certificates(data, pw)
        except ValueError as e:
            last = e
    raise WrongPassphrase(str(last))


def pkcs12_needs_passphrase(config):
    try:
        _load(_bundle(config), None)
    except WrongPassphrase:
        return True
    return False


def needs_passphrase(config):
    if has_encrypted_key(config):
        return True
    return has_pkcs12(config) and pkcs12_needs_passphrase(config)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def expand_pkcs12(config, passphrase):
    """Returns the profile with <pkcs12> replaced by PEM blocks."""
    key, cert, extra = _load(_bundle(config), passphrase)
    if key is None or cert is None:
        raise InvalidBundle("The PKCS#12 bundle has no private key or certificate")
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    blocks = f"<cert>\n{_pem(cert)}</cert>\n<key>\n{key_pem}</key>\n"
    if extra:
        chain = "".join(_pem(c) for c in extra)
        # The profile's own CA wins; the bundle's chain then goes along as extra certs.
        blocks += f"<extra-certs>\n{chain}</extra-certs>\n" if _CA.search(config) else f"<ca>\n{chain}</ca>\n"
    return _PKCS12.sub(lambda _m: blocks, config, count=1)
