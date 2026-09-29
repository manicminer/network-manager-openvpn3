# SPDX-License-Identifier: GPL-2.0-or-later
"""Throwaway certificates for tests."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def _cert(subject, key, issuer=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    return (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer or name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key or key, hashes.SHA256()))


def make_client():
    """Returns (ca_cert, client_cert, client_key)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Test CA", ca_key, ca=True)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert("testuser", key, issuer=ca.subject, issuer_key=ca_key)
    return ca, cert, key


def p12(password=b"p12pass", with_ca=True):
    ca, cert, key = make_client()
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    data = pkcs12.serialize_key_and_certificates(b"testuser", key, cert, [ca] if with_ca else None, enc)
    return data, ca, cert


def pem_key(password=None):
    _, _, key = make_client()
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()
