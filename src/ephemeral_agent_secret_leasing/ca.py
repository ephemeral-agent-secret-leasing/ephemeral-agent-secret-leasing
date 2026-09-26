"""Local test CA and X.509-SVID helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass(frozen=True, slots=True)
class CertBundle:
    cert_pem: bytes
    key_pem: bytes
    ca_cert_pem: bytes
    spiffe_id: str
    cert_sha256: str


class TestCA:
    def __init__(self, common_name: str = "ephemeral-agent-secret-leasing test CA") -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def issue_svid(self, spiffe_id: str, ttl_s: int = 300) -> CertBundle:
        if not spiffe_id.startswith("spiffe://"):
            raise ValueError("spiffe_id must start with spiffe://")
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=5))
            .not_valid_after(now + timedelta(seconds=ttl_s))
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return CertBundle(cert_pem, key_pem, self.cert_pem, spiffe_id, cert_sha256(cert_pem))


def load_cert(cert_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem)


def cert_sha256(cert_pem: bytes) -> str:
    return hashlib.sha256(load_cert(cert_pem).public_bytes(serialization.Encoding.DER)).hexdigest()


def spiffe_id_from_cert(cert_pem: bytes) -> str:
    try:
        san = cast(
            x509.SubjectAlternativeName,
            load_cert(cert_pem)
            .extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            .value,
        )
    except ExtensionNotFound as exc:
        raise ValueError("certificate has no SPIFFE URI SAN") from exc
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith("spiffe://"):
            return uri
    raise ValueError("certificate has no SPIFFE URI SAN")
