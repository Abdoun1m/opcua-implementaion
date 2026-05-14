from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def parse_pem_certificate(pem_text: str) -> dict:
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    return {
        "pem": pem_text,
        "fingerprint_sha256": fp,
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
    }
