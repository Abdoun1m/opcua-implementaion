from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _build_ca(common_name: str):
    key = _key()
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_client(common_name: str, ca_key, ca_cert, not_before: datetime, not_after: datetime):
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate LabShock Phase 6.1 mTLS test certificates")
    parser.add_argument("--out-dir", default="gds/config/tls/lab-fixtures")
    args = parser.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = _build_ca("LabShock mTLS Test CA")
    now = datetime.now(timezone.utc)
    valid_key, valid_cert = _build_client("ot-gds-agent-valid", ca_key, ca_cert, now - timedelta(minutes=5), now + timedelta(days=90))
    expired_key, expired_cert = _build_client("ot-gds-agent-expired", ca_key, ca_cert, now - timedelta(days=30), now - timedelta(days=1))
    revoked_key, revoked_cert = _build_client("ot-gds-agent-revoked", ca_key, ca_cert, now - timedelta(minutes=5), now + timedelta(days=90))
    rogue_ca_key, rogue_ca_cert = _build_ca("LabShock Rogue Test CA")
    rogue_key, rogue_cert = _build_client("ot-gds-agent-rogue", rogue_ca_key, rogue_ca_cert, now - timedelta(minutes=5), now + timedelta(days=90))

    _write_key(out / "ca.key", ca_key)
    _write_cert(out / "ca.crt", ca_cert)
    for name, key, cert in (
        ("valid", valid_key, valid_cert),
        ("expired", expired_key, expired_cert),
        ("revoked", revoked_key, revoked_cert),
        ("rogue", rogue_key, rogue_cert),
    ):
        _write_key(out / f"{name}.key", key)
        _write_cert(out / f"{name}.crt", cert)
    _write_cert(out / "rogue-ca.crt", rogue_ca_cert)

    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_cert.serial_number)
            .revocation_date(now)
            .build()
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    (out / "client-ca.crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    print(f"wrote mTLS test fixtures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
