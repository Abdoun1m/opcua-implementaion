from __future__ import annotations

import hashlib
import json
import os
import base64
from dataclasses import dataclass
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _to_rfc3339_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_artifact_payload(artifact: dict) -> dict:
    # Canonical signed payload excludes transport metadata (for example ttl_remaining_seconds).
    payload = {
        "artifact_type": artifact.get("artifact_type"),
        "schema_version": artifact.get("schema_version"),
        "zone": artifact.get("zone"),
        "role": artifact.get("role"),
        "version": artifact.get("version"),
        "artifact_revision": artifact.get("artifact_revision"),
        "artifact_reason": artifact.get("artifact_reason"),
        "generated_at": artifact.get("generated_at"),
        "expires_at": artifact.get("expires_at"),
        "ca_chain_pem": artifact.get("ca_chain_pem"),
        "crl_base64": artifact.get("crl_base64"),
        "certificates": deepcopy(artifact.get("certificates", [])),
        "signer": deepcopy(artifact.get("signer", {})),
    }
    if "crl_bundle" in artifact:
        payload["crl_bundle"] = deepcopy(artifact.get("crl_bundle", {}))
    if "crl_metadata" in artifact:
        payload["crl_metadata"] = deepcopy(artifact.get("crl_metadata", {}))
    return payload


@dataclass(frozen=True)
class SignedArtifact:
    artifact: dict
    artifact_bytes: bytes
    artifact_sha256: str
    signature_base64: str
    signer_fingerprint_sha256: str
    signer_key_id: str
    signer_algorithm: str
    generated_at: datetime
    expires_at: datetime
    canonical_payload: dict


class TrustArtifactSigner:
    def __init__(self, key_path: str, key_id: str, ttl_seconds: int):
        self._key_path = key_path
        self._key_id = key_id
        self._ttl_seconds = ttl_seconds
        self._private_key = self._load_or_create_private_key(key_path)
        self._public_key = self._private_key.public_key()
        self._public_key_der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self._fingerprint = sha256_hex(self._public_key_der)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "ed25519"

    @property
    def public_key_pem(self) -> str:
        return self._public_key_pem

    @property
    def fingerprint_sha256(self) -> str:
        return self._fingerprint

    def trust_anchor_payload(self) -> dict:
        return {
            "key_id": self._key_id,
            "algorithm": self.algorithm,
            "public_key_pem": self._public_key_pem,
            "fingerprint_sha256": self._fingerprint,
        }

    def sign_canonical_payload(self, payload: dict) -> dict:
        canonical = canonical_json_bytes(payload)
        return {
            "algorithm": self.algorithm,
            "key_id": self._key_id,
            "fingerprint_sha256": self._fingerprint,
            "payload_sha256": sha256_hex(canonical),
            "signature_base64": base64.b64encode(self._private_key.sign(canonical)).decode("ascii"),
        }

    def build_signed_artifact(
        self,
        trust_list: dict,
        certs: list[dict],
        ca_chain_pem: str,
        crl_base64: str,
        artifact_revision: int,
        reason: str,
        crl_bundle: dict | None = None,
        crl_metadata: dict | None = None,
        generated_at: datetime | None = None,
    ) -> SignedArtifact:
        if generated_at is None:
            generated_at = datetime.now(UTC)
        elif generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=UTC)
        else:
            generated_at = generated_at.astimezone(UTC)
        expires_at = generated_at + timedelta(seconds=self._ttl_seconds)

        artifact = {
            "artifact_type": "opcua_trustlist",
            "schema_version": 1,
            "zone": trust_list["zone"],
            "role": trust_list["role"],
            "version": int(trust_list["version"]),
            "artifact_revision": int(artifact_revision),
            "artifact_reason": reason,
            "generated_at": _to_rfc3339_utc(generated_at),
            "expires_at": _to_rfc3339_utc(expires_at),
            "ca_chain_pem": ca_chain_pem,
            "crl_base64": crl_base64,
            "crl_bundle": deepcopy(crl_bundle or {}),
            "crl_metadata": deepcopy(crl_metadata or {}),
            "certificates": certs,
            "signer": {
                "key_id": self._key_id,
                "algorithm": self.algorithm,
                "fingerprint_sha256": self._fingerprint,
            },
        }
        canonical_payload = canonical_artifact_payload(artifact)
        canonical_bytes = canonical_json_bytes(canonical_payload)
        digest = sha256_hex(canonical_bytes)
        signature = self._private_key.sign(canonical_bytes)
        signature_b64 = base64.b64encode(signature).decode("ascii")
        return SignedArtifact(
            artifact=artifact,
            artifact_bytes=canonical_bytes,
            artifact_sha256=digest,
            signature_base64=signature_b64,
            signer_fingerprint_sha256=self._fingerprint,
            signer_key_id=self._key_id,
            signer_algorithm=self.algorithm,
            generated_at=generated_at,
            expires_at=expires_at,
            canonical_payload=canonical_payload,
        )

    def _load_or_create_private_key(self, key_path: str) -> Ed25519PrivateKey:
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                raw = f.read()
            loaded = serialization.load_pem_private_key(raw, password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError("configured trust artifact signing key is not Ed25519")
            return loaded

        key = Ed25519PrivateKey.generate()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        return key
