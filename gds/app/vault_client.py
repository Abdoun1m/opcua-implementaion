from __future__ import annotations

import logging
import threading
import time
import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import Settings


LOG = logging.getLogger("gds.vault")


class VaultSealedError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("vault_sealed")
        self.error_code = "vault_sealed"


def _dt_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class VaultTokenState:
    token: str | None = None
    renewable: bool = False
    expire_time_epoch: int = 0
    last_error: str | None = None
    vault_sealed: bool = False


class VaultClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._state = VaultTokenState()
        self._lock = threading.Lock()

    def _url(self, path: str) -> str:
        return self.settings.vault_addr.rstrip("/") + path

    @property
    def vault_sealed(self) -> bool:
        return bool(self._state.vault_sealed)

    @property
    def mtls_enabled(self) -> bool:
        return (
            self.settings.vault_addr.lower().startswith("https://")
            and bool(self.settings.vault_tls_client_cert)
            and bool(self.settings.vault_tls_client_key)
        )

    def _read_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()

    def _client_kwargs(self) -> dict:
        verify: bool | str = self.settings.vault_tls_verify
        if self.settings.vault_tls_verify and self.settings.vault_tls_ca_file:
            verify = self.settings.vault_tls_ca_file
        cert = None
        if self.settings.vault_tls_client_cert and self.settings.vault_tls_client_key:
            cert = (self.settings.vault_tls_client_cert, self.settings.vault_tls_client_key)
        kwargs = {
            "timeout": self.settings.vault_timeout_seconds,
            "verify": verify,
        }
        if cert:
            kwargs["cert"] = cert
        return kwargs

    def _raw_request(self, method: str, path: str, token: str | None = None, json_body: dict | None = None) -> httpx.Response:
        headers = {}
        if token:
            headers["X-Vault-Token"] = token
        with httpx.Client(**self._client_kwargs()) as client:
            return client.request(method, self._url(path), headers=headers, json=json_body)

    def _is_sealed_response(self, res: httpx.Response) -> bool:
        if res.status_code == 503:
            return True
        body = res.text[:4096] if res.content else ""
        return "vault is sealed" in body.lower()

    def _mark_sealed(self) -> None:
        self._state.vault_sealed = True
        self._state.last_error = "vault_sealed"

    def _mark_success(self) -> None:
        was_sealed = bool(self._state.vault_sealed)
        self._state.vault_sealed = False
        if was_sealed:
            try:
                from .db import audit

                audit(self.settings, "vault_unsealed_detected", "system", "vault", {"vault_addr": self.settings.vault_addr})
            except Exception as exc:
                LOG.warning("vault unsealed audit event failed: %s", exc.__class__.__name__)

    def _request(self, method: str, path: str, token: str | None = None, json_body: dict | None = None) -> httpx.Response:
        res = self._raw_request(method, path, token=token, json_body=json_body)
        if self._is_sealed_response(res):
            self._mark_sealed()
            raise VaultSealedError()
        self._mark_success()
        return res

    def _login_approle(self) -> None:
        role_id = self._read_file(self.settings.vault_role_id_file)
        secret_id = self._read_file(self.settings.vault_secret_id_file)
        res = self._request(
            "POST",
            self.settings.vault_approle_login_path,
            json_body={"role_id": role_id, "secret_id": secret_id},
        )
        res.raise_for_status()
        data = res.json().get("auth", {})
        token = data.get("client_token")
        if not token:
            raise RuntimeError("Vault AppRole login returned no client_token")

        lease_duration = int(data.get("lease_duration", 0))
        renewable = bool(data.get("renewable", False))
        now = int(time.time())
        self._state.token = token
        self._state.renewable = renewable
        self._state.expire_time_epoch = now + lease_duration
        self._state.last_error = None
        LOG.info("vault approle login succeeded renewable=%s ttl=%s", renewable, lease_duration)

    def _lookup_self(self, token: str) -> dict:
        res = self._request("GET", self.settings.vault_token_lookup_path, token=token)
        res.raise_for_status()
        return res.json().get("data", {})

    def _renew_self(self, token: str) -> None:
        res = self._request("POST", self.settings.vault_token_renew_path, token=token)
        res.raise_for_status()
        auth = res.json().get("auth", {})
        lease_duration = int(auth.get("lease_duration", 0))
        renewable = bool(auth.get("renewable", self._state.renewable))
        now = int(time.time())
        self._state.renewable = renewable
        self._state.expire_time_epoch = now + lease_duration
        self._state.last_error = None
        LOG.info("vault token renewed renewable=%s ttl=%s", renewable, lease_duration)

    def ensure_token(self) -> str:
        with self._lock:
            now = int(time.time())
            margin = self.settings.vault_token_renew_margin_seconds

            if not self._state.token:
                self._login_approle()
                return self._state.token or ""

            # Refresh lifecycle info
            try:
                lookup = self._lookup_self(self._state.token)
                ttl = int(lookup.get("ttl", 0))
                renewable = bool(lookup.get("renewable", self._state.renewable))
                self._state.renewable = renewable
                self._state.expire_time_epoch = now + ttl
                self._state.last_error = None
            except VaultSealedError:
                raise
            except Exception as exc:
                LOG.warning("vault token lookup failed, re-login: %s", exc.__class__.__name__)
                self._state.last_error = "token_lookup_failed"
                self._login_approle()
                return self._state.token or ""

            time_left = self._state.expire_time_epoch - now
            if time_left <= margin:
                try:
                    if self._state.renewable:
                        self._renew_self(self._state.token)
                    else:
                        LOG.info("vault token not renewable, re-login")
                        self._login_approle()
                except VaultSealedError:
                    raise
                except Exception as exc:
                    LOG.warning("vault renew failed, re-login: %s", exc.__class__.__name__)
                    self._state.last_error = "token_renew_failed"
                    self._login_approle()

            return self._state.token or ""

    def get_status(self) -> dict:
        checked_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        vault_reachable = False
        vault_initialized = False
        vault_sealed = True
        try:
            res = self._raw_request("GET", "/v1/sys/seal-status")
            vault_reachable = True
            data = res.json() if res.content else {}
            vault_initialized = bool(data.get("initialized", False))
            vault_sealed = bool(data.get("sealed", True))
            if vault_sealed:
                self._mark_sealed()
            else:
                self._mark_success()
        except Exception as exc:
            self._state.last_error = "vault_status_unavailable"
            LOG.warning("vault seal-status check failed: %s", exc.__class__.__name__)

        token_ok = False
        pki_root_ok = False
        pki_int_ok = False
        crl_status = "unavailable"

        if vault_reachable and vault_initialized and not vault_sealed:
            try:
                token = self.ensure_token()
                token_ok = bool(token)
            except VaultSealedError:
                vault_sealed = True
                token_ok = False
            except Exception as exc:
                self._state.last_error = "token_check_failed"
                LOG.warning("vault token check failed: %s", exc.__class__.__name__)
            if token_ok:
                try:
                    root = self.get_root_crl()
                    pki_root_ok = bool(root.get("freshness_verified"))
                    intermediate = self.get_intermediate_crl()
                    pki_int_ok = bool(intermediate.get("freshness_verified"))
                    crl_status = "fresh" if pki_root_ok and pki_int_ok else "stale"
                except VaultSealedError:
                    vault_sealed = True
                    crl_status = "unavailable"
                except Exception as exc:
                    crl_status = "stale"
                    LOG.warning("vault CRL status check failed: %s", exc.__class__.__name__)

        return {
            "vault_reachable": vault_reachable,
            "vault_initialized": vault_initialized,
            "vault_sealed": vault_sealed,
            "vault_mtls_enabled": self.mtls_enabled,
            "token_ok": token_ok,
            "pki_root_ok": pki_root_ok,
            "pki_int_ok": pki_int_ok,
            "crl_status": crl_status,
            "checked_at": checked_at,
        }

    def get_ca_chain(self) -> dict:
        if self.settings.vault_allow_unauthenticated_pki_read:
            res = self._request("GET", f"/v1/{self.settings.vault_pki_mount}/ca_chain")
        else:
            token = self.ensure_token()
            res = self._request("GET", f"/v1/{self.settings.vault_pki_mount}/ca_chain", token=token)
        res.raise_for_status()
        return {
            "mount": self.settings.vault_pki_mount,
            "content_type": res.headers.get("content-type", ""),
            "ca_chain_pem": res.text,
        }

    def get_crl(self) -> dict:
        return self.get_intermediate_crl()

    def _get_crl_from_endpoint(self, mount: str, path: str, source: str, issuer_id: str | None = None) -> dict:
        if self.settings.vault_allow_unauthenticated_pki_read:
            res = self._request("GET", path)
        else:
            token = self.ensure_token()
            res = self._request("GET", path, token=token)
        res.raise_for_status()
        crl_der = self._crl_response_to_der(res)
        meta = self._parse_crl_metadata(crl_der, mount=mount, source=source, endpoint=path, issuer_id=issuer_id)
        return {
            "mount": mount,
            "content_type": res.headers.get("content-type", ""),
            "encoding": "base64",
            "crl_base64": base64.b64encode(crl_der).decode("ascii"),
            **meta,
        }

    def _crl_response_to_der(self, res: httpx.Response) -> bytes:
        body = res.content
        content_type = res.headers.get("content-type", "").lower()
        if b"-----BEGIN X509 CRL-----" in body or b"-----BEGIN CRL-----" in body or "pem" in content_type:
            crl = x509.load_pem_x509_crl(body)
            return crl.public_bytes(serialization.Encoding.DER)
        try:
            crl = x509.load_der_x509_crl(body)
            return crl.public_bytes(serialization.Encoding.DER)
        except Exception:
            # Vault mount-level /crl commonly returns DER; /crl/pem returns PEM. If a
            # proxy stripped content-type, try PEM as the final parser.
            crl = x509.load_pem_x509_crl(body)
            return crl.public_bytes(serialization.Encoding.DER)

    def _parse_crl_metadata(self, crl_der: bytes, *, mount: str, source: str, endpoint: str, issuer_id: str | None) -> dict:
        try:
            crl = x509.load_der_x509_crl(crl_der)
        except Exception as exc:
            raise RuntimeError(f"unparsable CRL from {endpoint}: {exc}") from exc
        next_update = getattr(crl, "next_update_utc", None) or crl.next_update.replace(tzinfo=UTC)
        last_update = getattr(crl, "last_update_utc", None) or crl.last_update.replace(tzinfo=UTC)
        if self.settings.vault_strict_crl_freshness:
            if next_update is None:
                raise RuntimeError(f"CRL from {endpoint} has no nextUpdate")
            if next_update <= datetime.now(UTC):
                raise RuntimeError(f"CRL from {endpoint} expired at {_dt_iso(next_update)}")
        return {
            "source": source,
            "endpoint": endpoint,
            "issuer_id": issuer_id,
            "issuer": crl.issuer.rfc4514_string(),
            "last_update": _dt_iso(last_update),
            "next_update": _dt_iso(next_update),
            "sha256": hashlib.sha256(crl_der).hexdigest(),
            "freshness_verified": True,
        }

    def get_root_crl(self) -> dict:
        mount = self.settings.vault_root_pki_mount
        mode = self.settings.vault_root_crl_mode.lower()
        issuer_id = self.settings.vault_root_issuer_id.strip()
        if mode == "issuer_specific":
            if not issuer_id:
                raise RuntimeError("GDS__VAULT__ROOT_ISSUER_ID is required for issuer_specific root CRL mode")
            return self._get_crl_from_endpoint(
                mount,
                f"/v1/{mount}/issuer/{issuer_id}/crl/pem",
                source="issuer_specific",
                issuer_id=issuer_id,
            )
        return self._get_crl_from_endpoint(mount, f"/v1/{mount}/crl/pem", source="mount", issuer_id=None)

    def get_intermediate_crl(self) -> dict:
        mount = self.settings.vault_intermediate_pki_mount
        mode = self.settings.vault_intermediate_crl_mode.lower()
        issuer_id = self.settings.vault_intermediate_issuer_id.strip()
        if mode == "issuer_specific" and issuer_id:
            return self._get_crl_from_endpoint(
                mount,
                f"/v1/{mount}/issuer/{issuer_id}/crl/pem",
                source="issuer_specific",
                issuer_id=issuer_id,
            )
        return self._get_crl_from_endpoint(mount, f"/v1/{mount}/crl/pem", source="mount", issuer_id=issuer_id or None)

    def get_crl_bundle(self) -> dict:
        root = self.get_root_crl()
        intermediate = self.get_intermediate_crl()
        return {
            "root": root,
            "intermediate": intermediate,
            "crl_freshness_verified": bool(root.get("freshness_verified") and intermediate.get("freshness_verified")),
            "root_crl_source": root.get("source"),
            "root_pki_mount": root.get("mount"),
            "root_issuer_id": root.get("issuer_id"),
            "root_crl_issuer": root.get("issuer"),
            "root_crl_next_update": root.get("next_update"),
            "root_crl_sha256": root.get("sha256"),
            "intermediate_pki_mount": intermediate.get("mount"),
            "intermediate_crl_source": intermediate.get("source"),
            "intermediate_crl_issuer": intermediate.get("issuer"),
            "intermediate_crl_next_update": intermediate.get("next_update"),
            "intermediate_crl_sha256": intermediate.get("sha256"),
        }

    def revoke_certificate(self, serial_number: str) -> dict:
        token = self.ensure_token()
        serial = self._vault_serial_number(serial_number)
        res = self._request(
            "POST",
            f"/v1/{self.settings.vault_pki_mount}/revoke",
            token=token,
            json_body={"serial_number": serial},
        )
        res.raise_for_status()
        data = res.json().get("data", {})
        return {
            "mount": self.settings.vault_pki_mount,
            "serial_number": serial,
            "revocation_time": data.get("revocation_time"),
        }

    @staticmethod
    def _vault_serial_number(serial_number: str) -> str:
        serial = str(serial_number).strip().lower().replace("-", ":")
        if ":" in serial:
            return serial
        if len(serial) % 2 == 1:
            serial = "0" + serial
        return ":".join(serial[i : i + 2] for i in range(0, len(serial), 2))

    def sign_csr(self, csr_pem: str, ttl: str | None = None, common_name: str | None = None) -> dict:
        token = self.ensure_token()
        body = {
            "csr": csr_pem,
            "ttl": ttl or self.settings.cert_default_ttl,
        }
        if common_name:
            body["common_name"] = common_name
        res = self._request(
            "POST",
            f"/v1/{self.settings.vault_pki_mount}/sign/{self.settings.vault_sign_role}",
            token=token,
            json_body=body,
        )
        res.raise_for_status()
        data = res.json().get("data", {})
        certificate = data.get("certificate")
        if not certificate:
            raise RuntimeError("Vault CSR signing response did not include certificate")
        issuing_ca = data.get("issuing_ca", "")
        ca_chain = data.get("ca_chain", [])
        if isinstance(ca_chain, list) and ca_chain:
            ca_chain_pem = "\n".join(str(item).strip() for item in ca_chain if item).strip() + "\n"
        else:
            ca_chain_pem = str(issuing_ca).strip() + "\n" if issuing_ca else ""
        return {
            "certificate_pem": certificate.strip() + "\n",
            "issuing_ca_pem": str(issuing_ca).strip() + "\n" if issuing_ca else "",
            "ca_chain_pem": ca_chain_pem,
            "serial_number": data.get("serial_number"),
            "expiration": data.get("expiration"),
        }
