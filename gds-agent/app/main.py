from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from contextlib import suppress
from datetime import datetime, timezone, time as time_of_day, timedelta
from pathlib import Path
from uuid import uuid4
from urllib.parse import quote, urlparse
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_logging() -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(os.getenv("GDS_AGENT_LOG_LEVEL", "INFO").upper())
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    return logging.getLogger("gds.agent")


def env(name: str, default: str) -> str:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return v


def env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return int(v)


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def gds_transport_metadata(base_url: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    return {
        "control_plane_scheme": parsed.scheme or "http",
        "mtls_enabled": env_bool("GDS_AGENT_MTLS_ENABLED", False),
    }


def build_gds_http_client(timeout_seconds: float = 10.0) -> httpx.Client:
    mtls_enabled = env_bool("GDS_AGENT_MTLS_ENABLED", False)
    if not mtls_enabled:
        return httpx.Client(timeout=timeout_seconds)

    ca_file = env("GDS_AGENT_TLS_CA_FILE", "/etc/labshock-gds-agent-tls/ca.crt")
    cert_file = env("GDS_AGENT_TLS_CERT_FILE", "/etc/labshock-gds-agent-tls/client.crt")
    key_file = env("GDS_AGENT_TLS_KEY_FILE", "/etc/labshock-gds-agent-tls/client.key")
    return httpx.Client(
        timeout=timeout_seconds,
        verify=ca_file,
        cert=(cert_file, key_file),
    )


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tf:
        tf.write(content)
        tmp = Path(tf.name)
    tmp.replace(path)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as tf:
        tf.write(content)
        tmp = Path(tf.name)
    tmp.replace(path)


def optional_atomic_write_bytes(path: Path, content: bytes, log: logging.Logger | None = None) -> bool:
    try:
        atomic_write_bytes(path, content)
        return True
    except PermissionError as exc:
        (log or logging.getLogger("gds.agent")).warning("optional_runtime_alias_write_skipped path=%s err=%s", path, exc)
        return False


def parse_and_fingerprint_pem(pem_text: str) -> str:
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def parse_not_after_pem(pem_text: str) -> str:
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    return cert.not_valid_after_utc.isoformat()


def validate_trustlist_payload(payload: dict, zone: str, role: str) -> None:
    if payload.get("zone") != zone:
        raise ValueError(f"zone mismatch in trustlist payload: {payload.get('zone')} != {zone}")
    if payload.get("role") != role:
        raise ValueError(f"role mismatch in trustlist payload: {payload.get('role')} != {role}")
    if "ca_chain_pem" not in payload or "crl_base64" not in payload or "certificates" not in payload:
        raise ValueError("trustlist payload missing required fields")
    if "BEGIN CERTIFICATE" not in payload["ca_chain_pem"]:
        raise ValueError("ca_chain_pem does not contain PEM certificate text")

    for cert in payload["certificates"]:
        for key in ("application_uri", "common_name", "fingerprint_sha256", "pem"):
            if key not in cert:
                raise ValueError(f"certificate entry missing field: {key}")
        actual_fp = parse_and_fingerprint_pem(cert["pem"])
        if actual_fp.lower() != str(cert["fingerprint_sha256"]).lower():
            raise ValueError(f"certificate fingerprint mismatch for {cert.get('application_uri')}")

    crl_der = base64.b64decode(payload["crl_base64"])
    x509.load_der_x509_crl(crl_der)


def read_text_if_exists(path: Path) -> str | None:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def read_bytes_if_exists(path: Path) -> bytes | None:
    if not path.exists():
        return None
    return path.read_bytes()


def read_secret_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def load_json_if_exists(path: Path) -> dict | None:
    txt = read_text_if_exists(path)
    if txt is None:
        return None
    return json.loads(txt)


def cert_view(cert: dict) -> dict:
    return {
        "application_uri": cert.get("application_uri"),
        "common_name": cert.get("common_name"),
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "not_after": cert.get("not_after"),
    }


def build_cert_index(certs: list[dict]) -> tuple[dict[str, dict], list[str]]:
    idx: dict[str, dict] = {}
    parse_errors: list[str] = []
    for c in certs:
        app_uri = c.get("application_uri")
        if not app_uri:
            continue
        entry = {
            "application_uri": app_uri,
            "common_name": c.get("common_name"),
            "fingerprint_sha256": c.get("fingerprint_sha256"),
            "pem": c.get("pem"),
        }
        if entry["pem"]:
            try:
                entry["not_after"] = parse_not_after_pem(entry["pem"])
            except Exception:
                entry["not_after"] = None
                parse_errors.append(f"malformed_certificate_entry:{app_uri}")
        else:
            entry["not_after"] = None
        idx[app_uri] = entry
    return idx, parse_errors


def sanitize_payload(payload: dict) -> dict:
    sensitive_exact = {
        "pem",
        "ca_chain_pem",
        "crl_base64",
        "token",
        "vault_token",
        "role_id",
        "secret_id",
        "private_key",
    }

    def _scrub(value):
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                kl = str(k).lower()
                if kl in sensitive_exact:
                    out[k] = "[redacted]"
                else:
                    out[k] = _scrub(v)
            return out
        if isinstance(value, list):
            return [_scrub(v) for v in value]
        return value

    return _scrub(payload)


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_package_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    out = dict(manifest)
    out["manifest_sha256"] = ""
    out.pop("signature", None)
    return out


def package_manifest_sha256(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(canonical_package_manifest(manifest)))


class ArtifactVerificationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_artifact_payload(artifact: dict) -> dict:
    # Must match GDS canonical structure exactly.
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
        "certificates": artifact.get("certificates", []),
        "signer": artifact.get("signer", {}),
    }
    if "crl_bundle" in artifact:
        payload["crl_bundle"] = artifact.get("crl_bundle", {})
    if "crl_metadata" in artifact:
        payload["crl_metadata"] = artifact.get("crl_metadata", {})
    return payload


def normalize_signed_artifact_for_verification(artifact: dict) -> dict:
    normalized = dict(artifact)
    removed: list[str] = []
    for field in ("ttl_remaining_seconds",):
        if field in normalized:
            normalized.pop(field, None)
            removed.append(field)
    if removed:
        logging.getLogger("gds.agent").warning(
            "unsigned_volatile_field_removed=%s",
            ",".join(removed),
        )
    return normalized


def parse_rfc3339_utc(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now_z() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_runtime_targets(raw: str) -> list[str]:
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def parse_csv(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def build_runtime_target_catalog(agent_zone: str) -> dict[str, dict[str, Any]]:
    catalog = {
        "opcua-server": {
            "target": "opcua-server",
            "application_uri": env("GDS_AGENT_APPLICATION_URI_OPCUA_SERVER", "urn:dataprotect:opcua:ot-server"),
            "runtime_instance_id": env("GDS_AGENT_RUNTIME_INSTANCE_ID_OPCUA_SERVER", "urn:dataprotect:opcua:ot-server"),
            "profile_name": "open62541-server",
            "component_type": "server",
            "common_name": "PowerGridOPCUA",
            "artifact_zone": env("GDS_AGENT_TARGET_ZONE_OPCUA_SERVER", "OT"),
            "artifact_role": "server",
            "layout_kind": "open62541-opcua-server",
            "runtime_root": env("GDS_AGENT_RUNTIME_PATH_OPCUA_SERVER", "/runtime/opcua-server/pki"),
            "trusted_certs_dir": "ApplCerts/trusted/certs",
            "trusted_crl_dir": "ApplCerts/trusted/crl",
            "issuer_certs_dir": "ApplCerts/issuer/certs",
            "issuer_crl_dir": "ApplCerts/issuer/crl",
            "rejected_dir": "ApplCerts/rejected/certs",
            "runtime_paths_checked": [
                env("GDS_AGENT_RUNTIME_PATH_OPCUA_SERVER", "/runtime/opcua-server/pki"),
                env("GDS_AGENT_RUNTIME_PATH_OPCUA_SERVER_OWN_CERT", "/runtime/opcua-server/pki/ApplCerts/own/certs/server.der"),
                env("GDS_AGENT_RUNTIME_PATH_OPCUA_SERVER_TRUSTED", "/runtime/opcua-server/pki/ApplCerts/trusted/certs"),
            ],
        },
        "fuxa": {
            "target": "fuxa",
            "application_uri": env("GDS_AGENT_APPLICATION_URI_FUXA", "urn:dataprotect:opcua:fuxa-client"),
            "runtime_instance_id": env("GDS_AGENT_RUNTIME_INSTANCE_ID_FUXA", "urn:dataprotect:opcua:fuxa-client"),
            "profile_name": "node-opcua-client",
            "component_type": "client",
            "common_name": "FuxaClient",
            "artifact_zone": env("GDS_AGENT_TARGET_ZONE_FUXA", "OT"),
            "artifact_role": "scada-client",
            "layout_kind": "node-opcua-fuxa",
            "runtime_root": env("GDS_AGENT_RUNTIME_PATH_FUXA", "/runtime/fuxa/PKI"),
            "trusted_certs_dir": "trusted/certs",
            "trusted_crl_dir": "trusted/crl",
            "issuer_certs_dir": "issuers/certs",
            "issuer_crl_dir": "issuers/crl",
            "rejected_dir": "rejected",
            "runtime_paths_checked": [
                env("GDS_AGENT_RUNTIME_PATH_FUXA", "/runtime/fuxa/PKI"),
                env("GDS_AGENT_RUNTIME_PATH_FUXA_TRUSTED", "/runtime/fuxa/PKI/trusted/certs"),
            ],
        },
        # Declared for future orchestration, but disabled by default in OT runtime target list.
        "dmz-gateway-client": {
            "target": "dmz-gateway-client",
            "application_uri": env("GDS_AGENT_APPLICATION_URI_DMZ_GATEWAY_CLIENT", "urn:dataprotect:opcua:dmz-gateway-client"),
            "runtime_instance_id": env("GDS_AGENT_RUNTIME_INSTANCE_ID_DMZ_GATEWAY_CLIENT", "urn:dataprotect:opcua:dmz-gateway-client"),
            "profile_name": "open62541-client",
            "component_type": "client",
            "common_name": "DMZGatewayClient",
            "artifact_zone": "DMZ",
            "artifact_role": "southbound-client",
            "layout_kind": "open62541-dmz-gateway-client",
            "runtime_root": env("GDS_AGENT_RUNTIME_PATH_DMZ_GATEWAY_CLIENT", "/runtime/opcua-dmz-gateway/pki/southbound"),
            "trusted_certs_dir": "trusted/certs",
            "trusted_crl_dir": "trusted/crl",
            "issuer_certs_dir": "issuer/certs",
            "issuer_crl_dir": "issuer/crl",
            "rejected_dir": "rejected/certs",
            "runtime_paths_checked": [
                env("GDS_AGENT_RUNTIME_PATH_DMZ_GATEWAY_CLIENT", "/runtime/opcua-dmz-gateway/pki/southbound"),
            ],
        },
        "dmz-gateway-server": {
            "target": "dmz-gateway-server",
            "application_uri": env("GDS_AGENT_APPLICATION_URI_DMZ_GATEWAY_SERVER", "urn:dataprotect:opcua:dmz-gateway-server"),
            "runtime_instance_id": env("GDS_AGENT_RUNTIME_INSTANCE_ID_DMZ_GATEWAY_SERVER", "urn:dataprotect:opcua:dmz-gateway-server"),
            "profile_name": "open62541-server",
            "component_type": "server",
            "common_name": "DMZGatewayServer",
            "artifact_zone": "DMZ",
            "artifact_role": "northbound-server",
            "layout_kind": "open62541-dmz-gateway-server",
            "runtime_root": env("GDS_AGENT_RUNTIME_PATH_DMZ_GATEWAY_SERVER", "/runtime/opcua-dmz-gateway/pki/northbound"),
            "trusted_certs_dir": "trusted/certs",
            "trusted_crl_dir": "trusted/crl",
            "issuer_certs_dir": "issuer/certs",
            "issuer_crl_dir": "issuer/crl",
            "rejected_dir": "rejected/certs",
            "runtime_paths_checked": [
                env("GDS_AGENT_RUNTIME_PATH_DMZ_GATEWAY_SERVER", "/runtime/opcua-dmz-gateway/pki/northbound"),
            ],
        },
    }
    return catalog


def resolve_runtime_targets(agent_zone: str, configured_targets: list[str]) -> list[dict[str, Any]]:
    catalog = build_runtime_target_catalog(agent_zone)
    resolved: list[dict[str, Any]] = []
    for target in configured_targets:
        cfg = catalog.get(target)
        if cfg:
            resolved.append(cfg)
    return resolved


def _target_zone(target_cfg: dict[str, Any]) -> str:
    return str(target_cfg.get("artifact_zone") or "").strip().upper()


def target_managed_by_agent_zone(target_cfg: dict[str, Any], agent_zone: str) -> bool:
    return _target_zone(target_cfg) == str(agent_zone or "").strip().upper()


def unmanaged_configured_targets(agent_zone: str, configured_targets: list[str]) -> list[dict[str, str]]:
    catalog = build_runtime_target_catalog(agent_zone)
    out: list[dict[str, str]] = []
    for target in configured_targets:
        cfg = catalog.get(target)
        if cfg and not target_managed_by_agent_zone(cfg, agent_zone):
            out.append({"target": target, "target_zone": _target_zone(cfg), "agent_zone": str(agent_zone or "").strip().upper()})
    return out


def lookup_managed_runtime_target(agent_zone: str, runtime_targets: list[dict[str, Any]], target: str) -> tuple[dict[str, Any] | None, str]:
    target = str(target or "").strip()
    if not target:
        return None, "target_required"
    for cfg in runtime_targets:
        if str(cfg.get("target")) == target:
            if not target_managed_by_agent_zone(cfg, agent_zone):
                return None, "target_not_managed_by_agent_zone"
            return cfg, ""
    catalog_cfg = build_runtime_target_catalog(agent_zone).get(target)
    if catalog_cfg and not target_managed_by_agent_zone(catalog_cfg, agent_zone):
        return None, "target_not_managed_by_agent_zone"
    return None, "target_not_configured"


def infer_runtime_target_for_package(manifest: dict[str, Any], runtime_targets: list[dict[str, Any]]) -> dict[str, Any] | None:
    application_uri = str(manifest.get("application_uri") or "").strip()
    if application_uri:
        for target in runtime_targets:
            if str(target.get("application_uri") or "").strip() == application_uri:
                return target
        return None
    profile = str(manifest.get("profile_name", "")).lower()
    component_type = str(manifest.get("component_type", "")).lower()
    preferred = ""
    if profile == "node-opcua-client" or (profile.startswith("node-opcua") and component_type == "client"):
        preferred = "fuxa"
    elif profile == "open62541-server" or (profile.startswith("open62541") and component_type == "server"):
        preferred = "opcua-server"
    for target in runtime_targets:
        if str(target.get("target")) == preferred:
            return target
    return None


def parse_time_hhmm(raw: str) -> time_of_day | None:
    try:
        hh, mm = raw.split(":", 1)
        return time_of_day(hour=int(hh), minute=int(mm))
    except Exception:
        return None


def parse_weekday(raw: str) -> int | None:
    table = {
        "mon": 0,
        "monday": 0,
        "tue": 1,
        "tuesday": 1,
        "wed": 2,
        "wednesday": 2,
        "thu": 3,
        "thursday": 3,
        "fri": 4,
        "friday": 4,
        "sat": 5,
        "saturday": 5,
        "sun": 6,
        "sunday": 6,
    }
    return table.get(str(raw).strip().lower())


def _parse_blackout_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    start_raw = str(item.get("start_at", item.get("start", ""))).strip()
    end_raw = str(item.get("end_at", item.get("end", ""))).strip()
    if not start_raw or not end_raw:
        return None
    try:
        start_dt = parse_rfc3339_utc(start_raw)
        end_dt = parse_rfc3339_utc(end_raw)
    except Exception:
        return None
    if end_dt <= start_dt:
        return None
    return {
        "name": str(item.get("name", "unnamed")).strip() or "unnamed",
        "start_at": start_dt.isoformat().replace("+00:00", "Z"),
        "end_at": end_dt.isoformat().replace("+00:00", "Z"),
    }


def _parse_window_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    start_raw = str(item.get("start", item.get("start_at", ""))).strip()
    end_raw = str(item.get("end", item.get("end_at", ""))).strip()
    if "T" in start_raw and "T" in end_raw:
        try:
            start_dt = parse_rfc3339_utc(start_raw)
            end_dt = parse_rfc3339_utc(end_raw)
        except Exception:
            return None
        if end_dt <= start_dt:
            return None
        return {
            "start_at": start_dt.isoformat().replace("+00:00", "Z"),
            "end_at": end_dt.isoformat().replace("+00:00", "Z"),
            "id": str(item.get("id", item.get("name", "unnamed"))).strip() or "unnamed",
            "reason": str(item.get("reason", "")).strip(),
        }

    start = parse_time_hhmm(start_raw)
    end = parse_time_hhmm(end_raw)
    days_raw = item.get("days", [])
    if not start or not end or not isinstance(days_raw, list):
        return None
    days: list[int] = []
    for d in days_raw:
        wd = parse_weekday(str(d))
        if wd is not None:
            days.append(wd)
    if not days:
        return None
    return {"start": start, "end": end, "days": sorted(set(days))}


def _default_target_policy(target: str) -> dict[str, Any]:
    base = {
        "maintenance_window_required": True,
        "approval_level": "single",
        "emergency_override_allowed": False,
        "auto_rollback_enabled": True,
    }
    if target == "opcua-server":
        base["approval_level"] = "dual"
        return base
    if target == "fuxa":
        base["approval_level"] = "single"
        base["emergency_override_allowed"] = True
        return base
    if target.startswith("dmz-gateway"):
        base["maintenance_window_required"] = False
        base["approval_level"] = "single"
        base["emergency_override_allowed"] = True
        return base
    return base


def load_maintenance_policy(path: Path, default_timezone: str) -> dict[str, Any]:
    if not path.exists():
        return {
            "timezone": default_timezone,
            "targets": {},
            "global_blackouts": [],
        }
    raw = json.loads(path.read_text(encoding="utf-8"))
    tz_name = str(raw.get("timezone", default_timezone)).strip() or default_timezone
    targets: dict[str, dict[str, Any]] = {}
    global_blackouts: list[dict[str, Any]] = []
    for entry in raw.get("blackouts", []):
        if isinstance(entry, dict):
            parsed = _parse_blackout_entry(entry)
            if parsed:
                global_blackouts.append(parsed)

    # Backward-compatible v1 list: {"windows":[{"target":"...","days":[],"start":"..","end":".."}]}
    for item in raw.get("windows", []):
        if not isinstance(item, dict):
            continue
        target = str(item.get("target", "")).strip()
        if not target:
            continue
        win = _parse_window_entry(item)
        if not win:
            continue
        target_obj = targets.setdefault(
            target,
            {
                "target": target,
                "windows": [],
                "blackouts": [],
                "policy": _default_target_policy(target),
            },
        )
        target_obj["windows"].append(win)

    # Preferred v2 list: {"targets":[{"target":"...","windows":[...],"blackouts":[...],"policy":{...}}]}
    for item in raw.get("targets", []):
        if not isinstance(item, dict):
            continue
        target = str(item.get("target", "")).strip()
        if not target:
            continue
        target_obj = targets.setdefault(
            target,
            {
                "target": target,
                "windows": [],
                "blackouts": [],
                "policy": _default_target_policy(target),
            },
        )
        if isinstance(item.get("windows"), list):
            for win_item in item["windows"]:
                if isinstance(win_item, dict):
                    parsed = _parse_window_entry(win_item)
                    if parsed:
                        target_obj["windows"].append(parsed)
        if isinstance(item.get("blackouts"), list):
            for bo_item in item["blackouts"]:
                if isinstance(bo_item, dict):
                    parsed = _parse_blackout_entry(bo_item)
                    if parsed:
                        target_obj["blackouts"].append(parsed)

        policy_raw = item.get("policy", {})
        if isinstance(policy_raw, dict):
            policy = dict(target_obj["policy"])
            if "maintenance_window_required" in policy_raw:
                policy["maintenance_window_required"] = bool(policy_raw.get("maintenance_window_required"))
            if "emergency_override_allowed" in policy_raw:
                policy["emergency_override_allowed"] = bool(policy_raw.get("emergency_override_allowed"))
            if "auto_rollback_enabled" in policy_raw:
                policy["auto_rollback_enabled"] = bool(policy_raw.get("auto_rollback_enabled"))
            approval_level = str(policy_raw.get("approval_level", policy["approval_level"])).strip().lower()
            if approval_level in {"single", "dual"}:
                policy["approval_level"] = approval_level
            target_obj["policy"] = policy

    # Optional policy overrides map: {"target_policies":{"opcua-server":{"approval_level":"dual"}}}
    target_policy_map = raw.get("target_policies", {})
    if isinstance(target_policy_map, dict):
        for target, policy_raw in target_policy_map.items():
            if not isinstance(policy_raw, dict):
                continue
            target = str(target).strip()
            if not target:
                continue
            target_obj = targets.setdefault(
                target,
                {
                    "target": target,
                    "windows": [],
                    "blackouts": [],
                    "policy": _default_target_policy(target),
                },
            )
            policy = dict(target_obj["policy"])
            if "maintenance_window_required" in policy_raw:
                policy["maintenance_window_required"] = bool(policy_raw.get("maintenance_window_required"))
            if "emergency_override_allowed" in policy_raw:
                policy["emergency_override_allowed"] = bool(policy_raw.get("emergency_override_allowed"))
            if "auto_rollback_enabled" in policy_raw:
                policy["auto_rollback_enabled"] = bool(policy_raw.get("auto_rollback_enabled"))
            approval_level = str(policy_raw.get("approval_level", policy["approval_level"])).strip().lower()
            if approval_level in {"single", "dual"}:
                policy["approval_level"] = approval_level
            target_obj["policy"] = policy

    return {
        "timezone": tz_name,
        "targets": targets,
        "global_blackouts": global_blackouts,
    }


def maintenance_window_status(target: str, policy: dict[str, Any]) -> dict[str, Any]:
    targets = policy.get("targets", {}) if isinstance(policy, dict) else {}
    target_obj = targets.get(target, {})
    windows = target_obj.get("windows", []) if isinstance(target_obj, dict) else []
    target_blackouts = target_obj.get("blackouts", []) if isinstance(target_obj, dict) else []
    global_blackouts = policy.get("global_blackouts", []) if isinstance(policy, dict) else []
    target_policy = target_obj.get("policy", _default_target_policy(target)) if isinstance(target_obj, dict) else _default_target_policy(target)
    tz_name = str(policy.get("timezone", "UTC")) if isinstance(policy, dict) else "UTC"
    try:
        tzinfo = ZoneInfo(tz_name)
    except Exception:
        tz_name = "UTC"
        tzinfo = timezone.utc

    now_utc = utc_now()
    now_local = now_utc.astimezone(tzinfo)
    wd = now_local.weekday()
    tod = now_local.time().replace(second=0, microsecond=0)

    active_blackout = None
    for bo in [*global_blackouts, *target_blackouts]:
        try:
            start = parse_rfc3339_utc(str(bo.get("start_at", "")))
            end = parse_rfc3339_utc(str(bo.get("end_at", "")))
        except Exception:
            continue
        if start <= now_utc <= end:
            active_blackout = bo
            break

    within_window = False
    for w in windows:
        if "start_at" in w and "end_at" in w:
            try:
                start_at = parse_rfc3339_utc(str(w.get("start_at", "")))
                end_at = parse_rfc3339_utc(str(w.get("end_at", "")))
            except Exception:
                continue
            within_window = start_at <= now_utc <= end_at
            if within_window:
                break
            continue
        if wd not in w["days"]:
            continue
        start: time_of_day = w["start"]
        end: time_of_day = w["end"]
        if start <= end:
            within_window = start <= tod <= end
        else:
            within_window = tod >= start or tod <= end
        if within_window:
            break

    if active_blackout:
        status = "blackout"
    elif not windows:
        status = "not_configured"
    elif within_window:
        status = "open"
    else:
        status = "closed"
    return {
        "status": status,
        "within_window": within_window,
        "within_blackout": bool(active_blackout),
        "active_blackout_name": (active_blackout or {}).get("name"),
        "timezone": tz_name,
        "window_required": bool(target_policy.get("maintenance_window_required", True)),
        "emergency_override_allowed": bool(target_policy.get("emergency_override_allowed", False)),
        "policy": target_policy,
    }


class ApprovalSigner:
    def __init__(self, key_path: Path, key_id: str):
        self.key_path = key_path
        self.key_id = key_id
        self.private_key = self._load_or_create_private_key()
        self.public_key = self.private_key.public_key()
        pub_der = self.public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint_sha256 = hashlib.sha256(pub_der).hexdigest()

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            raw = self.key_path.read_bytes()
            loaded = serialization.load_pem_private_key(raw, password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError("approval signing key is not ed25519")
            return loaded

        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        atomic_write_bytes(self.key_path, pem)
        return key

    def sign(self, approval_payload: dict[str, Any]) -> dict[str, Any]:
        canonical = canonical_json_bytes(canonical_approval_payload(approval_payload))
        signature = self.private_key.sign(canonical)
        out = dict(approval_payload)
        out["signature"] = {
            "algorithm": "ed25519",
            "key_id": self.key_id,
            "fingerprint_sha256": self.fingerprint_sha256,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        return out

    def verify(self, approval_record: dict[str, Any]) -> tuple[bool, str]:
        sig_meta = approval_record.get("signature")
        if not isinstance(sig_meta, dict):
            return False, "approval_signature_missing"
        if str(sig_meta.get("algorithm", "")).lower() != "ed25519":
            return False, "approval_signature_unsupported"
        if str(sig_meta.get("key_id", "")).strip() != self.key_id:
            return False, "approval_signature_key_id_mismatch"
        fp = str(sig_meta.get("fingerprint_sha256", "")).strip().lower()
        if fp != self.fingerprint_sha256.lower():
            return False, "approval_signature_fingerprint_mismatch"
        sig_b64 = str(sig_meta.get("signature_base64", "")).strip()
        if not sig_b64:
            return False, "approval_signature_missing_bytes"
        try:
            sig_bytes = base64.b64decode(sig_b64)
            canonical = canonical_json_bytes(canonical_approval_payload(approval_record))
            self.public_key.verify(sig_bytes, canonical)
        except InvalidSignature:
            return False, "approval_signature_invalid"
        except Exception:
            return False, "approval_signature_malformed"
        return True, ""


def canonical_approval_payload(approval_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": approval_payload.get("schema"),
        "schema_version": approval_payload.get("schema_version"),
        "approval_id": approval_payload.get("approval_id"),
        "created_at": approval_payload.get("created_at"),
        "expires_at": approval_payload.get("expires_at"),
        "target": approval_payload.get("target"),
        "plan_id": approval_payload.get("plan_id"),
        "operator": approval_payload.get("operator"),
        "decision": approval_payload.get("decision"),
        "reason": approval_payload.get("reason"),
        "approval_level": approval_payload.get("approval_level"),
        "emergency_override": approval_payload.get("emergency_override"),
        "policy_snapshot": approval_payload.get("policy_snapshot"),
    }


def load_valid_approvals_for_target(approvals_dir: Path, target: str, signer: ApprovalSigner) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not approvals_dir.exists():
        return out
    for file in sorted(approvals_dir.glob("*.json"), reverse=True):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(payload.get("target", "")) != target:
            continue
        if str(payload.get("decision", "")).lower() != "approve":
            continue
        ok, _err = signer.verify(payload)
        if not ok:
            continue
        expires_at = str(payload.get("expires_at", "")).strip()
        if not expires_at:
            continue
        try:
            if parse_rfc3339_utc(expires_at) <= utc_now():
                continue
        except Exception:
            continue
        out.append(payload)
    return out


def load_active_approval_for_target(
    approvals_dir: Path,
    target: str,
    signer: ApprovalSigner,
    required_level: str,
) -> tuple[dict[str, Any] | None, str]:
    approvals = load_valid_approvals_for_target(approvals_dir, target, signer)
    if required_level == "dual":
        unique_ops = sorted(
            set(
                str(a.get("operator", "")).strip()
                for a in approvals
                if str(a.get("operator", "")).strip()
            )
        )
        if len(unique_ops) >= 2:
            return {
                "approval_id": ",".join([str(a.get("approval_id", "")) for a in approvals[:2]]),
                "operators": unique_ops[:2],
                "emergency_override": any(bool(a.get("emergency_override")) for a in approvals),
                "count": len(unique_ops),
            }, "approved_dual"
        return None, "required_missing_dual"

    if approvals:
        a = approvals[0]
        return {
            "approval_id": a.get("approval_id"),
            "operators": [a.get("operator")],
            "emergency_override": bool(a.get("emergency_override")),
            "count": 1,
        }, "approved_single"
    return None, "required_missing_single"


def find_latest_json_for_target(base_dir: Path, target: str) -> tuple[Path | None, dict[str, Any] | None]:
    target_dir = base_dir / target
    if not target_dir.exists():
        return None, None
    files = sorted(target_dir.glob("*.json"))
    if not files:
        return None, None
    latest = files[-1]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return latest, None
    return latest, payload


def evaluate_runtime_compatibility(target_cfg: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    runtime_paths_checked = [str(p) for p in target_cfg.get("runtime_paths_checked", [])]
    path_checks: list[dict[str, Any]] = []
    existing_count = 0
    for raw_path in runtime_paths_checked:
        path = Path(raw_path)
        exists = path.exists()
        if exists:
            existing_count += 1
        path_checks.append({"path": raw_path, "exists": exists})

    if artifact.get("zone") != target_cfg.get("artifact_zone"):
        issues.append("artifact_zone_mismatch")
    if artifact.get("role") != target_cfg.get("artifact_role"):
        issues.append("artifact_role_mismatch")
    if "BEGIN CERTIFICATE" not in str(artifact.get("ca_chain_pem", "")):
        issues.append("ca_chain_missing")
    if not isinstance(artifact.get("certificates"), list):
        issues.append("certificates_malformed")

    if issues:
        status = "INCOMPATIBLE"
    elif existing_count == 0:
        status = "PREVIEW_ONLY"
    else:
        status = "COMPATIBLE"

    return {
        "status": status,
        "issues": issues,
        "runtime_paths_checked": path_checks,
    }


def compute_would_keep(previous: dict | None, current: dict) -> list[dict[str, Any]]:
    if not previous:
        return []
    prev_certs = previous.get("certificates", []) if isinstance(previous.get("certificates"), list) else []
    cur_certs = current.get("certificates", []) if isinstance(current.get("certificates"), list) else []
    prev_idx, _ = build_cert_index(prev_certs)
    cur_idx, _ = build_cert_index(cur_certs)
    keep: list[dict[str, Any]] = []
    for app_uri in sorted(set(prev_idx.keys()).intersection(cur_idx.keys())):
        before = prev_idx[app_uri]
        after = cur_idx[app_uri]
        if (
            str(before.get("fingerprint_sha256", "")).lower() == str(after.get("fingerprint_sha256", "")).lower()
            and before.get("common_name") == after.get("common_name")
            and before.get("not_after") == after.get("not_after")
        ):
            keep.append(cert_view(after))
    return keep


def write_json_artifact(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=True, indent=2))


def build_rollback_bundle_metadata(target_cfg: dict[str, Any], rollback_dir: Path) -> dict[str, Any]:
    rollback_dir.mkdir(parents=True, exist_ok=True)
    bundle_id = uuid4().hex
    created_at = iso_now_z()
    path_meta: list[dict[str, Any]] = []
    any_exists = False
    for p in target_cfg.get("runtime_paths_checked", []):
        exists = Path(str(p)).exists()
        any_exists = any_exists or exists
        path_meta.append(
            {
                "path": str(p),
                "exists": exists,
                "snapshot_mode": "metadata_only",
            }
        )
    bundle = {
        "bundle_id": bundle_id,
        "created_at": created_at,
        "target": target_cfg.get("target"),
        "mode": "metadata_only",
        "runtime_paths": path_meta,
        "has_live_runtime_mount": any_exists,
    }
    write_json_artifact(rollback_dir / f"{created_at.replace(':', '').replace('-', '')}_{bundle_id}.json", bundle)
    return bundle


def load_previous_preview_payload(runtime_preview_dir: Path, target: str) -> dict[str, Any] | None:
    _latest_path, latest = find_latest_json_for_target(runtime_preview_dir, target)
    if not latest:
        return None
    artifact_snapshot = latest.get("artifact_snapshot")
    if isinstance(artifact_snapshot, dict):
        return artifact_snapshot
    return None


def create_signed_approval_file(
    *,
    approvals_dir: Path,
    signer: ApprovalSigner,
    target: str,
    operator: str,
    decision: str,
    reason: str,
    expires_in_minutes: int,
    approval_level: str,
    emergency_override: bool,
    policy_snapshot: dict[str, Any],
    plan_id: str,
) -> dict[str, Any]:
    approval_id = uuid4().hex
    created_at = iso_now_z()
    expires_at = (utc_now() + timedelta(minutes=max(1, expires_in_minutes))).isoformat().replace("+00:00", "Z")
    payload = {
        "schema": "labshock_approval_v1",
        "schema_version": 1,
        "approval_id": approval_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "target": target,
        "plan_id": plan_id or "",
        "operator": operator,
        "decision": decision,
        "reason": reason,
        "approval_level": approval_level,
        "emergency_override": emergency_override,
        "policy_snapshot": policy_snapshot,
    }
    signed = signer.sign(payload)
    file_name = f"{created_at.replace(':', '').replace('-', '')}_{approval_id}.json"
    write_json_artifact(approvals_dir / file_name, signed)
    return signed


def evaluate_activation_gate(
    *,
    target_cfg: dict[str, Any],
    preview: dict[str, Any],
    approval_required: bool,
    approval_summary: dict[str, Any] | None,
    approval_status: str,
    emergency_override_mode: bool,
) -> dict[str, Any]:
    mw = preview.get("maintenance_window_status", {})
    policy = (mw or {}).get("policy", {})
    window_required = bool((mw or {}).get("window_required", True))
    emergency_allowed = bool((mw or {}).get("emergency_override_allowed", False))
    within_window = bool((mw or {}).get("within_window"))
    within_blackout = bool((mw or {}).get("within_blackout"))
    compatibility_status = str(preview.get("compatibility_status", "INCOMPATIBLE"))
    risk_level = str(preview.get("risk_level", "CRITICAL"))
    override_requested = bool((approval_summary or {}).get("emergency_override", False))

    gate_status = "ready_for_staging"
    blocked_reason = ""
    if compatibility_status == "INCOMPATIBLE" or risk_level == "CRITICAL":
        gate_status = "blocked_incompatible"
        blocked_reason = "runtime_compatibility_failed"
    elif approval_required and not approval_summary:
        gate_status = "blocked_approval_missing"
        blocked_reason = approval_status
    elif within_blackout:
        if emergency_override_mode and emergency_allowed and override_requested:
            gate_status = "emergency_override_ready"
            blocked_reason = "emergency_override_blackout"
        else:
            gate_status = "blocked_blackout"
            blocked_reason = "blackout_period_active"
    elif window_required and not within_window:
        if emergency_override_mode and emergency_allowed and override_requested:
            gate_status = "emergency_override_ready"
            blocked_reason = "emergency_override_window_closed"
        else:
            gate_status = "blocked_window_closed"
            blocked_reason = "maintenance_window_closed"

    return {
        "target": target_cfg.get("target"),
        "status": gate_status,
        "blocked_reason": blocked_reason,
        "window_required": window_required,
        "approval_required": approval_required,
        "approval_status": approval_status,
        "emergency_override_mode": emergency_override_mode,
        "emergency_override_allowed": emergency_allowed,
        "emergency_override_requested": override_requested,
        "within_window": within_window,
        "within_blackout": within_blackout,
        "policy": policy,
        "artifact_version": preview.get("artifact_version"),
        "artifact_revision": preview.get("artifact_revision"),
        "preview_id": preview.get("preview_id"),
        "risk_level": risk_level,
    }


def persist_activation_gate(gate_dir: Path, gate: dict[str, Any]) -> Path:
    target = str(gate.get("target", "unknown"))
    out_dir = gate_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    event_id = uuid4().hex
    payload = {
        "gate_id": event_id,
        "generated_at": iso_now_z(),
        **gate,
        "runtime_write_enabled": False,
    }
    file_name = f"{payload['generated_at'].replace(':', '').replace('-', '')}_{event_id}.json"
    out_path = out_dir / file_name
    write_json_artifact(out_path, payload)
    return out_path


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pem_cert_to_der(pem_text: str) -> bytes:
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)


def _split_pem_chain(pem_text: str) -> list[str]:
    certs: list[str] = []
    marker_begin = "-----BEGIN CERTIFICATE-----"
    marker_end = "-----END CERTIFICATE-----"
    remaining = pem_text
    while marker_begin in remaining and marker_end in remaining:
        start = remaining.index(marker_begin)
        end = remaining.index(marker_end) + len(marker_end)
        certs.append(remaining[start:end] + "\n")
        remaining = remaining[end:]
    return certs


def _parse_cert_file_metadata(path: Path) -> dict[str, Any] | None:
    raw = path.read_bytes()
    cert = None
    try:
        if b"-----BEGIN CERTIFICATE-----" in raw:
            cert = x509.load_pem_x509_certificate(raw)
        else:
            cert = x509.load_der_x509_certificate(raw)
    except Exception:
        return None
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }


def _is_private_key_path(path: Path, relative_path: str | None = None) -> bool:
    rel = (relative_path or str(path)).replace("\\", "/").lower()
    parts = [p for p in rel.split("/") if p]
    name = path.name.lower()
    if "private" in parts or "keys" in parts:
        return True
    if ".key" in name or "private" in name:
        return True
    return name.endswith(".key.der") or name.endswith(".key.pem")


def _private_key_skip_item(relative_path: str, skipped_reason: str = "private_key_material") -> dict[str, Any]:
    return {
        "relative_path": relative_path,
        "exists": True,
        "type": "private_key",
        "readable": False,
        "skipped_reason": skipped_reason,
    }


def _collect_stage_checksums(root: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        rel = str(file.relative_to(root)).replace("\\", "/")
        checksums[rel] = _file_sha256(file)
    return checksums


def _target_stage_layout(target_cfg: dict[str, Any]) -> dict[str, str]:
    return {
        "trusted_certs_dir": str(target_cfg.get("trusted_certs_dir", "trusted/certs")),
        "trusted_crl_dir": str(target_cfg.get("trusted_crl_dir", "trusted/crl")),
        "issuer_certs_dir": str(target_cfg.get("issuer_certs_dir", "issuers/certs")),
        "issuer_crl_dir": str(target_cfg.get("issuer_crl_dir", "issuers/crl")),
        "rejected_dir": str(target_cfg.get("rejected_dir", "rejected")),
    }


def inspect_current_runtime_readonly(target_cfg: dict[str, Any]) -> dict[str, Any]:
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    if not runtime_root.exists() or not runtime_root.is_dir():
        return {
            "current_runtime_status": "unavailable",
            "runtime_root": str(runtime_root),
            "files": [],
            "warnings": ["runtime_root_unavailable"],
        }

    files: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in sorted(runtime_root.rglob("*")):
        rel = str(path.relative_to(runtime_root)).replace("\\", "/")
        try:
            if not path.is_file():
                continue
        except PermissionError:
            if _is_private_key_path(path, rel):
                files.append(_private_key_skip_item(rel))
                warnings.append("private_key_material_skipped_permission_denied")
            else:
                files.append(
                    {
                        "relative_path": rel,
                        "exists": True,
                        "readable": False,
                        "skipped_reason": "permission_denied",
                    }
                )
                warnings.append("runtime_file_permission_denied")
            continue

        if _is_private_key_path(path, rel):
            files.append(_private_key_skip_item(rel))
            warnings.append("private_key_material_skipped")
            continue

        item: dict[str, Any] = {"relative_path": rel, "exists": True, "readable": True}
        try:
            item["size_bytes"] = path.stat().st_size
            item["sha256"] = _file_sha256(path)
            cert_meta = _parse_cert_file_metadata(path)
            if cert_meta:
                item["certificate"] = cert_meta
        except PermissionError:
            item["readable"] = False
            item["skipped_reason"] = "permission_denied"
            warnings.append("runtime_file_permission_denied")
        except OSError as exc:
            item["readable"] = False
            item["skipped_reason"] = f"os_error:{exc.__class__.__name__}"
            warnings.append("runtime_file_inspection_error")
        files.append(item)

    if not files:
        warnings.append("runtime_root_empty")
    return {
        "current_runtime_status": "available",
        "runtime_root": str(runtime_root),
        "files": files,
        "warnings": warnings,
    }


def build_inventory_drift_report(
    *,
    trust_dir: Path,
    runtime_targets: list[dict[str, Any]],
    sync_cycle_id: str,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for target_cfg in runtime_targets:
        zone = str(target_cfg.get("artifact_zone", ""))
        role = str(target_cfg.get("artifact_role", ""))
        target = str(target_cfg.get("target", "unknown"))
        artifact = load_json_if_exists(trust_dir / f"{zone}_{role}.json")
        if not artifact:
            items.append({"type": "gds_artifact_missing_cache", "target": target, "zone": zone, "role": role})
            continue

        gds_certs = artifact.get("certificates", []) if isinstance(artifact.get("certificates"), list) else []
        gds_by_fp = {
            str(cert.get("fingerprint_sha256", "")).lower(): cert
            for cert in gds_certs
            if isinstance(cert, dict) and cert.get("fingerprint_sha256")
        }
        runtime = inspect_current_runtime_readonly(target_cfg)
        runtime_files = runtime.get("files", []) if isinstance(runtime.get("files"), list) else []
        runtime_by_fp: dict[str, dict[str, Any]] = {}
        for entry in runtime_files:
            if not isinstance(entry, dict):
                continue
            cert_meta = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else None
            if cert_meta and cert_meta.get("fingerprint_sha256"):
                runtime_by_fp[str(cert_meta["fingerprint_sha256"]).lower()] = entry

        for fp, cert in gds_by_fp.items():
            if fp not in runtime_by_fp:
                items.append(
                    {
                        "type": "gds_cert_missing_runtime",
                        "target": target,
                        "zone": zone,
                        "role": role,
                        "application_uri": cert.get("application_uri"),
                        "common_name": cert.get("common_name"),
                        "fingerprint_sha256": fp,
                        "artifact_revision": artifact.get("artifact_revision"),
                    }
                )

        for fp, entry in runtime_by_fp.items():
            if fp not in gds_by_fp:
                items.append(
                    {
                        "type": "runtime_cert_unknown",
                        "target": target,
                        "zone": zone,
                        "role": role,
                        "relative_path": entry.get("relative_path"),
                        "fingerprint_sha256": fp,
                        "subject": (entry.get("certificate") or {}).get("subject") if isinstance(entry.get("certificate"), dict) else None,
                    }
                )

    return {
        "drift_id": uuid4().hex,
        "generated_at": format_rfc3339_utc(),
        "sync_cycle_id": sync_cycle_id,
        "status": "drift_detected" if items else "ok",
        "drift_count": len(items),
        "items": items,
    }


def persist_and_forward_inventory_drift(
    *,
    log: logging.Logger,
    trust_dir: Path,
    inventory_drift_dir: Path,
    runtime_targets: list[dict[str, Any]],
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    sync_cycle_id: str,
) -> dict[str, Any]:
    report = build_inventory_drift_report(trust_dir=trust_dir, runtime_targets=runtime_targets, sync_cycle_id=sync_cycle_id)
    path = inventory_drift_dir / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['drift_id']}.json"
    write_json_artifact(path, report)
    if report["drift_count"]:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "pki_validation",
            "certificate_inventory_drift_detected",
            {"sync_cycle_id": sync_cycle_id, "drift_count": report["drift_count"], "report_path": str(path)},
            {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "diff_id": report["drift_id"], "risk_level": "MEDIUM"},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
        for item in report["items"][:25]:
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "warning",
                "pki_validation",
                str(item.get("type", "certificate_inventory_drift_detected")),
                {"sync_cycle_id": sync_cycle_id, **item},
                {
                    "sync_cycle_id": sync_cycle_id,
                    "correlation_id": sync_cycle_id,
                    "diff_id": report["drift_id"],
                    "risk_level": "MEDIUM",
                    "application_uri": str(item.get("application_uri", "")),
                    "mtls_fingerprint_sha256": str(item.get("fingerprint_sha256", "")),
                    "trustlist_zone": str(item.get("zone", "")),
                    "trustlist_role": str(item.get("role", "")),
                    "artifact_revision": str(item.get("artifact_revision", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
    return report


def _write_target_stage_material(root: Path, target_cfg: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    layout = _target_stage_layout(target_cfg)
    trusted_dir = root / layout["trusted_certs_dir"]
    trusted_crl_dir = root / layout["trusted_crl_dir"]
    issuer_dir = root / layout["issuer_certs_dir"]
    issuer_crl_dir = root / layout["issuer_crl_dir"]
    rejected_dir = root / layout["rejected_dir"]
    for directory in [trusted_dir, trusted_crl_dir, issuer_dir, issuer_crl_dir, rejected_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    written: list[dict[str, Any]] = []
    ca_chain = str(artifact.get("ca_chain_pem", ""))
    if ca_chain:
        atomic_write_text(issuer_dir / "ca-chain.pem", ca_chain)
        atomic_write_text(trusted_dir / "ca-chain.pem", ca_chain)
        written.append({"relative_path": str((issuer_dir / "ca-chain.pem").relative_to(root)).replace("\\", "/"), "source": "ca_chain"})
        written.append({"relative_path": str((trusted_dir / "ca-chain.pem").relative_to(root)).replace("\\", "/"), "source": "ca_chain"})
        chain = _split_pem_chain(ca_chain)
        for idx, pem in enumerate(chain, start=1):
            name = f"ca-chain-{idx}.der"
            der = _pem_cert_to_der(pem)
            atomic_write_bytes(issuer_dir / name, der)
            atomic_write_bytes(trusted_dir / name, der)
            written.append({"relative_path": str((issuer_dir / name).relative_to(root)).replace("\\", "/"), "source": "ca_chain_der"})
            written.append({"relative_path": str((trusted_dir / name).relative_to(root)).replace("\\", "/"), "source": "ca_chain_der"})
        if chain:
            root_der = _pem_cert_to_der(chain[-1])
            inter_der = _pem_cert_to_der(chain[0])
            aliases = [
                (trusted_dir / "labshock_root_ca.der", root_der, "root_ca_alias"),
                (trusted_dir / "labshock_intermediate_ca.der", inter_der, "intermediate_ca_alias"),
            ]
            for path, data, source in aliases:
                atomic_write_bytes(path, data)
                written.append({"relative_path": str(path.relative_to(root)).replace("\\", "/"), "source": source})

    crl_bundle = artifact.get("crl_bundle") if isinstance(artifact.get("crl_bundle"), dict) else {}
    crl_items = [
        ("root_ca", str(crl_bundle.get("root_crl_base64") or "")),
        ("vault_intermediate", str(crl_bundle.get("intermediate_crl_base64") or artifact.get("crl_base64") or "")),
    ]
    compat_crl_dir = root / "ApplCerts/issuers/crl" if str(layout.get("trusted_certs_dir", "")).startswith("ApplCerts/") else None
    if compat_crl_dir:
        compat_crl_dir.mkdir(parents=True, exist_ok=True)
    for alias, crl_base64 in crl_items:
        if not crl_base64:
            continue
        crl_bytes = base64.b64decode(crl_base64)
        for directory in [issuer_crl_dir, trusted_crl_dir] + ([compat_crl_dir] if compat_crl_dir else []):
            if directory is None:
                continue
            path = directory / f"{alias}.crl"
            if directory == compat_crl_dir:
                if optional_atomic_write_bytes(path, crl_bytes):
                    written.append({"relative_path": str(path.relative_to(root)).replace("\\", "/"), "source": f"{alias}_crl_compat"})
            else:
                atomic_write_bytes(path, crl_bytes)
                written.append({"relative_path": str(path.relative_to(root)).replace("\\", "/"), "source": f"{alias}_crl"})
        if alias == "vault_intermediate":
            atomic_write_bytes(issuer_crl_dir / "current.crl", crl_bytes)
            atomic_write_bytes(trusted_crl_dir / "current.crl", crl_bytes)
            written.append({"relative_path": str((issuer_crl_dir / "current.crl").relative_to(root)).replace("\\", "/"), "source": "crl"})
            written.append({"relative_path": str((trusted_crl_dir / "current.crl").relative_to(root)).replace("\\", "/"), "source": "crl"})

    certs = artifact.get("certificates", []) if isinstance(artifact.get("certificates"), list) else []
    for cert in certs:
        fp = str(cert.get("fingerprint_sha256", uuid4().hex)).lower()
        cn = str(cert.get("common_name", "peer")).replace("/", "_").replace("\\", "_").replace(" ", "_")
        pem = str(cert.get("pem", ""))
        if not pem:
            continue
        pem_path = trusted_dir / f"{cn}[{fp}].pem"
        der_path = trusted_dir / f"{cn}[{fp}].der"
        atomic_write_text(pem_path, pem)
        atomic_write_bytes(der_path, _pem_cert_to_der(pem))
        written.append({"relative_path": str(pem_path.relative_to(root)).replace("\\", "/"), "source": "allowed_peer_certificate", "fingerprint_sha256": fp})
        written.append({"relative_path": str(der_path.relative_to(root)).replace("\\", "/"), "source": "allowed_peer_certificate_der", "fingerprint_sha256": fp})
    return written


def _write_package_stage_material(root: Path, target_cfg: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    layout = _target_stage_layout(target_cfg)
    layout_kind = str(target_cfg.get("layout_kind", ""))
    install_plan = manifest.get("install_plan") if isinstance(manifest.get("install_plan"), dict) else {}
    target_layout = install_plan.get("target_layout") if isinstance(install_plan.get("target_layout"), dict) else {}
    if layout_kind == "open62541-opcua-server":
        trusted_dir = root / layout["trusted_certs_dir"]
        trusted_crl_dir = root / layout["trusted_crl_dir"]
        issuer_dir = root / layout["issuer_certs_dir"]
        issuer_crl_dir = root / layout["issuer_crl_dir"]
        rejected_dir = root / layout["rejected_dir"]
        app_cert_rel = "ApplCerts/own/certs/server.der"
    else:
        trusted_dir = root / str(target_layout.get("trusted_certs_dir") or layout["trusted_certs_dir"])
        trusted_crl_dir = root / str(target_layout.get("trusted_crl_dir") or layout["trusted_crl_dir"])
        issuer_dir = root / layout["issuer_certs_dir"]
        issuer_crl_dir = root / layout["issuer_crl_dir"]
        rejected_dir = root / layout["rejected_dir"]
        app_cert_rel = str(target_layout.get("application_certificate") or layout["trusted_certs_dir"] + "/application.pem")
    for directory in [trusted_dir, trusted_crl_dir, issuer_dir, issuer_crl_dir, rejected_dir, (root / app_cert_rel).parent]:
        directory.mkdir(parents=True, exist_ok=True)

    written: list[dict[str, Any]] = []
    cert_pem = str(manifest.get("certificate_pem", ""))
    if cert_pem:
        app_cert_path = root / app_cert_rel
        if app_cert_path.suffix.lower() == ".der":
            atomic_write_bytes(app_cert_path, _pem_cert_to_der(cert_pem))
        else:
            atomic_write_text(app_cert_path, cert_pem)
        written.append(
            {
                "relative_path": str(app_cert_path.relative_to(root)).replace("\\", "/"),
                "source": "package_application_certificate",
                "fingerprint_sha256": manifest.get("certificate_fingerprint_sha256"),
            }
        )
        if app_cert_path.suffix.lower() == ".pem":
            der_path = app_cert_path.with_suffix(".der")
            try:
                atomic_write_bytes(der_path, _pem_cert_to_der(cert_pem))
                written.append(
                    {
                        "relative_path": str(der_path.relative_to(root)).replace("\\", "/"),
                        "source": "package_application_certificate_der_preview",
                        "fingerprint_sha256": manifest.get("certificate_fingerprint_sha256"),
                    }
                )
            except Exception:
                pass

    ca_chain = str(manifest.get("ca_chain_pem", ""))
    if ca_chain:
        if layout_kind == "open62541-opcua-server":
            chain_rel = f"{layout['issuer_certs_dir']}/ca-chain.pem"
        else:
            chain_rel = str(target_layout.get("issuer_chain") or "issuers/certs/ca-chain.pem")
        chain_path = root / chain_rel
        chain_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(chain_path, ca_chain)
        atomic_write_text(trusted_dir / "ca-chain.pem", ca_chain)
        written.append({"relative_path": str(chain_path.relative_to(root)).replace("\\", "/"), "source": "package_ca_chain"})
        written.append({"relative_path": str((trusted_dir / "ca-chain.pem").relative_to(root)).replace("\\", "/"), "source": "package_ca_chain"})
        for idx, pem in enumerate(_split_pem_chain(ca_chain), start=1):
            name = f"ca-chain-{idx}.der"
            atomic_write_bytes(chain_path.parent / name, _pem_cert_to_der(pem))
            atomic_write_bytes(trusted_dir / name, _pem_cert_to_der(pem))
            written.append({"relative_path": str((chain_path.parent / name).relative_to(root)).replace("\\", "/"), "source": "package_ca_chain_der"})
            written.append({"relative_path": str((trusted_dir / name).relative_to(root)).replace("\\", "/"), "source": "package_ca_chain_der"})

    crl_base64 = str(manifest.get("crl_base64", ""))
    if crl_base64:
        crl_bytes = base64.b64decode(crl_base64)
        if layout_kind == "open62541-opcua-server":
            crl_rel = f"{layout['issuer_crl_dir']}/current.crl.b64"
        else:
            crl_rel = str(target_layout.get("issuer_crl") or "issuers/crl/current.crl.b64")
        crl_path = root / crl_rel
        crl_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(crl_path, crl_base64)
        atomic_write_bytes(crl_path.with_suffix(".crl"), crl_bytes)
        atomic_write_bytes(trusted_crl_dir / "current.crl", crl_bytes)
        written.append({"relative_path": str(crl_path.relative_to(root)).replace("\\", "/"), "source": "package_crl_base64"})
        written.append({"relative_path": str(crl_path.with_suffix(".crl").relative_to(root)).replace("\\", "/"), "source": "package_crl"})
        written.append({"relative_path": str((trusted_crl_dir / "current.crl").relative_to(root)).replace("\\", "/"), "source": "package_crl"})
    return written


def _classify_runtime_entry(entry: dict[str, Any]) -> str:
    rel = str(entry.get("relative_path", "")).lower()
    cert = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else {}
    subject = str(cert.get("subject", "")).lower()
    haystack = f"{rel} {subject}"
    if "uaexpert" in haystack:
        return "engineering_tool"
    if "fuxa" in haystack:
        return "runtime_local"
    if "gateway_client" in haystack or "gateway" in haystack or "dmz" in haystack:
        return "transitional_gateway"
    if entry.get("type") == "private_key":
        return "runtime_local"
    return "unknown_manual"


def _is_gds_managed_stage_path(path: str) -> bool:
    name = path.replace("\\", "/").lower()
    if "ca-chain" in name or name.endswith("current.crl"):
        return True
    return "[" in name and "]" in name


def _compare_runtime_to_stage(
    current: dict[str, Any],
    staged_checksums: dict[str, str],
    merge_policy: str,
    replace_allowed_paths: set[str] | None = None,
) -> dict[str, Any]:
    current_files = current.get("files", []) if isinstance(current.get("files"), list) else []
    current_map = {}
    current_entries = {}
    replace_allowed_paths = replace_allowed_paths or set()
    for item in current_files:
        rel = str(item.get("relative_path", ""))
        if not rel:
            continue
        current_entries[rel] = item
        if item.get("sha256"):
            current_map[rel] = str(item.get("sha256", ""))
    staged_paths = set(staged_checksums.keys())
    current_paths = set(current_entries.keys())
    proposed_additions = sorted(staged_paths - current_paths)
    proposed_updates: list[str] = []
    managed_prefixes = ("ApplCerts/trusted/", "ApplCerts/issuer/", "trusted/", "issuers/", "issuer/")
    deletion_candidates = sorted(path for path in current_paths - staged_paths if path.startswith(managed_prefixes))
    preserved_runtime_entries: list[dict[str, Any]] = []
    proposed_future_review: list[dict[str, Any]] = []

    for path in sorted(staged_paths.intersection(set(current_map.keys()))):
        if staged_checksums[path] == current_map[path]:
            continue
        entry = current_entries.get(path, {})
        classification = _classify_runtime_entry(entry)
        if path in replace_allowed_paths and not _is_private_key_path(Path(path), path):
            proposed_updates.append(path)
            continue
        if _is_gds_managed_stage_path(path) and classification not in {"runtime_local", "engineering_tool", "transitional_gateway", "unknown_manual"}:
            proposed_updates.append(path)
            continue
        if _is_gds_managed_stage_path(path) and ("ca-chain" in path.lower() or path.lower().endswith("current.crl")):
            proposed_updates.append(path)
            continue
        preserved_runtime_entries.append(
            {
                "relative_path": path,
                "classification": classification,
                "sha256": entry.get("sha256"),
                "reason": "same_path_update_blocked_by_conservative_merge",
            }
        )
        proposed_future_review.append(
            {
                "relative_path": path,
                "classification": classification,
                "review_reason": "same path differs but runtime-local overwrite is blocked",
            }
        )

    for path in deletion_candidates:
        entry = current_entries.get(path, {})
        classification = _classify_runtime_entry(entry)
        payload = {
            "relative_path": path,
            "classification": classification,
            "sha256": entry.get("sha256"),
            "subject": (entry.get("certificate") or {}).get("subject") if isinstance(entry.get("certificate"), dict) else None,
            "reason": "preserved_by_conservative_merge",
        }
        preserved_runtime_entries.append(payload)
        proposed_future_review.append(
            {
                "relative_path": path,
                "classification": classification,
                "review_reason": "runtime entry is not present in signed GDS artifact",
            }
        )

    staged_current_overlap_missing_hash = sorted(path for path in staged_paths.intersection(current_paths) if path not in current_map)
    for path in staged_current_overlap_missing_hash:
        entry = current_entries.get(path, {})
        if entry.get("type") == "private_key":
            preserved_runtime_entries.append(
                {
                    "relative_path": path,
                    "classification": _classify_runtime_entry(entry),
                    "reason": "private_key_never_overwritten",
                }
            )

    files_to_remove: list[str] = []
    if merge_policy == "strict_replace":
        files_to_remove = deletion_candidates

    return {
        "files_to_add": proposed_additions,
        "files_to_replace": proposed_updates,
        "files_to_remove": files_to_remove,
        "preserved_runtime_entries": preserved_runtime_entries,
        "proposed_additions": proposed_additions,
        "proposed_updates": proposed_updates,
        "proposed_future_review": proposed_future_review,
        "deletion_candidates": deletion_candidates,
        "destructive_changes_detected": bool(deletion_candidates),
        "destructive_changes_blocked": bool(deletion_candidates and merge_policy == "conservative_merge"),
        "runtime_entry_classifications": [
            {
                "relative_path": path,
                "classification": "managed_by_gds" if path in staged_paths and _is_gds_managed_stage_path(path) else _classify_runtime_entry(entry),
            }
            for path, entry in sorted(current_entries.items())
        ],
    }


def _find_activation_plan_for_target(plan_dir: Path, target: str, plan_id: str) -> dict[str, Any] | None:
    target_dir = plan_dir / target
    if not target_dir.exists():
        return None
    files = sorted(target_dir.glob("*.json"))
    if plan_id:
        for file in files:
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("plan_id", "")) == plan_id:
                return payload
        return None
    if not files:
        return None
    latest = files[-1]
    try:
        return json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return None


def stage_runtime_activation_dry_run(
    *,
    target_cfg: dict[str, Any],
    plan: dict[str, Any],
    preview: dict[str, Any],
    gate: dict[str, Any],
    stage_root_dir: Path,
    merge_policy: str,
) -> dict[str, Any]:
    target = str(target_cfg["target"])
    plan_id = str(plan.get("plan_id", uuid4().hex))
    stage_dir = stage_root_dir / target / plan_id
    shadow_dir = stage_dir / "shadow-trust-store"
    incoming_dir = stage_dir / "incoming-trust-store"
    shadow_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)

    artifact = preview.get("artifact_snapshot", {})
    current_runtime = inspect_current_runtime_readonly(target_cfg)
    incoming_written = _write_target_stage_material(incoming_dir, target_cfg, artifact)
    shadow_written = _write_target_stage_material(shadow_dir, target_cfg, artifact)

    checksums = {
        "shadow-trust-store": _collect_stage_checksums(shadow_dir),
        "incoming-trust-store": _collect_stage_checksums(incoming_dir),
    }
    checksums_path = stage_dir / "checksums.json"
    write_json_artifact(
        checksums_path,
        {
            "target": target,
            "plan_id": plan_id,
            "generated_at": iso_now_z(),
            "files": checksums,
        },
    )
    verified = _collect_stage_checksums(shadow_dir) == checksums["shadow-trust-store"]
    merge = _compare_runtime_to_stage(
        current_runtime,
        checksums["shadow-trust-store"],
        merge_policy,
    )
    files_to_add = merge["files_to_add"]
    files_to_replace = merge["files_to_replace"]
    files_to_remove = merge["files_to_remove"]

    live_runtime_root = str(target_cfg.get("runtime_root", (target_cfg.get("runtime_paths_checked") or [""])[0]))
    proposed_commands = [
        f"# future only: test -d {live_runtime_root}",
        f"# future only: cp -a {live_runtime_root} {live_runtime_root}.rollback.<plan_id>",
        f"# future only: rsync -a --delete {shadow_dir}/ {live_runtime_root}.next/",
        f"# future only: mv -T {live_runtime_root}.next {live_runtime_root}",
        "# future only: operator-controlled runtime reconnect/restart after validation",
    ]
    swap_plan = {
        "target": target,
        "plan_id": plan_id,
        "mode": "dry_run",
        "merge_policy": merge_policy,
        "current_runtime_path": live_runtime_root,
        "staged_path": str(shadow_dir),
        "runtime_write_enabled": False,
        "runtime_restart_automatic": False,
        "proposed_atomic_strategy": [
            "validate_stage_checksums",
            "prepare_shadow_runtime_tree_as_pki_next",
            "capture_current_runtime_snapshot_reference",
            "operator_runs_atomic_switch_in_future_phase",
            "operator_validates_runtime_health_before_finalize",
            "rollback_pointer_remains_available",
        ],
        "files_to_add": files_to_add,
        "files_to_replace": files_to_replace,
        "files_to_remove": files_to_remove,
        "preserved_runtime_entries": merge["preserved_runtime_entries"],
        "proposed_additions": merge["proposed_additions"],
        "proposed_updates": merge["proposed_updates"],
        "proposed_future_review": merge["proposed_future_review"],
        "deletion_candidates": merge["deletion_candidates"],
        "runtime_entry_classifications": merge["runtime_entry_classifications"],
        "safety_checks_required": [
            "signed_artifact_verified",
            "trust_anchor_verified",
            "approvals_valid",
            "maintenance_window_open",
            "blackout_inactive",
            "stage_checksums_verified",
            "runtime_write_enabled_false_for_phase5_4",
            "conservative_merge_blocks_automatic_deletion",
        ],
        "commands_reference_only": proposed_commands,
    }
    write_json_artifact(stage_dir / "swap-plan.json", swap_plan)

    rollback_pointer = {
        "target": target,
        "plan_id": plan_id,
        "generated_at": iso_now_z(),
        "mode": "dry_run",
        "rollback_bundle_id": plan.get("rollback_bundle_id", ""),
        "current_runtime_snapshot_reference": current_runtime,
        "rollback_strategy": [
            "use_recorded_current_runtime_snapshot_reference",
            "restore_previous_runtime_tree_in_future_controlled_phase",
            "operator_validates_runtime_health_after_rollback",
        ],
        "commands_reference_only": [
            f"# future only: rm -rf {live_runtime_root}.failed.<plan_id>",
            f"# future only: mv {live_runtime_root} {live_runtime_root}.failed.<plan_id>",
            f"# future only: cp -a {live_runtime_root}.rollback.<plan_id> {live_runtime_root}",
            "# future only: operator-controlled reconnect/restart after rollback",
        ],
        "runtime_write_enabled": False,
    }
    write_json_artifact(stage_dir / "rollback-pointer.json", rollback_pointer)

    warnings: list[str] = []
    warnings.extend(current_runtime.get("warnings", []) if isinstance(current_runtime.get("warnings"), list) else [])
    if current_runtime.get("current_runtime_status") == "unavailable":
        warnings.append("current_runtime_readonly_inspection_unavailable")
    if merge["destructive_changes_blocked"]:
        warnings.append("destructive_changes_blocked_by_conservative_merge")
    blocking_reasons: list[str] = []
    if not verified:
        blocking_reasons.append("stage_checksum_verification_failed")
    if str(gate.get("status", "")) not in {"ready_for_staging", "emergency_override_ready"}:
        blocking_reasons.append(str(gate.get("blocked_reason", "activation_gate_not_ready")))

    validation_report = {
        "target": target,
        "plan_id": plan_id,
        "generated_at": iso_now_z(),
        "signed_artifact_verified": True,
        "trust_anchor_verified": True,
        "approvals_valid": str(preview.get("approval_status", "")).startswith("approved") or str(preview.get("approval_status", "")) == "not_required",
        "maintenance_window_status": (preview.get("maintenance_window_status") or {}).get("status"),
        "blackout_status": "active" if (preview.get("maintenance_window_status") or {}).get("within_blackout") else "inactive",
        "emergency_override_status": "active" if gate.get("status") == "emergency_override_ready" else "inactive",
        "runtime_write_enabled": False,
        "dry_run_only": True,
        "merge_policy": merge_policy,
        "destructive_changes_detected": merge["destructive_changes_detected"],
        "destructive_changes_blocked": merge["destructive_changes_blocked"],
        "preserved_runtime_entries_count": len(merge["preserved_runtime_entries"]),
        "target_compatibility": preview.get("compatibility_status"),
        "risk_level": preview.get("risk_level"),
        "current_runtime_status": current_runtime.get("current_runtime_status"),
        "checksum_verified": verified,
        "blocking_reasons": blocking_reasons,
        "warnings": sorted(set(warnings)),
        "recommended_operator_action": (
            "Review generated dry-run bundle and schedule future controlled activation."
            if not blocking_reasons
            else "Resolve blocking reasons before any future activation."
        ),
    }
    write_json_artifact(stage_dir / "validation-report.json", validation_report)

    readme = f"""LabShock OT GDS Agent Phase 5.4 dry-run bundle

Target: {target}
Plan ID: {plan_id}

This directory is a dry-run artifact only.
No live OPC UA or FUXA runtime PKI directory was modified.
No service restart was performed.
No symlink swap was executed.

Files:
- shadow-trust-store/: proposed future trust-store shape.
- incoming-trust-store/: GDS-managed trust material generated from the signed artifact.
- checksums.json: hashes of staged files.
- swap-plan.json: future activation strategy as strings only.
- rollback-pointer.json: future rollback strategy as strings only.
- validation-report.json: operator-facing readiness and warning summary.
"""
    atomic_write_text(stage_dir / "README-DRY-RUN.txt", readme)

    return {
        "target": target,
        "plan_id": plan_id,
        "stage_dir": str(stage_dir),
        "shadow_trust_store_dir": str(shadow_dir),
        "incoming_trust_store_dir": str(incoming_dir),
        "checksums_path": str(checksums_path),
        "checksum_verified": verified,
        "swap_plan_path": str(stage_dir / "swap-plan.json"),
        "rollback_pointer_path": str(stage_dir / "rollback-pointer.json"),
        "validation_report_path": str(stage_dir / "validation-report.json"),
        "readme_path": str(stage_dir / "README-DRY-RUN.txt"),
        "current_runtime_status": current_runtime.get("current_runtime_status"),
        "files_to_add_count": len(files_to_add),
        "files_to_replace_count": len(files_to_replace),
        "files_to_remove_count": len(files_to_remove),
        "merge_policy": merge_policy,
        "preserved_runtime_entries": merge["preserved_runtime_entries"],
        "preserved_runtime_entries_count": len(merge["preserved_runtime_entries"]),
        "deletion_candidates": merge["deletion_candidates"],
        "destructive_changes_detected": merge["destructive_changes_detected"],
        "destructive_changes_blocked": merge["destructive_changes_blocked"],
        "warnings": validation_report["warnings"],
        "blocking_reasons": blocking_reasons,
        "incoming_written": incoming_written,
        "shadow_written": shadow_written,
        "runtime_write_enabled": False,
        "runtime_restart_automatic": False,
    }


def load_cached_package_manifest(package_dir: Path, package_id: str) -> dict[str, Any]:
    manifest_path = package_dir / package_id / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"package manifest is not cached: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if str(payload.get("package_id", "")) != package_id:
        raise ValueError("cached package manifest package_id mismatch")
    return payload


def load_cached_package_signature(package_dir: Path, package_id: str) -> dict[str, Any]:
    signature_path = package_dir / package_id / "manifest.sig.json"
    if not signature_path.exists():
        raise FileNotFoundError(f"package signature is not cached: {signature_path}")
    return json.loads(signature_path.read_text(encoding="utf-8"))


def build_package_activation_preview(
    *,
    target_cfg: dict[str, Any],
    manifest: dict[str, Any],
    runtime_preview_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
) -> dict[str, Any]:
    target = str(target_cfg.get("target"))
    compatibility = manifest.get("compatibility") if isinstance(manifest.get("compatibility"), dict) else {}
    compatibility_status = str(compatibility.get("status") or "UNKNOWN")
    risk_level = str(compatibility.get("risk_level") or ("HIGH" if compatibility_status == "INCOMPATIBLE" else "LOW"))
    mw = maintenance_window_status(target, maintenance_policy)
    approval_level = str((mw.get("policy") or {}).get("approval_level", "single")).lower()
    approval, approval_status = load_active_approval_for_target(approvals_dir, target, approval_signer, approval_level)
    if not approval_required:
        approval_status = "not_required"

    preview_id = uuid4().hex
    blocking = list(compatibility.get("blocking_reasons", [])) if isinstance(compatibility.get("blocking_reasons"), list) else []
    recommendation = "Package activation preview generated. Runtime writes remain disabled."
    if compatibility_status == "INCOMPATIBLE":
        recommendation = "Resolve package compatibility blockers before any future activation."
    elif approval_required and not approval:
        recommendation = "Collect operator approval before staging."
    elif mw["status"] == "blackout":
        recommendation = "Activation denied due to blackout period."
    elif mw["status"] != "open":
        recommendation = "Schedule or open a maintenance window before staging."

    preview = {
        "preview_id": preview_id,
        "generated_at": iso_now_z(),
        "source": "certificate_package",
        "target": target,
        "package_id": manifest.get("package_id"),
        "generation": manifest.get("generation"),
        "supersedes_package_id": manifest.get("supersedes_package_id"),
        "supersedes_generation": manifest.get("supersedes_generation"),
        "runtime_instance_id": manifest.get("runtime_instance_id"),
        "application_uri": manifest.get("application_uri"),
        "profile_name": manifest.get("profile_name"),
        "component_type": manifest.get("component_type"),
        "artifact_zone": target_cfg.get("artifact_zone"),
        "artifact_role": target_cfg.get("artifact_role"),
        "artifact_version": None,
        "artifact_revision": None,
        "maintenance_window_status": mw,
        "approval_status": approval_status,
        "approval_summary": approval or {},
        "compatibility_status": compatibility_status,
        "compatibility_issues": blocking,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "safe_to_stage": compatibility_status != "INCOMPATIBLE" and risk_level != "CRITICAL",
        "safe_to_activate": False,
        "package_snapshot": manifest,
        "runtime_write_enabled": False,
        "dry_run_only": True,
    }
    out_dir = runtime_preview_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{preview['generated_at'].replace(':', '').replace('-', '')}_{preview_id}_package.json"
    write_json_artifact(out_dir / file_name, preview)
    return preview


def create_package_activation_plan_once(
    *,
    target_cfg: dict[str, Any],
    manifest: dict[str, Any],
    runtime_preview_dir: Path,
    plan_dir: Path,
    approvals_dir: Path,
    rollback_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
) -> dict[str, Any]:
    preview = build_package_activation_preview(
        target_cfg=target_cfg,
        manifest=manifest,
        runtime_preview_dir=runtime_preview_dir,
        approvals_dir=approvals_dir,
        maintenance_policy=maintenance_policy,
        approval_signer=approval_signer,
        approval_required=approval_required,
    )
    rollback = build_rollback_bundle_metadata(target_cfg, rollback_dir)
    approval = preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None
    gate = evaluate_activation_gate(
        target_cfg=target_cfg,
        preview=preview,
        approval_required=approval_required,
        approval_summary=approval,
        approval_status=str(preview.get("approval_status", "")),
        emergency_override_mode=emergency_override_mode,
    )
    if gate["status"] == "ready_for_staging":
        status_value = "ready_for_package_staging"
    elif gate["status"] == "emergency_override_ready":
        status_value = "emergency_override_ready"
    elif gate["status"] == "blocked_approval_missing":
        status_value = "pending_approval"
    elif gate["status"] == "blocked_window_closed":
        status_value = "pending_window"
    elif gate["status"] == "blocked_blackout":
        status_value = "blocked_blackout"
    else:
        status_value = "blocked_incompatible"
    plan_id = uuid4().hex
    plan = {
        "plan_id": plan_id,
        "created_at": iso_now_z(),
        "source": "certificate_package",
        "target": target_cfg["target"],
        "package_id": manifest.get("package_id"),
        "generation": manifest.get("generation"),
        "supersedes_package_id": manifest.get("supersedes_package_id"),
        "supersedes_generation": manifest.get("supersedes_generation"),
        "preview_id": preview["preview_id"],
        "required_approval_id": (approval or {}).get("approval_id") if isinstance(approval, dict) else f"approval-{plan_id}",
        "required_maintenance_window": True,
        "rollback_bundle_id": rollback["bundle_id"],
        "steps": [
            "verify_signed_package_manifest",
            "verify_package_hash_tree",
            "confirm_runtime_compatibility",
            "confirm_operator_approval",
            "enforce_maintenance_window_and_blackout_policy",
            "prepare_package_runtime_stage_dry_run",
        ],
        "status": status_value,
        "activation_blocked_reason": str(gate.get("blocked_reason", "")),
        "runtime_write_enabled": False,
        "dry_run_only": True,
        "gate": gate,
    }
    target_dir = plan_dir / str(target_cfg["target"])
    target_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{plan['created_at'].replace(':', '').replace('-', '')}_{plan_id}_package.json"
    write_json_artifact(target_dir / file_name, plan)
    return plan


def stage_package_activation_dry_run(
    *,
    target_cfg: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    preview: dict[str, Any],
    gate: dict[str, Any],
    stage_root_dir: Path,
    merge_policy: str,
) -> dict[str, Any]:
    target = str(target_cfg["target"])
    plan_id = str(plan.get("plan_id", uuid4().hex))
    package_id = str(manifest.get("package_id", "unknown-package"))
    stage_dir = stage_root_dir / target / plan_id
    shadow_dir = stage_dir / "shadow-trust-store"
    incoming_dir = stage_dir / "incoming-trust-store"
    shadow_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    current_runtime = inspect_current_runtime_readonly(target_cfg)
    incoming_written = _write_package_stage_material(incoming_dir, target_cfg, manifest)
    shadow_written = _write_package_stage_material(shadow_dir, target_cfg, manifest)
    checksums = {
        "shadow-trust-store": _collect_stage_checksums(shadow_dir),
        "incoming-trust-store": _collect_stage_checksums(incoming_dir),
    }
    write_json_artifact(
        stage_dir / "checksums.json",
        {
            "target": target,
            "plan_id": plan_id,
            "source": "certificate_package",
            "package_id": package_id,
            "generated_at": iso_now_z(),
            "files": checksums,
        },
    )
    verified = _collect_stage_checksums(shadow_dir) == checksums["shadow-trust-store"]
    install_plan = manifest.get("install_plan") if isinstance(manifest.get("install_plan"), dict) else {}
    target_layout = install_plan.get("target_layout") if isinstance(install_plan.get("target_layout"), dict) else {}
    if str(target_cfg.get("layout_kind", "")) == "open62541-opcua-server":
        application_certificate_path = "ApplCerts/own/certs/server.der"
    else:
        application_certificate_path = str(target_layout.get("application_certificate") or "").replace("\\", "/")
    package_replace_allowed = {application_certificate_path} if application_certificate_path else set()
    merge = _compare_runtime_to_stage(
        current_runtime,
        checksums["shadow-trust-store"],
        merge_policy,
        replace_allowed_paths=package_replace_allowed,
    )
    live_runtime_root = str(target_cfg.get("runtime_root", (target_cfg.get("runtime_paths_checked") or [""])[0]))
    swap_plan = {
        "target": target,
        "plan_id": plan_id,
        "source": "certificate_package",
        "package_id": package_id,
        "generation": manifest.get("generation"),
        "current_runtime_path": live_runtime_root,
        "staged_path": str(shadow_dir),
        "runtime_write_enabled": False,
        "dry_run_only": True,
        "merge_policy": merge_policy,
        "proposed_atomic_strategy": [
            "validate_signed_package_manifest",
            "validate_stage_checksums",
            "prepare_shadow_runtime_tree_as_pki_next",
            "operator_runs_atomic_switch_in_future_phase",
            "operator_validates_runtime_health_before_finalize",
        ],
        "files_to_add": merge["files_to_add"],
        "files_to_replace": merge["files_to_replace"],
        "files_to_remove": merge["files_to_remove"],
        "preserved_runtime_entries": merge["preserved_runtime_entries"],
        "proposed_additions": merge["proposed_additions"],
        "proposed_updates": merge["proposed_updates"],
        "proposed_future_review": merge["proposed_future_review"],
        "deletion_candidates": merge["deletion_candidates"],
        "runtime_entry_classifications": merge["runtime_entry_classifications"],
        "commands_reference_only": [
            f"# future only: test -d {live_runtime_root}",
            f"# future only: cp -a {live_runtime_root} {live_runtime_root}.rollback.<{plan_id}>",
            f"# future only: rsync -a --delete {shadow_dir}/ {live_runtime_root}.next/",
            f"# future only: mv -T {live_runtime_root}.next {live_runtime_root}",
        ],
    }
    write_json_artifact(stage_dir / "swap-plan.json", swap_plan)
    rollback_pointer = {
        "target": target,
        "plan_id": plan_id,
        "source": "certificate_package",
        "package_id": package_id,
        "rollback_bundle_id": plan.get("rollback_bundle_id", ""),
        "current_runtime_snapshot_reference": current_runtime,
        "rollback_strategy": [
            "restore_previous_runtime_tree_in_future_controlled_phase",
            "operator_validates_runtime_health_after_rollback",
        ],
        "runtime_write_enabled": False,
        "dry_run_only": True,
    }
    write_json_artifact(stage_dir / "rollback-pointer.json", rollback_pointer)
    warnings: list[str] = []
    warnings.extend(current_runtime.get("warnings", []) if isinstance(current_runtime.get("warnings"), list) else [])
    if current_runtime.get("current_runtime_status") == "unavailable":
        warnings.append("current_runtime_readonly_inspection_unavailable")
    if merge["destructive_changes_blocked"]:
        warnings.append("destructive_changes_blocked_by_conservative_merge")
    blocking_reasons: list[str] = []
    if not verified:
        blocking_reasons.append("stage_checksum_verification_failed")
    if str(gate.get("status", "")) not in {"ready_for_staging", "emergency_override_ready"}:
        blocking_reasons.append(str(gate.get("blocked_reason", "activation_gate_not_ready")))
    validation_report = {
        "target": target,
        "plan_id": plan_id,
        "source": "certificate_package",
        "package_id": package_id,
        "generation": manifest.get("generation"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "generated_at": iso_now_z(),
        "signed_package_verified": True,
        "trust_anchor_verified": True,
        "approvals_valid": str(preview.get("approval_status", "")).startswith("approved") or str(preview.get("approval_status", "")) == "not_required",
        "maintenance_window_status": (preview.get("maintenance_window_status") or {}).get("status"),
        "blackout_status": "active" if (preview.get("maintenance_window_status") or {}).get("within_blackout") else "inactive",
        "emergency_override_status": "active" if gate.get("status") == "emergency_override_ready" else "inactive",
        "runtime_write_enabled": False,
        "dry_run_only": True,
        "merge_policy": merge_policy,
        "destructive_changes_detected": merge["destructive_changes_detected"],
        "destructive_changes_blocked": merge["destructive_changes_blocked"],
        "preserved_runtime_entries_count": len(merge["preserved_runtime_entries"]),
        "target_compatibility": preview.get("compatibility_status"),
        "risk_level": preview.get("risk_level"),
        "current_runtime_status": current_runtime.get("current_runtime_status"),
        "checksum_verified": verified,
        "blocking_reasons": blocking_reasons,
        "warnings": sorted(set(warnings)),
        "recommended_operator_action": (
            "Review package dry-run bundle and schedule future controlled activation."
            if not blocking_reasons
            else "Resolve blocking reasons before any future package activation."
        ),
    }
    write_json_artifact(stage_dir / "validation-report.json", validation_report)
    atomic_write_text(
        stage_dir / "README-DRY-RUN.txt",
        f"""LabShock OT GDS Agent Phase 7.3 package activation dry-run bundle

Target: {target}
Plan ID: {plan_id}
Package ID: {package_id}

This directory is a dry-run artifact only.
No live runtime PKI directory was modified.
No service restart was performed.
No symlink swap was executed.
""",
    )
    return {
        "target": target,
        "plan_id": plan_id,
        "source": "certificate_package",
        "package_id": package_id,
        "generation": manifest.get("generation"),
        "stage_dir": str(stage_dir),
        "shadow_trust_store_dir": str(shadow_dir),
        "incoming_trust_store_dir": str(incoming_dir),
        "checksum_verified": verified,
        "swap_plan_path": str(stage_dir / "swap-plan.json"),
        "rollback_pointer_path": str(stage_dir / "rollback-pointer.json"),
        "validation_report_path": str(stage_dir / "validation-report.json"),
        "current_runtime_status": current_runtime.get("current_runtime_status"),
        "files_to_add_count": len(merge["files_to_add"]),
        "files_to_replace_count": len(merge["files_to_replace"]),
        "files_to_remove_count": len(merge["files_to_remove"]),
        "merge_policy": merge_policy,
        "preserved_runtime_entries": merge["preserved_runtime_entries"],
        "preserved_runtime_entries_count": len(merge["preserved_runtime_entries"]),
        "deletion_candidates": merge["deletion_candidates"],
        "destructive_changes_detected": merge["destructive_changes_detected"],
        "destructive_changes_blocked": merge["destructive_changes_blocked"],
        "warnings": validation_report["warnings"],
        "blocking_reasons": blocking_reasons,
        "incoming_written": incoming_written,
        "shadow_written": shadow_written,
        "runtime_write_enabled": False,
        "dry_run_only": True,
    }


PRIVATE_RUNTIME_PRESERVE_PATHS = {
    "mutex.lock",
    "own/openssl.cnf",
    "own/private/private_key.pem",
    "applcerts/own/private/server.key.der",
    "private/private.key.der",
    "private/private.pem",
}


def _is_preserved_runtime_path(relative_path: str) -> bool:
    rel = relative_path.replace("\\", "/").lower()
    if _is_private_key_path(Path(rel), rel):
        return True
    return rel in PRIVATE_RUNTIME_PRESERVE_PATHS


def _assert_path_inside(base: Path, candidate: Path) -> None:
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    if candidate_resolved != base_resolved and base_resolved not in candidate_resolved.parents:
        raise ValueError(f"path escapes runtime root: {candidate}")


def _find_package_stage_bundle(stage_root_dir: Path, target: str, package_id: str, plan_id: str = "") -> tuple[Path, dict[str, Any], dict[str, Any]]:
    target_dir = stage_root_dir / target
    if not target_dir.exists():
        raise FileNotFoundError(f"package stage directory not found for target={target}")
    candidates = sorted([p for p in target_dir.iterdir() if p.is_dir()])
    if plan_id:
        candidates = [target_dir / plan_id]
    for stage_dir in reversed(candidates):
        validation_path = stage_dir / "validation-report.json"
        checksums_path = stage_dir / "checksums.json"
        if not validation_path.exists() or not checksums_path.exists():
            continue
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        if str(validation.get("package_id", "")) != package_id:
            continue
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        return stage_dir, validation, checksums
    raise FileNotFoundError(f"matching package stage bundle not found package_id={package_id} target={target} plan_id={plan_id}")


def _validate_stage_bundle(stage_dir: Path, validation: dict[str, Any], checksums: dict[str, Any], package_id: str) -> dict[str, Any]:
    if validation.get("dry_run_only") is not True:
        raise ValueError("stage bundle is not marked dry_run_only")
    if str(validation.get("package_id", "")) != package_id:
        raise ValueError("stage bundle package_id mismatch")
    if validation.get("checksum_verified") is not True:
        raise ValueError("stage bundle checksum was not verified")
    if validation.get("blocking_reasons"):
        raise ValueError(f"stage bundle has blocking reasons: {validation.get('blocking_reasons')}")
    shadow_dir = stage_dir / "shadow-trust-store"
    if not shadow_dir.exists() or not shadow_dir.is_dir():
        raise FileNotFoundError("stage shadow-trust-store missing")
    expected = checksums.get("files", {}).get("shadow-trust-store") if isinstance(checksums.get("files"), dict) else None
    if not isinstance(expected, dict) or not expected:
        raise ValueError("stage bundle missing shadow-trust-store checksums")
    actual = _collect_stage_checksums(shadow_dir)
    if actual != expected:
        raise ValueError("stage shadow-trust-store checksum mismatch")
    return actual


def _ensure_runtime_writable(runtime_root: Path) -> None:
    if not runtime_root.exists() or not runtime_root.is_dir():
        raise FileNotFoundError(f"runtime root is not available: {runtime_root}")
    probe = runtime_root / f".labshock-write-probe-{uuid4().hex}"
    try:
        atomic_write_text(probe, "probe")
        probe.unlink()
    except Exception as exc:
        with suppress(Exception):
            probe.unlink()
        raise PermissionError("runtime_mount_not_writable") from exc


def _public_key_der_from_private_key(private_key_path: Path) -> bytes:
    private_key = _load_private_key_from_path(private_key_path)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_private_key_from_path(private_key_path: Path) -> Any:
    raw = private_key_path.read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        return load_pem_private_key(raw, password=None)
    return load_der_private_key(raw, password=None)


def _public_key_der_from_private_key_object(private_key: Any) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_key_der_from_certificate_pem(cert_pem: str) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _target_private_key_candidates(target: str, runtime_root: Path) -> list[Path]:
    if target == "fuxa":
        return [runtime_root / "own/private/private_key.pem"]
    if target == "dmz-gateway-client":
        return [
            runtime_root / "own/private/client.key.der",
            runtime_root / "private/private.key.der",
            runtime_root / "private/private.pem",
        ]
    if target in {"opcua-server", "dmz-gateway-server"}:
        return [
            runtime_root / "ApplCerts/own/private/server.key.der",
            runtime_root / "own/private/server.key.der",
            runtime_root / "private/private.key.der",
            runtime_root / "private/private.pem",
        ]
    return []


def _runtime_private_key_path(target: str, runtime_root: Path) -> Path:
    for candidate in _target_private_key_candidates(target, runtime_root):
        if candidate.exists() and candidate.is_file():
            return candidate
    raise FileNotFoundError(f"{target} runtime private key is missing")


def _verify_certificate_matches_runtime_key(target: str, manifest: dict[str, Any], runtime_root: Path) -> None:
    cert_pem = str(manifest.get("certificate_pem", ""))
    if not cert_pem:
        raise ValueError("package certificate is missing")
    private_key_path = _runtime_private_key_path(target, runtime_root)
    cert_pub = _public_key_der_from_certificate_pem(cert_pem)
    key_pub = _public_key_der_from_private_key(private_key_path)
    if hashlib.sha256(cert_pub).hexdigest() != hashlib.sha256(key_pub).hexdigest():
        raise ValueError("certificate_private_key_mismatch")


def _runtime_certificate_path(target: str, runtime_root: Path) -> Path:
    if target == "fuxa":
        return runtime_root / "own/certs/client_certificate.pem"
    if target == "opcua-server":
        return runtime_root / "ApplCerts/own/certs/server.der"
    if target == "dmz-gateway-client":
        return runtime_root / "own/certs/client.der"
    if target == "dmz-gateway-server":
        return runtime_root / "own/certs/server.der"
    raise ValueError("target_not_enabled_for_renewal")


def _load_runtime_certificate(target: str, runtime_root: Path) -> x509.Certificate:
    cert_path = _runtime_certificate_path(target, runtime_root)
    raw = cert_path.read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(raw)
    return x509.load_der_x509_certificate(raw)


def _certificate_identity(cert: x509.Certificate) -> dict[str, Any]:
    uri_sans: list[str] = []
    dns_sans: list[str] = []
    ip_sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uri_sans = [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
        dns_sans = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        ip_sans = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": cert.subject.rfc4514_string(),
        "application_uri": uri_sans[0] if uri_sans else "",
        "uri_sans": uri_sans,
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
        "fingerprint_sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }


def _renewal_profile_for_target(target: str) -> str:
    if target == "fuxa":
        return "node-opcua-client"
    if target == "opcua-server":
        return "open62541-server"
    raise ValueError("target_not_enabled_for_renewal")


def build_runtime_renewal_csr(target: str, runtime_root: Path) -> tuple[str, dict[str, Any]]:
    cert = _load_runtime_certificate(target, runtime_root)
    private_key = _load_private_key_from_path(_runtime_private_key_path(target, runtime_root))
    cert_pub = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = _public_key_der_from_private_key_object(private_key)
    if hashlib.sha256(cert_pub).hexdigest() != hashlib.sha256(key_pub).hexdigest():
        raise ValueError("runtime_certificate_private_key_mismatch")

    builder = x509.CertificateSigningRequestBuilder().subject_name(cert.subject)
    for extension_type in (x509.SubjectAlternativeName, x509.KeyUsage, x509.ExtendedKeyUsage):
        try:
            extension = cert.extensions.get_extension_for_class(extension_type)
            builder = builder.add_extension(extension.value, critical=extension.critical)
        except x509.ExtensionNotFound:
            continue
    algorithm = None if isinstance(private_key, Ed25519PrivateKey) else hashes.SHA256()
    csr = builder.sign(private_key, algorithm)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return csr_pem, _certificate_identity(cert)


def renewal_check_for_target(target_cfg: dict[str, Any], threshold_days: int) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    cert = _load_runtime_certificate(target, runtime_root)
    identity = _certificate_identity(cert)
    not_after = cert.not_valid_after_utc
    days_remaining = int((not_after - utc_now()).total_seconds() // 86400)
    return {
        "target": target,
        "runtime_root": str(runtime_root),
        "application_uri": identity.get("application_uri"),
        "runtime_instance_id": identity.get("application_uri"),
        "profile_name": _renewal_profile_for_target(target),
        "certificate_fingerprint_sha256": identity.get("fingerprint_sha256"),
        "not_after": identity.get("not_after"),
        "days_remaining": days_remaining,
        "renewal_threshold_days": threshold_days,
        "renewal_due": days_remaining <= threshold_days,
    }


def request_certificate_renewal(
    client: httpx.Client,
    base_url: str,
    headers: dict[str, str],
    *,
    application_uri: str,
    runtime_instance_id: str,
    profile_name: str,
    csr_pem: str,
    renewal_reason: str,
    requested_ttl: str = "",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "application_uri": application_uri,
        "runtime_instance_id": runtime_instance_id,
        "profile_name": profile_name,
        "csr_pem": csr_pem,
        "renewal_reason": renewal_reason,
    }
    if requested_ttl:
        body["requested_ttl"] = requested_ttl
    res = client.post(f"{base_url}/api/v1/certificates/renew", headers=headers, json=body)
    if res.status_code >= 400:
        raise RuntimeError(f"renewal_request_failed status={res.status_code} body={res.text[:500]}")
    return res.json()


def _component_cache_dir(component_dir: Path, target: str) -> Path:
    path = component_dir / target
    path.mkdir(parents=True, exist_ok=True)
    return path


def _component_application_uri(target_cfg: dict[str, Any]) -> str:
    return str(target_cfg.get("application_uri") or "").strip()


def _component_private_key_path(target: str, runtime_root: Path) -> Path:
    candidates = _target_private_key_candidates(target, runtime_root)
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    if not candidates:
        raise ValueError("component_private_key_path_unknown")
    return candidates[0]


def _mount_mode_for_component_target(target: str, runtime_fuxa_mount_mode: str, runtime_opcua_server_mount_mode: str) -> str:
    if target == "opcua-server":
        return runtime_opcua_server_mount_mode
    if target == "fuxa":
        return runtime_fuxa_mount_mode
    if target in {"dmz-gateway-client", "dmz-gateway-server"}:
        return env("GDS_AGENT_RUNTIME_DMZ_GATEWAY_MOUNT_MODE", "ro").strip().lower()
    return "ro"


def _ensure_component_private_key(target: str, runtime_root: Path) -> tuple[Path, bool]:
    key_path = _component_private_key_path(target, runtime_root)
    if key_path.exists() and key_path.is_file():
        return key_path, False
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if target == "fuxa" or key_path.suffix.lower() == ".pem":
        raw = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        raw = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    atomic_write_bytes(key_path, raw)
    return key_path, True


def _component_csr_for_target(target_cfg: dict[str, Any], runtime_root: Path) -> tuple[str, dict[str, Any]]:
    target = str(target_cfg.get("target", ""))
    key_path, key_created = _ensure_component_private_key(target, runtime_root)
    private_key = _load_private_key_from_path(key_path)
    app_uri = _component_application_uri(target_cfg)
    common_name = str(target_cfg.get("common_name") or target or "LabShockComponent")
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(app_uri)]),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    eku = ExtendedKeyUsageOID.SERVER_AUTH if str(target_cfg.get("component_type")) == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    csr = builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return csr_pem, {
        "private_key_path": str(key_path),
        "private_key_created": key_created,
        "private_key_exported": False,
        "application_uri": app_uri,
        "common_name": common_name,
    }


def component_discover_once(
    *,
    base_url: str,
    auth_headers: dict[str, str],
    target_cfg: dict[str, Any],
    component_dir: Path,
) -> dict[str, Any]:
    app_uri = _component_application_uri(target_cfg)
    if not app_uri:
        raise ValueError("component_application_uri_missing")
    encoded = quote(app_uri, safe="")
    with build_gds_http_client(timeout_seconds=10.0) as client:
        discovery = client.get(f"{base_url}/api/v1/discovery", headers=auth_headers)
        discovery.raise_for_status()
        profiles = client.get(f"{base_url}/api/v1/discovery/component-profiles", headers=auth_headers)
        profiles.raise_for_status()
        groups = client.get(f"{base_url}/api/v1/discovery/certificate-groups", headers=auth_headers)
        groups.raise_for_status()
        identity = client.get(f"{base_url}/api/v1/discovery/components/{encoded}/identity", headers=auth_headers)
        identity.raise_for_status()
        renewal = client.get(f"{base_url}/api/v1/discovery/components/{encoded}/renewal-policy", headers=auth_headers)
        renewal.raise_for_status()
        revocation = client.get(f"{base_url}/api/v1/discovery/components/{encoded}/revocation-status", headers=auth_headers)
        revocation.raise_for_status()
        trust_anchor = client.get(f"{base_url}/api/v1/signing/trust-anchor", headers=auth_headers)
        trust_anchor.raise_for_status()
    report = {
        "schema": "labshock_component_discovery_cache_v1",
        "generated_at": iso_now_z(),
        "target": target_cfg.get("target"),
        "application_uri": app_uri,
        "discovery": discovery.json(),
        "component_profiles": profiles.json(),
        "certificate_groups": groups.json(),
        "identity": identity.json(),
        "renewal_policy": renewal.json(),
        "revocation_status": revocation.json(),
        "trust_anchor": trust_anchor.json(),
        "private_key_included": False,
    }
    out_dir = _component_cache_dir(component_dir, str(target_cfg.get("target", "unknown")))
    write_json_artifact(out_dir / "discovery.json", report)
    return report


def component_enroll_once(
    *,
    base_url: str,
    auth_headers: dict[str, str],
    target_cfg: dict[str, Any],
    component_dir: Path,
    package_dir: Path,
    requested_ttl: str = "",
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    csr_pem, csr_meta = _component_csr_for_target(target_cfg, runtime_root)
    body = {
        "application_uri": _component_application_uri(target_cfg),
        "runtime_instance_id": str(target_cfg.get("runtime_instance_id") or _component_application_uri(target_cfg)),
        "profile_name": str(target_cfg.get("profile_name") or ""),
        "csr_pem": csr_pem,
    }
    if requested_ttl:
        body["requested_ttl"] = requested_ttl
    with build_gds_http_client(timeout_seconds=20.0) as client:
        res = client.post(f"{base_url}/api/v1/enrollments/components/csr", headers=auth_headers, json=body)
    if res.status_code >= 400:
        raise RuntimeError(f"component_enrollment_failed status={res.status_code} body={res.text[:500]}")
    result = res.json()
    out_dir = _component_cache_dir(component_dir, target)
    cache_payload = {
        **result,
        "target": target,
        "generated_at": iso_now_z(),
        "csr": {
            "fingerprint_sha256": hashlib.sha256(csr_pem.encode("utf-8")).hexdigest(),
            "private_key_path": csr_meta["private_key_path"],
            "private_key_created": csr_meta["private_key_created"],
            "private_key_exported": False,
        },
    }
    write_json_artifact(out_dir / "enrollment-result.json", cache_payload)
    manifest = result.get("manifest") if isinstance(result.get("manifest"), dict) else {}
    signature = result.get("signature") if isinstance(result.get("signature"), dict) else {}
    package_id = str(result.get("package_id") or manifest.get("package_id") or "")
    if package_id and manifest:
        pkg_dir = package_dir / package_id
        write_json_artifact(pkg_dir / "manifest.json", manifest)
        if signature:
            write_json_artifact(pkg_dir / "manifest.sig.json", signature)
    return cache_payload


def component_pull_trust_once(
    *,
    base_url: str,
    auth_headers: dict[str, str],
    target_cfg: dict[str, Any],
    component_dir: Path,
) -> dict[str, Any]:
    app_uri = _component_application_uri(target_cfg)
    encoded = quote(app_uri, safe="")
    with build_gds_http_client(timeout_seconds=10.0) as client:
        res = client.get(f"{base_url}/api/v1/distribution/components/{encoded}/trust-material", headers=auth_headers)
    if res.status_code >= 400:
        raise RuntimeError(f"component_trust_pull_failed status={res.status_code} body={res.text[:500]}")
    payload = res.json()
    out_dir = _component_cache_dir(component_dir, str(target_cfg.get("target", "unknown")))
    write_json_artifact(out_dir / "trust-material.json", payload)
    return payload


def _load_component_enrollment(component_dir: Path, target: str) -> dict[str, Any]:
    path = component_dir / target / "enrollment-result.json"
    if not path.exists():
        raise FileNotFoundError(f"component enrollment result missing for target={target}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_component_enrollment_if_present(component_dir: Path, target: str) -> dict[str, Any] | None:
    path = component_dir / target / "enrollment-result.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_component_trust_material(component_dir: Path, target: str) -> dict[str, Any]:
    path = component_dir / target / "trust-material.json"
    if not path.exists():
        raise FileNotFoundError(f"component trust material cache missing for target={target}")
    return json.loads(path.read_text(encoding="utf-8"))


def _component_trust_material_present(component_dir: Path, target: str) -> bool:
    return (component_dir / target / "trust-material.json").exists()


def _component_manifest_for_target(target_cfg: dict[str, Any], enrollment: dict[str, Any]) -> dict[str, Any]:
    manifest = dict(enrollment.get("manifest") if isinstance(enrollment.get("manifest"), dict) else {})
    if not manifest:
        raise ValueError("component_enrollment_manifest_missing")
    target = str(target_cfg.get("target", ""))
    if target in {"dmz-gateway-client", "dmz-gateway-server"}:
        install_plan = dict(manifest.get("install_plan") if isinstance(manifest.get("install_plan"), dict) else {})
        target_layout = dict(install_plan.get("target_layout") if isinstance(install_plan.get("target_layout"), dict) else {})
        if target == "dmz-gateway-client":
            target_layout["application_certificate"] = "own/certs/client.der"
        else:
            target_layout["application_certificate"] = "own/certs/server.der"
        target_layout.setdefault("issuer_chain", "issuer/certs/ca-chain.pem")
        target_layout.setdefault("issuer_crl", "issuer/crl/current.crl.b64")
        target_layout.setdefault("trusted_certs_dir", "trusted/certs")
        target_layout.setdefault("trusted_crl_dir", "trusted/crl")
        install_plan["target_layout"] = target_layout
        manifest["install_plan"] = install_plan
    return manifest


def _component_trust_artifact_from_cache(trust_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    material = trust_payload.get("trust_material") if isinstance(trust_payload.get("trust_material"), dict) else {}
    artifact = material.get("artifact") if isinstance(material.get("artifact"), dict) else {}
    signature = material.get("artifact_signature") if isinstance(material.get("artifact_signature"), dict) else {}
    if not artifact:
        raise ValueError("component_trust_artifact_missing")
    if not signature:
        raise ValueError("component_trust_artifact_signature_missing")
    return artifact, signature


def _component_activation_gate(
    *,
    target_cfg: dict[str, Any],
    runtime_preview_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
    source: str,
    artifact: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = str(target_cfg.get("target", ""))
    mw = maintenance_window_status(target, maintenance_policy)
    approval_level = str((mw.get("policy") or {}).get("approval_level", "single")).lower()
    approval, approval_status = load_active_approval_for_target(approvals_dir, target, approval_signer, approval_level)
    if not approval_required:
        approval_status = "not_required"
    preview = {
        "preview_id": uuid4().hex,
        "generated_at": iso_now_z(),
        "source": source,
        "target": target,
        "artifact_zone": target_cfg.get("artifact_zone"),
        "artifact_role": target_cfg.get("artifact_role"),
        "artifact_version": (artifact or {}).get("version"),
        "artifact_revision": (artifact or {}).get("artifact_revision"),
        "application_uri": (manifest or {}).get("application_uri") or (target_cfg.get("application_uri")),
        "package_id": (manifest or {}).get("package_id"),
        "maintenance_window_status": mw,
        "approval_status": approval_status,
        "approval_summary": approval or {},
        "compatibility_status": "COMPATIBLE",
        "compatibility_issues": [],
        "risk_level": "LOW",
        "safe_to_activate": False,
        "runtime_write_enabled": False,
        "dry_run_only": True,
    }
    out_dir = runtime_preview_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{preview['generated_at'].replace(':', '').replace('-', '')}_{preview['preview_id']}_{source}.json"
    write_json_artifact(out_dir / file_name, preview)
    gate = evaluate_activation_gate(
        target_cfg=target_cfg,
        preview=preview,
        approval_required=approval_required,
        approval_summary=approval if isinstance(approval, dict) else None,
        approval_status=approval_status,
        emergency_override_mode=emergency_override_mode,
    )
    return preview, gate


def _apply_component_trust_only(
    *,
    log: logging.Logger,
    base_url: str,
    auth_headers: dict[str, str],
    target_cfg: dict[str, Any],
    component_dir: Path,
    component_apply_dir: Path,
    runtime_preview_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
    runtime_write_enabled: bool,
    mount_mode: str,
    pinned_anchor_fingerprint: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    trust_payload = _load_component_trust_material(component_dir, target)
    artifact, signature = _component_trust_artifact_from_cache(trust_payload)
    zone = str(target_cfg.get("artifact_zone", ""))
    role = str(target_cfg.get("artifact_role", ""))
    with build_gds_http_client(timeout_seconds=10.0) as client:
        trust_anchor = load_trust_anchor(client, base_url, auth_headers)
    trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)
    artifact_sha256, verifier_payload_length = verify_signed_artifact(artifact, signature, zone, role, trust_anchor_pub, trust_anchor_fp)
    crl_meta = artifact.get("crl_metadata") if isinstance(artifact.get("crl_metadata"), dict) else {}
    if env_bool("GDS_AGENT_STRICT_CRL_FRESHNESS", True) and crl_meta.get("crl_freshness_verified") is not True:
        raise ValueError("blocked_crl_freshness_not_verified")
    preview, gate = _component_activation_gate(
        target_cfg=target_cfg,
        runtime_preview_dir=runtime_preview_dir,
        approvals_dir=approvals_dir,
        maintenance_policy=maintenance_policy,
        approval_signer=approval_signer,
        approval_required=approval_required,
        emergency_override_mode=emergency_override_mode,
        source="component_trust_only",
        artifact=artifact,
    )
    if str(gate.get("status", "")).startswith("blocked"):
        raise ValueError(f"{gate.get('status')}:{gate.get('blocked_reason')}")

    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    _assert_path_inside(runtime_root, runtime_root)
    before_cert_sha = ""
    cert_path = _runtime_certificate_path(target, runtime_root)
    if cert_path.exists() and cert_path.is_file():
        before_cert_sha = _file_sha256(cert_path)
    written = _write_target_stage_material(runtime_root, target_cfg, artifact)
    after_cert_sha = ""
    if cert_path.exists() and cert_path.is_file():
        after_cert_sha = _file_sha256(cert_path)
    if before_cert_sha and after_cert_sha and before_cert_sha != after_cert_sha:
        raise RuntimeError("own_certificate_changed_during_trust_only_apply")

    plan_id = uuid4().hex
    receipt = {
        "schema": "labshock_component_apply_trust_v1",
        "generated_at": iso_now_z(),
        "target": target,
        "application_uri": trust_payload.get("application_uri") or target_cfg.get("application_uri"),
        "plan_id": plan_id,
        "apply_mode": "trust_only",
        "status": "trust_applied",
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": True,
        "own_certificate_touched": False,
        "private_key_touched": False,
        "private_key_overwritten": False,
        "private_key_included": False,
        "package_lifecycle_touched": False,
        "runtime_restart_automatic": False,
        "artifact_sha256": artifact_sha256,
        "artifact_revision": artifact.get("artifact_revision"),
        "root_crl_next_update": crl_meta.get("root_crl_next_update"),
        "intermediate_crl_next_update": crl_meta.get("intermediate_crl_next_update"),
        "crl_freshness_verified": bool(crl_meta.get("crl_freshness_verified")),
        "trust_anchor_fingerprint_sha256": trust_anchor_fp,
        "verifier_payload_length": verifier_payload_length,
        "changed_files": written,
        "changed_files_count": len(written),
        "files_written": written,
        "files_deleted": [],
        "rollback_material_touched": False,
        "package_activation_state_touched": False,
        "blocking_reasons": [],
        "preview": {
            "preview_id": preview.get("preview_id"),
            "approval_status": preview.get("approval_status"),
            "maintenance_window_status": preview.get("maintenance_window_status"),
            "gate_status": gate.get("status"),
        },
        "approval_status": preview.get("approval_status"),
        "maintenance_window_status": preview.get("maintenance_window_status"),
    }
    out_dir = component_apply_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{receipt['generated_at'].replace(':', '').replace('-', '')}_{plan_id}.json"
    receipt["report_path"] = str(out_path)
    write_json_artifact(out_path, receipt)
    write_json_artifact(_component_cache_dir(component_dir, target) / "apply-result.json", receipt)
    log.info("component_trust_only_applied target=%s plan_id=%s changed_files=%s", target, plan_id, len(written))
    return receipt


def component_apply_trust_once(
    *,
    log: logging.Logger,
    base_url: str,
    auth_headers: dict[str, str],
    target_cfg: dict[str, Any],
    component_dir: Path,
    component_apply_dir: Path,
    runtime_preview_dir: Path,
    runtime_stage_dir: Path,
    runtime_rollback_dir: Path,
    activation_receipt_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
    runtime_write_enabled: bool,
    runtime_activation_targets: list[str],
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
    pinned_anchor_fingerprint: str,
    merge_policy: str,
    apply_mode: str = "auto",
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    apply_mode = (apply_mode or "auto").strip().lower()
    if apply_mode not in {"auto", "trust_only", "certificate_and_trust"}:
        raise ValueError("invalid_component_apply_mode")
    if target not in runtime_activation_targets:
        raise ValueError("target_not_enabled_for_component_apply")
    if not runtime_write_enabled:
        raise ValueError("blocked_runtime_write_disabled")
    mount_mode = _mount_mode_for_component_target(target, runtime_fuxa_mount_mode, runtime_opcua_server_mount_mode)
    if mount_mode != "rw":
        raise ValueError("runtime_mount_not_writable")
    if merge_policy != "conservative_merge":
        raise ValueError("strict_replace_not_allowed_for_component_apply")
    if not pinned_anchor_fingerprint:
        raise ValueError("trust_anchor_fingerprint_required")

    trust_material_present = _component_trust_material_present(component_dir, target)
    if apply_mode == "trust_only" or (apply_mode == "auto" and trust_material_present):
        return _apply_component_trust_only(
            log=log,
            base_url=base_url,
            auth_headers=auth_headers,
            target_cfg=target_cfg,
            component_dir=component_dir,
            component_apply_dir=component_apply_dir,
            runtime_preview_dir=runtime_preview_dir,
            approvals_dir=approvals_dir,
            maintenance_policy=maintenance_policy,
            approval_signer=approval_signer,
            approval_required=approval_required,
            emergency_override_mode=emergency_override_mode,
            runtime_write_enabled=runtime_write_enabled,
            mount_mode=mount_mode,
            pinned_anchor_fingerprint=pinned_anchor_fingerprint,
        )

    enrollment = _load_component_enrollment_if_present(component_dir, target)
    if enrollment is None:
        raise FileNotFoundError(f"component enrollment result missing for target={target}")

    manifest = _component_manifest_for_target(target_cfg, enrollment)
    signature = enrollment.get("signature") if isinstance(enrollment.get("signature"), dict) else {}
    with build_gds_http_client(timeout_seconds=10.0) as client:
        trust_anchor = load_trust_anchor(client, base_url, auth_headers)
    trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)
    manifest_sha256 = verify_certificate_package_manifest(manifest, signature, trust_anchor_pub, trust_anchor_fp)

    preview = build_package_activation_preview(
        target_cfg=target_cfg,
        manifest=manifest,
        runtime_preview_dir=runtime_preview_dir,
        approvals_dir=approvals_dir,
        maintenance_policy=maintenance_policy,
        approval_signer=approval_signer,
        approval_required=approval_required,
    )
    gate = evaluate_activation_gate(
        target_cfg=target_cfg,
        preview=preview,
        approval_required=approval_required,
        approval_summary=preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None,
        approval_status=str(preview.get("approval_status", "")),
        emergency_override_mode=emergency_override_mode,
    )
    if str(gate.get("status", "")).startswith("blocked"):
        raise ValueError(f"{gate.get('status')}:{gate.get('blocked_reason')}")

    plan_id = uuid4().hex
    stage_dir = runtime_stage_dir / target / plan_id
    shadow_dir = stage_dir / "shadow-trust-store"
    incoming_dir = stage_dir / "incoming-trust-store"
    shadow_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    _write_package_stage_material(incoming_dir, target_cfg, manifest)
    _write_package_stage_material(shadow_dir, target_cfg, manifest)
    stage_checksums = _collect_stage_checksums(shadow_dir)
    write_json_artifact(
        stage_dir / "checksums.json",
        {
            "target": target,
            "plan_id": plan_id,
            "source": "component_distribution",
            "package_id": manifest.get("package_id"),
            "generated_at": iso_now_z(),
            "files": {"shadow-trust-store": stage_checksums, "incoming-trust-store": _collect_stage_checksums(incoming_dir)},
        },
    )
    validation = {
        "target": target,
        "plan_id": plan_id,
        "source": "component_distribution",
        "package_id": manifest.get("package_id"),
        "generated_at": iso_now_z(),
        "signed_package_verified": True,
        "trust_anchor_verified": True,
        "manifest_sha256": manifest_sha256,
        "approvals_valid": str(preview.get("approval_status", "")).startswith("approved") or str(preview.get("approval_status", "")) == "not_required",
        "maintenance_window_status": (preview.get("maintenance_window_status") or {}).get("status"),
        "blackout_status": "active" if (preview.get("maintenance_window_status") or {}).get("within_blackout") else "inactive",
        "runtime_write_enabled": runtime_write_enabled,
        "dry_run_only": False,
        "checksum_verified": True,
        "blocking_reasons": [],
    }
    write_json_artifact(stage_dir / "validation-report.json", validation)
    receipt = activate_package_runtime(
        target_cfg=target_cfg,
        manifest=manifest,
        stage_dir=stage_dir,
        stage_checksums=stage_checksums,
        validation=validation,
        rollback_root=runtime_rollback_dir,
        receipts_root=activation_receipt_dir,
        gate=gate,
    )
    report = {
        "schema": "labshock_component_apply_trust_v1",
        "generated_at": iso_now_z(),
        "target": target,
        "application_uri": manifest.get("application_uri"),
        "package_id": manifest.get("package_id"),
        "plan_id": receipt.get("plan_id") or plan_id,
        "apply_mode": "certificate_and_trust",
        "manifest_sha256": manifest_sha256,
        "status": receipt.get("status"),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": True,
        "runtime_restart_automatic": False,
        "own_certificate_touched": True,
        "private_key_touched": False,
        "private_key_overwritten": False,
        "private_key_included": False,
        "changed_files_count": len(receipt.get("changed_files", [])),
        "receipt": receipt,
    }
    out_dir = component_apply_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['plan_id']}.json"
    report["report_path"] = str(out_path)
    write_json_artifact(out_path, report)
    write_json_artifact(_component_cache_dir(component_dir, target) / "apply-result.json", report)
    log.info("component_trust_applied target=%s package_id=%s plan_id=%s status=%s", target, manifest.get("package_id"), report["plan_id"], report["status"])
    return report


def fetch_certificate_inventory(client: httpx.Client, base_url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    res = client.get(f"{base_url}/api/v1/certificates", headers=headers)
    res.raise_for_status()
    payload = res.json()
    if not isinstance(payload, list):
        raise ValueError("certificate_inventory_malformed")
    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "certificate_id": item.get("id"),
                "application_uri": item.get("application_uri"),
                "runtime_instance_id": item.get("runtime_instance_id"),
                "common_name": item.get("common_name"),
                "zone": item.get("zone"),
                "role": item.get("role"),
                "fingerprint_sha256": item.get("fingerprint_sha256"),
                "serial_number": item.get("serial_number"),
                "status": item.get("status"),
                "revoked_at": item.get("revoked_at"),
            }
        )
    return out


def _crl_serials(crl_der: bytes | None) -> set[str]:
    if not crl_der:
        return set()
    try:
        crl = x509.load_der_x509_crl(crl_der)
    except Exception:
        return set()
    serials: set[str] = set()
    for item in crl:
        serials.add(str(item.serial_number))
        serials.add(format(item.serial_number, "x"))
    return serials


def build_revocation_dry_run_report(
    *,
    target_cfg: dict[str, Any],
    revoked_certificates: list[dict[str, Any]],
    old_crl_der: bytes | None,
    new_crl_der: bytes | None,
    trust_dir: Path,
    revocation_dir: Path,
    merge_policy: str,
    runtime_write_enabled: bool,
    runtime_mount_mode: str,
    sync_cycle_id: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", "unknown"))
    zone = str(target_cfg.get("artifact_zone", ""))
    role = str(target_cfg.get("artifact_role", ""))
    artifact = load_json_if_exists(trust_dir / f"{zone}_{role}.json") or {}
    artifact_certs = artifact.get("certificates", []) if isinstance(artifact.get("certificates"), list) else []
    active_artifact_fps = {
        str(cert.get("fingerprint_sha256", "")).strip().lower()
        for cert in artifact_certs
        if isinstance(cert, dict) and cert.get("fingerprint_sha256")
    }
    runtime = inspect_current_runtime_readonly(target_cfg)
    runtime_entries = runtime.get("files", []) if isinstance(runtime.get("files"), list) else []
    revoked_by_fp = {
        str(cert.get("fingerprint_sha256", "")).strip().lower(): cert
        for cert in revoked_certificates
        if cert.get("fingerprint_sha256")
    }
    old_serials = _crl_serials(old_crl_der)
    new_serials = _crl_serials(new_crl_der)
    newly_revoked_serials = sorted(new_serials - old_serials)

    affected_entries: list[dict[str, Any]] = []
    for entry in runtime_entries:
        if not isinstance(entry, dict):
            continue
        cert_meta = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else None
        if not cert_meta:
            continue
        fp = str(cert_meta.get("fingerprint_sha256", "")).strip().lower()
        if not fp or fp not in revoked_by_fp:
            continue
        affected_entries.append(
            {
                "relative_path": entry.get("relative_path"),
                "fingerprint_sha256": fp,
                "subject": cert_meta.get("subject"),
                "serial_number": cert_meta.get("serial_number"),
                "application_uri": revoked_by_fp[fp].get("application_uri"),
                "classification": _classify_runtime_entry(entry),
                "present_in_active_signed_artifact": fp in active_artifact_fps,
                "review_reason": "runtime entry matches revoked certificate metadata",
            }
        )

    report_id = uuid4().hex
    generated_at = iso_now_z()
    path = revocation_dir / target / f"{generated_at.replace(':', '').replace('-', '')}_{report_id}.json"
    report = {
        "schema": "labshock_phase_8_4_revocation_dry_run_v1",
        "snapshot_reference": "SNAPSHOT_P8_4_REVOCATION_RECONCILED_SAFE_20260512",
        "report_id": report_id,
        "generated_at": generated_at,
        "sync_cycle_id": sync_cycle_id,
        "target": target,
        "runtime_root": str(target_cfg.get("runtime_root", "")),
        "artifact_zone": zone,
        "artifact_role": role,
        "artifact_revision": artifact.get("artifact_revision"),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": runtime_mount_mode,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "merge_policy": merge_policy,
        "crl_changed": old_crl_der != new_crl_der,
        "crl_sha256_before": hashlib.sha256(old_crl_der).hexdigest() if old_crl_der else None,
        "crl_sha256_after": hashlib.sha256(new_crl_der).hexdigest() if new_crl_der else None,
        "newly_revoked_crl_serials": newly_revoked_serials,
        "certificates_revoked_total": len(revoked_certificates),
        "certificates_revoked_known": [
            {
                "certificate_id": cert.get("certificate_id"),
                "application_uri": cert.get("application_uri"),
                "common_name": cert.get("common_name"),
                "fingerprint_sha256": cert.get("fingerprint_sha256"),
                "serial_number": cert.get("serial_number"),
                "revoked_at": cert.get("revoked_at"),
                "crl_contains_serial": str(cert.get("serial_number", "")) in new_serials,
            }
            for cert in revoked_certificates
        ],
        "certificates_newly_revoked": [
            {
                "certificate_id": cert.get("certificate_id"),
                "application_uri": cert.get("application_uri"),
                "common_name": cert.get("common_name"),
                "fingerprint_sha256": cert.get("fingerprint_sha256"),
                "serial_number": cert.get("serial_number"),
                "revoked_at": cert.get("revoked_at"),
                "crl_contains_serial": str(cert.get("serial_number", "")) in new_serials,
            }
            for cert in revoked_certificates
            if str(cert.get("serial_number", "")) in newly_revoked_serials
        ],
        "runtime_trust_entries_affected": affected_entries,
        "deletion_candidates": affected_entries,
        "files_to_remove": [],
        "files_to_remove_count": 0,
        "conservative_merge_blocks_deletion": merge_policy == "conservative_merge",
        "warnings": sorted(set(runtime.get("warnings", []) if isinstance(runtime.get("warnings"), list) else [])),
        "recommended_operator_action": "Review affected runtime entries. Phase 8.4 performs no deletion, no trust-store replacement, and no service restart.",
    }
    write_json_artifact(path, report)
    report["report_path"] = str(path)
    return report


def pull_revocation_update_once(
    *,
    log: logging.Logger,
    base_url: str,
    trust_targets: list[tuple[str, str]],
    trust_dir: Path,
    pki_dir: Path,
    diff_dir: Path,
    telemetry_dir: Path,
    revocation_dir: Path,
    runtime_targets: list[dict[str, Any]],
    requested_target: str,
    require_signed_artifacts: bool,
    pinned_anchor_fingerprint: str,
    sign_debug: bool,
    auth_headers: dict[str, str],
    sync_cycle_id: str,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    runtime_write_enabled: bool,
    fuxa_mount_mode: str,
    opcua_server_mount_mode: str,
    merge_policy: str,
) -> dict[str, Any]:
    old_crl = read_bytes_if_exists(pki_dir / "crl.der")
    if require_signed_artifacts:
        run_sync_cycle_signed(
            log,
            base_url,
            trust_targets,
            trust_dir,
            pki_dir,
            diff_dir,
            telemetry_dir,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
            agent_zone,
            asset_ip,
            control_plane_host,
            pinned_anchor_fingerprint,
            sign_debug,
            auth_headers,
            sync_cycle_id,
        )
    else:
        run_sync_cycle(
            log,
            base_url,
            trust_targets,
            trust_dir,
            pki_dir,
            diff_dir,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
            agent_zone,
            asset_ip,
            control_plane_host,
        )
    new_crl = read_bytes_if_exists(pki_dir / "crl.der")

    with build_gds_http_client(timeout_seconds=10.0) as client:
        inventory = fetch_certificate_inventory(client, base_url, auth_headers)
    revoked_certificates = [cert for cert in inventory if str(cert.get("status", "")).strip().lower() == "revoked"]
    target_map = {str(t.get("target", "")): t for t in runtime_targets}
    selected_names = [requested_target] if requested_target else sorted(target_map)
    reports: list[dict[str, Any]] = []
    for target in selected_names:
        target_cfg = target_map.get(target)
        if not target_cfg:
            raise ValueError(f"target_config_missing:{target}")
        mount_mode = _mount_mode_for_component_target(target, fuxa_mount_mode, opcua_server_mount_mode)
        reports.append(
            build_revocation_dry_run_report(
                target_cfg=target_cfg,
                revoked_certificates=revoked_certificates,
                old_crl_der=old_crl,
                new_crl_der=new_crl,
                trust_dir=trust_dir,
                revocation_dir=revocation_dir,
                merge_policy=merge_policy,
                runtime_write_enabled=runtime_write_enabled,
                runtime_mount_mode=mount_mode,
                sync_cycle_id=sync_cycle_id,
            )
        )

    affected_count = sum(len(r.get("runtime_trust_entries_affected", [])) for r in reports)
    deletion_candidate_count = sum(len(r.get("deletion_candidates", [])) for r in reports)
    result = {
        "schema": "labshock_phase_8_4_revocation_update_result_v1",
        "generated_at": iso_now_z(),
        "snapshot_reference": "SNAPSHOT_P8_4_REVOCATION_RECONCILED_SAFE_20260512",
        "sync_cycle_id": sync_cycle_id,
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "crl_changed": old_crl != new_crl,
        "revoked_certificates_count": len(revoked_certificates),
        "affected_runtime_entries_count": affected_count,
        "deletion_candidates_count": deletion_candidate_count,
        "files_to_remove_count": 0,
        "reports": [
            {
                "target": report.get("target"),
                "report_path": report.get("report_path"),
                "runtime_trust_entries_affected_count": len(report.get("runtime_trust_entries_affected", [])),
                "deletion_candidates_count": len(report.get("deletion_candidates", [])),
                "files_to_remove_count": report.get("files_to_remove_count"),
                "runtime_mount_mode": report.get("runtime_mount_mode"),
            }
            for report in reports
        ],
    }
    forward_ot_collector_event(
        log,
        forward_enabled,
        collector_url,
        collector_timeout_seconds,
        agent_zone,
        asset_ip,
        control_plane_host,
        "info" if affected_count == 0 else "warning",
        "pki_validation",
        "revocation_dry_run_created",
        {
            "sync_cycle_id": sync_cycle_id,
            "crl_changed": result["crl_changed"],
            "revoked_certificates_count": len(revoked_certificates),
            "affected_runtime_entries_count": affected_count,
            "deletion_candidates_count": deletion_candidate_count,
            "files_to_remove_count": 0,
            "runtime_mutation_performed": False,
        },
        {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "risk_level": "LOW" if affected_count == 0 else "MEDIUM"},
        collector_max_message_len,
        collector_max_raw_len,
        collector_max_payload_bytes,
    )
    return result


def _normalize_relative_path(path: str) -> str:
    return str(path or "").replace("\\", "/").strip().lstrip("/")


def _load_revocation_report(
    *,
    revocation_dir: Path,
    target: str,
    report_id: str,
) -> tuple[Path | None, dict[str, Any] | None]:
    target_dir = revocation_dir / target
    if not target_dir.exists():
        return None, None
    files = sorted(target_dir.glob("*.json"))
    if not files:
        return None, None
    if report_id:
        for file in reversed(files):
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("report_id", "")) == report_id or report_id in file.name:
                return file, payload
        return None, None
    latest = files[-1]
    try:
        return latest, json.loads(latest.read_text(encoding="utf-8"))
    except Exception:
        return latest, None


def _load_quarantine_plan(quarantine_plan_dir: Path, target: str, plan_id: str) -> tuple[Path | None, dict[str, Any] | None]:
    target_dir = quarantine_plan_dir / target
    if not target_dir.exists():
        return None, None
    files = sorted(target_dir.glob("*.json"))
    for file in reversed(files):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(payload.get("plan_id", "")) == plan_id:
            return file, payload
    return None, None


def _is_quarantine_eligible_runtime_path(relative_path: str) -> bool:
    rel = _normalize_relative_path(relative_path).lower()
    if not rel:
        return False
    if _is_private_key_path(Path(rel), rel):
        return False
    if "/own/" in rel or rel.startswith("own/"):
        return False
    return (
        rel.startswith("applcerts/trusted/certs/")
        or rel.startswith("trusted/certs/")
        or rel.startswith("applcerts/rejected/")
        or rel.startswith("rejected/")
    )


def _runtime_cert_entry_map(runtime_files: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in runtime_files:
        if not isinstance(entry, dict):
            continue
        rel = _normalize_relative_path(str(entry.get("relative_path", "")))
        cert = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else {}
        fp = str(cert.get("fingerprint_sha256", "")).strip().lower()
        if not rel or not fp:
            continue
        out[(rel, fp)] = entry
    return out


def _candidate_from_runtime_entry(entry: dict[str, Any], revoked_meta: dict[str, Any]) -> dict[str, Any]:
    cert = entry.get("certificate") if isinstance(entry.get("certificate"), dict) else {}
    rel = _normalize_relative_path(str(entry.get("relative_path", "")))
    return {
        "relative_path": rel,
        "fingerprint_sha256": str(cert.get("fingerprint_sha256", "")).strip().lower(),
        "subject": cert.get("subject"),
        "serial_number": cert.get("serial_number"),
        "application_uri": revoked_meta.get("application_uri"),
        "certificate_id": revoked_meta.get("certificate_id"),
        "revoked_at": revoked_meta.get("revoked_at"),
        "classification": _classify_runtime_entry(entry),
        "review_reason": "runtime entry matches revoked certificate metadata",
    }


def _latest_rollback_preflight_for_target(
    rollback_preflight_dir: Path,
    target: str,
) -> tuple[Path | None, dict[str, Any] | None]:
    return find_latest_json_for_target(rollback_preflight_dir, target)


def quarantine_revoked_dry_run_once(
    *,
    target_cfg: dict[str, Any],
    revocation_dir: Path,
    quarantine_plan_dir: Path,
    rollback_preflight_dir: Path,
    report_id: str,
    runtime_write_enabled: bool,
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    generated_at = iso_now_z()
    plan_id = uuid4().hex
    revocation_report_path, revocation_report = _load_revocation_report(
        revocation_dir=revocation_dir,
        target=target,
        report_id=report_id,
    )
    rollback_preflight_path, rollback_preflight = _latest_rollback_preflight_for_target(rollback_preflight_dir, target)
    base = {
        "schema": "labshock_phase_8_7_quarantine_dry_run_v1",
        "generated_at": generated_at,
        "target": target,
        "plan_id": plan_id,
        "runtime_root": str(target_cfg.get("runtime_root", "")),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "revocation_report_id": report_id or "",
        "revocation_report_path": str(revocation_report_path) if revocation_report_path else "",
        "rollback_preflight_required": True,
        "rollback_preflight_found": bool(rollback_preflight),
        "rollback_preflight_path": str(rollback_preflight_path) if rollback_preflight_path else "",
        "rollback_target_revoked": bool((rollback_preflight or {}).get("rollback_target_certificate_revoked", False)),
        "rollback_execution_allowed": str((rollback_preflight or {}).get("decision", "")) == "eligible",
        "revoked_runtime_entries": [],
        "quarantine_candidates": [],
        "files_to_move": [],
        "files_to_delete": [],
        "decision": "blocked",
        "reason": "",
        "blocking_reasons": [],
        "warnings": [],
    }

    if not isinstance(revocation_report, dict):
        base["blocking_reasons"] = ["revocation_report_missing"]
        base["reason"] = "revocation_report_missing"
    else:
        runtime = inspect_current_runtime_readonly(target_cfg)
        runtime_files = runtime.get("files", []) if isinstance(runtime.get("files"), list) else []
        runtime_index = _runtime_cert_entry_map(runtime_files)
        warnings = list(runtime.get("warnings", [])) if isinstance(runtime.get("warnings"), list) else []
        revoked_known = revocation_report.get("certificates_revoked_known", [])
        revoked_by_fp = {
            str(item.get("fingerprint_sha256", "")).strip().lower(): item
            for item in revoked_known
            if isinstance(item, dict) and item.get("fingerprint_sha256")
        }
        affected = revocation_report.get("runtime_trust_entries_affected", [])
        active_revoked_entries: list[dict[str, Any]] = []
        quarantine_candidates: list[dict[str, Any]] = []
        for entry in affected if isinstance(affected, list) else []:
            if not isinstance(entry, dict):
                continue
            rel = _normalize_relative_path(str(entry.get("relative_path", "")))
            fp = str(entry.get("fingerprint_sha256", "")).strip().lower()
            if not rel or not fp:
                continue
            runtime_entry = runtime_index.get((rel, fp))
            if not runtime_entry:
                continue
            revoked_meta = revoked_by_fp.get(fp, {})
            active_entry = _candidate_from_runtime_entry(runtime_entry, revoked_meta)
            active_revoked_entries.append(active_entry)
            if _is_quarantine_eligible_runtime_path(rel):
                quarantine_candidates.append(active_entry)
            else:
                warnings.append(f"quarantine_ineligible_path_preserved:{rel}")

        base["revoked_runtime_entries"] = active_revoked_entries
        base["quarantine_candidates"] = quarantine_candidates
        base["files_to_move"] = [item["relative_path"] for item in quarantine_candidates]
        base["warnings"] = sorted(set(warnings))
        if not active_revoked_entries:
            base["decision"] = "not_applicable"
            base["reason"] = "no_revoked_runtime_entries_found"
        elif not quarantine_candidates:
            base["decision"] = "not_applicable"
            base["reason"] = "no_quarantine_eligible_revoked_entries_found"
        else:
            base["decision"] = "ready_for_quarantine"
            base["reason"] = "quarantine_candidates_ready"

    out_dir = quarantine_plan_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{plan_id}.json"
    write_json_artifact(out_path, base)
    base["plan_path"] = str(out_path)
    return base


def activate_revocation_quarantine_once(
    *,
    target_cfg: dict[str, Any],
    quarantine_plan_dir: Path,
    quarantine_receipt_dir: Path,
    runtime_quarantine_dir: Path,
    rollback_preflight_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    plan_id: str,
    runtime_write_enabled: bool,
    runtime_activation_targets: list[str],
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server"}:
        raise ValueError("target_not_enabled_for_quarantine")
    if not plan_id:
        raise ValueError("quarantine_activation_requires_plan_id")

    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    generated_at = iso_now_z()
    plan_path, plan = _load_quarantine_plan(quarantine_plan_dir, target, plan_id)
    if not isinstance(plan, dict):
        raise FileNotFoundError("quarantine_plan_missing")

    receipt_base = {
        "schema": "labshock_phase_8_7_quarantine_receipt_v1",
        "target": target,
        "plan_id": plan_id,
        "created_at": generated_at,
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "status": "blocked",
        "moved_files": [],
        "files_deleted": [],
        "private_key_material_touched": False,
        "safe_mode_restored": (not runtime_write_enabled and mount_mode == "ro"),
        "rollback_pointer": str((plan or {}).get("rollback_preflight_path", "")),
        "plan_path": str(plan_path) if plan_path else "",
        "blocking_reasons": [],
        "warnings": [],
    }
    if str(plan.get("decision", "")) != "ready_for_quarantine":
        receipt_base["status"] = "not_applicable"
        receipt_base["blocking_reasons"] = [str(plan.get("reason", "quarantine_plan_not_ready"))]
    else:
        blocking_reasons: list[str] = []
        warnings: list[str] = []
        if not runtime_write_enabled:
            blocking_reasons.append("runtime_write_disabled")
        if mount_mode != "rw":
            blocking_reasons.append("runtime_mount_not_writable")
        if target not in runtime_activation_targets:
            blocking_reasons.append("target_not_enabled_for_phase_8_7")

        mw = maintenance_window_status(target, maintenance_policy)
        if bool(mw.get("within_blackout")):
            blocking_reasons.append("blackout_period_active")
        elif bool(mw.get("window_required")) and not bool(mw.get("within_window")):
            blocking_reasons.append("maintenance_window_closed")
        approval_level = str((mw.get("policy") or {}).get("approval_level", "single")).lower()
        approval, approval_status = load_active_approval_for_target(approvals_dir, target, approval_signer, approval_level)
        if not approval:
            blocking_reasons.append(approval_status or "approval_missing")

        rollback_preflight_path, rollback_preflight = _latest_rollback_preflight_for_target(rollback_preflight_dir, target)
        if not rollback_preflight:
            blocking_reasons.append("rollback_preflight_missing")
        else:
            if str(rollback_preflight.get("decision", "")) == "not_applicable":
                blocking_reasons.append("rollback_preflight_not_applicable")
            if bool(rollback_preflight.get("rollback_target_certificate_revoked", False)):
                warnings.append("rollback_target_certificate_revoked")

        revocation_report_path = Path(str(plan.get("revocation_report_path", ""))) if plan.get("revocation_report_path") else None
        if not revocation_report_path or not revocation_report_path.exists():
            blocking_reasons.append("revocation_report_missing")

        candidates = plan.get("quarantine_candidates", []) if isinstance(plan.get("quarantine_candidates"), list) else []
        if not candidates:
            receipt_base["status"] = "not_applicable"
            receipt_base["blocking_reasons"] = ["no_quarantine_candidates"]
            receipt_base["warnings"] = warnings
        elif blocking_reasons:
            receipt_base["status"] = "blocked"
            receipt_base["blocking_reasons"] = blocking_reasons
            receipt_base["warnings"] = warnings
        else:
            runtime_root = Path(str(target_cfg.get("runtime_root", "")))
            _ensure_runtime_writable(runtime_root)
            moved_files: list[dict[str, Any]] = []
            quarantine_root = runtime_quarantine_dir / target / plan_id
            revoked_dir = quarantine_root / "revoked"
            metadata_dir = quarantine_root / "metadata"
            revoked_dir.mkdir(parents=True, exist_ok=True)
            metadata_dir.mkdir(parents=True, exist_ok=True)
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                rel = _normalize_relative_path(str(item.get("relative_path", "")))
                if not rel or not _is_quarantine_eligible_runtime_path(rel):
                    continue
                src = runtime_root / rel
                _assert_path_inside(runtime_root, src)
                if not src.exists() or not src.is_file():
                    continue
                before_sha = _file_sha256(src)
                dst = revoked_dir / rel
                _assert_path_inside(revoked_dir, dst)
                _copy_file_bytes_only(src, dst)
                after_sha = _file_sha256(dst)
                if before_sha != after_sha:
                    raise ValueError(f"quarantine_copy_checksum_mismatch:{rel}")
                src.unlink()
                moved_files.append(
                    {
                        "from": rel,
                        "to": str(dst),
                        "sha256": after_sha,
                        "certificate_id": item.get("certificate_id"),
                        "serial_number": item.get("serial_number"),
                        "fingerprint_sha256": item.get("fingerprint_sha256"),
                        "revoked_at": item.get("revoked_at"),
                    }
                )

            write_json_artifact(
                metadata_dir / "tombstones.json",
                {
                    "schema": "labshock_phase_8_7_quarantine_tombstones_v1",
                    "created_at": generated_at,
                    "target": target,
                    "plan_id": plan_id,
                    "moved_files": moved_files,
                },
            )
            if moved_files:
                receipt_base["status"] = "quarantined"
                receipt_base["runtime_mutation_performed"] = True
                receipt_base["safe_mode_restored"] = False
            else:
                receipt_base["status"] = "not_applicable"
                receipt_base["blocking_reasons"] = ["no_quarantine_candidates_present_in_runtime"]
            receipt_base["moved_files"] = moved_files
            receipt_base["warnings"] = warnings
            if rollback_preflight_path:
                receipt_base["rollback_pointer"] = str(rollback_preflight_path)

    out_dir = quarantine_receipt_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    receipt_id = uuid4().hex
    out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{receipt_id}.json"
    write_json_artifact(out_path, receipt_base)
    receipt_base["receipt_path"] = str(out_path)
    return receipt_base


def _latest_quarantine_receipt_for_plan(
    quarantine_receipt_dir: Path,
    target: str,
    plan_id: str,
) -> tuple[Path | None, dict[str, Any] | None]:
    target_dir = quarantine_receipt_dir / target
    if not target_dir.exists():
        return None, None
    files = sorted(target_dir.glob("*.json"))
    for file in reversed(files):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(payload.get("plan_id", "")) == plan_id:
            return file, payload
    return None, None


def validate_revocation_quarantine_once(
    *,
    target_cfg: dict[str, Any],
    quarantine_plan_dir: Path,
    quarantine_receipt_dir: Path,
    runtime_quarantine_dir: Path,
    quarantine_validation_dir: Path,
    plan_id: str,
    runtime_write_enabled: bool,
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server"}:
        raise ValueError("target_not_enabled_for_quarantine")
    if not plan_id:
        raise ValueError("quarantine_validation_requires_plan_id")
    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    generated_at = iso_now_z()
    plan_path, plan = _load_quarantine_plan(quarantine_plan_dir, target, plan_id)
    receipt_path, receipt = _latest_quarantine_receipt_for_plan(quarantine_receipt_dir, target, plan_id)
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    validation = {
        "schema": "labshock_phase_8_7_quarantine_validation_v1",
        "generated_at": generated_at,
        "target": target,
        "plan_id": plan_id,
        "runtime_root": str(runtime_root),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "safe_mode_restored": (not runtime_write_enabled and mount_mode == "ro"),
        "plan_found": bool(plan),
        "plan_path": str(plan_path) if plan_path else "",
        "receipt_found": bool(receipt),
        "receipt_path": str(receipt_path) if receipt_path else "",
        "status": "failed",
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "moved_files_validated_count": 0,
        "moved_files_missing_in_quarantine": [],
        "moved_files_still_present_in_runtime": [],
        "sha256_mismatches": [],
        "private_key_material_touched": bool((receipt or {}).get("private_key_material_touched", False)),
        "blocking_reasons": [],
    }
    if not plan:
        validation["blocking_reasons"] = ["quarantine_plan_missing"]
    elif not receipt:
        validation["blocking_reasons"] = ["quarantine_receipt_missing"]
    else:
        moved_files = receipt.get("moved_files", []) if isinstance(receipt.get("moved_files"), list) else []
        if not moved_files and str(receipt.get("status", "")) == "not_applicable":
            validation["status"] = "not_applicable"
        else:
            missing_quarantine: list[str] = []
            still_in_runtime: list[str] = []
            sha_mismatches: list[dict[str, Any]] = []
            checked = 0
            for moved in moved_files:
                if not isinstance(moved, dict):
                    continue
                rel = _normalize_relative_path(str(moved.get("from", "")))
                if not rel:
                    continue
                src = runtime_root / rel
                dst = Path(str(moved.get("to", "")))
                if src.exists():
                    still_in_runtime.append(rel)
                if not dst.exists() or not dst.is_file():
                    missing_quarantine.append(str(dst))
                    continue
                expected_sha = str(moved.get("sha256", "")).strip().lower()
                actual_sha = _file_sha256(dst)
                checked += 1
                if expected_sha and expected_sha != actual_sha:
                    sha_mismatches.append(
                        {
                            "path": str(dst),
                            "expected_sha256": expected_sha,
                            "actual_sha256": actual_sha,
                        }
                    )
            validation["moved_files_validated_count"] = checked
            validation["moved_files_missing_in_quarantine"] = missing_quarantine
            validation["moved_files_still_present_in_runtime"] = still_in_runtime
            validation["sha256_mismatches"] = sha_mismatches
            validation["runtime_mutation_performed"] = bool(receipt.get("runtime_mutation_performed", False))
            validation["runtime_restart_automatic"] = bool(receipt.get("runtime_restart_automatic", False))
            if str(receipt.get("status", "")) == "quarantined" and not missing_quarantine and not still_in_runtime and not sha_mismatches:
                validation["status"] = "validated"
            elif str(receipt.get("status", "")) == "not_applicable":
                validation["status"] = "not_applicable"
            else:
                validation["status"] = "failed"
                reasons: list[str] = []
                if missing_quarantine:
                    reasons.append("quarantine_files_missing")
                if still_in_runtime:
                    reasons.append("runtime_files_not_moved")
                if sha_mismatches:
                    reasons.append("quarantine_file_checksum_mismatch")
                validation["blocking_reasons"] = reasons
    out_dir = quarantine_validation_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    validation_id = uuid4().hex
    out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{validation_id}.json"
    write_json_artifact(out_path, validation)
    validation["validation_path"] = str(out_path)
    return validation


def emergency_rollback_preflight_once(
    *,
    target_cfg: dict[str, Any],
    rollback_root: Path,
    emergency_rollback_preflight_dir: Path,
    pki_dir: Path,
    base_url: str,
    auth_headers: dict[str, str],
    plan_id: str,
    runtime_write_enabled: bool,
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server"}:
        raise ValueError("target_not_enabled_for_emergency_rollback_preflight")
    if not plan_id:
        raise ValueError("emergency_rollback_preflight_requires_plan_id")

    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    runtime_cert = _load_runtime_certificate(target, runtime_root)
    runtime_identity = _certificate_identity(runtime_cert)
    runtime_serial_dec = str(runtime_cert.serial_number)
    runtime_serial_hex = format(runtime_cert.serial_number, "x")
    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    manifest_path = rollback_root / target / plan_id / "rollback-manifest.json"
    generated_at = iso_now_z()

    base_report = {
        "schema": "labshock_phase_8_7_emergency_rollback_preflight_v1",
        "generated_at": generated_at,
        "target": target,
        "plan_id": plan_id,
        "runtime_root": str(runtime_root),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "runtime_certificate": {
            "fingerprint_sha256": runtime_identity.get("fingerprint_sha256"),
            "subject": runtime_identity.get("subject"),
            "application_uri": runtime_identity.get("application_uri"),
            "serial_number_dec": runtime_serial_dec,
            "serial_number_hex": runtime_serial_hex,
            "not_after": runtime_identity.get("not_after"),
        },
        "rollback_manifest_found": False,
        "rollback_manifest_path": str(manifest_path),
        "rollback_snapshot_found": False,
        "rollback_snapshot_dir": "",
        "rollback_manifest_integrity": {
            "integrity_ok": False,
            "checked_files_count": 0,
            "missing_files": [],
            "sha256_mismatches": [],
            "invalid_entries_count": 0,
        },
        "private_key_material_copied": None,
        "runtime_certificate_gds": {},
        "rollback_snapshot_certificate_gds": {},
        "runtime_package_status": {},
        "rollback_snapshot_package_status": {},
        "rollback_target_certificate_status": "unknown",
        "rollback_target_certificate_revoked": False,
        "rollback_target_crl_serial_match": False,
        "decision": "not_applicable",
        "blocking_reasons": ["rollback_manifest_missing"],
        "emergency_override_possible": False,
        "emergency_execution_implemented": False,
        "recommended_operator_action": "Emergency rollback preflight is not applicable because rollback evidence is missing.",
    }
    if not manifest_path.exists() or not manifest_path.is_file():
        out_dir = emergency_rollback_preflight_dir / target
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{uuid4().hex}.json"
        write_json_artifact(out_path, base_report)
        base_report["report_path"] = str(out_path)
        return base_report

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    snapshot_dir_raw = str(manifest.get("snapshot_dir", "")).strip()
    snapshot_dir = Path(snapshot_dir_raw) if snapshot_dir_raw else (rollback_root / target / plan_id / "PKI")
    _assert_path_inside(rollback_root / target / plan_id, snapshot_dir)
    if not snapshot_dir.exists() or not snapshot_dir.is_dir():
        base_report.update(
            {
                "rollback_manifest_found": True,
                "private_key_material_copied": bool(manifest.get("private_key_material_copied")),
                "rollback_snapshot_dir": str(snapshot_dir),
                "decision": "not_applicable",
                "blocking_reasons": ["rollback_snapshot_missing"],
                "recommended_operator_action": "Emergency rollback preflight is not applicable because rollback snapshot files are missing.",
            }
        )
        out_dir = emergency_rollback_preflight_dir / target
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{uuid4().hex}.json"
        write_json_artifact(out_path, base_report)
        base_report["report_path"] = str(out_path)
        return base_report

    snapshot_cert = _load_runtime_certificate(target, snapshot_dir)
    snapshot_identity = _certificate_identity(snapshot_cert)
    snapshot_serial_dec = str(snapshot_cert.serial_number)
    snapshot_serial_hex = format(snapshot_cert.serial_number, "x")
    manifest_integrity = _rollback_manifest_integrity(manifest=manifest, snapshot_dir=snapshot_dir)
    private_key_material_copied = bool(manifest.get("private_key_material_copied"))
    crl_serials = _crl_serials(read_bytes_if_exists(pki_dir / "crl.der"))

    with build_gds_http_client(timeout_seconds=10.0) as client:
        inventory = fetch_certificate_inventory(client, base_url, auth_headers)
        runtime_cert_gds = _find_certificate_by_fingerprint(inventory, str(runtime_identity.get("fingerprint_sha256", "")))
        rollback_cert_gds = _find_certificate_by_fingerprint(inventory, str(snapshot_identity.get("fingerprint_sha256", "")))
        app_uri = str(
            (runtime_cert_gds or {}).get("application_uri")
            or (rollback_cert_gds or {}).get("application_uri")
            or runtime_identity.get("application_uri")
            or snapshot_identity.get("application_uri")
            or ""
        )
        package_inventory = fetch_package_inventory_for_application(client, base_url, auth_headers, app_uri)

    runtime_package = _latest_package_for_certificate(package_inventory, (runtime_cert_gds or {}).get("certificate_id"))
    rollback_package = _latest_package_for_certificate(package_inventory, (rollback_cert_gds or {}).get("certificate_id"))

    rollback_status = str((rollback_cert_gds or {}).get("status", "")).strip().lower() or "unknown"
    rollback_serial_in_crl = snapshot_serial_dec in crl_serials or snapshot_serial_hex in crl_serials
    rollback_revoked = rollback_status == "revoked" or rollback_serial_in_crl

    blocking_reasons: list[str] = []
    if not manifest_integrity.get("integrity_ok"):
        blocking_reasons.append("rollback_manifest_integrity_failed")
    if private_key_material_copied:
        blocking_reasons.append("rollback_snapshot_private_key_material_present")
    if rollback_revoked:
        blocking_reasons.append("rollback_target_certificate_revoked")

    decision = "eligible"
    if rollback_revoked:
        decision = "blocked"
    elif blocking_reasons:
        decision = "blocked"
    recommended_action = (
        "Emergency rollback preflight is blocked. Keep current runtime and investigate blocking reasons."
        if decision == "blocked"
        else "Emergency rollback preflight is eligible, but execution is not implemented in this phase."
    )

    report = {
        **base_report,
        "rollback_manifest_found": True,
        "rollback_snapshot_found": True,
        "rollback_snapshot_dir": str(snapshot_dir),
        "rollback_manifest_integrity": manifest_integrity,
        "private_key_material_copied": private_key_material_copied,
        "runtime_certificate_gds": runtime_cert_gds or {},
        "rollback_snapshot_certificate_gds": rollback_cert_gds or {},
        "runtime_package_status": runtime_package or {},
        "rollback_snapshot_package_status": rollback_package or {},
        "rollback_target_certificate_status": rollback_status,
        "rollback_target_certificate_revoked": rollback_revoked,
        "rollback_target_crl_serial_match": rollback_serial_in_crl,
        "decision": decision,
        "blocking_reasons": blocking_reasons,
        "emergency_override_possible": False,
        "emergency_execution_implemented": False,
        "recommended_operator_action": recommended_action,
    }

    out_dir = emergency_rollback_preflight_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{generated_at.replace(':', '').replace('-', '')}_{uuid4().hex}.json"
    write_json_artifact(out_path, report)
    report["report_path"] = str(out_path)
    return report


def _copy_file_bytes_only(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as in_file, tempfile.NamedTemporaryFile("wb", dir=dst.parent, delete=False) as tmp_file:
        tmp_path = Path(tmp_file.name)
        shutil.copyfileobj(in_file, tmp_file)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
    try:
        os.replace(tmp_path, dst)
    except Exception:
        with suppress(Exception):
            tmp_path.unlink()
        raise


def _runtime_stage_mismatches(runtime_root: Path, stage_checksums: dict[str, str]) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for rel, expected_sha256 in sorted(stage_checksums.items()):
        if _is_preserved_runtime_path(rel):
            continue
        dst = runtime_root / rel
        _assert_path_inside(runtime_root, dst)
        if not dst.exists() or not dst.is_file():
            mismatches.append({"relative_path": rel, "reason": "missing_runtime_file"})
            continue
        actual_sha256 = _file_sha256(dst)
        if actual_sha256 != expected_sha256:
            mismatches.append({"relative_path": rel, "reason": "sha256_mismatch"})
    return mismatches


def _private_key_sha256(runtime_root: Path, target: str) -> str:
    return _file_sha256(_runtime_private_key_path(target, runtime_root))


def _snapshot_runtime_non_private(runtime_root: Path, rollback_root: Path, target: str, plan_id: str) -> dict[str, Any]:
    snapshot_dir = rollback_root / target / plan_id / "PKI"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    copied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for src in sorted(runtime_root.rglob("*")):
        if not src.is_file():
            continue
        rel = str(src.relative_to(runtime_root)).replace("\\", "/")
        if _is_private_key_path(src, rel):
            skipped.append({"relative_path": rel, "reason": "private_key_not_copied"})
            continue
        dst = snapshot_dir / rel
        _copy_file_bytes_only(src, dst)
        copied.append({"relative_path": rel, "sha256": _file_sha256(dst)})
    manifest = {
        "target": target,
        "plan_id": plan_id,
        "created_at": iso_now_z(),
        "snapshot_dir": str(snapshot_dir),
        "private_key_material_copied": False,
        "copied_files": copied,
        "skipped_files": skipped,
    }
    write_json_artifact(rollback_root / target / plan_id / "rollback-manifest.json", manifest)
    return manifest


def activate_package_runtime(
    *,
    target_cfg: dict[str, Any],
    manifest: dict[str, Any],
    stage_dir: Path,
    stage_checksums: dict[str, str],
    validation: dict[str, Any],
    rollback_root: Path,
    receipts_root: Path,
    gate: dict[str, Any],
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server", "dmz-gateway-client", "dmz-gateway-server"}:
        raise ValueError("target_not_enabled_for_live_activation")
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    _ensure_runtime_writable(runtime_root)
    _verify_certificate_matches_runtime_key(target, manifest, runtime_root)
    plan_id = str(validation.get("plan_id") or stage_dir.name)
    package_id = str(manifest.get("package_id", ""))
    shadow_dir = stage_dir / "shadow-trust-store"
    private_key_sha256_before = _private_key_sha256(runtime_root, target)
    mismatches = _runtime_stage_mismatches(runtime_root, stage_checksums)
    if not mismatches:
        return {
            "status": "already_activated",
            "receipt_written": False,
            "created_at": iso_now_z(),
            "target": target,
            "package_id": package_id,
            "generation": manifest.get("generation"),
            "plan_id": plan_id,
            "runtime_root": str(runtime_root),
            "changed_files": [],
            "preserved_files": [],
            "runtime_write_enabled": True,
            "runtime_restart_automatic": False,
            "private_key_overwritten": False,
            "private_key_sha256_before": private_key_sha256_before,
            "private_key_sha256_after": private_key_sha256_before,
            "private_key_sha256_unchanged": True,
        }
    rollback = _snapshot_runtime_non_private(runtime_root, rollback_root, target, plan_id)
    changed: list[dict[str, Any]] = []
    preserved: list[dict[str, Any]] = []
    for rel in sorted(stage_checksums.keys()):
        if _is_preserved_runtime_path(rel):
            preserved.append({"relative_path": rel, "reason": "private_or_runtime_local_preserved"})
            continue
        src = shadow_dir / rel
        dst = runtime_root / rel
        _assert_path_inside(shadow_dir, src)
        _assert_path_inside(runtime_root, dst)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"staged file missing: {rel}")
        before = _file_sha256(dst) if dst.exists() and dst.is_file() else None
        _copy_file_bytes_only(src, dst)
        after = _file_sha256(dst)
        if after != stage_checksums[rel]:
            raise ValueError(f"post_copy_checksum_mismatch:{rel}")
        changed.append(
            {
                "relative_path": rel,
                "action": "updated" if before else "added",
                "before_sha256": before,
                "after_sha256": after,
            }
        )
    private_key_sha256_after = _private_key_sha256(runtime_root, target)
    receipt = {
        "receipt_id": uuid4().hex,
        "created_at": iso_now_z(),
        "status": "activated",
        "target": target,
        "package_id": package_id,
        "generation": manifest.get("generation"),
        "plan_id": plan_id,
        "runtime_root": str(runtime_root),
        "rollback_manifest": rollback.get("snapshot_dir"),
        "changed_files": changed,
        "preserved_files": preserved,
        "gate": {
            "status": gate.get("status"),
            "blocked_reason": gate.get("blocked_reason"),
            "emergency_override_requested": gate.get("emergency_override_requested"),
        },
        "stage_validation": {
            "checksum_verified": validation.get("checksum_verified"),
            "maintenance_window_status": validation.get("maintenance_window_status"),
            "blackout_status": validation.get("blackout_status"),
            "approvals_valid": validation.get("approvals_valid"),
        },
        "runtime_write_enabled": True,
        "runtime_restart_automatic": False,
        "private_key_overwritten": False,
        "private_key_sha256_before": private_key_sha256_before,
        "private_key_sha256_after": private_key_sha256_after,
        "private_key_sha256_unchanged": private_key_sha256_before == private_key_sha256_after,
    }
    receipt_dir = receipts_root / target
    receipt_dir.mkdir(parents=True, exist_ok=True)
    write_json_artifact(receipt_dir / f"{receipt['created_at'].replace(':', '').replace('-', '')}_{receipt['receipt_id']}.json", receipt)
    return receipt


def write_activation_failure_receipt(
    receipts_root: Path,
    *,
    target: str,
    package_id: str,
    plan_id: str,
    failure_code: str,
    error: str,
    mutation_started: bool = False,
) -> dict[str, Any]:
    receipt = {
        "receipt_id": uuid4().hex,
        "created_at": iso_now_z(),
        "target": target,
        "package_id": package_id,
        "plan_id": plan_id,
        "status": "failed",
        "failure_code": failure_code,
        "error": truncate_text(error, 500),
        "mutation_started": mutation_started,
        "activated": False,
        "auto_rollback_performed": False,
    }
    receipt_dir = receipts_root / (target or "unknown")
    receipt_dir.mkdir(parents=True, exist_ok=True)
    write_json_artifact(receipt_dir / f"{receipt['created_at'].replace(':', '').replace('-', '')}_{receipt['receipt_id']}_failure.json", receipt)
    return receipt


def _latest_activation_receipt(
    receipts_root: Path,
    target: str,
    package_id: str = "",
    plan_id: str = "",
    statuses: set[str] | None = None,
) -> dict[str, Any] | None:
    receipt_dir = receipts_root / target
    if not receipt_dir.exists():
        return None
    for file in reversed(sorted(receipt_dir.glob("*.json"))):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if package_id and str(payload.get("package_id", "")) != package_id:
            continue
        if plan_id and str(payload.get("plan_id", "")) != plan_id:
            continue
        if statuses and str(payload.get("status", "")) not in statuses:
            continue
        payload["_receipt_path"] = str(file)
        return payload
    return None


def validate_package_activation_state(
    *,
    target_cfg: dict[str, Any],
    package_dir: Path,
    runtime_stage_dir: Path,
    activation_receipt_dir: Path,
    package_id: str,
    plan_id: str,
    runtime_write_enabled: bool,
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str = "ro",
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server"}:
        raise ValueError("target_not_enabled_for_live_activation")
    manifest = load_cached_package_manifest(package_dir, package_id) if package_id else {}
    resolved_package_id = str(package_id or manifest.get("package_id", ""))
    stage_dir, validation, checksums = _find_package_stage_bundle(runtime_stage_dir, target, resolved_package_id, plan_id)
    stage_checksums = _validate_stage_bundle(stage_dir, validation, checksums, resolved_package_id)
    resolved_plan_id = str(validation.get("plan_id") or stage_dir.name)
    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    mismatches = _runtime_stage_mismatches(runtime_root, stage_checksums)
    receipt = _latest_activation_receipt(
        activation_receipt_dir,
        target,
        resolved_package_id,
        resolved_plan_id,
        statuses={"activated"},
    ) or _latest_activation_receipt(activation_receipt_dir, target, resolved_package_id, resolved_plan_id)
    current_private_key_sha256 = _private_key_sha256(runtime_root, target)
    private_key_unchanged: bool | None = None
    receipt_status = ""
    if receipt:
        receipt_status = str(receipt.get("status") or "")
        if not receipt_status and receipt.get("private_key_overwritten") is False and receipt.get("changed_files"):
            receipt_status = "activated_legacy"
        before = str(receipt.get("private_key_sha256_before", ""))
        after = str(receipt.get("private_key_sha256_after", ""))
        if before and after:
            private_key_unchanged = before == after == current_private_key_sha256
    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    return {
        "schema": "labshock_phase_8_package_activation_validation_v1",
        "generated_at": iso_now_z(),
        "target": target,
        "package_id": resolved_package_id,
        "generation": manifest.get("generation"),
        "plan_id": resolved_plan_id,
        "runtime_root": str(runtime_root),
        "runtime_matches_stage": not mismatches,
        "runtime_mismatches": mismatches,
        "activation_receipt_found": bool(receipt),
        "activation_receipt_path": receipt.get("_receipt_path") if receipt else "",
        "activation_receipt_status": receipt_status,
        "private_key_overwritten": bool(receipt.get("private_key_overwritten")) if receipt else None,
        "private_key_sha256_unchanged": private_key_unchanged,
        "private_key_checksum_evidence": "receipt_sha256_match" if private_key_unchanged else ("legacy_receipt_without_sha256" if receipt_status == "activated_legacy" else "unavailable"),
        "safe_mode_restored": (not runtime_write_enabled and mount_mode == "ro"),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
    }


def validate_fuxa_activation_state(**kwargs: Any) -> dict[str, Any]:
    return validate_package_activation_state(**kwargs)


def _find_certificate_by_fingerprint(
    inventory: list[dict[str, Any]], fingerprint_sha256: str
) -> dict[str, Any] | None:
    fp = str(fingerprint_sha256 or "").strip().lower()
    if not fp:
        return None
    for item in inventory:
        if str(item.get("fingerprint_sha256", "")).strip().lower() == fp:
            return item
    return None


def fetch_package_inventory_for_application(
    client: httpx.Client,
    base_url: str,
    headers: dict[str, str],
    application_uri: str,
) -> list[dict[str, Any]]:
    if not application_uri:
        return []
    res = client.get(
        f"{base_url}/api/v1/packages",
        headers=headers,
        params={"application_uri": application_uri},
    )
    res.raise_for_status()
    payload = res.json()
    if not isinstance(payload, list):
        return []
    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "package_id": item.get("package_id"),
                "certificate_id": item.get("certificate_id"),
                "lifecycle_state": item.get("lifecycle_state"),
                "generation": item.get("generation"),
                "supersedes_package_id": item.get("supersedes_package_id"),
                "created_at": item.get("created_at"),
            }
        )
    return out


def _latest_package_for_certificate(packages: list[dict[str, Any]], certificate_id: Any) -> dict[str, Any] | None:
    if certificate_id is None:
        return None
    matches = [p for p in packages if str(p.get("certificate_id", "")) == str(certificate_id)]
    if not matches:
        return None
    matches.sort(
        key=lambda p: (
            int(p.get("generation") or 0),
            str(p.get("created_at") or ""),
        ),
        reverse=True,
    )
    return matches[0]


def _rollback_manifest_integrity(
    *,
    manifest: dict[str, Any],
    snapshot_dir: Path,
) -> dict[str, Any]:
    copied_files = manifest.get("copied_files", [])
    if not isinstance(copied_files, list):
        return {
            "integrity_ok": False,
            "checked_files_count": 0,
            "missing_files": [],
            "sha256_mismatches": [],
            "invalid_entries_count": 1,
        }
    missing: list[str] = []
    mismatches: list[dict[str, Any]] = []
    invalid_entries = 0
    checked = 0
    for item in copied_files:
        if not isinstance(item, dict):
            invalid_entries += 1
            continue
        rel = str(item.get("relative_path", "")).strip()
        expected = str(item.get("sha256", "")).strip().lower()
        if not rel or len(expected) != 64:
            invalid_entries += 1
            continue
        candidate = snapshot_dir / rel
        try:
            _assert_path_inside(snapshot_dir, candidate)
        except Exception:
            invalid_entries += 1
            continue
        if not candidate.exists() or not candidate.is_file():
            missing.append(rel)
            continue
        checked += 1
        actual = _file_sha256(candidate)
        if actual != expected:
            mismatches.append(
                {
                    "relative_path": rel,
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                }
            )
    return {
        "integrity_ok": (not missing and not mismatches and invalid_entries == 0),
        "checked_files_count": checked,
        "missing_files": missing,
        "sha256_mismatches": mismatches,
        "invalid_entries_count": invalid_entries,
    }


def rollback_preflight_once(
    *,
    target_cfg: dict[str, Any],
    rollback_root: Path,
    rollback_preflight_dir: Path,
    pki_dir: Path,
    base_url: str,
    auth_headers: dict[str, str],
    plan_id: str,
    runtime_write_enabled: bool,
    runtime_fuxa_mount_mode: str,
    runtime_opcua_server_mount_mode: str,
) -> dict[str, Any]:
    target = str(target_cfg.get("target", ""))
    if target not in {"fuxa", "opcua-server"}:
        raise ValueError("target_not_enabled_for_rollback_preflight")
    if not plan_id:
        raise ValueError("rollback_preflight_requires_plan_id")

    runtime_root = Path(str(target_cfg.get("runtime_root", "")))
    runtime_cert = _load_runtime_certificate(target, runtime_root)
    runtime_identity = _certificate_identity(runtime_cert)
    runtime_serial_dec = str(runtime_cert.serial_number)
    runtime_serial_hex = format(runtime_cert.serial_number, "x")

    manifest_path = rollback_root / target / plan_id / "rollback-manifest.json"
    mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
    base_report = {
        "schema": "labshock_phase_8_6_rollback_preflight_v1",
        "generated_at": iso_now_z(),
        "snapshot_reference": "SNAPSHOT_P8_4_REVOCATION_RECONCILED_SAFE_20260512",
        "target": target,
        "plan_id": plan_id,
        "runtime_root": str(runtime_root),
        "runtime_write_enabled": runtime_write_enabled,
        "runtime_mount_mode": mount_mode,
        "runtime_mutation_performed": False,
        "runtime_restart_automatic": False,
        "safe_mode_restored": (not runtime_write_enabled and mount_mode == "ro"),
        "runtime_certificate": {
            "fingerprint_sha256": runtime_identity.get("fingerprint_sha256"),
            "subject": runtime_identity.get("subject"),
            "application_uri": runtime_identity.get("application_uri"),
            "serial_number_dec": runtime_serial_dec,
            "serial_number_hex": runtime_serial_hex,
            "not_after": runtime_identity.get("not_after"),
        },
        "rollback_manifest_found": False,
        "rollback_manifest_path": str(manifest_path),
        "rollback_snapshot_found": False,
        "rollback_snapshot_dir": "",
        "rollback_manifest_integrity": {
            "integrity_ok": False,
            "checked_files_count": 0,
            "missing_files": [],
            "sha256_mismatches": [],
            "invalid_entries_count": 0,
        },
        "private_key_material_copied": None,
        "rollback_snapshot_certificate": {},
        "runtime_certificate_gds": {},
        "rollback_snapshot_certificate_gds": {},
        "runtime_package_status": {},
        "rollback_snapshot_package_status": {},
        "rollback_target_certificate_status": "unknown",
        "rollback_target_certificate_revoked": False,
        "rollback_target_crl_serial_match": False,
        "decision": "not_applicable",
        "blocking_reasons": ["rollback_manifest_missing"],
        "recommended_operator_action": "Rollback preflight is not applicable because rollback evidence is missing.",
    }
    if not manifest_path.exists() or not manifest_path.is_file():
        out_dir = rollback_preflight_dir / target
        out_dir.mkdir(parents=True, exist_ok=True)
        report_id = uuid4().hex
        out_path = out_dir / f"{base_report['generated_at'].replace(':', '').replace('-', '')}_{report_id}.json"
        write_json_artifact(out_path, base_report)
        base_report["report_path"] = str(out_path)
        return base_report

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    snapshot_dir_raw = str(manifest.get("snapshot_dir", "")).strip()
    snapshot_dir = Path(snapshot_dir_raw) if snapshot_dir_raw else (rollback_root / target / plan_id / "PKI")
    _assert_path_inside(rollback_root / target / plan_id, snapshot_dir)
    if not snapshot_dir.exists() or not snapshot_dir.is_dir():
        base_report.update(
            {
                "rollback_manifest_found": True,
                "rollback_snapshot_dir": str(snapshot_dir),
                "private_key_material_copied": bool(manifest.get("private_key_material_copied")),
                "blocking_reasons": ["rollback_snapshot_missing"],
                "recommended_operator_action": "Rollback preflight is blocked until rollback snapshot files exist.",
            }
        )
        out_dir = rollback_preflight_dir / target
        out_dir.mkdir(parents=True, exist_ok=True)
        report_id = uuid4().hex
        out_path = out_dir / f"{base_report['generated_at'].replace(':', '').replace('-', '')}_{report_id}.json"
        write_json_artifact(out_path, base_report)
        base_report["report_path"] = str(out_path)
        return base_report

    snapshot_cert = _load_runtime_certificate(target, snapshot_dir)
    snapshot_identity = _certificate_identity(snapshot_cert)
    snapshot_serial_dec = str(snapshot_cert.serial_number)
    snapshot_serial_hex = format(snapshot_cert.serial_number, "x")
    manifest_integrity = _rollback_manifest_integrity(manifest=manifest, snapshot_dir=snapshot_dir)
    private_key_material_copied = bool(manifest.get("private_key_material_copied"))
    crl_serials = _crl_serials(read_bytes_if_exists(pki_dir / "crl.der"))

    with build_gds_http_client(timeout_seconds=10.0) as client:
        inventory = fetch_certificate_inventory(client, base_url, auth_headers)
        runtime_cert_gds = _find_certificate_by_fingerprint(inventory, str(runtime_identity.get("fingerprint_sha256", "")))
        rollback_cert_gds = _find_certificate_by_fingerprint(inventory, str(snapshot_identity.get("fingerprint_sha256", "")))
        app_uri = str(
            (runtime_cert_gds or {}).get("application_uri")
            or (rollback_cert_gds or {}).get("application_uri")
            or runtime_identity.get("application_uri")
            or snapshot_identity.get("application_uri")
            or ""
        )
        package_inventory = fetch_package_inventory_for_application(client, base_url, auth_headers, app_uri)

    runtime_package = _latest_package_for_certificate(package_inventory, (runtime_cert_gds or {}).get("certificate_id"))
    rollback_package = _latest_package_for_certificate(package_inventory, (rollback_cert_gds or {}).get("certificate_id"))

    rollback_status = str((rollback_cert_gds or {}).get("status", "")).strip().lower() or "unknown"
    rollback_serial_in_crl = snapshot_serial_dec in crl_serials or snapshot_serial_hex in crl_serials
    rollback_revoked = rollback_status == "revoked" or rollback_serial_in_crl

    blocking_reasons: list[str] = []
    if not manifest_integrity.get("integrity_ok"):
        blocking_reasons.append("rollback_manifest_integrity_failed")
    if private_key_material_copied:
        blocking_reasons.append("rollback_snapshot_private_key_material_present")
    if rollback_revoked:
        blocking_reasons.append("rollback_target_certificate_revoked")

    decision = "blocked" if blocking_reasons else "eligible"
    recommended_action = (
        "Rollback preflight is blocked. Keep current runtime and investigate blocking reasons."
        if decision == "blocked"
        else "Rollback preflight is eligible; maintain operator-controlled activation/rollback procedures."
    )

    report = {
        **base_report,
        "rollback_manifest_found": True,
        "rollback_snapshot_found": True,
        "rollback_snapshot_dir": str(snapshot_dir),
        "rollback_manifest_integrity": manifest_integrity,
        "private_key_material_copied": private_key_material_copied,
        "rollback_snapshot_certificate": {
            "fingerprint_sha256": snapshot_identity.get("fingerprint_sha256"),
            "subject": snapshot_identity.get("subject"),
            "application_uri": snapshot_identity.get("application_uri"),
            "serial_number_dec": snapshot_serial_dec,
            "serial_number_hex": snapshot_serial_hex,
            "not_after": snapshot_identity.get("not_after"),
        },
        "runtime_certificate_gds": runtime_cert_gds or {},
        "rollback_snapshot_certificate_gds": rollback_cert_gds or {},
        "runtime_package_status": runtime_package or {},
        "rollback_snapshot_package_status": rollback_package or {},
        "rollback_target_certificate_status": rollback_status,
        "rollback_target_certificate_revoked": rollback_revoked,
        "rollback_target_crl_serial_match": rollback_serial_in_crl,
        "decision": decision,
        "blocking_reasons": blocking_reasons,
        "recommended_operator_action": recommended_action,
    }

    out_dir = rollback_preflight_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    report_id = uuid4().hex
    out_path = out_dir / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report_id}.json"
    write_json_artifact(out_path, report)
    report["report_path"] = str(out_path)
    return report


def build_diff_report(
    zone: str,
    role: str,
    previous: dict | None,
    current: dict | None,
    ca_chain_changed: bool,
    crl_changed: bool,
    critical_reasons: list[str],
) -> dict:
    previous_version = previous.get("version") if previous else None
    new_version = current.get("version") if current else None

    prev_certs = previous.get("certificates", []) if previous else []
    new_certs = current.get("certificates", []) if current else []

    prev_idx, prev_parse_errors = build_cert_index(prev_certs)
    new_idx, new_parse_errors = build_cert_index(new_certs)
    prev_keys = set(prev_idx.keys())
    new_keys = set(new_idx.keys())

    added_map = {k: cert_view(new_idx[k]) for k in (new_keys - prev_keys)}
    removed_map = {k: cert_view(prev_idx[k]) for k in (prev_keys - new_keys)}
    changed: list[dict] = []

    prev_fp_to_uri = {v.get("fingerprint_sha256"): k for k, v in prev_idx.items() if v.get("fingerprint_sha256")}
    new_fp_to_uri = {v.get("fingerprint_sha256"): k for k, v in new_idx.items() if v.get("fingerprint_sha256")}
    for fp in set(prev_fp_to_uri.keys()).intersection(new_fp_to_uri.keys()):
        old_uri = prev_fp_to_uri[fp]
        new_uri = new_fp_to_uri[fp]
        if old_uri != new_uri:
            changed.append(
                {
                    "change_type": "application_uri_changed",
                    "previous_application_uri": old_uri,
                    "new_application_uri": new_uri,
                    "fingerprint_sha256": fp,
                }
            )
            added_map.pop(new_uri, None)
            removed_map.pop(old_uri, None)

    for app_uri in sorted(prev_keys.intersection(new_keys)):
        before = prev_idx[app_uri]
        after = new_idx[app_uri]
        fp_before = (before.get("fingerprint_sha256") or "").lower()
        fp_after = (after.get("fingerprint_sha256") or "").lower()
        cn_before = before.get("common_name")
        cn_after = after.get("common_name")
        nb_before = before.get("not_after")
        nb_after = after.get("not_after")

        if fp_before != fp_after:
            changed.append(
                {
                    "change_type": "fingerprint_changed",
                    "application_uri": app_uri,
                    "previous_fingerprint_sha256": before.get("fingerprint_sha256"),
                    "new_fingerprint_sha256": after.get("fingerprint_sha256"),
                }
            )
        if cn_before != cn_after:
            changed.append(
                {
                    "change_type": "common_name_changed",
                    "application_uri": app_uri,
                    "previous_common_name": cn_before,
                    "new_common_name": cn_after,
                }
            )
        if nb_before != nb_after:
            kind = "not_after_changed"
            if nb_before and nb_after:
                kind = "not_after_extended" if nb_after > nb_before else "not_after_reduced"
            changed.append(
                {
                    "change_type": kind,
                    "application_uri": app_uri,
                    "previous_not_after": nb_before,
                    "new_not_after": nb_after,
                }
            )

    added = [added_map[k] for k in sorted(added_map.keys())]
    removed = [removed_map[k] for k in sorted(removed_map.keys())]

    if current and len(current.get("certificates", [])) == 0:
        critical_reasons.append("trust_list_empty")
    if current and "ca_chain_pem" in current and "BEGIN CERTIFICATE" not in (current.get("ca_chain_pem") or ""):
        critical_reasons.append("ca_chain_missing")
    critical_reasons.extend(prev_parse_errors)
    critical_reasons.extend(new_parse_errors)

    risk = "LOW"
    recommendation = "No action required. Continue monitoring."
    if critical_reasons:
        risk = "CRITICAL"
        recommendation = "Do not enforce runtime trust. Investigate control-plane data integrity immediately."
    elif removed or ca_chain_changed or any(
        c.get("change_type") in {"fingerprint_changed", "common_name_changed", "application_uri_changed", "not_after_reduced"}
        for c in changed
    ):
        risk = "HIGH"
        recommendation = "Operator review required before any runtime trust enforcement."
    elif added or any(c.get("change_type") == "not_after_extended" for c in changed):
        risk = "MEDIUM"
        recommendation = "Review additions/expiry changes and validate expected maintenance activity."

    return {
        "diff_id": uuid4().hex,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "zone": zone,
        "role": role,
        "previous_version": previous_version,
        "new_version": new_version,
        "added": added,
        "removed": removed,
        "changed": changed,
        "ca_chain_changed": ca_chain_changed,
        "crl_changed": crl_changed,
        "risk_level": risk,
        "recommendation": recommendation,
        "critical_reasons": critical_reasons,
    }


def format_rfc3339_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_severity_for_diff(risk_level: str) -> str:
    if risk_level == "LOW":
        return "info"
    if risk_level in {"MEDIUM", "HIGH"}:
        return "warning"
    return "critical"


def truncate_text(value: str, max_len: int) -> str:
    if max_len <= 0:
        return value
    if len(value) <= max_len:
        return value
    return f"{value[:max_len]}...[truncated]"


def to_raw_string(raw: dict, max_len: int) -> str:
    try:
        txt = json.dumps(sanitize_payload(raw), ensure_ascii=True, separators=(",", ":"))
    except Exception:
        txt = "{\"error\":\"raw_payload_serialization_failed\"}"
    return truncate_text(txt, max_len)


def normalize_for_ot_collector(
    event: dict,
    *,
    max_message_len: int,
    max_raw_len: int,
    max_payload_bytes: int,
) -> dict:
    payload = {
        "id": event.get("id") or uuid4().hex,
        "timestamp": event.get("timestamp") or format_rfc3339_utc(),
        "zone": event.get("zone") or "OT",
        "source_type": event.get("source_type") or "gds-agent",
        "asset_name": event.get("asset_name") or "OT GDS Agent",
        "asset_ip": event.get("asset_ip") or "0.0.0.0",
        "severity": event.get("severity") or "info",
        "protocol": event.get("protocol") or "http",
        "event_category": event.get("event_category") or "pki_trust_sync",
        "message": truncate_text(str(event.get("message") or "gds-agent event"), max_message_len),
        "raw": to_raw_string(event.get("raw") or {}, max_raw_len),
        "tags": event.get("tags") or {},
    }

    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_payload_bytes:
        # Reduce raw first to preserve required top-level fields and tags.
        payload["raw"] = truncate_text(payload["raw"], max(256, max_raw_len // 2))
        tags = dict(payload.get("tags") or {})
        tags["payload_truncated"] = "true"
        payload["tags"] = tags

    return payload


def forward_ot_collector_event(
    log: logging.Logger,
    enabled: bool,
    collector_url: str,
    timeout_seconds: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    severity: str,
    event_category: str,
    message: str,
    raw: dict,
    tags: dict,
    max_message_len: int,
    max_raw_len: int,
    max_payload_bytes: int,
) -> None:
    if not enabled:
        return

    tag_payload = {
        "component": "labshock_ot_gds_agent",
        "gds_control_plane": control_plane_host,
        "trustlist_zone": tags.get("trustlist_zone", ""),
        "trustlist_role": tags.get("trustlist_role", ""),
        "risk_level": tags.get("risk_level", ""),
        "diff_id": tags.get("diff_id", ""),
        "collector_decision_hint": "store_forward",
    }
    for key, value in tags.items():
        if key not in tag_payload:
            tag_payload[key] = value

    event_payload = normalize_for_ot_collector(
        {
            "id": uuid4().hex,
            "timestamp": format_rfc3339_utc(),
            "zone": agent_zone,
            "source_type": "gds-agent",
            "asset_name": "OT GDS Agent",
            "asset_ip": asset_ip,
            "severity": severity,
            "protocol": "http",
            "event_category": event_category,
            "message": message,
            "raw": raw,
            "tags": tag_payload,
        },
        max_message_len=max_message_len,
        max_raw_len=max_raw_len,
        max_payload_bytes=max_payload_bytes,
    )
    try:
        with httpx.Client(timeout=float(timeout_seconds)) as client:
            res = client.post(collector_url, json=event_payload)
        if res.status_code >= 400:
            body = truncate_text(res.text or "", 1024)
            log.warning(
                "ot collector forward failed status=%s category=%s body=%s",
                res.status_code,
                event_category,
                body,
            )
    except Exception as exc:
        log.warning("ot collector forward exception category=%s err=%s", event_category, exc)


def load_trust_anchor(client: httpx.Client, base_url: str, headers: dict[str, str]) -> dict:
    res = client.get(f"{base_url}/api/v1/signing/trust-anchor", headers=headers)
    res.raise_for_status()
    anchor = res.json()
    for key in ("key_id", "algorithm", "public_key_pem", "fingerprint_sha256"):
        if key not in anchor:
            raise ArtifactVerificationError("malformed_artifact", f"trust anchor missing field: {key}")
    if str(anchor["algorithm"]).lower() != "ed25519":
        raise ArtifactVerificationError("unsupported_signer", f"unsupported trust anchor algorithm: {anchor['algorithm']}")
    return anchor


def build_agent_auth_headers(enabled: bool, agent_id: str, token: str) -> dict[str, str]:
    if not enabled:
        return {}
    return {
        "X-GDS-Agent-ID": agent_id,
        "X-GDS-Agent-Token": token,
    }


def verify_trust_anchor_fingerprint(anchor: dict, pinned_fingerprint: str) -> tuple[Ed25519PublicKey, str]:
    pub = load_pem_public_key(anchor["public_key_pem"].encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ArtifactVerificationError("unsupported_signer", "trust anchor public key is not Ed25519")
    der = pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    computed_fp = sha256_hex(der)
    anchor_fp = str(anchor.get("fingerprint_sha256", "")).lower()
    if computed_fp.lower() != anchor_fp:
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "trust anchor fingerprint mismatch with provided public key")
    if pinned_fingerprint and computed_fp.lower() != pinned_fingerprint.lower():
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "trust anchor fingerprint does not match pinned fingerprint")
    return pub, computed_fp


def fetch_signed_artifact(client: httpx.Client, base_url: str, zone: str, role: str, headers: dict[str, str]) -> tuple[dict, dict]:
    artifact_res = client.get(f"{base_url}/api/v1/trustlists/{zone}/{role}/artifact", headers=headers)
    if artifact_res.status_code == 404:
        raise FileNotFoundError(f"signed trustlist artifact not found for {zone}/{role}")
    artifact_res.raise_for_status()
    artifact = artifact_res.json()

    sig_res = client.get(f"{base_url}/api/v1/trustlists/{zone}/{role}/artifact.sig", headers=headers)
    if sig_res.status_code == 404:
        raise FileNotFoundError(f"signed trustlist signature not found for {zone}/{role}")
    sig_res.raise_for_status()
    signature = sig_res.json()
    return artifact, signature


def fetch_canonical_artifact_view(client: httpx.Client, base_url: str, zone: str, role: str, headers: dict[str, str]) -> dict:
    res = client.get(f"{base_url}/api/v1/trustlists/{zone}/{role}/artifact/canonical", headers=headers)
    if res.status_code == 404:
        raise FileNotFoundError(f"canonical artifact view not found for {zone}/{role}")
    res.raise_for_status()
    payload = res.json()
    for key in ("canonical_sha256", "canonical_payload"):
        if key not in payload:
            raise ArtifactVerificationError("malformed_artifact", f"canonical endpoint missing field: {key}")
    return payload


def pull_gds_telemetry(client: httpx.Client, base_url: str, headers: dict[str, str]) -> dict[str, Any]:
    endpoints = {
        "mtls_metrics": "/api/v1/mtls/metrics",
        "certificate_telemetry": "/api/v1/certificates/telemetry",
        "certificate_drift": "/api/v1/certificates/drift",
        "component_lifecycle_status": "/api/v1/components/status",
    }
    out: dict[str, Any] = {}
    for name, path in endpoints.items():
        res = client.get(f"{base_url}{path}", headers=headers)
        res.raise_for_status()
        out[name] = res.json()
    return out


def _telemetry_cert_events(certificate_telemetry: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    certs = certificate_telemetry.get("certificates", [])
    if not isinstance(certs, list):
        return events
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        state = str(cert.get("expiry_state", "unknown"))
        if state not in {"warning", "critical", "expired"}:
            continue
        events.append(
            {
                "message": "certificate_expiry_warning" if state == "warning" else "certificate_expiry_critical",
                "severity": "warning" if state == "warning" else "critical",
                "raw": {
                    "application_uri": cert.get("application_uri"),
                    "common_name": cert.get("common_name"),
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                    "serial_number": cert.get("serial_number"),
                    "days_remaining": cert.get("days_remaining"),
                    "expiry_state": state,
                },
                "tags": {
                    "application_uri": str(cert.get("application_uri", "")),
                    "certificate_serial": str(cert.get("serial_number", "")),
                    "mtls_fingerprint_sha256": str(cert.get("fingerprint_sha256", "")),
                    "risk_level": "MEDIUM" if state == "warning" else "CRITICAL",
                },
            }
        )
    return events


def persist_and_forward_gds_telemetry(
    *,
    log: logging.Logger,
    client: httpx.Client,
    base_url: str,
    headers: dict[str, str],
    telemetry_dir: Path,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    sync_cycle_id: str,
) -> None:
    payload = pull_gds_telemetry(client, base_url, headers)
    payload["pulled_at"] = format_rfc3339_utc()
    payload["sync_cycle_id"] = sync_cycle_id
    out_path = telemetry_dir / f"{payload['pulled_at'].replace(':', '').replace('-', '')}_{sync_cycle_id}.json"
    write_json_artifact(out_path, payload)

    metrics = payload.get("mtls_metrics", {}) if isinstance(payload.get("mtls_metrics"), dict) else {}
    certificate_drift = payload.get("certificate_drift", {}) if isinstance(payload.get("certificate_drift"), dict) else {}
    certificate_telemetry = payload.get("certificate_telemetry", {}) if isinstance(payload.get("certificate_telemetry"), dict) else {}
    component_lifecycle_status = payload.get("component_lifecycle_status", {}) if isinstance(payload.get("component_lifecycle_status"), dict) else {}
    forward_ot_collector_event(
        log,
        forward_enabled,
        collector_url,
        collector_timeout_seconds,
        agent_zone,
        asset_ip,
        control_plane_host,
        "info",
        "pki_trust_sync",
        "gds_telemetry_pulled",
        {
            "sync_cycle_id": sync_cycle_id,
            "mtls_success_count": metrics.get("success_count"),
            "mtls_failure_count": metrics.get("failure_count"),
            "certificate_drift_count": certificate_drift.get("drift_count"),
            "component_status_count": len(component_lifecycle_status.get("components", [])) if isinstance(component_lifecycle_status.get("components"), list) else 0,
            "telemetry_path": str(out_path),
        },
        {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id},
        collector_max_message_len,
        collector_max_raw_len,
        collector_max_payload_bytes,
    )

    if int(certificate_drift.get("drift_count") or 0) > 0:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "pki_validation",
            "certificate_inventory_drift_detected",
            {
                "sync_cycle_id": sync_cycle_id,
                "drift_count": certificate_drift.get("drift_count"),
                "items": certificate_drift.get("items", []),
            },
            {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "risk_level": "MEDIUM"},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )

    components = component_lifecycle_status.get("components", [])
    if isinstance(components, list):
        for component in components:
            if not isinstance(component, dict):
                continue
            app_uri = str(component.get("application_uri") or "")
            target = str(component.get("target") or "")
            raw: dict[str, Any] = {"sync_cycle_id": sync_cycle_id, "application_uri": app_uri, "target": target}
            message = ""
            severity = "warning"
            if component.get("private_key_exported") is True or component.get("private_key_touched") is True:
                message = "component_private_key_policy_violation_reported"
                severity = "critical"
                raw.update({"private_key_exported": component.get("private_key_exported"), "private_key_touched": component.get("private_key_touched")})
            elif component.get("crl_freshness_verified") is False:
                message = "component_crl_freshness_not_verified"
            elif str(component.get("last_renewal_status") or "").lower() == "failed":
                message = "component_renewal_failed"
            elif str(component.get("last_apply_status") or "").lower() == "failed":
                message = "component_trust_apply_failed"
            if not message:
                continue
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                severity,
                "pki_lifecycle",
                message,
                raw,
                {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "application_uri": app_uri, "risk_level": "CRITICAL" if severity == "critical" else "MEDIUM"},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )

    for event in _telemetry_cert_events(certificate_telemetry):
        tags = dict(event["tags"])
        tags.update({"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id})
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            event["severity"],
            "pki_validation",
            event["message"],
            {"sync_cycle_id": sync_cycle_id, **event["raw"]},
            tags,
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )


def verify_signed_artifact(
    artifact: dict,
    signature: dict,
    zone: str,
    role: str,
    trust_anchor_pub: Ed25519PublicKey,
    trust_anchor_fp: str,
) -> tuple[str, int]:
    artifact = normalize_signed_artifact_for_verification(artifact)
    if artifact.get("zone") != zone:
        raise ArtifactVerificationError("malformed_artifact", f"artifact zone mismatch: {artifact.get('zone')} != {zone}")
    if artifact.get("role") != role:
        raise ArtifactVerificationError("malformed_artifact", f"artifact role mismatch: {artifact.get('role')} != {role}")
    if str(artifact.get("artifact_type", "")).lower() != "opcua_trustlist":
        raise ArtifactVerificationError("malformed_artifact", "artifact_type must be opcua_trustlist")
    if artifact.get("artifact_revision") is None:
        raise ArtifactVerificationError("malformed_artifact", "artifact_revision missing from artifact")

    signer = artifact.get("signer", {})
    signer_alg = str(signer.get("algorithm", "")).lower()
    if signer_alg and signer_alg != "ed25519":
        raise ArtifactVerificationError("unsupported_signer", f"unsupported artifact signer algorithm: {signer.get('algorithm')}")
    signer_fp = str(signer.get("fingerprint_sha256", "")).lower()
    if signer_fp != trust_anchor_fp.lower():
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "artifact signer fingerprint does not match pinned trust anchor")

    sig_signer = signature.get("signer", {})
    sig_alg = str(sig_signer.get("algorithm", "")).lower()
    if sig_alg and sig_alg != "ed25519":
        raise ArtifactVerificationError("unsupported_signer", f"unsupported signature signer algorithm: {sig_signer.get('algorithm')}")
    sig_signer_fp = str(sig_signer.get("fingerprint_sha256", "")).lower()
    if sig_signer_fp and sig_signer_fp != trust_anchor_fp.lower():
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "signature signer fingerprint does not match pinned trust anchor")

    canonical_payload = canonical_artifact_payload(artifact)
    canonical = canonical_json_bytes(canonical_payload)
    digest = sha256_hex(canonical)
    declared_digest = str(signature.get("artifact_sha256", "")).lower()
    if declared_digest and declared_digest != digest.lower():
        raise ArtifactVerificationError("canonical_hash_mismatch", "artifact hash mismatch")
    if signature.get("version") is not None and int(signature.get("version")) != int(artifact.get("version")):
        raise ArtifactVerificationError("malformed_artifact", "signature version does not match artifact version")
    if signature.get("artifact_revision") is not None and int(signature.get("artifact_revision")) != int(artifact.get("artifact_revision")):
        raise ArtifactVerificationError("malformed_artifact", "signature artifact_revision does not match artifact artifact_revision")
    if signature.get("generated_at"):
        sig_generated = parse_rfc3339_utc(str(signature.get("generated_at")))
        art_generated = parse_rfc3339_utc(str(artifact.get("generated_at")))
        if sig_generated != art_generated:
            raise ArtifactVerificationError("malformed_artifact", "signature generated_at does not match artifact generated_at")
    if signature.get("expires_at"):
        sig_expires = parse_rfc3339_utc(str(signature.get("expires_at")))
        art_expires = parse_rfc3339_utc(str(artifact.get("expires_at")))
        if sig_expires != art_expires:
            raise ArtifactVerificationError("malformed_artifact", "signature expires_at does not match artifact expires_at")

    sig_b64 = signature.get("signature_base64")
    if not sig_b64:
        raise ArtifactVerificationError("malformed_artifact", "missing detached signature")
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as exc:
        raise ArtifactVerificationError("malformed_artifact", "invalid detached signature encoding") from exc
    try:
        trust_anchor_pub.verify(sig, canonical)
    except InvalidSignature as exc:
        raise ArtifactVerificationError("signature_invalid", "detached signature verification failed") from exc
    return digest, len(canonical)


def fetch_certificate_package(client: httpx.Client, base_url: str, package_id: str, headers: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_res = client.get(f"{base_url}/api/v1/packages/{package_id}/manifest", headers=headers)
    manifest_res.raise_for_status()
    sig_res = client.get(f"{base_url}/api/v1/packages/{package_id}/manifest.sig", headers=headers)
    sig_res.raise_for_status()
    return manifest_res.json(), sig_res.json()


def report_certificate_package_lifecycle(
    log: logging.Logger,
    client: httpx.Client,
    base_url: str,
    package_id: str,
    headers: dict[str, str],
    lifecycle_state: str,
    details: dict[str, Any],
    event_type: str | None = None,
) -> None:
    event_name = event_type or f"package_{lifecycle_state.lower()}"
    try:
        res = client.post(
            f"{base_url}/api/v1/packages/{package_id}/events",
            headers=headers,
            json={
                "lifecycle_state": lifecycle_state,
                "event_type": event_name,
                "details": details,
            },
        )
        if res.status_code >= 400:
            log.warning(
                "package lifecycle report failed package_id=%s state=%s event=%s status=%s body=%s",
                package_id,
                lifecycle_state,
                event_name,
                res.status_code,
                res.text[:500],
            )
            return
        log.info("package lifecycle reported package_id=%s state=%s event=%s", package_id, lifecycle_state, event_name)
    except Exception as exc:
        log.warning("package lifecycle report exception package_id=%s state=%s event=%s err=%s", package_id, lifecycle_state, event_name, exc)


def verify_certificate_package_manifest(
    manifest: dict[str, Any],
    signature: dict[str, Any],
    trust_anchor_pub: Ed25519PublicKey,
    trust_anchor_fp: str,
) -> str:
    if manifest.get("schema") != "labshock_certificate_package_v1":
        raise ArtifactVerificationError("malformed_package", "unsupported package schema")
    package_id = str(manifest.get("package_id", "")).strip()
    if not package_id:
        raise ArtifactVerificationError("malformed_package", "missing package_id")
    signer = manifest.get("signer", {})
    if not isinstance(signer, dict):
        raise ArtifactVerificationError("malformed_package", "missing package signer")
    if str(signer.get("algorithm", "")).lower() != "ed25519":
        raise ArtifactVerificationError("unsupported_signer", "unsupported package signer algorithm")
    if str(signer.get("fingerprint_sha256", "")).lower() != trust_anchor_fp.lower():
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "package signer fingerprint does not match pinned trust anchor")
    if str(signature.get("manifest_sha256", "")).lower() != str(manifest.get("manifest_sha256", "")).lower():
        raise ArtifactVerificationError("canonical_hash_mismatch", "package signature hash does not match manifest hash")
    digest = package_manifest_sha256(manifest)
    if digest.lower() != str(manifest.get("manifest_sha256", "")).lower():
        raise ArtifactVerificationError("canonical_hash_mismatch", "package manifest hash mismatch")
    files_sha256 = manifest.get("files_sha256", {})
    if not isinstance(files_sha256, dict):
        raise ArtifactVerificationError("malformed_package", "files_sha256 must be an object")
    for name, value in files_sha256.items():
        if not isinstance(name, str) or not isinstance(value, str) or len(value) != 64:
            raise ArtifactVerificationError("malformed_package", "invalid package file hash tree")
    sig_signer = signature.get("signer", {})
    if str(sig_signer.get("fingerprint_sha256", "")).lower() != trust_anchor_fp.lower():
        raise ArtifactVerificationError("signer_fingerprint_mismatch", "package signature signer fingerprint does not match pinned trust anchor")
    sig_b64 = str(signature.get("signature_base64", "")).strip()
    if not sig_b64:
        raise ArtifactVerificationError("malformed_package", "missing package manifest signature")
    try:
        trust_anchor_pub.verify(base64.b64decode(sig_b64), canonical_json_bytes(canonical_package_manifest(manifest)))
    except InvalidSignature as exc:
        raise ArtifactVerificationError("signature_invalid", "package manifest signature verification failed") from exc
    return digest


def cache_certificate_package(package_dir: Path, manifest: dict[str, Any], signature: dict[str, Any]) -> Path:
    package_id = str(manifest["package_id"])
    out_dir = package_dir / package_id
    write_json_artifact(out_dir / "manifest.json", manifest)
    write_json_artifact(out_dir / "manifest.sig.json", signature)
    plan = {
        "plan_id": uuid4().hex,
        "created_at": iso_now_z(),
        "source": "certificate_package",
        "package_id": package_id,
        "generation": manifest.get("generation"),
        "runtime_instance_id": manifest.get("runtime_instance_id"),
        "profile_name": manifest.get("profile_name"),
        "compatibility_status": (manifest.get("compatibility") or {}).get("status"),
        "status": "blocked_incompatible" if (manifest.get("compatibility") or {}).get("status") == "INCOMPATIBLE" else "package_verified_dry_run_only",
        "runtime_write_enabled": False,
        "dry_run_only": True,
        "install_plan": manifest.get("install_plan"),
        "rollback_metadata": manifest.get("rollback_metadata"),
    }
    write_json_artifact(out_dir / "activation-plan-preview.json", plan)
    return out_dir


def pull_and_cache_certificate_packages(
    *,
    log: logging.Logger,
    base_url: str,
    package_ids: list[str],
    package_dir: Path,
    auth_headers: dict[str, str],
    pinned_anchor_fingerprint: str,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    sync_cycle_id: str,
) -> None:
    if not package_ids:
        return
    with build_gds_http_client(timeout_seconds=10.0) as client:
        anchor = load_trust_anchor(client, base_url, auth_headers)
        anchor_pub, anchor_fp = verify_trust_anchor_fingerprint(anchor, pinned_anchor_fingerprint)
        for package_id in package_ids:
            try:
                manifest, signature = fetch_certificate_package(client, base_url, package_id, auth_headers)
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    auth_headers,
                    "PULLED",
                    {
                        "generation": manifest.get("generation"),
                        "manifest_sha256": manifest.get("manifest_sha256"),
                        "sync_cycle_id": sync_cycle_id,
                    },
                )
                digest = verify_certificate_package_manifest(manifest, signature, anchor_pub, anchor_fp)
                out_dir = cache_certificate_package(package_dir, manifest, signature)
                compatibility_status = str((manifest.get("compatibility") or {}).get("status", "UNKNOWN"))
                severity = "warning" if compatibility_status == "INCOMPATIBLE" else "info"
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    auth_headers,
                    "VERIFIED",
                    {
                        "generation": manifest.get("generation"),
                        "manifest_sha256": digest,
                        "compatibility_status": compatibility_status,
                        "sync_cycle_id": sync_cycle_id,
                    },
                )
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    auth_headers,
                    "STAGED",
                    {
                        "generation": manifest.get("generation"),
                        "cache_dir": str(out_dir),
                        "activation_plan_preview": str(out_dir / "activation-plan-preview.json"),
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": sync_cycle_id,
                    },
                )
                log.info("certificate_package_verified package_id=%s generation=%s compatibility=%s", package_id, manifest.get("generation"), compatibility_status)
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    severity,
                    "pki_trust_sync",
                    "certificate_package_verified",
                    {
                        "package_id": package_id,
                        "generation": manifest.get("generation"),
                        "manifest_sha256": digest,
                        "cache_dir": str(out_dir),
                        "compatibility_status": compatibility_status,
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": sync_cycle_id,
                    },
                    {
                        "risk_level": str((manifest.get("compatibility") or {}).get("risk_level", "")),
                        "application_uri": str(manifest.get("application_uri", "")),
                        "sync_cycle_id": sync_cycle_id,
                        "correlation_id": sync_cycle_id,
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            except Exception as exc:
                failure_code = exc.code if isinstance(exc, ArtifactVerificationError) else "certificate_package_pull_error"
                log.error("certificate_package_rejected package_id=%s failure_code=%s err=%s", package_id, failure_code, exc)
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "critical",
                    "pki_validation",
                    "certificate_package_rejected",
                    {"package_id": package_id, "failure_code": failure_code, "error": str(exc), "sync_cycle_id": sync_cycle_id},
                    {"risk_level": "CRITICAL", "sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )


def safe_write_pki_bundle(
    log: logging.Logger,
    pki_dir: Path,
    ca_chain_pem: str,
    crl_der: bytes,
    *,
    old_ca_chain: str | None,
    old_crl: bytes | None,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
) -> tuple[bool, bool]:
    ca_chain_changed = old_ca_chain is not None and old_ca_chain != ca_chain_pem
    crl_changed = old_crl is not None and old_crl != crl_der

    try:
        atomic_write_text(pki_dir / "ca-chain.pem", ca_chain_pem)
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "info",
            "pki_trust_sync",
            "cache_write_success ca-chain.pem",
            {"path": str(pki_dir / "ca-chain.pem")},
            {},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
    except Exception as exc:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "gds_agent_error",
            "cache_write_failure ca-chain.pem",
            {"path": str(pki_dir / "ca-chain.pem"), "error": str(exc)},
            {},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
        raise

    try:
        atomic_write_bytes(pki_dir / "crl.der", crl_der)
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "info",
            "pki_trust_sync",
            "cache_write_success crl.der",
            {"path": str(pki_dir / "crl.der")},
            {},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
    except Exception as exc:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "gds_agent_error",
            "cache_write_failure crl.der",
            {"path": str(pki_dir / "crl.der"), "error": str(exc)},
            {},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
        raise

    if ca_chain_changed:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "pki_validation",
            "ca_chain_changed",
            {"ca_chain_changed": True},
            {"risk_level": "HIGH"},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
    if crl_changed:
        forward_ot_collector_event(
            log,
            forward_enabled,
            collector_url,
            collector_timeout_seconds,
            agent_zone,
            asset_ip,
            control_plane_host,
            "warning",
            "pki_validation",
            "crl_changed",
            {"crl_changed": True},
            {"risk_level": "HIGH"},
            collector_max_message_len,
            collector_max_raw_len,
            collector_max_payload_bytes,
        )
    return ca_chain_changed, crl_changed


def run_sync_cycle_signed(
    log: logging.Logger,
    base_url: str,
    trust_targets: list[tuple[str, str]],
    trust_dir: Path,
    pki_dir: Path,
    diff_dir: Path,
    telemetry_dir: Path,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
    pinned_anchor_fingerprint: str,
    sign_debug: bool,
    auth_headers: dict[str, str],
    sync_cycle_id: str,
) -> bool:
    with build_gds_http_client(timeout_seconds=10.0) as client:
        trust_anchor = load_trust_anchor(client, base_url, auth_headers)
        trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)

        old_ca_chain = read_text_if_exists(pki_dir / "ca-chain.pem")
        old_crl = read_bytes_if_exists(pki_dir / "crl.der")
        ca_chain_changed_global = False
        crl_changed_global = False
        pki_written = False

        for target_zone, target_role in trust_targets:
            tl_path = trust_dir / f"{target_zone}_{target_role}.json"
            prev_tl = load_json_if_exists(tl_path)
            prev_signed_compatible = False
            if prev_tl:
                prev_artifact_type = str(prev_tl.get("artifact_type", "")).lower()
                prev_signer_fp = str((prev_tl.get("signer") or {}).get("fingerprint_sha256", "")).lower()
                prev_signed_compatible = (
                    prev_artifact_type == "opcua_trustlist"
                    and prev_signer_fp == trust_anchor_fp.lower()
                    and prev_tl.get("artifact_revision") is not None
                )
            critical_reasons: list[str] = []
            try:
                artifact, signature = fetch_signed_artifact(client, base_url, target_zone, target_role, auth_headers)
                canonical_sha256, verifier_payload_len = verify_signed_artifact(
                    artifact,
                    signature,
                    target_zone,
                    target_role,
                    trust_anchor_pub,
                    trust_anchor_fp,
                )
                signed_payload_len = verifier_payload_len
                if sign_debug:
                    canonical_view = fetch_canonical_artifact_view(client, base_url, target_zone, target_role, auth_headers)
                    gds_sha = str(canonical_view.get("canonical_sha256", "")).lower()
                    if gds_sha and gds_sha != canonical_sha256.lower():
                        raise ArtifactVerificationError(
                            "canonical_hash_mismatch",
                            f"canonical hash mismatch agent={canonical_sha256} gds={gds_sha}",
                        )
                    signed_payload_len = len(str(canonical_view.get("canonical_payload", "")).encode("utf-8"))
                    log.info(
                        "sign_debug zone=%s role=%s canonical_sha256=%s signed_payload_length=%s verifier_payload_length=%s",
                        target_zone,
                        target_role,
                        canonical_sha256,
                        signed_payload_len,
                        verifier_payload_len,
                    )
                validate_trustlist_payload(artifact, target_zone, target_role)

                expires_at = parse_rfc3339_utc(str(artifact.get("expires_at", "")))
                now_utc = datetime.now(timezone.utc)
                if expires_at < now_utc:
                    raise ValueError("signed trustlist artifact expired")

                prev_version = int(prev_tl.get("version")) if prev_signed_compatible and prev_tl and prev_tl.get("version") is not None else None
                prev_revision = int(prev_tl.get("artifact_revision")) if prev_signed_compatible and prev_tl and prev_tl.get("artifact_revision") is not None else None
                curr_version = int(artifact.get("version"))
                curr_revision = int(artifact.get("artifact_revision"))
                if prev_version is not None and prev_revision is not None:
                    if (curr_version, curr_revision) < (prev_version, prev_revision):
                        raise ValueError(
                            f"replay_detected tuple_regression {(curr_version, curr_revision)} < {(prev_version, prev_revision)}"
                        )

                crl_der = base64.b64decode(artifact["crl_base64"])
                x509.load_der_x509_crl(crl_der)

                if not pki_written:
                    ca_chain_changed, crl_changed = safe_write_pki_bundle(
                        log=log,
                        pki_dir=pki_dir,
                        ca_chain_pem=artifact["ca_chain_pem"],
                        crl_der=crl_der,
                        old_ca_chain=old_ca_chain,
                        old_crl=old_crl,
                        forward_enabled=forward_enabled,
                        collector_url=collector_url,
                        collector_timeout_seconds=collector_timeout_seconds,
                        collector_max_message_len=collector_max_message_len,
                        collector_max_raw_len=collector_max_raw_len,
                        collector_max_payload_bytes=collector_max_payload_bytes,
                        agent_zone=agent_zone,
                        asset_ip=asset_ip,
                        control_plane_host=control_plane_host,
                    )
                    ca_chain_changed_global = ca_chain_changed
                    crl_changed_global = crl_changed
                    pki_written = True

                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_validation",
                    "signed_artifact_verified",
                    {
                        "zone": target_zone,
                        "role": target_role,
                        "version": curr_version,
                        "artifact_revision": curr_revision,
                        "artifact_reason": artifact.get("artifact_reason"),
                        "ttl_remaining_seconds": artifact.get("ttl_remaining_seconds"),
                        "trust_anchor_fingerprint": trust_anchor_fp,
                        "canonical_sha256": canonical_sha256,
                        "signed_payload_length": signed_payload_len,
                        "verifier_payload_length": verifier_payload_len,
                        "sync_cycle_id": sync_cycle_id,
                        **gds_transport_metadata(base_url),
                    },
                    {
                        "trustlist_zone": target_zone,
                        "trustlist_role": target_role,
                        "sync_cycle_id": sync_cycle_id,
                        "correlation_id": sync_cycle_id,
                        "agent_id": env("GDS_AGENT_ID", "ot-gds-agent"),
                        "artifact_revision": str(curr_revision),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            except Exception as exc:
                failure_code = "malformed_artifact"
                if isinstance(exc, ArtifactVerificationError):
                    failure_code = exc.code
                critical_reasons.append(f"signed_artifact_validation_failed:{failure_code}:{exc}")
                report = build_diff_report(
                    zone=target_zone,
                    role=target_role,
                    previous=prev_tl if prev_signed_compatible else None,
                    current=None,
                    ca_chain_changed=ca_chain_changed_global,
                    crl_changed=crl_changed_global,
                    critical_reasons=critical_reasons,
                )
                report_path = diff_dir / target_zone / target_role / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['diff_id']}.json"
                atomic_write_text(report_path, json.dumps(report, ensure_ascii=True, indent=2))
                log.error(
                    "trustlist_diff_detected zone=%s role=%s risk=%s added=%s removed=%s changed=%s failure_code=%s reason=%s",
                    target_zone,
                    target_role,
                    report["risk_level"],
                    len(report["added"]),
                    len(report["removed"]),
                    len(report["changed"]),
                    failure_code,
                    str(exc),
                )
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "critical",
                    "pki_validation",
                    "signed_artifact_verification_failed",
                    {
                        "zone": target_zone,
                        "role": target_role,
                        "failure_code": failure_code,
                        "critical_reasons": report.get("critical_reasons", []),
                    },
                    {
                        "trustlist_zone": target_zone,
                        "trustlist_role": target_role,
                        "risk_level": "CRITICAL",
                        "diff_id": report.get("diff_id", ""),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                continue

            report = build_diff_report(
                zone=target_zone,
                role=target_role,
                previous=prev_tl if prev_signed_compatible else None,
                current=artifact,
                ca_chain_changed=ca_chain_changed_global,
                crl_changed=crl_changed_global,
                critical_reasons=critical_reasons,
            )
            report_path = diff_dir / target_zone / target_role / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['diff_id']}.json"
            atomic_write_text(report_path, json.dumps(report, ensure_ascii=True, indent=2))
            log.info(
                "trustlist_diff_detected zone=%s role=%s risk=%s added=%s removed=%s changed=%s",
                target_zone,
                target_role,
                report["risk_level"],
                len(report["added"]),
                len(report["removed"]),
                len(report["changed"]),
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                normalize_severity_for_diff(report["risk_level"]),
                "trustlist_diff",
                "trustlist_diff_detected",
                {
                    "zone": target_zone,
                    "role": target_role,
                    "previous_version": report.get("previous_version"),
                    "new_version": report.get("new_version"),
                    "previous_artifact_revision": prev_tl.get("artifact_revision") if prev_tl else None,
                    "new_artifact_revision": artifact.get("artifact_revision"),
                    "artifact_reason": artifact.get("artifact_reason"),
                    "added_count": len(report.get("added", [])),
                    "removed_count": len(report.get("removed", [])),
                    "changed_count": len(report.get("changed", [])),
                    "ca_chain_changed": report.get("ca_chain_changed"),
                    "crl_changed": report.get("crl_changed"),
                },
                {
                    "trustlist_zone": target_zone,
                    "trustlist_role": target_role,
                    "risk_level": report.get("risk_level", ""),
                    "diff_id": report.get("diff_id", ""),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            if report["risk_level"] == "CRITICAL":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "critical",
                    "gds_agent_error",
                    "critical_diff_detected",
                    {
                        "zone": target_zone,
                        "role": target_role,
                        "critical_reasons": report.get("critical_reasons", []),
                    },
                    {
                        "trustlist_zone": target_zone,
                        "trustlist_role": target_role,
                        "risk_level": report.get("risk_level", ""),
                        "diff_id": report.get("diff_id", ""),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )

            try:
                atomic_write_text(tl_path, json.dumps(artifact, ensure_ascii=True, indent=2))
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "cache_write_success trustlist",
                    {"path": str(tl_path), "zone": target_zone, "role": target_role, "version": artifact.get("version")},
                    {"trustlist_zone": target_zone, "trustlist_role": target_role},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            except Exception as exc:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "gds_agent_error",
                    "cache_write_failure trustlist",
                    {"path": str(tl_path), "zone": target_zone, "role": target_role, "error": str(exc)},
                    {"trustlist_zone": target_zone, "trustlist_role": target_role},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                raise
            log.info(
                "trustlist synced zone=%s role=%s version=%s cert_count=%s",
                target_zone,
                target_role,
                artifact.get("version"),
                len(artifact.get("certificates", [])),
            )

        persist_and_forward_gds_telemetry(
            log=log,
            client=client,
            base_url=base_url,
            headers=auth_headers,
            telemetry_dir=telemetry_dir,
            forward_enabled=forward_enabled,
            collector_url=collector_url,
            collector_timeout_seconds=collector_timeout_seconds,
            collector_max_message_len=collector_max_message_len,
            collector_max_raw_len=collector_max_raw_len,
            collector_max_payload_bytes=collector_max_payload_bytes,
            agent_zone=agent_zone,
            asset_ip=asset_ip,
            control_plane_host=control_plane_host,
            sync_cycle_id=sync_cycle_id,
        )

    return True


def run_sync_cycle(
    log: logging.Logger,
    base_url: str,
    trust_targets: list[tuple[str, str]],
    trust_dir: Path,
    pki_dir: Path,
    diff_dir: Path,
    forward_enabled: bool,
    collector_url: str,
    collector_timeout_seconds: int,
    collector_max_message_len: int,
    collector_max_raw_len: int,
    collector_max_payload_bytes: int,
    agent_zone: str,
    asset_ip: str,
    control_plane_host: str,
) -> bool:
    with build_gds_http_client(timeout_seconds=10.0) as client:
        old_ca_chain = read_text_if_exists(pki_dir / "ca-chain.pem")
        old_crl = read_bytes_if_exists(pki_dir / "crl.der")

        ca_chain_res = client.get(f"{base_url}/api/v1/pki/ca-chain")
        ca_chain_res.raise_for_status()
        ca_chain = ca_chain_res.json()
        ca_chain_pem = ca_chain.get("ca_chain_pem", "")
        if "BEGIN CERTIFICATE" not in ca_chain_pem:
            raise ValueError("invalid ca-chain response")
        ca_chain_changed = old_ca_chain is not None and old_ca_chain != ca_chain_pem
        try:
            atomic_write_text(pki_dir / "ca-chain.pem", ca_chain_pem)
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "cache_write_success ca-chain.pem",
                {"path": str(pki_dir / "ca-chain.pem")},
                {},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
        except Exception as exc:
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "warning",
                "gds_agent_error",
                "cache_write_failure ca-chain.pem",
                {"path": str(pki_dir / "ca-chain.pem"), "error": str(exc)},
                {},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            raise

        crl_res = client.get(f"{base_url}/api/v1/pki/crl")
        crl_res.raise_for_status()
        crl = crl_res.json()
        crl_der = base64.b64decode(crl.get("crl_base64", ""))
        x509.load_der_x509_crl(crl_der)
        crl_changed = old_crl is not None and old_crl != crl_der
        try:
            atomic_write_bytes(pki_dir / "crl.der", crl_der)
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "cache_write_success crl.der",
                {"path": str(pki_dir / "crl.der")},
                {},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
        except Exception as exc:
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "warning",
                "gds_agent_error",
                "cache_write_failure crl.der",
                {"path": str(pki_dir / "crl.der"), "error": str(exc)},
                {},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            raise

        if ca_chain_changed:
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "warning",
                "pki_validation",
                "ca_chain_changed",
                {"ca_chain_changed": True},
                {"risk_level": "HIGH"},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
        if crl_changed:
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                "warning",
                "pki_validation",
                "crl_changed",
                {"crl_changed": True},
                {"risk_level": "HIGH"},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )

        for target_zone, target_role in trust_targets:
            tl_path = trust_dir / f"{target_zone}_{target_role}.json"
            prev_tl = load_json_if_exists(tl_path)
            critical_reasons: list[str] = []
            try:
                tl_res = client.get(f"{base_url}/api/v1/trustlists/{target_zone}/{target_role}")
                if tl_res.status_code == 404:
                    log.warning("trustlist not found yet zone=%s role=%s", target_zone, target_role)
                    continue
                tl_res.raise_for_status()
                tl = tl_res.json()
                validate_trustlist_payload(tl, target_zone, target_role)
            except Exception as exc:
                critical_reasons.append(f"malformed_or_unavailable_trustlist:{exc}")
                report = build_diff_report(
                    zone=target_zone,
                    role=target_role,
                    previous=prev_tl,
                    current=None,
                    ca_chain_changed=ca_chain_changed,
                    crl_changed=crl_changed,
                    critical_reasons=critical_reasons,
                )
                report_path = diff_dir / target_zone / target_role / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['diff_id']}.json"
                atomic_write_text(report_path, json.dumps(report, ensure_ascii=True, indent=2))
                log.error(
                    "trustlist_diff_detected zone=%s role=%s risk=%s added=%s removed=%s changed=%s",
                    target_zone,
                    target_role,
                    report["risk_level"],
                    len(report["added"]),
                    len(report["removed"]),
                    len(report["changed"]),
                )
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "critical",
                    "pki_validation",
                    "malformed_trustlist_or_certificate",
                    {
                        "zone": target_zone,
                        "role": target_role,
                        "critical_reasons": report.get("critical_reasons", []),
                    },
                    {
                        "trustlist_zone": target_zone,
                        "trustlist_role": target_role,
                        "risk_level": "CRITICAL",
                        "diff_id": report.get("diff_id", ""),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                continue

            report = build_diff_report(
                zone=target_zone,
                role=target_role,
                previous=prev_tl,
                current=tl,
                ca_chain_changed=ca_chain_changed,
                crl_changed=crl_changed,
                critical_reasons=critical_reasons,
            )
            report_path = diff_dir / target_zone / target_role / f"{report['generated_at'].replace(':', '').replace('-', '')}_{report['diff_id']}.json"
            atomic_write_text(report_path, json.dumps(report, ensure_ascii=True, indent=2))
            log.info(
                "trustlist_diff_detected zone=%s role=%s risk=%s added=%s removed=%s changed=%s",
                target_zone,
                target_role,
                report["risk_level"],
                len(report["added"]),
                len(report["removed"]),
                len(report["changed"]),
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                agent_zone,
                asset_ip,
                control_plane_host,
                normalize_severity_for_diff(report["risk_level"]),
                "trustlist_diff",
                "trustlist_diff_detected",
                {
                    "zone": target_zone,
                    "role": target_role,
                    "previous_version": report.get("previous_version"),
                    "new_version": report.get("new_version"),
                    "added_count": len(report.get("added", [])),
                    "removed_count": len(report.get("removed", [])),
                    "changed_count": len(report.get("changed", [])),
                    "ca_chain_changed": report.get("ca_chain_changed"),
                    "crl_changed": report.get("crl_changed"),
                },
                {
                    "trustlist_zone": target_zone,
                    "trustlist_role": target_role,
                    "risk_level": report.get("risk_level", ""),
                    "diff_id": report.get("diff_id", ""),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            if report["risk_level"] == "CRITICAL":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "critical",
                    "gds_agent_error",
                    "critical_diff_detected",
                    {
                        "zone": target_zone,
                        "role": target_role,
                        "critical_reasons": report.get("critical_reasons", []),
                    },
                    {
                        "trustlist_zone": target_zone,
                        "trustlist_role": target_role,
                        "risk_level": report.get("risk_level", ""),
                        "diff_id": report.get("diff_id", ""),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )

            try:
                atomic_write_text(tl_path, json.dumps(tl, ensure_ascii=True, indent=2))
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "cache_write_success trustlist",
                    {"path": str(tl_path), "zone": target_zone, "role": target_role, "version": tl.get("version")},
                    {"trustlist_zone": target_zone, "trustlist_role": target_role},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            except Exception as exc:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    agent_zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "gds_agent_error",
                    "cache_write_failure trustlist",
                    {"path": str(tl_path), "zone": target_zone, "role": target_role, "error": str(exc)},
                    {"trustlist_zone": target_zone, "trustlist_role": target_role},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                raise
            log.info(
                "trustlist synced zone=%s role=%s version=%s cert_count=%s",
                target_zone,
                target_role,
                tl.get("version"),
                len(tl.get("certificates", [])),
            )

    return True


def fetch_verified_signed_artifact(
    client: httpx.Client,
    base_url: str,
    zone: str,
    role: str,
    trust_anchor_pub: Ed25519PublicKey,
    trust_anchor_fp: str,
    headers: dict[str, str],
    sign_debug: bool,
    log: logging.Logger,
) -> dict[str, Any]:
    artifact, signature = fetch_signed_artifact(client, base_url, zone, role, headers)
    canonical_sha256, verifier_payload_len = verify_signed_artifact(
        artifact=artifact,
        signature=signature,
        zone=zone,
        role=role,
        trust_anchor_pub=trust_anchor_pub,
        trust_anchor_fp=trust_anchor_fp,
    )
    if sign_debug:
        canonical_view = fetch_canonical_artifact_view(client, base_url, zone, role, headers)
        gds_sha = str(canonical_view.get("canonical_sha256", "")).lower()
        if gds_sha and gds_sha != canonical_sha256.lower():
            raise ArtifactVerificationError(
                "canonical_hash_mismatch",
                f"canonical hash mismatch agent={canonical_sha256} gds={gds_sha}",
            )
        signed_payload_len = len(str(canonical_view.get("canonical_payload", "")).encode("utf-8"))
        log.info(
            "sign_debug zone=%s role=%s canonical_sha256=%s signed_payload_length=%s verifier_payload_length=%s",
            zone,
            role,
            canonical_sha256,
            signed_payload_len,
            verifier_payload_len,
        )
    validate_trustlist_payload(artifact, zone, role)
    expires_at = parse_rfc3339_utc(str(artifact.get("expires_at", "")))
    if expires_at < utc_now():
        raise ArtifactVerificationError("malformed_artifact", "signed trustlist artifact expired")
    return artifact


def build_runtime_preview_for_target(
    *,
    log: logging.Logger,
    target_cfg: dict[str, Any],
    artifact: dict[str, Any],
    runtime_preview_dir: Path,
    runtime_compat_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
) -> dict[str, Any]:
    target = str(target_cfg.get("target"))
    previous_payload = load_previous_preview_payload(runtime_preview_dir, target)
    diff = build_diff_report(
        zone=str(artifact.get("zone", "")),
        role=str(artifact.get("role", "")),
        previous=previous_payload,
        current=artifact,
        ca_chain_changed=False,
        crl_changed=False,
        critical_reasons=[],
    )
    keep = compute_would_keep(previous_payload, artifact)
    compat = evaluate_runtime_compatibility(target_cfg, artifact)
    compat_dir = runtime_compat_dir / target
    compat_dir.mkdir(parents=True, exist_ok=True)
    compat_id = uuid4().hex
    compat_payload = {
        "compat_id": compat_id,
        "generated_at": iso_now_z(),
        "target": target,
        "artifact_zone": artifact.get("zone"),
        "artifact_role": artifact.get("role"),
        "artifact_version": artifact.get("version"),
        "artifact_revision": artifact.get("artifact_revision"),
        "status": compat["status"],
        "issues": compat["issues"],
        "runtime_paths_checked": compat["runtime_paths_checked"],
    }
    write_json_artifact(
        compat_dir / f"{compat_payload['generated_at'].replace(':', '').replace('-', '')}_{compat_id}.json",
        compat_payload,
    )
    mw = maintenance_window_status(target, maintenance_policy)
    approval_level = str((mw.get("policy") or {}).get("approval_level", "single")).lower()
    approval, approval_status = load_active_approval_for_target(approvals_dir, target, approval_signer, approval_level)
    if not approval_required:
        approval_status = "not_required"

    risk_level = diff.get("risk_level", "LOW")
    if compat["status"] == "INCOMPATIBLE":
        risk_level = "CRITICAL"
    elif risk_level == "LOW" and compat["status"] == "PREVIEW_ONLY":
        risk_level = "MEDIUM"

    recommendation = "Preview generated. Activation remains blocked in Phase 5.1."
    if compat["status"] == "INCOMPATIBLE":
        recommendation = "Resolve compatibility issues before any staged activation."
    elif approval_required and not approval:
        recommendation = "Collect operator approval before maintenance-window enforcement."
    elif mw["status"] == "blackout":
        recommendation = "Activation denied due to blackout period."
    elif mw["status"] != "open":
        recommendation = "Schedule maintenance window before activation."

    safe_to_stage = compat["status"] in {"COMPATIBLE", "PREVIEW_ONLY"} and risk_level != "CRITICAL"
    preview_id = uuid4().hex
    preview = {
        "preview_id": preview_id,
        "generated_at": iso_now_z(),
        "target": target,
        "artifact_zone": artifact.get("zone"),
        "artifact_role": artifact.get("role"),
        "artifact_version": artifact.get("version"),
        "artifact_revision": artifact.get("artifact_revision"),
        "maintenance_window_status": mw,
        "approval_status": approval_status,
        "approval_summary": approval or {},
        "compatibility_status": compat["status"],
        "compatibility_issues": compat["issues"],
        "would_add": diff.get("added", []),
        "would_remove": diff.get("removed", []),
        "would_keep": keep,
        "would_change": diff.get("changed", []),
        "runtime_paths_checked": compat["runtime_paths_checked"],
        "risk_level": risk_level,
        "recommendation": recommendation,
        "safe_to_stage": safe_to_stage,
        "safe_to_activate": False,
        "artifact_snapshot": artifact,
    }
    out_dir = runtime_preview_dir / target
    out_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{preview['generated_at'].replace(':', '').replace('-', '')}_{preview_id}.json"
    write_json_artifact(out_dir / file_name, preview)
    log.info(
        "runtime_preview_generated target=%s version=%s revision=%s risk=%s compat=%s",
        target,
        artifact.get("version"),
        artifact.get("artifact_revision"),
        risk_level,
        compat["status"],
    )
    return preview


def run_runtime_preview_once(
    *,
    log: logging.Logger,
    base_url: str,
    runtime_targets: list[dict[str, Any]],
    runtime_preview_dir: Path,
    runtime_compat_dir: Path,
    approvals_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    require_signed_artifacts: bool,
    pinned_anchor_fingerprint: str,
    sign_debug: bool,
    auth_headers: dict[str, str],
) -> list[dict[str, Any]]:
    if not require_signed_artifacts:
        raise ValueError("runtime preview simulation requires signed artifact mode")
    if not pinned_anchor_fingerprint:
        raise ValueError("runtime preview simulation requires GDS_AGENT_TRUST_ANCHOR_FINGERPRINT")

    with build_gds_http_client(timeout_seconds=10.0) as client:
        trust_anchor = load_trust_anchor(client, base_url, auth_headers)
        trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)
        previews: list[dict[str, Any]] = []
        for target_cfg in runtime_targets:
            artifact = fetch_verified_signed_artifact(
                client=client,
                base_url=base_url,
                zone=str(target_cfg["artifact_zone"]),
                role=str(target_cfg["artifact_role"]),
                trust_anchor_pub=trust_anchor_pub,
                trust_anchor_fp=trust_anchor_fp,
                headers=auth_headers,
                sign_debug=sign_debug,
                log=log,
            )
            preview = build_runtime_preview_for_target(
                log=log,
                target_cfg=target_cfg,
                artifact=artifact,
                runtime_preview_dir=runtime_preview_dir,
                runtime_compat_dir=runtime_compat_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=approval_required,
            )
            previews.append(preview)
        return previews


def create_activation_plan_once(
    *,
    log: logging.Logger,
    base_url: str,
    target_cfg: dict[str, Any],
    runtime_preview_dir: Path,
    runtime_compat_dir: Path,
    plan_dir: Path,
    approvals_dir: Path,
    rollback_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
    require_signed_artifacts: bool,
    pinned_anchor_fingerprint: str,
    sign_debug: bool,
    auth_headers: dict[str, str],
) -> dict[str, Any]:
    previews = run_runtime_preview_once(
        log=log,
        base_url=base_url,
        runtime_targets=[target_cfg],
        runtime_preview_dir=runtime_preview_dir,
        runtime_compat_dir=runtime_compat_dir,
        approvals_dir=approvals_dir,
        maintenance_policy=maintenance_policy,
        approval_signer=approval_signer,
        approval_required=approval_required,
        require_signed_artifacts=require_signed_artifacts,
        pinned_anchor_fingerprint=pinned_anchor_fingerprint,
        sign_debug=sign_debug,
        auth_headers=auth_headers,
    )
    preview = previews[0]
    rollback = build_rollback_bundle_metadata(target_cfg, rollback_dir)
    approval = preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None

    plan_id = uuid4().hex
    required_approval_id = approval.get("approval_id") if isinstance(approval, dict) else f"approval-{plan_id}"
    gate = evaluate_activation_gate(
        target_cfg=target_cfg,
        preview=preview,
        approval_required=approval_required,
        approval_summary=approval,
        approval_status=str(preview.get("approval_status", "")),
        emergency_override_mode=emergency_override_mode,
    )
    if gate["status"] == "ready_for_staging":
        status = "ready_for_staging"
    elif gate["status"] == "emergency_override_ready":
        status = "emergency_override_ready"
    elif gate["status"] == "blocked_approval_missing":
        status = "pending_approval"
    elif gate["status"] == "blocked_window_closed":
        status = "pending_window"
    elif gate["status"] == "blocked_blackout":
        status = "blocked_blackout"
    else:
        status = "blocked_incompatible"
    blocked_reason = str(gate.get("blocked_reason", "phase5_preview_only"))

    plan = {
        "plan_id": plan_id,
        "created_at": iso_now_z(),
        "target": target_cfg["target"],
        "preview_id": preview["preview_id"],
        "artifact_version": preview["artifact_version"],
        "artifact_revision": preview["artifact_revision"],
        "required_approval_id": required_approval_id,
        "required_maintenance_window": True,
        "rollback_bundle_id": rollback["bundle_id"],
        "steps": [
            "verify_signed_artifact_and_runtime_compatibility",
            "confirm_operator_approval",
            "enforce_maintenance_window_and_blackout_policy",
            "optional_emergency_override_validation",
            "prepare_atomic_swap_bundle_phase5_3",
            "activate_runtime_changes_phase5_3_manual_only",
        ],
        "status": status,
        "activation_blocked_reason": blocked_reason,
        "runtime_write_enabled": False,
        "gate": gate,
    }
    target_dir = plan_dir / str(target_cfg["target"])
    target_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{plan['created_at'].replace(':', '').replace('-', '')}_{plan_id}.json"
    write_json_artifact(target_dir / file_name, plan)
    log.info(
        "activation_plan_created target=%s plan_id=%s status=%s blocked_reason=%s",
        target_cfg["target"],
        plan_id,
        status,
        blocked_reason,
    )
    return plan


def run_activation_gate_cycle(
    *,
    log: logging.Logger,
    base_url: str,
    runtime_targets: list[dict[str, Any]],
    runtime_preview_dir: Path,
    runtime_compat_dir: Path,
    approvals_dir: Path,
    gate_dir: Path,
    maintenance_policy: dict[str, Any],
    approval_signer: ApprovalSigner,
    approval_required: bool,
    emergency_override_mode: bool,
    require_signed_artifacts: bool,
    pinned_anchor_fingerprint: str,
    sign_debug: bool,
    auth_headers: dict[str, str],
) -> list[dict[str, Any]]:
    previews = run_runtime_preview_once(
        log=log,
        base_url=base_url,
        runtime_targets=runtime_targets,
        runtime_preview_dir=runtime_preview_dir,
        runtime_compat_dir=runtime_compat_dir,
        approvals_dir=approvals_dir,
        maintenance_policy=maintenance_policy,
        approval_signer=approval_signer,
        approval_required=approval_required,
        require_signed_artifacts=require_signed_artifacts,
        pinned_anchor_fingerprint=pinned_anchor_fingerprint,
        sign_debug=sign_debug,
        auth_headers=auth_headers,
    )
    gates: list[dict[str, Any]] = []
    for idx, target_cfg in enumerate(runtime_targets):
        preview = previews[idx]
        gate = evaluate_activation_gate(
            target_cfg=target_cfg,
            preview=preview,
            approval_required=approval_required,
            approval_summary=preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None,
            approval_status=str(preview.get("approval_status", "")),
            emergency_override_mode=emergency_override_mode,
        )
        path = persist_activation_gate(gate_dir, gate)
        gate["gate_report_path"] = str(path)
        gates.append(gate)
        log.info(
            "maintenance_window_enforcement target=%s gate=%s reason=%s override=%s",
            gate.get("target"),
            gate.get("status"),
            gate.get("blocked_reason"),
            gate.get("emergency_override_requested"),
        )
    return gates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OT GDS pull-based sync agent")
    parser.add_argument("--preview-once", action="store_true", help="Run a single sync+diff cycle and exit")
    parser.add_argument("--runtime-preview-once", action="store_true", help="Run a single runtime preview simulation and exit")
    parser.add_argument("--create-activation-plan", action="store_true", help="Create a staged activation plan for one target and exit")
    parser.add_argument("--stage-activation-dry-run", action="store_true", help="Create dry-run atomic staging bundle for one target")
    parser.add_argument("--create-package-activation-plan", action="store_true", help="Create a dry-run activation plan from a cached certificate package")
    parser.add_argument("--stage-package-activation-dry-run", action="store_true", help="Create a package-driven dry-run staging bundle")
    parser.add_argument("--activate-package", action="store_true", help="Activate a verified certificate package for an enabled runtime target")
    parser.add_argument("--validate-package-activation", action="store_true", help="Validate package activation evidence for an enabled runtime target without mutating runtime")
    parser.add_argument("--validate-fuxa-activation", action="store_true", help="Validate Phase 8.1 FUXA activation evidence without mutating runtime")
    parser.add_argument("--renewal-check-once", action="store_true", help="Report runtime certificate renewal eligibility without mutating runtime")
    parser.add_argument("--renew-runtime-certificate", action="store_true", help="Generate a runtime-key CSR and request a renewal package from GDS")
    parser.add_argument("--activate-if-gates-open", action="store_true", help="After renewal staging, activate only if all existing runtime gates are open")
    parser.add_argument("--pull-revocation-update", action="store_true", help="Pull CRL/trust updates and write Phase 8.4 revocation dry-run reports")
    parser.add_argument("--rollback-preflight", action="store_true", help="Run a read-only rollback readiness preflight for one target and plan id")
    parser.add_argument("--quarantine-revoked-dry-run", action="store_true", help="Generate Phase 8.7 move-only quarantine dry-run plan for revoked runtime entries")
    parser.add_argument("--activate-revocation-quarantine", action="store_true", help="Activate Phase 8.7 revocation quarantine plan under runtime gates")
    parser.add_argument("--validate-revocation-quarantine", action="store_true", help="Validate Phase 8.7 quarantine receipt and moved file evidence")
    parser.add_argument("--emergency-rollback-preflight", action="store_true", help="Run read-only Phase 8.7 emergency rollback preflight (execution not implemented)")
    parser.add_argument("--report-id", type=str, default="", help="Optional report id for revocation quarantine dry-run source selection")
    parser.add_argument("--component-discover", action="store_true", help="Discover GDS component profile, identity, policy, trust anchor, and revocation state")
    parser.add_argument("--component-enroll", action="store_true", help="Generate or reuse a local component key, submit CSR to GDS, and cache component distribution material")
    parser.add_argument("--component-pull-trust", action="store_true", help="Pull GDS component trust material and CRL without mutating runtime")
    parser.add_argument("--component-apply-trust", action="store_true", help="Apply cached GDS component distribution material to local runtime PKI under gates")
    parser.add_argument("--apply-mode", choices=["auto", "trust_only", "certificate_and_trust"], default="auto", help="Component apply mode for --component-apply-trust")
    parser.add_argument("--pull-package", action="store_true", help="Pull and verify one certificate lifecycle package")
    parser.add_argument("--package-id", type=str, default="", help="Certificate package id for package pull mode")
    parser.add_argument("--plan-id", type=str, default="", help="Activation plan id for dry-run staging")
    parser.add_argument("--create-approval", action="store_true", help="Create signed approval record file for one target")
    parser.add_argument("--target", type=str, default="", help="Runtime target name for activation plan")
    parser.add_argument("--operator", type=str, default="operator", help="Approval operator id")
    parser.add_argument("--decision", type=str, default="approve", help="Approval decision: approve|deny")
    parser.add_argument("--reason", type=str, default="manual approval", help="Approval reason")
    parser.add_argument("--expires-in-minutes", type=int, default=60, help="Approval validity in minutes")
    parser.add_argument("--approval-level", type=str, default="single", help="Approval level: single|dual")
    parser.add_argument("--emergency-override", action="store_true", help="Mark approval as emergency override")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log = configure_logging()
    agent_id = env("GDS_AGENT_ID", "ot-gds-agent")
    base_url = env("GDS_CONTROL_PLANE_URL", "http://192.168.10.30:8081").rstrip("/")
    zone = env("GDS_AGENT_ZONE", "OT")
    interval = env_int("GDS_AGENT_SYNC_INTERVAL_SECONDS", 60)
    forward_enabled = env_bool("GDS_AGENT_FORWARD_TO_OT_COLLECTOR", True)
    collector_url = env("GDS_AGENT_OT_COLLECTOR_URL", "http://192.168.1.70:8088/events")
    collector_timeout_seconds = env_int("GDS_AGENT_FORWARD_TIMEOUT_SECONDS", 3)
    success_event_min_interval = env_int("GDS_AGENT_SYNC_SUCCESS_EVENT_MIN_INTERVAL_SECONDS", 300)
    collector_max_message_len = env_int("GDS_AGENT_OT_COLLECTOR_MAX_MESSAGE_LEN", 512)
    collector_max_raw_len = env_int("GDS_AGENT_OT_COLLECTOR_MAX_RAW_LEN", 4096)
    collector_max_payload_bytes = env_int("GDS_AGENT_OT_COLLECTOR_MAX_PAYLOAD_BYTES", 16384)
    require_signed_artifacts = env_bool("GDS_AGENT_REQUIRE_SIGNED_ARTIFACTS", True)
    sign_debug = env_bool("GDS_SIGN_DEBUG", False)
    agent_auth_enabled = env_bool("GDS_AGENT_AUTH_ENABLED", False)
    agent_token_file = Path(env("GDS_AGENT_TOKEN_FILE", "/etc/labshock-gds-agent-auth/token"))
    runtime_preview_enabled = env_bool("GDS_AGENT_RUNTIME_PREVIEW_ENABLED", True)
    runtime_targets_raw = env("GDS_AGENT_RUNTIME_TARGETS", "opcua-server,fuxa")
    runtime_approval_required = env_bool("GDS_AGENT_RUNTIME_APPROVAL_REQUIRED", True)
    runtime_write_enabled = env_bool("GDS_AGENT_RUNTIME_WRITE_ENABLED", False)
    policy_orchestrator_mode = env_bool("GDS_AGENT_POLICY_ORCHESTRATOR_MODE", False)
    runtime_activation_targets = parse_csv(env("GDS_AGENT_RUNTIME_ACTIVATION_TARGETS", ""))
    runtime_fuxa_mount_mode = env("GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE", "none").strip().lower()
    runtime_opcua_server_mount_mode = env("GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE", "none").strip().lower()
    runtime_emergency_override_mode = env_bool("GDS_AGENT_EMERGENCY_OVERRIDE_MODE", False)
    activation_merge_policy = env("GDS_AGENT_ACTIVATION_MERGE_POLICY", "conservative_merge").strip().lower()
    if activation_merge_policy not in {"conservative_merge", "strict_replace"}:
        activation_merge_policy = "conservative_merge"
    renewal_enabled = env_bool("GDS_AGENT_RENEWAL_ENABLED", False)
    renewal_targets = parse_csv(env("GDS_AGENT_RENEWAL_TARGETS", ""))
    renewal_threshold_days = env_int("GDS_AGENT_RENEWAL_THRESHOLD_DAYS", 14)
    renewal_activate_if_gates_open = env_bool("GDS_AGENT_RENEWAL_ACTIVATE_IF_GATES_OPEN", False)
    maintenance_windows_file = Path(env("GDS_AGENT_MAINTENANCE_WINDOWS_FILE", "/etc/labshock-gds-agent/maintenance-windows.json"))
    maintenance_timezone = env("GDS_AGENT_MAINTENANCE_TIMEZONE", "UTC")
    pinned_anchor_fingerprint = env("GDS_AGENT_TRUST_ANCHOR_FINGERPRINT", "").strip().lower()
    asset_ip = env("GDS_AGENT_ASSET_IP", "192.168.1.30")
    cache_dir = Path(env("GDS_AGENT_CACHE_DIR", "/var/lib/labshock-gds-agent"))
    approval_signing_key_path = Path(env("GDS_AGENT_APPROVAL_SIGNING_KEY_PATH", str(cache_dir / "approval-signing" / "approval-ed25519.pem")))
    approval_signing_key_id = env("GDS_AGENT_APPROVAL_SIGNING_KEY_ID", "ot-approval-key-v1")
    package_ids = parse_csv(env("GDS_AGENT_PACKAGE_IDS", ""))
    agent_token = ""
    if agent_auth_enabled:
        try:
            agent_token = read_secret_text(agent_token_file)
        except Exception as exc:
            log.error("agent auth enabled but token file unreadable path=%s err=%s", agent_token_file, exc)
            return 1
        if not agent_token:
            log.error("agent auth enabled but token file is empty path=%s", agent_token_file)
            return 1
    auth_headers = build_agent_auth_headers(agent_auth_enabled, agent_id, agent_token)

    trust_targets = [
        (zone, "server"),
        (zone, "scada-client"),
    ]

    trust_dir = cache_dir / "trustlists"
    pki_dir = cache_dir / "pki"
    diff_dir = cache_dir / "diff"
    telemetry_dir = cache_dir / "telemetry"
    inventory_drift_dir = cache_dir / "inventory-drift"
    runtime_preview_dir = cache_dir / "runtime-previews"
    runtime_plan_dir = cache_dir / "activation-plans"
    runtime_gate_dir = cache_dir / "activation-gates"
    approvals_dir = cache_dir / "approvals"
    runtime_stage_dir = cache_dir / "runtime-stage"
    rollback_dir = cache_dir / "rollback-bundles"
    runtime_rollback_dir = cache_dir / "runtime-rollbacks"
    activation_receipt_dir = cache_dir / "activation-receipts"
    runtime_compat_dir = cache_dir / "runtime-compat"
    package_dir = cache_dir / "packages"
    component_dir = cache_dir / "components"
    component_apply_dir = cache_dir / "component-apply-trust"
    revocation_dir = cache_dir / "revocation-dry-runs"
    rollback_preflight_dir = cache_dir / "rollback-preflights"
    quarantine_plan_dir = cache_dir / "quarantine-plans"
    quarantine_receipt_dir = cache_dir / "quarantine-receipts"
    quarantine_validation_dir = cache_dir / "quarantine-validation"
    runtime_quarantine_dir = cache_dir / "runtime-quarantine"
    emergency_rollback_preflight_dir = cache_dir / "emergency-rollback-preflights"
    trust_dir.mkdir(parents=True, exist_ok=True)
    pki_dir.mkdir(parents=True, exist_ok=True)
    diff_dir.mkdir(parents=True, exist_ok=True)
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    inventory_drift_dir.mkdir(parents=True, exist_ok=True)
    runtime_preview_dir.mkdir(parents=True, exist_ok=True)
    runtime_plan_dir.mkdir(parents=True, exist_ok=True)
    runtime_gate_dir.mkdir(parents=True, exist_ok=True)
    approvals_dir.mkdir(parents=True, exist_ok=True)
    runtime_stage_dir.mkdir(parents=True, exist_ok=True)
    rollback_dir.mkdir(parents=True, exist_ok=True)
    runtime_rollback_dir.mkdir(parents=True, exist_ok=True)
    activation_receipt_dir.mkdir(parents=True, exist_ok=True)
    runtime_compat_dir.mkdir(parents=True, exist_ok=True)
    package_dir.mkdir(parents=True, exist_ok=True)
    component_dir.mkdir(parents=True, exist_ok=True)
    component_apply_dir.mkdir(parents=True, exist_ok=True)
    revocation_dir.mkdir(parents=True, exist_ok=True)
    rollback_preflight_dir.mkdir(parents=True, exist_ok=True)
    quarantine_plan_dir.mkdir(parents=True, exist_ok=True)
    quarantine_receipt_dir.mkdir(parents=True, exist_ok=True)
    quarantine_validation_dir.mkdir(parents=True, exist_ok=True)
    runtime_quarantine_dir.mkdir(parents=True, exist_ok=True)
    emergency_rollback_preflight_dir.mkdir(parents=True, exist_ok=True)
    approval_signer = ApprovalSigner(approval_signing_key_path, approval_signing_key_id)
    transport_meta = gds_transport_metadata(base_url)
    if transport_meta["mtls_enabled"]:
        for tls_path in (
            env("GDS_AGENT_TLS_CA_FILE", "/etc/labshock-gds-agent-tls/ca.crt"),
            env("GDS_AGENT_TLS_CERT_FILE", "/etc/labshock-gds-agent-tls/client.crt"),
            env("GDS_AGENT_TLS_KEY_FILE", "/etc/labshock-gds-agent-tls/client.key"),
        ):
            if not Path(tls_path).is_file():
                log.error("GDS_AGENT_MTLS_ENABLED=true but TLS file is missing path=%s", tls_path)
                return 1

    log.info("agent start id=%s zone=%s base_url=%s interval=%s", agent_id, zone, base_url, interval)
    log.info("TODO: enforce mTLS/API key for production OT pull model")
    log.info("gds transport scheme=%s mtls_enabled=%s", transport_meta["control_plane_scheme"], transport_meta["mtls_enabled"])
    log.info("agent auth enabled=%s", agent_auth_enabled)
    log.info("signed artifact mode require_signed=%s pinned_anchor_set=%s", require_signed_artifacts, bool(pinned_anchor_fingerprint))
    log.info("sign_debug enabled=%s", sign_debug)
    log.info(
        "runtime preview enabled=%s approval_required=%s emergency_override_mode=%s merge_policy=%s",
        runtime_preview_enabled,
        runtime_approval_required,
        runtime_emergency_override_mode,
        activation_merge_policy,
    )
    log.info(
        "runtime live writes enabled=%s activation_targets=%s fuxa_mount_mode=%s opcua_server_mount_mode=%s",
        runtime_write_enabled,
        ",".join(runtime_activation_targets),
        runtime_fuxa_mount_mode,
        runtime_opcua_server_mount_mode,
    )
    log.info(
        "renewal enabled=%s targets=%s threshold_days=%s activate_if_gates_open=%s",
        renewal_enabled,
        ",".join(renewal_targets),
        renewal_threshold_days,
        renewal_activate_if_gates_open,
    )
    log.info("approval signer key_id=%s fingerprint_sha256=%s", approval_signer.key_id, approval_signer.fingerprint_sha256)
    if policy_orchestrator_mode:
        deprecated_commands = {
            "--runtime-preview-once": args.runtime_preview_once,
            "--stage-activation-dry-run": args.stage_activation_dry_run,
            "--stage-package-activation-dry-run": args.stage_package_activation_dry_run,
            "--activate-package": args.activate_package,
            "--validate-package-activation": args.validate_package_activation,
            "--validate-fuxa-activation": args.validate_fuxa_activation,
            "--renewal-check-once": args.renewal_check_once,
            "--renew-runtime-certificate": args.renew_runtime_certificate,
            "--pull-revocation-update": args.pull_revocation_update,
            "--rollback-preflight": args.rollback_preflight,
            "--quarantine-revoked-dry-run": args.quarantine_revoked_dry_run,
            "--activate-revocation-quarantine": args.activate_revocation_quarantine,
            "--validate-revocation-quarantine": args.validate_revocation_quarantine,
            "--emergency-rollback-preflight": args.emergency_rollback_preflight,
            "--component-enroll": args.component_enroll,
            "--component-apply-trust": args.component_apply_trust,
        }
        for command_name, requested in deprecated_commands.items():
            if requested:
                log.error(
                    "runtime_write_deprecated_use_native_client command=%s policy_orchestrator_mode=true",
                    command_name,
                )
                print(json.dumps({
                    "error": "runtime_write_deprecated_use_native_client",
                    "command": command_name,
                    "policy_orchestrator_mode": True,
                    "recommended_operator_action": "Run the owning runtime native GDS client or the FUXA local helper.",
                }, ensure_ascii=True, indent=2))
                return 1
    if require_signed_artifacts and not pinned_anchor_fingerprint:
        log.error("signed artifact mode enabled but GDS_AGENT_TRUST_ANCHOR_FINGERPRINT is empty")
        return 1
    if args.preview_once:
        log.info("preview-once mode enabled")
    if args.runtime_preview_once:
        log.info("runtime-preview-once mode enabled")
    if args.create_activation_plan:
        log.info("create-activation-plan mode enabled target=%s", args.target)
    if args.stage_activation_dry_run:
        log.info("stage-activation-dry-run mode enabled target=%s plan_id=%s", args.target, args.plan_id)
    if args.create_package_activation_plan:
        log.info("create-package-activation-plan mode enabled package_id=%s target=%s", args.package_id, args.target)
    if args.stage_package_activation_dry_run:
        log.info("stage-package-activation-dry-run mode enabled package_id=%s target=%s plan_id=%s", args.package_id, args.target, args.plan_id)
    if args.activate_package:
        log.info("activate-package mode enabled package_id=%s target=%s plan_id=%s", args.package_id, args.target, args.plan_id)
    if args.validate_fuxa_activation:
        log.info("validate-fuxa-activation mode enabled package_id=%s target=%s plan_id=%s", args.package_id, args.target, args.plan_id)
    if args.validate_package_activation:
        log.info("validate-package-activation mode enabled package_id=%s target=%s plan_id=%s", args.package_id, args.target, args.plan_id)
    if args.renewal_check_once:
        log.info("renewal-check-once mode enabled target=%s threshold_days=%s", args.target, renewal_threshold_days)
    if args.renew_runtime_certificate:
        log.info("renew-runtime-certificate mode enabled target=%s activate_if_gates_open=%s", args.target, args.activate_if_gates_open or renewal_activate_if_gates_open)
    if args.pull_revocation_update:
        log.info("pull-revocation-update mode enabled target=%s", args.target)
    if args.rollback_preflight:
        log.info("rollback-preflight mode enabled target=%s plan_id=%s", args.target, args.plan_id)
    if args.quarantine_revoked_dry_run:
        log.info("quarantine-revoked-dry-run mode enabled target=%s report_id=%s", args.target, args.report_id)
    if args.activate_revocation_quarantine:
        log.info("activate-revocation-quarantine mode enabled target=%s plan_id=%s", args.target, args.plan_id)
    if args.validate_revocation_quarantine:
        log.info("validate-revocation-quarantine mode enabled target=%s plan_id=%s", args.target, args.plan_id)
    if args.emergency_rollback_preflight:
        log.info("emergency-rollback-preflight mode enabled target=%s plan_id=%s", args.target, args.plan_id)
    if args.component_discover:
        log.info("component-discover mode enabled target=%s", args.target)
    if args.component_enroll:
        log.info("component-enroll mode enabled target=%s", args.target)
    if args.component_pull_trust:
        log.info("component-pull-trust mode enabled target=%s", args.target)
    if args.component_apply_trust:
        log.info("component-apply-trust mode enabled target=%s", args.target)
    if args.pull_package:
        log.info("pull-package mode enabled package_id=%s", args.package_id)
    if args.create_approval:
        log.info("create-approval mode enabled target=%s operator=%s", args.target, args.operator)
    parsed_cp = urlparse(base_url)
    control_plane_host = parsed_cp.netloc
    maintenance_policy = load_maintenance_policy(maintenance_windows_file, maintenance_timezone)
    configured_targets = parse_runtime_targets(runtime_targets_raw)
    unmanaged_targets = unmanaged_configured_targets(zone, configured_targets)
    if unmanaged_targets:
        log.error(
            "target_not_managed_by_agent_zone agent_zone=%s targets=%s",
            str(zone or "").strip().upper(),
            unmanaged_targets,
        )
        return 1
    runtime_targets = resolve_runtime_targets(zone, configured_targets)

    if args.create_approval:
        if not args.target:
            log.error("--create-approval requires --target")
            return 1
        target_policy_snapshot = _default_target_policy(args.target)
        targets_cfg = maintenance_policy.get("targets", {}) if isinstance(maintenance_policy, dict) else {}
        if isinstance(targets_cfg, dict) and args.target in targets_cfg:
            policy_cfg = targets_cfg[args.target]
            if isinstance(policy_cfg, dict) and isinstance(policy_cfg.get("policy"), dict):
                target_policy_snapshot = dict(policy_cfg["policy"])
        decision = str(args.decision).strip().lower()
        if decision not in {"approve", "deny"}:
            log.error("invalid --decision value=%s expected approve|deny", args.decision)
            return 1
        approval_level = str(args.approval_level).strip().lower()
        if approval_level not in {"single", "dual"}:
            log.error("invalid --approval-level value=%s expected single|dual", args.approval_level)
            return 1
        signed_approval = create_signed_approval_file(
            approvals_dir=approvals_dir,
            signer=approval_signer,
            target=args.target,
            operator=args.operator,
            decision=decision,
            reason=args.reason,
            expires_in_minutes=args.expires_in_minutes,
            approval_level=approval_level,
            emergency_override=args.emergency_override,
            policy_snapshot=target_policy_snapshot,
            plan_id=args.plan_id,
        )
        log.info(
            "approval_record_created target=%s approval_id=%s decision=%s emergency_override=%s expires_at=%s",
            signed_approval.get("target"),
            signed_approval.get("approval_id"),
            signed_approval.get("decision"),
            signed_approval.get("emergency_override"),
            signed_approval.get("expires_at"),
        )
        return 0

    if args.component_discover or args.component_enroll or args.component_pull_trust or args.component_apply_trust:
        target = str(args.target or "").strip()
        if not target:
            log.error("component mode requires --target")
            return 1
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg:
            if target_err == "target_not_managed_by_agent_zone":
                log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            else:
                log.error("component target is not configured target=%s configured_targets=%s", target, [t.get("target") for t in runtime_targets])
            return 1
        try:
            if args.component_discover:
                report = component_discover_once(
                    base_url=base_url,
                    auth_headers=auth_headers,
                    target_cfg=target_cfg,
                    component_dir=component_dir,
                )
                print(json.dumps(report, ensure_ascii=True, indent=2))
                return 0
            if args.component_enroll:
                runtime_root = Path(str(target_cfg.get("runtime_root", "")))
                key_path = _component_private_key_path(target, runtime_root)
                if not key_path.exists():
                    if target not in runtime_activation_targets:
                        raise ValueError("target_not_enabled_for_component_key_generation")
                    if not runtime_write_enabled:
                        raise ValueError("runtime_write_disabled_for_component_key_generation")
                    mount_mode = _mount_mode_for_component_target(target, runtime_fuxa_mount_mode, runtime_opcua_server_mount_mode)
                    if mount_mode != "rw":
                        raise ValueError("runtime_mount_not_writable_for_component_key_generation")
                    mw = maintenance_window_status(target, maintenance_policy)
                    policy = (mw or {}).get("policy", {}) if isinstance(mw, dict) else {}
                    required_level = str(policy.get("approval_level", _default_target_policy(target)["approval_level"]))
                    approval = None
                    approval_status = "not_required"
                    if runtime_approval_required:
                        approval, approval_status = load_active_approval_for_target(approvals_dir, target, approval_signer, required_level)
                    gate = evaluate_activation_gate(
                        target_cfg=target_cfg,
                        preview={
                            "compatibility_status": "COMPATIBLE",
                            "risk_level": "LOW",
                            "maintenance_window_status": mw,
                        },
                        approval_required=runtime_approval_required,
                        approval_summary=approval,
                        approval_status=approval_status,
                        emergency_override_mode=runtime_emergency_override_mode,
                    )
                    if str(gate.get("status", "")).startswith("blocked"):
                        raise ValueError(f"component_key_generation_gate_closed:{gate.get('blocked_reason')}")
                report = component_enroll_once(
                    base_url=base_url,
                    auth_headers=auth_headers,
                    target_cfg=target_cfg,
                    component_dir=component_dir,
                    package_dir=package_dir,
                )
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "component_enrolled",
                    {
                        "target": target,
                        "application_uri": report.get("application_uri"),
                        "package_id": report.get("package_id"),
                        "certificate_id": report.get("certificate_id"),
                        "private_key_exported": False,
                    },
                    {"risk_level": "LOW", "application_uri": str(report.get("application_uri", ""))},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                print(json.dumps(report, ensure_ascii=True, indent=2))
                return 0
            if args.component_pull_trust:
                report = component_pull_trust_once(
                    base_url=base_url,
                    auth_headers=auth_headers,
                    target_cfg=target_cfg,
                    component_dir=component_dir,
                )
                auto_targets = [item.strip() for item in env("GDS_AGENT_AUTO_APPLY_TRUST_ONLY_TARGETS", "opcua-server,fuxa").split(",") if item.strip()]
                if env_bool("GDS_AGENT_AUTO_APPLY_TRUST_ONLY", False) and target in auto_targets:
                    report["auto_apply_trust_only"] = component_apply_trust_once(
                        log=log,
                        base_url=base_url,
                        auth_headers=auth_headers,
                        target_cfg=target_cfg,
                        component_dir=component_dir,
                        component_apply_dir=component_apply_dir,
                        runtime_preview_dir=runtime_preview_dir,
                        runtime_stage_dir=runtime_stage_dir,
                        runtime_rollback_dir=runtime_rollback_dir,
                        activation_receipt_dir=activation_receipt_dir,
                        approvals_dir=approvals_dir,
                        maintenance_policy=maintenance_policy,
                        approval_signer=approval_signer,
                        approval_required=runtime_approval_required,
                        emergency_override_mode=runtime_emergency_override_mode,
                        runtime_write_enabled=runtime_write_enabled,
                        runtime_activation_targets=runtime_activation_targets,
                        runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                        runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
                        pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                        merge_policy=activation_merge_policy,
                        apply_mode="trust_only",
                    )
                print(json.dumps(report, ensure_ascii=True, indent=2))
                return 0
            if args.component_apply_trust:
                report = component_apply_trust_once(
                    log=log,
                    base_url=base_url,
                    auth_headers=auth_headers,
                    target_cfg=target_cfg,
                    component_dir=component_dir,
                    component_apply_dir=component_apply_dir,
                    runtime_preview_dir=runtime_preview_dir,
                    runtime_stage_dir=runtime_stage_dir,
                    runtime_rollback_dir=runtime_rollback_dir,
                    activation_receipt_dir=activation_receipt_dir,
                    approvals_dir=approvals_dir,
                    maintenance_policy=maintenance_policy,
                    approval_signer=approval_signer,
                    approval_required=runtime_approval_required,
                    emergency_override_mode=runtime_emergency_override_mode,
                    runtime_write_enabled=runtime_write_enabled,
                    runtime_activation_targets=runtime_activation_targets,
                    runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                    runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
                    pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                    merge_policy=activation_merge_policy,
                    apply_mode=args.apply_mode,
                )
                package_id = str(report.get("package_id") or "")
                if report.get("apply_mode") == "certificate_and_trust" and package_id and report.get("status") != "already_activated":
                    with build_gds_http_client(timeout_seconds=10.0) as client:
                        report_certificate_package_lifecycle(
                            log,
                            client,
                            base_url,
                            package_id,
                            auth_headers,
                            "ACTIVATED",
                            {
                                "event_type": "package_activated",
                                "target": target,
                                "application_uri": report.get("application_uri"),
                                "plan_id": report.get("plan_id"),
                                "receipt_id": (report.get("receipt") or {}).get("receipt_id") if isinstance(report.get("receipt"), dict) else None,
                                "manifest_sha256": report.get("manifest_sha256"),
                                "changed_files_count": report.get("changed_files_count"),
                                "runtime_write_enabled": runtime_write_enabled,
                                "runtime_restart_automatic": False,
                                "private_key_overwritten": False,
                                "component_distribution": True,
                            },
                            event_type="package_activated",
                        )
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "component_trust_applied",
                    {
                        "target": target,
                        "application_uri": report.get("application_uri"),
                        "package_id": report.get("package_id"),
                        "plan_id": report.get("plan_id"),
                        "apply_mode": report.get("apply_mode"),
                        "status": report.get("status"),
                        "changed_files_count": report.get("changed_files_count"),
                        "runtime_restart_automatic": False,
                        "private_key_overwritten": False,
                    },
                    {"risk_level": "LOW", "application_uri": str(report.get("application_uri", "")), "diff_id": str(report.get("plan_id", ""))},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                print(json.dumps(report, ensure_ascii=True, indent=2))
                return 0
        except Exception as exc:
            log.error("component_mode_failed target=%s err=%s", target, exc)
            return 1

    if args.validate_fuxa_activation or args.validate_package_activation:
        if not args.package_id:
            log.error("activation validation requires --package-id")
            return 1
        target = str(args.target or ("fuxa" if args.validate_fuxa_activation else "")).strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if args.validate_fuxa_activation and target != "fuxa":
            log.error("--validate-fuxa-activation only supports --target fuxa")
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("activation validation supports --target fuxa|opcua-server")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            report = validate_package_activation_state(
                target_cfg=target_cfg,
                package_dir=package_dir,
                runtime_stage_dir=runtime_stage_dir,
                activation_receipt_dir=activation_receipt_dir,
                package_id=args.package_id,
                plan_id=args.plan_id,
                runtime_write_enabled=runtime_write_enabled,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 0 if report["runtime_matches_stage"] else 1
        except Exception as exc:
            log.error("validate_package_activation_failed target=%s package_id=%s err=%s", target, args.package_id, exc)
            return 1

    if args.pull_revocation_update:
        requested_target = str(args.target or "").strip()
        if requested_target:
            target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, requested_target)
            if not target_cfg and target_err == "target_not_managed_by_agent_zone":
                log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, requested_target)
                return 1
        configured_target_names = {str(cfg.get("target", "")) for cfg in runtime_targets}
        if requested_target and requested_target not in configured_target_names:
            log.error("--pull-revocation-update target is not configured target=%s configured_targets=%s", requested_target, sorted(configured_target_names))
            return 1
        try:
            report = pull_revocation_update_once(
                log=log,
                base_url=base_url,
                trust_targets=trust_targets,
                trust_dir=trust_dir,
                pki_dir=pki_dir,
                diff_dir=diff_dir,
                telemetry_dir=telemetry_dir,
                revocation_dir=revocation_dir,
                runtime_targets=runtime_targets,
                requested_target=requested_target,
                require_signed_artifacts=require_signed_artifacts,
                pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                sign_debug=sign_debug,
                auth_headers=auth_headers,
                sync_cycle_id=uuid4().hex,
                forward_enabled=forward_enabled,
                collector_url=collector_url,
                collector_timeout_seconds=collector_timeout_seconds,
                collector_max_message_len=collector_max_message_len,
                collector_max_raw_len=collector_max_raw_len,
                collector_max_payload_bytes=collector_max_payload_bytes,
                agent_zone=zone,
                asset_ip=asset_ip,
                control_plane_host=control_plane_host,
                runtime_write_enabled=runtime_write_enabled,
                fuxa_mount_mode=runtime_fuxa_mount_mode,
                opcua_server_mount_mode=runtime_opcua_server_mount_mode,
                merge_policy=activation_merge_policy,
            )
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 0
        except Exception as exc:
            log.error("pull_revocation_update_failed target=%s err=%s", requested_target, exc)
            return 1

    if args.rollback_preflight:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("--rollback-preflight supports --target fuxa|opcua-server")
            return 1
        if not args.plan_id:
            log.error("--rollback-preflight requires --plan-id")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            report = rollback_preflight_once(
                target_cfg=target_cfg,
                rollback_root=runtime_rollback_dir,
                rollback_preflight_dir=rollback_preflight_dir,
                pki_dir=pki_dir,
                base_url=base_url,
                auth_headers=auth_headers,
                plan_id=args.plan_id,
                runtime_write_enabled=runtime_write_enabled,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 1 if str(report.get("decision", "")) == "not_applicable" else 0
        except Exception as exc:
            log.error("rollback_preflight_failed target=%s plan_id=%s err=%s", target, args.plan_id, exc)
            return 1

    if args.quarantine_revoked_dry_run:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("--quarantine-revoked-dry-run supports --target fuxa|opcua-server")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            report = quarantine_revoked_dry_run_once(
                target_cfg=target_cfg,
                revocation_dir=revocation_dir,
                quarantine_plan_dir=quarantine_plan_dir,
                rollback_preflight_dir=rollback_preflight_dir,
                report_id=str(args.report_id or "").strip(),
                runtime_write_enabled=runtime_write_enabled,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            decision = str(report.get("decision", "blocked"))
            if decision == "ready_for_quarantine":
                event_name = "revocation_quarantine_plan_created"
                severity = "info"
            elif decision == "not_applicable":
                event_name = "revocation_quarantine_not_applicable"
                severity = "info"
            else:
                event_name = "revocation_quarantine_denied"
                severity = "warning"
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                severity,
                "pki_validation",
                "gds_agent_revocation_quarantine_dry_run",
                {
                    "event_type": event_name,
                    "target": target,
                    "plan_id": report.get("plan_id"),
                    "decision": decision,
                    "quarantine_candidates_count": len(report.get("quarantine_candidates", [])),
                    "files_to_move_count": len(report.get("files_to_move", [])),
                    "files_to_delete_count": len(report.get("files_to_delete", [])),
                    "runtime_mutation_performed": False,
                    "report_path": report.get("plan_path"),
                },
                {
                    "risk_level": "LOW" if decision in {"ready_for_quarantine", "not_applicable"} else "MEDIUM",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 0 if decision in {"ready_for_quarantine", "not_applicable"} else 1
        except Exception as exc:
            log.error("quarantine_revoked_dry_run_failed target=%s report_id=%s err=%s", target, args.report_id, exc)
            return 1

    if args.activate_revocation_quarantine:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("--activate-revocation-quarantine supports --target fuxa|opcua-server")
            return 1
        if not args.plan_id:
            log.error("--activate-revocation-quarantine requires --plan-id")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            receipt = activate_revocation_quarantine_once(
                target_cfg=target_cfg,
                quarantine_plan_dir=quarantine_plan_dir,
                quarantine_receipt_dir=quarantine_receipt_dir,
                runtime_quarantine_dir=runtime_quarantine_dir,
                rollback_preflight_dir=rollback_preflight_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                plan_id=args.plan_id,
                runtime_write_enabled=runtime_write_enabled,
                runtime_activation_targets=runtime_activation_targets,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            status = str(receipt.get("status", "blocked"))
            if status == "quarantined":
                event_name = "revocation_quarantine_activated"
                severity = "warning"
            elif status == "not_applicable":
                event_name = "revocation_quarantine_not_applicable"
                severity = "info"
            else:
                event_name = "revocation_quarantine_denied"
                severity = "warning"
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                severity,
                "pki_validation",
                "gds_agent_revocation_quarantine_activated",
                {
                    "event_type": event_name,
                    "target": target,
                    "plan_id": args.plan_id,
                    "status": status,
                    "runtime_mutation_performed": bool(receipt.get("runtime_mutation_performed", False)),
                    "moved_files_count": len(receipt.get("moved_files", [])),
                    "files_deleted_count": len(receipt.get("files_deleted", [])),
                    "runtime_restart_automatic": bool(receipt.get("runtime_restart_automatic", False)),
                    "receipt_path": receipt.get("receipt_path"),
                    "blocking_reasons": receipt.get("blocking_reasons", []),
                },
                {
                    "risk_level": "MEDIUM" if status == "quarantined" else "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(args.plan_id),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            print(json.dumps(receipt, ensure_ascii=True, indent=2))
            return 0 if status in {"quarantined", "not_applicable"} else 1
        except Exception as exc:
            log.error("activate_revocation_quarantine_failed target=%s plan_id=%s err=%s", target, args.plan_id, exc)
            return 1

    if args.validate_revocation_quarantine:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("--validate-revocation-quarantine supports --target fuxa|opcua-server")
            return 1
        if not args.plan_id:
            log.error("--validate-revocation-quarantine requires --plan-id")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            validation = validate_revocation_quarantine_once(
                target_cfg=target_cfg,
                quarantine_plan_dir=quarantine_plan_dir,
                quarantine_receipt_dir=quarantine_receipt_dir,
                runtime_quarantine_dir=runtime_quarantine_dir,
                quarantine_validation_dir=quarantine_validation_dir,
                plan_id=args.plan_id,
                runtime_write_enabled=runtime_write_enabled,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            status = str(validation.get("status", "failed"))
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info" if status in {"validated", "not_applicable"} else "warning",
                "pki_validation",
                "revocation_quarantine_validated",
                {
                    "event_type": "revocation_quarantine_validated",
                    "target": target,
                    "plan_id": args.plan_id,
                    "status": status,
                    "moved_files_validated_count": validation.get("moved_files_validated_count"),
                    "safe_mode_restored": validation.get("safe_mode_restored"),
                    "validation_path": validation.get("validation_path"),
                    "blocking_reasons": validation.get("blocking_reasons", []),
                },
                {
                    "risk_level": "LOW" if status in {"validated", "not_applicable"} else "MEDIUM",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(args.plan_id),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            print(json.dumps(validation, ensure_ascii=True, indent=2))
            return 0 if status in {"validated", "not_applicable"} else 1
        except Exception as exc:
            log.error("validate_revocation_quarantine_failed target=%s plan_id=%s err=%s", target, args.plan_id, exc)
            return 1

    if args.emergency_rollback_preflight:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("--emergency-rollback-preflight supports --target fuxa|opcua-server")
            return 1
        if not args.plan_id:
            log.error("--emergency-rollback-preflight requires --plan-id")
            return 1
        if not target_cfg:
            log.error("%s runtime target is not configured", target)
            return 1
        try:
            report = emergency_rollback_preflight_once(
                target_cfg=target_cfg,
                rollback_root=runtime_rollback_dir,
                emergency_rollback_preflight_dir=emergency_rollback_preflight_dir,
                pki_dir=pki_dir,
                base_url=base_url,
                auth_headers=auth_headers,
                plan_id=args.plan_id,
                runtime_write_enabled=runtime_write_enabled,
                runtime_fuxa_mount_mode=runtime_fuxa_mount_mode,
                runtime_opcua_server_mount_mode=runtime_opcua_server_mount_mode,
            )
            decision = str(report.get("decision", "blocked"))
            event_type = "emergency_rollback_preflight_created"
            message = "gds_agent_emergency_rollback_blocked" if decision == "blocked" else "emergency_rollback_preflight_created"
            if decision == "blocked":
                event_type = "emergency_rollback_blocked"
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "warning" if decision == "blocked" else "info",
                "pki_validation",
                message,
                {
                    "event_type": event_type,
                    "target": target,
                    "plan_id": args.plan_id,
                    "decision": decision,
                    "blocking_reasons": report.get("blocking_reasons", []),
                    "emergency_execution_implemented": False,
                    "report_path": report.get("report_path"),
                },
                {
                    "risk_level": "MEDIUM" if decision == "blocked" else "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(args.plan_id),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 0 if decision in {"eligible", "not_applicable"} else 1
        except Exception as exc:
            log.error("emergency_rollback_preflight_failed target=%s plan_id=%s err=%s", target, args.plan_id, exc)
            return 1

    if args.renewal_check_once:
        requested_target = str(args.target or "").strip()
        checks: list[dict[str, Any]] = []
        targets_to_check = [requested_target] if requested_target else renewal_targets
        try:
            for target in targets_to_check:
                target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
                if not target_cfg and target_err == "target_not_managed_by_agent_zone":
                    raise ValueError("target_not_managed_by_agent_zone")
                if target not in {"fuxa", "opcua-server"}:
                    raise ValueError("target_not_enabled_for_renewal")
                if not target_cfg:
                    raise ValueError(f"target_config_missing:{target}")
                checks.append(renewal_check_for_target(target_cfg, renewal_threshold_days))
            print(
                json.dumps(
                    {
                        "schema": "labshock_phase_8_3_runtime_renewal_check_v1",
                        "generated_at": iso_now_z(),
                        "renewal_enabled": renewal_enabled,
                        "renewal_targets": renewal_targets,
                        "checks": checks,
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            return 0
        except Exception as exc:
            log.error("renewal_check_failed target=%s err=%s", requested_target or ",".join(targets_to_check), exc)
            return 1

    if args.renew_runtime_certificate:
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error("renewal denied target=%s failure_code=target_not_enabled_for_renewal", target)
            return 1
        if not renewal_enabled:
            log.error("renewal denied target=%s failure_code=renewal_disabled", target)
            return 1
        if target not in renewal_targets:
            log.error("renewal denied target=%s failure_code=target_not_enabled_for_renewal", target)
            return 1
        if not pinned_anchor_fingerprint:
            log.error("--renew-runtime-certificate requires GDS_AGENT_TRUST_ANCHOR_FINGERPRINT")
            return 1
        if not target_cfg:
            log.error("renewal denied target=%s failure_code=target_config_missing", target)
            return 1
        renewal_sync_id = uuid4().hex
        package_id = ""
        plan_id = ""
        activation_copy_started = False
        try:
            runtime_root = Path(str(target_cfg.get("runtime_root", "")))
            csr_pem, identity = build_runtime_renewal_csr(target, runtime_root)
            application_uri = str(identity.get("application_uri", "")).strip()
            if not application_uri:
                raise ValueError("runtime_certificate_application_uri_missing")
            profile_name = _renewal_profile_for_target(target)
            with build_gds_http_client(timeout_seconds=20.0) as client:
                renewal_result = request_certificate_renewal(
                    client,
                    base_url,
                    {**auth_headers, "X-Correlation-ID": renewal_sync_id},
                    application_uri=application_uri,
                    runtime_instance_id=application_uri,
                    profile_name=profile_name,
                    csr_pem=csr_pem,
                    renewal_reason=f"phase 8.3 runtime renewal target={target}",
                )
            package_id = str(renewal_result.get("package_id", ""))
            if not package_id:
                raise ValueError("renewal_response_missing_package_id")
            log.info(
                "certificate_renewal_packaged target=%s package_id=%s generation=%s supersedes_package_id=%s",
                target,
                package_id,
                renewal_result.get("generation"),
                renewal_result.get("supersedes_package_id"),
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "certificate_renewal_packaged",
                {
                    "target": target,
                    "package_id": package_id,
                    "generation": renewal_result.get("generation"),
                    "supersedes_package_id": renewal_result.get("supersedes_package_id"),
                    "runtime_write_enabled": False,
                    "private_key_exported": False,
                    "sync_cycle_id": renewal_sync_id,
                },
                {
                    "risk_level": "LOW",
                    "application_uri": application_uri,
                    "sync_cycle_id": renewal_sync_id,
                    "correlation_id": renewal_sync_id,
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            pull_and_cache_certificate_packages(
                log=log,
                base_url=base_url,
                package_ids=[package_id],
                package_dir=package_dir,
                auth_headers={**auth_headers, "X-Correlation-ID": renewal_sync_id},
                pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                forward_enabled=forward_enabled,
                collector_url=collector_url,
                collector_timeout_seconds=collector_timeout_seconds,
                collector_max_message_len=collector_max_message_len,
                collector_max_raw_len=collector_max_raw_len,
                collector_max_payload_bytes=collector_max_payload_bytes,
                agent_zone=zone,
                asset_ip=asset_ip,
                control_plane_host=control_plane_host,
                sync_cycle_id=renewal_sync_id,
            )
            manifest = load_cached_package_manifest(package_dir, package_id)
            plan = create_package_activation_plan_once(
                target_cfg=target_cfg,
                manifest=manifest,
                runtime_preview_dir=runtime_preview_dir,
                plan_dir=runtime_plan_dir,
                approvals_dir=approvals_dir,
                rollback_dir=rollback_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
                emergency_override_mode=runtime_emergency_override_mode,
            )
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    {**auth_headers, "X-Correlation-ID": renewal_sync_id},
                    "STAGED",
                    {
                        "event_type": "renewal_activation_plan_created",
                        "target": target,
                        "plan_id": plan.get("plan_id"),
                        "generation": plan.get("generation"),
                        "status": plan.get("status"),
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": renewal_sync_id,
                    },
                    event_type="renewal_activation_plan_created",
                )
            preview = build_package_activation_preview(
                target_cfg=target_cfg,
                manifest=manifest,
                runtime_preview_dir=runtime_preview_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
            )
            gate = evaluate_activation_gate(
                target_cfg=target_cfg,
                preview=preview,
                approval_required=runtime_approval_required,
                approval_summary=preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None,
                approval_status=str(preview.get("approval_status", "")),
                emergency_override_mode=runtime_emergency_override_mode,
            )
            if str(gate.get("status", "")).startswith("blocked"):
                log.error(
                    "renewal staging denied by enforcement target=%s package_id=%s gate=%s reason=%s",
                    target,
                    package_id,
                    gate.get("status"),
                    gate.get("blocked_reason"),
                )
                return 1
            stage_report = stage_package_activation_dry_run(
                target_cfg=target_cfg,
                manifest=manifest,
                plan=plan,
                preview=preview,
                gate=gate,
                stage_root_dir=runtime_stage_dir,
                merge_policy=activation_merge_policy,
            )
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    {**auth_headers, "X-Correlation-ID": renewal_sync_id},
                    "STAGED",
                    {
                        "event_type": "renewal_activation_dry_run_staged",
                        "target": target,
                        "plan_id": stage_report.get("plan_id"),
                        "checksum_verified": stage_report.get("checksum_verified"),
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": renewal_sync_id,
                    },
                    event_type="renewal_activation_dry_run_staged",
                )
            plan_id = str(stage_report.get("plan_id") or "")
            activate_requested = args.activate_if_gates_open or renewal_activate_if_gates_open
            if not activate_requested:
                print(
                    json.dumps(
                        {
                            "schema": "labshock_phase_8_3_runtime_renewal_result_v1",
                            "target": target,
                            "package_id": package_id,
                            "generation": renewal_result.get("generation"),
                            "plan_id": stage_report.get("plan_id"),
                            "status": "renewal_staged_activation_skipped",
                            "activate_if_gates_open": False,
                            "runtime_write_enabled": runtime_write_enabled,
                            "runtime_restart_automatic": False,
                        },
                        ensure_ascii=True,
                        indent=2,
                    )
                )
                return 0
            if target not in runtime_activation_targets:
                failure_code = "target_not_enabled_for_phase_8_2" if target == "opcua-server" else "target_not_enabled_for_phase_8_1"
                raise ValueError(failure_code)
            if not runtime_write_enabled:
                raise ValueError("runtime_write_disabled")
            target_mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
            if target_mount_mode != "rw":
                raise ValueError("runtime_mount_not_writable")
            signature = load_cached_package_signature(package_dir, package_id)
            with build_gds_http_client(timeout_seconds=10.0) as client:
                trust_anchor = load_trust_anchor(client, base_url, auth_headers)
            trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)
            manifest_sha256 = verify_certificate_package_manifest(manifest, signature, trust_anchor_pub, trust_anchor_fp)
            stage_dir, validation, checksums = _find_package_stage_bundle(runtime_stage_dir, target, package_id, str(stage_report.get("plan_id") or ""))
            stage_checksums = _validate_stage_bundle(stage_dir, validation, checksums, package_id)
            activation_copy_started = True
            receipt = activate_package_runtime(
                target_cfg=target_cfg,
                manifest=manifest,
                stage_dir=stage_dir,
                stage_checksums=stage_checksums,
                validation=validation,
                rollback_root=runtime_rollback_dir,
                receipts_root=activation_receipt_dir,
                gate=gate,
            )
            if receipt.get("status") == "already_activated":
                log.info("renewal_package_runtime_already_activated target=%s package_id=%s plan_id=%s", target, package_id, receipt.get("plan_id"))
                return 0
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    package_id,
                    {**auth_headers, "X-Correlation-ID": renewal_sync_id},
                    "ACTIVATED",
                    {
                        "event_type": "package_activated",
                        "target": target,
                        "plan_id": receipt.get("plan_id"),
                        "receipt_id": receipt.get("receipt_id"),
                        "generation": manifest.get("generation"),
                        "manifest_sha256": manifest_sha256,
                        "changed_files_count": len(receipt.get("changed_files", [])),
                        "rollback_snapshot_created": True,
                        "runtime_write_enabled": True,
                        "runtime_restart_automatic": False,
                        "private_key_overwritten": False,
                        "renewal": True,
                        "sync_cycle_id": renewal_sync_id,
                    },
                    event_type="package_activated",
                )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "package_runtime_activated",
                {
                    "target": target,
                    "package_id": package_id,
                    "generation": manifest.get("generation"),
                    "plan_id": receipt.get("plan_id"),
                    "receipt_id": receipt.get("receipt_id"),
                    "changed_files_count": len(receipt.get("changed_files", [])),
                    "rollback_snapshot_created": True,
                    "runtime_write_enabled": True,
                    "runtime_restart_automatic": False,
                    "private_key_overwritten": False,
                    "renewal": True,
                    "sync_cycle_id": renewal_sync_id,
                },
                {
                    "risk_level": "LOW",
                    "application_uri": application_uri,
                    "diff_id": str(receipt.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            log.info("renewal_runtime_activated target=%s package_id=%s plan_id=%s", target, package_id, receipt.get("plan_id"))
            return 0
        except Exception as exc:
            failure_text = str(exc) or exc.__class__.__name__
            failure_code = failure_text.split(":", 1)[0]
            if package_id:
                with suppress(Exception):
                    failure_receipt = write_activation_failure_receipt(
                        activation_receipt_dir,
                        target=target,
                        package_id=package_id,
                        plan_id=plan_id,
                        failure_code=failure_code,
                        error=failure_text,
                        mutation_started=activation_copy_started,
                    )
                    plan_id = str(failure_receipt.get("plan_id") or plan_id)
                with suppress(Exception):
                    with build_gds_http_client(timeout_seconds=10.0) as client:
                        report_certificate_package_lifecycle(
                            log,
                            client,
                            base_url,
                            package_id,
                            {**auth_headers, "X-Correlation-ID": renewal_sync_id},
                            "STAGED",
                            {
                                "event_type": "package_activation_failed",
                                "target": target,
                                "plan_id": plan_id,
                                "failure_code": failure_code,
                                "error": truncate_text(failure_text, 500),
                                "mutation_started": activation_copy_started,
                                "renewal": True,
                                "sync_cycle_id": renewal_sync_id,
                            },
                            event_type="package_activation_failed",
                        )
            log.error("renew_runtime_certificate_failed target=%s failure_code=%s err=%s", target, failure_code, failure_text)
            return 1

    if args.pull_package:
        if not args.package_id:
            log.error("--pull-package requires --package-id")
            return 1
        if not pinned_anchor_fingerprint:
            log.error("--pull-package requires GDS_AGENT_TRUST_ANCHOR_FINGERPRINT")
            return 1
        pull_and_cache_certificate_packages(
            log=log,
            base_url=base_url,
            package_ids=[args.package_id],
            package_dir=package_dir,
            auth_headers=auth_headers,
            pinned_anchor_fingerprint=pinned_anchor_fingerprint,
            forward_enabled=forward_enabled,
            collector_url=collector_url,
            collector_timeout_seconds=collector_timeout_seconds,
            collector_max_message_len=collector_max_message_len,
            collector_max_raw_len=collector_max_raw_len,
            collector_max_payload_bytes=collector_max_payload_bytes,
            agent_zone=zone,
            asset_ip=asset_ip,
            control_plane_host=control_plane_host,
            sync_cycle_id=uuid4().hex,
        )
        return 0

    if args.create_package_activation_plan:
        if not args.package_id:
            log.error("--create-package-activation-plan requires --package-id")
            return 1
        if not runtime_preview_enabled:
            log.error("runtime preview orchestration is disabled (set GDS_AGENT_RUNTIME_PREVIEW_ENABLED=true)")
            return 1
        try:
            manifest = load_cached_package_manifest(package_dir, args.package_id)
            target_cfg = None
            if args.target:
                target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, args.target)
                if not target_cfg and target_err == "target_not_managed_by_agent_zone":
                    log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, args.target)
                    return 1
            else:
                target_cfg = infer_runtime_target_for_package(manifest, runtime_targets)
            if not target_cfg:
                log.error("unable to resolve runtime target for package_id=%s profile=%s", args.package_id, manifest.get("profile_name"))
                return 1
            plan = create_package_activation_plan_once(
                target_cfg=target_cfg,
                manifest=manifest,
                runtime_preview_dir=runtime_preview_dir,
                plan_dir=runtime_plan_dir,
                approvals_dir=approvals_dir,
                rollback_dir=rollback_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
                emergency_override_mode=runtime_emergency_override_mode,
            )
            log.info(
                "package_activation_plan_created package_id=%s target=%s plan_id=%s status=%s",
                args.package_id,
                target_cfg.get("target"),
                plan.get("plan_id"),
                plan.get("status"),
            )
            plan_sync_id = uuid4().hex
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    args.package_id,
                    {**auth_headers, "X-Correlation-ID": plan_sync_id},
                    "STAGED",
                    {
                        "event_type": "package_activation_plan_created",
                        "target": plan.get("target"),
                        "plan_id": plan.get("plan_id"),
                        "generation": plan.get("generation"),
                        "status": plan.get("status"),
                        "activation_blocked_reason": plan.get("activation_blocked_reason"),
                        "preview_id": plan.get("preview_id"),
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": plan_sync_id,
                    },
                    event_type="package_activation_plan_created",
                )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info" if str(plan.get("status")) in {"ready_for_package_staging", "emergency_override_ready"} else "warning",
                "pki_trust_sync",
                "package_activation_plan_created",
                {
                    "target": plan.get("target"),
                    "plan_id": plan.get("plan_id"),
                    "package_id": plan.get("package_id"),
                    "generation": plan.get("generation"),
                    "status": plan.get("status"),
                    "activation_blocked_reason": plan.get("activation_blocked_reason"),
                    "runtime_write_enabled": False,
                    "dry_run_only": True,
                },
                {
                    "risk_level": "LOW" if str(plan.get("status")) in {"ready_for_package_staging", "emergency_override_ready"} else "MEDIUM",
                    "application_uri": str(manifest.get("application_uri", "")),
                    "diff_id": str(plan.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 0
        except Exception as exc:
            log.error("package activation plan creation failed package_id=%s err=%s", args.package_id, exc)
            return 1

    if args.stage_package_activation_dry_run:
        if not args.package_id:
            log.error("--stage-package-activation-dry-run requires --package-id")
            return 1
        if not runtime_preview_enabled:
            log.error("runtime preview orchestration is disabled (set GDS_AGENT_RUNTIME_PREVIEW_ENABLED=true)")
            return 1
        try:
            manifest = load_cached_package_manifest(package_dir, args.package_id)
            target_cfg = None
            if args.target:
                target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, args.target)
                if not target_cfg and target_err == "target_not_managed_by_agent_zone":
                    log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, args.target)
                    return 1
            else:
                target_cfg = infer_runtime_target_for_package(manifest, runtime_targets)
            if not target_cfg:
                log.error("unable to resolve runtime target for package_id=%s profile=%s", args.package_id, manifest.get("profile_name"))
                return 1
            plan = _find_activation_plan_for_target(runtime_plan_dir, str(target_cfg["target"]), args.plan_id)
            if not plan or str(plan.get("package_id", "")) != args.package_id:
                plan = create_package_activation_plan_once(
                    target_cfg=target_cfg,
                    manifest=manifest,
                    runtime_preview_dir=runtime_preview_dir,
                    plan_dir=runtime_plan_dir,
                    approvals_dir=approvals_dir,
                    rollback_dir=rollback_dir,
                    maintenance_policy=maintenance_policy,
                    approval_signer=approval_signer,
                    approval_required=runtime_approval_required,
                    emergency_override_mode=runtime_emergency_override_mode,
                )
            preview = build_package_activation_preview(
                target_cfg=target_cfg,
                manifest=manifest,
                runtime_preview_dir=runtime_preview_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
            )
            gate = evaluate_activation_gate(
                target_cfg=target_cfg,
                preview=preview,
                approval_required=runtime_approval_required,
                approval_summary=preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None,
                approval_status=str(preview.get("approval_status", "")),
                emergency_override_mode=runtime_emergency_override_mode,
            )
            if str(gate.get("status", "")).startswith("blocked"):
                log.error(
                    "package runtime stage dry-run denied by enforcement target=%s package_id=%s gate=%s reason=%s",
                    target_cfg.get("target"),
                    args.package_id,
                    gate.get("status"),
                    gate.get("blocked_reason"),
                )
                return 1
            stage_report = stage_package_activation_dry_run(
                target_cfg=target_cfg,
                manifest=manifest,
                plan=plan,
                preview=preview,
                gate=gate,
                stage_root_dir=runtime_stage_dir,
                merge_policy=activation_merge_policy,
            )
            log.info(
                "package_runtime_stage_dry_run_created target=%s package_id=%s plan_id=%s checksum_verified=%s",
                stage_report.get("target"),
                stage_report.get("package_id"),
                stage_report.get("plan_id"),
                stage_report.get("checksum_verified"),
            )
            stage_sync_id = uuid4().hex
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    args.package_id,
                    {**auth_headers, "X-Correlation-ID": stage_sync_id},
                    "STAGED",
                    {
                        "event_type": "package_activation_dry_run_staged",
                        "target": stage_report.get("target"),
                        "plan_id": stage_report.get("plan_id"),
                        "generation": stage_report.get("generation"),
                        "stage_dir": stage_report.get("stage_dir"),
                        "checksum_verified": stage_report.get("checksum_verified"),
                        "approvals_valid": stage_report.get("approvals_valid"),
                        "maintenance_window_status": stage_report.get("maintenance_window_status"),
                        "blackout_status": stage_report.get("blackout_status"),
                        "destructive_changes_detected": stage_report.get("destructive_changes_detected"),
                        "destructive_changes_blocked": stage_report.get("destructive_changes_blocked"),
                        "runtime_write_enabled": False,
                        "dry_run_only": True,
                        "sync_cycle_id": stage_sync_id,
                    },
                    event_type="package_activation_dry_run_staged",
                )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "package_runtime_stage_dry_run_created",
                {
                    "target": stage_report.get("target"),
                    "plan_id": stage_report.get("plan_id"),
                    "package_id": stage_report.get("package_id"),
                    "stage_dir": stage_report.get("stage_dir"),
                    "checksum_verified": stage_report.get("checksum_verified"),
                    "runtime_write_enabled": False,
                    "dry_run_only": True,
                },
                {
                    "risk_level": "LOW",
                    "application_uri": str(manifest.get("application_uri", "")),
                    "diff_id": str(stage_report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 0
        except Exception as exc:
            log.error("package runtime stage dry-run failed package_id=%s err=%s", args.package_id, exc)
            return 1

    if args.activate_package:
        if not args.package_id:
            log.error("--activate-package requires --package-id")
            return 1
        target = str(args.target or "").strip()
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, target)
        if not target_cfg and target_err == "target_not_managed_by_agent_zone":
            log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, target)
            return 1
        if target not in {"fuxa", "opcua-server"}:
            log.error(
                "package activation denied target=%s package_id=%s failure_code=target_not_enabled_for_live_activation",
                target,
                args.package_id,
            )
            return 1
        if target not in runtime_activation_targets:
            failure_code = "target_not_enabled_for_phase_8_2" if target == "opcua-server" else "target_not_enabled_for_phase_8_1"
            log.error(
                "package activation denied target=%s package_id=%s failure_code=%s",
                target,
                args.package_id,
                failure_code,
            )
            return 1
        if not runtime_write_enabled:
            log.error(
                "package activation denied target=%s package_id=%s failure_code=runtime_write_disabled",
                target,
                args.package_id,
            )
            return 1
        target_mount_mode = runtime_opcua_server_mount_mode if target == "opcua-server" else runtime_fuxa_mount_mode
        if target_mount_mode != "rw":
            log.error(
                "package activation denied target=%s package_id=%s failure_code=runtime_mount_not_writable mount_mode=%s",
                target,
                args.package_id,
                target_mount_mode,
            )
            return 1
        if activation_merge_policy != "conservative_merge":
            log.error(
                "package activation denied target=%s package_id=%s failure_code=strict_replace_not_allowed_for_live_activation merge_policy=%s",
                target,
                args.package_id,
                activation_merge_policy,
            )
            return 1
        if not runtime_preview_enabled:
            log.error("package activation denied target=%s package_id=%s failure_code=runtime_preview_disabled", target, args.package_id)
            return 1
        if not target_cfg:
            log.error("package activation denied target=%s package_id=%s failure_code=target_config_missing", target, args.package_id)
            return 1

        activation_sync_id = uuid4().hex
        manifest: dict[str, Any] = {}
        plan_id = str(args.plan_id or "")
        activation_copy_started = False
        try:
            manifest = load_cached_package_manifest(package_dir, args.package_id)
            signature = load_cached_package_signature(package_dir, args.package_id)
            compatibility_status = str((manifest.get("compatibility") or {}).get("status", "UNKNOWN"))
            if compatibility_status != "COMPATIBLE":
                raise ValueError("incompatible_package")

            with build_gds_http_client(timeout_seconds=10.0) as client:
                trust_anchor = load_trust_anchor(client, base_url, auth_headers)
            trust_anchor_pub, trust_anchor_fp = verify_trust_anchor_fingerprint(trust_anchor, pinned_anchor_fingerprint)
            manifest_sha256 = verify_certificate_package_manifest(
                manifest,
                signature,
                trust_anchor_pub,
                trust_anchor_fp,
            )

            preview = build_package_activation_preview(
                target_cfg=target_cfg,
                manifest=manifest,
                runtime_preview_dir=runtime_preview_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
            )
            gate = evaluate_activation_gate(
                target_cfg=target_cfg,
                preview=preview,
                approval_required=runtime_approval_required,
                approval_summary=preview.get("approval_summary") or {},
                approval_status=str(preview.get("approval_status", "")),
                emergency_override_mode=runtime_emergency_override_mode,
            )
            if gate.get("blocked_reason"):
                raise ValueError(f"{gate.get('status')}:{gate.get('blocked_reason')}")

            stage_dir, validation, checksums = _find_package_stage_bundle(runtime_stage_dir, target, args.package_id, plan_id)
            stage_checksums = _validate_stage_bundle(stage_dir, validation, checksums, args.package_id)
            plan_id = str(validation.get("plan_id") or stage_dir.name)
            runtime_root = Path(str(target_cfg.get("runtime_root", "")))
            _ensure_runtime_writable(runtime_root)
            _verify_certificate_matches_runtime_key(target, manifest, runtime_root)
            activation_copy_started = True
            receipt = activate_package_runtime(
                target_cfg=target_cfg,
                manifest=manifest,
                stage_dir=stage_dir,
                stage_checksums=stage_checksums,
                validation=validation,
                rollback_root=runtime_rollback_dir,
                receipts_root=activation_receipt_dir,
                gate=gate,
            )
            if receipt.get("status") == "already_activated":
                log.info(
                    "package_runtime_already_activated target=%s package_id=%s plan_id=%s changed_files=0 private_key_overwritten=False",
                    target,
                    args.package_id,
                    receipt.get("plan_id"),
                )
                return 0
            log.info(
                "package_runtime_activated target=%s package_id=%s plan_id=%s changed_files=%s private_key_overwritten=%s",
                target,
                args.package_id,
                receipt.get("plan_id"),
                len(receipt.get("changed_files", [])),
                receipt.get("private_key_overwritten"),
            )
            with build_gds_http_client(timeout_seconds=10.0) as client:
                report_certificate_package_lifecycle(
                    log,
                    client,
                    base_url,
                    args.package_id,
                    {**auth_headers, "X-Correlation-ID": activation_sync_id},
                    "ACTIVATED",
                    {
                        "event_type": "package_activated",
                        "target": target,
                        "plan_id": receipt.get("plan_id"),
                        "receipt_id": receipt.get("receipt_id"),
                        "generation": manifest.get("generation"),
                        "manifest_sha256": manifest_sha256,
                        "changed_files_count": len(receipt.get("changed_files", [])),
                        "preserved_files_count": len(receipt.get("preserved_files", [])),
                        "rollback_snapshot_created": True,
                        "runtime_write_enabled": True,
                        "runtime_restart_automatic": False,
                        "private_key_overwritten": False,
                        "sync_cycle_id": activation_sync_id,
                    },
                    event_type="package_activated",
                )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "package_runtime_activated",
                {
                    "target": target,
                    "package_id": args.package_id,
                    "generation": manifest.get("generation"),
                    "plan_id": receipt.get("plan_id"),
                    "receipt_id": receipt.get("receipt_id"),
                    "changed_files_count": len(receipt.get("changed_files", [])),
                    "rollback_snapshot_created": True,
                    "runtime_write_enabled": True,
                    "runtime_restart_automatic": False,
                    "private_key_overwritten": False,
                    "sync_cycle_id": activation_sync_id,
                },
                {
                    "risk_level": "LOW",
                    "application_uri": str(manifest.get("application_uri", "")),
                    "diff_id": str(receipt.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 0
        except Exception as exc:
            failure_text = str(exc) or exc.__class__.__name__
            failure_code = failure_text.split(":", 1)[0]
            with suppress(Exception):
                failure_receipt = write_activation_failure_receipt(
                    activation_receipt_dir,
                    target=target,
                    package_id=args.package_id,
                    plan_id=plan_id,
                    failure_code=failure_code,
                    error=failure_text,
                    mutation_started=activation_copy_started,
                )
                plan_id = str(failure_receipt.get("plan_id") or plan_id)
            log.error(
                "package_activation_failed target=%s package_id=%s plan_id=%s failure_code=%s err=%s",
                target,
                args.package_id,
                plan_id,
                failure_code,
                failure_text,
            )
            with suppress(Exception):
                with build_gds_http_client(timeout_seconds=10.0) as client:
                    report_certificate_package_lifecycle(
                        log,
                        client,
                        base_url,
                        args.package_id,
                        {**auth_headers, "X-Correlation-ID": activation_sync_id},
                        "STAGED",
                        {
                            "event_type": "package_activation_failed",
                            "target": target,
                            "plan_id": plan_id,
                            "generation": manifest.get("generation"),
                            "failure_code": failure_code,
                            "error": truncate_text(failure_text, 500),
                            "runtime_write_enabled": runtime_write_enabled,
                            "activated": False,
                            "sync_cycle_id": activation_sync_id,
                        },
                        event_type="package_activation_failed",
                    )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "warning",
                "gds_agent_error",
                "package_activation_failed",
                {
                    "target": target,
                    "package_id": args.package_id,
                    "plan_id": plan_id,
                    "failure_code": failure_code,
                    "error": truncate_text(failure_text, 300),
                    "runtime_write_enabled": runtime_write_enabled,
                    "activated": False,
                    "sync_cycle_id": activation_sync_id,
                },
                {
                    "risk_level": "MEDIUM",
                    "application_uri": str(manifest.get("application_uri", "")) if manifest else "",
                    "diff_id": plan_id,
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 1

    if not runtime_preview_enabled and (args.runtime_preview_once or args.create_activation_plan or args.stage_activation_dry_run):
        log.error("runtime preview orchestration is disabled (set GDS_AGENT_RUNTIME_PREVIEW_ENABLED=true)")
        return 1

    if runtime_preview_enabled and args.runtime_preview_once:
        if not runtime_targets:
            log.error("no runtime targets configured; set GDS_AGENT_RUNTIME_TARGETS")
            return 1
        try:
            previews = run_runtime_preview_once(
                log=log,
                base_url=base_url,
                runtime_targets=runtime_targets,
                runtime_preview_dir=runtime_preview_dir,
                runtime_compat_dir=runtime_compat_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
                require_signed_artifacts=require_signed_artifacts,
                pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                sign_debug=sign_debug,
                auth_headers=auth_headers,
            )
            for preview in previews:
                severity = normalize_severity_for_diff(str(preview.get("risk_level", "LOW")))
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    severity,
                    "pki_trust_sync",
                    "runtime_preview_generated",
                    {
                        "target": preview.get("target"),
                        "preview_id": preview.get("preview_id"),
                        "artifact_version": preview.get("artifact_version"),
                        "artifact_revision": preview.get("artifact_revision"),
                        "compatibility_status": preview.get("compatibility_status"),
                        "maintenance_window_status": (preview.get("maintenance_window_status") or {}).get("status"),
                        "approval_status": preview.get("approval_status"),
                    },
                    {
                        "risk_level": str(preview.get("risk_level", "")),
                        "trustlist_zone": str(preview.get("artifact_zone", "")),
                        "trustlist_role": str(preview.get("artifact_role", "")),
                        "diff_id": str(preview.get("preview_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                if str(preview.get("compatibility_status")) == "INCOMPATIBLE":
                    forward_ot_collector_event(
                        log,
                        forward_enabled,
                        collector_url,
                        collector_timeout_seconds,
                        zone,
                        asset_ip,
                        control_plane_host,
                        "critical",
                        "pki_validation",
                        "runtime_compatibility_failed",
                        {
                            "target": preview.get("target"),
                            "preview_id": preview.get("preview_id"),
                            "issues": preview.get("compatibility_issues", []),
                        },
                        {
                            "risk_level": "CRITICAL",
                            "trustlist_zone": str(preview.get("artifact_zone", "")),
                            "trustlist_role": str(preview.get("artifact_role", "")),
                            "diff_id": str(preview.get("preview_id", "")),
                        },
                        collector_max_message_len,
                        collector_max_raw_len,
                        collector_max_payload_bytes,
                    )
            return 0
        except Exception as exc:
            failure_code = exc.code if isinstance(exc, ArtifactVerificationError) else "runtime_preview_error"
            log.error("runtime preview failed failure_code=%s err=%s", failure_code, exc)
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "warning",
                "gds_agent_error",
                "runtime_preview_failed",
                {"failure_code": failure_code, "error": str(exc)},
                {},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 1

    if runtime_preview_enabled and args.create_activation_plan:
        if not args.target:
            log.error("--create-activation-plan requires --target")
            return 1
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, args.target)
        if not target_cfg:
            if target_err == "target_not_managed_by_agent_zone":
                log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, args.target)
            else:
                log.error("unknown or disabled runtime target=%s configured_targets=%s", args.target, [t.get("target") for t in runtime_targets])
            return 1
        try:
            plan = create_activation_plan_once(
                log=log,
                base_url=base_url,
                target_cfg=target_cfg,
                runtime_preview_dir=runtime_preview_dir,
                runtime_compat_dir=runtime_compat_dir,
                plan_dir=runtime_plan_dir,
                approvals_dir=approvals_dir,
                rollback_dir=rollback_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
                emergency_override_mode=runtime_emergency_override_mode,
                require_signed_artifacts=require_signed_artifacts,
                pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                sign_debug=sign_debug,
                auth_headers=auth_headers,
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "activation_plan_created",
                {
                    "target": plan.get("target"),
                    "plan_id": plan.get("plan_id"),
                    "status": plan.get("status"),
                    "activation_blocked_reason": plan.get("activation_blocked_reason"),
                    "artifact_version": plan.get("artifact_version"),
                    "artifact_revision": plan.get("artifact_revision"),
                },
                {
                    "risk_level": "",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(plan.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "rollback_bundle_prepared",
                {
                    "target": plan.get("target"),
                    "plan_id": plan.get("plan_id"),
                    "rollback_bundle_id": plan.get("rollback_bundle_id"),
                },
                {
                    "risk_level": "",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(plan.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            if str(plan.get("status")) == "pending_approval":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "approval_missing",
                    {
                        "target": plan.get("target"),
                        "plan_id": plan.get("plan_id"),
                        "required_approval_id": plan.get("required_approval_id"),
                    },
                    {
                        "risk_level": "MEDIUM",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(plan.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            if str(plan.get("status")) == "pending_window":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "maintenance_window_closed",
                    {
                        "target": plan.get("target"),
                        "plan_id": plan.get("plan_id"),
                    },
                    {
                        "risk_level": "MEDIUM",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(plan.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            if str(plan.get("status")) == "blocked_blackout":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "blackout_period_active",
                    {
                        "target": plan.get("target"),
                        "plan_id": plan.get("plan_id"),
                        "activation_blocked_reason": plan.get("activation_blocked_reason"),
                    },
                    {
                        "risk_level": "HIGH",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(plan.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            if str(plan.get("status")) == "emergency_override_ready":
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "emergency_override_used",
                    {
                        "target": plan.get("target"),
                        "plan_id": plan.get("plan_id"),
                        "activation_blocked_reason": plan.get("activation_blocked_reason"),
                    },
                    {
                        "risk_level": "MEDIUM",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(plan.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            return 0
        except Exception as exc:
            failure_code = exc.code if isinstance(exc, ArtifactVerificationError) else "activation_plan_error"
            log.error("activation plan creation failed failure_code=%s err=%s", failure_code, exc)
            return 1

    if runtime_preview_enabled and args.stage_activation_dry_run:
        if not args.target:
            log.error("--stage-activation-dry-run requires --target")
            return 1
        target_cfg, target_err = lookup_managed_runtime_target(zone, runtime_targets, args.target)
        if not target_cfg:
            if target_err == "target_not_managed_by_agent_zone":
                log.error("target_not_managed_by_agent_zone agent_zone=%s target=%s", zone, args.target)
            else:
                log.error("unknown or disabled runtime target=%s configured_targets=%s", args.target, [t.get("target") for t in runtime_targets])
            return 1
        plan = _find_activation_plan_for_target(runtime_plan_dir, args.target, args.plan_id)
        if not plan:
            log.error("activation plan not found target=%s plan_id=%s", args.target, args.plan_id)
            return 1
        try:
            previews = run_runtime_preview_once(
                log=log,
                base_url=base_url,
                runtime_targets=[target_cfg],
                runtime_preview_dir=runtime_preview_dir,
                runtime_compat_dir=runtime_compat_dir,
                approvals_dir=approvals_dir,
                maintenance_policy=maintenance_policy,
                approval_signer=approval_signer,
                approval_required=runtime_approval_required,
                require_signed_artifacts=require_signed_artifacts,
                pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                sign_debug=sign_debug,
                auth_headers=auth_headers,
            )
            preview = previews[0]
            gate = evaluate_activation_gate(
                target_cfg=target_cfg,
                preview=preview,
                approval_required=runtime_approval_required,
                approval_summary=preview.get("approval_summary") if isinstance(preview.get("approval_summary"), dict) else None,
                approval_status=str(preview.get("approval_status", "")),
                emergency_override_mode=runtime_emergency_override_mode,
            )
            if str(gate.get("status", "")).startswith("blocked"):
                log.error(
                    "runtime stage dry-run denied by enforcement target=%s gate=%s reason=%s",
                    target_cfg.get("target"),
                    gate.get("status"),
                    gate.get("blocked_reason"),
                )
                return 1
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info" if str(gate.get("status")) == "ready_for_staging" else "warning",
                "pki_trust_sync",
                "activation_gate_ready",
                {
                    "target": target_cfg.get("target"),
                    "plan_id": plan.get("plan_id"),
                    "gate_status": gate.get("status"),
                    "maintenance_window_status": (preview.get("maintenance_window_status") or {}).get("status"),
                    "approval_status": preview.get("approval_status"),
                },
                {
                    "risk_level": str(preview.get("risk_level", "")),
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(plan.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            stage_report = stage_runtime_activation_dry_run(
                target_cfg=target_cfg,
                plan=plan,
                preview=preview,
                gate=gate,
                stage_root_dir=runtime_stage_dir,
                merge_policy=activation_merge_policy,
            )
            log.info(
                "runtime_stage_dry_run_created target=%s plan_id=%s checksum_verified=%s",
                stage_report.get("target"),
                stage_report.get("plan_id"),
                stage_report.get("checksum_verified"),
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "runtime_stage_dry_run_created",
                {
                    "target": stage_report.get("target"),
                    "plan_id": stage_report.get("plan_id"),
                    "stage_dir": stage_report.get("stage_dir"),
                    "checksum_verified": stage_report.get("checksum_verified"),
                    "current_runtime_status": stage_report.get("current_runtime_status"),
                    "files_to_add_count": stage_report.get("files_to_add_count"),
                    "files_to_replace_count": stage_report.get("files_to_replace_count"),
                    "files_to_remove_count": stage_report.get("files_to_remove_count"),
                    "merge_policy": stage_report.get("merge_policy"),
                    "preserved_runtime_entries_count": stage_report.get("preserved_runtime_entries_count"),
                    "destructive_changes_blocked": stage_report.get("destructive_changes_blocked"),
                },
                {
                    "risk_level": "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(stage_report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            preserved_entries = stage_report.get("preserved_runtime_entries", [])
            if isinstance(preserved_entries, list):
                for entry in preserved_entries[:25]:
                    forward_ot_collector_event(
                        log,
                        forward_enabled,
                        collector_url,
                        collector_timeout_seconds,
                        zone,
                        asset_ip,
                        control_plane_host,
                        "info",
                        "pki_trust_sync",
                        "conservative_merge_preserved_entry",
                        {
                            "target": stage_report.get("target"),
                            "plan_id": stage_report.get("plan_id"),
                            "relative_path": entry.get("relative_path"),
                            "classification": entry.get("classification"),
                            "reason": entry.get("reason"),
                        },
                        {
                            "risk_level": "LOW",
                            "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                            "trustlist_role": str(target_cfg.get("artifact_role", "")),
                            "diff_id": str(stage_report.get("plan_id", "")),
                        },
                        collector_max_message_len,
                        collector_max_raw_len,
                        collector_max_payload_bytes,
                    )
            deletion_candidates = stage_report.get("deletion_candidates", [])
            if isinstance(deletion_candidates, list) and deletion_candidates:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "deletion_candidate_detected",
                    {
                        "target": stage_report.get("target"),
                        "plan_id": stage_report.get("plan_id"),
                        "candidate_count": len(deletion_candidates),
                        "merge_policy": stage_report.get("merge_policy"),
                        "candidates": deletion_candidates[:25],
                    },
                    {
                        "risk_level": "MEDIUM",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(stage_report.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            if stage_report.get("destructive_changes_blocked"):
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "destructive_change_blocked",
                    {
                        "target": stage_report.get("target"),
                        "plan_id": stage_report.get("plan_id"),
                        "merge_policy": stage_report.get("merge_policy"),
                        "deletion_candidate_count": len(deletion_candidates) if isinstance(deletion_candidates, list) else 0,
                        "files_to_remove_count": stage_report.get("files_to_remove_count"),
                    },
                    {
                        "risk_level": "MEDIUM",
                        "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                        "trustlist_role": str(target_cfg.get("artifact_role", "")),
                        "diff_id": str(stage_report.get("plan_id", "")),
                    },
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
            validation_has_warning = bool(stage_report.get("warnings")) or bool(stage_report.get("blocking_reasons"))
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "warning" if validation_has_warning else "info",
                "pki_validation",
                "runtime_stage_validation_warning" if validation_has_warning else "runtime_stage_validation_passed",
                {
                    "target": stage_report.get("target"),
                    "plan_id": stage_report.get("plan_id"),
                    "checksum_verified": stage_report.get("checksum_verified"),
                    "warnings": stage_report.get("warnings", []),
                    "blocking_reasons": stage_report.get("blocking_reasons", []),
                    "validation_report_path": stage_report.get("validation_report_path"),
                },
                {
                    "risk_level": "MEDIUM" if validation_has_warning else "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(stage_report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_trust_sync",
                "rollback_pointer_created",
                {
                    "target": stage_report.get("target"),
                    "plan_id": stage_report.get("plan_id"),
                    "rollback_pointer_path": stage_report.get("rollback_pointer_path"),
                    "runtime_write_enabled": False,
                },
                {
                    "risk_level": "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(stage_report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "info",
                "pki_validation",
                "runtime_write_blocked_by_design",
                {
                    "target": stage_report.get("target"),
                    "plan_id": stage_report.get("plan_id"),
                    "runtime_write_enabled": False,
                    "runtime_restart_automatic": False,
                    "phase": "5.4",
                },
                {
                    "risk_level": "LOW",
                    "trustlist_zone": str(target_cfg.get("artifact_zone", "")),
                    "trustlist_role": str(target_cfg.get("artifact_role", "")),
                    "diff_id": str(stage_report.get("plan_id", "")),
                },
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            return 0
        except Exception as exc:
            failure_code = exc.code if isinstance(exc, ArtifactVerificationError) else "runtime_stage_dry_run_error"
            log.error("runtime stage dry-run failed failure_code=%s err=%s", failure_code, exc)
            return 1

    run_forever = not args.preview_once
    last_success_event_at = 0.0
    while True:
        cycle_start = time.time()
        sync_cycle_id = uuid4().hex
        cycle_auth_headers = {**auth_headers, "X-Correlation-ID": sync_cycle_id}
        try:
            if require_signed_artifacts:
                run_sync_cycle_signed(
                    log=log,
                    base_url=base_url,
                    trust_targets=trust_targets,
                    trust_dir=trust_dir,
                    pki_dir=pki_dir,
                    diff_dir=diff_dir,
                    telemetry_dir=telemetry_dir,
                    forward_enabled=forward_enabled,
                    collector_url=collector_url,
                    collector_timeout_seconds=collector_timeout_seconds,
                    collector_max_message_len=collector_max_message_len,
                    collector_max_raw_len=collector_max_raw_len,
                    collector_max_payload_bytes=collector_max_payload_bytes,
                    agent_zone=zone,
                    asset_ip=asset_ip,
                    control_plane_host=control_plane_host,
                    pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                    sign_debug=sign_debug,
                    auth_headers=cycle_auth_headers,
                    sync_cycle_id=sync_cycle_id,
                )
            else:
                run_sync_cycle(
                    log=log,
                    base_url=base_url,
                    trust_targets=trust_targets,
                    trust_dir=trust_dir,
                    pki_dir=pki_dir,
                    diff_dir=diff_dir,
                    forward_enabled=forward_enabled,
                    collector_url=collector_url,
                    collector_timeout_seconds=collector_timeout_seconds,
                    collector_max_message_len=collector_max_message_len,
                    collector_max_raw_len=collector_max_raw_len,
                    collector_max_payload_bytes=collector_max_payload_bytes,
                    agent_zone=zone,
                    asset_ip=asset_ip,
                    control_plane_host=control_plane_host,
                )
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "pki_validation",
                    "unsigned_trustlist_mode_active",
                    {"agent_id": agent_id},
                    {"risk_level": "HIGH"},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )

            if package_ids and require_signed_artifacts:
                pull_and_cache_certificate_packages(
                    log=log,
                    base_url=base_url,
                    package_ids=package_ids,
                    package_dir=package_dir,
                    auth_headers=cycle_auth_headers,
                    pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                    forward_enabled=forward_enabled,
                    collector_url=collector_url,
                    collector_timeout_seconds=collector_timeout_seconds,
                    collector_max_message_len=collector_max_message_len,
                    collector_max_raw_len=collector_max_raw_len,
                    collector_max_payload_bytes=collector_max_payload_bytes,
                    agent_zone=zone,
                    asset_ip=asset_ip,
                    control_plane_host=control_plane_host,
                    sync_cycle_id=sync_cycle_id,
                )

            elapsed = round(time.time() - cycle_start, 3)
            if runtime_targets and require_signed_artifacts:
                persist_and_forward_inventory_drift(
                    log=log,
                    trust_dir=trust_dir,
                    inventory_drift_dir=inventory_drift_dir,
                    runtime_targets=runtime_targets,
                    forward_enabled=forward_enabled,
                    collector_url=collector_url,
                    collector_timeout_seconds=collector_timeout_seconds,
                    collector_max_message_len=collector_max_message_len,
                    collector_max_raw_len=collector_max_raw_len,
                    collector_max_payload_bytes=collector_max_payload_bytes,
                    agent_zone=zone,
                    asset_ip=asset_ip,
                    control_plane_host=control_plane_host,
                    sync_cycle_id=sync_cycle_id,
                )
            if runtime_preview_enabled and runtime_targets and require_signed_artifacts:
                try:
                    gates = run_activation_gate_cycle(
                        log=log,
                        base_url=base_url,
                        runtime_targets=runtime_targets,
                        runtime_preview_dir=runtime_preview_dir,
                        runtime_compat_dir=runtime_compat_dir,
                        approvals_dir=approvals_dir,
                        gate_dir=runtime_gate_dir,
                        maintenance_policy=maintenance_policy,
                        approval_signer=approval_signer,
                        approval_required=runtime_approval_required,
                        emergency_override_mode=runtime_emergency_override_mode,
                        require_signed_artifacts=require_signed_artifacts,
                        pinned_anchor_fingerprint=pinned_anchor_fingerprint,
                        sign_debug=sign_debug,
                        auth_headers=cycle_auth_headers,
                    )
                    for gate in gates:
                        gate_status = str(gate.get("status", ""))
                        severity = "info"
                        category = "pki_trust_sync"
                        message = "activation_gate_ready"
                        if gate_status == "emergency_override_ready":
                            severity = "warning"
                            category = "pki_validation"
                            message = "emergency_override_used"
                        elif gate_status.startswith("blocked"):
                            severity = "warning"
                            category = "pki_validation"
                            message = "activation_gate_denied"
                        forward_ot_collector_event(
                            log,
                            forward_enabled,
                            collector_url,
                            collector_timeout_seconds,
                            zone,
                            asset_ip,
                            control_plane_host,
                            severity,
                            category,
                            message,
                            {
                                "target": gate.get("target"),
                                "status": gate_status,
                                "blocked_reason": gate.get("blocked_reason"),
                                "approval_status": gate.get("approval_status"),
                                "within_window": gate.get("within_window"),
                                "within_blackout": gate.get("within_blackout"),
                                "artifact_version": gate.get("artifact_version"),
                                "artifact_revision": gate.get("artifact_revision"),
                            },
                            {
                                "risk_level": str(gate.get("risk_level", "")),
                                "trustlist_zone": str(zone),
                                "trustlist_role": "",
                                "diff_id": str(gate.get("preview_id", "")),
                            },
                            collector_max_message_len,
                            collector_max_raw_len,
                            collector_max_payload_bytes,
                        )
                except Exception as gate_exc:
                    log.warning("activation gate cycle failed err=%s", gate_exc)
            log.info("sync cycle success id=%s elapsed_seconds=%s", agent_id, elapsed)
            now = time.time()
            if now - last_success_event_at >= success_event_min_interval:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "sync_cycle_success",
                    {"agent_id": agent_id, "elapsed_seconds": elapsed, "sync_cycle_id": sync_cycle_id, **transport_meta},
                    {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "agent_id": agent_id},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                last_success_event_at = now
            if args.preview_once:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "info",
                    "pki_trust_sync",
                    "preview_once_success",
                    {"agent_id": agent_id, "elapsed_seconds": elapsed, "sync_cycle_id": sync_cycle_id, **transport_meta},
                    {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "agent_id": agent_id},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
        except Exception as exc:
            failure_code = exc.code if isinstance(exc, ArtifactVerificationError) else "sync_cycle_error"
            log.error("sync cycle failed id=%s failure_code=%s err=%s", agent_id, failure_code, exc)
            forward_ot_collector_event(
                log,
                forward_enabled,
                collector_url,
                collector_timeout_seconds,
                zone,
                asset_ip,
                control_plane_host,
                "warning",
                "gds_agent_error",
                "sync_cycle_failure",
                {"agent_id": agent_id, "failure_code": failure_code, "error": str(exc), "sync_cycle_id": sync_cycle_id, **transport_meta},
                {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "agent_id": agent_id},
                collector_max_message_len,
                collector_max_raw_len,
                collector_max_payload_bytes,
            )
            if args.preview_once:
                forward_ot_collector_event(
                    log,
                    forward_enabled,
                    collector_url,
                    collector_timeout_seconds,
                    zone,
                    asset_ip,
                    control_plane_host,
                    "warning",
                    "gds_agent_error",
                    "preview_once_failure",
                    {"agent_id": agent_id, "failure_code": failure_code, "error": str(exc), "sync_cycle_id": sync_cycle_id, **transport_meta},
                    {"sync_cycle_id": sync_cycle_id, "correlation_id": sync_cycle_id, "agent_id": agent_id},
                    collector_max_message_len,
                    collector_max_raw_len,
                    collector_max_payload_bytes,
                )
                return 1

        if not run_forever:
            return 0

        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
