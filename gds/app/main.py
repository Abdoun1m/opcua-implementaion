from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .agent_auth import AgentAuthStore, verify_token
from .artifact_signing import TrustArtifactSigner, canonical_artifact_payload, canonical_json_bytes, sha256_hex
from .cert_utils import parse_pem_certificate
from .checks import full_health
from .config import load_settings
from .db import (
    ALLOWED_ROLES,
    ALLOWED_ZONES,
    audit,
    build_trust_list,
    ensure_trust_list_current,
    get_application,
    get_application_by_uri,
    get_component_status,
    get_certificate,
    get_certificate_by_fingerprint,
    get_certificate_package,
    get_certificate_request,
    list_certificate_packages_for_certificate,
    list_certificate_packages,
    list_certificate_packages_for_lineage,
    list_package_events,
    get_latest_trust_list_with_certs,
    get_latest_trust_artifact,
    get_component_profile,
    heartbeat_application,
    insert_trust_artifact,
    insert_certificate,
    insert_component_event,
    list_component_profiles,
    list_component_statuses,
    list_component_events,
    list_trust_artifact_history,
    list_applications,
    list_audit_events,
    list_audit_events_by_type,
    list_certificates,
    list_trustlist_targets,
    insert_package_event,
    mark_certificate_revoked,
    migrate,
    count_audit_events_by_reason,
    package_lifecycle_telemetry,
    seed_component_profiles,
    upsert_component_status,
    update_certificate_package_lifecycle,
    upsert_application,
)
from .dmz_collector_sender import DmzCollectorSender, start_dmz_collector_sender
from .inventory import seed_and_import
from .lifecycle import LifecycleError, issue_certificate_package, package_signature_payload
from .logging_json import configure_logging
from .opcua_boundary_adapter import OpcUaPart12BoundaryAdapter
from .runtime_adapters import default_component_profiles
from .vault_client import VaultClient, VaultSealedError


configure_logging(os.getenv("GDS_LOG_LEVEL", "INFO"))
SETTINGS = load_settings()
LOG = logging.getLogger("gds.api")
OPCUA_BOUNDARY_ADAPTER: OpcUaPart12BoundaryAdapter | None = None
VAULT_CLIENT: VaultClient | None = None
TRUST_ARTIFACT_SIGNER: TrustArtifactSigner | None = None
SIGNED_ARTIFACT_CACHE: dict[str, object] = {}
ARTIFACT_REGEN_LOCK = threading.Lock()
ARTIFACT_REGEN_LAST_AT: dict[str, float] = {}
ARTIFACT_SCAN_STOP = threading.Event()
ARTIFACT_SCAN_THREAD: threading.Thread | None = None
DMZ_COLLECTOR_SENDER: DmzCollectorSender | None = None
AGENT_AUTH_STORE: AgentAuthStore | None = None
LAST_GOOD_INTERMEDIATE_CRL: dict | None = None


class RegisterApplicationBody(BaseModel):
    application_uri: str
    common_name: str
    zone: Literal["OT", "DMZ", "IT"]
    role: str
    runtime_instance_id: str | None = None
    component_type: str | None = None
    host: str | None = None
    port: int | None = None
    status: str = "active"


class TrustListBuildBody(BaseModel):
    zone: Literal["OT", "DMZ", "IT"]
    role: str


class ImportCertificateBody(BaseModel):
    application_uri: str
    zone: Literal["OT", "DMZ", "IT"]
    role: str
    pem: str


class EnrollCsrBody(BaseModel):
    application_uri: str
    runtime_instance_id: str | None = None
    profile_name: str
    csr_pem: str
    requested_ttl: str | None = None
    requested_subject: str | None = None
    requested_sans: dict | None = None


class RenewCsrBody(BaseModel):
    application_uri: str
    runtime_instance_id: str | None = None
    profile_name: str
    csr_pem: str
    requested_ttl: str | None = None
    renewal_reason: str | None = None


class RevokeCertificateBody(BaseModel):
    certificate_id: int | None = None
    package_id: str | None = None
    fingerprint_sha256: str | None = None
    operator: str | None = None
    reason: str = "operator requested revocation"


class PackageLifecycleEventBody(BaseModel):
    lifecycle_state: Literal["PULLED", "VERIFIED", "STAGED", "APPROVED", "ACTIVATED", "ROLLED_BACK", "REVOKED", "EXPIRED"]
    event_type: str | None = None
    details: dict | None = None


class ComponentStatusBody(BaseModel):
    application_uri: str
    component_name: str | None = None
    runtime_instance_id: str | None = None
    zone: str | None = None
    role: str | None = None
    target: str | None = None
    certificate_fingerprint_sha256: str | None = None
    certificate_not_before: datetime | None = None
    certificate_not_after: datetime | None = None
    days_until_expiry: int | None = None
    trust_artifact_version: int | None = None
    trust_artifact_revision: int | None = None
    trust_artifact_sha256: str | None = None
    crl_freshness_verified: bool = False
    last_pull_status: str | None = None
    last_apply_status: str | None = None
    last_renewal_status: str | None = None
    private_key_exported: bool = False
    private_key_touched: bool = False
    runtime_write_enabled: bool = False
    timestamp: datetime | None = None


class ComponentEventBody(BaseModel):
    application_uri: str
    component_name: str | None = None
    target: str | None = None
    event_type: str
    status: str | None = None
    message: str | None = None
    details: dict | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global OPCUA_BOUNDARY_ADAPTER, VAULT_CLIENT, TRUST_ARTIFACT_SIGNER, ARTIFACT_SCAN_THREAD, DMZ_COLLECTOR_SENDER, AGENT_AUTH_STORE
    os.makedirs(SETTINGS.data_dir, exist_ok=True)
    LOG.info("gds bootstrap starting version=%s", SETTINGS.service_version)
    VAULT_CLIENT = VaultClient(SETTINGS)
    AGENT_AUTH_STORE = AgentAuthStore(SETTINGS.agent_tokens_file)
    TRUST_ARTIFACT_SIGNER = TrustArtifactSigner(
        SETTINGS.trust_artifact_signing_key_path,
        SETTINGS.trust_artifact_signing_key_id,
        SETTINGS.trust_artifact_ttl_seconds,
    )
    if SETTINGS.agent_auth_enabled:
        LOG.info("agent auth enabled tokens_file=%s", SETTINGS.agent_tokens_file)
        if not os.path.exists(SETTINGS.agent_tokens_file):
            LOG.warning("agent auth token policy file not found path=%s", SETTINGS.agent_tokens_file)
        elif not os.access(SETTINGS.agent_tokens_file, os.R_OK):
            LOG.warning("agent auth token policy file is not readable path=%s", SETTINGS.agent_tokens_file)
    else:
        LOG.info("agent auth disabled")
    migrate(SETTINGS)
    seed_component_profiles(SETTINGS, default_component_profiles())
    seed_and_import(SETTINGS)
    ARTIFACT_SCAN_STOP.clear()
    ARTIFACT_SCAN_THREAD = threading.Thread(target=_artifact_scan_loop, name="gds-artifact-scan", daemon=True)
    ARTIFACT_SCAN_THREAD.start()
    DMZ_COLLECTOR_SENDER = start_dmz_collector_sender(SETTINGS)

    if SETTINGS.opcua_facade_enabled:
        OPCUA_BOUNDARY_ADAPTER = OpcUaPart12BoundaryAdapter(SETTINGS)
        await OPCUA_BOUNDARY_ADAPTER.start()

    try:
        yield
    finally:
        ARTIFACT_SCAN_STOP.set()
        if ARTIFACT_SCAN_THREAD:
            ARTIFACT_SCAN_THREAD.join(timeout=3.0)
        if DMZ_COLLECTOR_SENDER:
            DMZ_COLLECTOR_SENDER.stop(timeout=3.0)
        if OPCUA_BOUNDARY_ADAPTER:
            await OPCUA_BOUNDARY_ADAPTER.stop()
        LOG.info("gds bootstrap stopped")


app = FastAPI(
    title="LabShock GDS Bootstrap",
    version=SETTINGS.service_version,
    lifespan=lifespan,
)


def _connection_ip(request: Request) -> str:
    if not request.client:
        return "unknown"
    return request.client.host or "unknown"


def _request_ip(request: Request) -> str:
    connection_ip = _connection_ip(request)
    if connection_ip in SETTINGS.trusted_proxy_ips:
        real_ip = str(request.headers.get("X-Real-IP", "")).strip()
        if real_ip:
            return real_ip
    return connection_ip


def _correlation_id(request: Request) -> str:
    value = str(getattr(request.state, "correlation_id", "") or "").strip()
    if value:
        return value
    value = str(request.headers.get("X-Correlation-ID", "")).strip() or uuid4().hex
    request.state.correlation_id = value
    return value


def _agent_id_from_request(request: Request) -> str:
    return str(request.headers.get("X-GDS-Agent-ID", "")).strip() or "unknown"


def _require_https_mtls(request: Request) -> JSONResponse | None:
    if str(request.headers.get("X-Forwarded-Proto", "")).strip().lower() != "https":
        audit(
            SETTINGS,
            "mtls_client_identity_failure",
            _agent_id_from_request(request),
            f"enrollment:{request.url.path}",
            {"reason": "https_mtls_required", "path": request.url.path, "source_ip": _request_ip(request)},
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "HTTPS/mTLS listener required", "error_code": "https_mtls_required"},
        )
    details = _client_cert_header_details(request)
    if details.get("verify") != "SUCCESS":
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "valid client certificate required", "error_code": "missing_client_certificate"},
        )
    return None


def _parse_tls_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _cert_days_remaining(not_after_value: str, header_value: str) -> int | None:
    if header_value.strip().lstrip("-").isdigit():
        return int(header_value.strip())
    parsed = _parse_tls_date(not_after_value)
    if not parsed:
        return None
    return int((parsed - datetime.now(timezone.utc)).total_seconds() // 86400)


def _client_cert_header_details(request: Request) -> dict:
    not_after = str(request.headers.get("X-Client-Cert-Not-After", "")).strip()
    days_remaining = _cert_days_remaining(
        not_after,
        str(request.headers.get("X-Client-Cert-Days-Remaining", "")).strip(),
    )
    return {
        "verify": str(request.headers.get("X-Client-Cert-Verify", "")).strip(),
        "subject": str(request.headers.get("X-Client-Cert-Subject", "")).strip(),
        "issuer": str(request.headers.get("X-Client-Cert-Issuer", "")).strip(),
        "serial": str(request.headers.get("X-Client-Cert-Serial", "")).strip(),
        "fingerprint": str(request.headers.get("X-Client-Cert-Fingerprint", "")).strip(),
        "not_before": str(request.headers.get("X-Client-Cert-Not-Before", "")).strip(),
        "not_after": not_after,
        "days_remaining": days_remaining,
    }


def _has_client_cert_headers(request: Request) -> bool:
    return any(value for value in _client_cert_header_details(request).values())


def _internal_proxy_proof_ok(request: Request) -> bool:
    expected = SETTINGS.internal_proxy_secret
    if not expected:
        return False
    supplied = str(request.headers.get("X-GDS-Internal-Proxy", "")).strip()
    return supplied == expected


def _audit_mtls_identity(request: Request, event_type: str, reason: str, details: dict | None = None) -> None:
    payload = {
        "reason": reason,
        "source_ip": _request_ip(request),
        "proxy_source_ip": _connection_ip(request),
        "path": request.url.path,
        "agent_id": _agent_id_from_request(request),
        "correlation_id": _correlation_id(request),
    }
    payload.update(_client_cert_header_details(request))
    if details:
        payload.update(details)
    try:
        audit(SETTINGS, event_type, payload["agent_id"], f"mtls:{request.url.path}", payload)
    except Exception as exc:
        LOG.warning("mTLS audit failed event_type=%s reason=%s err=%s", event_type, reason, exc)


@app.middleware("http")
async def enforce_mtls_header_boundary(request: Request, call_next):
    correlation_id = _correlation_id(request)
    source_ip = _connection_ip(request)
    forwarded_proto = str(request.headers.get("X-Forwarded-Proto", "")).strip().lower()
    is_https_edge_request = forwarded_proto == "https"
    has_cert_headers = _has_client_cert_headers(request)
    proxy_proof_ok = _internal_proxy_proof_ok(request)

    if request.url.path == "/internal/health":
        if source_ip not in {"127.0.0.1", "::1"}:
            response = JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "not found"})
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    if (has_cert_headers or is_https_edge_request) and not proxy_proof_ok:
        _audit_mtls_identity(request, "mtls_client_identity_failure", "untrusted_proxy_headers", {"proxy_proof": "fail"})
        response = JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "untrusted client certificate headers",
                "error_code": "untrusted_proxy_headers",
                "correlation_id": correlation_id,
            },
        )
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    if has_cert_headers and not is_https_edge_request:
        _audit_mtls_identity(request, "mtls_client_identity_failure", "mtls_headers_on_non_https_request", {"proxy_proof": "ok"})
        response = JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "client certificate headers are not trusted on this listener",
                "error_code": "mtls_headers_on_non_https_request",
                "correlation_id": correlation_id,
            },
        )
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    if is_https_edge_request:
        details = _client_cert_header_details(request)
        if details["verify"] != "SUCCESS":
            reason = "missing_client_certificate" if details["verify"] in {"", "NONE"} else "client_certificate_verify_failed"
            _audit_mtls_identity(request, "mtls_client_identity_failure", reason, {"proxy_proof": "ok"})
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "valid client certificate required",
                    "error_code": reason,
                    "mtls_verify_status": details["verify"],
                    "correlation_id": correlation_id,
                },
            )
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        _audit_mtls_identity(request, "mtls_client_identity_success", "client_certificate_verified", {"proxy_proof": "ok"})

    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


def _authorize_agent_pull(
    request: Request,
    access: str,
    zone: str | None = None,
    role: str | None = None,
    application_uri: str | None = None,
) -> JSONResponse | None:
    if not SETTINGS.agent_auth_enabled:
        return None
    if not AGENT_AUTH_STORE:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "agent auth not initialized", "error_code": "agent_auth_not_initialized"},
        )

    agent_id = str(request.headers.get("X-GDS-Agent-ID", "")).strip()
    agent_token = str(request.headers.get("X-GDS-Agent-Token", "")).strip()
    source_ip = _request_ip(request)
    target = f"{access}:{zone or ''}:{role or ''}:{application_uri or ''}"

    if not agent_id or not agent_token:
        audit(
            SETTINGS,
            "agent_auth_failure",
            "unknown",
            target,
            {"reason": "missing_headers", "source_ip": source_ip},
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "agent authentication required", "error_code": "agent_auth_missing_headers"},
        )

    if not os.path.exists(SETTINGS.agent_tokens_file):
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "tokens_file_missing", "source_ip": source_ip, "tokens_file": SETTINGS.agent_tokens_file},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "agent auth token policy unavailable", "error_code": "agent_token_policy_missing"},
        )
    if not os.access(SETTINGS.agent_tokens_file, os.R_OK):
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "tokens_file_unreadable", "source_ip": source_ip, "tokens_file": SETTINGS.agent_tokens_file},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "agent auth token policy unavailable", "error_code": "agent_token_policy_unreadable"},
        )

    try:
        policy = AGENT_AUTH_STORE.get_policy(agent_id)
    except Exception:
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "tokens_file_error", "source_ip": source_ip},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "agent auth unavailable", "error_code": "agent_token_policy_error"},
        )

    if not policy:
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "unknown_agent", "source_ip": source_ip},
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid agent credentials", "error_code": "agent_unknown"},
        )

    if not verify_token(policy, agent_token):
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "invalid_token", "source_ip": source_ip},
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid agent credentials", "error_code": "agent_invalid_token"},
        )

    allowed = False
    if access == "trust_anchor":
        allowed = policy.allow_trust_anchor
    elif access == "artifact_read":
        allowed = zone is not None and role is not None and (zone, role) in policy.allowed_trustlists
    elif access == "telemetry_read":
        allowed = True
    elif access in {"lifecycle_read", "lifecycle_write"}:
        allowed = True
    elif access in {"enrollment_submit", "package_read", "package_update"}:
        allowed = True
    if allowed and application_uri and access in {"lifecycle_read", "lifecycle_write"}:
        lifecycle_apps = policy.owned_applications or policy.allowed_applications
        allowed = application_uri in lifecycle_apps
    elif allowed and application_uri and policy.allowed_applications:
        allowed = application_uri in policy.allowed_applications

    if not allowed:
        audit(
            SETTINGS,
            "agent_unauthorized_pull",
            agent_id,
            target,
            {"source_ip": source_ip, "zone": zone, "role": role, "application_uri": application_uri},
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "agent not authorized for this resource", "error_code": "agent_not_authorized"},
        )

    audit(
        SETTINGS,
        "agent_auth_success",
        agent_id,
        target,
        {"source_ip": source_ip, "zone": zone, "role": role, "application_uri": application_uri},
    )
    return None


def _deny_agent_on_admin_endpoint(request: Request, target: str) -> JSONResponse | None:
    if not SETTINGS.agent_auth_enabled:
        return None
    if not AGENT_AUTH_STORE:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "agent auth not initialized"})

    agent_id = str(request.headers.get("X-GDS-Agent-ID", "")).strip()
    agent_token = str(request.headers.get("X-GDS-Agent-Token", "")).strip()
    if not agent_id and not agent_token:
        return None

    source_ip = _request_ip(request)
    if not agent_id or not agent_token:
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id or "unknown",
            target,
            {"reason": "missing_headers", "source_ip": source_ip},
        )
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"error": "invalid agent credentials"})

    try:
        policy = AGENT_AUTH_STORE.get_policy(agent_id)
    except Exception:
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "tokens_file_error", "source_ip": source_ip},
        )
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "agent auth unavailable"})

    if not policy or not verify_token(policy, agent_token):
        audit(
            SETTINGS,
            "agent_auth_failure",
            agent_id,
            target,
            {"reason": "invalid_credentials", "source_ip": source_ip},
        )
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"error": "invalid agent credentials"})

    audit(
        SETTINGS,
        "agent_unauthorized_pull",
        agent_id,
        target,
        {"source_ip": source_ip, "reason": "admin_endpoint_forbidden"},
    )
    return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"error": "agent is not authorized for admin endpoint"})


@app.get("/health")
def health(response: Response):
    report = full_health(SETTINGS)
    crl_status = {}
    vault_sealed = False
    if VAULT_CLIENT:
        try:
            vault_report = VAULT_CLIENT.get_status()
            vault_sealed = bool(vault_report.get("vault_sealed"))
            bundle = VAULT_CLIENT.get_crl_bundle()
            crl_status = {
                "root_crl_ok": bool(bundle.get("root", {}).get("freshness_verified")),
                "root_crl_next_update": bundle.get("root_crl_next_update"),
                "root_crl_source": bundle.get("root_crl_source"),
                "intermediate_crl_ok": bool(bundle.get("intermediate", {}).get("freshness_verified")),
                "intermediate_crl_next_update": bundle.get("intermediate_crl_next_update"),
                "crl_freshness_verified": bool(bundle.get("crl_freshness_verified")),
            }
            if SETTINGS.vault_strict_crl_freshness and not crl_status["crl_freshness_verified"]:
                report["ok"] = False
        except Exception as exc:
            vault_sealed = VAULT_CLIENT.vault_sealed if VAULT_CLIENT else False
            crl_status = {"root_crl_ok": False, "intermediate_crl_ok": False, "detail": exc.__class__.__name__}
            if SETTINGS.vault_strict_crl_freshness and not vault_sealed:
                report["ok"] = False
    if vault_sealed:
        report["ok"] = False
    response.status_code = status.HTTP_200_OK if report["ok"] else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "service": SETTINGS.service_name,
        "version": SETTINGS.service_version,
        "status": "ok" if report["ok"] else "degraded",
        "vault_sealed": vault_sealed,
        "cached_artifacts": _cached_artifacts_state(),
        "checks": report["components"],
        "crl_status": crl_status,
    }


@app.get("/internal/health")
def internal_health():
    return {"status": "ok", "service": SETTINGS.service_name}


def _as_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _json_safe(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _vault_sealed_response() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error_code": "vault_sealed"})


def _require_vault_unsealed() -> JSONResponse | None:
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    try:
        report = VAULT_CLIENT.get_status()
    except Exception as exc:
        LOG.warning("vault status guard failed: %s", exc.__class__.__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error_code": "vault_unavailable"})
    if report.get("vault_sealed"):
        return _vault_sealed_response()
    return None


def _cached_artifacts_state() -> str:
    try:
        rows = [get_latest_trust_artifact(SETTINGS, zone, role) for zone, role in list_trustlist_targets(SETTINGS)]
    except Exception:
        return "unavailable"
    valid = False
    expired = False
    for row in rows:
        if not row:
            continue
        if _ttl_remaining_seconds(row) > 0:
            valid = True
        else:
            expired = True
    if valid:
        return "valid"
    if expired:
        return "expired"
    return "unavailable"


def _crl_payload_valid(payload: dict | None) -> bool:
    if not isinstance(payload, dict):
        return False
    next_update = payload.get("next_update")
    if not next_update:
        return False
    try:
        parsed = datetime.fromisoformat(str(next_update).replace("Z", "+00:00"))
    except Exception:
        try:
            parsed = parsedate_to_datetime(str(next_update))
        except Exception:
            return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed > datetime.now(timezone.utc)


def _days_until(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int((value.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds() // 86400)
    return None


def _expiry_state(days_remaining: int | None) -> str:
    if days_remaining is None:
        return "unknown"
    if days_remaining < 0:
        return "expired"
    if days_remaining <= SETTINGS.cert_expiry_critical_days:
        return "critical"
    if days_remaining <= SETTINGS.cert_expiry_warning_days:
        return "warning"
    return "ok"


def _certificate_telemetry_record(cert: dict) -> dict:
    days_remaining = _days_until(cert.get("not_after"))
    operational = str(cert.get("status", "")).lower() == "active" and not cert.get("revoked_at")
    return {
        "id": cert.get("id"),
        "application_id": cert.get("application_id"),
        "application_uri": cert.get("application_uri"),
        "common_name": cert.get("common_name"),
        "zone": cert.get("zone"),
        "role": cert.get("role"),
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "serial_number": cert.get("serial_number"),
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_before": _as_iso(cert.get("not_before")),
        "not_after": _as_iso(cert.get("not_after")),
        "days_remaining": days_remaining,
        "expiry_state": _expiry_state(days_remaining),
        "operational": operational,
        "status": cert.get("status"),
        "revoked_at": _as_iso(cert.get("revoked_at")),
    }


def _count_by_expiry_state(certs: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for cert in certs:
        state = str(cert.get("expiry_state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
    return counts


def _renewal_threshold_days_for_profile(profile_meta: dict | None) -> int:
    profile_meta = profile_meta or {}
    policy = profile_meta.get("enrollment_policy_json")
    if not isinstance(policy, dict):
        policy = profile_meta.get("enrollment_policy")
    if isinstance(policy, dict) and policy.get("renewal_threshold_days") is not None:
        try:
            threshold = int(policy["renewal_threshold_days"])
            if threshold >= 0:
                return threshold
        except (TypeError, ValueError):
            LOG.warning(
                "invalid profile renewal_threshold_days profile=%s value=%r",
                profile_meta.get("profile_name"),
                policy.get("renewal_threshold_days"),
            )
    try:
        threshold = int(SETTINGS.renewal_threshold_days)
        if threshold >= 0:
            return threshold
    except (TypeError, ValueError):
        LOG.warning("invalid setting renewal_threshold_days value=%r", SETTINGS.renewal_threshold_days)
    return 14


def _renewal_threshold_days_for_app(app: dict) -> int:
    profile_meta = _profile_for_application(app)
    profile_row = get_component_profile(SETTINGS, str(profile_meta.get("profile_name") or "")) or {}
    return _renewal_threshold_days_for_profile({**profile_meta, **profile_row})


def _certificate_drift_report() -> dict:
    applications = list_applications(SETTINGS)
    certs = list_certificates(SETTINGS)
    active_cert_apps = {
        int(cert["application_id"])
        for cert in certs
        if str(cert.get("status", "")).lower() == "active"
    }
    drift: list[dict] = []
    for app_row in applications:
        if str(app_row.get("status", "")).lower() == "active" and int(app_row["id"]) not in active_cert_apps:
            drift.append(
                {
                    "type": "application_missing_active_certificate",
                    "application_id": app_row["id"],
                    "application_uri": app_row["application_uri"],
                    "zone": app_row["zone"],
                    "role": app_row["role"],
                }
            )
    for cert in certs:
        telemetry = _certificate_telemetry_record(cert)
        if telemetry["expiry_state"] == "expired" and str(cert.get("status", "")).lower() == "active":
            drift.append(
                {
                    "type": "active_certificate_expired",
                    "certificate_id": cert["id"],
                    "application_uri": cert.get("application_uri"),
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                    "days_remaining": telemetry["days_remaining"],
                }
            )
        if str(cert.get("status", "")).lower() == "revoked" and not cert.get("revoked_at"):
            drift.append(
                {
                    "type": "revoked_certificate_missing_revoked_at",
                    "certificate_id": cert["id"],
                    "application_uri": cert.get("application_uri"),
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                }
            )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "drift_detected" if drift else "ok",
        "drift_count": len(drift),
        "items": drift,
    }


@app.get("/api/v1/mtls/metrics")
def get_mtls_metrics(request: Request):
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    recent = list_audit_events_by_type(
        SETTINGS,
        ["mtls_client_identity_success", "mtls_client_identity_failure"],
        limit=500,
    )
    failures_by_reason = count_audit_events_by_reason(SETTINGS, "mtls_client_identity_failure")
    success_count = sum(1 for row in recent if row.get("event_type") == "mtls_client_identity_success")
    failure_count = sum(1 for row in recent if row.get("event_type") == "mtls_client_identity_failure")
    audit(
        SETTINGS,
        "mtls_metrics_read",
        _agent_id_from_request(request),
        "mtls:metrics",
        {"correlation_id": _correlation_id(request), "recent_count": len(recent)},
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"recent_limit": 500},
        "success_count": success_count,
        "failure_count": failure_count,
        "failed_cert_auth_counters": failures_by_reason,
        "recent": [
            {
                "id": row.get("id"),
                "event_type": row.get("event_type"),
                "actor": row.get("actor"),
                "target": row.get("target"),
                "created_at": row.get("created_at"),
                "details_json": row.get("details_json"),
            }
            for row in recent[:50]
        ],
    }


@app.get("/api/v1/certificates/telemetry")
def get_certificate_telemetry(request: Request):
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    certs = [_certificate_telemetry_record(cert) for cert in list_certificates(SETTINGS)]
    operational_certs = [cert for cert in certs if cert.get("operational")]
    counts = _count_by_expiry_state(operational_certs)
    historical_counts = _count_by_expiry_state([cert for cert in certs if not cert.get("operational")])
    audit(
        SETTINGS,
        "certificate_telemetry_read",
        _agent_id_from_request(request),
        "certificates:telemetry",
        {"correlation_id": _correlation_id(request), "certificate_count": len(certs)},
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": {
            "warning_days": SETTINGS.cert_expiry_warning_days,
            "critical_days": SETTINGS.cert_expiry_critical_days,
        },
        "counts_by_expiry_state": counts,
        "historical_counts_by_expiry_state": historical_counts,
        "operational_certificate_count": len(operational_certs),
        "historical_certificate_count": len(certs) - len(operational_certs),
        "certificates": certs,
    }


@app.get("/api/v1/certificates/drift")
def get_certificate_drift(request: Request):
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    report = _certificate_drift_report()
    audit(
        SETTINGS,
        "certificate_drift_read",
        _agent_id_from_request(request),
        "certificates:drift",
        {"correlation_id": _correlation_id(request), "drift_count": report["drift_count"]},
    )
    return report


@app.get("/api/v1/pki/ca-chain")
def get_ca_chain():
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized"})
    try:
        return VAULT_CLIENT.get_ca_chain()
    except VaultSealedError:
        return _vault_sealed_response()
    except Exception as exc:
        LOG.error("ca-chain retrieval failed: %s", exc.__class__.__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "ca-chain retrieval failed", "error_code": "ca_chain_unavailable"})


@app.get("/api/v1/pki/crl")
def get_crl(response: Response):
    global LAST_GOOD_INTERMEDIATE_CRL
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized"})
    try:
        payload = VAULT_CLIENT.get_intermediate_crl()
        if _crl_payload_valid(payload):
            LAST_GOOD_INTERMEDIATE_CRL = payload
        return payload
    except VaultSealedError:
        if _crl_payload_valid(LAST_GOOD_INTERMEDIATE_CRL):
            response.headers["X-GDS-Cache"] = "true"
            response.headers["X-GDS-Cache-Reason"] = "vault_sealed"
            return LAST_GOOD_INTERMEDIATE_CRL
        return _vault_sealed_response()
    except Exception as exc:
        LOG.error("crl retrieval failed: %s", exc.__class__.__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "crl retrieval failed", "error_code": "crl_unavailable"})


@app.get("/api/v1/pki/crls")
def get_crl_bundle():
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized"})
    try:
        bundle = VAULT_CLIENT.get_crl_bundle()
        return {
            "root": {k: v for k, v in bundle["root"].items() if k != "crl_base64"},
            "intermediate": {k: v for k, v in bundle["intermediate"].items() if k != "crl_base64"},
            "crl_freshness_verified": bundle.get("crl_freshness_verified"),
        }
    except VaultSealedError:
        return _vault_sealed_response()
    except Exception as exc:
        LOG.error("crl bundle retrieval failed: %s", exc.__class__.__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "crl bundle retrieval failed", "error_code": "crl_bundle_unavailable"})


@app.get("/api/v1/vault/status")
def vault_status(response: Response):
    if not VAULT_CLIENT:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "vault_reachable": False,
            "vault_initialized": False,
            "vault_sealed": True,
            "vault_mtls_enabled": False,
            "token_ok": False,
            "pki_root_ok": False,
            "pki_int_ok": False,
            "crl_status": "unavailable",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    report = VAULT_CLIENT.get_status()
    ok = bool(report.get("vault_reachable")) and bool(report.get("vault_initialized")) and not bool(report.get("vault_sealed")) and bool(report.get("token_ok"))
    if SETTINGS.vault_strict_crl_freshness:
        ok = ok and bool(report.get("pki_int_ok")) and bool(report.get("pki_root_ok"))
    response.status_code = status.HTTP_200_OK if ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return report


@app.get("/api/v1/trustlists/{zone}/{role}")
def get_trustlist(zone: str, role: str):
    if zone not in ALLOWED_ZONES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid zone"})
    if role not in ALLOWED_ROLES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid role"})
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized"})
    trust_list, certs = get_latest_trust_list_with_certs(SETTINGS, zone, role)
    if not trust_list:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})
    ca_chain = VAULT_CLIENT.get_ca_chain()
    crl = VAULT_CLIENT.get_intermediate_crl()
    payload = {
        "zone": zone,
        "role": role,
        "version": trust_list["version"],
        "generated_at": trust_list["published_at"],
        "ca_chain_pem": ca_chain["ca_chain_pem"],
        "crl_base64": crl["crl_base64"],
        "certificates": certs,
    }
    audit(SETTINGS, "trustlist_read", "system", f"trustlist:{zone}:{role}", {"version": trust_list["version"]})
    return payload


@app.get("/api/v1/signing/trust-anchor")
def get_signing_trust_anchor(request: Request):
    auth_err = _authorize_agent_pull(request, access="trust_anchor")
    if auth_err:
        return auth_err
    if not TRUST_ARTIFACT_SIGNER:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized"})
    return TRUST_ARTIFACT_SIGNER.trust_anchor_payload()


COMPONENT_DISCOVERY_CATALOG: dict[str, dict[str, object]] = {
    "opcua-server": {
        "target": "opcua-server",
        "application_uri": "urn:dataprotect:opcua:ot-server",
        "runtime_instance_id": "urn:dataprotect:opcua:ot-server",
        "profile_name": "open62541-server",
        "zone": "OT",
        "role": "server",
        "component_type": "server",
        "runtime_family": "open62541",
    },
    "fuxa": {
        "target": "fuxa",
        "application_uri": "urn:dataprotect:opcua:fuxa-client",
        "runtime_instance_id": "urn:dataprotect:opcua:fuxa-client",
        "profile_name": "node-opcua-client",
        "zone": "OT",
        "role": "scada-client",
        "component_type": "client",
        "runtime_family": "node-opcua",
    },
    "dmz-gateway-client": {
        "target": "dmz-gateway-client",
        "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
        "runtime_instance_id": "urn:dataprotect:opcua:dmz-gateway-client",
        "profile_name": "open62541-client",
        "zone": "DMZ",
        "role": "southbound-client",
        "component_type": "client",
        "runtime_family": "open62541",
    },
    "dmz-gateway-server": {
        "target": "dmz-gateway-server",
        "application_uri": "urn:dataprotect:opcua:dmz-gateway-server",
        "runtime_instance_id": "urn:dataprotect:opcua:dmz-gateway-server",
        "profile_name": "open62541-server",
        "zone": "DMZ",
        "role": "northbound-server",
        "component_type": "server",
        "runtime_family": "open62541",
    },
}


def _component_catalog_items() -> list[dict]:
    profiles = {str(p.get("profile_name")): p for p in list_component_profiles(SETTINGS)}
    out: list[dict] = []
    for item in COMPONENT_DISCOVERY_CATALOG.values():
        profile = profiles.get(str(item["profile_name"]), {})
        out.append(
            {
                **item,
                "certificate_format": profile.get("certificate_format"),
                "trust_store_layout": profile.get("trust_store_layout_json", {}),
                "runtime_semantics": profile.get("runtime_semantics_json", {}),
                "enrollment_policy": profile.get("enrollment_policy_json", {}),
                "status": profile.get("status", "unknown"),
            }
        )
    return out


def _active_certificate_fallback_for_app(application_id: int) -> dict | None:
    candidates = [
        cert
        for cert in list_certificates(SETTINGS)
        if int(cert.get("application_id") or 0) == int(application_id)
        and str(cert.get("status", "")).lower() == "active"
        and not cert.get("revoked_at")
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda c: (
            str(c.get("created_at") or c.get("not_before") or ""),
            int(c.get("id") or 0),
        ),
        reverse=True,
    )
    return candidates[0]


def resolve_component_active_certificate(app: dict) -> dict | None:
    """Resolve the active component certificate from activated package lineage first."""
    app_uri = str(app.get("application_uri") or "")
    activated_packages = [
        pkg for pkg in list_certificate_packages(
            SETTINGS,
            application_uri=app_uri,
            lifecycle_state="ACTIVATED",
            limit=100,
        )
        if str(pkg.get("status", "")).lower() == "active"
    ]
    activated_packages.sort(
        key=lambda p: (
            str(p.get("created_at") or ""),
            int(p.get("generation") or 0),
        ),
        reverse=True,
    )
    for package in activated_packages:
        cert_id = package.get("certificate_id")
        if not cert_id:
            continue
        cert = get_certificate(SETTINGS, int(cert_id))
        if cert and str(cert.get("status", "")).lower() == "active" and not cert.get("revoked_at"):
            return cert
    return _active_certificate_fallback_for_app(int(app.get("id") or 0))


def _safe_certificate(cert: dict | None) -> dict:
    if not cert:
        return {}
    return {
        "id": cert.get("id"),
        "application_id": cert.get("application_id"),
        "application_uri": cert.get("application_uri"),
        "common_name": cert.get("common_name"),
        "zone": cert.get("zone"),
        "role": cert.get("role"),
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "serial_number": cert.get("serial_number"),
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_before": _as_iso(cert.get("not_before")),
        "not_after": _as_iso(cert.get("not_after")),
        "status": cert.get("status"),
        "revoked_at": _as_iso(cert.get("revoked_at")),
    }


def _profile_for_application(app: dict) -> dict:
    app_uri = str(app.get("application_uri", ""))
    for item in COMPONENT_DISCOVERY_CATALOG.values():
        if str(item.get("application_uri")) == app_uri:
            return dict(item)
    component_type = str(app.get("component_type") or app.get("role") or "").lower()
    runtime_family = "node-opcua" if "fuxa" in app_uri.lower() else "open62541"
    profile_name = "node-opcua-client" if runtime_family == "node-opcua" else ("open62541-server" if component_type == "server" else "open62541-client")
    return {
        "target": app_uri,
        "application_uri": app_uri,
        "runtime_instance_id": app.get("runtime_instance_id") or app_uri,
        "profile_name": profile_name,
        "zone": app.get("zone"),
        "role": app.get("role"),
        "component_type": app.get("component_type") or component_type,
        "runtime_family": runtime_family,
    }


def _certificate_group_for_profile(profile_name: str, app: dict | None = None) -> dict:
    profile = get_component_profile(SETTINGS, profile_name) or {}
    profile_meta = dict(profile)
    for key in ("created_at", "updated_at"):
        if key in profile_meta:
            profile_meta[key] = _as_iso(profile_meta[key])
    app_meta = _profile_for_application(app) if app else {}
    return {
        "profile_name": profile_name,
        "runtime_family": profile_meta.get("runtime_family") or app_meta.get("runtime_family"),
        "component_type": profile_meta.get("component_type") or app_meta.get("component_type"),
        "certificate_format": profile_meta.get("certificate_format"),
        "zone": (app or {}).get("zone") or app_meta.get("zone"),
        "role": (app or {}).get("role") or app_meta.get("role"),
        "trust_store_layout": profile_meta.get("trust_store_layout_json", {}),
        "runtime_semantics": profile_meta.get("runtime_semantics_json", {}),
        "compatibility_rules": profile_meta.get("compatibility_rules_json", {}),
        "enrollment_policy": profile_meta.get("enrollment_policy_json", {}),
        "status": profile_meta.get("status", "unknown"),
    }


def _safe_package(row: dict | None) -> dict:
    if not row:
        return {}
    return {
        "package_id": row.get("package_id"),
        "certificate_id": row.get("certificate_id"),
        "generation": row.get("generation"),
        "profile_name": row.get("profile_name"),
        "supersedes_package_id": row.get("supersedes_package_id"),
        "supersedes_generation": row.get("supersedes_generation"),
        "compatibility_status": row.get("compatibility_status"),
        "lifecycle_state": row.get("lifecycle_state"),
        "status": row.get("status"),
        "created_at": _as_iso(row.get("created_at")),
    }


def _latest_package_for_app(app: dict, profile_name: str | None = None) -> dict | None:
    packages = list_certificate_packages(
        SETTINGS,
        application_uri=str(app.get("application_uri", "")),
        profile_name=profile_name,
        limit=50,
    )
    if not packages:
        return None
    return packages[0]


def _revocation_status_for_app(app: dict) -> dict:
    certs = [
        cert for cert in list_certificates(SETTINGS)
        if int(cert.get("application_id") or 0) == int(app.get("id") or 0)
    ]
    revoked = [cert for cert in certs if str(cert.get("status", "")).lower() == "revoked"]
    active_cert = resolve_component_active_certificate(app)
    revoked_packages: list[dict] = []
    for cert in revoked:
        revoked_packages.extend(list_certificate_packages_for_certificate(SETTINGS, int(cert["id"])))
    return {
        "schema": "labshock_gds_component_revocation_status_v1",
        "application_uri": app.get("application_uri"),
        "runtime_instance_id": app.get("runtime_instance_id") or app.get("application_uri"),
        "active_certificate": _safe_certificate(active_cert),
        "revoked_certificates": [_safe_certificate(cert) for cert in revoked],
        "revoked_certificate_count": len(revoked),
        "revoked_packages": [_safe_package(pkg) for pkg in revoked_packages],
        "revoked_package_count": len(revoked_packages),
        "crl_source": "vault_via_gds",
    }


def _trust_material_for_application(app: dict, request: Request) -> dict | JSONResponse:
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    if not TRUST_ARTIFACT_SIGNER:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized", "error_code": "signer_unavailable"})
    zone = str(app.get("zone", ""))
    role = str(app.get("role", ""))
    auth_err = _authorize_agent_pull(request, access="artifact_read", zone=zone, role=role, application_uri=str(app.get("application_uri") or ""))
    if auth_err:
        return auth_err
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False, source="component_distribution")
    if not trust_list or not artifact_row or not artifact:
        build_trust_list(SETTINGS, zone, role)
        trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=True, source="component_distribution")
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust material not found", "error_code": "trust_material_not_found"})
    profile_meta = _profile_for_application(app)
    profile_name = str(profile_meta.get("profile_name", ""))
    active_cert = resolve_component_active_certificate(app)
    package = _latest_package_for_app(app, profile_name)
    payload = {
        "schema": "labshock_gds_component_trust_material_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application_uri": app.get("application_uri"),
        "runtime_instance_id": app.get("runtime_instance_id") or app.get("application_uri"),
        "component": profile_meta,
        "certificate_group": _certificate_group_for_profile(profile_name, app),
        "active_certificate": _safe_certificate(active_cert),
        "latest_package": _safe_package(package),
        "trust_material": {
            "zone": zone,
            "role": role,
            "trustlist_version": artifact_row["trustlist_version"],
            "artifact_revision": artifact_row["artifact_revision"],
            "artifact_sha256": artifact_row["artifact_sha256"],
            "artifact": artifact,
            "artifact_signature": {
                "zone": zone,
                "role": role,
                "version": artifact_row["trustlist_version"],
                "artifact_revision": artifact_row["artifact_revision"],
                "artifact_sha256": artifact_row["artifact_sha256"],
                "signature_base64": artifact_row["signature_base64"],
                "generated_at": artifact_row["generated_at"],
                "expires_at": artifact_row["expires_at"],
                "signer": {
                    "key_id": artifact_row["signer_key_id"],
                    "algorithm": artifact.get("signer", {}).get("algorithm", "ed25519"),
                    "fingerprint_sha256": artifact_row["signer_fingerprint_sha256"],
                },
            },
            "ca_chain_pem": artifact.get("ca_chain_pem"),
            "crl_base64": artifact.get("crl_base64"),
            "crl_bundle": artifact.get("crl_bundle", {}),
            "crl_metadata": artifact.get("crl_metadata", {}),
            "certificates": artifact.get("certificates", []),
        },
        "private_key_included": False,
    }
    audit(
        SETTINGS,
        "component_trust_material_read",
        _agent_id_from_request(request),
        f"component:{app.get('application_uri')}",
        {
            "zone": zone,
            "role": role,
            "artifact_revision": artifact_row["artifact_revision"],
            "private_key_included": False,
        },
    )
    return payload


def _current_component_trust_version(app: dict, source: str = "component_trust_version") -> dict | JSONResponse:
    zone = str(app.get("zone", ""))
    role = str(app.get("role", ""))
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err

    artifact_row = get_latest_trust_artifact(SETTINGS, zone, role)
    if artifact_row:
        artifact = artifact_row.get("artifact_json") or {}
    else:
        if not VAULT_CLIENT:
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
        if not TRUST_ARTIFACT_SIGNER:
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized", "error_code": "signer_unavailable"})
        try:
            build_trust_list(SETTINGS, zone, role)
            _trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=True, source=source)
        except Exception as exc:
            LOG.warning("component trust-version unavailable zone=%s role=%s err=%s", zone, role, exc)
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"error": "trust version unavailable", "error_code": "trust_version_unavailable", "details": {"reason": str(exc)}},
            )
    if not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust version not found", "error_code": "trust_version_not_found"})
    crl_metadata = artifact.get("crl_metadata", {}) if isinstance(artifact, dict) else {}
    return {
        "application_uri": app.get("application_uri"),
        "zone": zone,
        "role": role,
        "trust_artifact_version": artifact_row["trustlist_version"],
        "trust_artifact_revision": artifact_row["artifact_revision"],
        "trust_artifact_sha256": artifact_row["artifact_sha256"],
        "generated_at": _as_iso(artifact_row.get("generated_at")),
        "expires_at": _as_iso(artifact_row.get("expires_at")),
        "crl_freshness_verified": bool(crl_metadata.get("crl_freshness_verified")),
        "crl_metadata": crl_metadata,
    }


def _component_lifecycle_payload(app: dict) -> dict | JSONResponse:
    try:
        active_cert = resolve_component_active_certificate(app)
        trust_version = _current_component_trust_version(app, source="component_lifecycle")
        if isinstance(trust_version, JSONResponse):
            return trust_version
        status_row = get_component_status(SETTINGS, str(app.get("application_uri") or ""))
        local_hash = str(status_row.get("trust_artifact_sha256") or "") if status_row else ""
        current_hash = str(trust_version.get("trust_artifact_sha256") or "")
        not_after = active_cert.get("not_after") if active_cert else None
        days_until_expiry = None
        if isinstance(not_after, datetime):
            days_until_expiry = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
        renewal_threshold_days = _renewal_threshold_days_for_app(app)
        renewal_required = bool(days_until_expiry is not None and days_until_expiry <= renewal_threshold_days)
        return _json_safe({
            "schema": "labshock_gds_component_lifecycle_v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "registered": True,
            "application_uri": app.get("application_uri"),
            "runtime_instance_id": app.get("runtime_instance_id") or app.get("application_uri"),
            "current_certificate_fingerprint_sha256": active_cert.get("fingerprint_sha256") if active_cert else None,
            "certificate_not_after": _as_iso(not_after),
            "days_until_expiry": days_until_expiry,
            "renewal_required": renewal_required,
            "renewal_threshold_days": renewal_threshold_days,
            "trust_artifact_version": trust_version.get("trust_artifact_version"),
            "trust_artifact_revision": trust_version.get("trust_artifact_revision"),
            "trust_artifact_sha256": current_hash,
            "trust_update_available": not bool(local_hash) or local_hash != current_hash,
            "component_reported_trust_artifact_sha256": local_hash or None,
            "crl_metadata": trust_version.get("crl_metadata", {}),
            "policy": {
                "auto_renewal_recommended": False,
                "component_owned_pki_required": True,
                "private_key_export_allowed": False,
                "shared_runtime_pki_writes_allowed": False,
            },
            "allowed_actions": ["status_report", "event_report", "pull_trust", "renew_certificate"],
            "latest_status": status_row,
        })
    except Exception as exc:
        LOG.exception("component lifecycle payload failed application_uri=%s", app.get("application_uri"))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "component lifecycle failed", "error_code": "component_lifecycle_failed", "details": {"reason": str(exc)}},
        )


def _component_enrollment_response(result: dict, request: Request) -> dict | JSONResponse:
    package = result["package"]
    certificate = result["certificate"]
    request_row = result["request"]
    manifest = result["manifest"]
    app_row = get_application_by_uri(SETTINGS, str(manifest.get("application_uri", "")))
    if not app_row:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"error": "issued application not found", "error_code": "application_lookup_failed"})
    trust_payload = _trust_material_for_application(app_row, request)
    if isinstance(trust_payload, JSONResponse):
        return trust_payload
    return {
        "schema": "labshock_gds_component_enrollment_result_v1",
        "request_id": request_row["request_id"],
        "application_uri": manifest.get("application_uri"),
        "runtime_instance_id": manifest.get("runtime_instance_id"),
        "profile_name": manifest.get("profile_name"),
        "package_id": package["package_id"],
        "generation": package["generation"],
        "certificate_id": certificate["id"],
        "certificate_fingerprint_sha256": certificate["fingerprint_sha256"],
        "compatibility_status": package["compatibility_status"],
        "lifecycle_state": package["lifecycle_state"],
        "manifest_sha256": package["manifest_sha256"],
        "certificate_pem": manifest.get("certificate_pem"),
        "ca_chain_pem": manifest.get("ca_chain_pem"),
        "crl_base64": manifest.get("crl_base64"),
        "install_plan": manifest.get("install_plan", {}),
        "manifest": manifest,
        "signature": package_signature_payload(package),
        "trust_distribution": trust_payload,
        "private_key_included": False,
    }


def _rebuild_affected_consumer_artifacts_for_component(application_uri: str, source: str) -> list[dict]:
    affected: list[tuple[str, str]] = []
    if application_uri in {
        "urn:dataprotect:opcua:dmz-gateway-client",
        "urn:dataprotect:opcua:fuxa-client",
    }:
        affected.append(("OT", "server"))
    rebuilt: list[dict] = []
    for zone, role in affected:
        trust_list, artifact_row, _artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=True, source=source)
        if artifact_row:
            rebuilt.append({
                "zone": zone,
                "role": role,
                "trustlist_version": artifact_row.get("trustlist_version"),
                "artifact_revision": artifact_row.get("artifact_revision"),
                "artifact_sha256": artifact_row.get("artifact_sha256"),
            })
    return rebuilt


@app.get("/api/v1/component-profiles")
def get_component_profiles():
    return list_component_profiles(SETTINGS)


@app.get("/api/v1/discovery")
def get_discovery(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    anchor = TRUST_ARTIFACT_SIGNER.trust_anchor_payload() if TRUST_ARTIFACT_SIGNER else {}
    return {
        "schema": "labshock_gds_discovery_v1",
        "service": SETTINGS.service_name,
        "version": SETTINGS.service_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vault_ca_authority": True,
        "private_key_export_allowed": False,
        "supported_api_versions": ["v1"],
        "supported_enrollment_modes": ["rest_component_csr", "rest_csr_legacy", "opcua_facade_dry_run", "opcua_facade_component_csr"],
        "supported_distribution_modes": ["component_trust_material", "signed_trust_artifact", "legacy_package_manifest"],
        "safety_gates": ["mtls", "agent_token", "signed_artifacts", "trust_anchor_pinning", "approvals", "maintenance_windows", "blackouts"],
        "trust_anchor": {
            "key_id": anchor.get("key_id"),
            "algorithm": anchor.get("algorithm"),
            "fingerprint_sha256": anchor.get("fingerprint_sha256"),
        },
        "endpoints": {
            "component_profiles": "/api/v1/discovery/component-profiles",
            "certificate_groups": "/api/v1/discovery/certificate-groups",
            "component_identity": "/api/v1/discovery/components/{application_uri}/identity",
            "renewal_policy": "/api/v1/discovery/components/{application_uri}/renewal-policy",
            "revocation_status": "/api/v1/discovery/components/{application_uri}/revocation-status",
            "trust_material": "/api/v1/distribution/components/{application_uri}/trust-material",
            "component_csr_enrollment": "/api/v1/enrollments/components/csr",
            "component_certificate_renewal": "/api/v1/certificates/renew",
        },
    }


@app.get("/api/v1/discovery/component-profiles")
def get_discovery_component_profiles(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    return {
        "schema": "labshock_gds_component_profiles_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "component_profiles": _component_catalog_items(),
    }


@app.get("/api/v1/discovery/certificate-groups")
def get_discovery_certificate_groups(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    groups = []
    for item in _component_catalog_items():
        groups.append(
            {
                "target": item.get("target"),
                "profile_name": item.get("profile_name"),
                "zone": item.get("zone"),
                "role": item.get("role"),
                "runtime_family": item.get("runtime_family"),
                "component_type": item.get("component_type"),
                "certificate_format": item.get("certificate_format"),
                "trust_store_layout": item.get("trust_store_layout", {}),
            }
        )
    return {
        "schema": "labshock_gds_certificate_groups_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "certificate_groups": groups,
    }


@app.get("/api/v1/discovery/components/{application_uri}/identity")
def get_component_identity(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="telemetry_read", application_uri=application_uri)
    if auth_err:
        return auth_err
    profile_meta = _profile_for_application(app_row)
    active_cert = resolve_component_active_certificate(app_row)
    package = _latest_package_for_app(app_row, str(profile_meta.get("profile_name", "")))
    return {
        "schema": "labshock_gds_component_identity_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": {
            "id": app_row.get("id"),
            "application_uri": app_row.get("application_uri"),
            "common_name": app_row.get("common_name"),
            "zone": app_row.get("zone"),
            "role": app_row.get("role"),
            "runtime_instance_id": app_row.get("runtime_instance_id") or app_row.get("application_uri"),
            "component_type": app_row.get("component_type"),
            "host": app_row.get("host"),
            "port": app_row.get("port"),
            "status": app_row.get("status"),
            "last_seen_at": _as_iso(app_row.get("last_seen_at")),
        },
        "component": profile_meta,
        "certificate_group": _certificate_group_for_profile(str(profile_meta.get("profile_name", "")), app_row),
        "active_certificate": _safe_certificate(active_cert),
        "latest_package": _safe_package(package),
        "private_key_included": False,
    }


@app.get("/api/v1/discovery/components/{application_uri}/renewal-policy")
def get_component_renewal_policy(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="telemetry_read", application_uri=application_uri)
    if auth_err:
        return auth_err
    profile_meta = _profile_for_application(app_row)
    profile_row = get_component_profile(SETTINGS, str(profile_meta.get("profile_name") or "")) or {}
    renewal_threshold_days = _renewal_threshold_days_for_profile({**profile_meta, **profile_row})
    active_cert = resolve_component_active_certificate(app_row)
    return {
        "schema": "labshock_gds_component_renewal_policy_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application_uri": application_uri,
        "runtime_instance_id": app_row.get("runtime_instance_id") or application_uri,
        "profile_name": profile_meta.get("profile_name"),
        "enrollment_allowed": True,
        "renewal_allowed": bool(active_cert),
        "default_ttl": SETTINGS.cert_default_ttl,
        "renewal_threshold_days": renewal_threshold_days,
        "active_certificate": _safe_certificate(active_cert),
        "private_key_included": False,
    }


@app.get("/api/v1/discovery/components/{application_uri}/revocation-status")
def get_component_revocation_status(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="telemetry_read", application_uri=application_uri)
    if auth_err:
        return auth_err
    return _revocation_status_for_app(app_row)


@app.get("/api/v1/components/status")
def get_all_component_lifecycle_status(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    rows = list_component_statuses(SETTINGS, limit=200)
    return {
        "schema": "labshock_gds_component_status_list_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "components": _json_safe(rows),
    }


@app.get("/api/v1/components/events")
def get_component_lifecycle_events(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    application_uri = request.query_params.get("application_uri")
    if application_uri:
        app_row = get_application_by_uri(SETTINGS, application_uri)
        if not app_row:
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
        auth_err = _authorize_agent_pull(request, access="lifecycle_read", application_uri=application_uri)
    else:
        auth_err = _authorize_agent_pull(request, access="telemetry_read")
    if auth_err:
        return auth_err
    try:
        limit = int(request.query_params.get("limit", "200"))
    except ValueError:
        limit = 200
    rows = list_component_events(SETTINGS, application_uri=application_uri, limit=max(1, min(limit, 500)))
    return {
        "schema": "labshock_gds_component_event_list_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application_uri": application_uri,
        "events": _json_safe(rows),
    }


@app.post("/api/v1/components/{application_uri}/status")
def post_component_lifecycle_status(application_uri: str, body: ComponentStatusBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    if body.application_uri != application_uri:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "application_uri mismatch", "error_code": "application_uri_mismatch"})
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="lifecycle_write", application_uri=application_uri)
    if auth_err:
        return auth_err
    payload = body.dict()
    if payload.get("timestamp") is None:
        payload["timestamp"] = datetime.now(timezone.utc)
    row = upsert_component_status(SETTINGS, payload)
    if body.private_key_exported or body.private_key_touched:
        audit(
            SETTINGS,
            "component_private_key_flag_reported",
            _agent_id_from_request(request),
            f"component:{application_uri}",
            {"private_key_exported": body.private_key_exported, "private_key_touched": body.private_key_touched},
        )
    audit(
        SETTINGS,
        "component_lifecycle_status_reported",
        _agent_id_from_request(request),
        f"component:{application_uri}",
        {
            "target": body.target,
            "trust_artifact_sha256": body.trust_artifact_sha256,
            "crl_freshness_verified": body.crl_freshness_verified,
            "runtime_write_enabled": body.runtime_write_enabled,
        },
    )
    return {"schema": "labshock_gds_component_status_ack_v1", "application_uri": application_uri, "stored": True, "status": _json_safe(row)}


@app.get("/api/v1/components/{application_uri}/lifecycle")
def get_component_lifecycle(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"registered": False, "error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="lifecycle_read", application_uri=application_uri)
    if auth_err:
        return auth_err
    payload = _component_lifecycle_payload(app_row)
    if isinstance(payload, JSONResponse):
        return payload
    audit(
        SETTINGS,
        "component_lifecycle_read",
        _agent_id_from_request(request),
        f"component:{application_uri}",
        {"trust_artifact_sha256": payload.get("trust_artifact_sha256"), "renewal_required": payload.get("renewal_required")},
    )
    return payload


@app.get("/api/v1/components/{application_uri}/trust-version")
def get_component_trust_version(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="lifecycle_read", application_uri=application_uri)
    if auth_err:
        return auth_err
    payload = _current_component_trust_version(app_row)
    if isinstance(payload, JSONResponse):
        return payload
    payload["schema"] = "labshock_gds_component_trust_version_v1"
    return payload


@app.post("/api/v1/components/{application_uri}/events")
def post_component_lifecycle_event(application_uri: str, body: ComponentEventBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    if body.application_uri != application_uri:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "application_uri mismatch", "error_code": "application_uri_mismatch"})
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    auth_err = _authorize_agent_pull(request, access="lifecycle_write", application_uri=application_uri)
    if auth_err:
        return auth_err
    allowed_events = {
        "lifecycle_check_started", "lifecycle_check_completed", "trust_version_changed",
        "trust_pull_started", "trust_pull_completed", "trust_apply_started",
        "trust_apply_completed", "trust_apply_failed", "renewal_threshold_reached",
        "renewal_csr_generated", "renewal_package_received", "renewal_apply_started",
        "renewal_apply_completed", "renewal_apply_failed", "reconnect_required",
        "reconnect_completed",
    }
    if body.event_type not in allowed_events:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "unsupported lifecycle event", "error_code": "unsupported_lifecycle_event"})
    row = insert_component_event(SETTINGS, body.dict())
    audit(
        SETTINGS,
        "component_lifecycle_event",
        _agent_id_from_request(request),
        f"component:{application_uri}",
        {"event_type": body.event_type, "target": body.target, "status": body.status},
    )
    return {"schema": "labshock_gds_component_event_ack_v1", "application_uri": application_uri, "stored": True, "event": _json_safe(row)}


@app.get("/api/v1/distribution/components/{application_uri}/trust-material")
def get_component_trust_material(application_uri: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    app_row = get_application_by_uri(SETTINGS, application_uri)
    if not app_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found", "error_code": "unknown_application"})
    return _trust_material_for_application(app_row, request)


@app.post("/api/v1/enrollments/rest/csr")
def post_rest_csr_enrollment(body: EnrollCsrBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="enrollment_submit", application_uri=body.application_uri)
    if auth_err:
        return auth_err
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    if not TRUST_ARTIFACT_SIGNER:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized", "error_code": "signer_unavailable"})
    sealed_err = _require_vault_unsealed()
    if sealed_err:
        return sealed_err
    try:
        result = issue_certificate_package(
            settings=SETTINGS,
            vault_client=VAULT_CLIENT,
            signer=TRUST_ARTIFACT_SIGNER,
            application_uri=body.application_uri,
            runtime_instance_id=body.runtime_instance_id or "",
            profile_name=body.profile_name,
            csr_pem=body.csr_pem,
            requested_ttl=body.requested_ttl,
            requested_by=_agent_id_from_request(request),
            source_interface="rest",
        )
    except LifecycleError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": str(exc), "error_code": exc.code, "details": exc.details},
        )
    except Exception as exc:
        LOG.error("certificate enrollment failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "certificate enrollment failed", "error_code": "enrollment_failed"},
        )
    package = result["package"]
    certificate = result["certificate"]
    return {
        "request_id": result["request"]["request_id"],
        "package_id": package["package_id"],
        "generation": package["generation"],
        "certificate_id": certificate["id"],
        "certificate_fingerprint_sha256": certificate["fingerprint_sha256"],
        "compatibility_status": package["compatibility_status"],
        "lifecycle_state": package["lifecycle_state"],
        "manifest_sha256": package["manifest_sha256"],
    }


@app.post("/api/v1/enrollments/components/csr")
def post_component_csr_enrollment(body: EnrollCsrBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="enrollment_submit", application_uri=body.application_uri)
    if auth_err:
        return auth_err
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    if not TRUST_ARTIFACT_SIGNER:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized", "error_code": "signer_unavailable"})
    sealed_err = _require_vault_unsealed()
    if sealed_err:
        return sealed_err
    try:
        result = issue_certificate_package(
            settings=SETTINGS,
            vault_client=VAULT_CLIENT,
            signer=TRUST_ARTIFACT_SIGNER,
            application_uri=body.application_uri,
            runtime_instance_id=body.runtime_instance_id or "",
            profile_name=body.profile_name,
            csr_pem=body.csr_pem,
            requested_ttl=body.requested_ttl,
            requested_by=_agent_id_from_request(request),
            source_interface="component_rest",
        )
        response = _component_enrollment_response(result, request)
        if isinstance(response, JSONResponse):
            return response
        response["affected_trust_artifacts_rebuilt"] = _rebuild_affected_consumer_artifacts_for_component(
            body.application_uri,
            source="component_enrollment",
        )
        audit(
            SETTINGS,
            "component_enrollment_completed",
            _agent_id_from_request(request),
            f"component:{body.application_uri}",
            {
                "request_id": response.get("request_id"),
                "package_id": response.get("package_id"),
                "certificate_id": response.get("certificate_id"),
                "private_key_included": False,
            },
        )
        return response
    except LifecycleError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": str(exc), "error_code": exc.code, "details": exc.details},
        )
    except Exception as exc:
        LOG.error("component certificate enrollment failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "component certificate enrollment failed", "error_code": "component_enrollment_failed"},
        )


@app.get("/api/v1/enrollments/requests/{request_id}")
def get_enrollment_request(request_id: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    row = get_certificate_request(SETTINGS, request_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "certificate request not found"})
    out = dict(row)
    out.pop("csr_pem", None)
    return out


@app.get("/api/v1/packages")
def list_certificate_packages_endpoint(
    request: Request,
    application_uri: str | None = None,
    runtime_instance_id: str | None = None,
    profile_name: str | None = None,
    lifecycle_state: str | None = None,
    limit: int = 100,
):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    limit = max(1, min(int(limit), 500))
    return list_certificate_packages(
        SETTINGS,
        application_uri=application_uri,
        runtime_instance_id=runtime_instance_id,
        profile_name=profile_name,
        lifecycle_state=lifecycle_state.upper() if lifecycle_state else None,
        limit=limit,
    )


@app.get("/api/v1/packages/telemetry")
def get_package_lifecycle_telemetry(request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    payload = package_lifecycle_telemetry(SETTINGS)
    audit(SETTINGS, "package_lifecycle_telemetry_read", _agent_id_from_request(request), "certificate_packages", {})
    return payload


@app.get("/api/v1/packages/{package_id}")
def get_certificate_package_endpoint(package_id: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    row = get_certificate_package(SETTINGS, package_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    manifest = _manifest_from_package_row(row)
    audit(SETTINGS, "certificate_package_read", _agent_id_from_request(request), f"certificate_package:{package_id}", {"generation": row["generation"]})
    return {
        "package_id": row["package_id"],
        "generation": row["generation"],
        "application_uri": row["application_uri"],
        "runtime_instance_id": row["runtime_instance_id"],
        "profile_name": row["profile_name"],
        "compatibility_status": row["compatibility_status"],
        "lifecycle_state": row["lifecycle_state"],
        "manifest_sha256": row["manifest_sha256"],
        "signature": package_signature_payload(row),
        "manifest": manifest,
    }


@app.get("/api/v1/packages/{package_id}/history")
def get_certificate_package_history(package_id: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    row = get_certificate_package(SETTINGS, package_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    lineage = list_certificate_packages_for_lineage(SETTINGS, int(row["application_id"]), str(row["profile_name"]))
    events = list_package_events(SETTINGS, package_id, limit=200)
    audit(SETTINGS, "package_history_read", _agent_id_from_request(request), f"certificate_package:{package_id}", {"generation": row["generation"]})
    return {
        "package_id": package_id,
        "application_uri": row.get("application_uri"),
        "runtime_instance_id": row.get("runtime_instance_id"),
        "profile_name": row.get("profile_name"),
        "generation": row.get("generation"),
        "supersedes_package_id": row.get("supersedes_package_id"),
        "supersedes_generation": row.get("supersedes_generation"),
        "lineage": lineage,
        "events": events,
    }


@app.get("/api/v1/packages/{package_id}/events")
def get_certificate_package_events(package_id: str, request: Request, limit: int = 100):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    if not get_certificate_package(SETTINGS, package_id):
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    return list_package_events(SETTINGS, package_id, limit=max(1, min(int(limit), 500)))


@app.post("/api/v1/packages/{package_id}/events")
def post_certificate_package_event(package_id: str, body: PackageLifecycleEventBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_update")
    if auth_err:
        return auth_err
    package_row = get_certificate_package(SETTINGS, package_id)
    if not package_row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    default_event_type = f"package_{body.lifecycle_state.lower()}"
    event_type = body.event_type or default_event_type
    details = dict(body.details or {})
    details["event_type"] = event_type
    details["source_interface"] = "ot_agent_pull"
    actor = _agent_id_from_request(request)
    if event_type != default_event_type:
        details["lifecycle_state"] = package_row["lifecycle_state"]
        details["requested_lifecycle_state"] = body.lifecycle_state
        insert_package_event(SETTINGS, package_id, event_type, actor, details)
        audit(
            SETTINGS,
            event_type,
            actor,
            f"certificate_package:{package_id}",
            {"lifecycle_state": package_row["lifecycle_state"], **details},
        )
        return {
            "package_id": package_id,
            "lifecycle_state": package_row["lifecycle_state"],
            "event_recorded": True,
        }
    try:
        row = update_certificate_package_lifecycle(SETTINGS, package_id, body.lifecycle_state, actor, details)
    except ValueError as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": str(exc), "error_code": "invalid_lifecycle_state"})
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    audit(
        SETTINGS,
        details["event_type"],
        actor,
        f"certificate_package:{package_id}",
        {"lifecycle_state": row["lifecycle_state"], **details},
    )
    return {
        "package_id": package_id,
        "lifecycle_state": row["lifecycle_state"],
        "event_recorded": True,
    }


@app.get("/api/v1/packages/{package_id}/manifest")
def get_certificate_package_manifest(package_id: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    row = get_certificate_package(SETTINGS, package_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    audit(SETTINGS, "package_manifest_read", _agent_id_from_request(request), f"certificate_package:{package_id}", {"generation": row["generation"], "manifest_sha256": row["manifest_sha256"]})
    return _manifest_from_package_row(row)


@app.get("/api/v1/packages/{package_id}/manifest.sig")
def get_certificate_package_manifest_signature(package_id: str, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_read")
    if auth_err:
        return auth_err
    row = get_certificate_package(SETTINGS, package_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "package not found"})
    audit(SETTINGS, "package_manifest_sig_read", _agent_id_from_request(request), f"certificate_package:{package_id}", {"generation": row["generation"]})
    return package_signature_payload(row)


@app.get("/api/v1/trustlists/{zone}/{role}/artifact")
def get_trustlist_artifact(zone: str, role: str, request: Request, response: Response):
    auth_err = _authorize_agent_pull(request, access="artifact_read", zone=zone, role=role)
    if auth_err:
        return auth_err
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    try:
        trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False)
    except VaultSealedError:
        artifact_row = get_latest_trust_artifact(SETTINGS, zone, role)
        if artifact_row and _ttl_remaining_seconds(artifact_row) > 0:
            artifact = _artifact_from_row(artifact_row)
            response.headers["X-GDS-Cache"] = "true"
            response.headers["X-GDS-Cache-Reason"] = "vault_sealed"
            audit(
                SETTINGS,
                "trustlist_artifact_cached_read",
                "system",
                f"trustlist_artifact:{zone}:{role}",
                {"artifact_revision": artifact_row["artifact_revision"], "cache_reason": "vault_sealed"},
            )
            return _json_safe(artifact)
        return _vault_sealed_response()
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})
    audit(
        SETTINGS,
        "trustlist_artifact_read",
        "system",
        f"trustlist_artifact:{zone}:{role}",
        {
            "version": trust_list["version"],
            "artifact_revision": artifact_row["artifact_revision"],
            "key_id": artifact_row["signer_key_id"],
        },
    )
    return artifact


@app.get("/api/v1/trustlists/{zone}/{role}/artifact/status")
def get_trustlist_artifact_status(zone: str, role: str, request: Request):
    auth_err = _authorize_agent_pull(request, access="artifact_read", zone=zone, role=role)
    if auth_err:
        return auth_err
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False)
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})
    return {
        "zone": zone,
        "role": role,
        "version": artifact_row["trustlist_version"],
        "artifact_revision": artifact_row["artifact_revision"],
        "artifact_sha256": artifact_row["artifact_sha256"],
        "generated_at": artifact_row["generated_at"],
        "expires_at": artifact_row["expires_at"],
        "ttl_remaining_seconds": _ttl_remaining_seconds(artifact_row),
    }


@app.get("/api/v1/trustlists/{zone}/{role}/artifact.sig")
def get_trustlist_artifact_signature(zone: str, role: str, request: Request):
    auth_err = _authorize_agent_pull(request, access="artifact_read", zone=zone, role=role)
    if auth_err:
        return auth_err
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False)
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})
    audit(
        SETTINGS,
        "trustlist_artifact_sig_read",
        "system",
        f"trustlist_artifact_sig:{zone}:{role}",
        {
            "version": trust_list["version"],
            "artifact_revision": artifact_row["artifact_revision"],
            "key_id": artifact_row["signer_key_id"],
        },
    )
    return {
        "zone": zone,
        "role": role,
        "version": artifact_row["trustlist_version"],
        "artifact_revision": artifact_row["artifact_revision"],
        "artifact_sha256": artifact_row["artifact_sha256"],
        "signature_base64": artifact_row["signature_base64"],
        "generated_at": artifact_row["generated_at"],
        "expires_at": artifact_row["expires_at"],
        "signer": {
            "key_id": artifact_row["signer_key_id"],
            "algorithm": artifact.get("signer", {}).get("algorithm", "ed25519"),
            "fingerprint_sha256": artifact_row["signer_fingerprint_sha256"],
        },
    }


@app.get("/api/v1/trustlists/{zone}/{role}/artifact/canonical")
def get_trustlist_artifact_canonical(zone: str, role: str, request: Request):
    auth_err = _authorize_agent_pull(request, access="artifact_read", zone=zone, role=role)
    if auth_err:
        return auth_err
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False)
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})
    canonical_payload = canonical_artifact_payload(artifact)
    canonical_bytes = canonical_json_bytes(canonical_payload)
    canonical_sha256 = sha256_hex(canonical_bytes)
    payload_text = canonical_bytes.decode("utf-8")
    audit(
        SETTINGS,
        "trustlist_artifact_canonical_read",
        "system",
        f"trustlist_artifact_canonical:{zone}:{role}",
        {
            "version": trust_list["version"],
            "artifact_revision": artifact_row["artifact_revision"],
            "canonical_sha256": canonical_sha256,
        },
    )
    return {
        "zone": zone,
        "role": role,
        "version": artifact_row["trustlist_version"],
        "artifact_revision": artifact_row["artifact_revision"],
        "canonical_sha256": canonical_sha256,
        "canonical_payload": payload_text,
        "diagnostic_metadata": {
            "generated_at": artifact_row["generated_at"],
            "expires_at": artifact_row["expires_at"],
            "ttl_remaining_seconds": _ttl_remaining_seconds(artifact_row),
        },
    }


@app.post("/api/v1/trustlists/{zone}/{role}/artifact/rebuild")
def post_trustlist_artifact_rebuild(zone: str, role: str, request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target=f"admin:artifact_rebuild:{zone}:{role}")
    if deny:
        return deny
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    trust_list, artifact_row, artifact = _get_or_regenerate_signed_artifact(zone, role, force_rebuild=True)
    if not trust_list or not artifact_row or not artifact:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "trust list not found"})

    audit(
        SETTINGS,
        "trustlist_artifact_rebuild",
        "system",
        f"trustlist_artifact:{zone}:{role}",
        {
            "version": trust_list["version"],
            "artifact_revision": artifact_row["artifact_revision"],
            "reason": artifact_row["reason"],
        },
    )
    return {
        "zone": zone,
        "role": role,
        "version": artifact_row["trustlist_version"],
        "artifact_revision": artifact_row["artifact_revision"],
        "generated_at": artifact_row["generated_at"],
        "expires_at": artifact_row["expires_at"],
        "artifact_sha256": artifact_row["artifact_sha256"],
        "reason": artifact_row["reason"],
        "signer": {
            "key_id": artifact_row["signer_key_id"],
            "fingerprint_sha256": artifact_row["signer_fingerprint_sha256"],
            "algorithm": artifact.get("signer", {}).get("algorithm", "ed25519"),
        },
    }


@app.get("/api/v1/trustlists/{zone}/{role}/artifact/history")
def get_trustlist_artifact_history(zone: str, role: str):
    ok, err = _validate_trust_artifact_request(zone, role)
    if not ok:
        return err
    rows = list_trust_artifact_history(SETTINGS, zone, role, limit=200)
    out = []
    now = datetime.now(timezone.utc)
    for row in rows:
        expires_at = _as_utc_dt(row.get("expires_at"))
        ttl_remaining = max(0, int((expires_at - now).total_seconds())) if expires_at else 0
        out.append(
            {
                "zone": row["zone"],
                "role": row["role"],
                "version": row["trustlist_version"],
                "artifact_revision": row["artifact_revision"],
                "artifact_sha256": row["artifact_sha256"],
                "generated_at": row["generated_at"],
                "expires_at": row["expires_at"],
                "ttl_remaining_seconds": ttl_remaining,
                "reason": row["reason"],
                "signer": {
                    "key_id": row["signer_key_id"],
                    "fingerprint_sha256": row["signer_fingerprint_sha256"],
                },
            }
        )
    return out


def _validate_trust_artifact_request(zone: str, role: str) -> tuple[bool, JSONResponse | None]:
    if zone not in ALLOWED_ZONES:
        return False, JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid zone"})
    if role not in ALLOWED_ROLES:
        return False, JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid role"})
    if not VAULT_CLIENT:
        return False, JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized"})
    if not TRUST_ARTIFACT_SIGNER:
        return False, JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized"})
    return True, None


def _as_utc_dt(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _artifact_from_row(row: dict) -> dict:
    raw = row.get("artifact_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(raw)
    return {}


def _manifest_from_package_row(row: dict) -> dict:
    raw = row.get("manifest_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(raw)
    return {}


def _ttl_remaining_seconds(row: dict) -> int:
    expires = _as_utc_dt(row.get("expires_at"))
    if not expires:
        return 0
    now = datetime.now(timezone.utc)
    return max(0, int((expires - now).total_seconds()))


def _regeneration_reason(trust_list: dict, current_row: dict | None, force_rebuild: bool, source: str) -> str | None:
    if force_rebuild:
        return "force_rebuild"
    if not current_row:
        return "cache_miss"

    current_version = int(current_row.get("trustlist_version"))
    if current_version != int(trust_list["version"]):
        return "version_changed"

    if current_row.get("signer_key_id") != TRUST_ARTIFACT_SIGNER.key_id:
        return "signer_changed"
    if str(current_row.get("signer_fingerprint_sha256", "")).lower() != TRUST_ARTIFACT_SIGNER.fingerprint_sha256.lower():
        return "signer_changed"

    ttl_remaining = _ttl_remaining_seconds(current_row)
    threshold_seconds = int(SETTINGS.trust_artifact_ttl_seconds * (SETTINGS.trust_artifact_regen_threshold_percent / 100.0))
    if ttl_remaining < threshold_seconds:
        if source == "scheduler":
            return "ttl_refresh"
        return "ttl_threshold"
    return None


def _get_or_regenerate_signed_artifact(zone: str, role: str, force_rebuild: bool, source: str = "api"):
    if not VAULT_CLIENT or not TRUST_ARTIFACT_SIGNER:
        return None, None, None

    ensure_trust_list_current(SETTINGS, zone, role)
    trust_list, certs = get_latest_trust_list_with_certs(SETTINGS, zone, role)
    if not trust_list:
        return None, None, None

    cache_key = f"{zone}:{role}"
    cache_entry = SIGNED_ARTIFACT_CACHE.get(cache_key)
    with ARTIFACT_REGEN_LOCK:
        artifact_row = get_latest_trust_artifact(SETTINGS, zone, role)
        reason = _regeneration_reason(trust_list, artifact_row, force_rebuild, source)
    artifact: dict | None = None

    if reason:
        with ARTIFACT_REGEN_LOCK:
            artifact_row = get_latest_trust_artifact(SETTINGS, zone, role)
            reason = _regeneration_reason(trust_list, artifact_row, force_rebuild, source)
            if reason:
                now_ts = time.time()
                last_regen = ARTIFACT_REGEN_LAST_AT.get(cache_key, 0.0)
                min_interval = SETTINGS.trust_artifact_regen_min_interval_seconds
                if not force_rebuild and (now_ts - last_regen) < float(min_interval):
                    reason = None
                    artifact_row = get_latest_trust_artifact(SETTINGS, zone, role)
                if reason:
                    previous_revision = int(artifact_row["artifact_revision"]) if artifact_row else 0
                    next_revision = previous_revision + 1
                    ca_chain = VAULT_CLIENT.get_ca_chain()
                    crl_bundle = VAULT_CLIENT.get_crl_bundle()
                    crl = crl_bundle["intermediate"]
                    signed = TRUST_ARTIFACT_SIGNER.build_signed_artifact(
                        trust_list=trust_list,
                        certs=certs,
                        ca_chain_pem=ca_chain["ca_chain_pem"],
                        crl_base64=crl["crl_base64"],
                        artifact_revision=next_revision,
                        reason=reason,
                        crl_bundle={
                            "root_crl_base64": crl_bundle["root"]["crl_base64"],
                            "intermediate_crl_base64": crl_bundle["intermediate"]["crl_base64"],
                        },
                        crl_metadata={
                            "root_crl_source": crl_bundle.get("root_crl_source"),
                            "root_pki_mount": crl_bundle.get("root_pki_mount"),
                            "root_issuer_id": crl_bundle.get("root_issuer_id"),
                            "root_crl_issuer": crl_bundle.get("root_crl_issuer"),
                            "root_crl_next_update": crl_bundle.get("root_crl_next_update"),
                            "root_crl_sha256": crl_bundle.get("root_crl_sha256"),
                            "intermediate_pki_mount": crl_bundle.get("intermediate_pki_mount"),
                            "intermediate_crl_issuer": crl_bundle.get("intermediate_crl_issuer"),
                            "intermediate_crl_next_update": crl_bundle.get("intermediate_crl_next_update"),
                            "intermediate_crl_sha256": crl_bundle.get("intermediate_crl_sha256"),
                            "crl_freshness_verified": crl_bundle.get("crl_freshness_verified"),
                        },
                    )
                    artifact_row = insert_trust_artifact(
                        settings=SETTINGS,
                        zone=zone,
                        role=role,
                        trustlist_version=int(trust_list["version"]),
                        artifact_json=signed.artifact,
                        artifact_sha256=signed.artifact_sha256,
                        signature_base64=signed.signature_base64,
                        signer_key_id=signed.signer_key_id,
                        signer_fingerprint_sha256=signed.signer_fingerprint_sha256,
                        generated_at=signed.generated_at,
                        expires_at=signed.expires_at,
                        reason=reason,
                    )
                    ARTIFACT_REGEN_LAST_AT[cache_key] = now_ts
                    if SETTINGS.sign_debug:
                        LOG.info(
                            "sign_debug zone=%s role=%s canonical_sha256=%s signed_payload_length=%s",
                            zone,
                            role,
                            signed.artifact_sha256,
                            len(signed.artifact_bytes),
                        )
                    audit(
                        SETTINGS,
                        "artifact_regenerated",
                        "system",
                        f"trustlist_artifact:{zone}:{role}",
                        {
                            "version": int(trust_list["version"]),
                            "artifact_revision": int(artifact_row["artifact_revision"]),
                            "reason": reason,
                            "source": source,
                        },
                    )
                    artifact = signed.artifact
                    LOG.info(
                        "artifact regenerated zone=%s role=%s version=%s revision=%s reason=%s",
                        zone,
                        role,
                        trust_list["version"],
                        artifact_row["artifact_revision"],
                        reason,
                    )

    if artifact is None and artifact_row and isinstance(cache_entry, dict):
        if cache_entry.get("row_id") == artifact_row["id"] and isinstance(cache_entry.get("artifact"), dict):
            artifact = cache_entry["artifact"]
    if artifact is None:
        artifact = _artifact_from_row(artifact_row)

    SIGNED_ARTIFACT_CACHE[cache_key] = {
        "row_id": artifact_row["id"],
        "artifact_revision": artifact_row["artifact_revision"],
        "artifact": artifact,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }
    return trust_list, artifact_row, artifact


@app.post("/api/v1/trustlists/build")
def post_build_trustlist(body: TrustListBuildBody, request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target=f"admin:trustlists_build:{body.zone}:{body.role}")
    if deny:
        return deny
    if body.role not in ALLOWED_ROLES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid role"})
    tl = build_trust_list(SETTINGS, body.zone, body.role)
    audit(
        SETTINGS,
        "trustlist_build",
        "system",
        f"trustlist:{body.zone}:{body.role}",
        {"version": tl["version"]},
    )
    # Keep artifact publication lifecycle aligned with trustlist publication.
    _get_or_regenerate_signed_artifact(body.zone, body.role, force_rebuild=False, source="trustlist_build")
    return {
        "zone": tl["zone"],
        "role": tl["role"],
        "version": tl["version"],
        "status": tl["status"],
        "created_at": tl["created_at"],
        "published_at": tl["published_at"],
    }


def _artifact_scan_loop() -> None:
    LOG.info(
        "artifact scan loop started interval_seconds=%s regen_min_interval_seconds=%s",
        SETTINGS.trust_artifact_scan_interval_seconds,
        SETTINGS.trust_artifact_regen_min_interval_seconds,
    )
    while not ARTIFACT_SCAN_STOP.is_set():
        try:
            targets = list_trustlist_targets(SETTINGS)
            for row in targets:
                zone = row.get("zone")
                role = row.get("role")
                if not zone or not role:
                    continue
                _get_or_regenerate_signed_artifact(zone, role, force_rebuild=False, source="scheduler")
        except Exception as exc:
            LOG.warning("artifact scan loop iteration failed: %s", exc)
        ARTIFACT_SCAN_STOP.wait(max(1, SETTINGS.trust_artifact_scan_interval_seconds))
    LOG.info("artifact scan loop stopped")


@app.post("/api/v1/applications/register")
def register_application(body: RegisterApplicationBody, request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target="admin:applications_register")
    if deny:
        return deny
    if body.role not in ALLOWED_ROLES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid role"})
    row = upsert_application(
        settings=SETTINGS,
        application_uri=body.application_uri,
        common_name=body.common_name,
        zone=body.zone,
        role=body.role,
        host=body.host,
        port=body.port,
        status=body.status,
        runtime_instance_id=body.runtime_instance_id,
        component_type=body.component_type,
    )
    audit(SETTINGS, "application_register", "system", f"application:{row['id']}", {"application_uri": body.application_uri})
    return row


@app.get("/api/v1/applications")
def get_applications():
    return list_applications(SETTINGS)


@app.get("/api/v1/applications/{app_id}")
def get_application_by_id(app_id: int):
    row = get_application(SETTINGS, app_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found"})
    return row


@app.post("/api/v1/applications/{app_id}/heartbeat")
def post_application_heartbeat(app_id: int, request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target=f"admin:applications_heartbeat:{app_id}")
    if deny:
        return deny
    row = heartbeat_application(SETTINGS, app_id)
    if not row:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found"})
    audit(SETTINGS, "application_heartbeat", "system", f"application:{app_id}", {})
    return row


@app.get("/api/v1/audit/events")
def get_audit_events(request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target="admin:audit_events")
    if deny:
        return deny
    return list_audit_events(SETTINGS, limit=200)


@app.post("/api/v1/certificates/import")
def import_certificate(body: ImportCertificateBody, request: Request):
    deny = _deny_agent_on_admin_endpoint(request, target="admin:certificates_import")
    if deny:
        return deny
    if body.role not in ALLOWED_ROLES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid role"})

    app = get_application_by_uri(SETTINGS, body.application_uri)
    if not app:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "application not found"})
    if app["zone"] != body.zone or app["role"] != body.role:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "application zone/role mismatch"},
        )

    try:
        parsed = parse_pem_certificate(body.pem)
    except Exception as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"invalid pem: {exc}"})

    existing = get_certificate_by_fingerprint(SETTINGS, parsed["fingerprint_sha256"])
    if existing:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": "certificate already exists",
                "fingerprint_sha256": parsed["fingerprint_sha256"],
                "certificate_id": existing["id"],
            },
        )

    row = insert_certificate(
        settings=SETTINGS,
        application_id=app["id"],
        fingerprint_sha256=parsed["fingerprint_sha256"],
        serial_number=parsed["serial_number"],
        subject=parsed["subject"],
        issuer=parsed["issuer"],
        not_before=parsed["not_before"],
        not_after=parsed["not_after"],
        pem=parsed["pem"],
        status="active",
    )
    if not row:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"error": "certificate already exists"})

    audit(
        SETTINGS,
        "certificate_import",
        "system",
        f"certificate:{row['id']}",
        {
            "application_uri": body.application_uri,
            "fingerprint_sha256": parsed["fingerprint_sha256"],
        },
    )
    return row


@app.get("/api/v1/certificates")
def get_certificates():
    return list_certificates(SETTINGS)


def _crl_sha256_from_vault_payload(payload: dict) -> str:
    crl_b64 = str(payload.get("crl_base64", ""))
    if not crl_b64:
        return ""
    return hashlib.sha256(base64.b64decode(crl_b64)).hexdigest()


def _resolve_revoke_certificate(body: RevokeCertificateBody) -> tuple[dict | None, dict | None]:
    selectors = [
        bool(body.certificate_id),
        bool(body.package_id),
        bool(body.fingerprint_sha256),
    ]
    if sum(1 for selected in selectors if selected) != 1:
        raise ValueError("exactly_one_certificate_selector_required")
    if body.package_id:
        package = get_certificate_package(SETTINGS, str(body.package_id))
        if not package:
            return None, None
        cert_id = package.get("certificate_id")
        if not cert_id:
            return None, package
        return get_certificate(SETTINGS, int(cert_id)), package
    if body.certificate_id:
        return get_certificate(SETTINGS, int(body.certificate_id)), None
    return get_certificate_by_fingerprint(SETTINGS, str(body.fingerprint_sha256).strip().lower()), None


@app.post("/api/v1/certificates/revoke")
def revoke_certificate(body: RevokeCertificateBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="package_update")
    if auth_err:
        return auth_err
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    sealed_err = _require_vault_unsealed()
    if sealed_err:
        return sealed_err

    actor = body.operator or _agent_id_from_request(request)
    correlation_id = _correlation_id(request)
    try:
        cert, selected_package = _resolve_revoke_certificate(body)
    except ValueError as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": str(exc), "error_code": str(exc)})
    if not cert:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "certificate not found", "error_code": "certificate_not_found"})

    cert_id = int(cert["id"])
    serial_number = str(cert.get("serial_number") or "").strip()
    if not serial_number:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "certificate serial missing", "error_code": "certificate_serial_missing"})

    packages = list_certificate_packages_for_certificate(SETTINGS, cert_id)
    package_ids = [str(pkg["package_id"]) for pkg in packages]
    if selected_package and str(selected_package["package_id"]) not in package_ids:
        package_ids.insert(0, str(selected_package["package_id"]))

    audit(
        SETTINGS,
        "certificate_revocation_requested",
        actor,
        f"certificate:{cert_id}",
        {
            "certificate_id": cert_id,
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
            "package_ids": package_ids,
            "reason": body.reason,
            "correlation_id": correlation_id,
        },
    )

    try:
        already_revoked = str(cert.get("status", "")).strip().lower() == "revoked"
        if already_revoked:
            vault_result = {"already_revoked": True, "revocation_time": cert.get("revoked_at")}
        else:
            vault_result = VAULT_CLIENT.revoke_certificate(serial_number)
        revoked_cert = mark_certificate_revoked(SETTINGS, cert_id) or cert
        revoked_packages: list[dict] = []
        for package_id in package_ids:
            row = update_certificate_package_lifecycle(
                SETTINGS,
                package_id,
                "REVOKED",
                actor,
                {
                    "event_type": "package_revoked",
                    "source_interface": "rest_revoke",
                    "certificate_id": cert_id,
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                    "reason": body.reason,
                    "correlation_id": correlation_id,
                },
            )
            if row:
                revoked_packages.append(row)
        trust_list = build_trust_list(SETTINGS, str(cert.get("zone")), str(cert.get("role")))
        if TRUST_ARTIFACT_SIGNER:
            _get_or_regenerate_signed_artifact(str(cert.get("zone")), str(cert.get("role")), force_rebuild=True)
        crl_payload = VAULT_CLIENT.get_intermediate_crl()
        crl_sha256 = _crl_sha256_from_vault_payload(crl_payload)
    except VaultSealedError:
        return _vault_sealed_response()
    except Exception as exc:
        LOG.error("certificate revocation failed: %s", exc.__class__.__name__)
        audit(
            SETTINGS,
            "certificate_revocation_failed",
            actor,
            f"certificate:{cert_id}",
            {
                "certificate_id": cert_id,
                "fingerprint_sha256": cert.get("fingerprint_sha256"),
                "error_code": "revocation_failed",
                "correlation_id": correlation_id,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "certificate revocation failed", "error_code": "revocation_failed"},
        )

    audit(
        SETTINGS,
        "certificate_revocation_crl_refreshed",
        actor,
        f"certificate:{cert_id}",
        {
            "certificate_id": cert_id,
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
            "package_ids": package_ids,
            "reason": body.reason,
            "already_revoked": vault_result.get("already_revoked", False),
            "vault_revocation_time": vault_result.get("revocation_time"),
            "trustlist_zone": cert.get("zone"),
            "trustlist_role": cert.get("role"),
            "trustlist_version": trust_list.get("version") if trust_list else None,
            "crl_sha256": crl_sha256,
            "correlation_id": correlation_id,
        },
    )
    audit(
        SETTINGS,
        "certificate_revoked",
        actor,
        f"certificate:{cert_id}",
        {
            "certificate_id": cert_id,
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
            "package_ids": package_ids,
            "reason": body.reason,
            "correlation_id": correlation_id,
        },
    )

    return {
        "certificate_id": cert_id,
        "fingerprint_sha256": revoked_cert.get("fingerprint_sha256"),
        "status": revoked_cert.get("status"),
        "revoked_at": revoked_cert.get("revoked_at"),
        "package_ids": package_ids,
        "package_lifecycle_state": "REVOKED" if revoked_packages else None,
        "already_revoked": vault_result.get("already_revoked", False),
        "trustlist_zone": cert.get("zone"),
        "trustlist_role": cert.get("role"),
        "trustlist_version": trust_list.get("version") if trust_list else None,
        "crl_refreshed": True,
        "crl_sha256": crl_sha256,
        "runtime_mutation_performed": False,
        "dry_run_runtime_propagation_required": True,
    }


@app.get("/api/v1/certificates/{cert_id}")
def get_certificate_by_id(cert_id: int):
    cert = get_certificate(SETTINGS, cert_id)
    if not cert:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"error": "certificate not found"})
    return cert


@app.post("/api/v1/certificates/issue", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def issue_certificate():
    sealed_err = _require_vault_unsealed()
    if sealed_err:
        return sealed_err
    return {"status": "not_implemented", "phase": "phase1"}


@app.post("/api/v1/certificates/renew")
def renew_certificate(body: RenewCsrBody, request: Request):
    mtls_err = _require_https_mtls(request)
    if mtls_err:
        return mtls_err
    auth_err = _authorize_agent_pull(request, access="enrollment_submit", application_uri=body.application_uri)
    if auth_err:
        return auth_err
    if not VAULT_CLIENT:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "vault client not initialized", "error_code": "vault_client_unavailable"})
    if not TRUST_ARTIFACT_SIGNER:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"error": "trust artifact signer not initialized", "error_code": "signer_unavailable"})
    sealed_err = _require_vault_unsealed()
    if sealed_err:
        return sealed_err

    actor = _agent_id_from_request(request)
    correlation_id = _correlation_id(request)
    audit(
        SETTINGS,
        "certificate_renewal_requested",
        actor,
        f"application:{body.application_uri}",
        {
            "application_uri": body.application_uri,
            "runtime_instance_id": body.runtime_instance_id,
            "profile_name": body.profile_name,
            "renewal_reason": body.renewal_reason or "",
            "correlation_id": correlation_id,
        },
    )
    try:
        result = issue_certificate_package(
            settings=SETTINGS,
            vault_client=VAULT_CLIENT,
            signer=TRUST_ARTIFACT_SIGNER,
            application_uri=body.application_uri,
            runtime_instance_id=body.runtime_instance_id or "",
            profile_name=body.profile_name,
            csr_pem=body.csr_pem,
            requested_ttl=body.requested_ttl,
            requested_by=actor,
            source_interface="rest_renewal",
            allow_duplicate_csr=True,
        )
    except LifecycleError as exc:
        audit(
            SETTINGS,
            "certificate_renewal_failed",
            actor,
            f"application:{body.application_uri}",
            {
                "application_uri": body.application_uri,
                "profile_name": body.profile_name,
                "error_code": exc.code,
                "correlation_id": correlation_id,
            },
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": str(exc), "error_code": exc.code, "details": exc.details},
        )
    except Exception as exc:
        LOG.error("certificate renewal failed: %s", exc)
        audit(
            SETTINGS,
            "certificate_renewal_failed",
            actor,
            f"application:{body.application_uri}",
            {
                "application_uri": body.application_uri,
                "profile_name": body.profile_name,
                "error_code": "renewal_failed",
                "correlation_id": correlation_id,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "certificate renewal failed", "error_code": "renewal_failed"},
        )

    package = result["package"]
    certificate = result["certificate"]
    audit(
        SETTINGS,
        "certificate_renewal_packaged",
        actor,
        f"certificate_package:{package['package_id']}",
        {
            "request_id": result["request"]["request_id"],
            "package_id": package["package_id"],
            "generation": package["generation"],
            "supersedes_package_id": package.get("supersedes_package_id"),
            "application_uri": body.application_uri,
            "profile_name": body.profile_name,
            "correlation_id": correlation_id,
        },
    )
    affected_rebuilt = _rebuild_affected_consumer_artifacts_for_component(
        body.application_uri,
        source="certificate_renewal",
    )
    component_response = _component_enrollment_response(result, request)
    if isinstance(component_response, JSONResponse):
        return component_response
    component_response["schema"] = "labshock_gds_component_renewal_result_v1"
    component_response["supersedes_package_id"] = package.get("supersedes_package_id")
    component_response["supersedes_generation"] = package.get("supersedes_generation")
    component_response["affected_trust_artifacts_rebuilt"] = affected_rebuilt
    component_response["private_key_included"] = False
    return component_response
