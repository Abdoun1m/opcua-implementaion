from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .artifact_signing import TrustArtifactSigner
from .cert_utils import parse_pem_certificate
from .config import Settings
from .db import (
    audit,
    get_application_by_uri,
    get_certificate_by_fingerprint,
    get_latest_certificate_package_for_application,
    get_certificate_request_by_csr,
    get_component_profile,
    insert_certificate,
    insert_certificate_package,
    insert_certificate_request,
    insert_package_event,
    update_certificate_request_status,
)
from .package_signing import (
    canonical_package_manifest,
    manifest_sha256,
    package_files_sha256,
    package_payload_sha256,
)
from .runtime_adapters import RuntimeCompatibility, adapter_for_profile
from .vault_client import VaultClient, VaultSealedError


LIFECYCLE_ISSUED = "ISSUED"
LIFECYCLE_PACKAGED = "PACKAGED"


class LifecycleError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def issue_certificate_package(
    *,
    settings: Settings,
    vault_client: VaultClient,
    signer: TrustArtifactSigner,
    application_uri: str,
    runtime_instance_id: str,
    profile_name: str,
    csr_pem: str,
    requested_ttl: str | None,
    requested_by: str,
    source_interface: str = "rest",
    allow_duplicate_csr: bool = False,
) -> dict[str, Any]:
    app = get_application_by_uri(settings, application_uri)
    if not app:
        raise LifecycleError("unknown_application", "application_uri is not registered", 404)

    app_runtime = str(app.get("runtime_instance_id") or app.get("application_uri") or "")
    if runtime_instance_id and app_runtime and runtime_instance_id != app_runtime:
        raise LifecycleError(
            "runtime_instance_mismatch",
            "runtime_instance_id does not match application inventory",
            400,
            {"expected": app_runtime, "provided": runtime_instance_id},
        )
    runtime_instance_id = runtime_instance_id or app_runtime

    profile = get_component_profile(settings, profile_name)
    if not profile or str(profile.get("status", "")).lower() != "active":
        raise LifecycleError("unknown_profile", "component profile is not active or does not exist", 404)

    csr = _load_csr(csr_pem)
    if not csr.is_signature_valid:
        raise LifecycleError("invalid_csr_signature", "CSR signature is invalid", 400)
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_fp = hashlib.sha256(csr_der).hexdigest()
    existing_req = get_certificate_request_by_csr(settings, csr_fp)
    if existing_req and not allow_duplicate_csr:
        raise LifecycleError("duplicate_csr", "CSR fingerprint already has a non-failed request", 409, {"request_id": existing_req.get("request_id")})

    adapter = adapter_for_profile(profile)
    validation_errors, validation_warnings, csr_info = adapter.validate_csr(csr, app)
    validation_result = {
        "errors": validation_errors,
        "warnings": validation_warnings,
        "csr_identity": csr_info,
    }
    request_id = uuid4().hex
    cert_request = insert_certificate_request(
        settings,
        request_id=request_id,
        application_id=int(app["id"]),
        runtime_instance_id=runtime_instance_id,
        profile_name=profile_name,
        source_interface=source_interface,
        csr_pem=csr_pem,
        csr_fingerprint_sha256=csr_fp,
        subject=csr_info.get("subject"),
        uri_sans=csr_info.get("uri_sans", []),
        dns_sans=csr_info.get("dns_sans", []),
        ip_sans=csr_info.get("ip_sans", []),
        validation_result=validation_result,
        requested_by=requested_by,
        status_value="REJECTED" if validation_errors else "VALIDATED",
    )
    audit(settings, "certificate_request_created", requested_by, f"certificate_request:{request_id}", {"application_uri": application_uri, "profile_name": profile_name})

    if validation_errors:
        audit(settings, "csr_rejected", requested_by, f"certificate_request:{request_id}", validation_result)
        raise LifecycleError("csr_validation_failed", "CSR failed validation", 400, validation_result)
    audit(settings, "csr_validated", requested_by, f"certificate_request:{request_id}", validation_result)

    pre_compat = adapter.validate_runtime_compatibility(csr_info, app)
    common_name = _common_name_from_subject(csr_info.get("subject")) or str(app.get("common_name") or "")
    try:
        signed = vault_client.sign_csr(csr_pem, ttl=requested_ttl or settings.cert_default_ttl, common_name=common_name)
    except VaultSealedError:
        update_certificate_request_status(settings, request_id, "FAILED", {"errors": ["vault_sealed"]})
        audit(settings, "certificate_issue_failed", requested_by, f"certificate_request:{request_id}", {"error_code": "vault_sealed"})
        raise LifecycleError("vault_sealed", "Vault is sealed", 503)
    except Exception as exc:
        update_certificate_request_status(settings, request_id, "FAILED", {"errors": ["vault_signing_failed"], "detail": exc.__class__.__name__})
        audit(settings, "certificate_issue_failed", requested_by, f"certificate_request:{request_id}", {"error_code": "vault_signing_failed"})
        raise LifecycleError("vault_signing_failed", "Vault failed to sign CSR", 503, {"detail": exc.__class__.__name__})

    issued_cert = parse_pem_certificate(signed["certificate_pem"])
    cert_row = insert_certificate(
        settings,
        int(app["id"]),
        issued_cert["fingerprint_sha256"],
        issued_cert.get("serial_number"),
        issued_cert.get("subject"),
        issued_cert.get("issuer"),
        issued_cert.get("not_before"),
        issued_cert.get("not_after"),
        issued_cert["pem"],
        status="active",
    )
    if not cert_row:
        cert_row = get_certificate_by_fingerprint(settings, issued_cert["fingerprint_sha256"])
    if not cert_row:
        raise LifecycleError("certificate_storage_failed", "issued certificate could not be stored", 500)

    update_certificate_request_status(settings, request_id, LIFECYCLE_ISSUED)
    audit(settings, "certificate_issued", requested_by, f"certificate:{cert_row['id']}", {"request_id": request_id, "fingerprint_sha256": issued_cert["fingerprint_sha256"]})

    ca_chain = signed.get("ca_chain_pem") or _safe_ca_chain(vault_client)
    crl = _safe_crl(vault_client)
    crl_bundle = _safe_crl_bundle(vault_client)
    post_compat = adapter.validate_runtime_compatibility(csr_info, app, issued_cert)
    compatibility = _merge_compatibility(pre_compat, post_compat)
    layout = adapter.generate_package_layout(issued_cert, ca_chain, crl)
    install_plan = adapter.generate_install_plan(layout, compatibility)
    files_sha256 = package_files_sha256(layout)
    payload_sha = package_payload_sha256(files_sha256)

    previous_package = get_latest_certificate_package_for_application(settings, int(app["id"]), profile_name)
    generation = int(previous_package["generation"]) + 1 if previous_package else 1
    supersedes_package_id = previous_package.get("package_id") if previous_package else None
    supersedes_generation = previous_package.get("generation") if previous_package else None
    package_id = uuid4().hex
    created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    manifest = {
        "schema": "labshock_certificate_package_v1",
        "schema_version": 1,
        "package_id": package_id,
        "generation": generation,
        "supersedes_package_id": supersedes_package_id,
        "supersedes_generation": supersedes_generation,
        "application_uri": application_uri,
        "runtime_instance_id": runtime_instance_id,
        "profile_name": profile_name,
        "component_type": app.get("component_type") or app.get("role"),
        "certificate_fingerprint_sha256": issued_cert["fingerprint_sha256"],
        "certificate_serial": issued_cert.get("serial_number"),
        "not_before": _iso(issued_cert.get("not_before")),
        "not_after": _iso(issued_cert.get("not_after")),
        "certificate_pem": issued_cert["pem"],
        "ca_chain_pem": ca_chain,
        "crl_base64": crl,
        "crl_bundle": crl_bundle.get("crl_bundle", {}),
        "crl_metadata": crl_bundle.get("crl_metadata", {}),
        "install_plan": install_plan,
        "rollback_metadata": {
            "rollback_supported": True,
            "previous_generation_required": True,
            "runtime_write_enabled": False,
        },
        "compatibility": {
            "status": compatibility.status,
            "risk_level": compatibility.risk_level,
            "blocking_reasons": compatibility.blocking_reasons,
            "warnings": compatibility.warnings,
            "details": compatibility.details,
        },
        "lifecycle_state": LIFECYCLE_PACKAGED,
        "payload_sha256": payload_sha,
        "files_sha256": files_sha256,
        "manifest_sha256": "",
        "created_at": created_at,
        "signer": {
            "key_id": signer.key_id,
            "algorithm": signer.algorithm,
            "fingerprint_sha256": signer.fingerprint_sha256,
        },
    }
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    sig = signer.sign_canonical_payload(canonical_package_manifest(manifest))

    package_row = insert_certificate_package(
        settings,
        package_id=package_id,
        application_id=int(app["id"]),
        runtime_instance_id=runtime_instance_id,
        request_id=request_id,
        certificate_id=int(cert_row["id"]),
        profile_name=profile_name,
        manifest_json=manifest,
        manifest_sha256=manifest["manifest_sha256"],
        signature_base64=sig["signature_base64"],
        compatibility_status=compatibility.status,
        lifecycle_state=LIFECYCLE_PACKAGED,
        generation=generation,
        supersedes_package_id=supersedes_package_id,
        supersedes_generation=supersedes_generation,
    )
    update_certificate_request_status(settings, request_id, LIFECYCLE_PACKAGED)
    insert_package_event(settings, package_id, "certificate_package_created", requested_by, {"request_id": request_id, "generation": generation, "compatibility_status": compatibility.status})
    audit(settings, "certificate_package_created", requested_by, f"certificate_package:{package_id}", {"request_id": request_id, "generation": generation, "compatibility_status": compatibility.status})
    return {
        "request": cert_request,
        "certificate": cert_row,
        "package": package_row,
        "manifest": manifest,
        "signature": package_signature_payload(package_row),
    }


def validate_certificate_request_dry_run(
    *,
    settings: Settings,
    application_uri: str,
    runtime_instance_id: str,
    profile_name: str,
    csr_pem: str,
    requested_by: str,
    source_interface: str,
    correlation_id: str,
) -> dict[str, Any]:
    app = get_application_by_uri(settings, application_uri)
    if not app:
        raise LifecycleError("unknown_application", "application_uri is not registered", 404)

    app_runtime = str(app.get("runtime_instance_id") or app.get("application_uri") or "")
    if runtime_instance_id and app_runtime and runtime_instance_id != app_runtime:
        raise LifecycleError(
            "runtime_instance_mismatch",
            "runtime_instance_id does not match application inventory",
            400,
            {"expected": app_runtime, "provided": runtime_instance_id},
        )
    runtime_instance_id = runtime_instance_id or app_runtime

    profile = get_component_profile(settings, profile_name)
    if not profile or str(profile.get("status", "")).lower() != "active":
        raise LifecycleError("unknown_profile", "component profile is not active or does not exist", 404)

    csr = _load_csr(csr_pem)
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_fp = hashlib.sha256(csr_der).hexdigest()
    adapter = adapter_for_profile(profile)
    validation_errors, validation_warnings, csr_info = adapter.validate_csr(csr, app)
    if not csr.is_signature_valid:
        validation_errors.append("invalid_csr_signature")
    compatibility = adapter.validate_runtime_compatibility(csr_info, app)
    validation_result = {
        "errors": validation_errors,
        "warnings": validation_warnings,
        "csr_identity": csr_info,
        "compatibility": {
            "status": compatibility.status,
            "risk_level": compatibility.risk_level,
            "blocking_reasons": compatibility.blocking_reasons,
            "warnings": compatibility.warnings,
        },
        "dry_run_only": True,
        "vault_signing_performed": False,
        "package_created": False,
        "correlation_id": correlation_id,
    }
    request_id = uuid4().hex
    request_row = insert_certificate_request(
        settings,
        request_id=request_id,
        application_id=int(app["id"]),
        runtime_instance_id=runtime_instance_id,
        profile_name=profile_name,
        source_interface=source_interface,
        csr_pem=csr_pem,
        csr_fingerprint_sha256=csr_fp,
        subject=csr_info.get("subject"),
        uri_sans=csr_info.get("uri_sans", []),
        dns_sans=csr_info.get("dns_sans", []),
        ip_sans=csr_info.get("ip_sans", []),
        validation_result=validation_result,
        requested_by=requested_by,
        status_value="DRY_RUN_REJECTED" if validation_errors else "DRY_RUN_VALIDATED",
    )
    audit(
        settings,
        "opcua_signing_request_dry_run",
        requested_by,
        f"certificate_request:{request_id}",
        {
            "application_uri": application_uri,
            "runtime_instance_id": runtime_instance_id,
            "profile_name": profile_name,
            "request_id": request_id,
            "correlation_id": correlation_id,
            "validation_status": request_row["status"],
            "compatibility_status": compatibility.status,
            "dry_run_only": True,
        },
    )
    return {
        "request": request_row,
        "validation_result": validation_result,
        "application_uri": application_uri,
        "runtime_instance_id": runtime_instance_id,
        "profile_name": profile_name,
        "status": request_row["status"],
    }


def package_signature_payload(package_row: dict[str, Any]) -> dict[str, Any]:
    manifest = package_row.get("manifest_json")
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    if not isinstance(manifest, dict):
        manifest = {}
    signer = manifest.get("signer", {}) if isinstance(manifest.get("signer"), dict) else {}
    return {
        "package_id": package_row["package_id"],
        "generation": package_row["generation"],
        "manifest_sha256": package_row["manifest_sha256"],
        "signature_base64": package_row["signature_base64"],
        "signer": {
            "key_id": signer.get("key_id"),
            "algorithm": signer.get("algorithm", "ed25519"),
            "fingerprint_sha256": signer.get("fingerprint_sha256"),
        },
    }


def _load_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except Exception as exc:
        raise LifecycleError("malformed_csr", "CSR PEM could not be parsed", 400) from exc


def _common_name_from_subject(subject: str | None) -> str | None:
    if not subject:
        return None
    for part in subject.split(","):
        if part.strip().startswith("CN="):
            return part.strip()[3:]
    return None


def _safe_ca_chain(vault_client: VaultClient) -> str:
    try:
        return vault_client.get_ca_chain().get("ca_chain_pem", "")
    except Exception:
        return ""


def _safe_crl(vault_client: VaultClient) -> str:
    try:
        return vault_client.get_intermediate_crl().get("crl_base64", "")
    except Exception:
        return ""


def _safe_crl_bundle(vault_client: VaultClient) -> dict:
    try:
        bundle = vault_client.get_crl_bundle()
        return {
            "crl_bundle": {
                "root_crl_base64": bundle["root"]["crl_base64"],
                "intermediate_crl_base64": bundle["intermediate"]["crl_base64"],
            },
            "crl_metadata": {
                "root_crl_source": bundle.get("root_crl_source"),
                "root_pki_mount": bundle.get("root_pki_mount"),
                "root_issuer_id": bundle.get("root_issuer_id"),
                "root_crl_issuer": bundle.get("root_crl_issuer"),
                "root_crl_next_update": bundle.get("root_crl_next_update"),
                "root_crl_sha256": bundle.get("root_crl_sha256"),
                "intermediate_pki_mount": bundle.get("intermediate_pki_mount"),
                "intermediate_crl_issuer": bundle.get("intermediate_crl_issuer"),
                "intermediate_crl_next_update": bundle.get("intermediate_crl_next_update"),
                "intermediate_crl_sha256": bundle.get("intermediate_crl_sha256"),
                "crl_freshness_verified": bundle.get("crl_freshness_verified"),
            },
        }
    except Exception:
        return {"crl_bundle": {}, "crl_metadata": {}}


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return None


def _merge_compatibility(first: Any, second: Any) -> Any:
    blocking = sorted(set(first.blocking_reasons + second.blocking_reasons))
    warnings = sorted(set(first.warnings + second.warnings))
    status = "INCOMPATIBLE" if first.status == "INCOMPATIBLE" or second.status == "INCOMPATIBLE" else "COMPATIBLE"
    risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    risk_level = max(
        [str(first.risk_level), str(second.risk_level), "HIGH" if status == "INCOMPATIBLE" else "LOW"],
        key=lambda value: risk_order.get(value, 0),
    )
    details = dict(first.details)
    details.update(second.details)
    return RuntimeCompatibility(
        status=status,
        risk_level=risk_level,
        blocking_reasons=blocking,
        warnings=warnings,
        details=details,
    )
