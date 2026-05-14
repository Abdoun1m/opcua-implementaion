from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID


@dataclass(frozen=True)
class RuntimeCompatibility:
    status: str
    risk_level: str
    blocking_reasons: list[str]
    warnings: list[str]
    details: dict[str, Any]


class RuntimeAdapter:
    runtime_family = "generic"

    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.runtime_semantics = _as_dict(profile.get("runtime_semantics_json"))
        self.compatibility_rules = _as_dict(profile.get("compatibility_rules_json"))
        self.trust_store_layout = _as_dict(profile.get("trust_store_layout_json"))
        self.enrollment_policy = _as_dict(profile.get("enrollment_policy_json"))

    def validate_csr(self, csr: x509.CertificateSigningRequest, app: dict[str, Any], requested_sans: dict[str, Any] | None = None) -> tuple[list[str], list[str], dict[str, Any]]:
        errors: list[str] = []
        warnings: list[str] = []
        csr_info = extract_csr_identity(csr)

        app_uri = str(app.get("application_uri", "")).strip()
        if app_uri and csr_info["uri_sans"] and app_uri not in csr_info["uri_sans"]:
            errors.append("csr_uri_san_mismatch")

        for dns_name in csr_info["dns_sans"]:
            if dns_name.startswith("*."):
                errors.append("wildcard_dns_san_rejected")

        allowed_zones = self.enrollment_policy.get("allowed_zones")
        if isinstance(allowed_zones, list) and app.get("zone") not in allowed_zones:
            errors.append("zone_not_allowed_by_profile")

        if not self.enrollment_policy.get("allow_private_ip_sans", True):
            for ip_text in csr_info["ip_sans"]:
                try:
                    if ipaddress.ip_address(ip_text).is_private:
                        errors.append("private_ip_san_rejected")
                except ValueError:
                    errors.append("invalid_ip_san")

        required_eku = set(self.compatibility_rules.get("required_extended_key_usage", []))
        csr_eku = set(csr_info["extended_key_usage"])
        if required_eku and not required_eku.issubset(csr_eku):
            errors.append("extended_key_usage_missing_required")

        required_ku = set(self.compatibility_rules.get("required_key_usage", []))
        csr_ku = set(csr_info["key_usage"])
        if required_ku and not required_ku.issubset(csr_ku):
            errors.append("key_usage_missing_required")

        return errors, warnings, csr_info

    def validate_runtime_compatibility(self, csr_info: dict[str, Any], app: dict[str, Any], issued_cert: dict[str, Any] | None = None) -> RuntimeCompatibility:
        blocking: list[str] = []
        warnings: list[str] = []

        component_type = str(app.get("component_type") or app.get("role") or "").strip()
        profile_component = str(self.profile.get("component_type") or "").strip()
        if profile_component and component_type and component_type != profile_component:
            blocking.append("component_type_differs_from_profile")

        if str(self.profile.get("certificate_format", "")).lower() not in {"pem", "pem+der", "der"}:
            blocking.append("unsupported_certificate_format")

        if not self.trust_store_layout:
            blocking.append("missing_trust_store_layout")

        status = "INCOMPATIBLE" if blocking else "COMPATIBLE"
        return RuntimeCompatibility(
            status=status,
            risk_level="HIGH" if blocking else ("MEDIUM" if warnings else "LOW"),
            blocking_reasons=blocking,
            warnings=warnings,
            details={
                "runtime_family": self.runtime_family,
                "certificate_format": self.profile.get("certificate_format"),
                "runtime_semantics": self.runtime_semantics,
                "trust_store_layout": self.trust_store_layout,
                "csr_identity": csr_info,
                "issued_certificate_fingerprint": issued_cert.get("fingerprint_sha256") if issued_cert else None,
            },
        )

    def generate_package_layout(self, issued_cert: dict[str, Any], ca_chain_pem: str, crl_base64: str) -> dict[str, Any]:
        layout = dict(self.trust_store_layout)
        return {
            "runtime_family": self.runtime_family,
            "layout": layout,
            "files": {
                layout.get("application_certificate", "own/certs/application.pem"): issued_cert["pem"],
                layout.get("issuer_chain", "issuers/certs/ca-chain.pem"): ca_chain_pem,
                layout.get("issuer_crl", "issuers/crl/current.crl.b64"): crl_base64,
            },
        }

    def generate_install_plan(self, package_layout: dict[str, Any], compatibility: RuntimeCompatibility) -> dict[str, Any]:
        return {
            "runtime_write_enabled": False,
            "dry_run_only": True,
            "runtime_family": self.runtime_family,
            "target_layout": package_layout.get("layout", {}),
            "steps": [
                "verify_signed_manifest",
                "verify_payload_hash_tree",
                "verify_runtime_compatibility",
                "create_shadow_trust_store",
                "evaluate_approval_and_maintenance_window",
                "prepare_activation_dry_run_only",
            ],
            "blocked": compatibility.status != "COMPATIBLE",
            "blocking_reasons": compatibility.blocking_reasons,
            "warnings": compatibility.warnings,
        }

    def classify_risk(self, compatibility: RuntimeCompatibility) -> str:
        return compatibility.risk_level


class Open62541RuntimeAdapter(RuntimeAdapter):
    runtime_family = "open62541"


class NodeOpcuaRuntimeAdapter(RuntimeAdapter):
    runtime_family = "node-opcua"


class OpcUaPart12EnrollmentAdapter:
    source_interface = "opcua_part12"

    def to_lifecycle_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "source_interface": self.source_interface,
            "application_uri": payload.get("application_uri"),
            "runtime_instance_id": payload.get("runtime_instance_id"),
            "profile_name": payload.get("profile_name"),
            "csr_pem": payload.get("csr_pem"),
            "requested_ttl": payload.get("requested_ttl"),
            "requested_subject": payload.get("requested_subject"),
            "requested_sans": payload.get("requested_sans"),
        }


def adapter_for_profile(profile: dict[str, Any]) -> RuntimeAdapter:
    family = str(profile.get("runtime_family", "")).strip().lower()
    if family == "open62541":
        return Open62541RuntimeAdapter(profile)
    if family == "node-opcua":
        return NodeOpcuaRuntimeAdapter(profile)
    return RuntimeAdapter(profile)


def extract_csr_identity(csr: x509.CertificateSigningRequest) -> dict[str, Any]:
    uri_sans: list[str] = []
    dns_sans: list[str] = []
    ip_sans: list[str] = []
    key_usage: list[str] = []
    extended_key_usage: list[str] = []

    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uri_sans = [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
        dns_sans = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        ip_sans = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    try:
        ku = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if ku.digital_signature:
            key_usage.append("digitalSignature")
        if ku.key_encipherment:
            key_usage.append("keyEncipherment")
        if ku.key_cert_sign:
            key_usage.append("keyCertSign")
    except x509.ExtensionNotFound:
        pass

    try:
        eku = csr.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        for oid in eku:
            if oid == ExtendedKeyUsageOID.SERVER_AUTH:
                extended_key_usage.append("serverAuth")
            elif oid == ExtendedKeyUsageOID.CLIENT_AUTH:
                extended_key_usage.append("clientAuth")
            else:
                extended_key_usage.append(oid.dotted_string)
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": csr.subject.rfc4514_string(),
        "uri_sans": uri_sans,
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
    }


def default_component_profiles() -> list[dict[str, Any]]:
    open62541_layout = {
        "application_certificate": "own/certs/application.pem",
        "issuer_chain": "issuers/certs/ca-chain.pem",
        "issuer_crl": "issuers/crl/current.crl.b64",
        "trusted_certs_dir": "trusted/certs",
        "trusted_crl_dir": "trusted/crl",
    }
    node_layout = {
        "application_certificate": "own/certs/client_certificate.pem",
        "issuer_chain": "issuers/certs/ca-chain.pem",
        "issuer_crl": "issuers/crl/current.crl.b64",
        "trusted_certs_dir": "trusted/certs",
        "trusted_crl_dir": "trusted/crl",
    }
    return [
        _profile("open62541-server", "open62541", "server", "pem", open62541_layout, ["serverAuth"]),
        _profile("open62541-client", "open62541", "client", "pem", open62541_layout, ["clientAuth"]),
        _profile("node-opcua-server", "node-opcua", "server", "pem", node_layout, ["serverAuth"]),
        _profile("node-opcua-client", "node-opcua", "client", "pem", node_layout, ["clientAuth"]),
    ]


def _profile(
    profile_name: str,
    runtime_family: str,
    component_type: str,
    certificate_format: str,
    trust_store_layout: dict[str, Any],
    required_eku: list[str],
) -> dict[str, Any]:
    return {
        "profile_name": profile_name,
        "runtime_family": runtime_family,
        "component_type": component_type,
        "certificate_format": certificate_format,
        "trust_store_layout_json": trust_store_layout,
        "runtime_semantics_json": {
            "hot_reload_supported": False,
            "restart_required_for_key_change": True,
            "restart_required_for_trust_change": False,
            "private_key_format": "DER" if runtime_family == "open62541" else "PEM",
            "certificate_store_model": "open62541-filestore" if runtime_family == "open62541" else "node-opcua-pki",
        },
        "compatibility_rules_json": {
            "required_key_usage": ["digitalSignature", "keyEncipherment"],
            "required_extended_key_usage": required_eku,
            "reject_wildcard_dns_sans": True,
        },
        "enrollment_policy_json": {
            "auto_issue_allowed": True,
            "manual_approval_required": False,
            "allowed_zones": ["OT", "DMZ"],
            "allow_private_ip_sans": True,
        },
        "status": "active",
    }


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}
