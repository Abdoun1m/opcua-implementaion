from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from .config import Settings
from .db import (
    audit,
    get_application_by_uri,
    get_certificate_package,
    list_applications,
    list_certificate_packages,
    list_component_profiles,
)
from .lifecycle import LifecycleError, issue_certificate_package, validate_certificate_request_dry_run
from .artifact_signing import TrustArtifactSigner
from .vault_client import VaultClient

try:
    from asyncua import Server, ua, uamethod
except Exception:  # pragma: no cover - runtime dependency is installed in the GDS image.
    Server = None
    ua = None

    def uamethod(func):  # type: ignore[no-redef]
        return func


LOG = logging.getLogger("gds.opcua.boundary")
NAMESPACE_URI = "urn:labshock:gds:facade"
ENDPOINT_PATH = "/LabShock/GDS/Facade"
READ_DRY_RUN_OPERATIONS = [
    "GetServerCapabilities",
    "GetDiscovery",
    "GetApplicationInventory",
    "GetCertificateGroups",
    "GetTrustMaterialStatus",
    "CreateSigningRequestDryRun",
    "GetPackageStatus",
]
SIGNING_OPERATION = "CreateSigningRequest"


@dataclass
class _RateCounter:
    window_started_at: float
    count: int


class OpcUaPart12BoundaryAdapter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._server: Any | None = None
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._session_limits: dict[str, _RateCounter] = {}
        self._enrollment_limits: dict[str, _RateCounter] = {}

    async def start(self) -> None:
        if not self.settings.opcua_facade_enabled:
            LOG.info("opcua boundary adapter disabled")
            return
        if Server is None or ua is None:
            LOG.error("asyncua is not installed; OPC UA boundary adapter not started")
            return
        self._task = asyncio.create_task(self._serve(), name="opcua-part12-boundary-adapter")

    async def stop(self) -> None:
        self._stopping.set()
        if self._server is not None:
            with suppress(Exception):
                await self._server.stop()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        LOG.info("opcua boundary adapter stopped")

    async def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                server = Server()
                await server.init()
                server.set_endpoint(f"opc.tcp://{self.settings.opcua_facade_host}:{self.settings.opcua_facade_port}{ENDPOINT_PATH}")
                with suppress(AttributeError):
                    server.set_server_name("LabShock GDS OPC UA Boundary Adapter")
                with suppress(AttributeError):
                    maybe_coro = server.set_application_uri(NAMESPACE_URI)
                    if asyncio.iscoroutine(maybe_coro):
                        await maybe_coro
                with suppress(AttributeError):
                    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
                idx = await server.register_namespace(NAMESPACE_URI)
                root = await server.nodes.objects.add_folder(idx, "LabShockGdsFacade")
                await root.add_property(idx, "FacadeMode", self.settings.opcua_facade_mode)
                await root.add_property(idx, "Part12FullCompliance", False)
                await root.add_method(idx, "GetServerCapabilities", self.get_server_capabilities, [], [ua.VariantType.String])
                await root.add_method(idx, "GetDiscovery", self.get_discovery, [], [ua.VariantType.String])
                await root.add_method(idx, "GetApplicationInventory", self.get_application_inventory, [], [ua.VariantType.String])
                await root.add_method(idx, "GetCertificateGroups", self.get_certificate_groups, [], [ua.VariantType.String])
                await root.add_method(idx, "GetTrustMaterialStatus", self.get_trust_material_status, [ua.VariantType.String], [ua.VariantType.String])
                await root.add_method(idx, "CreateSigningRequestDryRun", self.create_signing_request_dry_run, [ua.VariantType.String], [ua.VariantType.String])
                await root.add_method(idx, "CreateSigningRequest", self.create_signing_request, [ua.VariantType.String], [ua.VariantType.String])
                await root.add_method(idx, "GetPackageStatus", self.get_package_status, [ua.VariantType.String], [ua.VariantType.String])
                self._server = server
                async with server:
                    LOG.info(
                        "opcua boundary adapter listening on %s:%s namespace=%s mode=%s",
                        self.settings.opcua_facade_host,
                        self.settings.opcua_facade_port,
                        NAMESPACE_URI,
                        self.settings.opcua_facade_mode,
                    )
                    while not self._stopping.is_set():
                        await asyncio.sleep(1.0)
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("opcua boundary adapter crashed; restarting err=%s", exc)
                await asyncio.sleep(5.0)

    @uamethod
    async def get_server_capabilities(self, parent: Any) -> str:
        context = self._context({})
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        profiles = list_component_profiles(self.settings)
        enabled_operations = list(READ_DRY_RUN_OPERATIONS)
        disabled_operations: list[str] = []
        if self.settings.opcua_facade_allow_signing:
            enabled_operations.append(SIGNING_OPERATION)
        else:
            disabled_operations.append(SIGNING_OPERATION)
        response = {
            "schema": "labshock_opcua_gds_facade_capabilities_v1",
            "namespace": NAMESPACE_URI,
            "mode": self.settings.opcua_facade_mode,
            "endpoint_path": ENDPOINT_PATH,
            "part12_full_compliance": False,
            "runtime_write_enabled": False,
            "dry_run_only": True,
            "opcua_signing_enabled": self.settings.opcua_facade_allow_signing,
            "security_model": "cyber_range_minimal_restricted_namespace",
            "enabled_operations": enabled_operations,
            "disabled_operations": disabled_operations,
            "supported_operations": enabled_operations,
            "supported_profiles": [p.get("profile_name") for p in profiles],
            "limits": {
                "max_csr_bytes": self.settings.opcua_facade_max_csr_bytes,
                "session_request_limit": self.settings.opcua_facade_session_request_limit,
                "client_enrollment_limit": self.settings.opcua_facade_client_enrollment_limit,
            },
            **context,
        }
        self._audit("opcua_capabilities_read", "opcua:gds_facade", context, {})
        return self._json(response)

    @uamethod
    async def get_discovery(self, parent: Any) -> str:
        context = self._context({})
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        profiles = list_component_profiles(self.settings)
        enabled_operations = list(READ_DRY_RUN_OPERATIONS)
        if self.settings.opcua_facade_allow_signing:
            enabled_operations.append(SIGNING_OPERATION)
        response = {
            "schema": "labshock_opcua_gds_discovery_v1",
            "namespace": NAMESPACE_URI,
            "mode": self.settings.opcua_facade_mode,
            "private_key_export_allowed": False,
            "runtime_write_enabled": False,
            "dry_run_only": True,
            "enabled_operations": enabled_operations,
            "disabled_operations": [] if self.settings.opcua_facade_allow_signing else [SIGNING_OPERATION],
            "supported_operations": enabled_operations,
            "supported_profiles": [p.get("profile_name") for p in profiles],
            **context,
        }
        self._audit("opcua_discovery_read", "opcua:gds_facade", context, {"profile_count": len(profiles)})
        return self._json(response)

    @uamethod
    async def get_application_inventory(self, parent: Any) -> str:
        context = self._context({})
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        apps = [
            {
                "application_uri": row.get("application_uri"),
                "common_name": row.get("common_name"),
                "zone": row.get("zone"),
                "role": row.get("role"),
                "component_type": row.get("component_type"),
                "runtime_instance_id": row.get("runtime_instance_id"),
                "host": row.get("host"),
                "port": row.get("port"),
                "status": row.get("status"),
            }
            for row in list_applications(self.settings)
        ]
        self._audit("opcua_application_inventory_read", "opcua:gds_facade", context, {"application_count": len(apps)})
        return self._json({"schema": "labshock_opcua_application_inventory_v1", "applications": apps, **context})

    @uamethod
    async def get_certificate_groups(self, parent: Any) -> str:
        context = self._context({})
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        groups = [
            {
                "profile_name": row.get("profile_name"),
                "runtime_family": row.get("runtime_family"),
                "component_type": row.get("component_type"),
                "certificate_format": row.get("certificate_format"),
                "status": row.get("status"),
            }
            for row in list_component_profiles(self.settings)
        ]
        self._audit("opcua_certificate_groups_read", "opcua:gds_facade", context, {"group_count": len(groups)})
        return self._json({"schema": "labshock_opcua_certificate_groups_v1", "certificate_groups": groups, **context})

    @uamethod
    async def get_trust_material_status(self, parent: Any, payload_json: str) -> str:
        payload = self._parse_payload(payload_json)
        context = self._context(payload)
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        application_uri = str(payload.get("application_uri") or "").strip()
        if not application_uri:
            return self._error("missing_application_uri", "Provide application_uri", context)
        app = get_application_by_uri(self.settings, application_uri)
        if not app:
            return self._error("unknown_application", "application_uri is not registered", context)
        packages = [self._safe_package(row) for row in list_certificate_packages(self.settings, application_uri=application_uri, limit=5)]
        response = {
            "schema": "labshock_opcua_trust_material_status_v1",
            "application_uri": application_uri,
            "runtime_instance_id": app.get("runtime_instance_id") or application_uri,
            "zone": app.get("zone"),
            "role": app.get("role"),
            "private_key_included": False,
            "packages": packages,
            **context,
        }
        self._audit("opcua_trust_material_status_read", "opcua:gds_facade", context, {"application_uri": application_uri})
        return self._json(response)

    @uamethod
    async def create_signing_request_dry_run(self, parent: Any, payload_json: str) -> str:
        payload = self._parse_payload(payload_json)
        context = self._context(payload)
        actor = self._actor(payload)
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        if not self._allow_enrollment(context):
            return self._error("enrollment_rate_limit_exceeded", "OPC UA facade client enrollment limit exceeded", context)
        csr_pem = str(payload.get("csr_pem") or "")
        if len(csr_pem.encode("utf-8")) > self.settings.opcua_facade_max_csr_bytes:
            self._audit("opcua_signing_request_dry_run_rejected", actor, context, {"error_code": "csr_too_large"})
            return self._error("csr_too_large", "CSR exceeds OPC UA facade maximum size", context)
        try:
            result = validate_certificate_request_dry_run(
                settings=self.settings,
                application_uri=str(payload.get("application_uri") or ""),
                runtime_instance_id=str(payload.get("runtime_instance_id") or ""),
                profile_name=str(payload.get("profile_name") or ""),
                csr_pem=csr_pem,
                requested_by=actor,
                source_interface="opcua_part12_dry_run",
                correlation_id=context["correlation_id"],
            )
        except LifecycleError as exc:
            self._audit("opcua_signing_request_dry_run_rejected", actor, context, {"error_code": exc.code, "details": exc.details})
            return self._error(exc.code, str(exc), context, exc.details)
        request = result["request"]
        validation = result["validation_result"]
        response = {
            "schema": "labshock_opcua_signing_request_dry_run_v1",
            "request_id": request["request_id"],
            "application_uri": result["application_uri"],
            "runtime_instance_id": result["runtime_instance_id"],
            "profile_name": result["profile_name"],
            "status": result["status"],
            "validation_errors": validation.get("errors", []),
            "validation_warnings": validation.get("warnings", []),
            "compatibility": validation.get("compatibility", {}),
            "vault_signing_performed": False,
            "package_created": False,
            "runtime_write_enabled": False,
            "dry_run_only": True,
            **context,
        }
        return self._json(response)

    @uamethod
    async def create_signing_request(self, parent: Any, payload_json: str) -> str:
        payload = self._parse_payload(payload_json)
        context = self._context(payload)
        actor = self._actor(payload)
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        if not self._allow_enrollment(context):
            return self._error("enrollment_rate_limit_exceeded", "OPC UA facade client enrollment limit exceeded", context)
        if not self.settings.opcua_facade_allow_signing:
            self._audit("opcua_signing_request_rejected", actor, context, {"error_code": "opcua_signing_disabled"})
            return self._error(
                "opcua_signing_disabled",
                "OPC UA facade signing is disabled; use REST HTTPS/mTLS issuance or CreateSigningRequestDryRun",
                context,
                {"vault_signing_performed": False, "package_created": False, "dry_run_only": True},
            )
        csr_pem = str(payload.get("csr_pem") or "")
        if len(csr_pem.encode("utf-8")) > self.settings.opcua_facade_max_csr_bytes:
            self._audit("opcua_signing_request_rejected", actor, context, {"error_code": "csr_too_large"})
            return self._error("csr_too_large", "CSR exceeds OPC UA facade maximum size", context)
        try:
            vault_client = VaultClient(self.settings)
            signer = TrustArtifactSigner(
                self.settings.trust_artifact_signing_key_path,
                self.settings.trust_artifact_signing_key_id,
                self.settings.trust_artifact_ttl_seconds,
            )
            result = issue_certificate_package(
                settings=self.settings,
                vault_client=vault_client,
                signer=signer,
                application_uri=str(payload.get("application_uri") or ""),
                runtime_instance_id=str(payload.get("runtime_instance_id") or ""),
                profile_name=str(payload.get("profile_name") or ""),
                csr_pem=csr_pem,
                requested_ttl=str(payload.get("requested_ttl") or "") or None,
                requested_by=actor,
                source_interface="opcua_part12_component",
            )
        except LifecycleError as exc:
            self._audit("opcua_signing_request_rejected", actor, context, {"error_code": exc.code, "details": exc.details})
            return self._error(exc.code, str(exc), context, exc.details)
        package = result["package"]
        certificate = result["certificate"]
        response = {
            "schema": "labshock_opcua_signing_request_result_v1",
            "request_id": result["request"]["request_id"],
            "application_uri": result["manifest"].get("application_uri"),
            "runtime_instance_id": result["manifest"].get("runtime_instance_id"),
            "profile_name": result["manifest"].get("profile_name"),
            "package_id": package["package_id"],
            "generation": package["generation"],
            "certificate_id": certificate["id"],
            "certificate_fingerprint_sha256": certificate["fingerprint_sha256"],
            "compatibility_status": package["compatibility_status"],
            "lifecycle_state": package["lifecycle_state"],
            "vault_signing_performed": True,
            "runtime_write_enabled": False,
            "private_key_included": False,
            **context,
        }
        self._audit("opcua_signing_request_completed", actor, context, {"package_id": package["package_id"], "certificate_id": certificate["id"]})
        return self._json(response)

    @uamethod
    async def get_package_status(self, parent: Any, payload_json: str) -> str:
        payload = self._parse_payload(payload_json)
        context = self._context(payload)
        if not self._allow_request(context):
            return self._error("rate_limit_exceeded", "OPC UA facade session request limit exceeded", context)
        package_id = str(payload.get("package_id") or "").strip()
        application_uri = str(payload.get("application_uri") or "").strip()
        if package_id:
            row = get_certificate_package(self.settings, package_id)
            packages = [self._safe_package(row)] if row else []
        elif application_uri:
            packages = [self._safe_package(row) for row in list_certificate_packages(self.settings, application_uri=application_uri, limit=10)]
        else:
            return self._error("missing_package_selector", "Provide package_id or application_uri", context)
        self._audit("opcua_package_status_read", "opcua:gds_facade", context, {"package_id": package_id, "application_uri": application_uri})
        return self._json({"schema": "labshock_opcua_package_status_v1", "packages": packages, **context})

    def _context(self, payload: dict[str, Any]) -> dict[str, str]:
        return {
            "correlation_id": str(payload.get("correlation_id") or uuid4().hex),
            "opcua_session_id": str(payload.get("opcua_session_id") or "anonymous"),
            "application_uri": str(payload.get("application_uri") or ""),
        }

    def _actor(self, payload: dict[str, Any]) -> str:
        client = str(payload.get("client_id") or payload.get("application_uri") or "anonymous").strip()
        return f"opcua:{client[:96]}"

    def _parse_payload(self, payload_json: str) -> dict[str, Any]:
        try:
            payload = json.loads(payload_json or "{}")
            return payload if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _allow_request(self, context: dict[str, str]) -> bool:
        return self._allow(self._session_limits, context.get("opcua_session_id") or "anonymous", self.settings.opcua_facade_session_request_limit)

    def _allow_enrollment(self, context: dict[str, str]) -> bool:
        key = context.get("application_uri") or context.get("opcua_session_id") or "anonymous"
        return self._allow(self._enrollment_limits, key, self.settings.opcua_facade_client_enrollment_limit)

    def _allow(self, counters: dict[str, _RateCounter], key: str, limit: int) -> bool:
        now = time.monotonic()
        counter = counters.get(key)
        if counter is None or now - counter.window_started_at >= 60:
            counters[key] = _RateCounter(now, 1)
            return True
        counter.count += 1
        return counter.count <= limit

    def _audit(self, event_type: str, actor: str, context: dict[str, str], details: dict[str, Any]) -> None:
        safe_details = {
            **details,
            "correlation_id": context.get("correlation_id"),
            "opcua_session_id": context.get("opcua_session_id"),
            "application_uri": context.get("application_uri"),
            "facade_mode": self.settings.opcua_facade_mode,
        }
        try:
            audit(self.settings, event_type, actor, "opcua:gds_facade", safe_details)
        except Exception as exc:
            LOG.warning("opcua audit failed event_type=%s err=%s", event_type, exc)

    def _safe_package(self, row: dict[str, Any] | None) -> dict[str, Any]:
        if not row:
            return {}
        return {
            "package_id": row.get("package_id"),
            "application_uri": row.get("application_uri"),
            "runtime_instance_id": row.get("runtime_instance_id"),
            "profile_name": row.get("profile_name"),
            "generation": row.get("generation"),
            "supersedes_package_id": row.get("supersedes_package_id"),
            "supersedes_generation": row.get("supersedes_generation"),
            "manifest_sha256": row.get("manifest_sha256"),
            "compatibility_status": row.get("compatibility_status"),
            "lifecycle_state": row.get("lifecycle_state"),
            "status": row.get("status"),
            "created_at": row.get("created_at"),
            "component_type": row.get("component_type"),
            "zone": row.get("zone"),
            "role": row.get("role"),
        }

    def _error(self, code: str, message: str, context: dict[str, str], details: dict[str, Any] | None = None) -> str:
        return self._json(
            {
                "schema": "labshock_opcua_error_v1",
                "ok": False,
                "error_code": code,
                "error": message,
                "details": details or {},
                "runtime_write_enabled": False,
                "dry_run_only": True,
                **context,
            }
        )

    def _json(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, default=str, ensure_ascii=True, separators=(",", ":"))
