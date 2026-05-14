#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

try:
    from asyncua import Client
except Exception as exc:  # pragma: no cover - operator environment check.
    print(f"[FAIL] asyncua_import_failed:{exc}")
    sys.exit(2)


NAMESPACE_URI = "urn:labshock:gds:facade"


def _loads(raw: Any) -> dict[str, Any]:
    if isinstance(raw, list) and len(raw) == 1:
        raw = raw[0]
    if hasattr(raw, "Value"):
        raw = raw.Value
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if not isinstance(raw, str):
        raise ValueError(f"method returned non-string value: {type(raw).__name__}")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("method returned non-object JSON")
    return data


def _pass(name: str) -> None:
    print(f"[PASS] {name}")


def _fail(name: str, detail: str) -> None:
    print(f"[FAIL] {name}:{detail}")


async def _call(facade: Any, ns_idx: int, method_name: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    method = await facade.get_child([f"{ns_idx}:{method_name}"])
    if payload is None:
        return _loads(await facade.call_method(method))
    return _loads(await facade.call_method(method, json.dumps(payload, separators=(",", ":"), sort_keys=True)))


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Validate the LabShock GDS Phase 7 OPC UA facade dry-run contract.")
    parser.add_argument("--endpoint", default="opc.tcp://127.0.0.1:4841/LabShock/GDS/Facade")
    parser.add_argument("--application-uri", default="urn:dataprotect:opcua:fuxa-client")
    parser.add_argument("--profile-name", default="node-opcua-client")
    parser.add_argument("--csr-pem-file", default="")
    args = parser.parse_args()

    failures = 0
    try:
        client = Client(args.endpoint)
        async with client:
            ns_idx = await client.get_namespace_index(NAMESPACE_URI)
            facade = await client.nodes.objects.get_child([f"{ns_idx}:LabShockGdsFacade"])

            capabilities = await _call(facade, ns_idx, "GetServerCapabilities")
            enabled = set(capabilities.get("enabled_operations") or [])
            disabled = set(capabilities.get("disabled_operations") or [])
            if (
                capabilities.get("dry_run_only") is True
                and capabilities.get("runtime_write_enabled") is False
                and capabilities.get("part12_full_compliance") is False
                and "CreateSigningRequestDryRun" in enabled
                and "CreateSigningRequest" in disabled
            ):
                _pass("capabilities_report_default_dry_run_contract")
            else:
                failures += 1
                _fail("capabilities_report_default_dry_run_contract", json.dumps(capabilities, sort_keys=True))

            discovery = await _call(facade, ns_idx, "GetDiscovery")
            if discovery.get("dry_run_only") is True and "CreateSigningRequestDryRun" in set(discovery.get("enabled_operations") or []):
                _pass("discovery_reports_dry_run_operations")
            else:
                failures += 1
                _fail("discovery_reports_dry_run_operations", json.dumps(discovery, sort_keys=True))

            inventory = await _call(facade, ns_idx, "GetApplicationInventory")
            if inventory.get("schema") == "labshock_opcua_application_inventory_v1":
                _pass("application_inventory_callable")
            else:
                failures += 1
                _fail("application_inventory_callable", json.dumps(inventory, sort_keys=True))

            groups = await _call(facade, ns_idx, "GetCertificateGroups")
            if groups.get("schema") == "labshock_opcua_certificate_groups_v1":
                _pass("certificate_groups_callable")
            else:
                failures += 1
                _fail("certificate_groups_callable", json.dumps(groups, sort_keys=True))

            status = await _call(facade, ns_idx, "GetPackageStatus", {"application_uri": args.application_uri})
            if status.get("schema") == "labshock_opcua_package_status_v1":
                _pass("package_status_callable")
            else:
                failures += 1
                _fail("package_status_callable", json.dumps(status, sort_keys=True))

            signing = await _call(
                facade,
                ns_idx,
                "CreateSigningRequest",
                {
                    "application_uri": args.application_uri,
                    "profile_name": args.profile_name,
                    "csr_pem": "not-a-real-csr",
                    "client_id": "phase7-validation",
                },
            )
            if signing.get("error_code") == "opcua_signing_disabled" and signing.get("dry_run_only") is True:
                _pass("create_signing_request_disabled_by_default")
            else:
                failures += 1
                _fail("create_signing_request_disabled_by_default", json.dumps(signing, sort_keys=True))

            invalid_dry_run = await _call(
                facade,
                ns_idx,
                "CreateSigningRequestDryRun",
                {
                    "application_uri": args.application_uri,
                    "profile_name": args.profile_name,
                    "csr_pem": "not-a-real-csr",
                    "client_id": "phase7-validation",
                },
            )
            if invalid_dry_run.get("vault_signing_performed") is False and invalid_dry_run.get("package_created") is False:
                _pass("dry_run_rejects_invalid_csr_without_signing")
            else:
                failures += 1
                _fail("dry_run_rejects_invalid_csr_without_signing", json.dumps(invalid_dry_run, sort_keys=True))

            if args.csr_pem_file:
                csr_pem = Path(args.csr_pem_file).read_text(encoding="utf-8")
                valid_dry_run = await _call(
                    facade,
                    ns_idx,
                    "CreateSigningRequestDryRun",
                    {
                        "application_uri": args.application_uri,
                        "profile_name": args.profile_name,
                        "csr_pem": csr_pem,
                        "client_id": "phase7-validation",
                    },
                )
                if (
                    valid_dry_run.get("schema") == "labshock_opcua_signing_request_dry_run_v1"
                    and valid_dry_run.get("vault_signing_performed") is False
                    and valid_dry_run.get("package_created") is False
                ):
                    _pass("dry_run_accepts_valid_csr_without_signing")
                else:
                    failures += 1
                    _fail("dry_run_accepts_valid_csr_without_signing", json.dumps(valid_dry_run, sort_keys=True))
            else:
                print("[SKIP] dry_run_accepts_valid_csr_without_signing:no --csr-pem-file provided")
    except Exception as exc:
        _fail("opcua_facade_validation_exception", str(exc))
        return 1

    print(f"[SUMMARY] fail={failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
