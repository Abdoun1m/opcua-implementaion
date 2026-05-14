from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from .artifact_signing import canonical_json_bytes


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def package_files_sha256(package_layout: dict[str, Any]) -> dict[str, str]:
    files = package_layout.get("files", {})
    if not isinstance(files, dict):
        return {}
    return {str(path): sha256_text(str(content)) for path, content in sorted(files.items())}


def package_payload_sha256(files_sha256: dict[str, str]) -> str:
    return hashlib.sha256(canonical_json_bytes(files_sha256)).hexdigest()


def canonical_package_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(manifest)
    out["manifest_sha256"] = ""
    out.pop("signature", None)
    return out


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(canonical_package_manifest(manifest))).hexdigest()
