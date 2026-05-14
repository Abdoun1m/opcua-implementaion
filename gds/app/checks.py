from __future__ import annotations

import os
from typing import Any

import httpx
import psycopg

from .config import Settings


def check_postgres(settings: Settings) -> dict[str, Any]:
    try:
        with psycopg.connect(settings.pg_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                _ = cur.fetchone()
        return {"ok": True, "detail": "postgres reachable"}
    except Exception as exc:
        return {"ok": False, "detail": f"postgres check failed: {exc}"}


def check_vault(settings: Settings) -> dict[str, Any]:
    url = settings.vault_addr.rstrip("/") + settings.vault_health_path
    try:
        verify: bool | str = settings.vault_tls_verify
        if settings.vault_tls_verify and settings.vault_tls_ca_file:
            verify = settings.vault_tls_ca_file
        kwargs: dict[str, Any] = {"timeout": settings.vault_timeout_seconds, "verify": verify}
        if settings.vault_tls_client_cert and settings.vault_tls_client_key:
            kwargs["cert"] = (settings.vault_tls_client_cert, settings.vault_tls_client_key)
        with httpx.Client(**kwargs) as client:
            res = client.get(url)
        if res.status_code in (200, 429, 472, 473, 501, 503):
            return {"ok": True, "detail": f"vault reachable ({res.status_code})"}
        return {"ok": False, "detail": f"vault bad status: {res.status_code}"}
    except Exception as exc:
        return {"ok": False, "detail": f"vault check failed: {exc}"}


def check_config_files(settings: Settings) -> dict[str, Any]:
    files = {
        "vault_role_id_file": settings.vault_role_id_file,
        "vault_secret_id_file": settings.vault_secret_id_file,
    }
    missing = [name for name, path in files.items() if not os.path.exists(path)]
    if missing:
        return {
            "ok": False,
            "detail": "missing files: " + ", ".join(missing),
        }
    return {"ok": True, "detail": "approle files present"}


def full_health(settings: Settings) -> dict[str, Any]:
    postgres = check_postgres(settings)
    vault = check_vault(settings)
    config_files = check_config_files(settings)
    ok = postgres["ok"] and vault["ok"] and config_files["ok"]
    return {
        "ok": ok,
        "components": {
            "postgres": postgres,
            "vault": vault,
            "config_files": config_files,
        },
    }
