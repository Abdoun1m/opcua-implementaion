from __future__ import annotations

import json
import logging
import threading
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import uuid4

from .config import Settings


LOG = logging.getLogger("gds.dmz_collector")

SOURCE_TYPE = "gds"
SPLUNK_SOURCETYPE = "labshock:dmz:gds"
ZONE = "DMZ"
ASSET_NAME = "labshock_gds"
ASSET_IP = "192.168.10.30"

DROP_OR_REDACT_KEYS = {
    "token",
    "client_token",
    "x-vault-token",
    "x-gds-agent-token",
    "password",
    "passwd",
    "pwd",
    "role_id",
    "secret_id",
    "private_key",
    "private_key_pem",
    "server_key",
    "client_key",
    "pem",
    "csr_pem",
    "certificate_pem",
    "ca_chain_pem",
    "crl_base64",
    "root_crl_base64",
    "intermediate_crl_base64",
    "crl_bundle",
    "signature_base64",
}

SAFE_FIELD_NAMES = {
    "event_type",
    "actor",
    "target",
    "application_uri",
    "runtime_instance_id",
    "package_id",
    "request_id",
    "certificate_id",
    "fingerprint_sha256",
    "serial_number",
    "trustlist_zone",
    "trustlist_role",
    "trustlist_version",
    "artifact_revision",
    "artifact_sha256",
    "error_code",
    "correlation_id",
    "source_ip",
    "mtls_verify_status",
}

AUDIT_EVENT_MAP = {
    "application_register": ("gds_client_registered", "pki_lifecycle", "info", False),
    "certificate_request_created": ("gds_enrollment_request", "pki_lifecycle", "info", False),
    "certificate_renewal_requested": ("gds_enrollment_request", "pki_lifecycle", "info", False),
    "csr_validated": ("gds_enrollment_approved", "pki_lifecycle", "info", False),
    "component_enrollment_completed": ("gds_enrollment_approved", "pki_lifecycle", "info", False),
    "csr_rejected": ("gds_enrollment_failed", "pki_lifecycle", "warning", True),
    "certificate_issue_failed": ("gds_enrollment_failed", "pki_lifecycle", "warning", True),
    "certificate_renewal_failed": ("gds_enrollment_failed", "pki_lifecycle", "warning", True),
    "certificate_issued": ("gds_certificate_issued", "certificate_lifecycle", "info", True),
    "certificate_renewal_packaged": ("gds_certificate_renewed", "certificate_lifecycle", "info", True),
    "certificate_revoked": ("gds_certificate_revoked", "certificate_lifecycle", "warning", True),
    "certificate_revocation_crl_refreshed": ("gds_certificate_revoked", "certificate_lifecycle", "warning", True),
    "trustlist_build": ("gds_trust_list_updated", "pki_trust_sync", "info", False),
    "artifact_regenerated": ("gds_trust_list_published", "pki_trust_sync", "info", True),
    "trustlist_artifact_rebuild": ("gds_trust_list_published", "pki_trust_sync", "info", True),
    "agent_auth_failure": ("gds_unauthorized_request", "security", "warning", True),
    "agent_unauthorized_pull": ("gds_unauthorized_request", "security", "warning", True),
    "mtls_client_identity_failure": ("gds_unauthorized_request", "security", "warning", True),
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return "<redacted-bytes>"
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in DROP_OR_REDACT_KEYS:
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = redact_secrets(item)
        return out
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        if "-----BEGIN " in value or "-----END " in value:
            return "<redacted-pem>"
        return value
    return _json_safe(value)


def truncate_text(value: str, max_len: int) -> str:
    if max_len <= 0 or len(value) <= max_len:
        return value
    return value[: max(0, max_len - 15)] + "...<truncated>"


def limit_raw(raw: dict[str, Any], max_raw_len: int) -> dict[str, Any]:
    safe = redact_secrets(raw)
    encoded = json.dumps(safe, ensure_ascii=True, separators=(",", ":"), default=str)
    if max_raw_len <= 0 or len(encoded) <= max_raw_len:
        return safe
    return {
        "truncated": True,
        "preview": truncate_text(encoded, max_raw_len),
    }


def _details(row: dict[str, Any]) -> dict[str, Any]:
    details = row.get("details_json") or {}
    if isinstance(details, str):
        try:
            parsed = json.loads(details)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return details if isinstance(details, dict) else {}


def _timestamp_from(values: dict[str, Any]) -> str:
    for key in ("created_at", "generated_at", "reported_at", "ts", "timestamp", "checked_at"):
        value = values.get(key)
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if value:
            return str(value)
    return utc_now_iso()


def _target_parts(target: str) -> dict[str, str]:
    parts = target.split(":")
    if len(parts) >= 3 and parts[0] in {"trustlist", "trustlist_artifact", "trustlist_artifact_sig", "trustlist_artifact_canonical"}:
        return {"trustlist_zone": parts[1], "trustlist_role": parts[2]}
    if len(parts) >= 2 and parts[0] == "certificate" and parts[1]:
        return {"certificate_id": parts[1]}
    return {}


def _safe_fields(row: dict[str, Any], details: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    merged = {**row, **details, **_target_parts(str(row.get("target") or ""))}
    for key in SAFE_FIELD_NAMES:
        value = merged.get(key)
        if value not in (None, ""):
            fields[key] = _json_safe(value)
    if "verify" in details and "mtls_verify_status" not in fields:
        fields["mtls_verify_status"] = details["verify"]
    return fields


def _base_event(
    *,
    event_name: str,
    event_category: str,
    severity: str,
    message: str,
    timestamp: str,
    raw: dict[str, Any],
    tags: dict[str, Any],
    max_message_len: int,
    max_raw_len: int,
) -> dict[str, Any]:
    payload = {
        "id": tags.get("event_id") or uuid4().hex,
        "timestamp": timestamp,
        "zone": ZONE,
        "source_type": SOURCE_TYPE,
        "sourcetype": SPLUNK_SOURCETYPE,
        "asset_name": ASSET_NAME,
        "asset_ip": ASSET_IP,
        "severity": severity,
        "protocol": "http",
        "event_category": event_category,
        "message": truncate_text(message, max_message_len),
        "raw": limit_raw(raw, max_raw_len),
        "tags": redact_secrets(tags),
    }
    payload["tags"]["gds_event"] = event_name
    return payload


def normalize_audit_event(row: dict[str, Any], *, max_message_len: int = 512, max_raw_len: int = 4096) -> dict[str, Any]:
    details = _details(row)
    audit_event_type = str(row.get("event_type") or "gds_audit_event")
    event_name, category, severity, alert_candidate = AUDIT_EVENT_MAP.get(
        audit_event_type,
        ("gds_audit_event", "audit", "info", False),
    )
    safe_fields = _safe_fields(row, details)
    tags = {
        "source_table": "audit_events",
        "audit_event_type": audit_event_type,
        "alert_candidate": str(alert_candidate).lower(),
        **safe_fields,
    }
    raw = {
        "audit_row": row,
        "details": details,
        "normalized_event": event_name,
    }
    return _base_event(
        event_name=event_name,
        event_category=category,
        severity=severity,
        message=f"{event_name}: {audit_event_type}",
        timestamp=_timestamp_from(row),
        raw=raw,
        tags=tags,
        max_message_len=max_message_len,
        max_raw_len=max_raw_len,
    )


def normalize_db_snapshot_event(snapshot: dict[str, Any], *, max_message_len: int = 512, max_raw_len: int = 4096) -> dict[str, Any]:
    ok = bool(snapshot.get("ok"))
    event_name = "gds_db_snapshot" if ok else "gds_db_disconnected"
    return _base_event(
        event_name=event_name,
        event_category="system_health" if ok else "error",
        severity="info" if ok else "critical",
        message=event_name,
        timestamp=_timestamp_from(snapshot),
        raw={"db_snapshot": snapshot},
        tags={
            "source_table": "gds_db_telemetry",
            "alert_candidate": "false" if ok else "true",
            "database": snapshot.get("database", ""),
            "db_host": snapshot.get("host", ""),
        },
        max_message_len=max_message_len,
        max_raw_len=max_raw_len,
    )


def normalize_db_health_event(health: dict[str, Any], *, max_message_len: int = 512, max_raw_len: int = 4096) -> dict[str, Any]:
    postgres = ((health.get("components") or {}).get("postgres") or {}) if isinstance(health, dict) else {}
    ok = bool(postgres.get("ok"))
    event_name = "gds_db_connected" if ok else "gds_db_disconnected"
    return _base_event(
        event_name=event_name,
        event_category="system_health" if ok else "error",
        severity="info" if ok else "critical",
        message=event_name,
        timestamp=utc_now_iso(),
        raw={"health": health},
        tags={
            "source_table": "gds_health",
            "alert_candidate": "false" if ok else "true",
            "postgres_ok": str(ok).lower(),
        },
        max_message_len=max_message_len,
        max_raw_len=max_raw_len,
    )


def normalize_heartbeat_event(health: dict[str, Any], *, max_message_len: int = 512, max_raw_len: int = 4096) -> dict[str, Any]:
    ok = bool(health.get("ok")) if isinstance(health, dict) else False
    return _base_event(
        event_name="gds_heartbeat",
        event_category="system_health" if ok else "error",
        severity="info" if ok else "warning",
        message="gds_heartbeat",
        timestamp=utc_now_iso(),
        raw={"health": health},
        tags={
            "source_table": "gds_health",
            "alert_candidate": "false" if ok else "true",
            "health_ok": str(ok).lower(),
        },
        max_message_len=max_message_len,
        max_raw_len=max_raw_len,
    )


def _payload_within_limit(events: list[dict[str, Any]], max_payload_bytes: int) -> list[dict[str, Any]]:
    if max_payload_bytes <= 0:
        return events
    encoded = json.dumps(events, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(encoded) <= max_payload_bytes:
        return events
    trimmed: list[dict[str, Any]] = []
    for event in events:
        candidate = [*trimmed, event]
        encoded = json.dumps(candidate, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) > max_payload_bytes:
            break
        trimmed.append(event)
    return trimmed or events[:1]


def read_bearer_token(token_file: str) -> str:
    try:
        with open(token_file, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def post_events(url: str, token: str, events: list[dict[str, Any]], timeout_seconds: int) -> None:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        import httpx

        with httpx.Client(timeout=float(timeout_seconds)) as client:
            res = client.post(url, json=events, headers=headers)
        res.raise_for_status()
        return
    except ModuleNotFoundError:
        pass

    from urllib import request

    body = json.dumps(events, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=float(timeout_seconds)) as res:
        if res.status >= 400:
            raise RuntimeError(f"collector returned status {res.status}")


class DmzCollectorSender:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_audit_id = 0
        self.last_token_warning_at = 0.0

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, name="gds-dmz-collector-sender", daemon=True)
        self.thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=timeout)

    def _initialize_last_audit_id(self) -> None:
        from .db import list_audit_events

        try:
            latest = list_audit_events(self.settings, limit=1)
            if latest:
                self.last_audit_id = int(latest[0].get("id") or 0)
        except Exception as exc:
            LOG.warning("dmz collector sender audit cursor init failed err=%s", exc.__class__.__name__)

    def _run(self) -> None:
        self._initialize_last_audit_id()
        next_health_at = 0.0
        next_db_snapshot_at = 0.0
        LOG.info("dmz collector sender started url=%s", self.settings.dmz_collector_url)
        while not self.stop_event.is_set():
            try:
                self._tick(time.time(), next_health_at, next_db_snapshot_at)
                now = time.time()
                if now >= next_health_at:
                    next_health_at = now + max(1, self.settings.dmz_collector_health_interval_seconds)
                if now >= next_db_snapshot_at:
                    next_db_snapshot_at = now + max(1, self.settings.dmz_collector_db_summary_interval_seconds)
            except Exception as exc:
                LOG.warning("dmz collector sender tick failed err=%s", exc.__class__.__name__)
            self.stop_event.wait(max(1, self.settings.dmz_collector_poll_interval_seconds))
        LOG.info("dmz collector sender stopped")

    def _tick(self, now: float, next_health_at: float, next_db_snapshot_at: float) -> None:
        from .checks import full_health
        from .db import gds_db_telemetry_snapshot, list_audit_events_after_id

        events: list[dict[str, Any]] = []
        max_message_len = self.settings.dmz_collector_max_message_len
        max_raw_len = self.settings.dmz_collector_max_raw_len

        try:
            audit_rows = list_audit_events_after_id(
                self.settings,
                self.last_audit_id,
                max(1, self.settings.dmz_collector_batch_size),
            )
            for row in audit_rows:
                events.append(normalize_audit_event(row, max_message_len=max_message_len, max_raw_len=max_raw_len))
                self.last_audit_id = max(self.last_audit_id, int(row.get("id") or self.last_audit_id))
        except Exception as exc:
            failure = {
                "ok": False,
                "checked_at": utc_now_iso(),
                "database": self.settings.pg_db,
                "host": self.settings.pg_host,
                "error_class": exc.__class__.__name__,
                "source": "audit_events_poll",
            }
            events.append(normalize_db_snapshot_event(failure, max_message_len=max_message_len, max_raw_len=max_raw_len))

        if now >= next_health_at:
            health = full_health(self.settings)
            events.append(normalize_heartbeat_event(health, max_message_len=max_message_len, max_raw_len=max_raw_len))
            events.append(normalize_db_health_event(health, max_message_len=max_message_len, max_raw_len=max_raw_len))

        if now >= next_db_snapshot_at:
            try:
                snapshot = gds_db_telemetry_snapshot(self.settings)
                events.append(normalize_db_snapshot_event(snapshot, max_message_len=max_message_len, max_raw_len=max_raw_len))
            except Exception as exc:
                failure = {
                    "ok": False,
                    "checked_at": utc_now_iso(),
                    "database": self.settings.pg_db,
                    "host": self.settings.pg_host,
                    "error_class": exc.__class__.__name__,
                }
                events.append(normalize_db_snapshot_event(failure, max_message_len=max_message_len, max_raw_len=max_raw_len))

        if events:
            self._send(events)

    def _send(self, events: list[dict[str, Any]]) -> None:
        token = read_bearer_token(self.settings.dmz_collector_token_file)
        if not token:
            now = time.time()
            if now - self.last_token_warning_at >= 60:
                self.last_token_warning_at = now
                LOG.warning("dmz collector sender skipped: bearer token file unavailable path=%s", self.settings.dmz_collector_token_file)
            return
        limited = _payload_within_limit(events, self.settings.dmz_collector_max_payload_bytes)
        try:
            post_events(
                self.settings.dmz_collector_url,
                token,
                limited,
                self.settings.dmz_collector_timeout_seconds,
            )
        except Exception as exc:
            LOG.warning("dmz collector sender post failed count=%s err=%s", len(limited), exc.__class__.__name__)


def start_dmz_collector_sender(settings: Settings) -> DmzCollectorSender | None:
    if not settings.dmz_collector_enabled:
        LOG.info("dmz collector sender disabled")
        return None
    sender = DmzCollectorSender(settings)
    sender.start()
    return sender
