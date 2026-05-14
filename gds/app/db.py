from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .config import Settings


ALLOWED_ZONES = {"OT", "DMZ", "IT"}
ALLOWED_ROLES = {"server", "southbound-client", "northbound-server", "scada-client", "client"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_conn(settings: Settings):
    return psycopg.connect(settings.pg_dsn, row_factory=dict_row)


def migrate(settings: Settings) -> None:
    sql = """
    CREATE TABLE IF NOT EXISTS applications (
      id BIGSERIAL PRIMARY KEY,
      application_uri TEXT NOT NULL UNIQUE,
      common_name TEXT NOT NULL,
      zone TEXT NOT NULL,
      role TEXT NOT NULL,
      runtime_instance_id TEXT,
      component_type TEXT,
      host TEXT,
      port INTEGER,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS certificates (
      id BIGSERIAL PRIMARY KEY,
      application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
      fingerprint_sha256 TEXT NOT NULL UNIQUE,
      serial_number TEXT,
      subject TEXT,
      issuer TEXT,
      not_before TIMESTAMPTZ,
      not_after TIMESTAMPTZ,
      pem TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      revoked_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS trust_lists (
      id BIGSERIAL PRIMARY KEY,
      zone TEXT NOT NULL,
      role TEXT NOT NULL,
      version INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      published_at TIMESTAMPTZ,
      UNIQUE(zone, role, version)
    );

    CREATE TABLE IF NOT EXISTS trust_list_members (
      id BIGSERIAL PRIMARY KEY,
      trust_list_id BIGINT NOT NULL REFERENCES trust_lists(id) ON DELETE CASCADE,
      certificate_id BIGINT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
      member_type TEXT NOT NULL DEFAULT 'application',
      UNIQUE(trust_list_id, certificate_id, member_type)
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id BIGSERIAL PRIMARY KEY,
      event_type TEXT NOT NULL,
      actor TEXT NOT NULL,
      target TEXT NOT NULL,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS trust_artifacts (
      id BIGSERIAL PRIMARY KEY,
      zone TEXT NOT NULL,
      role TEXT NOT NULL,
      trustlist_version INTEGER NOT NULL,
      artifact_revision INTEGER NOT NULL,
      artifact_json JSONB NOT NULL,
      artifact_sha256 TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      signer_key_id TEXT NOT NULL,
      signer_fingerprint_sha256 TEXT NOT NULL,
      generated_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(zone, role, artifact_revision)
    );

    CREATE TABLE IF NOT EXISTS component_profiles (
      id BIGSERIAL PRIMARY KEY,
      profile_name TEXT NOT NULL UNIQUE,
      runtime_family TEXT NOT NULL,
      component_type TEXT NOT NULL,
      certificate_format TEXT NOT NULL,
      trust_store_layout_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      runtime_semantics_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      compatibility_rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      enrollment_policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS certificate_requests (
      id BIGSERIAL PRIMARY KEY,
      request_id TEXT NOT NULL UNIQUE,
      application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
      runtime_instance_id TEXT,
      profile_name TEXT NOT NULL REFERENCES component_profiles(profile_name),
      source_interface TEXT NOT NULL,
      csr_pem TEXT NOT NULL,
      csr_fingerprint_sha256 TEXT NOT NULL,
      subject TEXT,
      uri_sans_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      dns_sans_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      ip_sans_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      validation_result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      requested_by TEXT NOT NULL DEFAULT 'unknown',
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS certificate_packages (
      id BIGSERIAL PRIMARY KEY,
      package_id TEXT NOT NULL UNIQUE,
      application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
      runtime_instance_id TEXT,
      request_id TEXT NOT NULL REFERENCES certificate_requests(request_id),
      certificate_id BIGINT REFERENCES certificates(id),
      generation INTEGER NOT NULL,
      profile_name TEXT NOT NULL REFERENCES component_profiles(profile_name),
      supersedes_package_id TEXT,
      supersedes_generation INTEGER,
      manifest_json JSONB NOT NULL,
      manifest_sha256 TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      compatibility_status TEXT NOT NULL DEFAULT 'UNKNOWN',
      lifecycle_state TEXT NOT NULL DEFAULT 'PACKAGED',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(application_id, profile_name, generation)
    );

    CREATE TABLE IF NOT EXISTS package_events (
      id BIGSERIAL PRIMARY KEY,
      package_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      actor TEXT NOT NULL,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS component_status (
      application_uri TEXT PRIMARY KEY,
      component_name TEXT,
      runtime_instance_id TEXT,
      zone TEXT,
      role TEXT,
      target TEXT,
      certificate_fingerprint_sha256 TEXT,
      certificate_not_before TIMESTAMPTZ,
      certificate_not_after TIMESTAMPTZ,
      days_until_expiry INTEGER,
      trust_artifact_version INTEGER,
      trust_artifact_revision INTEGER,
      trust_artifact_sha256 TEXT,
      crl_freshness_verified BOOLEAN NOT NULL DEFAULT false,
      last_pull_status TEXT,
      last_apply_status TEXT,
      last_renewal_status TEXT,
      private_key_exported BOOLEAN NOT NULL DEFAULT false,
      private_key_touched BOOLEAN NOT NULL DEFAULT false,
      runtime_write_enabled BOOLEAN NOT NULL DEFAULT false,
      status_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      reported_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS component_events (
      id BIGSERIAL PRIMARY KEY,
      application_uri TEXT NOT NULL,
      component_name TEXT,
      target TEXT,
      event_type TEXT NOT NULL,
      status TEXT,
      message TEXT,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute("ALTER TABLE applications ADD COLUMN IF NOT EXISTS runtime_instance_id TEXT")
            cur.execute("ALTER TABLE applications ADD COLUMN IF NOT EXISTS component_type TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_certificate_packages_application_profile ON certificate_packages(application_id, profile_name, generation DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_certificate_packages_lifecycle ON certificate_packages(lifecycle_state)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_package_events_package_created ON package_events(package_id, created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_component_status_updated ON component_status(updated_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_component_events_app_created ON component_events(application_uri, created_at DESC)")
        conn.commit()


def audit(settings: Settings, event_type: str, actor: str, target: str, details: dict[str, Any]) -> None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events(event_type, actor, target, details_json)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (event_type, actor, target, json.dumps(details)),
            )
        conn.commit()


def upsert_component_status(settings: Settings, payload: dict[str, Any]) -> dict[str, Any]:
    application_uri = str(payload.get("application_uri") or "").strip()
    if not application_uri:
        raise ValueError("application_uri required")
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO component_status(
                  application_uri, component_name, runtime_instance_id, zone, role, target,
                  certificate_fingerprint_sha256, certificate_not_before, certificate_not_after,
                  days_until_expiry, trust_artifact_version, trust_artifact_revision,
                  trust_artifact_sha256, crl_freshness_verified, last_pull_status,
                  last_apply_status, last_renewal_status, private_key_exported,
                  private_key_touched, runtime_write_enabled, status_json, reported_at,
                  updated_at
                )
                VALUES (
                  %(application_uri)s, %(component_name)s, %(runtime_instance_id)s, %(zone)s, %(role)s, %(target)s,
                  %(certificate_fingerprint_sha256)s, %(certificate_not_before)s, %(certificate_not_after)s,
                  %(days_until_expiry)s, %(trust_artifact_version)s, %(trust_artifact_revision)s,
                  %(trust_artifact_sha256)s, %(crl_freshness_verified)s, %(last_pull_status)s,
                  %(last_apply_status)s, %(last_renewal_status)s, %(private_key_exported)s,
                  %(private_key_touched)s, %(runtime_write_enabled)s, %(status_json)s::jsonb, %(reported_at)s,
                  now()
                )
                ON CONFLICT(application_uri) DO UPDATE SET
                  component_name=excluded.component_name,
                  runtime_instance_id=excluded.runtime_instance_id,
                  zone=excluded.zone,
                  role=excluded.role,
                  target=excluded.target,
                  certificate_fingerprint_sha256=excluded.certificate_fingerprint_sha256,
                  certificate_not_before=excluded.certificate_not_before,
                  certificate_not_after=excluded.certificate_not_after,
                  days_until_expiry=excluded.days_until_expiry,
                  trust_artifact_version=excluded.trust_artifact_version,
                  trust_artifact_revision=excluded.trust_artifact_revision,
                  trust_artifact_sha256=excluded.trust_artifact_sha256,
                  crl_freshness_verified=excluded.crl_freshness_verified,
                  last_pull_status=excluded.last_pull_status,
                  last_apply_status=excluded.last_apply_status,
                  last_renewal_status=excluded.last_renewal_status,
                  private_key_exported=excluded.private_key_exported,
                  private_key_touched=excluded.private_key_touched,
                  runtime_write_enabled=excluded.runtime_write_enabled,
                  status_json=excluded.status_json,
                  reported_at=excluded.reported_at,
                  updated_at=now()
                RETURNING *
                """,
                {
                    "application_uri": application_uri,
                    "component_name": payload.get("component_name"),
                    "runtime_instance_id": payload.get("runtime_instance_id"),
                    "zone": payload.get("zone"),
                    "role": payload.get("role"),
                    "target": payload.get("target"),
                    "certificate_fingerprint_sha256": payload.get("certificate_fingerprint_sha256"),
                    "certificate_not_before": payload.get("certificate_not_before"),
                    "certificate_not_after": payload.get("certificate_not_after"),
                    "days_until_expiry": payload.get("days_until_expiry"),
                    "trust_artifact_version": payload.get("trust_artifact_version"),
                    "trust_artifact_revision": payload.get("trust_artifact_revision"),
                    "trust_artifact_sha256": payload.get("trust_artifact_sha256"),
                    "crl_freshness_verified": bool(payload.get("crl_freshness_verified", False)),
                    "last_pull_status": payload.get("last_pull_status"),
                    "last_apply_status": payload.get("last_apply_status"),
                    "last_renewal_status": payload.get("last_renewal_status"),
                    "private_key_exported": bool(payload.get("private_key_exported", False)),
                    "private_key_touched": bool(payload.get("private_key_touched", False)),
                    "runtime_write_enabled": bool(payload.get("runtime_write_enabled", False)),
                    "status_json": json.dumps(payload, default=str),
                    "reported_at": payload.get("timestamp") or utc_now(),
                },
            )
            row = cur.fetchone()
        conn.commit()
        return row


def get_component_status(settings: Settings, application_uri: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM component_status WHERE application_uri = %s", (application_uri,))
            return cur.fetchone()


def list_component_statuses(settings: Settings, limit: int = 200) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM component_status ORDER BY updated_at DESC LIMIT %s", (limit,))
            return cur.fetchall()


def insert_component_event(settings: Settings, payload: dict[str, Any]) -> dict[str, Any]:
    application_uri = str(payload.get("application_uri") or "").strip()
    if not application_uri:
        raise ValueError("application_uri required")
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO component_events(
                  application_uri, component_name, target, event_type, status, message, details_json
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                RETURNING *
                """,
                (
                    application_uri,
                    payload.get("component_name"),
                    payload.get("target"),
                    payload.get("event_type"),
                    payload.get("status"),
                    payload.get("message"),
                    json.dumps(payload.get("details") or {}, default=str),
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def list_component_events(settings: Settings, application_uri: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            if application_uri:
                cur.execute(
                    "SELECT * FROM component_events WHERE application_uri = %s ORDER BY id DESC LIMIT %s",
                    (application_uri, limit),
                )
            else:
                cur.execute("SELECT * FROM component_events ORDER BY id DESC LIMIT %s", (limit,))
            return cur.fetchall()


def upsert_application(
    settings: Settings,
    application_uri: str,
    common_name: str,
    zone: str,
    role: str,
    host: str | None,
    port: int | None,
    status: str = "active",
    runtime_instance_id: str | None = None,
    component_type: str | None = None,
) -> dict[str, Any]:
    runtime_instance_id = runtime_instance_id or application_uri
    component_type = component_type or ("server" if "server" in role else "client")
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO applications(
                  application_uri, common_name, zone, role, runtime_instance_id, component_type,
                  host, port, status, last_seen_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT(application_uri) DO UPDATE SET
                  common_name=excluded.common_name,
                  zone=excluded.zone,
                  role=excluded.role,
                  runtime_instance_id=COALESCE(applications.runtime_instance_id, excluded.runtime_instance_id),
                  component_type=COALESCE(applications.component_type, excluded.component_type),
                  host=excluded.host,
                  port=excluded.port,
                  status=excluded.status,
                  updated_at=now()
                RETURNING *
                """,
                (
                    application_uri,
                    common_name,
                    zone,
                    role,
                    runtime_instance_id,
                    component_type,
                    host,
                    port,
                    status,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def list_applications(settings: Settings) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM applications ORDER BY id")
            return cur.fetchall()


def get_application(settings: Settings, app_id: int) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM applications WHERE id = %s", (app_id,))
            return cur.fetchone()


def get_application_by_uri(settings: Settings, application_uri: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM applications WHERE application_uri = %s", (application_uri,))
            return cur.fetchone()


def heartbeat_application(settings: Settings, app_id: int) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE applications
                SET last_seen_at = now(), updated_at = now(), status = 'active'
                WHERE id = %s
                RETURNING *
                """,
                (app_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def insert_certificate(
    settings: Settings,
    application_id: int,
    fingerprint_sha256: str,
    serial_number: str | None,
    subject: str | None,
    issuer: str | None,
    not_before: datetime | None,
    not_after: datetime | None,
    pem: str,
    status: str = "active",
) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO certificates(
                  application_id, fingerprint_sha256, serial_number, subject, issuer,
                  not_before, not_after, pem, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(fingerprint_sha256) DO NOTHING
                RETURNING *
                """,
                (
                    application_id,
                    fingerprint_sha256,
                    serial_number,
                    subject,
                    issuer,
                    not_before,
                    not_after,
                    pem,
                    status,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def list_certificates(settings: Settings) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  c.*,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.runtime_instance_id,
                  a.component_type
                FROM certificates c
                JOIN applications a ON a.id = c.application_id
                ORDER BY c.id
                """
            )
            return cur.fetchall()


def get_certificate(settings: Settings, cert_id: int) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  c.*,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.runtime_instance_id,
                  a.component_type
                FROM certificates c
                JOIN applications a ON a.id = c.application_id
                WHERE c.id = %s
                """,
                (cert_id,),
            )
            return cur.fetchone()


def get_certificate_by_fingerprint(settings: Settings, fingerprint_sha256: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  c.*,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.runtime_instance_id,
                  a.component_type
                FROM certificates c
                JOIN applications a ON a.id = c.application_id
                WHERE c.fingerprint_sha256 = %s
                """,
                (fingerprint_sha256,),
            )
            return cur.fetchone()


def _trustlist_application_filter(zone: str, role: str) -> tuple[str, tuple[Any, ...]]:
    if zone == "OT" and role == "server":
        return (
            """
            (
              (a.zone = %s AND a.role = %s)
              OR (a.zone = %s AND a.role = %s)
            )
            """,
            ("DMZ", "southbound-client", "OT", "scada-client"),
        )
    return "a.zone = %s AND a.role = %s", (zone, role)


def _active_certificate_id_for_application(cur: Any, application_id: int) -> int | None:
    cur.execute(
        """
        SELECT c.id AS certificate_id
        FROM certificate_packages cp
        JOIN certificates c ON c.id = cp.certificate_id
        WHERE cp.application_id = %s
          AND cp.lifecycle_state = 'ACTIVATED'
          AND cp.status = 'active'
          AND c.status = 'active'
          AND c.revoked_at IS NULL
        ORDER BY cp.created_at DESC, cp.generation DESC, c.id DESC
        LIMIT 1
        """,
        (application_id,),
    )
    row = cur.fetchone()
    if row:
        return int(row["certificate_id"])

    cur.execute(
        """
        SELECT c.id AS certificate_id
        FROM certificates c
        WHERE c.application_id = %s
          AND c.status = 'active'
          AND c.revoked_at IS NULL
        ORDER BY c.created_at DESC, c.not_before DESC, c.id DESC
        LIMIT 1
        """,
        (application_id,),
    )
    row = cur.fetchone()
    return int(row["certificate_id"]) if row else None


def _desired_trustlist_certificate_ids(cur: Any, zone: str, role: str) -> list[int]:
    app_filter, params = _trustlist_application_filter(zone, role)
    cur.execute(
        f"""
        SELECT a.id
        FROM applications a
        WHERE a.status = 'active'
          AND {app_filter}
        ORDER BY a.application_uri
        """,
        params,
    )
    app_rows = cur.fetchall()
    certificate_ids: list[int] = []
    for app in app_rows:
        cert_id = _active_certificate_id_for_application(cur, int(app["id"]))
        if cert_id is not None:
            certificate_ids.append(cert_id)
    return certificate_ids


def build_trust_list(settings: Settings, zone: str, role: str) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(version), 0) AS max_version FROM trust_lists WHERE zone = %s AND role = %s",
                (zone, role),
            )
            next_version = int(cur.fetchone()["max_version"]) + 1

            cur.execute(
                """
                INSERT INTO trust_lists(zone, role, version, status, published_at)
                VALUES (%s, %s, %s, 'active', now())
                RETURNING *
                """,
                (zone, role, next_version),
            )
            trust_list = cur.fetchone()

            certificate_ids = _desired_trustlist_certificate_ids(cur, zone, role)

            for cert_id in certificate_ids:
                cur.execute(
                    """
                    INSERT INTO trust_list_members(trust_list_id, certificate_id, member_type)
                    VALUES (%s, %s, 'application')
                    ON CONFLICT(trust_list_id, certificate_id, member_type) DO NOTHING
                    """,
                    (trust_list["id"], cert_id),
                )
        conn.commit()
        return trust_list


def ensure_trust_list_current(settings: Settings, zone: str, role: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            desired = sorted(_desired_trustlist_certificate_ids(cur, zone, role))
            cur.execute(
                """
                SELECT * FROM trust_lists
                WHERE zone = %s AND role = %s
                ORDER BY version DESC
                LIMIT 1
                """,
                (zone, role),
            )
            trust_list = cur.fetchone()
            if trust_list:
                cur.execute(
                    """
                    SELECT certificate_id
                    FROM trust_list_members
                    WHERE trust_list_id = %s AND member_type = 'application'
                    ORDER BY certificate_id
                    """,
                    (trust_list["id"],),
                )
                current = sorted(int(row["certificate_id"]) for row in cur.fetchall())
                if current == desired:
                    return trust_list
    return build_trust_list(settings, zone, role)


def get_latest_trust_list_with_certs(settings: Settings, zone: str, role: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM trust_lists
                WHERE zone = %s AND role = %s
                ORDER BY version DESC
                LIMIT 1
                """,
                (zone, role),
            )
            trust_list = cur.fetchone()
            if not trust_list:
                return None, []

            cur.execute(
                """
                SELECT
                  c.id AS certificate_id,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.component_type,
                  c.fingerprint_sha256,
                  c.pem
                FROM trust_list_members tlm
                JOIN certificates c ON c.id = tlm.certificate_id
                JOIN applications a ON a.id = c.application_id
                WHERE tlm.trust_list_id = %s
                ORDER BY a.application_uri
                """,
                (trust_list["id"],),
            )
            certs = cur.fetchall()
            return trust_list, certs


def list_audit_events(settings: Settings, limit: int = 200) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            return cur.fetchall()


def list_audit_events_by_type(settings: Settings, event_types: list[str], limit: int = 1000) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_events
                WHERE event_type = ANY(%s)
                ORDER BY id DESC
                LIMIT %s
                """,
                (event_types, limit),
            )
            return cur.fetchall()


def count_audit_events_by_reason(settings: Settings, event_type: str) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  COALESCE(details_json->>'reason', 'unknown') AS reason,
                  COUNT(*) AS count
                FROM audit_events
                WHERE event_type = %s
                GROUP BY COALESCE(details_json->>'reason', 'unknown')
                ORDER BY count DESC, reason
                """,
                (event_type,),
            )
            return cur.fetchall()


def get_latest_trust_artifact(settings: Settings, zone: str, role: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM trust_artifacts
                WHERE zone = %s AND role = %s
                ORDER BY artifact_revision DESC
                LIMIT 1
                """,
                (zone, role),
            )
            return cur.fetchone()


def insert_trust_artifact(
    settings: Settings,
    zone: str,
    role: str,
    trustlist_version: int,
    artifact_json: dict[str, Any],
    artifact_sha256: str,
    signature_base64: str,
    signer_key_id: str,
    signer_fingerprint_sha256: str,
    generated_at: datetime,
    expires_at: datetime,
    reason: str,
) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO trust_artifacts(
                  zone, role, trustlist_version, artifact_revision, artifact_json,
                  artifact_sha256, signature_base64, signer_key_id, signer_fingerprint_sha256,
                  generated_at, expires_at, reason
                )
                VALUES (
                  %s, %s, %s,
                  (SELECT COALESCE(MAX(artifact_revision), 0) + 1 FROM trust_artifacts WHERE zone = %s AND role = %s),
                  %s::jsonb, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING *
                """,
                (
                    zone,
                    role,
                    trustlist_version,
                    zone,
                    role,
                    json.dumps(artifact_json),
                    artifact_sha256,
                    signature_base64,
                    signer_key_id,
                    signer_fingerprint_sha256,
                    generated_at,
                    expires_at,
                    reason,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def list_trustlist_targets(settings: Settings) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT zone, role
                FROM trust_lists
                ORDER BY zone, role
                """
            )
            return cur.fetchall()


def list_trust_artifact_history(settings: Settings, zone: str, role: str, limit: int = 100) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM trust_artifacts
                WHERE zone = %s AND role = %s
                ORDER BY artifact_revision DESC
                LIMIT %s
                """,
                (zone, role, limit),
            )
            return cur.fetchall()


def upsert_component_profile(settings: Settings, profile: dict[str, Any]) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO component_profiles(
                  profile_name, runtime_family, component_type, certificate_format,
                  trust_store_layout_json, runtime_semantics_json, compatibility_rules_json,
                  enrollment_policy_json, status
                )
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s)
                ON CONFLICT(profile_name) DO UPDATE SET
                  runtime_family=excluded.runtime_family,
                  component_type=excluded.component_type,
                  certificate_format=excluded.certificate_format,
                  trust_store_layout_json=excluded.trust_store_layout_json,
                  runtime_semantics_json=excluded.runtime_semantics_json,
                  compatibility_rules_json=excluded.compatibility_rules_json,
                  enrollment_policy_json=excluded.enrollment_policy_json,
                  status=excluded.status,
                  updated_at=now()
                RETURNING *
                """,
                (
                    profile["profile_name"],
                    profile["runtime_family"],
                    profile["component_type"],
                    profile["certificate_format"],
                    json.dumps(profile.get("trust_store_layout_json", {})),
                    json.dumps(profile.get("runtime_semantics_json", {})),
                    json.dumps(profile.get("compatibility_rules_json", {})),
                    json.dumps(profile.get("enrollment_policy_json", {})),
                    profile.get("status", "active"),
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def seed_component_profiles(settings: Settings, profiles: list[dict[str, Any]]) -> None:
    for profile in profiles:
        upsert_component_profile(settings, profile)


def get_component_profile(settings: Settings, profile_name: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM component_profiles WHERE profile_name = %s", (profile_name,))
            return cur.fetchone()


def list_component_profiles(settings: Settings) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM component_profiles ORDER BY profile_name")
            return cur.fetchall()


def insert_certificate_request(
    settings: Settings,
    *,
    request_id: str,
    application_id: int,
    runtime_instance_id: str | None,
    profile_name: str,
    source_interface: str,
    csr_pem: str,
    csr_fingerprint_sha256: str,
    subject: str | None,
    uri_sans: list[str],
    dns_sans: list[str],
    ip_sans: list[str],
    validation_result: dict[str, Any],
    requested_by: str,
    status_value: str,
) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO certificate_requests(
                  request_id, application_id, runtime_instance_id, profile_name, source_interface,
                  csr_pem, csr_fingerprint_sha256, subject, uri_sans_json, dns_sans_json,
                  ip_sans_json, validation_result_json, requested_by, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
                RETURNING *
                """,
                (
                    request_id,
                    application_id,
                    runtime_instance_id,
                    profile_name,
                    source_interface,
                    csr_pem,
                    csr_fingerprint_sha256,
                    subject,
                    json.dumps(uri_sans),
                    json.dumps(dns_sans),
                    json.dumps(ip_sans),
                    json.dumps(validation_result),
                    requested_by,
                    status_value,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def update_certificate_request_status(settings: Settings, request_id: str, status_value: str, validation_result: dict[str, Any] | None = None) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            if validation_result is None:
                cur.execute(
                    """
                    UPDATE certificate_requests
                    SET status = %s, updated_at = now()
                    WHERE request_id = %s
                    RETURNING *
                    """,
                    (status_value, request_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE certificate_requests
                    SET status = %s, validation_result_json = %s::jsonb, updated_at = now()
                    WHERE request_id = %s
                    RETURNING *
                    """,
                    (status_value, json.dumps(validation_result), request_id),
                )
            row = cur.fetchone()
        conn.commit()
        return row


def get_certificate_request(settings: Settings, request_id: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cr.*, a.application_uri, a.common_name, a.zone, a.role, a.component_type
                FROM certificate_requests cr
                JOIN applications a ON a.id = cr.application_id
                WHERE cr.request_id = %s
                """,
                (request_id,),
            )
            return cur.fetchone()


def get_certificate_request_by_csr(settings: Settings, csr_fingerprint_sha256: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM certificate_requests
                WHERE csr_fingerprint_sha256 = %s
                  AND status NOT IN ('FAILED', 'REJECTED', 'DRY_RUN_VALIDATED', 'DRY_RUN_REJECTED')
                ORDER BY id DESC
                LIMIT 1
                """,
                (csr_fingerprint_sha256,),
            )
            return cur.fetchone()


def insert_certificate_package(
    settings: Settings,
    *,
    package_id: str,
    application_id: int,
    runtime_instance_id: str | None,
    request_id: str,
    certificate_id: int | None,
    profile_name: str,
    manifest_json: dict[str, Any],
    manifest_sha256: str,
    signature_base64: str,
    compatibility_status: str,
    lifecycle_state: str,
    generation: int | None = None,
    supersedes_package_id: str | None = None,
    supersedes_generation: int | None = None,
) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            if generation is None:
                previous = get_latest_certificate_package_for_application(settings, application_id, profile_name)
                generation = int(previous["generation"]) + 1 if previous else 1
                supersedes_package_id = previous["package_id"] if previous else None
                supersedes_generation = previous["generation"] if previous else None
            cur.execute(
                """
                INSERT INTO certificate_packages(
                  package_id, application_id, runtime_instance_id, request_id, certificate_id,
                  generation, profile_name, supersedes_package_id, supersedes_generation,
                  manifest_json, manifest_sha256, signature_base64, compatibility_status,
                  lifecycle_state
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    package_id,
                    application_id,
                    runtime_instance_id,
                    request_id,
                    certificate_id,
                    generation,
                    profile_name,
                    supersedes_package_id,
                    supersedes_generation,
                    json.dumps(manifest_json),
                    manifest_sha256,
                    signature_base64,
                    compatibility_status,
                    lifecycle_state,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def get_latest_certificate_package_for_application(settings: Settings, application_id: int, profile_name: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM certificate_packages
                WHERE application_id = %s AND profile_name = %s
                ORDER BY generation DESC
                LIMIT 1
                """,
                (application_id, profile_name),
            )
            return cur.fetchone()


def get_certificate_package(settings: Settings, package_id: str) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cp.*, a.application_uri, a.common_name, a.zone, a.role, a.component_type
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                WHERE cp.package_id = %s
                """,
                (package_id,),
            )
            return cur.fetchone()


def list_certificate_packages_for_certificate(settings: Settings, certificate_id: int) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cp.*, a.application_uri, a.common_name, a.zone, a.role, a.component_type
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                WHERE cp.certificate_id = %s
                ORDER BY cp.generation DESC
                """,
                (certificate_id,),
            )
            return cur.fetchall()


def mark_certificate_revoked(settings: Settings, certificate_id: int) -> dict[str, Any] | None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE certificates
                SET status = 'revoked',
                    revoked_at = COALESCE(revoked_at, now())
                WHERE id = %s
                RETURNING *
                """,
                (certificate_id,),
            )
            row = cur.fetchone()
        conn.commit()
        return row


def list_certificate_packages(
    settings: Settings,
    *,
    application_uri: str | None = None,
    runtime_instance_id: str | None = None,
    profile_name: str | None = None,
    lifecycle_state: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    filters: list[str] = []
    params: list[Any] = []
    if application_uri:
        filters.append("a.application_uri = %s")
        params.append(application_uri)
    if runtime_instance_id:
        filters.append("cp.runtime_instance_id = %s")
        params.append(runtime_instance_id)
    if profile_name:
        filters.append("cp.profile_name = %s")
        params.append(profile_name)
    if lifecycle_state:
        filters.append("cp.lifecycle_state = %s")
        params.append(lifecycle_state)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    params.append(limit)
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                  cp.package_id,
                  cp.application_id,
                  cp.runtime_instance_id,
                  cp.request_id,
                  cp.certificate_id,
                  cp.generation,
                  cp.profile_name,
                  cp.supersedes_package_id,
                  cp.supersedes_generation,
                  cp.manifest_sha256,
                  cp.compatibility_status,
                  cp.lifecycle_state,
                  cp.status,
                  cp.created_at,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.component_type
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                {where}
                ORDER BY a.application_uri, cp.profile_name, cp.generation DESC
                LIMIT %s
                """,
                tuple(params),
            )
            return cur.fetchall()


def list_certificate_packages_for_lineage(settings: Settings, application_id: int, profile_name: str) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  cp.package_id,
                  cp.application_id,
                  cp.runtime_instance_id,
                  cp.request_id,
                  cp.certificate_id,
                  cp.generation,
                  cp.profile_name,
                  cp.supersedes_package_id,
                  cp.supersedes_generation,
                  cp.manifest_sha256,
                  cp.compatibility_status,
                  cp.lifecycle_state,
                  cp.status,
                  cp.created_at,
                  a.application_uri,
                  a.common_name,
                  a.zone,
                  a.role,
                  a.component_type
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                WHERE cp.application_id = %s AND cp.profile_name = %s
                ORDER BY cp.generation DESC
                """,
                (application_id, profile_name),
            )
            return cur.fetchall()


def list_package_events(settings: Settings, package_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM package_events
                WHERE package_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (package_id, limit),
            )
            return cur.fetchall()


PACKAGE_LIFECYCLE_ORDER = {
    "ISSUED": 10,
    "PACKAGED": 20,
    "PULLED": 30,
    "VERIFIED": 40,
    "STAGED": 50,
    "APPROVED": 60,
    "ACTIVATED": 70,
    "ROLLED_BACK": 80,
    "REVOKED": 90,
    "EXPIRED": 100,
}


def update_certificate_package_lifecycle(
    settings: Settings,
    package_id: str,
    lifecycle_state: str,
    actor: str,
    details: dict[str, Any],
) -> dict[str, Any] | None:
    lifecycle_state = lifecycle_state.upper()
    if lifecycle_state not in PACKAGE_LIFECYCLE_ORDER:
        raise ValueError(f"unsupported package lifecycle state: {lifecycle_state}")
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT lifecycle_state FROM certificate_packages WHERE package_id = %s", (package_id,))
            current = cur.fetchone()
            if not current:
                return None
            current_state = str(current["lifecycle_state"]).upper()
            target_state = lifecycle_state
            if PACKAGE_LIFECYCLE_ORDER.get(target_state, -1) < PACKAGE_LIFECYCLE_ORDER.get(current_state, -1):
                target_state = current_state
                details = dict(details)
                details["requested_lifecycle_state"] = lifecycle_state
                details["transition_ignored"] = "non_regressive_lifecycle_state"
            cur.execute(
                """
                UPDATE certificate_packages
                SET lifecycle_state = %s,
                    status = CASE WHEN %s = 'REVOKED' THEN 'revoked' ELSE status END
                WHERE package_id = %s
                RETURNING *
                """,
                (target_state, target_state, package_id),
            )
            row = cur.fetchone()
            cur.execute(
                """
                INSERT INTO package_events(package_id, event_type, actor, details_json)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (package_id, f"package_{lifecycle_state.lower()}", actor, json.dumps(details)),
            )
        conn.commit()
        return row


def package_lifecycle_telemetry(settings: Settings) -> dict[str, Any]:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT lifecycle_state, COUNT(*) AS count
                FROM certificate_packages
                GROUP BY lifecycle_state
                ORDER BY lifecycle_state
                """
            )
            by_state = cur.fetchall()
            cur.execute(
                """
                SELECT compatibility_status, COUNT(*) AS count
                FROM certificate_packages
                GROUP BY compatibility_status
                ORDER BY compatibility_status
                """
            )
            by_compatibility = cur.fetchall()
            cur.execute(
                """
                SELECT
                  a.application_uri,
                  cp.profile_name,
                  MAX(cp.generation) AS latest_generation,
                  COUNT(*) AS package_count
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                GROUP BY a.application_uri, cp.profile_name
                ORDER BY a.application_uri, cp.profile_name
                """
            )
            lineages = cur.fetchall()
            cur.execute(
                """
                SELECT
                  cp.package_id,
                  cp.generation,
                  cp.profile_name,
                  cp.lifecycle_state,
                  cp.compatibility_status,
                  cp.created_at,
                  a.application_uri,
                  a.runtime_instance_id,
                  c.fingerprint_sha256,
                  c.serial_number,
                  c.not_after,
                  EXTRACT(EPOCH FROM (c.not_after - now())) / 86400.0 AS days_remaining
                FROM certificate_packages cp
                JOIN applications a ON a.id = cp.application_id
                LEFT JOIN certificates c ON c.id = cp.certificate_id
                ORDER BY cp.created_at DESC
                LIMIT 25
                """
            )
            latest = cur.fetchall()
    return {
        "by_lifecycle_state": by_state,
        "by_compatibility_status": by_compatibility,
        "lineages": lineages,
        "latest_packages": latest,
    }


def insert_package_event(settings: Settings, package_id: str, event_type: str, actor: str, details: dict[str, Any]) -> None:
    with get_conn(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO package_events(package_id, event_type, actor, details_json)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (package_id, event_type, actor, json.dumps(details)),
            )
        conn.commit()
