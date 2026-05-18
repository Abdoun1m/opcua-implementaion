from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.dmz_collector_sender import (  # noqa: E402
    normalize_audit_event,
    normalize_db_health_event,
    normalize_db_snapshot_event,
    redact_secrets,
)


class DmzCollectorSenderTests(unittest.TestCase):
    def test_certificate_issued_audit_row(self) -> None:
        event = normalize_audit_event(
            {
                "id": 7,
                "event_type": "certificate_issued",
                "actor": "dmz-gateway",
                "target": "certificate:42",
                "created_at": "2026-05-18T00:00:00Z",
                "details_json": {
                    "request_id": "req-1",
                    "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
                    "fingerprint_sha256": "abc123",
                },
            }
        )
        self.assertEqual(event["source_type"], "gds")
        self.assertEqual(event["sourcetype"], "labshock:dmz:gds")
        self.assertEqual(event["event_category"], "certificate_lifecycle")
        self.assertEqual(event["tags"]["gds_event"], "gds_certificate_issued")
        self.assertEqual(event["tags"]["certificate_id"], "42")
        self.assertEqual(event["tags"]["fingerprint_sha256"], "abc123")

    def test_artifact_regenerated_audit_row(self) -> None:
        event = normalize_audit_event(
            {
                "id": 8,
                "event_type": "artifact_regenerated",
                "actor": "system",
                "target": "trustlist_artifact:OT:server",
                "created_at": "2026-05-18T00:01:00Z",
                "details_json": {"version": 3, "artifact_revision": 7, "artifact_sha256": "def456"},
            }
        )
        self.assertEqual(event["event_category"], "pki_trust_sync")
        self.assertEqual(event["tags"]["gds_event"], "gds_trust_list_published")
        self.assertEqual(event["tags"]["trustlist_zone"], "OT")
        self.assertEqual(event["tags"]["trustlist_role"], "server")
        self.assertEqual(event["tags"]["artifact_revision"], 7)

    def test_agent_auth_failure_audit_row(self) -> None:
        event = normalize_audit_event(
            {
                "id": 9,
                "event_type": "agent_auth_failure",
                "actor": "dmz-gateway",
                "target": "artifact_read:OT:server:",
                "details_json": {"reason": "invalid_token", "source_ip": "192.168.10.20"},
            }
        )
        self.assertEqual(event["event_category"], "security")
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["tags"]["gds_event"], "gds_unauthorized_request")
        self.assertEqual(event["tags"]["alert_candidate"], "true")
        self.assertEqual(event["tags"]["source_ip"], "192.168.10.20")

    def test_db_snapshot_success(self) -> None:
        event = normalize_db_snapshot_event(
            {
                "ok": True,
                "checked_at": "2026-05-18T00:02:00Z",
                "database": "labshock_gds",
                "host": "192.168.10.31",
                "tables": {"audit_events": {"ok": True, "row_count": 10, "latest_id": 10}},
            }
        )
        self.assertEqual(event["tags"]["gds_event"], "gds_db_snapshot")
        self.assertEqual(event["event_category"], "system_health")
        self.assertEqual(event["severity"], "info")

    def test_db_health_failure(self) -> None:
        event = normalize_db_health_event(
            {
                "ok": False,
                "components": {
                    "postgres": {"ok": False, "detail": "postgres check failed: timeout"},
                    "vault": {"ok": True},
                    "config_files": {"ok": True},
                },
            }
        )
        self.assertEqual(event["tags"]["gds_event"], "gds_db_disconnected")
        self.assertEqual(event["event_category"], "error")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["tags"]["alert_candidate"], "true")

    def test_redaction_removes_secret_material(self) -> None:
        redacted = redact_secrets(
            {
                "token": "s.secret",
                "role_id": "role-value",
                "secret_id": "secret-value",
                "password": "password-value",
                "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
                "crl_base64": "abcd",
                "safe": {"fingerprint_sha256": "abc123"},
            }
        )
        serialized = str(redacted)
        self.assertNotIn("s.secret", serialized)
        self.assertNotIn("role-value", serialized)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("password-value", serialized)
        self.assertNotIn("BEGIN PRIVATE KEY", serialized)
        self.assertNotIn("BEGIN CERTIFICATE", serialized)
        self.assertNotIn("BEGIN CERTIFICATE REQUEST", serialized)
        self.assertNotIn("abcd", serialized)
        self.assertEqual(redacted["safe"]["fingerprint_sha256"], "abc123")


if __name__ == "__main__":
    unittest.main()
