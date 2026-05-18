#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PORT="${GDS_DMZ_COLLECTOR_TEST_PORT:-19090}"
REQUEST_FILE="$TMP_DIR/request.json"
TOKEN_FILE="$TMP_DIR/dmz-collector-token"

cleanup() {
  if [ -n "${MOCK_PID:-}" ]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

printf 'lab-test-token\n' > "$TOKEN_FILE"

REQUEST_FILE="$REQUEST_FILE" PORT="$PORT" python - <<'PY' &
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

request_file = os.environ["REQUEST_FILE"]
port = int(os.environ["PORT"])


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        with open(request_file, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "path": self.path,
                    "authorization": self.headers.get("Authorization", ""),
                    "body": body,
                },
                handle,
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"accepted":3,"rejected":0,"queued":3,"errors":[]}')

    def log_message(self, _format, *args):
        return


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
MOCK_PID="$!"
sleep 1

PYTHONPATH="$ROOT_DIR/gds" TOKEN_FILE="$TOKEN_FILE" PORT="$PORT" python - <<'PY'
import os

from app.dmz_collector_sender import (
    normalize_audit_event,
    normalize_db_snapshot_event,
    normalize_heartbeat_event,
    post_events,
    read_bearer_token,
)

port = os.environ["PORT"]
token = read_bearer_token(os.environ["TOKEN_FILE"])
events = [
    normalize_audit_event(
        {
            "id": 1,
            "event_type": "certificate_issued",
            "actor": "dmz-gateway",
            "target": "certificate:42",
            "details_json": {
                "request_id": "req-1",
                "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
                "fingerprint_sha256": "abc123",
            },
        }
    ),
    normalize_audit_event(
        {
            "id": 2,
            "event_type": "agent_auth_failure",
            "actor": "dmz-gateway",
            "target": "artifact_read:OT:server:",
            "details_json": {"reason": "invalid_token", "source_ip": "192.168.10.20"},
        }
    ),
    normalize_db_snapshot_event(
        {
            "ok": True,
            "database": "labshock_gds",
            "host": "192.168.10.31",
            "tables": {"audit_events": {"ok": True, "row_count": 2, "latest_id": 2}},
        }
    ),
    normalize_heartbeat_event({"ok": True, "components": {"postgres": {"ok": True}}}),
]
post_events(f"http://127.0.0.1:{port}/gds/events", token, events, 3)
PY

REQUEST_FILE="$REQUEST_FILE" python - <<'PY'
import json
import os
import sys

with open(os.environ["REQUEST_FILE"], "r", encoding="utf-8") as handle:
    captured = json.load(handle)

body = json.loads(captured["body"])
if captured["path"] != "/gds/events":
    print(f"[FAIL] unexpected_path={captured['path']}")
    sys.exit(1)
if captured["authorization"] != "Bearer lab-test-token":
    print("[FAIL] missing_bearer_authorization")
    sys.exit(1)
if not all(event.get("source_type") == "gds" for event in body):
    print("[FAIL] source_type_not_gds")
    sys.exit(1)
if not any(event.get("tags", {}).get("gds_event") == "gds_db_snapshot" for event in body):
    print("[FAIL] gds_db_snapshot_missing")
    sys.exit(1)
if not any(event.get("tags", {}).get("gds_event") == "gds_certificate_issued" for event in body):
    print("[FAIL] certificate_event_missing")
    sys.exit(1)
print("[PASS] gds_dmz_collector_sender_payload")
PY
