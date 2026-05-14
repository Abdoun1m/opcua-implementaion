#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

GDS_HTTP_URL="${GDS_HTTP_URL:-http://192.168.10.30:8081}"
GDS_HTTPS_URL="${GDS_HTTPS_URL:-https://192.168.10.30:8443}"
GDS_CA_CERT="${GDS_CA_CERT:-$REPO_ROOT/gds/config/tls/ca.crt}"
GDS_AGENT_CLIENT_CERT="${GDS_AGENT_CLIENT_CERT:-$REPO_ROOT/gds-agent/config/tls/client.crt}"
GDS_AGENT_CLIENT_KEY="${GDS_AGENT_CLIENT_KEY:-$REPO_ROOT/gds-agent/config/tls/client.key}"
GDS_AGENT_TOKEN_FILE="${GDS_AGENT_TOKEN_FILE:-$REPO_ROOT/gds-agent/config/secrets/token}"
GDS_AGENT_ID="${GDS_AGENT_ID:-ot-gds-agent}"
GDS_AGENT_CONTAINER="${GDS_AGENT_CONTAINER:-labshock_ot_gds_agent}"
SUDO="${SUDO:-sudo}"

REVOKED_CERT_ID="${REVOKED_CERT_ID:-28}"
ACTIVE_CERT_ID="${ACTIVE_CERT_ID:-30}"
REVOKED_PACKAGE_ID="${REVOKED_PACKAGE_ID:-30d848e8cf7546eea002fa7b0d7831eb}"
ACTIVE_PACKAGE_ID="${ACTIVE_PACKAGE_ID:-ab1603b27b2b4107a5c203be14501069}"
ACTIVE_PLAN_ID="${ACTIVE_PLAN_ID:-54f3d16c6fe444eb91bff0719f5a76fc}"
TARGET="${TARGET:-opcua-server}"
RUNTIME_CERT_PATH="${RUNTIME_CERT_PATH:-$REPO_ROOT/shared-pki/runtime/opcua-server/ApplCerts/own/certs/server.der}"
EXPECTED_ACTIVE_FINGERPRINT="${EXPECTED_ACTIVE_FINGERPRINT:-f08b852eb667ba4492575aeee494b92b6d56bc9b28d0f98337020f9d03e2ae2a}"
EXPECTED_REVOKED_FINGERPRINT="${EXPECTED_REVOKED_FINGERPRINT:-3947e536ed160f97dbda26feb8f1ea32148eaca30e667e8f41652bfc3c0cd416}"
SNAPSHOT_REFERENCE="${SNAPSHOT_REFERENCE:-SNAPSHOT_P8_4_REVOCATION_RECONCILED_SAFE_20260512}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

extract_last_json() {
  python3 -c '
import json
import sys

data = sys.stdin.read()
decoder = json.JSONDecoder()
idx = 0
last = None
while idx < len(data):
    while idx < len(data) and data[idx].isspace():
        idx += 1
    if idx >= len(data):
        break
    if data[idx] not in "{[":
        newline = data.find("\n", idx)
        if newline == -1:
            break
        idx = newline + 1
        continue
    try:
        obj, end = decoder.raw_decode(data[idx:])
    except json.JSONDecodeError:
        newline = data.find("\n", idx)
        if newline == -1:
            break
        idx = newline + 1
        continue
    last = obj
    idx += end
if last is None:
    raise SystemExit("no JSON object found in command output")
print(json.dumps(last, sort_keys=True))
'
}

read_agent_token() {
  if [[ -r "$GDS_AGENT_TOKEN_FILE" ]]; then
    cat "$GDS_AGENT_TOKEN_FILE"
  else
    $SUDO cat "$GDS_AGENT_TOKEN_FILE"
  fi
}

curl_mtls() {
  local token
  token="$(read_agent_token)"
  curl -fsS \
    --cacert "$GDS_CA_CERT" \
    --cert "$GDS_AGENT_CLIENT_CERT" \
    --key "$GDS_AGENT_CLIENT_KEY" \
    -H "X-GDS-Agent-ID: $GDS_AGENT_ID" \
    -H "X-GDS-Agent-Token: $token" \
    "$@"
}

assert_jq() {
  local json="$1"
  local filter="$2"
  local message="$3"
  jq -e "$filter" >/dev/null <<<"$json" || fail "$message"
  pass "$message"
}

assert_jq_arg() {
  local json="$1"
  local arg_name="$2"
  local arg_value="$3"
  local filter="$4"
  local message="$5"
  jq -e --arg "$arg_name" "$arg_value" "$filter" >/dev/null <<<"$json" || fail "$message"
  pass "$message"
}

need curl
need docker
need grep
need jq
need openssl
need python3
need tr
need awk

cd "$REPO_ROOT"

health_json="$(curl -fsS "$GDS_HTTP_URL/health")"
assert_jq "$health_json" '(.status // .service_status // .service.status // "") == "ok"' "GDS health status is ok"

vault_json="$(curl -fsS "$GDS_HTTP_URL/api/v1/vault/status")"
assert_jq "$vault_json" '((.vault_reachable // .vault.reachable // .reachable // false) == true)' "Vault is reachable through GDS"
assert_jq "$vault_json" '(((.approle_auth // .approle.status // .approle_auth_status // "") == "active") or ((.approle_auth // .approle_auth_active // .approle.active // false) == true))' "GDS AppRole auth is active"
assert_jq "$vault_json" '((.token_renewable // .token.renewable // .renewable // false) == true)' "GDS Vault token is renewable"

revoked_cert_json="$(curl_mtls "$GDS_HTTPS_URL/api/v1/certificates/$REVOKED_CERT_ID")"
assert_jq "$revoked_cert_json" '.status == "revoked"' "certificate id '$REVOKED_CERT_ID' is revoked"
assert_jq_arg "$revoked_cert_json" fp "$EXPECTED_REVOKED_FINGERPRINT" '(.fingerprint_sha256 | ascii_downcase) == $fp' "revoked certificate fingerprint matches snapshot"

active_cert_json="$(curl_mtls "$GDS_HTTPS_URL/api/v1/certificates/$ACTIVE_CERT_ID")"
assert_jq "$active_cert_json" '.status == "active"' "certificate id '$ACTIVE_CERT_ID' is active"
assert_jq_arg "$active_cert_json" fp "$EXPECTED_ACTIVE_FINGERPRINT" '(.fingerprint_sha256 | ascii_downcase) == $fp' "active certificate fingerprint matches snapshot"

revoked_package_history="$(curl_mtls "$GDS_HTTPS_URL/api/v1/packages/$REVOKED_PACKAGE_ID/history")"
assert_jq "$revoked_package_history" '.lineage[0].lifecycle_state == "REVOKED"' "revoked package lifecycle is REVOKED"

active_package_history="$(curl_mtls "$GDS_HTTPS_URL/api/v1/packages/$ACTIVE_PACKAGE_ID/history")"
assert_jq "$active_package_history" '.lineage[0].lifecycle_state == "ACTIVATED"' "active package lifecycle is ACTIVATED"
assert_jq "$active_package_history" '.lineage[0].generation == 2' "active package generation is 2"
assert_jq_arg "$active_package_history" pkg "$REVOKED_PACKAGE_ID" '.lineage[0].supersedes_package_id == $pkg' "active package supersedes revoked package"

runtime_fingerprint="$($SUDO openssl x509 -inform DER -in "$RUNTIME_CERT_PATH" -noout -fingerprint -sha256 | awk -F= '{print tolower($2)}' | tr -d ':')"
[[ "$runtime_fingerprint" == "$EXPECTED_ACTIVE_FINGERPRINT" ]] || fail "runtime certificate fingerprint '$runtime_fingerprint' does not match active fingerprint '$EXPECTED_ACTIVE_FINGERPRINT'"
[[ "$runtime_fingerprint" != "$EXPECTED_REVOKED_FINGERPRINT" ]] || fail "runtime certificate still matches revoked fingerprint '$EXPECTED_REVOKED_FINGERPRINT'"
pass "runtime certificate matches active replacement and not revoked certificate"

receipt_path="$(docker exec "$GDS_AGENT_CONTAINER" sh -lc 'find /var/lib/labshock-gds-agent/activation-receipts/opcua-server -type f -name "*.json" -print | sort | tail -1')"
[[ -n "$receipt_path" ]] || fail "no OPC UA server activation receipt found"
receipt_json="$(docker exec "$GDS_AGENT_CONTAINER" cat "$receipt_path")"
assert_jq_arg "$receipt_json" pkg "$ACTIVE_PACKAGE_ID" '.package_id == $pkg' "activation receipt package id matches active package"
assert_jq_arg "$receipt_json" plan "$ACTIVE_PLAN_ID" '.plan_id == $plan' "activation receipt plan id matches active plan"
assert_jq "$receipt_json" '.status == "activated"' "activation receipt status is activated"
assert_jq "$receipt_json" '.runtime_restart_automatic == false' "activation receipt confirms no automatic restart"
assert_jq "$receipt_json" '.private_key_overwritten == false' "activation receipt confirms private key was not overwritten"
assert_jq "$receipt_json" '.private_key_sha256_unchanged == true' "activation receipt confirms private key checksum unchanged"

rollback_json="$(docker exec "$GDS_AGENT_CONTAINER" cat "/var/lib/labshock-gds-agent/runtime-rollbacks/opcua-server/$ACTIVE_PLAN_ID/rollback-manifest.json")"
assert_jq "$rollback_json" '.private_key_material_copied == false' "rollback manifest confirms private key material was not copied"

revocation_output="$(docker exec "$GDS_AGENT_CONTAINER" python -m app.main --pull-revocation-update --target "$TARGET")"
revocation_json="$(printf '%s\n' "$revocation_output" | extract_last_json)"
assert_jq_arg "$revocation_json" snapshot "$SNAPSHOT_REFERENCE" '.snapshot_reference == $snapshot' "revocation result references expected snapshot"
assert_jq "$revocation_json" '.runtime_write_enabled == false' "revocation dry-run confirms runtime writes disabled"
assert_jq "$revocation_json" '.runtime_mutation_performed == false' "revocation dry-run performed no runtime mutation"
assert_jq "$revocation_json" '.runtime_restart_automatic == false' "revocation dry-run performed no automatic restart"
assert_jq "$revocation_json" '.affected_runtime_entries_count == 0' "revocation dry-run has zero affected runtime entries"
assert_jq "$revocation_json" '.deletion_candidates_count == 0' "revocation dry-run has zero deletion candidates"
assert_jq "$revocation_json" '.files_to_remove_count == 0' "revocation dry-run has zero files to remove"
assert_jq "$revocation_json" '.reports[0].runtime_mount_mode == "ro"' "revocation dry-run confirms runtime mount mode is ro"

latest_report="$(jq -r '.reports[0].report_path' <<<"$revocation_json")"
report_json="$(docker exec "$GDS_AGENT_CONTAINER" cat "$latest_report")"
if grep -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|VAULT_TOKEN|secret_id|role_id|approle' <<<"$report_json" >/dev/null; then
  fail "latest revocation report contains private-key or Vault secret markers"
fi
pass "latest revocation report contains no private-key or Vault secret markers"

echo "[OK] $SNAPSHOT_REFERENCE validation complete"
