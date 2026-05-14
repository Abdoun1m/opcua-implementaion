#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

GDS_AGENT_CONTAINER="${GDS_AGENT_CONTAINER:-labshock_ot_gds_agent}"
TARGET="${TARGET:-opcua-server}"
ROLLBACK_PLAN_ID="${ROLLBACK_PLAN_ID:-54f3d16c6fe444eb91bff0719f5a76fc}"

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

assert_jq() {
  local json="$1"
  local filter="$2"
  local message="$3"
  jq -e "$filter" >/dev/null <<<"$json" || fail "$message"
  pass "$message"
}

need docker
need jq
need python3

cd "$REPO_ROOT"

dry_run_raw="$(docker exec "$GDS_AGENT_CONTAINER" python -m app.main --quarantine-revoked-dry-run --target "$TARGET")"
dry_run_json="$(printf '%s\n' "$dry_run_raw" | extract_last_json)"
assert_jq "$dry_run_json" '.schema == "labshock_phase_8_7_quarantine_dry_run_v1"' "dry-run schema is phase 8.7 quarantine"
assert_jq "$dry_run_json" '.runtime_mutation_performed == false' "dry-run did not mutate runtime"
assert_jq "$dry_run_json" '.runtime_restart_automatic == false' "dry-run did not restart runtime"
assert_jq "$dry_run_json" '(.files_to_delete | type == "array") and ((.files_to_delete | length) == 0)' "dry-run files_to_delete is empty"
assert_jq "$dry_run_json" '(.decision == "ready_for_quarantine") or (.decision == "not_applicable") or (.decision == "blocked")' "dry-run decision is valid"

dry_plan_id="$(jq -r '.plan_id // ""' <<<"$dry_run_json")"
if [[ -n "$dry_plan_id" ]]; then
  validate_raw="$(docker exec "$GDS_AGENT_CONTAINER" python -m app.main --validate-revocation-quarantine --target "$TARGET" --plan-id "$dry_plan_id")"
  validate_json="$(printf '%s\n' "$validate_raw" | extract_last_json)"
  assert_jq "$validate_json" '.schema == "labshock_phase_8_7_quarantine_validation_v1"' "quarantine validation schema is phase 8.7"
  assert_jq "$validate_json" '(.status == "validated") or (.status == "not_applicable") or (.status == "failed")' "quarantine validation status is valid"
fi

rollback_raw="$(docker exec "$GDS_AGENT_CONTAINER" python -m app.main --emergency-rollback-preflight --target "$TARGET" --plan-id "$ROLLBACK_PLAN_ID")"
rollback_json="$(printf '%s\n' "$rollback_raw" | extract_last_json)"
assert_jq "$rollback_json" '.schema == "labshock_phase_8_7_emergency_rollback_preflight_v1"' "emergency rollback preflight schema is phase 8.7"
assert_jq "$rollback_json" '.runtime_mutation_performed == false' "emergency rollback preflight did not mutate runtime"
assert_jq "$rollback_json" '.runtime_restart_automatic == false' "emergency rollback preflight did not restart runtime"
assert_jq "$rollback_json" '.emergency_execution_implemented == false' "emergency rollback execution remains unimplemented"
assert_jq "$rollback_json" '(.decision == "eligible") or (.decision == "blocked") or (.decision == "not_applicable")' "emergency rollback preflight decision is valid"

if grep -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|VAULT_TOKEN|secret_id|role_id|X-GDS-Agent-Token' <<<"$dry_run_raw$rollback_raw" >/dev/null; then
  fail "phase 8.7 command output includes private-key or secret markers"
fi
pass "phase 8.7 command outputs contain no private-key or secret markers"

echo "[OK] Phase 8.7 validation complete"
