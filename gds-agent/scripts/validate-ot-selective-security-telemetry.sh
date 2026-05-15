#!/usr/bin/env bash
set -u

PASS_COUNT=0
FAIL_COUNT=0

has_pattern() {
  local pattern="$1"
  local file="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -q -- "$pattern" "$file"
    return $?
  fi
  grep -Eq -- "$pattern" "$file"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit 1

AGENT_CONTAINER="${AGENT_CONTAINER:-labshock_ot_gds_agent}"
COLLECTOR_SUMMARY_URL="${COLLECTOR_SUMMARY_URL:-http://192.168.1.70:8088/stats/summary}"
TARGET="${TARGET:-opcua-server}"

if ! command -v docker >/dev/null 2>&1; then
  fail "docker_not_found"
  printf '[SUMMARY] pass=%s fail=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
  exit 1
fi

if docker exec "$AGENT_CONTAINER" python -m app.main --component-apply-trust --target "$TARGET" --apply-mode trust_only >/tmp/labshock-ot-telemetry-agent-test.log 2>&1; then
  pass "component_apply_trust_command_completed"
else
  if has_pattern "runtime_write_deprecated_use_native_client|blocked_runtime_write_disabled|target_not_managed_by_agent_zone" /tmp/labshock-ot-telemetry-agent-test.log; then
    pass "security_policy_event_triggered_without_runtime_write"
  else
    fail "expected_policy_guard_event_missing"
  fi
fi

if curl -fsS "$COLLECTOR_SUMMARY_URL" >/tmp/labshock-ot-telemetry-summary.json 2>/tmp/labshock-ot-telemetry-summary.err; then
  if has_pattern "security|policy|error|events" /tmp/labshock-ot-telemetry-summary.json; then
    pass "collector_summary_available"
  else
    fail "collector_summary_missing_expected_keys"
  fi
else
  fail "collector_summary_unreachable"
fi

if docker logs --tail=500 "$AGENT_CONTAINER" >/tmp/labshock-ot-telemetry-agent-logs.txt 2>/tmp/labshock-ot-telemetry-agent-logs.err; then
  if has_pattern "ot collector telemetry dropped|runtime_write_deprecated_use_native_client|package_activation_dry_run_staged|certificate_package_rejected|target_not_managed_by_agent_zone|ot telemetry enabled=|HTTP Request: POST http://192.168.1.70:8088/events|package lifecycle reported" /tmp/labshock-ot-telemetry-agent-logs.txt; then
    pass "agent_logs_include_selective_telemetry_markers"
  elif has_pattern "runtime_write_deprecated_use_native_client|blocked_runtime_write_disabled|target_not_managed_by_agent_zone" /tmp/labshock-ot-telemetry-agent-test.log; then
    pass "agent_policy_markers_confirmed_from_command_log"
  else
    fail "agent_logs_missing_selective_markers"
  fi
else
  fail "agent_logs_unavailable"
fi

printf '[SUMMARY] pass=%s fail=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL_COUNT" -ne 0 ]; then
  exit 1
fi
