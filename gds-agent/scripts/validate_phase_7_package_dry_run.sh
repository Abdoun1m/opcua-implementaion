#!/usr/bin/env bash
set -u

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1"
}

CONTAINER="${GDS_AGENT_CONTAINER:-labshock_ot_gds_agent}"
PACKAGE_ID="${PHASE7_PACKAGE_ID:-${GDS_AGENT_PACKAGE_ID:-${PACKAGE_ID:-}}}"
TARGET="${PHASE7_TARGET:-${GDS_AGENT_TARGET:-${TARGET:-}}}"

if [ -z "$PACKAGE_ID" ]; then
  fail "missing_package_id_set_PHASE7_PACKAGE_ID"
  printf '[SUMMARY] pass=%s fail=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
  exit 1
fi

DOCKER_ENVS=(
  -e GDS_AGENT_RUNTIME_PREVIEW_ENABLED=true
  -e GDS_AGENT_RUNTIME_WRITE_ENABLED=false
  -e GDS_AGENT_RUNTIME_APPROVAL_REQUIRED=false
  -e GDS_AGENT_EMERGENCY_OVERRIDE_MODE=true
)

for name in \
  GDS_CONTROL_PLANE_URL \
  GDS_AGENT_AUTH_ENABLED \
  GDS_AGENT_ID \
  GDS_AGENT_TOKEN_FILE \
  GDS_AGENT_TLS_CA_FILE \
  GDS_AGENT_TLS_CLIENT_CERT \
  GDS_AGENT_TLS_CLIENT_KEY \
  GDS_AGENT_TRUST_ANCHOR_FINGERPRINT \
  GDS_AGENT_CACHE_DIR; do
  value="${!name:-}"
  if [ -n "$value" ]; then
    DOCKER_ENVS+=(-e "$name=$value")
  fi
done

agent() {
  docker exec "${DOCKER_ENVS[@]}" "$CONTAINER" python -m app.main "$@"
}

if agent --pull-package --package-id "$PACKAGE_ID"; then
  pass "package_pulled_and_signature_verified"
else
  fail "package_pull_or_signature_verification_failed"
fi

PLAN_ARGS=(--create-package-activation-plan --package-id "$PACKAGE_ID")
STAGE_ARGS=(--stage-package-activation-dry-run --package-id "$PACKAGE_ID")
if [ -n "$TARGET" ]; then
  PLAN_ARGS+=(--target "$TARGET")
  STAGE_ARGS+=(--target "$TARGET")
fi

if agent "${PLAN_ARGS[@]}"; then
  pass "package_activation_plan_created"
else
  fail "package_activation_plan_creation_failed"
fi

if agent "${STAGE_ARGS[@]}"; then
  pass "package_activation_dry_run_staged"
else
  fail "package_activation_dry_run_stage_failed"
fi

if docker exec "${DOCKER_ENVS[@]}" "$CONTAINER" python - "$PACKAGE_ID" <<'PY'
import json
import os
import sys
from pathlib import Path

package_id = sys.argv[1]
cache_dir = Path(os.environ.get("GDS_AGENT_CACHE_DIR", "/var/lib/labshock-gds-agent"))
pkg_dir = cache_dir / "packages" / package_id
manifest_path = pkg_dir / "manifest.json"
signature_path = pkg_dir / "manifest.sig.json"
preview_path = pkg_dir / "activation-plan-preview.json"
for path in (manifest_path, signature_path, preview_path):
    if not path.exists():
        raise SystemExit(f"missing_artifact:{path}")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
signature = json.loads(signature_path.read_text(encoding="utf-8"))
preview = json.loads(preview_path.read_text(encoding="utf-8"))

if manifest.get("schema") != "labshock_certificate_package_v1":
    raise SystemExit("unexpected_manifest_schema")
if manifest.get("private_key_included") is not False:
    raise SystemExit("private_key_included_not_false")
if "manifest_sha256" not in manifest or signature.get("manifest_sha256") != manifest.get("manifest_sha256"):
    raise SystemExit("manifest_signature_hash_mismatch")
install_plan = manifest.get("install_plan") if isinstance(manifest.get("install_plan"), dict) else {}
if install_plan.get("runtime_write_enabled") is not False:
    raise SystemExit("manifest_runtime_write_enabled_not_false")
if preview.get("runtime_write_enabled") is not False or preview.get("dry_run_only") is not True:
    raise SystemExit("activation_preview_not_dry_run")

def contains_private_pem(value):
    if isinstance(value, str):
        return "BEGIN PRIVATE KEY" in value or "BEGIN RSA PRIVATE KEY" in value or "BEGIN EC PRIVATE KEY" in value
    if isinstance(value, dict):
        return any(contains_private_pem(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_private_pem(v) for v in value)
    return False

if contains_private_pem(manifest) or contains_private_pem(signature) or contains_private_pem(preview):
    raise SystemExit("private_key_material_found_in_package_artifacts")

plan_candidates = []
for path in (cache_dir / "activation-plans").glob("*/*_package.json"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    if data.get("package_id") == package_id:
        plan_candidates.append((path.stat().st_mtime, path, data))
if not plan_candidates:
    raise SystemExit("package_activation_plan_not_found")
_, plan_path, plan = sorted(plan_candidates)[-1]
if plan.get("runtime_write_enabled") is not False or plan.get("dry_run_only") is not True:
    raise SystemExit("package_activation_plan_not_dry_run")

stage_candidates = []
for path in (cache_dir / "runtime-stage").glob("*/*/validation-report.json"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    if data.get("package_id") == package_id:
        stage_candidates.append((path.stat().st_mtime, path, data))
if not stage_candidates:
    raise SystemExit("package_stage_validation_report_not_found")
_, validation_path, validation = sorted(stage_candidates)[-1]
if validation.get("runtime_write_enabled") is not False:
    raise SystemExit("stage_runtime_write_enabled_not_false")
if validation.get("dry_run_only") is not True:
    raise SystemExit("stage_not_marked_dry_run_only")
if validation.get("runtime_mutation_performed", False) is not False:
    raise SystemExit("runtime_mutation_performed_not_false")

stage_dir = validation_path.parent
for sensitive_name in ("private.key", "private_key", "server.key", "client.key"):
    for path in stage_dir.rglob("*"):
        if sensitive_name in path.name.lower():
            raise SystemExit(f"private_key_path_staged:{path.relative_to(stage_dir)}")

print(json.dumps({
    "package_id": package_id,
    "manifest_sha256": manifest.get("manifest_sha256"),
    "plan_id": plan.get("plan_id"),
    "plan_path": str(plan_path),
    "stage_validation_report": str(validation_path),
    "runtime_write_enabled": False,
    "runtime_mutation_performed": False,
}, sort_keys=True))
PY
then
  pass "dry_run_artifacts_are_safe"
else
  fail "dry_run_artifact_safety_check_failed"
fi

printf '[SUMMARY] pass=%s fail=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL_COUNT" -ne 0 ]; then
  exit 1
fi
