# OT GDS Agent (Phase 4 Foundation)

This agent runs in OT and initiates outbound pull synchronization from the DMZ GDS control plane.

## Native-Owned PKI Model

`labshock_ot_gds_agent` is now a policy, audit, and plan-orchestration layer. It no longer mounts or writes component runtime PKI directories for `opcua-server`, `fuxa`, or DMZ gateway identities.

Direct runtime PKI write/apply commands fail in orchestrator mode with:

```text
runtime_write_deprecated_use_native_client
```

Use the owning runtime instead:

- `powergrid_opcua_server` native GDS client for `ot-server`.
- `/opt/labshock/fuxa-gds/fuxa-gds.sh` inside `labshock_scada` for `fuxa-client`.
- `opcua_dmz_gateway` native GDS client for DMZ gateway identities.

The OT Agent may still check GDS health, verify signatures, create approvals, record plans, forward collector events, and produce audit reports. It does not execute Docker commands or mutate another runtime's PKI.

## Purpose

- Pull trust lists and PKI metadata from DMZ GDS.
- Cache data locally in OT.
- Validate payload shape, certificate fingerprints, and DER CRL integrity.
- Verify detached signature on signed trust artifacts before cache write.
- Enforce trust-anchor fingerprint pinning when signed mode is enabled.
- Reconstruct canonical payload bytes and verify both detached signature and canonical hash (`artifact_sha256`) before accepting artifacts.
- Track replay protection using `(version, artifact_revision)` for signed-compatible baselines.
- Never accept inbound DMZ push.
- Do not modify runtime trust stores unless explicit Phase 8.1 live-activation gates are enabled.
- Forward normalized operational/security events to OT Collector (non-blocking).

## Preview/Diff Mode

After each sync cycle, the agent compares newly pulled trust lists with previous cached versions and writes diff reports under:

- `/var/lib/labshock-gds-agent/diff/<zone>/<role>/*.json`

Each diff report contains:

- `diff_id`
- `generated_at`
- `zone`
- `role`
- `previous_version`
- `new_version`
- `added[]`
- `removed[]`
- `changed[]`
- `ca_chain_changed`
- `crl_changed`
- `risk_level`
- `recommendation`
- `critical_reasons[]`

Risk levels:

- `LOW`: no material cert/pki change (version/timestamp only)
- `MEDIUM`: certificate added or expiry extended
- `HIGH`: certificate removed, fingerprint changed, CN changed, application URI changed, CA chain changed
- `CRITICAL`: empty trust list, malformed trust list/cert, CA chain missing, CRL invalid

Optional one-shot preview mode:

```bash
docker exec labshock_ot_gds_agent python -m app.main --preview-once
```

## Runtime Enforcement Orchestration (Phase 5.2 - 5.5 Dry-Run)

The agent now enforces maintenance-gate policy decisions and can build dry-run atomic staging bundles without touching live runtime trust stores.

Implemented:

- Maintenance window enforcement gate in continuous sync mode.
- Blackout period denial support.
- Emergency override mode support (policy + signed approval required).
- Purdue-aware per-target policy defaults:
  - `opcua-server`: dual approval, maintenance mandatory, emergency override disabled.
  - `fuxa`: single approval, maintenance mandatory, emergency override allowed.
- Signed approval record schema and helper CLI.
- Controlled dry-run staging artifacts:
  - shadow trust store
  - incoming trust store
  - staged activation directory
  - checksums + verification
  - atomic symlink swap procedure file
  - rollback pointer metadata
  - read-only current runtime inspection
  - validation report
  - operator README
- Conservative merge policy:
  - Adds GDS-approved trust entries.
  - Updates GDS-managed matching entries.
  - Preserves unknown or local runtime trust entries by default.
  - Records deletion candidates as informational only.

New CLI modes:

- `python -m app.main --runtime-preview-once`
- `python -m app.main --create-activation-plan --target opcua-server`
- `python -m app.main --create-activation-plan --target fuxa`
- `python -m app.main --create-approval --target opcua-server --operator ot-admin --decision approve --reason "windowed rollout" --approval-level dual --expires-in-minutes 120`
- `python -m app.main --stage-activation-dry-run --target opcua-server --plan-id <plan_id>`

New environment:

- `GDS_AGENT_RUNTIME_PREVIEW_ENABLED=true`
- `GDS_AGENT_RUNTIME_TARGETS=opcua-server,fuxa`
- `GDS_AGENT_RUNTIME_APPROVAL_REQUIRED=true`
- `GDS_AGENT_EMERGENCY_OVERRIDE_MODE=false`
- `GDS_AGENT_MAINTENANCE_WINDOWS_FILE=/etc/labshock-gds-agent/maintenance-windows.json`
- `GDS_AGENT_MAINTENANCE_TIMEZONE=UTC`
- `GDS_AGENT_APPROVAL_SIGNING_KEY_PATH=/var/lib/labshock-gds-agent/approval-signing/approval-ed25519.pem`
- `GDS_AGENT_APPROVAL_SIGNING_KEY_ID=ot-approval-key-v1`
- `GDS_AGENT_ACTIVATION_MERGE_POLICY=conservative_merge`

Maintenance policy example:

- `cp ./gds-agent/config/maintenance-windows.example.json ./gds-agent/config/maintenance-windows.json`

Phase 5.2+5.3 storage:

- `/var/lib/labshock-gds-agent/runtime-previews`
- `/var/lib/labshock-gds-agent/activation-plans`
- `/var/lib/labshock-gds-agent/activation-gates`
- `/var/lib/labshock-gds-agent/approvals`
- `/var/lib/labshock-gds-agent/runtime-stage`
- `/var/lib/labshock-gds-agent/rollback-bundles`
- `/var/lib/labshock-gds-agent/runtime-compat`
- `/var/lib/labshock-gds-agent/telemetry`
- `/var/lib/labshock-gds-agent/inventory-drift`

Phase 5.4 dry-run bundle:

- `shadow-trust-store/`: proposed target-specific runtime trust-store shape.
- `incoming-trust-store/`: GDS-managed material generated from the verified signed artifact.
- `checksums.json`: SHA256 hashes for staged files.
- `swap-plan.json`: future atomic activation strategy as reference strings only.
- `rollback-pointer.json`: future rollback strategy as reference strings only.
- `validation-report.json`: gate, approval, window, blackout, compatibility, and warning summary.
- `README-DRY-RUN.txt`: operator interpretation notes.

Conservative merge policy:

- `conservative_merge` is the default because OT availability takes priority over strict trust-store replacement.
- The dry-run keeps runtime-local entries such as UaExpert emergency engineering access, FUXA local trust, transitional gateway trust, and manually added trust anchors.
- Under `conservative_merge`, `swap-plan.json` keeps `files_to_remove=[]`.
- `deletion_candidates[]` are informational only and require a future explicit revocation phase before removal.
- `strict_replace` is reserved for a future phase because it can remove emergency access or transitional trust needed for recovery.

Read-only runtime inspection:

- `opcua-server` maps to `/runtime/opcua-server/pki` and preserves the `ApplCerts/...` layout.
- `fuxa` maps to `/runtime/fuxa/PKI` and preserves the NodeOPCUA `trusted/`, `issuers/`, and `rejected/` layout.
- If runtime mounts are unavailable, dry-run staging still succeeds with `current_runtime_status=unavailable`.
- Private key material is intentionally skipped before any read, hash, or parse operation. Paths under `private/` or `keys/`, filenames containing `.key` or `private`, and `.key.der` or `.key.pem` files are recorded as metadata only.

Important:

- Runtime writes remain disabled (`runtime_write_enabled=false`).
- No OPC UA/FUXA trust-store replacement is performed.
- No automatic runtime restart is performed.
- Existing runtime PKI mounts are inspected read-only only.

## OT Collector Forwarding

Environment:

- `GDS_AGENT_FORWARD_TO_OT_COLLECTOR=true`
- `GDS_AGENT_OT_COLLECTOR_URL=http://192.168.1.70:8088/events`
- `GDS_AGENT_FORWARD_TIMEOUT_SECONDS=3`
- `GDS_AGENT_SYNC_SUCCESS_EVENT_MIN_INTERVAL_SECONDS=300`
- `LABSHOCK_OT_TELEMETRY_ENABLED=true`
- `LABSHOCK_OT_TELEMETRY_MODE=security_only`
- `GDS_AGENT_OT_TELEMETRY_ENABLED=true`
- `GDS_AGENT_OT_TELEMETRY_MODE=security_only`
- `GDS_AGENT_OT_COLLECTOR_DEDUP_WINDOW_SECONDS=60`
- `GDS_AGENT_OT_COLLECTOR_HEALTH_SUMMARY_SECONDS=300`
- `GDS_AGENT_OT_COLLECTOR_SAMPLE_RATE=0.05` (used when mode is `sampled_operations`)

Forwarding behavior:

- Best effort only, never blocks sync cycle.
- No retry yet.
- Logs forwarding failures and continues local cache/diff flow.
- Selective forwarding policy modes:
  - `debug_all`: forward all normalized events.
  - `security_only`: forward only security/policy/error/high-severity events plus rate-limited health summaries.
  - `sampled_operations`: same security behavior plus sampled low-value operational events.
  - `off`: local logs only.
- Duplicate suppression is applied before forwarding using `GDS_AGENT_OT_COLLECTOR_DEDUP_WINDOW_SECONDS`.
- Health/lifecycle info forwarding is rate-limited by `GDS_AGENT_OT_COLLECTOR_HEALTH_SUMMARY_SECONDS`.
- `raw` is always sent as a JSON string (collector compatibility mode), never as nested object.
- Never forwards private keys, Vault tokens, role IDs, secret IDs, full PEM, or full CRL payload.
- Sensitive fields in forwarded `raw` payloads are redacted defensively (`pem`, `ca_chain_pem`, `crl_base64`, `token`, `role_id`, `secret_id`, `private_key`).
- Payload size guards:
  - `GDS_AGENT_OT_COLLECTOR_MAX_MESSAGE_LEN` (default `512`)
  - `GDS_AGENT_OT_COLLECTOR_MAX_RAW_LEN` (default `4096`)
  - `GDS_AGENT_OT_COLLECTOR_MAX_PAYLOAD_BYTES` (default `16384`)

Validation helper:

- `gds-agent/scripts/validate-ot-selective-security-telemetry.sh`

## Pulled Endpoints

- `/api/v1/trustlists/OT/server`
- `/api/v1/trustlists/OT/scada-client`
- `/api/v1/pki/ca-chain`
- `/api/v1/pki/crl`

Signed artifact mode endpoints:

- `/api/v1/signing/trust-anchor`
- `/api/v1/trustlists/OT/server/artifact`
- `/api/v1/trustlists/OT/server/artifact.sig`
- `/api/v1/trustlists/OT/server/artifact/canonical`
- `/api/v1/trustlists/OT/scada-client/artifact`
- `/api/v1/trustlists/OT/scada-client/artifact.sig`
- `/api/v1/trustlists/OT/scada-client/artifact/canonical`

Phase 6.1 telemetry endpoints pulled during signed sync:

- `/api/v1/mtls/metrics`
- `/api/v1/certificates/telemetry`
- `/api/v1/certificates/drift`

Signed artifact mode environment:

- `GDS_AGENT_REQUIRE_SIGNED_ARTIFACTS=true`
- `GDS_AGENT_TRUST_ANCHOR_FINGERPRINT=<sha256 hex fingerprint>`
- `GDS_SIGN_DEBUG=true` (optional canonical debug logging: canonical SHA256 and verifier payload length)
- `GDS_AGENT_AUTH_ENABLED=true` (optional pull authentication)
- `GDS_AGENT_TOKEN_FILE=/etc/labshock-gds-agent-auth/token`

When auth is enabled, the agent sends:

- `X-GDS-Agent-ID`
- `X-GDS-Agent-Token`

## Phase 6 HTTPS/mTLS Pull Channel

The OT agent can pull from the GDS HTTPS/mTLS listener while keeping token authorization and signed artifact verification enabled.

Environment:

- `GDS_CONTROL_PLANE_URL=https://192.168.10.30:8443`
- `GDS_AGENT_MTLS_ENABLED=true`
- `GDS_AGENT_TLS_CA_FILE=/etc/labshock-gds-agent-tls/ca.crt`
- `GDS_AGENT_TLS_CERT_FILE=/etc/labshock-gds-agent-tls/client.crt`
- `GDS_AGENT_TLS_KEY_FILE=/etc/labshock-gds-agent-tls/client.key`

The mTLS client factory is used for normal sync, signed artifact pulls, trust-anchor pulls, runtime preview, activation gate evaluation, and dry-run staging. OT Collector forwarding remains separate and unchanged.

Phase 6 keeps the layered model:

- mTLS protects transport identity.
- `X-GDS-Agent-ID` and `X-GDS-Agent-Token` preserve pull authorization.
- Signed artifacts, canonical hash checks, and trust-anchor pinning protect content integrity and replay resistance.

## Phase 7 Certificate Package Orchestration

The OT agent can now pull immutable signed certificate packages from GDS over the existing HTTPS/mTLS and token-authenticated channel.

Phase 7 ownership rules:

- Runtime components still own their local PKI directories.
- The agent does not write live runtime PKI directories.
- Package handling creates local cache and activation-plan previews only.
- Runtime activation remains dry-run only (`runtime_write_enabled=false`, `dry_run_only=true`).
- `shared-pki` remains migration/reference material and is not authoritative.

Package verification checks:

- GDS signing trust anchor fingerprint.
- Signed manifest signature.
- Manifest hash (`manifest_sha256`).
- Package hash tree metadata (`payload_sha256`, `files_sha256`).
- Package compatibility status.

Package cache:

- `/var/lib/labshock-gds-agent/packages/<package_id>/manifest.json`
- `/var/lib/labshock-gds-agent/packages/<package_id>/manifest.sig.json`
- `/var/lib/labshock-gds-agent/packages/<package_id>/activation-plan-preview.json`

Environment:

- `GDS_AGENT_PACKAGE_IDS=<package_id>[,<package_id>...]`

CLI:

- `python -m app.main --pull-package --package-id <package_id>`
- `python -m app.main --create-package-activation-plan --package-id <package_id>`
- `python -m app.main --stage-package-activation-dry-run --package-id <package_id> --target fuxa --plan-id <plan_id>`

Normalized package workflow events:

- `package_pulled`
- `certificate_package_verified`
- `package_activation_plan_created`
- `package_activation_dry_run_staged`
- `certificate_package_rejected`
- `package_activation_failed`

Rejected or failed package events include a stable `failure_code` when the failure class is known.

GDS lifecycle reports:

- `PULLED` after the manifest and detached signature are fetched.
- `VERIFIED` after manifest signature and hash verification passes.
- `STAGED` after local package cache and activation-plan preview are written.

These reports are best-effort and non-blocking. `STAGED` remains dry-run/local-cache only in Phase 7.

Public Phase 7 validation entrypoint:

```bash
export PHASE7_PACKAGE_ID=<package_id>
export GDS_AGENT_CONTAINER=labshock_ot_gds_agent
export GDS_AGENT_TRUST_ANCHOR_FINGERPRINT=<expected_gds_signing_key_sha256>
gds-agent/scripts/validate_phase_7_package_dry_run.sh
```

The script pulls the package, verifies its manifest signature against the pinned trust anchor, creates a package activation plan, stages the dry-run bundle, and asserts `runtime_write_enabled=false`, `runtime_mutation_performed=false`, and no private key overwrite in generated package artifacts.

Package activation-plan integration:

- Cached package manifests can create activation plans using the same approval, maintenance-window, blackout, emergency override, and conservative-merge controls as runtime trust-artifact plans.
- `node-opcua-client` packages map to the `fuxa` target by default.
- `open62541-server` packages map to the `opcua-server` target by default.
- Package staging writes only under `/var/lib/labshock-gds-agent/runtime-stage/<target>/<plan_id>/`.
- Live runtime PKI paths remain read-only.
- `stage-package-activation-dry-run` is denied if the gate is closed.

Private key rule:

- Package telemetry and metadata never include private keys.
- The agent does not log PEM private key material.
- Phase 7 packages currently carry signed certificate material and install-plan metadata only.

## Phase 8.1 FUXA Live Activation Gate

Historical note: Phase 8.1 through Phase 8.7 direct runtime activation commands are retained in the codebase for evidence compatibility, but they are deprecated when `GDS_AGENT_POLICY_ORCHESTRATOR_MODE=true`. New operations must use the owning runtime native client or local helper instead of OT Agent PKI mounts.

The first live mutation path is restricted to FUXA only. It keeps conservative merge semantics, never restarts FUXA, never deletes unknown runtime entries, and never overwrites private key material.

Safety gates:

- `GDS_AGENT_RUNTIME_WRITE_ENABLED=false` by default.
- `GDS_AGENT_RUNTIME_ACTIVATION_TARGETS=fuxa` by default.
- `GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=ro` by default in Docker Compose.
- Activation refuses targets outside the active phase allow-list.
- Activation refuses read-only/default operation with `runtime_write_disabled` or `runtime_mount_not_writable`.
- The package certificate public key must match `/runtime/fuxa/PKI/own/private/private_key.pem`; otherwise activation fails with `certificate_private_key_mismatch`.

CLI:

- `python -m app.main --activate-package --package-id <package_id> --target fuxa`
- `python -m app.main --activate-package --package-id <package_id> --target fuxa --plan-id <plan_id>`
- `python -m app.main --validate-fuxa-activation --package-id <package_id> --target fuxa`

Activation creates:

- `/var/lib/labshock-gds-agent/runtime-rollbacks/fuxa/<plan_id>/`
- `/var/lib/labshock-gds-agent/activation-receipts/fuxa/*.json`
- GDS lifecycle event `package_activated` on success.
- OT Collector event `package_runtime_activated` on success.
- Repeated activation of the same package/stage returns `package_runtime_already_activated` locally and does not create another rollback, receipt, GDS lifecycle event, or OT Collector activation event.

Operator-controlled positive path:

```bash
export GDS_AGENT_RUNTIME_WRITE_ENABLED=true
export GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=rw
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh
docker exec labshock_ot_gds_agent python -m app.main --activate-package --package-id "$PKG" --target fuxa
```

Evidence checks:

```bash
docker exec labshock_ot_gds_agent python -m app.main --validate-fuxa-activation --package-id "$PKG" --target fuxa
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/runtime-rollbacks/fuxa -maxdepth 6 -type f -print
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/activation-receipts/fuxa -type f -print | tail -5
```

After the controlled activation, return to safe mode:

```bash
export GDS_AGENT_RUNTIME_WRITE_ENABLED=false
export GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=ro
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
```

## Phase 8.2 OPC UA Server Live Activation Gate

The OPC UA server activation path reuses the package activation engine, but requires explicit target enablement and the open62541 runtime mount to be writable. It preserves dual approval policy, does not restart the service, and never overwrites `ApplCerts/own/private/server.key.der`.

Additional gates:

- `GDS_AGENT_RUNTIME_ACTIVATION_TARGETS` must include `opcua-server`.
- `GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=rw` is required for mutation.
- Package CSR must be generated from the existing server private key.
- The package certificate public key must match `ApplCerts/own/private/server.key.der`.
- Maintenance window and dual approval must be valid.

Operator-controlled path:

```bash
export GDS_AGENT_RUNTIME_WRITE_ENABLED=true
export GDS_AGENT_RUNTIME_ACTIVATION_TARGETS=fuxa,opcua-server
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=rw
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh
docker exec labshock_ot_gds_agent python -m app.main --activate-package --package-id "$PKG_SERVER" --target opcua-server
```

Validation:

```bash
docker exec labshock_ot_gds_agent python -m app.main --validate-package-activation --package-id "$PKG_SERVER" --target opcua-server
```

## Phase 8.3 Automatic Renewal End-to-End

Renewal is disabled by default and reuses the existing signed package, dry-run staging, approval, maintenance-window, blackout, and live activation gates. The OT Agent generates a CSR from the existing runtime private key in memory only; the private key is never copied, logged, sent to GDS, or forwarded to the OT Collector.

Safe defaults:

- `GDS_AGENT_RENEWAL_ENABLED=false`
- `GDS_AGENT_RENEWAL_TARGETS=fuxa,opcua-server`
- `GDS_AGENT_RENEWAL_THRESHOLD_DAYS=14`
- `GDS_AGENT_RENEWAL_ACTIVATE_IF_GATES_OPEN=false`

Read-only renewal check:

```bash
docker exec labshock_ot_gds_agent python -m app.main --renewal-check-once
docker exec labshock_ot_gds_agent python -m app.main --renewal-check-once --target opcua-server
```

Package and stage a renewal without live activation:

```bash
export GDS_AGENT_RENEWAL_ENABLED=true
export GDS_AGENT_RUNTIME_WRITE_ENABLED=false
export GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=ro
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=ro
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh

docker exec labshock_ot_gds_agent python -m app.main --renew-runtime-certificate --target fuxa
docker exec labshock_ot_gds_agent python -m app.main --renew-runtime-certificate --target opcua-server
```

Controlled renewal activation uses the same live gates as Phase 8.1 and 8.2. Set the relevant runtime mount to `rw`, collect the required approval, ensure the maintenance window is open, then pass `--activate-if-gates-open`:

```bash
export GDS_AGENT_RENEWAL_ENABLED=true
export GDS_AGENT_RUNTIME_WRITE_ENABLED=true
export GDS_AGENT_RUNTIME_ACTIVATION_TARGETS=fuxa,opcua-server
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=rw
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh

docker exec labshock_ot_gds_agent python -m app.main --renew-runtime-certificate --target opcua-server --activate-if-gates-open
```

After testing, restore safe mode:

```bash
export GDS_AGENT_RENEWAL_ENABLED=false
export GDS_AGENT_RUNTIME_WRITE_ENABLED=false
export GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=ro
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=ro
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
```

## Phase 8.4 Revocation Propagation Dry-Run

Revocation propagation is dry-run only. The agent refreshes signed trust material and the CRL into its local cache, inspects runtime trust entries without reading private keys, and writes operator review reports under `/var/lib/labshock-gds-agent/revocation-dry-runs/<target>/`.

Safe mode:

```bash
export GDS_AGENT_RUNTIME_WRITE_ENABLED=false
export GDS_AGENT_RUNTIME_FUXA_MOUNT_MODE=ro
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=ro
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh

docker exec labshock_ot_gds_agent python -m app.main --pull-revocation-update
docker exec labshock_ot_gds_agent python -m app.main --pull-revocation-update --target opcua-server
```

Phase 8.4 does not delete files, replace runtime trust stores, restart services, or auto-rollback. Under `conservative_merge`, revocation reports keep `files_to_remove=[]` and list matching runtime entries as `deletion_candidates` for operator review only.

## Phase 8.5 Evidence Snapshot and Regression Harness

Phase 8.5 records the completed Phase 8.4 chain as `SNAPSHOT_P8_4_REVOCATION_RECONCILED_SAFE_20260512` and keeps the next validation step read-only. The canonical reconciled OPC UA server state is:

- Revoked certificate id `28`, package `30d848e8cf7546eea002fa7b0d7831eb`, lifecycle `REVOKED`
- Active certificate id `30`, package `ab1603b27b2b4107a5c203be14501069`, plan `54f3d16c6fe444eb91bff0719f5a76fc`, lifecycle `ACTIVATED`
- Runtime certificate fingerprint `f08b852eb667ba4492575aeee494b92b6d56bc9b28d0f98337020f9d03e2ae2a`
- Safe mode restored with runtime writes disabled and FUXA/OPC UA server mounts set to `ro`

After rebuilding the OT Agent image with this code, run the snapshot verifier from the repository root while the GDS and OT Agent containers are up:

```bash
bash ./gds-agent/scripts/validate_phase_8_5_snapshot.sh
```

The verifier checks GDS/Vault health, revoked and active certificate state, package lifecycle, runtime certificate fingerprint, activation receipt safety flags, rollback manifest private-key handling, and a final `--pull-revocation-update --target opcua-server` clean result. It does not delete files, replace trust stores, restart services, or enable runtime writes.

Operator sequence proven by the snapshot:

1. Revoke the superseded certificate through GDS/Vault only.
2. Pull revocation updates with the OT Agent and review dry-run reports.
3. Reconcile runtime using the active replacement package through the existing approval, maintenance-window, signed-package, checksum, and mount gates.
4. Restore safe mode.
5. Run the Phase 8.5 verifier and require a clean revocation dry-run.

## Phase 8.6 Rollback Readiness Preflight

Phase 8.6 adds a read-only rollback preflight command. It inspects rollback evidence and current runtime/GDS status without replacing runtime files, deleting trust entries, restarting services, or enabling runtime writes.

Run preflight for the reconciled OPC UA server plan:

```bash
docker exec labshock_ot_gds_agent python -m app.main \
  --rollback-preflight \
  --target opcua-server \
  --plan-id 54f3d16c6fe444eb91bff0719f5a76fc
```

The preflight report is written under:

- `/var/lib/labshock-gds-agent/rollback-preflights/opcua-server/`

For the current snapshot, expected result is a safety block because the rollback snapshot certificate is revoked:

- `rollback_target_certificate_status=revoked`
- `decision=blocked`
- `blocking_reasons` includes `rollback_target_certificate_revoked`

This is expected behavior. Phase 8.6 proves rollback readiness evidence and guardrails; it does not perform rollback execution.

## Phase 8.7 Controlled Revocation Quarantine and Emergency Rollback Framework

Phase 8.7 adds a governed quarantine workflow for revoked runtime trust entries and a separate emergency rollback preflight framework. This phase is evidence and guardrails only: there is no hard deletion, no automatic rollback, and no automatic restart.

No new repository snapshot documents are created in this phase.

Quarantine dry-run (read-only):

```bash
docker exec labshock_ot_gds_agent python -m app.main \
  --quarantine-revoked-dry-run \
  --target opcua-server

docker exec labshock_ot_gds_agent python -m app.main \
  --quarantine-revoked-dry-run \
  --target opcua-server \
  --report-id <revocation_report_id>
```

Quarantine activation (gated, move-only):

```bash
docker exec labshock_ot_gds_agent python -m app.main \
  --activate-revocation-quarantine \
  --target opcua-server \
  --plan-id <quarantine_plan_id>
```

Quarantine validation:

```bash
docker exec labshock_ot_gds_agent python -m app.main \
  --validate-revocation-quarantine \
  --target opcua-server \
  --plan-id <quarantine_plan_id>
```

Emergency rollback preflight (read-only, execution intentionally not implemented):

```bash
docker exec labshock_ot_gds_agent python -m app.main \
  --emergency-rollback-preflight \
  --target opcua-server \
  --plan-id 54f3d16c6fe444eb91bff0719f5a76fc
```

Phase 8.7 regression helper:

```bash
bash ./gds-agent/scripts/validate_phase_8_7_quarantine.sh
```

Phase 8.7 runtime mutation behavior:

- Quarantine dry-run is always read-only.
- Quarantine activation only moves eligible revoked trust files into `/var/lib/labshock-gds-agent/runtime-quarantine/...`.
- `files_to_delete` remains empty.
- Private key material is never moved or copied.
- Whole trust-store replacement is not performed.
- Runtime restart remains operator-controlled.

## Real GDS Component Discovery and Enrollment

The preferred runtime PKI path is now component-centric. `shared-pki` remains historical fixture material only; live OT runtime PKI mounts use named local volumes and are populated by GDS discovery, local CSR enrollment, trust pull, and gated apply.

Purdue ownership boundary:

- The main GDS control plane manages OT and DMZ component identities, lifecycle, discovery, CSR validation, Vault signing, trust distribution, revocation state, package lineage, and audit.
- Runtime PKI installation is delegated to the local runtime side.
- `labshock_ot_gds_agent` is only the OT-side executor for `opcua-server` and `fuxa`.
- DMZ gateway runtime PKI is owned by the DMZ gateway runtime and is handled by the native GDS client inside `opcua_dmz_gateway`.
- The OT agent must not mount, read, enroll, renew, activate, quarantine, roll back, or rotate `dmz-gateway-client` or `dmz-gateway-server` runtime PKI.

The component API path uses the HTTPS/mTLS GDS edge:

```bash
export GDS_CONTROL_PLANE_URL=https://192.168.10.30:8443
export GDS_AGENT_MTLS_ENABLED=true
export GDS_AGENT_AUTH_ENABLED=true
export GDS_AGENT_REQUIRE_SIGNED_ARTIFACTS=true
export GDS_AGENT_TRUST_ANCHOR_FINGERPRINT=<gds_trust_anchor_fingerprint>
```

Component commands:

```bash
docker exec labshock_ot_gds_agent python -m app.main --component-discover --target opcua-server
docker exec labshock_ot_gds_agent python -m app.main --component-pull-trust --target opcua-server
docker exec labshock_ot_gds_agent python -m app.main --component-apply-trust --target opcua-server
docker exec labshock_ot_gds_agent python -m app.main --component-apply-trust --target opcua-server --apply-mode trust_only

# Only needed when issuing or replacing the component's own certificate:
docker exec labshock_ot_gds_agent python -m app.main --component-enroll --target opcua-server
```

For an empty named runtime volume, run the enrollment step with the target mounted writable and normal operator gates open so the local private key can be created in runtime PKI. Subsequent enrollments reuse that local key and do not need to recreate it.

Supported targets:

- `opcua-server`
- `fuxa`

Operational sequence:

1. Discover component identity, profile, certificate group, renewal policy, trust anchor, and revocation status.
2. Pull signed trust material and CRL from GDS.
3. Open the usual gates only for apply: write-enabled runtime, target allowlist, writable mount, approvals, maintenance window, no blackout, pinned trust anchor.
4. Run `--component-apply-trust`, then restore safe mode immediately.

`--component-apply-trust` has two modes:

- `trust_only`: explicitly selected with `--apply-mode trust_only`, or selected by `--apply-mode auto` when `components/<target>/trust-material.json` exists. This updates CA chain, CRL, and trusted certificates only.
- `certificate_and_trust`: used when `components/<target>/enrollment-result.json` exists. This can replace the component's own certificate from the GDS-issued package and still preserves the private key.

Enrollment is only required when issuing or replacing the component's own certificate. Trust-only discovery, pull, and apply can run independently from certificate package activation. Use `--apply-mode certificate_and_trust` when intentionally applying an enrollment/package result.

Apply gate example:

```bash
export GDS_AGENT_RUNTIME_WRITE_ENABLED=true
export GDS_AGENT_RUNTIME_ACTIVATION_TARGETS=fuxa,opcua-server
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=rw
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh
docker exec labshock_ot_gds_agent python -m app.main --component-apply-trust --target opcua-server

export GDS_AGENT_RUNTIME_WRITE_ENABLED=false
export GDS_AGENT_RUNTIME_OPCUA_SERVER_MOUNT_MODE=ro
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh
```

Safety properties:

- GDS returns certificate/trust material only; no private key material is accepted or returned.
- Manifest signatures and trust-anchor pinning are still required before runtime mutation.
- Trust-only apply verifies the signed trust artifact, writes only CA chain, CRL, and trusted certificates, does not touch the own certificate or private key, does not create rollback material, and does not report package activation.
- Certificate-and-trust apply verifies the signed package manifest and may update the own certificate under gates, while preserving the private key.
- Apply never restarts services automatically.
- Existing renewal, revocation dry-run, quarantine, rollback preflight, and revoked-certificate guards remain compatible with the component distribution cache.

Setup for lab:

- `cp ./gds/config/secrets/gds-agent-tokens.example.json ./gds/config/secrets/gds-agent-tokens.json`
- `cp ./gds-agent/config/secrets/token.example ./gds-agent/config/secrets/token`
- `export GDS_AGENT_AUTH_ENABLED=true`

Verification failure classes emitted by the agent:

- `signature_invalid`
- `canonical_hash_mismatch`
- `signer_fingerprint_mismatch`
- `unsupported_signer`
- `malformed_artifact`

Pinning workflow:

1. `curl -s http://192.168.10.30:8081/api/v1/signing/trust-anchor | jq -r .fingerprint_sha256`
2. Set `GDS_AGENT_TRUST_ANCHOR_FINGERPRINT` to that value.
3. Set `GDS_AGENT_REQUIRE_SIGNED_ARTIFACTS=true` and restart agent.

## Cache Directory

- `/var/lib/labshock-gds-agent`
  - `trustlists/OT_server.json`
  - `trustlists/OT_scada-client.json`
  - `pki/ca-chain.pem`
  - `pki/crl.der`
  - `telemetry/*.json`
  - `inventory-drift/*.json`
  - `components/<target>/discovery.json`
  - `components/<target>/enrollment-result.json`
  - `components/<target>/trust-material.json`
  - `components/<target>/apply-result.json`
  - `component-apply-trust/<target>/*.json`
  - `packages/<package_id>/*.json`
  - `rollback-preflights/<target>/*.json`
  - `quarantine-plans/<target>/*.json`
  - `quarantine-receipts/<target>/*.json`
  - `quarantine-validation/<target>/*.json`
  - `runtime-quarantine/<target>/<plan_id>/`
  - `emergency-rollback-preflights/<target>/*.json`

## Required Purdue Rule

- Allow outbound OT -> DMZ:
  - `192.168.1.30 -> 192.168.10.30 tcp/8081` during transition/fallback
  - `192.168.1.30 -> 192.168.10.30 tcp/8443` for Phase 6 HTTPS/mTLS

## Kali Validation

```bash
docker compose --profile gds build gds
docker compose --profile gds-agent build labshock_ot_gds_agent
docker compose --profile gds up -d --force-recreate gds
docker compose --profile gds-agent up -d labshock_ot_gds_agent
sudo ./switch/attach_dmz.sh
sudo ./switch/attach_ot.sh
docker logs --tail=100 labshock_ot_gds_agent
docker exec labshock_ot_gds_agent ls -R /var/lib/labshock-gds-agent
docker exec labshock_ot_gds_agent python -m app.main --runtime-preview-once
docker exec labshock_ot_gds_agent python -m app.main --create-activation-plan --target opcua-server
docker exec labshock_ot_gds_agent python -m app.main --create-activation-plan --target fuxa
docker exec labshock_ot_gds_agent python -m app.main --create-approval --target opcua-server --operator ot-admin-1 --decision approve --reason "planned change" --approval-level dual --expires-in-minutes 120
docker exec labshock_ot_gds_agent python -m app.main --create-approval --target opcua-server --operator ot-admin-2 --decision approve --reason "planned change" --approval-level dual --expires-in-minutes 120
docker exec labshock_ot_gds_agent python -m app.main --stage-activation-dry-run --target opcua-server
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/runtime-stage -maxdepth 5 -type f
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/runtime-stage/opcua-server/<plan_id>/validation-report.json
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/runtime-stage/opcua-server/<plan_id>/swap-plan.json
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/runtime-stage/opcua-server/<plan_id>/swap-plan.json | jq '{merge_policy, files_to_remove, preserved_runtime_entries, deletion_candidates}'
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/runtime-stage/opcua-server/<plan_id>/rollback-pointer.json
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/runtime-stage/opcua-server/<plan_id>/rollback-pointer.json | jq '.current_runtime_snapshot_reference.files[] | select(.type=="private_key")'
curl -s "http://192.168.1.70:8088/events?source_type=gds-agent&limit=20" | jq
curl -s "http://192.168.1.70:8088/stats/summary" | jq
```

Phase 6 HTTPS/mTLS validation:

```bash
FP=$(curl -s --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: ChangeMe_OtGdsAgentToken" \
  https://192.168.10.30:8443/api/v1/signing/trust-anchor | tee /tmp/gds-trust-anchor.json | jq -r .fingerprint_sha256)

# If FP prints null, inspect the full response. GDS returns error_code for mTLS/auth failures.
jq . /tmp/gds-trust-anchor.json
docker exec labshock_gds test -r /etc/labshock-gds-agent-auth/gds-agent-tokens.json
openssl verify -CAfile ./gds/config/tls/ca.crt ./gds-agent/config/tls/client.crt

export GDS_CONTROL_PLANE_URL=https://192.168.10.30:8443
export GDS_AGENT_MTLS_ENABLED=true
export GDS_AGENT_AUTH_ENABLED=true
export GDS_AGENT_REQUIRE_SIGNED_ARTIFACTS=true
export GDS_AGENT_TRUST_ANCHOR_FINGERPRINT="$FP"

docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
sudo ./switch/attach_ot.sh
sleep 70
docker logs --tail=200 labshock_ot_gds_agent
curl -s "http://192.168.1.70:8088/events?source_type=gds-agent&limit=20" | jq
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/telemetry -type f -maxdepth 2 -print
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/inventory-drift -type f -maxdepth 2 -print
```

Phase 7 package pull validation:

```bash
# After enrolling a CSR through GDS and saving the returned package id:
PKG=$(jq -r .package_id /tmp/phase7-package.json)

docker exec labshock_ot_gds_agent python -m app.main --pull-package --package-id "$PKG"
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/packages -maxdepth 3 -type f -print
docker exec labshock_ot_gds_agent cat /var/lib/labshock-gds-agent/packages/"$PKG"/activation-plan-preview.json | jq
curl -s "http://192.168.1.70:8088/events?source_type=gds-agent&limit=30" | jq

sudo curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  "https://192.168.10.30:8443/api/v1/packages/$PKG/history" \
  | jq '.package_id,.generation,.lineage[0].lifecycle_state,.events[0:5]'

docker exec labshock_ot_gds_agent python -m app.main --create-package-activation-plan --package-id "$PKG"
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/activation-plans/fuxa -maxdepth 1 -type f -print | tail -1

# Staging requires approval and an open maintenance window. If the gate is closed this must fail safely.
docker exec labshock_ot_gds_agent python -m app.main --stage-package-activation-dry-run --package-id "$PKG" --target fuxa
docker exec labshock_ot_gds_agent find /var/lib/labshock-gds-agent/runtime-stage/fuxa -maxdepth 3 -type f -print

# Continuous pull mode:
export GDS_AGENT_PACKAGE_IDS="$PKG"
docker compose --profile gds-agent up -d --force-recreate labshock_ot_gds_agent
```

No-live-change check:

```bash
docker run --rm -v opcua-implementaion_opcua-server-runtime-pki:/pki:ro alpine sh -c 'find /pki -type f -exec sha256sum {} \; | sort' > /tmp/pki-before.sha256
docker exec labshock_ot_gds_agent python -m app.main --stage-activation-dry-run --target opcua-server --plan-id <plan_id>
docker run --rm -v opcua-implementaion_opcua-server-runtime-pki:/pki:ro alpine sh -c 'find /pki -type f -exec sha256sum {} \; | sort' > /tmp/pki-after.sha256
diff -u /tmp/pki-before.sha256 /tmp/pki-after.sha256
```
# OT trust-only automation notes

The OT Agent manages only OT runtime targets, currently `opcua-server` and
`fuxa`. It must not read, enroll, apply, quarantine, roll back, or rotate DMZ
Gateway runtime PKI; DMZ Gateway runtime PKI is owned by the native DMZ Gateway
GDS client.

Trust-only updates can run independently of component enrollment. Use
`--component-pull-trust` to cache signed GDS trust material, then
`--component-apply-trust --apply-mode trust_only` to write only CA chain, CRLs,
and trusted peer certificates under the existing approval, maintenance window,
target allowlist, mount-mode, signature, and trust-anchor gates.

Trust-only apply writes open62541-compatible stable aliases for the OT server:

```text
ApplCerts/trusted/certs/labshock_root_ca.der
ApplCerts/trusted/certs/labshock_intermediate_ca.der
ApplCerts/trusted/crl/root_ca.crl
ApplCerts/trusted/crl/vault_intermediate.crl
ApplCerts/issuer/crl/root_ca.crl
ApplCerts/issuer/crl/vault_intermediate.crl
ApplCerts/issuers/crl/root_ca.crl
ApplCerts/issuers/crl/vault_intermediate.crl
```

Useful automation toggles:

```text
GDS_AGENT_AUTO_APPLY_TRUST_ONLY=false
GDS_AGENT_AUTO_APPLY_TRUST_ONLY_TARGETS=opcua-server,fuxa
GDS_AGENT_REQUIRE_MAINTENANCE_WINDOW=true
GDS_AGENT_REQUIRE_APPROVAL=true
GDS_AGENT_STRICT_CRL_FRESHNESS=true
```

Trust-only apply never touches the component's own certificate, private key,
package lifecycle, rollback material, or service restart behavior.

## Known issue fixed: stale CRL artifacts

**Symptom:** The OPC UA server fails to start with `crl_expired_or_missing_next_update`
and `[PKI][EXPLICIT] Explicit trust material loading failed` even after a fresh CRL has
been deployed by `gds-apply-trust`.

**Root cause:** Earlier code paths in `_write_package_stage_material` (the package+certificate
activation path) wrote both a DER file and a base64 alias:

```text
issuers/crl/current.crl      ← DER bytes
issuers/crl/current.crl.b64  ← base64 text
```

When the trust-only path (`_write_target_stage_material`) took over, it refreshed the `.crl`
files but left the stale `.crl.b64` aliases in place.  Because the OPC UA server scans **all**
files ending in `.crl` or `.crl.b64` under its PKI directories with
`OPCUA_GDS_STRICT_CRL_FRESHNESS=true`, a single expired `.crl.b64` alias is enough to abort
the entire trust-loading phase.

**Fix:** Before writing a fresh CRL set, `_write_target_stage_material` and
`_write_package_stage_material` now:

1. Snapshot all existing CRL files in every target directory (for rollback).
2. Delete every GDS-controlled CRL alias — both `.crl` and `.crl.b64` variants — for
   the stems `vault_intermediate`, `root_ca`, and `current` from:
   - `ApplCerts/trusted/crl`
   - `ApplCerts/issuers/crl`
   - `ApplCerts/issuer/crl` (compat)
3. Write the fresh CRL set atomically (temp-file + rename).
4. Scan **all** `.crl` and `.crl.b64` files remaining under those directories and validate:
   - File is parseable as a DER CRL (or valid base64-wrapped DER for `.crl.b64`).
   - `nextUpdate` field is present.
   - `nextUpdate` is in the future when `GDS_AGENT_STRICT_CRL_FRESHNESS=true`.
5. If any file fails validation, restore from the snapshot (rollback) and raise an error
   with `gds_apply_trust_crl_validation_failed`.
6. Emit structured log events at each step:
   - `pki_trust_apply_started`
   - `pki_crl_alias_removed` (one per deleted file)
   - `pki_crl_cleanup_done`
   - `pki_crl_written` (one per written file)
   - `pki_crl_validation_ok` or `pki_crl_validation_expired` (one per scanned file)
   - `pki_crl_validation_failed` + `pki_crl_rollback_restored` on error
   - `pki_trust_apply_success` on clean completion

**Security invariants preserved:**

- Only GDS-controlled stems (`vault_intermediate`, `root_ca`, `current`) are removed.
  Files with unknown names are never deleted.
- `trusted/certs/` is untouched — unknown local peer certificates such as `UaExpertClient`
  are preserved.
- Private key material is never touched.
- Rollback restores the previous state if the new CRL set fails validation.

**Verification after fix:**

```bash
# Apply trust:
docker exec powergrid_opcua_server /app/build/powergrid_server \
  --gds-apply-trust --target ot-server

# All CRL files must show valid future nextUpdate:
find /app/pki/ApplCerts -type f \( -name "*.crl" -o -name "*.crl.b64" \) \
  -exec openssl crl -inform DER -in {} -noout -nextupdate \; 2>/dev/null

# No expired or unparseable file must remain:
find /app/pki/ApplCerts -type f \( -name "*.crl" -o -name "*.crl.b64" \) -print

# Server must start cleanly:
# Logs must include:
#   [PKI][EXPLICIT] trustListSize=... issuerListSize=... revocationListSize=...
#   [BOOT] ApplicationUri=urn:dataprotect:opcua:ot-server
# Logs must NOT include:
#   crl_expired_or_missing_next_update
#   Explicit trust material loading failed
```

**Environment toggle:**

```text
GDS_AGENT_STRICT_CRL_FRESHNESS=true   # default — post-write validation enforces future nextUpdate
GDS_AGENT_STRICT_CRL_FRESHNESS=false  # relaxed — parses and logs but does not fail on expiry
```
