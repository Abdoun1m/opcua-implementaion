# GDS Control Plane (Phase 3)

This service is progressive and non-disruptive:

- Vault stays the PKI authority.
- GDS stores inventory/trust-list metadata in PostgreSQL.
- OT/DMZ/FUXA runtimes are unchanged.
- `shared-pki` remains migration/reference material only and is not authoritative.

Runtime PKI ownership model:

- Every runtime component owns its own PKI directory structure.
- GDS never directly writes runtime PKI directories.
- OT Agent is policy/audit/plan orchestration only and does not mount component PKI.
- Runtime mutation is delegated to the owning runtime native client or local helper.
- `shared-pki` is migration/reference only and is not authoritative.

Real GDS discovery/distribution model:

- Components or local agents discover profile, certificate group, identity, renewal policy, and revocation state through `/api/v1/discovery`.
- Components submit CSRs to `/api/v1/enrollments/components/csr`; GDS validates registered identity/profile/zone/role/application URI and signs through Vault.
- Distribution returns only certificate, CA chain, CRL, signed trust artifact, and runtime layout hints. Private keys are never accepted from or returned by GDS.
- Legacy package endpoints remain as lineage and compatibility evidence, but the preferred operational flow is component discovery, local key/CSR, GDS enrollment, trust pull, then gated local apply.
- The new discovery, distribution, and component enrollment endpoints require the HTTPS/mTLS edge plus agent token authorization.
- `labshock_ot_gds_agent` is only the OT-side runtime executor for `opcua-server` and `fuxa`; DMZ gateway runtime PKI installation belongs to the native GDS client inside `opcua_dmz_gateway`.
- GDS still manages DMZ gateway identities at the control-plane level; it does not mount or write DMZ runtime PKI.

DMZ gateway native GDS client:

- `opcua_dmz_gateway` uses the same REST/mTLS discovery, distribution, and enrollment APIs as other component clients.
- `dmz-gateway-client` maps to `urn:dataprotect:opcua:dmz-gateway-client` with profile `open62541-client` and the gateway southbound runtime side.
- `dmz-gateway-server` maps to `urn:dataprotect:opcua:dmz-gateway-server` with profile `open62541-server` and the gateway northbound runtime side.
- `ot-server` is available to the DMZ gateway native client as a read-only remote peer discovery target; it cannot be enrolled or applied by the DMZ gateway.
- The gateway caches GDS responses under `/var/lib/opcua-dmz-gateway/gds` and writes runtime PKI only when `DMZ_GDS_RUNTIME_WRITE_ENABLED=true`.
- GDS never accepts or returns private keys; the gateway generates or reuses local keys under `/app/pki`.

Trustlist composition is relationship based for `OT/server`: the server-side trust material includes active certificates for components authorized to connect to OT servers, currently `DMZ/southbound-client` and `OT/scada-client`. It does not include unrelated server certificates.

Native/local runtime executors:

- `powergrid_opcua_server` has a native GDS client for `ot-server` and writes only `/app/pki/ApplCerts`.
- `/opt/labshock/fuxa-gds/fuxa-gds.sh` is the in-container FUXA helper for `urn:dataprotect:opcua:fuxa-client`; invoke it with `docker exec labshock_scada ...`. It uses only local tools inside FUXA, generates CSRs from the FUXA-local key, and writes only public trust/certificate material.
- `opcua_dmz_gateway` keeps its native GDS client for `dmz-gateway-client` and `dmz-gateway-server`.
- `labshock_ot_gds_agent` no longer mounts component PKI volumes and is not a runtime PKI writer.

Lifecycle communication:

- Components report local PKI state to `POST /api/v1/components/{application_uri}/status` and append audit events to `POST /api/v1/components/{application_uri}/events`.
- Components poll `GET /api/v1/components/{application_uri}/lifecycle` and `GET /api/v1/components/{application_uri}/trust-version` to detect trust artifact changes without triggering another runtime.
- GDS compares the current signed trust artifact with the last component-reported hash and returns `trust_update_available`.
- Component tokens must be scoped with `owned_applications`; lifecycle status/query access is limited to those owned application URIs.
- OT Agent reads lifecycle status for monitoring and forwarding only. It does not execute Docker commands or write runtime PKI.

## Implemented Endpoints

- `GET /health`
- `GET /api/v1/vault/status`
- `GET /api/v1/pki/ca-chain`
- `GET /api/v1/pki/crl`
- `GET /api/v1/signing/trust-anchor`
- `POST /api/v1/applications/register`
- `GET /api/v1/applications`
- `GET /api/v1/applications/{id}`
- `POST /api/v1/applications/{id}/heartbeat`
- `POST /api/v1/certificates/import`
- `GET /api/v1/certificates`
- `GET /api/v1/certificates/{id}`
- `GET /api/v1/certificates/telemetry`
- `GET /api/v1/certificates/drift`
- `POST /api/v1/certificates/renew`
- `GET /api/v1/mtls/metrics`
- `GET /api/v1/component-profiles`
- `GET /api/v1/discovery`
- `GET /api/v1/discovery/component-profiles`
- `GET /api/v1/discovery/certificate-groups`
- `GET /api/v1/discovery/components/{application_uri}/identity`
- `GET /api/v1/discovery/components/{application_uri}/renewal-policy`
- `GET /api/v1/discovery/components/{application_uri}/revocation-status`
- `GET /api/v1/distribution/components/{application_uri}/trust-material`
- `GET /api/v1/components/status`
- `POST /api/v1/components/{application_uri}/status`
- `GET /api/v1/components/{application_uri}/lifecycle`
- `GET /api/v1/components/{application_uri}/trust-version`
- `POST /api/v1/components/{application_uri}/events`
- `POST /api/v1/enrollments/rest/csr`
- `POST /api/v1/enrollments/components/csr`
- `GET /api/v1/enrollments/requests/{request_id}`
- `GET /api/v1/packages`
- `GET /api/v1/packages/telemetry`
- `GET /api/v1/packages/{package_id}`
- `GET /api/v1/packages/{package_id}/history`
- `GET /api/v1/packages/{package_id}/events`
- `POST /api/v1/packages/{package_id}/events`
- `GET /api/v1/packages/{package_id}/manifest`
- `GET /api/v1/packages/{package_id}/manifest.sig`
- `POST /api/v1/trustlists/build`
- `GET /api/v1/trustlists/{zone}/{role}`
- `GET /api/v1/trustlists/{zone}/{role}/artifact`
- `GET /api/v1/trustlists/{zone}/{role}/artifact.sig`
- `GET /api/v1/trustlists/{zone}/{role}/artifact/canonical`
- `POST /api/v1/trustlists/{zone}/{role}/artifact/rebuild`
- `GET /api/v1/trustlists/{zone}/{role}/artifact/history`
- `GET /api/v1/audit/events`

## Phase 6 HTTPS/mTLS Edge

GDS now runs behind an in-container Nginx edge:

- Uvicorn is internal only on `127.0.0.1:${GDS_UVICORN_INTERNAL_PORT:-18081}`.
- HTTP `8081` remains available as a Phase 6 transition/fallback listener.
- HTTPS/mTLS `8443` is added for OT agent pull traffic.
- `/internal/health` is available only through the internal Uvicorn listener for container health checks.

TLS controls:

- `GDS_TLS_PROFILE=lab` enables TLS 1.2 and TLS 1.3.
- `GDS_TLS_PROFILE=strict` enables TLS 1.3 only.
- `GDS_MTLS_MODE=optional` lets the request reach FastAPI so missing or failed client identity can be audited, then rejected.
- `GDS_MTLS_MODE=required` requires a valid client certificate during the Nginx TLS handshake.
- `GDS_VAULT_SIGN_ROLE=opcua-application` selects the Vault PKI signing role for lifecycle enrollment.
- `GDS_CERT_DEFAULT_TTL=720h` sets the default issued certificate TTL.

TLS files are mounted under `/etc/labshock-gds-tls`:

- `server.crt`
- `server.key`
- `ca.crt`

FastAPI only trusts `X-Client-Cert-*` identity headers when Nginx also supplies the internal proxy proof header, and only on the HTTPS listener. Spoofed client-certificate headers on direct or HTTP traffic are rejected and audited.

Phase 6.1 hardens that boundary with an internal proxy proof header:

- Nginx injects `X-GDS-Internal-Proxy` with an internal shared secret when proxying to Uvicorn.
- FastAPI trusts `X-Client-Cert-*` only when `X-GDS-Internal-Proxy` matches `GDS_INTERNAL_PROXY_SECRET`.
- If `GDS_INTERNAL_PROXY_SECRET_FILE` is readable, the entrypoint uses that file.
- If `GDS_INTERNAL_PROXY_SECRET` is set, the entrypoint uses the env value.
- If neither is present, the entrypoint generates an ephemeral secret at startup and exports it to Uvicorn.
- The secret is never logged.
- Client certificate details logged to audit are limited to verify status, subject, issuer, serial, fingerprint, source IP, path, and agent ID.

## Vault TLS/mTLS Client

GDS is the only LabShock control-plane component with Vault AppRole credentials. It talks to Vault over HTTPS/mTLS and never exposes Vault tokens, AppRole IDs, AppRole secret IDs, or client private key material in API responses or logs.

Vault client TLS files are mounted read-only under `/etc/labshock-vault-tls`:

- `ca.crt`
- `client.crt`
- `client.key`

Relevant settings:

```text
GDS__VAULT__ADDR=https://192.168.10.10:8200
GDS__VAULT__TLS_CA_FILE=/etc/labshock-vault-tls/ca.crt
GDS__VAULT__TLS_CLIENT_CERT=/etc/labshock-vault-tls/client.crt
GDS__VAULT__TLS_CLIENT_KEY=/etc/labshock-vault-tls/client.key
GDS__VAULT__TLS_VERIFY=true
```

Generate lab Vault TLS material with:

```bash
./scripts/generate-vault-tls-certs.sh
```

Use the guarded startup sequence:

```bash
./scripts/startup-sequence.sh
```

`/api/v1/vault/status` returns the current Vault transport and PKI state:

```json
{
  "vault_reachable": true,
  "vault_initialized": true,
  "vault_sealed": false,
  "vault_mtls_enabled": true,
  "token_ok": true,
  "pki_root_ok": true,
  "pki_int_ok": true,
  "crl_status": "fresh",
  "checked_at": "2026-05-14T00:00:00Z"
}
```

When Vault is sealed, GDS returns structured `error_code=vault_sealed` from issuance, renewal, and revocation paths. `/health` reports degraded instead of down. Valid cached CRLs and signed trust artifacts may still be served with `X-GDS-Cache=true` and `X-GDS-Cache-Reason=vault_sealed`.

Never store Vault tokens, AppRole credentials, unseal keys, or client private keys in source, compose environment variables, shell history, logs, chat, or issue trackers. If an unseal key was pasted anywhere outside protected local files, treat it as compromised and rekey Vault before use outside this lab.

Phase 6.1 adds observability-only telemetry:

- mTLS audit events include `correlation_id`, certificate validity dates, and days remaining.
- GDS returns `X-Correlation-ID` on REST responses.
- `GDS_CERT_EXPIRY_WARNING_DAYS` and `GDS_CERT_EXPIRY_CRITICAL_DAYS` control lifecycle state.
- If `GDS_TLS_CLIENT_CRL_FILE` exists, Nginx enables `ssl_crl` for revoked-client tests.
- Telemetry endpoints never return PEM bodies, tokens, role IDs, secret IDs, or private key material.

## Phase 7 Unified Certificate Lifecycle Orchestration

Phase 7 adds a foundation lifecycle engine while keeping runtime activation dry-run only.

Architecture:

- GDS is the certificate lifecycle authority and control plane.
- Vault performs real CSR signing through AppRole.
- PostgreSQL records request, package, and lifecycle state.
- Runtime adapters describe component-specific package and activation semantics.
- OT Agent pulls signed packages over mTLS and prepares dry-run activation plans.
- GDS does not write runtime PKI directories.

Seeded component profiles:

- `open62541-server`
- `open62541-client`
- `node-opcua-server`
- `node-opcua-client`

Runtime adapter abstraction:

- `validate_csr()`
- `validate_runtime_compatibility()`
- `generate_package_layout()`
- `generate_install_plan()`
- `classify_risk()`

Package lifecycle semantics:

- Packages are immutable.
- New issuance creates a new generation.
- Older generations remain queryable for rollback and audit.
- A package may supersede a previous generation but never overwrites it.
- Issued certificate metadata, package generation, and runtime activation state are separate concepts.

Lifecycle states reserved by the data model:

- `ISSUED`
- `PACKAGED`
- `PULLED`
- `VERIFIED`
- `STAGED`
- `APPROVED`
- `ACTIVATED`
- `ROLLED_BACK`
- `REVOKED`
- `EXPIRED`

REST enrollment is available only over HTTPS/mTLS and still honors agent token authorization when enabled. A CSR package request validates:

- CSR parse and CSR signature.
- Known application identity and matching `application_uri`.
- Matching `runtime_instance_id`, zone, role, and profile policy.
- URI SAN matching `application_uri` when present.
- No wildcard DNS SANs by default.
- Required key usage and extended key usage from the selected profile.
- Runtime compatibility before signing and before package creation.

Package manifests are signed with the existing Ed25519 GDS signing key. The manifest includes a hash tree (`payload_sha256`, `files_sha256`, `manifest_sha256`) and never includes private key material.

Phase 7.2 package lifecycle visibility:

- Package list, history, events, and telemetry endpoints expose lineage without direct DB access.
- OT Agent reports package lifecycle events after pull, verification, and local dry-run staging.
- Lifecycle state transitions are non-regressive; a later `PULLED` event cannot downgrade a package already marked `STAGED`.
- `STAGED` in Phase 7 means local OT-agent package cache plus activation-plan preview only, not runtime PKI mutation.

Phase 7.C adds a minimal OPC UA-native boundary adapter on `opc.tcp://192.168.10.30:4841/LabShock/GDS/Facade`.

- Namespace: `urn:labshock:gds:facade`.
- Mode: `GDS_OPCUA_FACADE_MODE=cyber_range`.
- Real signing through the OPC UA facade is disabled by default with `GDS_OPCUA_FACADE_ALLOW_SIGNING=false`.
- This is not full OPC UA Part 12 production compliance.
- Exposed methods are restricted to capability, inventory, certificate-group, dry-run CSR validation, and package-status reads.
- Dry-run CSR validation records request/audit metadata only; it does not sign with Vault and does not create packages.
- `GetServerCapabilities` reports `enabled_operations`, `disabled_operations`, `runtime_write_enabled=false`, `dry_run_only=true`, and `part12_full_compliance=false`.
- `CreateSigningRequestDryRun` remains available in the default mode and never signs or packages.
- `CreateSigningRequest` returns structured `error_code=opcua_signing_disabled` unless `GDS_OPCUA_FACADE_ALLOW_SIGNING=true` is set for a controlled lab test.
- REST HTTPS/mTLS endpoints remain the authoritative package issuance path.
- No OPC UA method may mutate runtime trust stores, activation state, approvals, maintenance policy, revocation state, or live trust lists.
- Responses never include private keys, Vault tokens, AppRole IDs, raw manifests, runtime paths, or policy blobs.

## Notes

- All write operations create audit events.
- Administrative endpoints are still intentionally lab-oriented; OT pull endpoints can layer mTLS plus token auth.
- Optional pull authentication is available with `GDS_AGENT_AUTH_ENABLED=true` and a token map file (`GDS_AGENT_TOKENS_FILE`).
- REST CSR issuance, controlled renewal packaging, and governed certificate revocation are implemented through Vault PKI.
- Revocation propagation to OT runtimes starts as a Phase 8.4 dry-run: GDS refreshes CRL state, while OT Agent reports affected runtime trust entries without deletion or restart.
- Fallback import from `/shared-pki/source/issued` remains supported at startup for migration/reference only.
- Trust artifacts are signed with a detached Ed25519 signature using a persisted key under `GDS_TRUST_ARTIFACT_SIGNING_KEY_PATH`.
- Signature and `artifact_sha256` are computed from canonical deterministic JSON bytes only (sorted keys, compact separators, UTF-8).
- Canonical view endpoint returns the exact signed semantic payload and its SHA256 (`/artifact/canonical`).
- Artifact regeneration is automatic on trustlist version changes and TTL threshold (`GDS_TRUST_ARTIFACT_REGEN_THRESHOLD_PERCENT`).
- A background scheduler scans trust artifacts and performs TTL refresh (`reason=ttl_refresh`) before expiration.
- Previous artifact revisions remain queryable from history endpoint.
- Debug mode: `GDS_SIGN_DEBUG=true` logs canonical SHA256 and payload length at signing time.
- When agent auth is enabled, signed pull endpoints require:
  - `X-GDS-Agent-ID`
  - `X-GDS-Agent-Token`
- GDS writes audit events for:
  - `agent_auth_success`
  - `agent_auth_failure`
  - `agent_unauthorized_pull`
  - `mtls_client_identity_success`
  - `mtls_client_identity_failure`
  - `certificate_request_created`
  - `csr_validated`
  - `csr_rejected`
  - `certificate_issued`
  - `certificate_package_created`
  - `package_manifest_read`
  - `package_pulled`
  - `package_verified`
  - `package_staged`
  - `package_history_read`
  - `package_lifecycle_telemetry_read`

## Kali Validation

```bash
docker compose --profile gds build gds
docker compose --profile gds up -d --force-recreate gds
sudo ./switch/attach_dmz.sh
curl -s http://192.168.10.30:8081/health | jq
curl -s --cacert ./gds/config/tls/ca.crt --cert ./gds-agent/config/tls/client.crt --key ./gds-agent/config/tls/client.key https://192.168.10.30:8443/health | jq
curl -s http://192.168.10.30:8081/api/v1/vault/status | jq
curl -s http://192.168.10.30:8081/api/v1/signing/trust-anchor | jq
curl -s http://192.168.10.30:8081/api/v1/applications | jq
curl -s -X POST http://192.168.10.30:8081/api/v1/trustlists/build -H 'Content-Type: application/json' -d '{"zone":"DMZ","role":"southbound-client"}' | jq
curl -s http://192.168.10.30:8081/api/v1/trustlists/DMZ/southbound-client | jq
curl -s http://192.168.10.30:8081/api/v1/trustlists/OT/server/artifact | jq
curl -s http://192.168.10.30:8081/api/v1/trustlists/OT/server/artifact.sig | jq
curl -s http://192.168.10.30:8081/api/v1/trustlists/OT/server/artifact/canonical | jq
curl -s -X POST http://192.168.10.30:8081/api/v1/trustlists/OT/server/artifact/rebuild | jq
curl -s http://192.168.10.30:8081/api/v1/trustlists/OT/server/artifact/history | jq
curl -s http://192.168.10.30:8081/api/v1/mtls/metrics | jq
curl -s http://192.168.10.30:8081/api/v1/certificates/telemetry | jq
curl -s http://192.168.10.30:8081/api/v1/certificates/drift | jq
curl -s http://192.168.10.30:8081/api/v1/audit/events | jq

# optional authenticated pull mode
cp ./gds/config/secrets/gds-agent-tokens.example.json ./gds/config/secrets/gds-agent-tokens.json
cp ./gds-agent/config/secrets/token.example ./gds-agent/config/secrets/token
export GDS_AGENT_AUTH_ENABLED=true
docker compose --profile gds up -d --force-recreate gds

# should return 200 with valid headers
curl -s http://192.168.10.30:8081/api/v1/signing/trust-anchor \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: ChangeMe_OtGdsAgentToken" | jq

# should return 403 when agent credentials call admin endpoint
curl -i -s http://192.168.10.30:8081/api/v1/audit/events \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: ChangeMe_OtGdsAgentToken"

# Phase 6 mTLS optional-mode failure should be app-layer/audited.
export GDS_MTLS_MODE=optional
docker compose --profile gds up -d --force-recreate gds
sudo ./switch/attach_dmz.sh
curl -sk -i https://192.168.10.30:8443/health
curl -s http://192.168.10.30:8081/api/v1/audit/events | jq '.[] | select(.event_type=="mtls_client_identity_failure")'

# Phase 6 mTLS required-mode failure should fail at TLS/Nginx.
export GDS_MTLS_MODE=required
docker compose --profile gds up -d --force-recreate gds
sudo ./switch/attach_dmz.sh
curl -sk -i https://192.168.10.30:8443/health

# Signed artifact pull over HTTPS/mTLS with token headers.
curl -s --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: ChangeMe_OtGdsAgentToken" \
  https://192.168.10.30:8443/api/v1/signing/trust-anchor | tee /tmp/gds-trust-anchor.json | jq

# If .fingerprint_sha256 is null, inspect the complete body. Rejections include error_code.
jq . /tmp/gds-trust-anchor.json

# Validate token policy and client-cert CA wiring inside the lab.
docker exec labshock_gds test -r /etc/labshock-gds-agent-auth/gds-agent-tokens.json
openssl verify -CAfile ./gds/config/tls/ca.crt ./gds-agent/config/tls/client.crt

# If the client cert was issued by a separate client CA, place that CA under ./gds/config/tls
# and point Nginx at it. docker-compose honors this override.
export GDS_TLS_CLIENT_CA_FILE=/etc/labshock-gds-tls/client-ca.crt
docker compose --profile gds up -d --force-recreate gds

# If the token policy file is missing, create the lab defaults.
cp ./gds/config/secrets/gds-agent-tokens.example.json ./gds/config/secrets/gds-agent-tokens.json
cp ./gds-agent/config/secrets/token.example ./gds-agent/config/secrets/token

# Phase 6.1 lab-only mTLS fixtures and negative paths.
# Use the built GDS image so the cryptography dependency is present.
docker run --rm -v "$PWD:/work" -w /work labshock-gds python gds/scripts/generate_mtls_test_certs.py --out-dir ./gds/config/tls/lab-fixtures
curl -sk -i https://192.168.10.30:8443/health
curl -s --cacert ./gds/config/tls/lab-fixtures/ca.crt --cert ./gds/config/tls/lab-fixtures/valid.crt --key ./gds/config/tls/lab-fixtures/valid.key https://192.168.10.30:8443/health | jq
curl -sk --cert ./gds/config/tls/lab-fixtures/expired.crt --key ./gds/config/tls/lab-fixtures/expired.key https://192.168.10.30:8443/health
curl -sk --cert ./gds/config/tls/lab-fixtures/rogue.crt --key ./gds/config/tls/lab-fixtures/rogue.key https://192.168.10.30:8443/health
cp ./gds/config/tls/lab-fixtures/client-ca.crl.pem ./gds/config/tls/client-ca.crl.pem
export GDS_TLS_CLIENT_CRL_FILE=/etc/labshock-gds-tls/client-ca.crl.pem
docker compose --profile gds up -d --force-recreate gds
sudo ./switch/attach_dmz.sh
curl -sk --cacert ./gds/config/tls/lab-fixtures/ca.crt --cert ./gds/config/tls/lab-fixtures/revoked.crt --key ./gds/config/tls/lab-fixtures/revoked.key https://192.168.10.30:8443/health
curl -i -s http://192.168.10.30:8081/health -H 'X-Client-Cert-Verify: SUCCESS'

# Phase 7 REST CSR enrollment and immutable package retrieval.
# Ensure the Vault signing role exists for the lab.
docker exec -i \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" \
  labshock_vault vault write pki-int/roles/opcua-application \
    allowed_domains="dataprotect,local,opcua" \
    allow_subdomains=true \
    allow_any_name=true \
    allow_ip_sans=true \
    allow_uri_sans=true \
    client_flag=true \
    server_flag=true \
    key_usage="DigitalSignature,KeyEncipherment" \
    ext_key_usage="ServerAuth,ClientAuth" \
    max_ttl="720h"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout /tmp/phase7-client.key \
  -out /tmp/phase7-client.csr \
  -subj "/CN=FuxaClient" \
  -addext "subjectAltName=URI:urn:dataprotect:opcua:fuxa-client,DNS:fuxa-client,IP:192.168.1.60" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=clientAuth"

jq -n --arg csr "$(cat /tmp/phase7-client.csr)" '{
  application_uri:"urn:dataprotect:opcua:fuxa-client",
  runtime_instance_id:"urn:dataprotect:opcua:fuxa-client",
  profile_name:"node-opcua-client",
  csr_pem:$csr
}' > /tmp/phase7-enroll.json

curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  -H "Content-Type: application/json" \
  --data @/tmp/phase7-enroll.json \
  https://192.168.10.30:8443/api/v1/enrollments/rest/csr \
  | tee /tmp/phase7-package.json | jq

PKG=$(jq -r .package_id /tmp/phase7-package.json)
curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  "https://192.168.10.30:8443/api/v1/packages/$PKG/manifest" \
  | jq '.package_id,.generation,.compatibility.status,.install_plan.runtime_write_enabled'

curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  "https://192.168.10.30:8443/api/v1/packages?application_uri=urn:dataprotect:opcua:fuxa-client" | jq

curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  "https://192.168.10.30:8443/api/v1/packages/$PKG/history" | jq

curl -sS --cacert ./gds/config/tls/ca.crt \
  --cert ./gds-agent/config/tls/client.crt \
  --key ./gds-agent/config/tls/client.key \
  -H "X-GDS-Agent-ID: ot-gds-agent" \
  -H "X-GDS-Agent-Token: $(sudo cat ./gds-agent/config/secrets/token)" \
  "https://192.168.10.30:8443/api/v1/packages/telemetry" | jq

# Phase 7 OPC UA facade dry-run contract validation.
# Pass --csr-pem-file for the optional valid CSR dry-run check.
python gds/scripts/validate_phase_7_facade_contract.py \
  --endpoint opc.tcp://192.168.10.30:4841/LabShock/GDS/Facade \
  --application-uri urn:dataprotect:opcua:fuxa-client \
  --profile-name node-opcua-client
```
# GDS CRL and trust distribution notes

LabShock GDS is the control plane for OT and DMZ OPC UA certificate discovery,
CSR validation, Vault signing, trust-list composition, revocation state, package
lineage, and audit. Runtime PKI writes remain delegated to the local runtime
side: the OT Agent for OT components, and the native DMZ Gateway GDS client for
DMZ gateway identities. GDS never accepts or returns private keys.

Root CA CRLs must be fetched from the Vault issuer-specific endpoint, not the
mount-level CRL endpoint, because the mount-level Root CRL can be stale:

```text
/v1/pki-root/issuer/<root_issuer_id>/crl/pem
```

The default lab issuer is:

```text
f4e8cc06-e50b-dd54-6fbf-752dd4180352
```

Relevant settings:

```text
GDS__VAULT__ROOT_PKI_MOUNT=pki-root
GDS__VAULT__INTERMEDIATE_PKI_MOUNT=pki-int
GDS__VAULT__ROOT_ISSUER_ID=f4e8cc06-e50b-dd54-6fbf-752dd4180352
GDS__VAULT__ROOT_CRL_MODE=issuer_specific
GDS__VAULT__INTERMEDIATE_CRL_MODE=mount_or_issuer
GDS__VAULT__STRICT_CRL_FRESHNESS=true
```

Trust artifacts include non-secret CRL metadata for both Root and Intermediate
CRLs, including source, issuer, nextUpdate, SHA256, and
`crl_freshness_verified=true`. If strict freshness is enabled, expired,
unparsable, or missing-nextUpdate CRLs fail artifact generation.

For the OT/server consumer trustlist, GDS composes trust from authorized client
producer identities rather than static files. The current relationship mapping
includes the DMZ Gateway southbound client and the FUXA client, using each
component's active non-revoked certificate.

Run the end-to-end validation helper after rotations:

```bash
scripts/validate-gds-opcua-e2e.sh
```
