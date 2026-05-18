#!/usr/bin/env bash
set -euo pipefail

COLLECTOR_URL="${DMZ_GATEWAY_COLLECTOR_URL:-http://192.168.10.70:9000/opcua-dmz/events}"
TOKEN_FILE="${DMZ_GATEWAY_COLLECTOR_TOKEN_FILE:-./opcua-dmz-gateway/config/secrets/dmz-collector-token}"

if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "token file not readable: $TOKEN_FILE" >&2
  exit 1
fi

TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"

payload='[
  {
    "timestamp": "2026-05-18T00:00:00Z",
    "source_type": "opcua_dmz_gateway",
    "sourcetype": "labshock:dmz:opcua_gateway",
    "zone": "DMZ",
    "asset_name": "opcua_dmz_gateway",
    "asset_ip": "192.168.10.20",
    "protocol": "opcua",
    "source": "opcua_dmz_gateway",
    "message": "opcua_dmz_started",
    "event_category": "system_health",
    "severity": "info",
    "raw": {
      "event_type": "opcua_dmz_started",
      "component": "opcua_dmz_gateway",
      "ot_endpoint": "opc.tcp://192.168.1.62:4840"
    },
    "tags": {
      "component": "opcua_dmz_gateway",
      "zone": "DMZ",
      "splunk_sourcetype": "labshock:dmz:opcua_gateway",
      "risk_level": "LOW",
      "alert_candidate": false
    }
  },
  {
    "timestamp": "2026-05-18T00:00:01Z",
    "source_type": "opcua_dmz_gateway",
    "sourcetype": "labshock:dmz:opcua_gateway",
    "zone": "DMZ",
    "asset_name": "opcua_dmz_gateway",
    "asset_ip": "192.168.10.20",
    "protocol": "opcua",
    "source": "opcua_dmz_gateway",
    "message": "opcua_dmz_gds_trust_pull_success",
    "event_category": "pki_trust_sync",
    "severity": "info",
    "raw": {
      "event_type": "trust_pull_completed",
      "target": "dmz-gateway-client",
      "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
      "status": "completed"
    },
    "tags": {
      "component": "opcua_dmz_gateway",
      "zone": "DMZ",
      "splunk_sourcetype": "labshock:dmz:opcua_gateway",
      "risk_level": "LOW",
      "alert_candidate": false
    }
  },
  {
    "timestamp": "2026-05-18T00:00:02Z",
    "source_type": "opcua_dmz_gateway",
    "sourcetype": "labshock:dmz:opcua_gateway",
    "zone": "DMZ",
    "asset_name": "opcua_dmz_gateway",
    "asset_ip": "192.168.10.20",
    "protocol": "opcua",
    "source": "opcua_dmz_gateway",
    "message": "opcua_dmz_southbound_connect_failed",
    "event_category": "opcua_session",
    "severity": "warning",
    "raw": {
      "event_type": "southbound_connect_failed",
      "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
      "endpoint": "opc.tcp://192.168.1.62:4840",
      "status_name": "BadSecurityChecksFailed"
    },
    "tags": {
      "component": "opcua_dmz_gateway",
      "zone": "DMZ",
      "splunk_sourcetype": "labshock:dmz:opcua_gateway",
      "risk_level": "MEDIUM",
      "alert_candidate": true
    }
  }
]'

curl -sS -X POST "$COLLECTOR_URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data "$payload"
echo
