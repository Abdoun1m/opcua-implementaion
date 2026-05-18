#!/bin/sh
set -eu

APP="/app/build/opcua_dmz_gateway"
OT_HOST="${OT_HOST:-192.168.1.62}"
OT_PORT="${OT_PORT:-4840}"

echo "[ENTRYPOINT] Starting DMZ OPC UA gateway bootstrap"

case "${1:-}" in
  --gds-*)
    exec "${APP}" "$@"
    ;;
esac

attempt=1
while ! ip link show eth0 >/dev/null 2>&1; do
  if [ $((attempt % 10)) -eq 1 ]; then
    echo "[ENTRYPOINT] waiting for DMZ network interface eth0 attempt=${attempt}"
  fi
  attempt=$((attempt + 1))
  sleep 1
done

attempt=1
while ! ip -4 addr show dev eth0 | grep -q "inet "; do
  if [ $((attempt % 10)) -eq 1 ]; then
    echo "[ENTRYPOINT] waiting for IPv4 address on eth0 attempt=${attempt}"
  fi
  attempt=$((attempt + 1))
  sleep 1
done

attempt=1
while ! nc -z "${OT_HOST}" "${OT_PORT}" >/dev/null 2>&1; do
  if [ $((attempt % 10)) -eq 1 ]; then
    echo "[ENTRYPOINT] waiting for OT endpoint ${OT_HOST}:${OT_PORT} attempt=${attempt}"
  fi
  attempt=$((attempt + 1))
  sleep 2
done

echo "[ENTRYPOINT] DMZ network and OT endpoint reachable"

if [ "${DMZ_GDS_LIFECYCLE_ENABLED:-false}" = "true" ] || [ "${DMZ_GDS_LIFECYCLE_ENABLED:-false}" = "1" ]; then
  echo "[ENTRYPOINT] Starting DMZ GDS lifecycle loop target=${DMZ_GDS_LIFECYCLE_TARGET:-all}"
  "${APP}" --gds-lifecycle-loop --target "${DMZ_GDS_LIFECYCLE_TARGET:-all}" &
fi

exec "${APP}" "$@"
