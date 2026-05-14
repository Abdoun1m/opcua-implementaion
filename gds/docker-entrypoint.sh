#!/usr/bin/env sh
set -eu

echo "[gds-entrypoint] waiting for DMZ network interface"

i=0
while [ "$i" -lt 60 ]; do
  if python - <<'PY'
import socket, sys
targets = [("192.168.10.31", 5432), ("192.168.10.10", 8200)]
for host, port in targets:
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((host, port))
    except Exception:
        sys.exit(1)
    finally:
        s.close()
sys.exit(0)
PY
  then
    echo "[gds-entrypoint] DMZ dependencies reachable"
    break
  fi

  i=$((i + 1))
  echo "[gds-entrypoint] waiting for DMZ attach... attempt $i/60"
  sleep 2
done

if [ "$i" -ge 60 ]; then
  echo "[gds-entrypoint] ERROR: DMZ dependencies not reachable after timeout"
  exit 1
fi

echo "[gds-entrypoint] running startup preflight checks"
python -m app.preflight

GDS_UVICORN_INTERNAL_PORT="${GDS_UVICORN_INTERNAL_PORT:-18081}"
GDS_TLS_PROFILE="${GDS_TLS_PROFILE:-lab}"
GDS_MTLS_MODE="${GDS_MTLS_MODE:-optional}"
GDS_TLS_SERVER_CERT_FILE="${GDS_TLS_SERVER_CERT_FILE:-/etc/labshock-gds-tls/server.crt}"
GDS_TLS_SERVER_KEY_FILE="${GDS_TLS_SERVER_KEY_FILE:-/etc/labshock-gds-tls/server.key}"
GDS_TLS_CLIENT_CA_FILE="${GDS_TLS_CLIENT_CA_FILE:-/etc/labshock-gds-tls/ca.crt}"
GDS_TLS_CLIENT_CRL_FILE="${GDS_TLS_CLIENT_CRL_FILE:-/etc/labshock-gds-tls/client-ca.crl.pem}"
GDS_INTERNAL_PROXY_SECRET_FILE="${GDS_INTERNAL_PROXY_SECRET_FILE:-/run/secrets/gds-internal-proxy/secret}"

case "$GDS_TLS_PROFILE" in
  lab)
    GDS_NGINX_SSL_PROTOCOLS="TLSv1.2 TLSv1.3"
    ;;
  strict)
    GDS_NGINX_SSL_PROTOCOLS="TLSv1.3"
    ;;
  *)
    echo "[gds-entrypoint] ERROR: invalid GDS_TLS_PROFILE=$GDS_TLS_PROFILE (expected lab|strict)"
    exit 1
    ;;
esac

case "$GDS_MTLS_MODE" in
  optional)
    GDS_NGINX_SSL_VERIFY_CLIENT="optional"
    ;;
  required)
    GDS_NGINX_SSL_VERIFY_CLIENT="on"
    ;;
  *)
    echo "[gds-entrypoint] ERROR: invalid GDS_MTLS_MODE=$GDS_MTLS_MODE (expected optional|required)"
    exit 1
    ;;
esac

for tls_file in "$GDS_TLS_SERVER_CERT_FILE" "$GDS_TLS_SERVER_KEY_FILE" "$GDS_TLS_CLIENT_CA_FILE"; do
  if [ ! -r "$tls_file" ]; then
    echo "[gds-entrypoint] ERROR: required TLS file not readable: $tls_file"
    echo "[gds-entrypoint] mount TLS material under /etc/labshock-gds-tls or set GDS_TLS_*_FILE"
    exit 1
  fi
done

GDS_NGINX_SSL_CRL_DIRECTIVE=""
if [ -r "$GDS_TLS_CLIENT_CRL_FILE" ]; then
  GDS_NGINX_SSL_CRL_DIRECTIVE="ssl_crl $GDS_TLS_CLIENT_CRL_FILE;"
fi

if [ "${GDS_INTERNAL_PROXY_SECRET:-}" = "" ]; then
  if [ -r "$GDS_INTERNAL_PROXY_SECRET_FILE" ]; then
    GDS_INTERNAL_PROXY_SECRET="$(tr -d '\r\n' < "$GDS_INTERNAL_PROXY_SECRET_FILE")"
  else
    GDS_INTERNAL_PROXY_SECRET="$(python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  fi
fi

if [ "$GDS_INTERNAL_PROXY_SECRET" = "" ]; then
  echo "[gds-entrypoint] ERROR: internal proxy secret is empty"
  exit 1
fi
case "$GDS_INTERNAL_PROXY_SECRET" in
  *[!A-Za-z0-9._-]*)
    echo "[gds-entrypoint] ERROR: internal proxy secret contains unsupported characters"
    exit 1
    ;;
esac
export GDS_INTERNAL_PROXY_SECRET

mkdir -p /tmp/nginx/client_body /tmp/nginx/proxy /tmp/nginx/fastcgi /tmp/nginx/uwsgi /tmp/nginx/scgi
sed \
  -e "s|__GDS_UVICORN_INTERNAL_PORT__|$GDS_UVICORN_INTERNAL_PORT|g" \
  -e "s|__GDS_TLS_SERVER_CERT_FILE__|$GDS_TLS_SERVER_CERT_FILE|g" \
  -e "s|__GDS_TLS_SERVER_KEY_FILE__|$GDS_TLS_SERVER_KEY_FILE|g" \
  -e "s|__GDS_TLS_CLIENT_CA_FILE__|$GDS_TLS_CLIENT_CA_FILE|g" \
  -e "s|__GDS_NGINX_SSL_VERIFY_CLIENT__|$GDS_NGINX_SSL_VERIFY_CLIENT|g" \
  -e "s|__GDS_NGINX_SSL_PROTOCOLS__|$GDS_NGINX_SSL_PROTOCOLS|g" \
  -e "s|__GDS_NGINX_SSL_CRL_DIRECTIVE__|$GDS_NGINX_SSL_CRL_DIRECTIVE|g" \
  -e "s|__GDS_INTERNAL_PROXY_SECRET__|$GDS_INTERNAL_PROXY_SECRET|g" \
  /app/nginx/gds.conf.template > /tmp/labshock-gds-nginx.conf

echo "[gds-entrypoint] starting Uvicorn on 127.0.0.1:$GDS_UVICORN_INTERNAL_PORT"
uvicorn app.main:app --host 127.0.0.1 --port "$GDS_UVICORN_INTERNAL_PORT" &
uvicorn_pid="$!"

term_handler() {
  echo "[gds-entrypoint] stopping services"
  kill "$uvicorn_pid" 2>/dev/null || true
  exit 0
}
trap term_handler INT TERM

echo "[gds-entrypoint] starting Nginx edge http=8081 https=8443 tls_profile=$GDS_TLS_PROFILE mtls_mode=$GDS_MTLS_MODE"
nginx -c /tmp/labshock-gds-nginx.conf -g "daemon off;" &
nginx_pid="$!"

wait "$nginx_pid"
status="$?"
kill "$uvicorn_pid" 2>/dev/null || true
exit "$status"
