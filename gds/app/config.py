import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _env_file_text(name: str, default: str) -> str:
    path = _env(name, default)
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


@dataclass(frozen=True)
class Settings:
    service_name: str
    service_version: str
    http_port: int
    health_path: str
    startup_retries: int
    startup_retry_seconds: int
    pg_host: str
    pg_port: int
    pg_db: str
    pg_user: str
    pg_password: str
    pg_connect_timeout: int
    vault_addr: str
    vault_health_path: str
    vault_timeout_seconds: int
    vault_tls_ca_file: str
    vault_tls_client_cert: str
    vault_tls_client_key: str
    vault_tls_verify: bool
    vault_role_id_file: str
    vault_secret_id_file: str
    vault_approle_login_path: str
    vault_token_lookup_path: str
    vault_token_renew_path: str
    vault_pki_mount: str
    vault_root_pki_mount: str
    vault_intermediate_pki_mount: str
    vault_root_issuer_id: str
    vault_intermediate_issuer_id: str
    vault_root_crl_mode: str
    vault_intermediate_crl_mode: str
    vault_strict_crl_freshness: bool
    vault_token_renew_margin_seconds: int
    vault_allow_unauthenticated_pki_read: bool
    fallback_shared_pki_root: str
    opcua_facade_enabled: bool
    opcua_facade_host: str
    opcua_facade_port: int
    opcua_facade_mode: str
    opcua_facade_allow_signing: bool
    opcua_facade_max_csr_bytes: int
    opcua_facade_session_request_limit: int
    opcua_facade_client_enrollment_limit: int
    data_dir: str
    trust_artifact_signing_key_path: str
    trust_artifact_signing_key_id: str
    trust_artifact_ttl_seconds: int
    trust_artifact_regen_threshold_percent: int
    trust_artifact_scan_interval_seconds: int
    trust_artifact_regen_min_interval_seconds: int
    sign_debug: bool
    agent_auth_enabled: bool
    agent_tokens_file: str
    mtls_mode: str
    trusted_proxy_ips: tuple[str, ...]
    internal_proxy_secret: str
    internal_proxy_secret_file: str
    cert_expiry_warning_days: int
    cert_expiry_critical_days: int
    renewal_threshold_days: int
    tls_client_crl_file: str
    vault_sign_role: str
    cert_default_ttl: str
    dmz_collector_enabled: bool
    dmz_collector_url: str
    dmz_collector_token_file: str
    dmz_collector_poll_interval_seconds: int
    dmz_collector_health_interval_seconds: int
    dmz_collector_db_summary_interval_seconds: int
    dmz_collector_batch_size: int
    dmz_collector_timeout_seconds: int
    dmz_collector_max_message_len: int
    dmz_collector_max_raw_len: int
    dmz_collector_max_payload_bytes: int

    @property
    def pg_dsn(self) -> str:
        return (
            f"host={self.pg_host} "
            f"port={self.pg_port} "
            f"dbname={self.pg_db} "
            f"user={self.pg_user} "
            f"password={self.pg_password} "
            f"connect_timeout={self.pg_connect_timeout}"
        )


def load_settings() -> Settings:
    ttl_minutes = _env_int("GDS_TRUST_ARTIFACT_TTL_MINUTES", 15)
    ttl_seconds = _env_int("GDS_TRUST_ARTIFACT_TTL_SECONDS", ttl_minutes * 60)
    regen_threshold_pct = _env_int("GDS_TRUST_ARTIFACT_REGEN_THRESHOLD_PCT", _env_int("GDS_TRUST_ARTIFACT_REGEN_THRESHOLD_PERCENT", 20))
    trusted_proxy_ips = tuple(
        ip.strip()
        for ip in _env("GDS_TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",")
        if ip.strip()
    )
    internal_proxy_secret_file = _env("GDS_INTERNAL_PROXY_SECRET_FILE", "/run/secrets/gds-internal-proxy/secret")
    internal_proxy_secret = _env("GDS_INTERNAL_PROXY_SECRET", "") or _env_file_text(
        "GDS_INTERNAL_PROXY_SECRET_FILE",
        internal_proxy_secret_file,
    )
    return Settings(
        service_name=_env("GDS_SERVICE_NAME", "labshock-gds-bootstrap"),
        service_version=_env("GDS_SERVICE_VERSION", "0.1.0-phase1"),
        http_port=_env_int("GDS_HTTP_PORT", 8081),
        health_path=_env("GDS_HEALTH_PATH", "/health"),
        startup_retries=_env_int("GDS_STARTUP_RETRIES", 20),
        startup_retry_seconds=_env_int("GDS_STARTUP_RETRY_SECONDS", 3),
        pg_host=_env("GDS__DB__HOST", "192.168.10.31"),
        pg_port=_env_int("GDS__DB__PORT", 5432),
        pg_db=_env("GDS__DB__NAME", "labshock_gds"),
        pg_user=_env("GDS__DB__USER", "gds"),
        pg_password=_env("GDS__DB__PASSWORD", "ChangeMe_GDS_DB!"),
        pg_connect_timeout=_env_int("GDS_DB_CONNECT_TIMEOUT", 3),
        vault_addr=_env("GDS__VAULT__ADDR", "https://192.168.10.10:8200"),
        vault_health_path=_env("GDS_VAULT_HEALTH_PATH", "/v1/sys/health"),
        vault_timeout_seconds=_env_int("GDS_VAULT_TIMEOUT_SECONDS", 3),
        vault_tls_ca_file=_env("GDS__VAULT__TLS_CA_FILE", "/etc/labshock-vault-tls/ca.crt"),
        vault_tls_client_cert=_env("GDS__VAULT__TLS_CLIENT_CERT", "/etc/labshock-vault-tls/client.crt"),
        vault_tls_client_key=_env("GDS__VAULT__TLS_CLIENT_KEY", "/etc/labshock-vault-tls/client.key"),
        vault_tls_verify=_env_bool("GDS__VAULT__TLS_VERIFY", True),
        vault_role_id_file=_env("GDS__VAULT__ROLE_ID_FILE", "/run/secrets/role_id"),
        vault_secret_id_file=_env("GDS__VAULT__SECRET_ID_FILE", "/run/secrets/secret_id"),
        vault_approle_login_path=_env("GDS__VAULT__APPROLE_LOGIN_PATH", "/v1/auth/approle/login"),
        vault_token_lookup_path=_env("GDS__VAULT__TOKEN_LOOKUP_PATH", "/v1/auth/token/lookup-self"),
        vault_token_renew_path=_env("GDS__VAULT__TOKEN_RENEW_PATH", "/v1/auth/token/renew-self"),
        vault_pki_mount=_env("GDS__VAULT__PKI_MOUNT", "pki-int"),
        vault_root_pki_mount=_env("GDS__VAULT__ROOT_PKI_MOUNT", "pki-root"),
        vault_intermediate_pki_mount=_env("GDS__VAULT__INTERMEDIATE_PKI_MOUNT", _env("GDS__VAULT__PKI_MOUNT", "pki-int")),
        vault_root_issuer_id=_env("GDS__VAULT__ROOT_ISSUER_ID", "f4e8cc06-e50b-dd54-6fbf-752dd4180352"),
        vault_intermediate_issuer_id=_env("GDS__VAULT__INTERMEDIATE_ISSUER_ID", ""),
        vault_root_crl_mode=_env("GDS__VAULT__ROOT_CRL_MODE", "issuer_specific"),
        vault_intermediate_crl_mode=_env("GDS__VAULT__INTERMEDIATE_CRL_MODE", "mount_or_issuer"),
        vault_strict_crl_freshness=_env_bool("GDS__VAULT__STRICT_CRL_FRESHNESS", True),
        vault_token_renew_margin_seconds=_env_int("GDS__VAULT__TOKEN_RENEW_MARGIN_SECONDS", 300),
        vault_allow_unauthenticated_pki_read=_env_bool("GDS__VAULT__ALLOW_UNAUTHENTICATED_PKI_READ", False),
        fallback_shared_pki_root=_env("GDS_FALLBACK_SHARED_PKI_ROOT", "/shared-pki/source/issued"),
        opcua_facade_enabled=_env_bool("GDS_OPCUA_FACADE_ENABLED", _env_bool("GDS_OPCUA_PLACEHOLDER_ENABLED", True)),
        opcua_facade_host=_env("GDS_OPCUA_FACADE_HOST", _env("GDS_OPCUA_PLACEHOLDER_HOST", "0.0.0.0")),
        opcua_facade_port=_env_int("GDS_OPCUA_FACADE_PORT", _env_int("GDS_OPCUA_PLACEHOLDER_PORT", 4841)),
        opcua_facade_mode=_env("GDS_OPCUA_FACADE_MODE", "cyber_range"),
        opcua_facade_allow_signing=_env_bool("GDS_OPCUA_FACADE_ALLOW_SIGNING", False),
        opcua_facade_max_csr_bytes=_env_int("GDS_OPCUA_FACADE_MAX_CSR_BYTES", 8192),
        opcua_facade_session_request_limit=_env_int("GDS_OPCUA_FACADE_SESSION_REQUEST_LIMIT", 60),
        opcua_facade_client_enrollment_limit=_env_int("GDS_OPCUA_FACADE_CLIENT_ENROLLMENT_LIMIT", 10),
        data_dir=_env("GDS_DATA_DIR", "/var/lib/labshock-gds"),
        trust_artifact_signing_key_path=_env("GDS_TRUST_ARTIFACT_SIGNING_KEY_PATH", "/var/lib/labshock-gds/signing/trust-artifact-ed25519.pem"),
        trust_artifact_signing_key_id=_env("GDS_TRUST_ARTIFACT_SIGNING_KEY_ID", "gds-trust-artifact-v1"),
        trust_artifact_ttl_seconds=ttl_seconds,
        trust_artifact_regen_threshold_percent=regen_threshold_pct,
        trust_artifact_scan_interval_seconds=_env_int("GDS_TRUST_ARTIFACT_SCAN_INTERVAL_SECONDS", 30),
        trust_artifact_regen_min_interval_seconds=_env_int("GDS_TRUST_ARTIFACT_REGEN_MIN_INTERVAL_SECONDS", 30),
        sign_debug=_env_bool("GDS_SIGN_DEBUG", False),
        agent_auth_enabled=_env_bool("GDS_AGENT_AUTH_ENABLED", False),
        agent_tokens_file=_env("GDS_AGENT_TOKENS_FILE", "/etc/labshock-gds-agent-auth/gds-agent-tokens.json"),
        mtls_mode=_env("GDS_MTLS_MODE", "optional").strip().lower(),
        trusted_proxy_ips=trusted_proxy_ips,
        internal_proxy_secret=internal_proxy_secret,
        internal_proxy_secret_file=internal_proxy_secret_file,
        cert_expiry_warning_days=_env_int("GDS_CERT_EXPIRY_WARNING_DAYS", 30),
        cert_expiry_critical_days=_env_int("GDS_CERT_EXPIRY_CRITICAL_DAYS", 7),
        renewal_threshold_days=_env_int("GDS_RENEWAL_THRESHOLD_DAYS", 7),
        tls_client_crl_file=_env("GDS_TLS_CLIENT_CRL_FILE", "/etc/labshock-gds-tls/client-ca.crl.pem"),
        vault_sign_role=_env("GDS_VAULT_SIGN_ROLE", "opcua-application"),
        cert_default_ttl=_env("GDS_CERT_DEFAULT_TTL", "720h"),
        dmz_collector_enabled=_env_bool("GDS_DMZ_COLLECTOR_ENABLED", False),
        dmz_collector_url=_env("GDS_DMZ_COLLECTOR_URL", "http://192.168.10.70:9000/gds/events"),
        dmz_collector_token_file=_env("GDS_DMZ_COLLECTOR_TOKEN_FILE", "/etc/labshock-gds-agent-auth/dmz-collector-token"),
        dmz_collector_poll_interval_seconds=_env_int("GDS_DMZ_COLLECTOR_POLL_INTERVAL_SECONDS", 5),
        dmz_collector_health_interval_seconds=_env_int("GDS_DMZ_COLLECTOR_HEALTH_INTERVAL_SECONDS", 300),
        dmz_collector_db_summary_interval_seconds=_env_int("GDS_DMZ_COLLECTOR_DB_SUMMARY_INTERVAL_SECONDS", 300),
        dmz_collector_batch_size=_env_int("GDS_DMZ_COLLECTOR_BATCH_SIZE", 100),
        dmz_collector_timeout_seconds=_env_int("GDS_DMZ_COLLECTOR_TIMEOUT_SECONDS", 3),
        dmz_collector_max_message_len=_env_int("GDS_DMZ_COLLECTOR_MAX_MESSAGE_LEN", 512),
        dmz_collector_max_raw_len=_env_int("GDS_DMZ_COLLECTOR_MAX_RAW_LEN", 4096),
        dmz_collector_max_payload_bytes=_env_int("GDS_DMZ_COLLECTOR_MAX_PAYLOAD_BYTES", 16384),
    )
