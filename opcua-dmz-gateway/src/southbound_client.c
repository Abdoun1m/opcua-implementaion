#include "southbound_client.h"
#include "dmz_config.h"
#include "whitelist.h"
#include "cache.h"
#include "influx_writer.h"
#include "dmz_telemetry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <open62541/client_highlevel.h>
#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>

#define BASIC256SHA256_URI "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
#define CLIENT_APP_URI     "urn:dataprotect:opcua:dmz-gateway-client"

/* Taille batch Influx */
#define INFLUX_BATCH_SIZE 32768

static const char *status_name_safe(UA_StatusCode code) {
    const char *name = UA_StatusCode_name(code);
    return name ? name : "UnknownStatus";
}

static const char *env_or_default(const char *name, const char *fallback) {
    const char *v = getenv(name);
    if(v && v[0] != '\0')
        return v;
    return fallback;
}

static UA_ByteString load_file(const char *path) {
    UA_ByteString fileContents = UA_BYTESTRING_NULL;

    FILE *fp = fopen(path, "rb");
    if(!fp) {
        fprintf(stderr, "[DMZ][FILE] Cannot open: %s\n", path);
        return fileContents;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    rewind(fp);

    if(fileSize <= 0) {
        fclose(fp);
        return fileContents;
    }

    fileContents.length = (size_t)fileSize;
    fileContents.data = (UA_Byte*)UA_malloc(fileContents.length);
    if(!fileContents.data) {
        fclose(fp);
        return UA_BYTESTRING_NULL;
    }

    fread(fileContents.data, 1, fileContents.length, fp);
    fclose(fp);

    printf("[DMZ][FILE] Loaded: %s (%lu bytes)\n",
           path, (unsigned long)fileContents.length);

    return fileContents;
}

/* -------------------------------------------------- */
/* Helpers: classification métier pour InfluxDB       */
/* -------------------------------------------------- */

static int starts_with(const char *s, const char *prefix) {
    if(!s || !prefix)
        return 0;
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/*
 * Exemples:
 *   Factory.Cuve2.NiveauHaut
 *     -> measurement=factory, plc=none, node=Cuve2.NiveauHaut
 *
 *   RailAuto.Etape1.Terminee
 *     -> measurement=railauto, plc=none, node=Etape1.Terminee
 *
 *   PowerGrid.PLC2.PE.Power
 *     -> measurement=powergrid, plc=PLC2, node=PE.Power
 *
 *   PowerGrid.PLC1.Factory.Etat
 *     -> measurement=powergrid, plc=PLC1, node=Factory.Etat
 */
static void classify_point_label(const char *label,
                                 char *measurement, size_t measurementSize,
                                 char *plcTag, size_t plcTagSize,
                                 char *nodeTag, size_t nodeTagSize) {
    if(!label) {
        snprintf(measurement, measurementSize, "unknown");
        snprintf(plcTag, plcTagSize, "system");
        snprintf(nodeTag, nodeTagSize, "unknown");
        return;
    }

    if(starts_with(label, "Factory.")) {
        snprintf(measurement, measurementSize, "factory");
        snprintf(plcTag, plcTagSize, "PLC3");

        const char *rest = label + strlen("Factory.");
        influx_sanitize_label(rest, nodeTag, nodeTagSize);
        return;
    }

    if(starts_with(label, "RailAuto.")) {
        snprintf(measurement, measurementSize, "railauto");
        snprintf(plcTag, plcTagSize, "PLC4");

        const char *rest = label + strlen("RailAuto.");
        influx_sanitize_label(rest, nodeTag, nodeTagSize);
        return;
    }

    if(starts_with(label, "RailManual.")) {
        snprintf(measurement, measurementSize, "railmanual");
        snprintf(plcTag, plcTagSize, "PLC5");

        const char *rest = label + strlen("RailManual.");
        influx_sanitize_label(rest, nodeTag, nodeTagSize);
        return;
    }

    if(starts_with(label, "PowerGrid.")) {
        snprintf(measurement, measurementSize, "powergrid");

        const char *rest = label + strlen("PowerGrid.");
        const char *dot1 = strchr(rest, '.');

        if(dot1) {
            size_t plcLen = (size_t)(dot1 - rest);
            char plcRaw[64];

            if(plcLen >= sizeof(plcRaw))
                plcLen = sizeof(plcRaw) - 1;

            memcpy(plcRaw, rest, plcLen);
            plcRaw[plcLen] = '\0';

            influx_sanitize_label(plcRaw, plcTag, plcTagSize);

            const char *nodeRest = dot1 + 1;
            influx_sanitize_label(nodeRest, nodeTag, nodeTagSize);
        } else {
            snprintf(plcTag, plcTagSize, "PowerGrid");
            influx_sanitize_label(rest, nodeTag, nodeTagSize);
        }
        return;
    }

    if(starts_with(label, "MES.Health.")) {
        snprintf(measurement, measurementSize, "mes_health");
        snprintf(plcTag, plcTagSize, "gateway");

        const char *rest = label + strlen("MES.Health.");
        influx_sanitize_label(rest, nodeTag, nodeTagSize);
        return;
    }

    snprintf(measurement, measurementSize, "misc");
    snprintf(plcTag, plcTagSize, "system");
    influx_sanitize_label(label, nodeTag, nodeTagSize);
}

static void append_line_to_batch(char *batch, size_t *batchLen, size_t batchSize,
                                 const char *line) {
    if(!batch || !batchLen || !line)
        return;

    size_t lineLen = strlen(line);

    if(*batchLen + lineLen >= batchSize) {
        fprintf(stderr, "[INFLUX] Batch full, dropping line: %s", line);
        return;
    }

    memcpy(batch + *batchLen, line, lineLen);
    *batchLen += lineLen;
    batch[*batchLen] = '\0';
}

/* -------------------------------------------------- */
/* Southbound lifecycle                               */
/* -------------------------------------------------- */

int southbound_init(SouthboundContext *ctx,
                    const char *endpointUrl,
                    const char *username,
                    const char *password) {

    if(!ctx || !endpointUrl || !username || !password)
        return 0;

    memset(ctx, 0, sizeof(*ctx));

    snprintf(ctx->endpointUrl, sizeof(ctx->endpointUrl), "%s", endpointUrl);
    snprintf(ctx->username, sizeof(ctx->username), "%s", username);
    snprintf(ctx->password, sizeof(ctx->password), "%s", password);

    ctx->client = UA_Client_new();
    if(!ctx->client) {
        fprintf(stderr, "[DMZ][INIT] UA_Client_new failed\n");
        dmz_telemetry_event("opcua_dmz_client_alloc_failed", "error", "critical",
                            dmz_telemetry_raw("ua_client_new_failed"));
        return 0;
    }

    UA_ClientConfig *config = UA_Client_getConfig(ctx->client);

    const char *pkiBase = env_or_default("DMZ_PKI_DIR", "/app/pki");
    const char *certPathEnv = getenv("DMZ_SB_CERT_PATH");
    const char *keyPathEnv = getenv("DMZ_SB_KEY_PATH");
    const char *trustOtEnv = getenv("DMZ_SB_TRUST_OT_SERVER_PATH");
    const char *trustIntEnv = getenv("DMZ_SB_TRUST_INTERMEDIATE_PATH");
    const char *trustRootEnv = getenv("DMZ_SB_TRUST_ROOT_PATH");

    char certPath[512];
    char keyPath[512];
    char trustOtPath[512];
    char trustIntPath[512];
    char trustRootPath[512];

    if(certPathEnv && certPathEnv[0] != '\0')
        snprintf(certPath, sizeof(certPath), "%s", certPathEnv);
    else
        snprintf(certPath, sizeof(certPath), "%s/southbound/own/certs/client.der", pkiBase);

    if(keyPathEnv && keyPathEnv[0] != '\0')
        snprintf(keyPath, sizeof(keyPath), "%s", keyPathEnv);
    else
        snprintf(keyPath, sizeof(keyPath), "%s/southbound/own/private/client.key.der", pkiBase);

    if(trustOtEnv && trustOtEnv[0] != '\0')
        snprintf(trustOtPath, sizeof(trustOtPath), "%s", trustOtEnv);
    else
        snprintf(trustOtPath, sizeof(trustOtPath), "%s/southbound/trusted/certs/ot_server.der", pkiBase);

    if(trustIntEnv && trustIntEnv[0] != '\0')
        snprintf(trustIntPath, sizeof(trustIntPath), "%s", trustIntEnv);
    else
        snprintf(trustIntPath, sizeof(trustIntPath), "%s/southbound/trusted/certs/vault_intermediate.der", pkiBase);

    if(trustRootEnv && trustRootEnv[0] != '\0')
        snprintf(trustRootPath, sizeof(trustRootPath), "%s", trustRootEnv);
    else
        snprintf(trustRootPath, sizeof(trustRootPath), "%s/southbound/trusted/certs/root_ca.der", pkiBase);

    UA_ByteString certificate = load_file(certPath);
    UA_ByteString privateKey  = load_file(keyPath);

    if(certificate.length == 0 || privateKey.length == 0) {
        fprintf(stderr, "[DMZ][INIT] Missing client cert/key\n");
        {
            cJSON *raw = dmz_telemetry_raw("southbound_pki_load_failed");
            cJSON_AddStringToObject(raw, "application_uri", CLIENT_APP_URI);
            cJSON_AddStringToObject(raw, "cert_path", certPath);
            cJSON_AddStringToObject(raw, "key_path", keyPath);
            cJSON_AddBoolToObject(raw, "certificate_found", certificate.length > 0 ? 1 : 0);
            cJSON_AddBoolToObject(raw, "private_key_found", privateKey.length > 0 ? 1 : 0);
            dmz_telemetry_event("opcua_dmz_pki_load_failed", "pki_validation", "critical", raw);
        }
        return 0;
    }

    UA_ByteString trustList[3];
    trustList[0] = load_file(trustOtPath);
    trustList[1] = load_file(trustIntPath);
    trustList[2] = load_file(trustRootPath);

    size_t trustListSize = 3;

    for(size_t i = 0; i < trustListSize; i++) {
        if(trustList[i].length == 0) {
            fprintf(stderr, "[DMZ][INIT] Failed to load trust cert %lu\n",
                    (unsigned long)i);
            {
                const char *trustPath = i == 0 ? trustOtPath : (i == 1 ? trustIntPath : trustRootPath);
                cJSON *raw = dmz_telemetry_raw("southbound_trust_load_failed");
                cJSON_AddStringToObject(raw, "application_uri", CLIENT_APP_URI);
                cJSON_AddNumberToObject(raw, "trust_index", (double)i);
                cJSON_AddStringToObject(raw, "trust_path", trustPath);
                dmz_telemetry_event("opcua_dmz_trust_load_failed", "pki_validation", "critical", raw);
            }
            return 0;
        }
    }

    UA_StatusCode rc = UA_ClientConfig_setDefaultEncryption(
        config,
        certificate,
        privateKey,
        trustList,
        trustListSize,
        NULL,
        0
    );

    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][INIT] Encryption config failed: %s\n",
                status_name_safe(rc));
        {
            cJSON *raw = dmz_telemetry_raw("southbound_security_config_failed");
            cJSON_AddStringToObject(raw, "application_uri", CLIENT_APP_URI);
            cJSON_AddStringToObject(raw, "status_name", status_name_safe(rc));
            cJSON_AddNumberToObject(raw, "status_code", (double)rc);
            cJSON_AddStringToObject(raw, "security_policy", BASIC256SHA256_URI);
            cJSON_AddStringToObject(raw, "security_mode", "SignAndEncrypt");
            dmz_telemetry_event("opcua_dmz_security_config_failed", "pki_validation", "critical", raw);
        }
        return 0;
    }

    config->clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_APP_URI);
    config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    config->securityPolicyUri = UA_String_fromChars(BASIC256SHA256_URI);

    config->timeout = 10000;
    config->secureChannelLifeTime = 600000;
    config->requestedSessionTimeout = 600000;

    printf("[DMZ][INIT] TrustList size = %lu\n", (unsigned long)trustListSize);
    printf("[DMZ][INIT] Leaf trust mode enabled\n");

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for(size_t i = 0; i < trustListSize; i++) {
        UA_ByteString_clear(&trustList[i]);
    }

    return 1;
}

int southbound_connect(SouthboundContext *ctx) {
    if(!ctx || !ctx->client)
        return 0;

    printf("[DMZ][CONNECT] Endpoint=%s User=%s\n",
           ctx->endpointUrl, ctx->username);

    UA_StatusCode rc = UA_Client_connectUsername(
        ctx->client,
        ctx->endpointUrl,
        ctx->username,
        ctx->password
    );

    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][CONNECT] Failed: %s\n",
                status_name_safe(rc));
        {
            cJSON *raw = dmz_telemetry_raw("southbound_connect_failed");
            cJSON_AddStringToObject(raw, "application_uri", CLIENT_APP_URI);
            cJSON_AddStringToObject(raw, "endpoint", ctx->endpointUrl);
            cJSON_AddStringToObject(raw, "status_name", status_name_safe(rc));
            cJSON_AddNumberToObject(raw, "status_code", (double)rc);
            dmz_telemetry_event("opcua_dmz_southbound_connect_failed", "opcua_session", "warning", raw);
        }
        return 0;
    }

    UA_String nsUri = UA_STRING((char*)POWERGRID_NS_URI);
    rc = UA_Client_getNamespaceIndex(ctx->client, nsUri, &ctx->nsIdx);

    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][CONNECT] Namespace resolution failed\n");
        {
            cJSON *raw = dmz_telemetry_raw("southbound_namespace_failed");
            cJSON_AddStringToObject(raw, "application_uri", CLIENT_APP_URI);
            cJSON_AddStringToObject(raw, "endpoint", ctx->endpointUrl);
            cJSON_AddStringToObject(raw, "namespace_uri", POWERGRID_NS_URI);
            cJSON_AddStringToObject(raw, "status_name", status_name_safe(rc));
            cJSON_AddNumberToObject(raw, "status_code", (double)rc);
            dmz_telemetry_event("opcua_dmz_namespace_failed", "opcua_session", "warning", raw);
        }
        UA_Client_disconnect(ctx->client);
        return 0;
    }

    printf("[DMZ][CONNECT] Connected. nsIdx=%u\n", ctx->nsIdx);
    return 1;
}

int southbound_poll_once(SouthboundContext *ctx) {
    if(!ctx || !ctx->client)
        return 0;

    char batch[INFLUX_BATCH_SIZE];
    size_t batchLen = 0;
    batch[0] = '\0';

    for(size_t i = 0; i < GATEWAY_POINTS_COUNT; i++) {
        const GatewayPoint *pt = &GATEWAY_POINTS[i];
        UA_NodeId nodeId = UA_NODEID_NUMERIC(ctx->nsIdx, pt->numericId);

        UA_Variant value;
        UA_Variant_init(&value);

        UA_StatusCode rc = UA_Client_readValueAttribute(ctx->client, nodeId, &value);

        if(rc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[DMZ][READ] %s failed: %s\n",
                    pt->label, status_name_safe(rc));
            UA_Variant_clear(&value);
            continue;
        }

        char measurement[64];
        char plcTag[64];
        char nodeTag[128];
        classify_point_label(pt->label,
                             measurement, sizeof(measurement),
                             plcTag, sizeof(plcTag),
                             nodeTag, sizeof(nodeTag));

if(pt->type == GW_TYPE_BOOL) {
    if(UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_BOOLEAN]) && value.data) {
        UA_Boolean v = *(UA_Boolean*)value.data;
        cache_set_bool(i, v);

        char line[256];
        snprintf(line, sizeof(line),
                 "%s,plc=%s,node=%s value=%d\n",
                 measurement, plcTag, nodeTag, v ? 1 : 0);

        append_line_to_batch(batch, &batchLen, sizeof(batch), line);

        printf("[DMZ][READ]  %s ns=%u;i=%u = %s\n",
               pt->label, (unsigned)ctx->nsIdx, (unsigned)pt->numericId,
               v ? "true" : "false");
    } else {
        fprintf(stderr, "[DMZ][READ] %s invalid bool type\n", pt->label);
    }
}
else if(pt->type == GW_TYPE_DOUBLE) {
    if(UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DOUBLE]) && value.data) {
        UA_Double v = *(UA_Double*)value.data;
        cache_set_double(i, v);

        char line[256];
        snprintf(line, sizeof(line),
                 "%s,plc=%s,node=%s value=%f\n",
                 measurement, plcTag, nodeTag, v);

        append_line_to_batch(batch, &batchLen, sizeof(batch), line);

        printf("[DMZ][READ]  %s ns=%u;i=%u = %f\n",
               pt->label, (unsigned)ctx->nsIdx, (unsigned)pt->numericId, v);
    } else {
        fprintf(stderr, "[DMZ][READ] %s invalid double type\n", pt->label);
    }
}
else if(pt->type == GW_TYPE_INT32) {
    if(UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_INT32]) && value.data) {
        UA_Int32 v = *(UA_Int32*)value.data;
        cache_set_int32(i, v);

        char line[256];
        snprintf(line, sizeof(line),
                 "%s,plc=%s,node=%s value=%d\n",
                 measurement, plcTag, nodeTag, v);

        append_line_to_batch(batch, &batchLen, sizeof(batch), line);

        printf("[DMZ][READ]  %s ns=%u;i=%u = %d\n",
               pt->label, (unsigned)ctx->nsIdx, (unsigned)pt->numericId, v);
    } else {
        fprintf(stderr, "[DMZ][READ] %s invalid int32 type\n", pt->label);
    }
}
        UA_Variant_clear(&value);
    }

    if(batchLen > 0) {
        if(!influx_writer_write_batch(batch)) {
            fprintf(stderr, "[INFLUX] Batch write failed for current poll cycle\n");
            {
                cJSON *raw = dmz_telemetry_raw("influx_batch_write_failed");
                cJSON_AddNumberToObject(raw, "batch_bytes", (double)batchLen);
                cJSON_AddStringToObject(raw, "runtime_side", "southbound");
                dmz_telemetry_event("opcua_dmz_influx_write_failed", "error", "warning", raw);
            }
        }
    }

    return 1;
}

void southbound_disconnect(SouthboundContext *ctx) {
    if(ctx && ctx->client)
        UA_Client_disconnect(ctx->client);
}

void southbound_clear(SouthboundContext *ctx) {
    if(!ctx)
        return;

    if(ctx->client) {
        UA_Client_delete(ctx->client);
        ctx->client = NULL;
    }
}
