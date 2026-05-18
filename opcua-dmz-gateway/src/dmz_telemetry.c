#include "dmz_telemetry.h"

#include <curl/curl.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define DMZ_COLLECTOR_URL_DEFAULT "http://192.168.10.70:9000/opcua-dmz/events"
#define DMZ_COLLECTOR_TOKEN_FILE_DEFAULT "/etc/labshock-dmz-collector/token"
#define DMZ_ASSET_NAME_DEFAULT "opcua_dmz_gateway"
#define DMZ_ASSET_IP_DEFAULT "192.168.10.20"
#define DMZ_SOURCETYPE "labshock:dmz:opcua_gateway"
#define DMZ_SOURCE_TYPE "opcua_dmz_gateway"

static int telemetry_enabled = 0;
static int telemetry_timeout_seconds = 2;
static char telemetry_url[512];
static char telemetry_token_file[512];
static char telemetry_asset_name[128];
static char telemetry_asset_ip[64];
static int missing_token_logged = 0;

static const char *env_or_default(const char *name, const char *fallback) {
    const char *v = getenv(name);
    if(v && v[0] != '\0')
        return v;
    return fallback;
}

static int env_bool(const char *name, int fallback) {
    const char *v = getenv(name);
    if(!v || v[0] == '\0')
        return fallback;
    if(strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0)
        return 1;
    if(strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "off") == 0)
        return 0;
    return fallback;
}

static void utc_iso_now(char *out, size_t out_len) {
    time_t now = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    gmtime_s(&tmv, &now);
#else
    gmtime_r(&now, &tmv);
#endif
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static int read_trimmed_file(const char *path, char *out, size_t out_len) {
    FILE *fp;
    size_t n;
    if(!path || !out || out_len == 0)
        return 0;
    fp = fopen(path, "rb");
    if(!fp)
        return 0;
    n = fread(out, 1, out_len - 1, fp);
    fclose(fp);
    out[n] = '\0';
    while(n > 0 && isspace((unsigned char)out[n - 1])) {
        out[n - 1] = '\0';
        n--;
    }
    while(out[0] && isspace((unsigned char)out[0]))
        memmove(out, out + 1, strlen(out));
    return out[0] != '\0';
}

static const char *risk_for(const char *category, const char *severity) {
    if(severity && (strcasecmp(severity, "critical") == 0 || strcasecmp(severity, "error") == 0))
        return "HIGH";
    if(severity && strcasecmp(severity, "warning") == 0)
        return "MEDIUM";
    if(category && (strcmp(category, "security") == 0 || strcmp(category, "access_control") == 0))
        return "MEDIUM";
    return "LOW";
}

static int alert_candidate_for(const char *category, const char *severity) {
    if(severity && (strcasecmp(severity, "critical") == 0 || strcasecmp(severity, "error") == 0 || strcasecmp(severity, "warning") == 0))
        return 1;
    if(category && (strcmp(category, "security") == 0 || strcmp(category, "access_control") == 0 || strcmp(category, "pki_validation") == 0))
        return 1;
    return 0;
}

static void add_if_absent(cJSON *obj, const char *name, const char *value) {
    if(!obj || !name || !value || cJSON_GetObjectItemCaseSensitive(obj, name))
        return;
    cJSON_AddStringToObject(obj, name, value);
}

static int post_json(const char *body) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char token[4096];
    char auth_header[4200];
    long code = 0;

    if(!telemetry_enabled || !body)
        return 0;

    if(!read_trimmed_file(telemetry_token_file, token, sizeof(token))) {
        if(!missing_token_logged) {
            fprintf(stderr, "[DMZ][COLLECTOR] token unavailable path=%s\n", telemetry_token_file);
            missing_token_logged = 1;
        }
        return 0;
    }

    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);
    curl = curl_easy_init();
    if(!curl)
        return 0;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_URL, telemetry_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)telemetry_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "labshock-opcua-dmz-gateway-collector-sender/1");

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if(res != CURLE_OK) {
        fprintf(stderr, "[DMZ][COLLECTOR] post failed err=%s\n", curl_easy_strerror(res));
        return 0;
    }
    if(code < 200 || code >= 300) {
        fprintf(stderr, "[DMZ][COLLECTOR] post failed http_status=%ld\n", code);
        return 0;
    }
    return 1;
}

void dmz_telemetry_init(void) {
    const char *timeout_s;
    telemetry_enabled = env_bool("DMZ_GATEWAY_COLLECTOR_ENABLED", 0);
    snprintf(telemetry_url, sizeof(telemetry_url), "%s", env_or_default("DMZ_GATEWAY_COLLECTOR_URL", DMZ_COLLECTOR_URL_DEFAULT));
    snprintf(telemetry_token_file, sizeof(telemetry_token_file), "%s", env_or_default("DMZ_GATEWAY_COLLECTOR_TOKEN_FILE", DMZ_COLLECTOR_TOKEN_FILE_DEFAULT));
    snprintf(telemetry_asset_name, sizeof(telemetry_asset_name), "%s", env_or_default("DMZ_GATEWAY_ASSET_NAME", DMZ_ASSET_NAME_DEFAULT));
    snprintf(telemetry_asset_ip, sizeof(telemetry_asset_ip), "%s", env_or_default("DMZ_GATEWAY_ASSET_IP", DMZ_ASSET_IP_DEFAULT));
    timeout_s = getenv("DMZ_GATEWAY_COLLECTOR_TIMEOUT_SECONDS");
    if(timeout_s && timeout_s[0] != '\0') {
        int parsed = atoi(timeout_s);
        if(parsed > 0 && parsed <= 30)
            telemetry_timeout_seconds = parsed;
    }
    if(telemetry_enabled) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        fprintf(stdout, "[DMZ][COLLECTOR] sender enabled url=%s\n", telemetry_url);
    }
}

void dmz_telemetry_cleanup(void) {
    if(telemetry_enabled)
        curl_global_cleanup();
}

int dmz_telemetry_enabled(void) {
    return telemetry_enabled;
}

cJSON *dmz_telemetry_raw(const char *event_type) {
    cJSON *raw = cJSON_CreateObject();
    char ts[32];
    utc_iso_now(ts, sizeof(ts));
    cJSON_AddStringToObject(raw, "event_type", event_type ? event_type : "opcua_dmz_event");
    cJSON_AddStringToObject(raw, "generated_at", ts);
    cJSON_AddStringToObject(raw, "component", "opcua_dmz_gateway");
    return raw;
}

int dmz_telemetry_event(const char *message,
                        const char *event_category,
                        const char *severity,
                        cJSON *raw) {
    cJSON *root;
    cJSON *tags;
    char *body;
    char ts[32];
    int ok;

    if(!telemetry_enabled) {
        if(raw)
            cJSON_Delete(raw);
        return 0;
    }

    if(!raw)
        raw = dmz_telemetry_raw(message);
    utc_iso_now(ts, sizeof(ts));
    add_if_absent(raw, "asset_name", telemetry_asset_name);
    add_if_absent(raw, "asset_ip", telemetry_asset_ip);
    add_if_absent(raw, "zone", "DMZ");
    add_if_absent(raw, "protocol", "opcua");

    tags = cJSON_CreateObject();
    cJSON_AddStringToObject(tags, "component", "opcua_dmz_gateway");
    cJSON_AddStringToObject(tags, "zone", "DMZ");
    cJSON_AddStringToObject(tags, "purdue_zone", "dmz");
    cJSON_AddStringToObject(tags, "splunk_sourcetype", DMZ_SOURCETYPE);
    cJSON_AddStringToObject(tags, "normalization_source", "opcua_dmz_gateway_sender");
    cJSON_AddStringToObject(tags, "parser_version", "v1.opcua_dmz_gateway_sender");
    cJSON_AddStringToObject(tags, "risk_level", risk_for(event_category, severity));
    cJSON_AddBoolToObject(tags, "alert_candidate", alert_candidate_for(event_category, severity));

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", ts);
    cJSON_AddStringToObject(root, "source_type", DMZ_SOURCE_TYPE);
    cJSON_AddStringToObject(root, "sourcetype", DMZ_SOURCETYPE);
    cJSON_AddStringToObject(root, "zone", "DMZ");
    cJSON_AddStringToObject(root, "asset_name", telemetry_asset_name);
    cJSON_AddStringToObject(root, "asset_ip", telemetry_asset_ip);
    cJSON_AddStringToObject(root, "protocol", "opcua");
    cJSON_AddStringToObject(root, "source", "opcua_dmz_gateway");
    cJSON_AddStringToObject(root, "message", message ? message : "opcua_dmz_event");
    cJSON_AddStringToObject(root, "event_category", event_category ? event_category : "system");
    cJSON_AddStringToObject(root, "severity", severity ? severity : "info");
    cJSON_AddItemToObject(root, "raw", raw);
    cJSON_AddItemToObject(root, "tags", tags);

    body = cJSON_PrintUnformatted(root);
    ok = post_json(body);
    free(body);
    cJSON_Delete(root);
    return ok;
}

static int map_gds_message(const char *event_type,
                           const char *status,
                           const char **message,
                           const char **category,
                           const char **severity) {
    if(!event_type)
        return 0;
    *severity = "info";
    *category = "pki_trust_sync";
    if(strcmp(event_type, "trust_version_changed") == 0) {
        *message = "opcua_dmz_gds_trust_update_detected";
        return 1;
    }
    if(strcmp(event_type, "trust_pull_completed") == 0) {
        if(status && strcmp(status, "failed") == 0) {
            *message = "opcua_dmz_gds_trust_pull_failed";
            *severity = "warning";
        } else {
            *message = "opcua_dmz_gds_trust_pull_success";
        }
        return 1;
    }
    if(strcmp(event_type, "trust_apply_completed") == 0) {
        *message = "opcua_dmz_gds_trust_applied";
        return 1;
    }
    if(strcmp(event_type, "trust_apply_failed") == 0) {
        *message = "opcua_dmz_gds_trust_apply_failed";
        *severity = "warning";
        return 1;
    }
    if(strcmp(event_type, "renewal_threshold_reached") == 0) {
        *message = "opcua_dmz_gds_certificate_renewal_due";
        *category = "certificate_lifecycle";
        *severity = "warning";
        return 1;
    }
    if(strcmp(event_type, "enrollment_package_received") == 0) {
        *message = "opcua_dmz_gds_certificate_enrolled";
        *category = "certificate_lifecycle";
        return 1;
    }
    if(strcmp(event_type, "renewal_package_received") == 0) {
        *category = "certificate_lifecycle";
        if(status && strcmp(status, "failed") == 0) {
            *message = "opcua_dmz_gds_certificate_renewal_failed";
            *severity = "warning";
        } else {
            *message = "opcua_dmz_gds_certificate_renewed";
        }
        return 1;
    }
    if(strcmp(event_type, "renewal_apply_completed") == 0) {
        *message = "opcua_dmz_gds_certificate_applied";
        *category = "certificate_lifecycle";
        return 1;
    }
    if(strcmp(event_type, "renewal_apply_failed") == 0) {
        *message = "opcua_dmz_gds_certificate_renewal_failed";
        *category = "certificate_lifecycle";
        *severity = "warning";
        return 1;
    }
    return 0;
}

int dmz_telemetry_gds_event(const char *target,
                            const char *application_uri,
                            const char *event_type,
                            const char *status,
                            const char *detail) {
    const char *message = NULL;
    const char *category = NULL;
    const char *severity = NULL;
    cJSON *raw;

    if(!map_gds_message(event_type, status, &message, &category, &severity))
        return 0;
    raw = dmz_telemetry_raw(event_type);
    if(target)
        cJSON_AddStringToObject(raw, "target", target);
    if(application_uri)
        cJSON_AddStringToObject(raw, "application_uri", application_uri);
    if(status)
        cJSON_AddStringToObject(raw, "status", status);
    if(detail)
        cJSON_AddStringToObject(raw, "detail", detail);
    return dmz_telemetry_event(message, category, severity, raw);
}
