#define _GNU_SOURCE

#include "gds_client.h"
#include "dmz_telemetry.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define GDS_CACHE_DEFAULT "/var/lib/opcua-dmz-gateway/gds"
#define GDS_BASE_URL_DEFAULT "https://192.168.10.30:8443"
#define GDS_AGENT_ID_DEFAULT "dmz-gateway"
#define GDS_TOKEN_FILE_DEFAULT "/etc/labshock-dmz-gds/token"
#define GDS_TLS_CA_DEFAULT "/etc/labshock-dmz-gds-tls/ca.crt"
#define GDS_TLS_CERT_DEFAULT "/etc/labshock-dmz-gds-tls/client.crt"
#define GDS_TLS_KEY_DEFAULT "/etc/labshock-dmz-gds-tls/client.key"
#define GDS_LOCK_FILE_DEFAULT "/var/lib/opcua-dmz-gateway/gds/lifecycle.lock"

typedef struct {
    char *data;
    size_t len;
} Buffer;

typedef struct {
    const char *name;
    const char *application_uri;
    const char *runtime_instance_id;
    const char *profile_name;
    const char *component_type;
    const char *zone;
    const char *role;
    const char *runtime_family;
    const char *runtime_side;
    const char *cn;
    const char *cert_path;
    const char *key_path;
    const char *issuer_dir;
    const char *trusted_dir;
    const char *eku;
    int remote_peer_read_only;
} GdsTarget;

static const GdsTarget TARGETS[] = {
    {
        "dmz-gateway-client",
        "urn:dataprotect:opcua:dmz-gateway-client",
        "urn:dataprotect:opcua:dmz-gateway-client",
        "open62541-client",
        "client",
        "DMZ",
        "southbound-client",
        "open62541",
        "southbound",
        "LabShockDMZGatewayClient",
        "/app/pki/southbound/own/certs/client.der",
        "/app/pki/southbound/own/private/client.key.der",
        "/app/pki/southbound/issuer",
        "/app/pki/southbound/trusted",
        "clientAuth",
        0,
    },
    {
        "dmz-gateway-server",
        "urn:dataprotect:opcua:dmz-gateway-server",
        "urn:dataprotect:opcua:dmz-gateway-server",
        "open62541-server",
        "server",
        "DMZ",
        "northbound-server",
        "open62541",
        "northbound",
        "LabShockDMZGatewayServer",
        "/app/pki/northbound/own/certs/server.der",
        "/app/pki/northbound/own/private/server.key.der",
        "/app/pki/northbound/issuer",
        "/app/pki/northbound/trusted",
        "serverAuth",
        0,
    },
    {
        "ot-server",
        "urn:dataprotect:opcua:ot-server",
        "urn:dataprotect:opcua:ot-server",
        "open62541-server",
        "server",
        "OT",
        "server",
        "open62541",
        "remote-peer",
        "PowerGridOPCUA",
        NULL,
        NULL,
        NULL,
        NULL,
        "serverAuth",
        1,
    },
};

static const char *env_or_default(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value && value[0] != '\0') ? value : fallback;
}

static int env_bool(const char *name, int fallback) {
    const char *value = getenv(name);
    if(!value || value[0] == '\0')
        return fallback;
    return strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0;
}

static int csv_token_contains(const char *list, const char *token) {
    if(!list || !token || token[0] == '\0')
        return 0;
    const char *p = list;
    while(*p) {
        while(*p == ',' || isspace((unsigned char)*p))
            p++;
        const char *start = p;
        while(*p && *p != ',')
            p++;
        const char *end = p;
        while(end > start && isspace((unsigned char)*(end - 1)))
            end--;
        size_t len = (size_t)(end - start);
        if(len == strlen(token) && strncmp(start, token, len) == 0)
            return 1;
    }
    return 0;
}

static int auto_renew_allowed_for_target(const GdsTarget *target) {
    const char *targets = getenv("DMZ_GDS_AUTO_RENEW_TARGETS");
    if(!env_bool("DMZ_GDS_AUTO_RENEW", 0))
        return 0;
    if(!targets || targets[0] == '\0')
        return 0;
    return csv_token_contains(targets, target->name) ||
           csv_token_contains(targets, target->application_uri) ||
           csv_token_contains(targets, "all");
}

static char *copy_string(const char *value) {
    size_t len = value ? strlen(value) : 0;
    char *out = (char*)calloc(len + 1, 1);
    if(out && value)
        memcpy(out, value, len);
    return out;
}

static int dmz_gds_resolve_target(const char *name, const GdsTarget **out) {
    if(!name || !out)
        return 0;
    for(size_t i = 0; i < sizeof(TARGETS) / sizeof(TARGETS[0]); i++) {
        if(strcmp(TARGETS[i].name, name) == 0) {
            *out = &TARGETS[i];
            return 1;
        }
    }
    return 0;
}

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    size_t len;
    if(!path || path[0] == '\0')
        return 0;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if(len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for(char *p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = '\0';
            if(mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return 0;
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

static int ensure_parent_dir(const char *path) {
    char tmp[PATH_MAX];
    char *slash;
    snprintf(tmp, sizeof(tmp), "%s", path);
    slash = strrchr(tmp, '/');
    if(!slash)
        return 1;
    *slash = '\0';
    return mkdir_p(tmp);
}

static void cache_path(char *out, size_t out_len, const GdsTarget *target, const char *leaf) {
    const char *cache = env_or_default("DMZ_GDS_CACHE_DIR", GDS_CACHE_DEFAULT);
    snprintf(out, out_len, "%s/%s/%s", cache, target->name, leaf);
}

static char *read_text_file_trimmed(const char *path) {
    FILE *f = fopen(path, "rb");
    long size;
    char *data;
    if(!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);
    if(size <= 0) {
        fclose(f);
        return NULL;
    }
    data = (char*)calloc((size_t)size + 1, 1);
    if(!data) {
        fclose(f);
        return NULL;
    }
    if(fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    while(size > 0 && isspace((unsigned char)data[size - 1]))
        data[--size] = '\0';
    return data;
}

static int write_bytes(const char *path, const unsigned char *data, size_t len) {
    FILE *f;
    if(!ensure_parent_dir(path))
        return 0;
    f = fopen(path, "wb");
    if(!f)
        return 0;
    if(len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

static int write_text(const char *path, const char *text) {
    return write_bytes(path, (const unsigned char*)text, text ? strlen(text) : 0);
}

static int read_file_bytes(const char *path, unsigned char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    long size;
    unsigned char *data;
    if(!f)
        return 0;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);
    if(size < 0) {
        fclose(f);
        return 0;
    }
    data = (unsigned char*)malloc((size_t)size + 1);
    if(!data) {
        fclose(f);
        return 0;
    }
    if(size > 0 && fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return 0;
    }
    fclose(f);
    data[size] = 0;
    *out = data;
    *out_len = (size_t)size;
    return 1;
}

static int file_sha256_hex(const char *path, char out[65]) {
    unsigned char *data = NULL;
    size_t len = 0;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if(!read_file_bytes(path, &data, &len))
        return 0;
    SHA256(data, len, digest);
    free(data);
    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    return 1;
}

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    Buffer *mem = (Buffer*)userp;
    char *ptr = (char*)realloc(mem->data, mem->len + realsize + 1);
    if(!ptr)
        return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->len]), contents, realsize);
    mem->len += realsize;
    mem->data[mem->len] = 0;
    return realsize;
}

static int gds_http(const char *method, const char *path, const char *body, char **out) {
    CURL *curl;
    CURLcode res;
    long code = 0;
    Buffer chunk = {0};
    struct curl_slist *headers = NULL;
    char url[2048];
    char agent_header[256];
    char token_header[1024];
    char *token = NULL;
    const char *base_url = env_or_default("DMZ_GDS_BASE_URL", GDS_BASE_URL_DEFAULT);
    const char *agent_id = env_or_default("DMZ_GDS_AGENT_ID", GDS_AGENT_ID_DEFAULT);
    const char *token_file = env_or_default("DMZ_GDS_TOKEN_FILE", GDS_TOKEN_FILE_DEFAULT);
    const char *token_env = getenv("DMZ_GDS_AGENT_TOKEN");

    token = (token_env && token_env[0] != '\0') ? copy_string(token_env) : read_text_file_trimmed(token_file);
    if(!token || token[0] == '\0') {
        fprintf(stderr, "[DMZ][GDS] agent token unavailable\n");
        free(token);
        return 0;
    }

    snprintf(url, sizeof(url), "%s%s", base_url, path);
    snprintf(agent_header, sizeof(agent_header), "X-GDS-Agent-ID: %s", agent_id);
    snprintf(token_header, sizeof(token_header), "X-GDS-Agent-Token: %s", token);

    curl = curl_easy_init();
    if(!curl) {
        free(token);
        return 0;
    }
    headers = curl_slist_append(headers, agent_header);
    headers = curl_slist_append(headers, token_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "labshock-opcua-dmz-gateway-gds-client/1");

    if(strncmp(base_url, "https://", 8) == 0) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, env_or_default("DMZ_GDS_TLS_CA_FILE", GDS_TLS_CA_DEFAULT));
        curl_easy_setopt(curl, CURLOPT_SSLCERT, env_or_default("DMZ_GDS_TLS_CERT_FILE", GDS_TLS_CERT_DEFAULT));
        curl_easy_setopt(curl, CURLOPT_SSLKEY, env_or_default("DMZ_GDS_TLS_KEY_FILE", GDS_TLS_KEY_DEFAULT));
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    if(strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "{}");
    }

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(token);

    if(res != CURLE_OK) {
        fprintf(stderr, "[DMZ][GDS] HTTP request failed: %s\n", curl_easy_strerror(res));
        free(chunk.data);
        return 0;
    }
    if(code < 200 || code >= 300) {
        fprintf(stderr, "[DMZ][GDS] HTTP %ld for %s %s\n", code, method, path);
        if(chunk.data)
            fprintf(stderr, "%s\n", chunk.data);
        free(chunk.data);
        return 0;
    }
    *out = chunk.data ? chunk.data : copy_string("");
    return 1;
}

static int cache_json_response(const GdsTarget *target, const char *leaf, const char *json) {
    char path[PATH_MAX];
    cache_path(path, sizeof(path), target, leaf);
    return write_text(path, json);
}

static cJSON *read_cached_json(const GdsTarget *target, const char *leaf) {
    char path[PATH_MAX];
    unsigned char *data = NULL;
    size_t len = 0;
    cJSON *json;
    cache_path(path, sizeof(path), target, leaf);
    if(!read_file_bytes(path, &data, &len))
        return NULL;
    json = cJSON_ParseWithLength((const char*)data, len);
    free(data);
    return json;
}

static int component_get_path(const GdsTarget *target, const char *suffix, char *out, size_t out_len) {
    CURL *curl = curl_easy_init();
    char *escaped;
    if(!curl)
        return 0;
    escaped = curl_easy_escape(curl, target->application_uri, 0);
    if(!escaped) {
        curl_easy_cleanup(curl);
        return 0;
    }
    snprintf(out, out_len, "/api/v1/discovery/components/%s/%s", escaped, suffix);
    curl_free(escaped);
    curl_easy_cleanup(curl);
    return 1;
}

static int component_trust_path(const GdsTarget *target, char *out, size_t out_len) {
    CURL *curl = curl_easy_init();
    char *escaped;
    if(!curl)
        return 0;
    escaped = curl_easy_escape(curl, target->application_uri, 0);
    if(!escaped) {
        curl_easy_cleanup(curl);
        return 0;
    }
    snprintf(out, out_len, "/api/v1/distribution/components/%s/trust-material", escaped);
    curl_free(escaped);
    curl_easy_cleanup(curl);
    return 1;
}

static int component_lifecycle_path(const GdsTarget *target, const char *suffix, char *out, size_t out_len) {
    CURL *curl = curl_easy_init();
    char *escaped;
    if(!curl)
        return 0;
    escaped = curl_easy_escape(curl, target->application_uri, 0);
    if(!escaped) {
        curl_easy_cleanup(curl);
        return 0;
    }
    snprintf(out, out_len, "/api/v1/components/%s/%s", escaped, suffix);
    curl_free(escaped);
    curl_easy_cleanup(curl);
    return 1;
}

static int command_discover_one(const GdsTarget *target) {
    const char *suffixes[] = {"identity", "renewal-policy", "revocation-status"};
    const char *leaves[] = {"identity.json", "renewal-policy.json", "revocation-status.json"};
    int ok = 1;
    for(size_t i = 0; i < 3; i++) {
        char path[2048];
        char *resp = NULL;
        if(!component_get_path(target, suffixes[i], path, sizeof(path)) || !gds_http("GET", path, NULL, &resp)) {
            ok = 0;
            continue;
        }
        cache_json_response(target, leaves[i], resp);
        if(strcmp(suffixes[i], "identity") == 0)
            fprintf(stdout, "%s\n", resp);
        free(resp);
    }
    fprintf(stdout, "[DMZ][GDS] discovery target=%s status=%s\n", target->name, ok ? "ok" : "failed");
    return ok;
}

static int command_pull_trust_one(const GdsTarget *target) {
    char path[2048];
    char *resp = NULL;
    cJSON *doc = NULL;
    cJSON *tm = NULL;
    cJSON *version = NULL;
    if(!component_trust_path(target, path, sizeof(path)) || !gds_http("GET", path, NULL, &resp))
        return 0;
    if(!cache_json_response(target, "trust-material.json", resp)) {
        free(resp);
        return 0;
    }
    doc = cJSON_Parse(resp);
    tm = doc ? cJSON_GetObjectItemCaseSensitive(doc, "trust_material") : NULL;
    if(tm) {
        version = cJSON_CreateObject();
        cJSON_AddStringToObject(version, "application_uri", target->application_uri);
        cJSON_AddNumberToObject(version, "trust_artifact_version", cJSON_GetObjectItemCaseSensitive(tm, "trustlist_version") ? cJSON_GetObjectItemCaseSensitive(tm, "trustlist_version")->valuedouble : 0);
        cJSON_AddNumberToObject(version, "trust_artifact_revision", cJSON_GetObjectItemCaseSensitive(tm, "artifact_revision") ? cJSON_GetObjectItemCaseSensitive(tm, "artifact_revision")->valuedouble : 0);
        cJSON *sha = cJSON_GetObjectItemCaseSensitive(tm, "artifact_sha256");
        if(cJSON_IsString(sha))
            cJSON_AddStringToObject(version, "trust_artifact_sha256", sha->valuestring);
        cJSON *artifact = cJSON_GetObjectItemCaseSensitive(tm, "artifact");
        cJSON *crl_meta = artifact ? cJSON_GetObjectItemCaseSensitive(artifact, "crl_metadata") : cJSON_GetObjectItemCaseSensitive(tm, "crl_metadata");
        if(crl_meta)
            cJSON_AddItemToObject(version, "crl_metadata", cJSON_Duplicate(crl_meta, 1));
        char *version_text = cJSON_PrintUnformatted(version);
        if(version_text) {
            cache_json_response(target, "trust-version.json", version_text);
            free(version_text);
        }
        cJSON_Delete(version);
    }
    if(doc)
        cJSON_Delete(doc);
    free(resp);
    fprintf(stdout, "[DMZ][GDS] trust material cached target=%s\n", target->name);
    dmz_telemetry_gds_event(target->name, target->application_uri, "trust_pull_completed", "completed", NULL);
    return 1;
}

static EVP_PKEY *generate_rsa_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if(!ctx)
        return NULL;
    if(EVP_PKEY_keygen_init(ctx) <= 0 ||
       EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
       EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *load_or_create_key(const char *path) {
    FILE *f = fopen(path, "rb");
    EVP_PKEY *pkey = NULL;
    if(f) {
        pkey = d2i_PrivateKey_fp(f, NULL);
        fclose(f);
        return pkey;
    }
    if(!env_bool("DMZ_GDS_RUNTIME_WRITE_ENABLED", 0)) {
        fprintf(stderr, "[DMZ][GDS] blocked_runtime_write_disabled: private key missing for local target\n");
        return NULL;
    }
    pkey = generate_rsa_key();
    if(!pkey || !ensure_parent_dir(path)) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    f = fopen(path, "wb");
    if(!f) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if(i2d_PrivateKey_fp(f, pkey) <= 0) {
        fclose(f);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    fclose(f);
    fprintf(stdout, "[DMZ][GDS] generated local private key for target runtime\n");
    return pkey;
}

static int add_req_extension(STACK_OF(X509_EXTENSION) *exts, X509V3_CTX *ctx, int nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)value);
    if(!ex)
        return 0;
    sk_X509_EXTENSION_push(exts, ex);
    return 1;
}

static char *create_csr_pem(const GdsTarget *target) {
    char key_path[PATH_MAX];
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509V3_CTX ctx;
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    char san[512];
    char *out = NULL;

    snprintf(key_path, sizeof(key_path), "%s", target->key_path);
    pkey = load_or_create_key(key_path);
    if(!pkey)
        goto done;
    req = X509_REQ_new();
    name = X509_NAME_new();
    if(!req || !name)
        goto done;
    X509_REQ_set_version(req, 0L);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)target->cn, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);

    exts = sk_X509_EXTENSION_new_null();
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, req, NULL, 0);
    snprintf(san, sizeof(san), "URI:%s", target->application_uri);
    add_req_extension(exts, &ctx, NID_subject_alt_name, san);
    add_req_extension(exts, &ctx, NID_key_usage, "digitalSignature,keyEncipherment");
    add_req_extension(exts, &ctx, NID_ext_key_usage, target->eku);
    X509_REQ_add_extensions(req, exts);

    if(X509_REQ_sign(req, pkey, EVP_sha256()) <= 0)
        goto done;
    bio = BIO_new(BIO_s_mem());
    if(!bio || PEM_write_bio_X509_REQ(bio, req) != 1)
        goto done;
    BIO_get_mem_ptr(bio, &bptr);
    out = (char*)calloc(bptr->length + 1, 1);
    if(out)
        memcpy(out, bptr->data, bptr->length);

done:
    if(exts)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    BIO_free(bio);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return out;
}

static int command_enroll_one(const GdsTarget *target) {
    char *csr = NULL;
    char *body = NULL;
    char *resp = NULL;
    cJSON *root;
    int ok = 0;
    if(target->remote_peer_read_only) {
        fprintf(stderr, "[DMZ][GDS] remote_peer_read_only_target target=%s\n", target->name);
        return 0;
    }
    csr = create_csr_pem(target);
    if(!csr)
        return 0;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "application_uri", target->application_uri);
    cJSON_AddStringToObject(root, "runtime_instance_id", target->runtime_instance_id);
    cJSON_AddStringToObject(root, "profile_name", target->profile_name);
    cJSON_AddStringToObject(root, "component_type", target->component_type);
    cJSON_AddStringToObject(root, "csr_pem", csr);
    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(csr);
    if(!gds_http("POST", "/api/v1/enrollments/components/csr", body, &resp))
        goto done;
    if(!cache_json_response(target, "enrollment-result.json", resp))
        goto done;
    fprintf(stdout, "[DMZ][GDS] enrollment cached target=%s\n", target->name);
    dmz_telemetry_gds_event(target->name, target->application_uri, "enrollment_package_received", "completed", NULL);
    ok = 1;
done:
    free(body);
    free(resp);
    return ok;
}

static int command_renew_one(const GdsTarget *target) {
    char *csr = NULL;
    char *body = NULL;
    char *resp = NULL;
    cJSON *root;
    int ok = 0;
    if(target->remote_peer_read_only) {
        fprintf(stderr, "[DMZ][GDS] remote_peer_read_only_target target=%s\n", target->name);
        return 0;
    }
    csr = create_csr_pem(target);
    if(!csr)
        return 0;
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "application_uri", target->application_uri);
    cJSON_AddStringToObject(root, "runtime_instance_id", target->runtime_instance_id);
    cJSON_AddStringToObject(root, "profile_name", target->profile_name);
    cJSON_AddStringToObject(root, "component_type", target->component_type);
    cJSON_AddStringToObject(root, "renewal_reason", "dmz_gateway_native_gds_client");
    cJSON_AddStringToObject(root, "csr_pem", csr);
    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(csr);
    if(!gds_http("POST", "/api/v1/certificates/renew", body, &resp))
        goto done;
    if(!cache_json_response(target, "renewal-result.json", resp))
        goto done;
    fprintf(stdout, "[DMZ][GDS] renewal cached target=%s\n", target->name);
    dmz_telemetry_gds_event(target->name, target->application_uri, "renewal_package_received", "completed", NULL);
    ok = 1;
done:
    free(body);
    free(resp);
    return ok;
}

static unsigned char *base64_decode(const char *input, size_t *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, -1);
    size_t len = strlen(input);
    unsigned char *buffer = (unsigned char*)calloc(len + 1, 1);
    int decoded;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    decoded = BIO_read(bio, buffer, (int)len);
    BIO_free_all(bio);
    if(decoded <= 0) {
        free(buffer);
        return NULL;
    }
    *out_len = (size_t)decoded;
    return buffer;
}

static int pem_cert_to_der_bytes(const char *pem, unsigned char **out, int *out_len) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    X509 *cert;
    unsigned char *p;
    if(!bio)
        return 0;
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    if(!cert)
        return 0;
    *out_len = i2d_X509(cert, NULL);
    if(*out_len <= 0) {
        X509_free(cert);
        return 0;
    }
    *out = (unsigned char*)malloc((size_t)*out_len);
    p = *out;
    i2d_X509(cert, &p);
    X509_free(cert);
    return 1;
}

static int write_pem_cert_der(const char *path, const char *pem) {
    unsigned char *der = NULL;
    int der_len = 0;
    int ok;
    if(!pem_cert_to_der_bytes(pem, &der, &der_len))
        return 0;
    ok = write_bytes(path, der, (size_t)der_len);
    free(der);
    return ok;
}

static void sanitize_filename(const char *in, char *out, size_t out_len) {
    size_t j = 0;
    for(size_t i = 0; in && in[i] && j + 1 < out_len; i++) {
        char c = in[i];
        out[j++] = (isalnum((unsigned char)c) || c == '-' || c == '_') ? c : '_';
    }
    out[j] = '\0';
    if(j == 0)
        snprintf(out, out_len, "certificate");
}

static cJSON *trust_payload_from_cache_or_enrollment(const GdsTarget *target, int allow_certificate, int *certificate_mode, cJSON **owner_doc) {
    cJSON *doc;
    *certificate_mode = 0;
    *owner_doc = NULL;
    if(allow_certificate) {
        const char *leaves[] = {"renewal-result.json", "enrollment-result.json"};
        for(size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
            doc = read_cached_json(target, leaves[i]);
            if(doc) {
                cJSON *trust = cJSON_GetObjectItemCaseSensitive(doc, "trust_distribution");
                if(trust) {
                    *certificate_mode = 1;
                    *owner_doc = doc;
                    return trust;
                }
                cJSON_Delete(doc);
            }
        }
    }
    doc = read_cached_json(target, "trust-material.json");
    if(doc)
        return doc;
    return NULL;
}

static int validate_signed_artifact_metadata(cJSON *trust_doc) {
    cJSON *tm = cJSON_GetObjectItemCaseSensitive(trust_doc, "trust_material");
    cJSON *sig = tm ? cJSON_GetObjectItemCaseSensitive(tm, "artifact_signature") : NULL;
    cJSON *signer = sig ? cJSON_GetObjectItemCaseSensitive(sig, "signer") : NULL;
    cJSON *fingerprint = signer ? cJSON_GetObjectItemCaseSensitive(signer, "fingerprint_sha256") : NULL;
    cJSON *private_key = cJSON_GetObjectItemCaseSensitive(trust_doc, "private_key_included");
    cJSON *artifact = tm ? cJSON_GetObjectItemCaseSensitive(tm, "artifact") : NULL;
    cJSON *crl_meta = artifact ? cJSON_GetObjectItemCaseSensitive(artifact, "crl_metadata") : (tm ? cJSON_GetObjectItemCaseSensitive(tm, "crl_metadata") : NULL);
    const char *pinned = getenv("DMZ_GDS_TRUST_ANCHOR_FINGERPRINT");
    if(cJSON_IsTrue(private_key)) {
        fprintf(stderr, "[DMZ][GDS] private_key_included_blocked\n");
        return 0;
    }
    if(env_bool("DMZ_GDS_REQUIRE_SIGNED_ARTIFACTS", 1)) {
        if(!sig || !cJSON_GetObjectItemCaseSensitive(sig, "signature_base64") || !fingerprint) {
            fprintf(stderr, "[DMZ][GDS] signed_artifact_missing\n");
            return 0;
        }
    }
    if(pinned && pinned[0] != '\0' && (!cJSON_IsString(fingerprint) || strcasecmp(fingerprint->valuestring, pinned) != 0)) {
        fprintf(stderr, "[DMZ][GDS] trust_anchor_fingerprint_mismatch\n");
        return 0;
    }
    if(env_bool("DMZ_GDS_STRICT_CRL_FRESHNESS", 1) && !cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(crl_meta, "crl_freshness_verified"))) {
        fprintf(stderr, "[DMZ][GDS] crl_freshness_not_verified\n");
        return 0;
    }
    return 1;
}

static int apply_ca_chain(const GdsTarget *target, const char *ca_chain) {
    char path[PATH_MAX];
    const char *cursor = ca_chain;
    int index = 1;
    if(!ca_chain)
        return 1;
    snprintf(path, sizeof(path), "%s/certs/ca-chain.pem", target->issuer_dir);
    write_text(path, ca_chain);
    while((cursor = strstr(cursor, "-----BEGIN CERTIFICATE-----")) != NULL) {
        const char *end = strstr(cursor, "-----END CERTIFICATE-----");
        char *pem;
        size_t pem_len;
        if(!end)
            break;
        end += strlen("-----END CERTIFICATE-----");
        pem_len = (size_t)(end - cursor);
        pem = (char*)calloc(pem_len + 2, 1);
        memcpy(pem, cursor, pem_len);
        pem[pem_len] = '\n';
        snprintf(path, sizeof(path), "%s/certs/ca-chain-%d.der", target->issuer_dir, index);
        write_pem_cert_der(path, pem);
        if(strcmp(target->runtime_side, "southbound") == 0) {
            snprintf(path, sizeof(path), "%s/certs/%s", target->trusted_dir, index == 1 ? "vault_intermediate.der" : "root_ca.der");
            write_pem_cert_der(path, pem);
        }
        free(pem);
        cursor = end;
        index++;
    }
    return 1;
}

static int apply_crl_alias(const GdsTarget *target, const char *alias, const char *crl_b64) {
    char path[PATH_MAX];
    unsigned char *der = NULL;
    size_t der_len = 0;
    if(!crl_b64)
        return 1;
    der = base64_decode(crl_b64, &der_len);
    snprintf(path, sizeof(path), "%s/crl/%s.crl.b64", target->issuer_dir, alias);
    write_text(path, crl_b64);
    snprintf(path, sizeof(path), "%s/crl/%s.crl.b64", target->trusted_dir, alias);
    write_text(path, crl_b64);
    if(der) {
        snprintf(path, sizeof(path), "%s/crl/%s.crl", target->issuer_dir, alias);
        write_bytes(path, der, der_len);
        snprintf(path, sizeof(path), "%s/crl/%s.crl", target->trusted_dir, alias);
        write_bytes(path, der, der_len);
        if(strcmp(alias, "vault_intermediate") == 0) {
            snprintf(path, sizeof(path), "%s/crl/current.crl", target->issuer_dir);
            write_bytes(path, der, der_len);
            snprintf(path, sizeof(path), "%s/crl/current.crl", target->trusted_dir);
            write_bytes(path, der, der_len);
        }
        free(der);
    }
    return 1;
}

static int apply_trusted_certs(const GdsTarget *target, cJSON *certs) {
    cJSON *cert;
    int count = 0;
    cJSON_ArrayForEach(cert, certs) {
        cJSON *pem = cJSON_GetObjectItemCaseSensitive(cert, "pem");
        cJSON *uri = cJSON_GetObjectItemCaseSensitive(cert, "application_uri");
        cJSON *cn = cJSON_GetObjectItemCaseSensitive(cert, "common_name");
        char name[256];
        char path[PATH_MAX];
        if(!cJSON_IsString(pem))
            continue;
        sanitize_filename(cJSON_IsString(uri) ? uri->valuestring : (cJSON_IsString(cn) ? cn->valuestring : "trusted"), name, sizeof(name));
        snprintf(path, sizeof(path), "%s/certs/%s.der", target->trusted_dir, name);
        write_pem_cert_der(path, pem->valuestring);
        if(strcmp(target->runtime_side, "southbound") == 0 && count == 0) {
            snprintf(path, sizeof(path), "%s/certs/ot_server.der", target->trusted_dir);
            write_pem_cert_der(path, pem->valuestring);
        }
        count++;
    }
    return 1;
}

static int apply_trust_or_certificate_one(const GdsTarget *target, int allow_certificate) {
    cJSON *owner_doc = NULL;
    int certificate_mode = 0;
    cJSON *trust_doc;
    cJSON *tm;
    cJSON *ca_chain;
    cJSON *crl;
    cJSON *crl_bundle;
    cJSON *certs;
    char key_path[PATH_MAX];
    char cert_path[PATH_MAX];
    char key_before[65] = "";
    char key_after[65] = "";
    char receipt_path[PATH_MAX];
    char *receipt = NULL;
    cJSON *receipt_json;

    if(target->remote_peer_read_only) {
        fprintf(stderr, "[DMZ][GDS] remote_peer_read_only_target target=%s\n", target->name);
        return 0;
    }
    if(!env_bool("DMZ_GDS_RUNTIME_WRITE_ENABLED", 0)) {
        fprintf(stderr, "[DMZ][GDS] blocked_runtime_write_disabled\n");
        return 0;
    }
    trust_doc = trust_payload_from_cache_or_enrollment(target, allow_certificate, &certificate_mode, &owner_doc);
    if(!trust_doc) {
        fprintf(stderr, "[DMZ][GDS] trust_material_cache_missing target=%s\n", target->name);
        return 0;
    }
    if(!validate_signed_artifact_metadata(trust_doc))
        goto fail;

    tm = cJSON_GetObjectItemCaseSensitive(trust_doc, "trust_material");
    ca_chain = tm ? cJSON_GetObjectItemCaseSensitive(tm, "ca_chain_pem") : NULL;
    crl = tm ? cJSON_GetObjectItemCaseSensitive(tm, "crl_base64") : NULL;
    cJSON *artifact_obj = tm ? cJSON_GetObjectItemCaseSensitive(tm, "artifact") : NULL;
    crl_bundle = artifact_obj ? cJSON_GetObjectItemCaseSensitive(artifact_obj, "crl_bundle") : NULL;
    if(!crl_bundle)
        crl_bundle = tm ? cJSON_GetObjectItemCaseSensitive(tm, "crl_bundle") : NULL;
    certs = tm ? cJSON_GetObjectItemCaseSensitive(tm, "certificates") : NULL;
    snprintf(key_path, sizeof(key_path), "%s", target->key_path);
    snprintf(cert_path, sizeof(cert_path), "%s", target->cert_path);
    file_sha256_hex(key_path, key_before);

    if(cJSON_IsString(ca_chain))
        apply_ca_chain(target, ca_chain->valuestring);
    if(cJSON_IsObject(crl_bundle)) {
        cJSON *root_crl = cJSON_GetObjectItemCaseSensitive(crl_bundle, "root_crl_base64");
        cJSON *int_crl = cJSON_GetObjectItemCaseSensitive(crl_bundle, "intermediate_crl_base64");
        if(env_bool("DMZ_GDS_REQUIRE_REVOCATION_LISTS", 1) && (!cJSON_IsString(root_crl) || !cJSON_IsString(int_crl))) {
            fprintf(stderr, "[DMZ][GDS] revocation_lists_missing\n");
            goto fail;
        }
        if(cJSON_IsString(root_crl))
            apply_crl_alias(target, "root_ca", root_crl->valuestring);
        if(cJSON_IsString(int_crl))
            apply_crl_alias(target, "vault_intermediate", int_crl->valuestring);
    } else if(cJSON_IsString(crl)) {
        if(env_bool("DMZ_GDS_REQUIRE_REVOCATION_LISTS", 1)) {
            fprintf(stderr, "[DMZ][GDS] root_revocation_list_missing\n");
            goto fail;
        }
        apply_crl_alias(target, "vault_intermediate", crl->valuestring);
    } else if(env_bool("DMZ_GDS_REQUIRE_REVOCATION_LISTS", 1)) {
        fprintf(stderr, "[DMZ][GDS] revocation_lists_missing\n");
        goto fail;
    }
    if(cJSON_IsArray(certs))
        apply_trusted_certs(target, certs);
    if(certificate_mode) {
        cJSON *cert_pem = cJSON_GetObjectItemCaseSensitive(owner_doc, "certificate_pem");
        if(cJSON_IsString(cert_pem))
            write_pem_cert_der(cert_path, cert_pem->valuestring);
    }

    file_sha256_hex(key_path, key_after);
    receipt_json = cJSON_CreateObject();
    cJSON_AddStringToObject(receipt_json, "schema", "labshock_dmz_gateway_gds_apply_v1");
    cJSON_AddStringToObject(receipt_json, "target", target->name);
    cJSON_AddStringToObject(receipt_json, "application_uri", target->application_uri);
    cJSON_AddStringToObject(receipt_json, "apply_mode", certificate_mode ? "certificate_and_trust" : "trust_only");
    cJSON_AddBoolToObject(receipt_json, "runtime_mutation_performed", 1);
    cJSON_AddBoolToObject(receipt_json, "runtime_restart_automatic", 0);
    cJSON_AddBoolToObject(receipt_json, "own_certificate_touched", certificate_mode ? 1 : 0);
    cJSON_AddBoolToObject(receipt_json, "private_key_touched", 0);
    cJSON_AddBoolToObject(receipt_json, "private_key_sha256_unchanged", key_before[0] != '\0' && strcmp(key_before, key_after) == 0);
    cJSON_AddStringToObject(receipt_json, "own_certificate_path", cert_path);
    receipt = cJSON_PrintUnformatted(receipt_json);
    cJSON_Delete(receipt_json);
    cache_path(receipt_path, sizeof(receipt_path), target, "apply-receipt.json");
    write_text(receipt_path, receipt);
    fprintf(stdout, "[DMZ][GDS] apply complete target=%s mode=%s private_key_unchanged=%s\n",
            target->name,
            certificate_mode ? "certificate_and_trust" : "trust_only",
            key_before[0] != '\0' && strcmp(key_before, key_after) == 0 ? "true" : "false");
    dmz_telemetry_gds_event(target->name, target->application_uri,
                            certificate_mode ? "renewal_apply_completed" : "trust_apply_completed",
                            "completed", certificate_mode ? "certificate_and_trust" : "trust_only");
    free(receipt);
    if(owner_doc)
        cJSON_Delete(owner_doc);
    else
        cJSON_Delete(trust_doc);
    return 1;

fail:
    if(owner_doc)
        cJSON_Delete(owner_doc);
    else
        cJSON_Delete(trust_doc);
    return 0;
}

static int command_apply_trust_one(const GdsTarget *target) {
    return apply_trust_or_certificate_one(target, 0);
}

static int command_apply_certificate_one(const GdsTarget *target) {
    return apply_trust_or_certificate_one(target, 1);
}

static int command_renewal_check_one(const GdsTarget *target) {
    char path[2048];
    char *resp = NULL;
    if(!component_get_path(target, "renewal-policy", path, sizeof(path)) || !gds_http("GET", path, NULL, &resp))
        return 0;
    cache_json_response(target, "renewal-policy.json", resp);
    fprintf(stdout, "%s\n", resp);
    free(resp);
    return 1;
}

static void utc_iso_now(char *out, size_t out_len) {
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static int asn1_time_iso(const ASN1_TIME *t, char *out, size_t out_len) {
    struct tm tmv;
    if(!t || ASN1_TIME_to_tm(t, &tmv) != 1)
        return 0;
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return 1;
}

static int cert_metadata(const GdsTarget *target, char fingerprint[65], char not_before[32], char not_after[32], int *days_until_expiry) {
    unsigned char *data = NULL;
    const unsigned char *p;
    size_t len = 0;
    X509 *cert = NULL;
    int days = 0, secs = 0;
    fingerprint[0] = not_before[0] = not_after[0] = '\0';
    *days_until_expiry = -1;
    if(!target->cert_path || !file_sha256_hex(target->cert_path, fingerprint))
        return 0;
    if(!read_file_bytes(target->cert_path, &data, &len))
        return 0;
    p = data;
    cert = d2i_X509(NULL, &p, (long)len);
    if(!cert) {
        BIO *bio = BIO_new_mem_buf(data, (int)len);
        cert = bio ? PEM_read_bio_X509(bio, NULL, 0, NULL) : NULL;
        BIO_free(bio);
    }
    free(data);
    if(!cert)
        return 1;
    asn1_time_iso(X509_get0_notBefore(cert), not_before, 32);
    asn1_time_iso(X509_get0_notAfter(cert), not_after, 32);
    if(ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(cert)) == 1)
        *days_until_expiry = days;
    X509_free(cert);
    return 1;
}

static const char *json_string(cJSON *obj, const char *key) {
    cJSON *item = obj ? cJSON_GetObjectItemCaseSensitive(obj, key) : NULL;
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static int json_int(cJSON *obj, const char *key, int fallback) {
    cJSON *item = obj ? cJSON_GetObjectItemCaseSensitive(obj, key) : NULL;
    return cJSON_IsNumber(item) ? item->valueint : fallback;
}

static int json_bool(cJSON *obj, const char *key, int fallback) {
    cJSON *item = obj ? cJSON_GetObjectItemCaseSensitive(obj, key) : NULL;
    return cJSON_IsBool(item) ? cJSON_IsTrue(item) : fallback;
}

static long env_long(const char *name, long fallback) {
    const char *value = getenv(name);
    char *end = NULL;
    long parsed;
    if(!value || value[0] == '\0')
        return fallback;
    parsed = strtol(value, &end, 10);
    return end && *end == '\0' ? parsed : fallback;
}

static time_t parse_utc_iso_time(const char *value) {
    struct tm tmv;
    int year, month, day, hour, minute, second;
    if(!value)
        return (time_t)-1;
    if(sscanf(value, "%d-%d-%dT%d:%d:%dZ", &year, &month, &day, &hour, &minute, &second) != 6)
        return (time_t)-1;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = year - 1900;
    tmv.tm_mon = month - 1;
    tmv.tm_mday = day;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = second;
    return timegm(&tmv);
}

static long auto_renew_cooldown_remaining_seconds(const GdsTarget *target) {
    long cooldown = env_long("DMZ_GDS_AUTO_RENEW_COOLDOWN_SECONDS", 86400);
    cJSON *last = NULL;
    cJSON *item;
    long last_unix = 0;
    long remaining = 0;
    char fp[65] = "";
    char not_before[32] = "";
    char not_after[32] = "";
    int days = -1;
    if(cooldown <= 0)
        return 0;
    last = read_cached_json(target, "renewal-last.json");
    item = last ? cJSON_GetObjectItemCaseSensitive(last, "unix_time") : NULL;
    if(cJSON_IsNumber(item))
        last_unix = (long)item->valuedouble;
    if(last_unix > 0) {
        long elapsed = (long)time(NULL) - last_unix;
        if(elapsed < cooldown)
            remaining = cooldown - elapsed;
    }
    if(cert_metadata(target, fp, not_before, not_after, &days)) {
        time_t cert_start = parse_utc_iso_time(not_before);
        if(cert_start > 0) {
            long elapsed = (long)time(NULL) - (long)cert_start;
            long cert_remaining = elapsed < cooldown ? cooldown - elapsed : 0;
            if(cert_remaining > remaining)
                remaining = cert_remaining;
        }
    }
    if(last)
        cJSON_Delete(last);
    return remaining;
}

static void record_auto_renewal_success(const GdsTarget *target, const char *status) {
    cJSON *root = cJSON_CreateObject();
    char ts[32];
    char *body;
    utc_iso_now(ts, sizeof(ts));
    cJSON_AddStringToObject(root, "target", target->name);
    cJSON_AddStringToObject(root, "application_uri", target->application_uri);
    cJSON_AddStringToObject(root, "status", status ? status : "applied");
    cJSON_AddStringToObject(root, "timestamp", ts);
    cJSON_AddNumberToObject(root, "unix_time", (double)time(NULL));
    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if(body) {
        cache_json_response(target, "renewal-last.json", body);
        free(body);
    }
}

static cJSON *trust_version_from_cache(const GdsTarget *target) {
    cJSON *doc = read_cached_json(target, "trust-version.json");
    if(doc)
        return doc;
    doc = read_cached_json(target, "trust-material.json");
    if(doc) {
        cJSON *tm = cJSON_GetObjectItemCaseSensitive(doc, "trust_material");
        if(tm)
            return doc;
        cJSON_Delete(doc);
    }
    return NULL;
}

static int post_component_event(const GdsTarget *target, const char *event_type, const char *status_value, const char *message) {
    char path[2048];
    char *body = NULL;
    char *resp = NULL;
    cJSON *root = cJSON_CreateObject();
    int ok;
    cJSON_AddStringToObject(root, "application_uri", target->application_uri);
    cJSON_AddStringToObject(root, "component_name", "dmz-gateway");
    cJSON_AddStringToObject(root, "target", target->name);
    cJSON_AddStringToObject(root, "event_type", event_type);
    if(status_value)
        cJSON_AddStringToObject(root, "status", status_value);
    if(message)
        cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "details", cJSON_CreateObject());
    body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    ok = component_lifecycle_path(target, "events", path, sizeof(path)) && gds_http("POST", path, body, &resp);
    dmz_telemetry_gds_event(target->name, target->application_uri, event_type, status_value, message);
    free(body);
    free(resp);
    return ok;
}

static int post_component_status(const GdsTarget *target, const char *pull_status, const char *apply_status, const char *renewal_status) {
    char path[2048];
    char *body = NULL;
    char *resp = NULL;
    char ts[32], fp[65], nb[32], na[32];
    int days = -1;
    cJSON *cache = trust_version_from_cache(target);
    cJSON *tm = cache ? cJSON_GetObjectItemCaseSensitive(cache, "trust_material") : NULL;
    cJSON *src = tm ? tm : cache;
    cJSON *root = cJSON_CreateObject();
    int ok;
    cert_metadata(target, fp, nb, na, &days);
    utc_iso_now(ts, sizeof(ts));
    cJSON_AddStringToObject(root, "application_uri", target->application_uri);
    cJSON_AddStringToObject(root, "component_name", "dmz-gateway");
    cJSON_AddStringToObject(root, "runtime_instance_id", target->runtime_instance_id);
    cJSON_AddStringToObject(root, "zone", target->zone);
    cJSON_AddStringToObject(root, "role", target->role);
    cJSON_AddStringToObject(root, "target", target->name);
    if(fp[0])
        cJSON_AddStringToObject(root, "certificate_fingerprint_sha256", fp);
    if(nb[0])
        cJSON_AddStringToObject(root, "certificate_not_before", nb);
    if(na[0])
        cJSON_AddStringToObject(root, "certificate_not_after", na);
    if(days >= 0)
        cJSON_AddNumberToObject(root, "days_until_expiry", days);
    cJSON_AddNumberToObject(root, "trust_artifact_version", json_int(src, tm ? "trustlist_version" : "trust_artifact_version", 0));
    cJSON_AddNumberToObject(root, "trust_artifact_revision", json_int(src, "artifact_revision", json_int(src, "trust_artifact_revision", 0)));
    const char *sha = json_string(src, "artifact_sha256");
    if(!sha)
        sha = json_string(src, "trust_artifact_sha256");
    if(sha)
        cJSON_AddStringToObject(root, "trust_artifact_sha256", sha);
    cJSON *crl_meta = NULL;
    if(tm) {
        cJSON *artifact = cJSON_GetObjectItemCaseSensitive(tm, "artifact");
        crl_meta = artifact ? cJSON_GetObjectItemCaseSensitive(artifact, "crl_metadata") : cJSON_GetObjectItemCaseSensitive(tm, "crl_metadata");
    } else {
        crl_meta = cJSON_GetObjectItemCaseSensitive(src, "crl_metadata");
    }
    cJSON_AddBoolToObject(root, "crl_freshness_verified", json_bool(crl_meta, "crl_freshness_verified", 0));
    cJSON_AddStringToObject(root, "last_pull_status", pull_status ? pull_status : "unknown");
    cJSON_AddStringToObject(root, "last_apply_status", apply_status ? apply_status : "not_requested");
    cJSON_AddStringToObject(root, "last_renewal_status", renewal_status ? renewal_status : "not_requested");
    cJSON_AddBoolToObject(root, "private_key_exported", 0);
    cJSON_AddBoolToObject(root, "private_key_touched", 0);
    cJSON_AddBoolToObject(root, "runtime_write_enabled", env_bool("DMZ_GDS_AUTO_APPLY_TRUST", 0));
    cJSON_AddStringToObject(root, "timestamp", ts);
    body = cJSON_PrintUnformatted(root);
    cache_json_response(target, "status-last.json", body ? body : "{}");
    cJSON_Delete(root);
    if(cache)
        cJSON_Delete(cache);
    ok = component_lifecycle_path(target, "status", path, sizeof(path)) && gds_http("POST", path, body, &resp);
    free(body);
    free(resp);
    return ok;
}

static int command_lifecycle_once_one(const GdsTarget *target) {
    char path[2048];
    char *lifecycle = NULL;
    char *trust_version = NULL;
    cJSON *life = NULL;
    cJSON *tv = NULL;
    int got_lifecycle = 0;
    int trust_update = 0;
    int pull_ok = 0;
    int apply_ok = 0;
    int renewal_ok = 0;
    int renewal_apply_ok = 0;
    int renewal_required = 0;
    long cooldown_remaining = 0;
    const char *pull_status = "not_requested";
    const char *apply_status = "not_requested";
    const char *renewal_status = "not_requested";
    if(target->remote_peer_read_only)
        return 1;
    post_component_event(target, "lifecycle_check_started", "started", NULL);
    if(!component_lifecycle_path(target, "lifecycle", path, sizeof(path)) || !gds_http("GET", path, NULL, &lifecycle))
        goto done;
    got_lifecycle = 1;
    cache_json_response(target, "lifecycle.json", lifecycle);
    life = cJSON_Parse(lifecycle);
    trust_update = json_bool(life, "trust_update_available", 0);
    renewal_required = json_bool(life, "renewal_required", 0);
    if(!component_lifecycle_path(target, "trust-version", path, sizeof(path)) || !gds_http("GET", path, NULL, &trust_version))
        goto done;
    cache_json_response(target, "trust-version.json", trust_version);
    tv = cJSON_Parse(trust_version);
    if(trust_update)
        post_component_event(target, "trust_version_changed", "detected", json_string(tv, "trust_artifact_sha256"));
    if(trust_update && env_bool("DMZ_GDS_AUTO_PULL_TRUST", 1)) {
        post_component_event(target, "trust_pull_started", "started", NULL);
        pull_ok = command_pull_trust_one(target);
        pull_status = pull_ok ? "completed" : "failed";
        post_component_event(target, "trust_pull_completed", pull_ok ? "completed" : "failed", NULL);
    } else {
        pull_status = trust_update ? "skipped" : "not_needed";
    }
    if(trust_update && env_bool("DMZ_GDS_AUTO_APPLY_TRUST", 0)) {
        post_component_event(target, "trust_apply_started", "started", NULL);
        setenv("DMZ_GDS_RUNTIME_WRITE_ENABLED", "true", 1);
        apply_ok = command_apply_trust_one(target);
        apply_status = apply_ok ? "completed" : "failed";
        post_component_event(target, apply_ok ? "trust_apply_completed" : "trust_apply_failed", apply_ok ? "completed" : "failed", NULL);
    }
    if(renewal_required) {
        post_component_event(target, "renewal_threshold_reached", "detected", NULL);
        if(auto_renew_allowed_for_target(target)) {
            cooldown_remaining = auto_renew_cooldown_remaining_seconds(target);
            if(cooldown_remaining > 0) {
                char msg[128];
                snprintf(msg, sizeof(msg), "cooldown_remaining_seconds=%ld", cooldown_remaining);
                renewal_status = "blocked_auto_renew_cooldown";
                post_component_event(target, "renewal_apply_failed", "blocked", msg);
                goto done;
            }
            post_component_event(target, "renewal_csr_generated", "started", NULL);
            renewal_ok = command_renew_one(target);
            post_component_event(target, renewal_ok ? "renewal_package_received" : "renewal_apply_failed", renewal_ok ? "completed" : "failed", NULL);
            if(renewal_ok) {
                post_component_event(target, "renewal_apply_started", "started", NULL);
                setenv("DMZ_GDS_RUNTIME_WRITE_ENABLED", "true", 1);
                renewal_apply_ok = command_apply_certificate_one(target);
                renewal_status = renewal_apply_ok ? "applied" : "apply_failed";
                post_component_event(target, renewal_apply_ok ? "renewal_apply_completed" : "renewal_apply_failed", renewal_apply_ok ? "completed" : "failed", NULL);
                if(renewal_apply_ok)
                    record_auto_renewal_success(target, renewal_status);
            } else {
                renewal_status = "failed";
            }
        } else {
            renewal_status = env_bool("DMZ_GDS_AUTO_RENEW", 0) ? "blocked_auto_renew_target_not_allowed" : "blocked_auto_renew_false";
        }
    }
done:
    post_component_status(target, pull_status, apply_status, renewal_status);
    post_component_event(target, "lifecycle_check_completed", "completed", NULL);
    fprintf(stdout,
            "{\"schema\":\"labshock_dmz_gateway_gds_lifecycle_once_v1\",\"target\":\"%s\",\"application_uri\":\"%s\",\"trust_update_available\":%s,\"trust_pulled\":\"%s\",\"trust_apply_status\":\"%s\",\"renewal_required\":%s,\"renewal_status\":\"%s\",\"auto_renew\":%s,\"auto_renew_cooldown_remaining_seconds\":%ld}\n",
            target->name, target->application_uri, trust_update ? "true" : "false", pull_status, apply_status,
            renewal_required ? "true" : "false", renewal_status, auto_renew_allowed_for_target(target) ? "true" : "false", cooldown_remaining);
    free(lifecycle);
    free(trust_version);
    if(life)
        cJSON_Delete(life);
    if(tv)
        cJSON_Delete(tv);
    return got_lifecycle;
}

static volatile sig_atomic_t lifecycle_stop = 0;

static void lifecycle_signal_handler(int sig) {
    (void)sig;
    lifecycle_stop = 1;
}

static int lifecycle_lock_acquire(const char *path) {
    int fd;
    ensure_parent_dir(path);
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if(fd < 0)
        return -1;
    dprintf(fd, "%ld\n", (long)getpid());
    close(fd);
    return 0;
}

static int run_for_target(const char *target_name, int include_remote_peers, int (*fn)(const GdsTarget*));

static int command_lifecycle_loop(const char *target_name) {
    const char *lock_path = env_or_default("DMZ_GDS_LOCK_FILE", GDS_LOCK_FILE_DEFAULT);
    int interval = atoi(env_or_default("DMZ_GDS_LIFECYCLE_INTERVAL_SECONDS", "300"));
    if(interval <= 0)
        interval = 300;
    if(lifecycle_lock_acquire(lock_path) != 0) {
        fprintf(stderr, "[DMZ][GDS] lifecycle_lock_held path=%s\n", lock_path);
        return 1;
    }
    signal(SIGTERM, lifecycle_signal_handler);
    signal(SIGINT, lifecycle_signal_handler);
    srand((unsigned int)time(NULL));
    sleep((unsigned int)(rand() % 31));
    while(!lifecycle_stop) {
        run_for_target(target_name, 0, command_lifecycle_once_one);
        for(int i = 0; i < interval && !lifecycle_stop; i++)
            sleep(1);
    }
    unlink(lock_path);
    return 0;
}

static int command_validate_one(const GdsTarget *target) {
    char cert_hash[65] = "";
    char key_hash[65] = "";
    cJSON *trust = read_cached_json(target, "trust-material.json");
    int has_trust = trust != NULL;
    if(target->cert_path)
        file_sha256_hex(target->cert_path, cert_hash);
    if(target->key_path)
        file_sha256_hex(target->key_path, key_hash);
    if(trust)
        cJSON_Delete(trust);
    fprintf(stdout,
            "{\"schema\":\"labshock_dmz_gateway_gds_validate_v1\",\"target\":\"%s\",\"application_uri\":\"%s\",\"own_certificate_found\":%s,\"private_key_found\":%s,\"trust_material_cache_found\":%s,\"private_key_included\":false}\n",
            target->name,
            target->application_uri,
            cert_hash[0] ? "true" : "false",
            key_hash[0] ? "true" : "false",
            has_trust ? "true" : "false");
    return target->remote_peer_read_only ? has_trust : (cert_hash[0] && key_hash[0] && has_trust);
}

static int run_for_target(const char *target_name, int include_remote_peers, int (*fn)(const GdsTarget*)) {
    int ok = 1;
    if(strcmp(target_name, "all") == 0) {
        for(size_t i = 0; i < sizeof(TARGETS) / sizeof(TARGETS[0]); i++) {
            if(TARGETS[i].remote_peer_read_only && !include_remote_peers)
                continue;
            ok = fn(&TARGETS[i]) && ok;
        }
        return ok;
    }
    const GdsTarget *target = NULL;
    if(!dmz_gds_resolve_target(target_name, &target)) {
        fprintf(stderr, "[DMZ][GDS] unknown target=%s\n", target_name);
        return 0;
    }
    return fn(target);
}

static const char *parse_target_arg(int argc, char **argv) {
    for(int i = 1; i < argc - 1; i++) {
        if(strcmp(argv[i], "--target") == 0)
            return argv[i + 1];
    }
    return "all";
}

int gds_handle_cli(int argc, char **argv) {
    const char *target_name;
    if(argc < 2)
        return -1;
    target_name = parse_target_arg(argc, argv);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    OpenSSL_add_all_algorithms();
    if(strcmp(argv[1], "--gds-discover") == 0)
        return run_for_target(target_name, 1, command_discover_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-pull-trust") == 0)
        return run_for_target(target_name, 1, command_pull_trust_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-enroll") == 0)
        return run_for_target(target_name, 0, command_enroll_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-renew") == 0)
        return run_for_target(target_name, 0, command_renew_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-renewal-check") == 0)
        return run_for_target(target_name, 0, command_renewal_check_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-apply-trust") == 0)
        return run_for_target(target_name, 0, command_apply_trust_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-apply-certificate") == 0)
        return run_for_target(target_name, 0, command_apply_certificate_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-validate") == 0)
        return run_for_target(target_name, 1, command_validate_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-lifecycle-once") == 0)
        return run_for_target(target_name, 0, command_lifecycle_once_one) ? 0 : 1;
    if(strcmp(argv[1], "--gds-lifecycle-loop") == 0)
        return command_lifecycle_loop(target_name);
    return -1;
}

int gds_startup_bootstrap(void) {
    if(!env_bool("DMZ_GDS_ENABLED", 0))
        return 1;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if(env_bool("DMZ_GDS_DISCOVER_ON_START", 0) && !run_for_target("all", 1, command_discover_one))
        return 0;
    if(env_bool("DMZ_GDS_PULL_TRUST_ON_START", 0) && !run_for_target("all", 1, command_pull_trust_one))
        return 0;
    if(env_bool("DMZ_GDS_APPLY_TRUST_ON_START", 0) && !run_for_target("all", 0, command_apply_trust_one))
        return 0;
    if(env_bool("DMZ_GDS_LIFECYCLE_ENABLED", 0) && !run_for_target("all", 0, command_lifecycle_once_one))
        return 0;
    return 1;
}
