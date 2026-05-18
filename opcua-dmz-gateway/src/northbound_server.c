#include "northbound_server.h"
#include "cache.h"
#include "whitelist.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/accesscontrol_default.h>

static UA_Server *server = NULL;

#define NORTHBOUND_APP_URI "urn:dataprotect:opcua:dmz-gateway-server"
#define NORTHBOUND_PRODUCT_URI "urn:dataprotect:opcua:dmz-gateway"
#define NORTHBOUND_APP_NAME "LabShock DMZ Gateway Northbound Server"
#define NORTHBOUND_SERVER_URL "opc.tcp://192.168.10.20:4841"

static const char *env_or_default(const char *name, const char *fallback) {
    const char *v = getenv(name);
    if(v && v[0] != '\0')
        return v;
    return fallback;
}

static UA_ByteString
load_file(const char *path) {
    UA_ByteString out = UA_BYTESTRING_NULL;

    FILE *f = fopen(path, "rb");
    if(!f) {
        fprintf(stderr, "[DMZ][SERVER] Cannot open: %s\n", path);
        return out;
    }

    if(fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return out;
    }

    long sz = ftell(f);
    if(sz <= 0) {
        fclose(f);
        return out;
    }

    rewind(f);

    out.length = (size_t)sz;
    out.data = (UA_Byte*)UA_malloc(out.length);
    if(!out.data) {
        out.length = 0;
        fclose(f);
        return out;
    }

    size_t got = fread(out.data, 1, out.length, f);
    fclose(f);

    if(got != out.length) {
        UA_ByteString_clear(&out);
        return UA_BYTESTRING_NULL;
    }

    fprintf(stdout, "[DMZ][SERVER] Loaded %s (%lu bytes)\n",
            path, (unsigned long)out.length);
    return out;
}

static UA_StatusCode
read_callback(UA_Server *server_,
              const UA_NodeId *sessionId,
              void *sessionContext,
              const UA_NodeId *nodeId,
              void *nodeContext,
              UA_Boolean sourceTimeStamp,
              const UA_NumericRange *range,
              UA_DataValue *dataValue) {
    (void)server_;
    (void)sessionId;
    (void)sessionContext;
    (void)nodeId;
    (void)sourceTimeStamp;
    (void)range;

    size_t idx = (size_t)(uintptr_t)nodeContext;
    CacheValue cv = cache_get(idx);

    if(!cv.valid) {
        dataValue->hasValue = false;
        return UA_STATUSCODE_GOOD;
    }

if(GATEWAY_POINTS[idx].type == GW_TYPE_BOOL) {
    UA_Variant_setScalarCopy(&dataValue->value,
                             &cv.boolValue,
                             &UA_TYPES[UA_TYPES_BOOLEAN]);
}
else if(GATEWAY_POINTS[idx].type == GW_TYPE_DOUBLE) {
    UA_Variant_setScalarCopy(&dataValue->value,
                             &cv.doubleValue,
                             &UA_TYPES[UA_TYPES_DOUBLE]);
}
else if(GATEWAY_POINTS[idx].type == GW_TYPE_INT32) {
    UA_Variant_setScalarCopy(&dataValue->value,
                             &cv.int32Value,
                             &UA_TYPES[UA_TYPES_INT32]);
}
    dataValue->hasValue = true;
    dataValue->sourceTimestamp = cv.timestamp;
    dataValue->hasSourceTimestamp = true;
    return UA_STATUSCODE_GOOD;
}
static size_t load_trust_list_from_dir(const char *dirPath, UA_ByteString **outList) {
    DIR *dir = opendir(dirPath);
    if(!dir) {
        fprintf(stderr, "[NB][TRUST] Cannot open dir: %s\n", dirPath);
        return 0;
    }

    struct dirent *entry;
    size_t count = 0;

    /* First pass: count files */
    while((entry = readdir(dir)) != NULL) {
        if(entry->d_type == DT_REG) {
            count++;
        }
    }

    rewinddir(dir);

    if(count == 0) {
        closedir(dir);
        return 0;
    }

    UA_ByteString *list = (UA_ByteString*)UA_malloc(sizeof(UA_ByteString) * count);
    size_t index = 0;

    while((entry = readdir(dir)) != NULL) {
        if(entry->d_type != DT_REG)
            continue;

        char fullPath[512];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        list[index] = load_file(fullPath);

        if(list[index].length > 0) {
            printf("[NB][TRUST] Loaded: %s\n", fullPath);
            index++;
        } else {
            printf("[NB][TRUST] Skipped: %s\n", fullPath);
        }
    }

    closedir(dir);

    *outList = list;
    return index;
}

static void
configure_northbound_application_description(UA_ServerConfig *config) {
    if(!config)
        return;

    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC(NORTHBOUND_APP_URI);

    UA_String_clear(&config->applicationDescription.productUri);
    config->applicationDescription.productUri = UA_STRING_ALLOC(NORTHBOUND_PRODUCT_URI);

    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName = UA_LOCALIZEDTEXT_ALLOC("en-US", NORTHBOUND_APP_NAME);

    config->applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;

    if(config->serverUrlsSize > 0) {
        for(size_t i = 0; i < config->serverUrlsSize; i++)
            UA_String_clear(&config->serverUrls[i]);
        config->serverUrls[0] = UA_STRING_ALLOC(NORTHBOUND_SERVER_URL);
        config->serverUrlsSize = 1;
    }

    fprintf(stdout, "[DMZ][SERVER] ApplicationUri=%s\n", NORTHBOUND_APP_URI);
    fprintf(stdout, "[DMZ][SERVER] ApplicationName=%s\n", NORTHBOUND_APP_NAME);
}

int
northbound_init(void) {
    server = UA_Server_new();
    if(!server) {
        fprintf(stderr, "[DMZ][SERVER] UA_Server_new failed\n");
        return 0;
    }

    UA_ServerConfig *config = UA_Server_getConfig(server);

    const char *pkiBase = env_or_default("DMZ_PKI_DIR", "/app/pki");
    const char *certPathEnv = getenv("DMZ_NB_CERT_PATH");
    const char *keyPathEnv = getenv("DMZ_NB_KEY_PATH");
    const char *trustDirEnv = getenv("DMZ_NB_TRUST_DIR");
    char certPath[512];
    char keyPath[512];
    char trustDir[512];

    if(certPathEnv && certPathEnv[0] != '\0')
        snprintf(certPath, sizeof(certPath), "%s", certPathEnv);
    else
        snprintf(certPath, sizeof(certPath), "%s/northbound/own/certs/server.der", pkiBase);

    if(keyPathEnv && keyPathEnv[0] != '\0')
        snprintf(keyPath, sizeof(keyPath), "%s", keyPathEnv);
    else
        snprintf(keyPath, sizeof(keyPath), "%s/northbound/own/private/server.key.der", pkiBase);

    if(trustDirEnv && trustDirEnv[0] != '\0')
        snprintf(trustDir, sizeof(trustDir), "%s", trustDirEnv);
    else
        snprintf(trustDir, sizeof(trustDir), "%s/northbound/trusted/certs", pkiBase);

    UA_ByteString cert = load_file(certPath);
    UA_ByteString key  = load_file(keyPath);
    UA_ByteString *trustList = NULL;
    size_t trustListSize = load_trust_list_from_dir(trustDir, &trustList);

    if(trustListSize == 0) {
        fprintf(stderr, "[NB][INIT] No trusted certs loaded\n");
        return 0;
    }
    if(cert.length == 0 || key.length == 0 || trustListSize == 0){
        fprintf(stderr, "[DMZ][SERVER] Missing northbound PKI material\n");
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&trustList[0]);
        return 0;
    }

    configure_northbound_application_description(config);

    /* Current open62541 signature requires issuer + revocation args too */
    UA_StatusCode rc = UA_ServerConfig_setDefaultWithSecurityPolicies(
        config,
        4841,
        &cert,
        &key,
        trustList,
        trustListSize,
        NULL, 0,   /* issuerList, issuerListSize */
        NULL, 0    /* revocationList, revocationListSize */
    );

    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][SERVER] Security config failed: %s\n",
                UA_StatusCode_name(rc));
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&trustList[0]);
        return 0;
    }

    configure_northbound_application_description(config);

    /* Disable anonymous using the supported access-control helper API */
    if(config->accessControl.clear)
        config->accessControl.clear(&config->accessControl);
    static UA_UsernamePasswordLogin logins[1] = {
       { UA_STRING_STATIC("viewer"), UA_STRING_STATIC("viewer123") }
    };

    UA_StatusCode ac = UA_AccessControl_default(
       config,
       false,   /* no anonymous */
       NULL,
       1,
       logins
    );

    if(ac != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][SERVER] Access control init failed: %s\n",
                UA_StatusCode_name(ac));
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&trustList[0]);
        return 0;
    }

    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    for(size_t i = 0; i < trustListSize; i++) {
        UA_ByteString_clear(&trustList[i]);
    }
    UA_free(trustList);
    UA_NodeId folderId;
    rc = UA_Server_addObjectNode(
        server,
        UA_NODEID_NULL,
        UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        UA_QUALIFIEDNAME(1, "DMZ"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
        UA_ObjectAttributes_default,
        NULL,
        &folderId
    );
    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][SERVER] Failed to create DMZ folder: %s\n",
                UA_StatusCode_name(rc));
        return 0;
    }

    for(size_t i = 0; i < GATEWAY_POINTS_COUNT; i++) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;

        UA_DataSource ds;
        ds.read = read_callback;
        ds.write = NULL;

        rc = UA_Server_addDataSourceVariableNode(
            server,
            UA_NODEID_NULL,
            folderId,
            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
            UA_QUALIFIEDNAME(1, (char*)GATEWAY_POINTS[i].label),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            attr,
            ds,
            (void*)(uintptr_t)i,
            NULL
        );

        if(rc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[DMZ][SERVER] Failed to add node %s: %s\n",
                    GATEWAY_POINTS[i].label,
                    UA_StatusCode_name(rc));
        }
    }

    rc = UA_Server_run_startup(server);
    if(rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[DMZ][SERVER] Startup failed: %s\n",
                UA_StatusCode_name(rc));
        return 0;
    }

    fprintf(stdout, "[DMZ][SERVER] Secure northbound OPC UA server listening on 4841\n");
    return 1;
}

void
northbound_run_iterate(void) {
    if(server)
        UA_Server_run_iterate(server, true);
}
