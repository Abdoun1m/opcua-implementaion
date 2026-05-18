#ifndef SOUTHBOUND_CLIENT_H
#define SOUTHBOUND_CLIENT_H

#include <stddef.h>

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>

typedef struct {
    UA_Client *client;
    UA_UInt16 nsIdx;

    char endpointUrl[256];
    char username[128];
    char password[128];
} SouthboundContext;

int southbound_init(SouthboundContext *ctx,
                    const char *endpointUrl,
                    const char *username,
                    const char *password);

int southbound_connect(SouthboundContext *ctx);
void southbound_disconnect(SouthboundContext *ctx);
void southbound_clear(SouthboundContext *ctx);

int southbound_poll_once(SouthboundContext *ctx);

#endif
