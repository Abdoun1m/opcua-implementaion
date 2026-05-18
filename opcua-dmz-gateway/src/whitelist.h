#ifndef WHITELIST_H
#define WHITELIST_H

#include <stddef.h>
#include <open62541/client.h>

typedef enum {
    GW_TYPE_BOOL = 0,
    GW_TYPE_DOUBLE = 1,
    GW_TYPE_INT32 = 2
} GwDataType;

typedef struct {
    const char *label;
    UA_UInt32 numericId;
    GwDataType type;
} GatewayPoint;

extern const GatewayPoint GATEWAY_POINTS[];
extern const size_t GATEWAY_POINTS_COUNT;

#endif
