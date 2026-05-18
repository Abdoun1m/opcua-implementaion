#ifndef CACHE_H
#define CACHE_H

#include <open62541/types.h>

typedef struct {
    UA_Boolean valid;
    UA_Boolean boolValue;
    UA_Double doubleValue;
    UA_Int32 int32Value;
    UA_DateTime timestamp;
} CacheValue;
void cache_set_int32(size_t idx, UA_Int32 value);
void cache_init(void);
void cache_set_bool(size_t idx, UA_Boolean value);
void cache_set_double(size_t idx, UA_Double value);
CacheValue cache_get(size_t idx);

#endif
