#include "cache.h"
#include "whitelist.h"
#include <stdlib.h>

static CacheValue *cache = NULL;

void cache_init(void) {
    cache = (CacheValue*)calloc(GATEWAY_POINTS_COUNT, sizeof(CacheValue));
}

void cache_set_bool(size_t idx, UA_Boolean value) {
    cache[idx].valid = true;
    cache[idx].boolValue = value;
    cache[idx].timestamp = UA_DateTime_now();
}

void cache_set_double(size_t idx, UA_Double value) {
    cache[idx].valid = true;
    cache[idx].doubleValue = value;
    cache[idx].timestamp = UA_DateTime_now();
}
void cache_set_int32(size_t idx, UA_Int32 value) {
    cache[idx].valid = true;
    cache[idx].int32Value = value;
    cache[idx].timestamp = UA_DateTime_now();
}
CacheValue cache_get(size_t idx) {
    return cache[idx];
}
