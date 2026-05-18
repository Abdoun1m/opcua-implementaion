#ifndef DMZ_TELEMETRY_H
#define DMZ_TELEMETRY_H

#include <cjson/cJSON.h>

void dmz_telemetry_init(void);
void dmz_telemetry_cleanup(void);
int dmz_telemetry_enabled(void);
int dmz_telemetry_event(const char *message,
                        const char *event_category,
                        const char *severity,
                        cJSON *raw);
int dmz_telemetry_gds_event(const char *target,
                            const char *application_uri,
                            const char *event_type,
                            const char *status,
                            const char *detail);
cJSON *dmz_telemetry_raw(const char *event_type);

#endif
