#include "dmz_config.h"
#include "southbound_client.h"
#include "northbound_server.h"
#include "cache.h"
#include "influx_writer.h"
#include "gds_client.h"
#include "dmz_telemetry.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile int running = 1;

static void stop_handler(int sig) {
    fprintf(stdout, "[DMZ][LIFECYCLE] Signal received: %d -> stopping\n", sig);
    running = 0;
}

static const char *env_or_default(const char *name, const char *fallback) {
    const char *v = getenv(name);
    if(v && v[0] != '\0')
        return v;
    return fallback;
}

static int env_int_or_default(const char *name, int fallback) {
    const char *v = getenv(name);
    int parsed;
    if(!v || v[0] == '\0')
        return fallback;
    parsed = atoi(v);
    return parsed > 0 ? parsed : fallback;
}

int main(int argc, char **argv) {
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    int gds_cli = gds_handle_cli(argc, argv);
    if(gds_cli >= 0)
        return gds_cli == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

    const char *endpointUrl = env_or_default("OT_ENDPOINT_URL", DEFAULT_OT_ENDPOINT_URL);
    const char *username    = env_or_default("OT_USERNAME", DEFAULT_OT_USERNAME);
    const char *password    = env_or_default("OT_PASSWORD", DEFAULT_OT_PASSWORD);

    const char *influxHost   = env_or_default("INFLUX_HOST", "192.168.10.15");
    const char *influxPortS  = env_or_default("INFLUX_PORT", "8086");
    const char *influxOrg    = env_or_default("INFLUX_ORG", "dataprotect");
    const char *influxBucket = env_or_default("INFLUX_BUCKET", "ot_telemetry");
    const char *influxToken  = env_or_default("INFLUX_TOKEN", "supersecrettoken");

    int influxPort = atoi(influxPortS);
    int healthIntervalSeconds = env_int_or_default("DMZ_GATEWAY_COLLECTOR_HEALTH_INTERVAL_SECONDS", 300);
    time_t nextHeartbeat = 0;

    dmz_telemetry_init();

    fprintf(stdout, "[DMZ][BOOT] Starting OPC UA DMZ Gateway\n");
    fprintf(stdout, "[DMZ][BOOT] OT Endpoint: %s\n", endpointUrl);
    fprintf(stdout, "[DMZ][BOOT] Username: %s\n", username);
    fprintf(stdout, "[DMZ][BOOT] InfluxDB: http://%s:%d\n", influxHost, influxPort);
    {
        cJSON *raw = dmz_telemetry_raw("opcua_dmz_started");
        cJSON_AddStringToObject(raw, "ot_endpoint", endpointUrl);
        cJSON_AddStringToObject(raw, "ot_username", username);
        cJSON_AddStringToObject(raw, "influx_host", influxHost);
        cJSON_AddNumberToObject(raw, "influx_port", influxPort);
        cJSON_AddStringToObject(raw, "runtime_side", "dmz_gateway");
        dmz_telemetry_event("opcua_dmz_started", "system_health", "info", raw);
    }

    if(!gds_startup_bootstrap()) {
        fprintf(stderr, "[DMZ][FATAL] GDS startup bootstrap failed\n");
        dmz_telemetry_event("opcua_dmz_gds_bootstrap_failed", "pki_trust_sync", "critical",
                            dmz_telemetry_raw("gds_startup_bootstrap_failed"));
        dmz_telemetry_cleanup();
        return EXIT_FAILURE;
    }

    /* INIT CACHE + INFLUX + SERVER */
    cache_init();

    if(!influx_writer_init(influxHost, influxPort, influxOrg, influxBucket, influxToken)) {
        fprintf(stderr, "[DMZ][FATAL] InfluxDB writer init failed\n");
        dmz_telemetry_event("opcua_dmz_influx_unavailable", "error", "critical",
                            dmz_telemetry_raw("influx_init_failed"));
        dmz_telemetry_cleanup();
        return EXIT_FAILURE;
    }

    if(!northbound_init()) {
        fprintf(stderr, "[DMZ][FATAL] Northbound server init failed\n");
        dmz_telemetry_event("opcua_dmz_northbound_failed", "error", "critical",
                            dmz_telemetry_raw("northbound_init_failed"));
        influx_writer_cleanup();
        dmz_telemetry_cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stdout, "[DMZ][STATE] Northbound OPC UA server started\n");
    dmz_telemetry_event("opcua_dmz_northbound_started", "system_health", "info",
                        dmz_telemetry_raw("northbound_started"));

    SouthboundContext ctx;
    int initialized = 0;
    int connected = 0;

    while(running) {

        if(!initialized) {
            fprintf(stdout, "[DMZ][STATE] Initializing southbound client...\n");

            if(!southbound_init(&ctx, endpointUrl, username, password)) {
                fprintf(stderr, "[DMZ][STATE] Init failed, retry in 3s\n");
                sleep(3);
                continue;
            }

            initialized = 1;
            dmz_telemetry_event("opcua_dmz_southbound_initialized", "system_health", "info",
                                dmz_telemetry_raw("southbound_initialized"));
        }

        if(!connected) {
            fprintf(stdout, "[DMZ][STATE] Connecting to OT...\n");

            if(!southbound_connect(&ctx)) {
                fprintf(stderr, "[DMZ][STATE] Connect failed, retry in 3s\n");
                southbound_clear(&ctx);
                initialized = 0;
                sleep(3);
                continue;
            }

            connected = 1;
            fprintf(stdout, "[DMZ][STATE] Connected to OT OPC UA\n");
            dmz_telemetry_event("opcua_dmz_southbound_connected", "opcua_session", "info",
                                dmz_telemetry_raw("southbound_connected"));
        }

        if(!southbound_poll_once(&ctx)) {
            fprintf(stderr, "[DMZ][STATE] Poll failed → reconnect\n");

            dmz_telemetry_event("opcua_dmz_southbound_poll_failed", "opcua_session", "warning",
                                dmz_telemetry_raw("southbound_poll_failed"));

            southbound_disconnect(&ctx);
            southbound_clear(&ctx);

            initialized = 0;
            connected = 0;
            sleep(3);
            continue;
        }

        if(time(NULL) >= nextHeartbeat) {
            cJSON *raw = dmz_telemetry_raw("opcua_dmz_heartbeat");
            cJSON_AddBoolToObject(raw, "southbound_initialized", initialized ? 1 : 0);
            cJSON_AddBoolToObject(raw, "southbound_connected", connected ? 1 : 0);
            cJSON_AddNumberToObject(raw, "poll_interval_ms", POLL_INTERVAL_MS);
            cJSON_AddNumberToObject(raw, "health_interval_seconds", healthIntervalSeconds);
            dmz_telemetry_event("opcua_dmz_heartbeat", "system_health", "info", raw);
            nextHeartbeat = time(NULL) + healthIntervalSeconds;
        }

        northbound_run_iterate();

        usleep(POLL_INTERVAL_MS * 1000);
    }

    if(connected)
        southbound_disconnect(&ctx);

    if(initialized)
        southbound_clear(&ctx);

    fprintf(stdout, "[DMZ][SHUTDOWN] Clean exit\n");
    dmz_telemetry_event("opcua_dmz_stopped", "system_health", "info",
                        dmz_telemetry_raw("opcua_dmz_stopped"));

    influx_writer_cleanup();
    dmz_telemetry_cleanup();
    return EXIT_SUCCESS;
}
