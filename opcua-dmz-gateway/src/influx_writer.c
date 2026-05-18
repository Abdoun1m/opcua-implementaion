#include "influx_writer.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>

#define INFLUX_URL_SIZE        512
#define INFLUX_AUTH_SIZE       512
#define INFLUX_ERR_SIZE        512
#define INFLUX_MAX_RETRIES     3
#define INFLUX_TIMEOUT_SEC     5L
#define INFLUX_CONNECT_SEC     2L

static char influx_url[INFLUX_URL_SIZE];
static char auth_header[INFLUX_AUTH_SIZE];

static unsigned long write_ok_count = 0;
static unsigned long write_fail_count = 0;
static unsigned long batch_ok_count = 0;
static unsigned long batch_fail_count = 0;

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int influx_http_post(const char *payload, const char *mode) {
    if(!payload || payload[0] == '\0')
        return 0;

    for(int attempt = 1; attempt <= INFLUX_MAX_RETRIES; attempt++) {
        CURL *curl = curl_easy_init();
        if(!curl) {
            fprintf(stderr, "[INFLUX][%s] curl_easy_init failed\n", mode);
            return 0;
        }

        char errbuf[INFLUX_ERR_SIZE];
        memset(errbuf, 0, sizeof(errbuf));

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Content-Type: text/plain; charset=utf-8");
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, influx_url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, INFLUX_TIMEOUT_SEC);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, INFLUX_CONNECT_SEC);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        CURLcode res = curl_easy_perform(curl);

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if(res == CURLE_OK && (http_code == 204 || http_code == 200)) {
            fprintf(stdout, "[INFLUX][%s] Write OK attempt=%d http=%ld\n",
                    mode, attempt, http_code);
            return 1;
        }

        fprintf(stderr,
                "[INFLUX][%s] Write failed attempt=%d/%d curl=%d http=%ld err=%s\n",
                mode,
                attempt,
                INFLUX_MAX_RETRIES,
                res,
                http_code,
                errbuf[0] ? errbuf : curl_easy_strerror(res));

        if(attempt < INFLUX_MAX_RETRIES)
            sleep_ms(200L * attempt);
    }

    fprintf(stderr, "[INFLUX][%s] Final failure. Payload:\n%s\n", mode, payload);
    return 0;
}

int influx_writer_init(const char *host, int port,
                       const char *org, const char *bucket,
                       const char *token) {
    if(!host || !org || !bucket || !token) {
        fprintf(stderr, "[INFLUX] Missing configuration\n");
        return 0;
    }

    if(host[0] == '\0' || org[0] == '\0' || bucket[0] == '\0' || token[0] == '\0') {
        fprintf(stderr, "[INFLUX] Empty configuration value\n");
        return 0;
    }

    snprintf(influx_url, sizeof(influx_url),
             "http://%s:%d/api/v2/write?org=%s&bucket=%s&precision=s",
             host, port, org, bucket);

    snprintf(auth_header, sizeof(auth_header),
             "Authorization: Token %s", token);

    if(curl_global_init(CURL_GLOBAL_ALL) != 0) {
        fprintf(stderr, "[INFLUX] curl_global_init failed\n");
        return 0;
    }

    fprintf(stdout, "[INFLUX] Initialized URL=%s\n", influx_url);
    fprintf(stdout, "[INFLUX] Policy timeout=%lds connect=%lds retries=%d\n",
            INFLUX_TIMEOUT_SEC,
            INFLUX_CONNECT_SEC,
            INFLUX_MAX_RETRIES);

    return 1;
}

int influx_writer_write_line(const char *line_protocol) {
    int ok = influx_http_post(line_protocol, "single");

    if(ok)
        write_ok_count++;
    else
        write_fail_count++;

    return ok;
}

int influx_writer_write_batch(const char *payload) {
    int ok = influx_http_post(payload, "batch");

    if(ok)
        batch_ok_count++;
    else
        batch_fail_count++;

    return ok;
}

void influx_writer_cleanup(void) {
    fprintf(stdout,
            "[INFLUX] Cleanup stats: single_ok=%lu single_fail=%lu batch_ok=%lu batch_fail=%lu\n",
            write_ok_count,
            write_fail_count,
            batch_ok_count,
            batch_fail_count);

    curl_global_cleanup();
}

/*
 * Safe tag/measurement sanitizer.
 * Keeps only: A-Z a-z 0-9 _ - .
 */
void influx_sanitize_label(const char *input, char *output, size_t outSize) {
    if(!input || !output || outSize == 0)
        return;

    size_t j = 0;

    for(size_t i = 0; input[i] != '\0' && j < outSize - 1; i++) {
        unsigned char c = (unsigned char)input[i];

        if(isalnum(c) || c == '_' || c == '-' || c == '.') {
            output[j++] = (char)c;
        } else {
            output[j++] = '_';
        }
    }

    output[j] = '\0';
}

/*
 * Escape Influx tag value characters:
 * comma, space, equals.
 */
void influx_escape_tag_value(const char *input, char *output, size_t outSize) {
    if(!input || !output || outSize == 0)
        return;

    size_t j = 0;

    for(size_t i = 0; input[i] != '\0' && j < outSize - 1; i++) {
        char c = input[i];

        if((c == ',' || c == ' ' || c == '=') && j < outSize - 2) {
            output[j++] = '\\';
            output[j++] = c;
        } else {
            output[j++] = c;
        }
    }

    output[j] = '\0';
}

/*
 * Escape Influx string field values:
 * quote and backslash.
 */
void influx_escape_string_field(const char *input, char *output, size_t outSize) {
    if(!input || !output || outSize == 0)
        return;

    size_t j = 0;

    for(size_t i = 0; input[i] != '\0' && j < outSize - 1; i++) {
        char c = input[i];

        if((c == '"' || c == '\\') && j < outSize - 2) {
            output[j++] = '\\';
            output[j++] = c;
        } else {
            output[j++] = c;
        }
    }

    output[j] = '\0';
}

void influx_writer_print_stats(void) {
    fprintf(stdout,
            "[INFLUX] Stats: single_ok=%lu single_fail=%lu batch_ok=%lu batch_fail=%lu\n",
            write_ok_count,
            write_fail_count,
            batch_ok_count,
            batch_fail_count);
}
