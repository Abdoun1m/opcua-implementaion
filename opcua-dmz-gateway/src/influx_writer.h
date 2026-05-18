#ifndef INFLUX_WRITER_H
#define INFLUX_WRITER_H

#include <stddef.h>

int influx_writer_init(const char *host, int port,
                       const char *org, const char *bucket,
                       const char *token);

int influx_writer_write_line(const char *line_protocol);
int influx_writer_write_batch(const char *payload);

void influx_writer_cleanup(void);

void influx_sanitize_label(const char *input, char *output, size_t outSize);
void influx_escape_tag_value(const char *input, char *output, size_t outSize);
void influx_escape_string_field(const char *input, char *output, size_t outSize);

void influx_writer_print_stats(void);

#endif
