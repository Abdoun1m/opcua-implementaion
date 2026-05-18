#ifndef NORTHBOUND_SERVER_H
#define NORTHBOUND_SERVER_H

#include <open62541/server.h>

int northbound_init(void);
void northbound_run_iterate(void);

#endif
