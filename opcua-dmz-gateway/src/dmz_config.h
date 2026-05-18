#ifndef DMZ_CONFIG_H
#define DMZ_CONFIG_H

#define DEFAULT_OT_ENDPOINT_URL "opc.tcp://192.168.1.62:4840"
#define DEFAULT_OT_USERNAME     "historian"
#define DEFAULT_OT_PASSWORD     "ChangeMe_Historian!"

#define POWERGRID_NS_URI "http://dataprotect.ma/opcua/powergrid"

#define SOUTHBOUND_CERT_PATH "/app/pki/southbound/own/certs/client.der"
#define SOUTHBOUND_KEY_PATH  "/app/pki/southbound/own/private/client.key.der"

#define POLL_INTERVAL_MS 1000

#endif
