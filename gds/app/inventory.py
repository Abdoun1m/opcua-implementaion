from __future__ import annotations

import logging
from pathlib import Path

from .cert_utils import parse_pem_certificate
from .config import Settings
from .db import insert_certificate, upsert_application


LOG = logging.getLogger("gds.inventory")


SEEDED_APPS = [
    {
        "application_uri": "urn:dataprotect:opcua:ot-server",
        "common_name": "PowerGridOPCUA",
        "zone": "OT",
        "role": "server",
        "host": "192.168.1.62",
        "port": 4840,
        "cert_path": "ot_server/server.pem",
    },
    {
        "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
        "common_name": "OpcUaDmzGatewayClient",
        "zone": "DMZ",
        "role": "southbound-client",
        "host": "192.168.10.20",
        "port": None,
        "cert_path": "dmz_gateway_client/client.pem",
    },
    {
        "application_uri": "urn:dataprotect:opcua:dmz-gateway-server",
        "common_name": "OpcUaDmzGatewayServer",
        "zone": "DMZ",
        "role": "northbound-server",
        "host": "192.168.10.20",
        "port": 4841,
        "cert_path": "dmz_gateway_server/server.pem",
    },
    {
        "application_uri": "urn:dataprotect:opcua:fuxa-client",
        "common_name": "FuxaClient",
        "zone": "OT",
        "role": "scada-client",
        "host": "192.168.1.60",
        "port": None,
        "cert_path": "fuxa_client/client.pem",
    },
]


def seed_and_import(settings: Settings) -> None:
    root = Path(settings.fallback_shared_pki_root)
    for app in SEEDED_APPS:
        row = upsert_application(
            settings=settings,
            application_uri=app["application_uri"],
            common_name=app["common_name"],
            zone=app["zone"],
            role=app["role"],
            host=app["host"],
            port=app["port"],
            status="active",
        )
        cert_file = root / app["cert_path"]
        if not cert_file.exists():
            LOG.info("fallback certificate not found path=%s", cert_file)
            continue
        try:
            parsed = parse_pem_certificate(cert_file.read_text(encoding="utf-8"))
            inserted = insert_certificate(
                settings=settings,
                application_id=row["id"],
                fingerprint_sha256=parsed["fingerprint_sha256"],
                serial_number=parsed["serial_number"],
                subject=parsed["subject"],
                issuer=parsed["issuer"],
                not_before=parsed["not_before"],
                not_after=parsed["not_after"],
                pem=parsed["pem"],
                status="active",
            )
            if inserted:
                LOG.info("imported fallback certificate app_uri=%s path=%s", app["application_uri"], cert_file)
            else:
                LOG.info("fallback certificate already imported app_uri=%s path=%s", app["application_uri"], cert_file)
        except Exception as exc:
            LOG.error("failed to import fallback certificate app_uri=%s path=%s err=%s", app["application_uri"], cert_file, exc)
