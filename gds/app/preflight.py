import logging
import sys
import time

from .checks import check_config_files, check_postgres, check_vault
from .config import load_settings
from .logging_json import configure_logging


def _ok_or_fail(name: str, result: dict) -> bool:
    logger = logging.getLogger("gds.preflight")
    if result["ok"]:
        logger.info("%s check ok: %s", name, result["detail"])
        return True
    logger.error("%s check failed: %s", name, result["detail"])
    return False


def main() -> int:
    configure_logging()
    settings = load_settings()
    logger = logging.getLogger("gds.preflight")
    logger.info("starting preflight")

    retries = settings.startup_retries
    sleep_seconds = settings.startup_retry_seconds

    for attempt in range(1, retries + 1):
        config_ok = _ok_or_fail("config_files", check_config_files(settings))
        pg_ok = _ok_or_fail("postgres", check_postgres(settings))
        vault_ok = _ok_or_fail("vault", check_vault(settings))

        if config_ok and pg_ok and vault_ok:
            logger.info("preflight completed")
            return 0

        logger.warning("preflight attempt %s/%s failed, retrying in %ss", attempt, retries, sleep_seconds)
        time.sleep(sleep_seconds)

    logger.error("preflight failed after %s attempts", retries)
    return 1


if __name__ == "__main__":
    sys.exit(main())
