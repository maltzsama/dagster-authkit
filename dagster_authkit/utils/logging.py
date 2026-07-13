import logging

from dagster_authkit.utils.config import config


def setup_logging():
    """
    Configure the ``dagster_authkit`` logger from ``AuthConfig.LOG_LEVEL``.

    Sets up basic stdout logging with timestamp, level, logger name,
    and message format.

    Returns:
        ``logging.Logger`` instance named ``dagster_authkit``.
    """
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger = logging.getLogger("dagster_authkit")
    logger.setLevel(log_level)
    return logger
