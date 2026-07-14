"""
Unit tests for utils/logging.py

Covers:
- setup_logging returns a logger
- setup_logging respects LOG_LEVEL from config
"""

import logging

import pytest

from dagster_authkit.utils.logging import setup_logging


class TestSetupLogging:
    """Verifies logging setup function."""

    def test_returns_logger(self):
        """setup_logging should return a Logger instance."""
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)

    def test_logger_name_is_dagster_authkit(self):
        """Returned logger should be named 'dagster_authkit'."""
        logger = setup_logging()
        assert logger.name == "dagster_authkit"

    def test_log_level_defaults_to_info(self):
        """Default LOG_LEVEL should be INFO."""
        logger = setup_logging()
        assert logger.level == logging.INFO

    def test_respects_config_log_level(self, monkeypatch):
        """LOG_LEVEL from config should be applied."""
        monkeypatch.setenv("DAGSTER_AUTH_LOG_LEVEL", "DEBUG")
        from importlib import reload
        from dagster_authkit.utils import config
        reload(config)
        from dagster_authkit.utils import logging as log_mod
        reload(log_mod)
        from dagster_authkit.utils.logging import setup_logging
        logger = setup_logging()
        assert logger.level == logging.DEBUG
