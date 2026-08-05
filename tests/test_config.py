"""
Unit tests for utils/config.py

Covers:
- AuthConfig initialization with environment variables
- Default values for all config fields
- Validation of AUTH_BACKEND, SESSION_MAX_AGE, SECRET_KEY, REDIS_URL
- Secret key auto-generation
- Sensitive data masking in __repr__
"""

import os

import pytest

from dagster_authkit.utils.config import AuthConfig, config


class TestAuthConfigDefaults:
    """Verifies default configuration values."""

    def test_default_auth_backend(self, monkeypatch):
        """Default AUTH_BACKEND should be 'sql' (factory default, no env set)."""
        monkeypatch.delenv("DAGSTER_AUTH_BACKEND", raising=False)
        cfg = AuthConfig()
        assert cfg.AUTH_BACKEND == "sql"

    def test_default_session_cookie_name(self):
        """Default session cookie name should be 'dagster_session'."""
        cfg = AuthConfig()
        assert cfg.SESSION_COOKIE_NAME == "dagster_session"

    def test_default_session_max_age(self):
        """Default session max age should be 86400 seconds (24h)."""
        cfg = AuthConfig()
        assert cfg.SESSION_MAX_AGE == 86400

    def test_default_unknown_mutation_role(self):
        """Default unknown mutation role should be ADMIN (deny-by-default)."""
        cfg = AuthConfig()
        assert cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE == "ADMIN"

    def test_unknown_mutation_role_from_env(self, monkeypatch):
        """Unknown mutation role should be configurable via env."""
        monkeypatch.setenv("DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE", "EDITOR")
        cfg = AuthConfig()
        assert cfg.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE == "EDITOR"

    def test_invalid_unknown_mutation_role_raises(self, monkeypatch):
        """An invalid role should raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE", "SUPERADMIN")
        with pytest.raises(ValueError, match="DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE"):
            AuthConfig()

    def test_default_proxy_trusted_ips(self):
        """Default trusted IPs should be an empty frozenset (all IPs trusted)."""
        cfg = AuthConfig()
        assert cfg.DAGSTER_AUTH_PROXY_TRUSTED_IPS == frozenset()

    def test_proxy_trusted_ips_from_env(self, monkeypatch):
        """Trusted IPs should be parsed from comma/space-separated env var."""
        monkeypatch.setenv("DAGSTER_AUTH_PROXY_TRUSTED_IPS", "10.0.0.1, 10.0.0.2")
        cfg = AuthConfig()
        assert cfg.DAGSTER_AUTH_PROXY_TRUSTED_IPS == frozenset({"10.0.0.1", "10.0.0.2"})

    def test_default_rate_limit_settings(self):
        """Rate limiting should be enabled by default with 5 attempts / 300s."""
        cfg = AuthConfig()
        assert cfg.RATE_LIMIT_ENABLED is True
        assert cfg.RATE_LIMIT_MAX_ATTEMPTS == 5
        assert cfg.RATE_LIMIT_WINDOW_SECONDS == 300

    def test_default_log_level(self):
        """Default log level should be INFO."""
        cfg = AuthConfig()
        assert cfg.LOG_LEVEL == "INFO"

    def test_default_proxy_headers(self):
        """Proxy headers should have sensible defaults."""
        cfg = AuthConfig()
        assert cfg.DAGSTER_AUTH_PROXY_USER_HEADER == "Remote-User"
        assert cfg.DAGSTER_AUTH_PROXY_GROUPS_HEADER == "Remote-Groups"

    def test_session_cookie_httponly_always_true(self):
        """SESSION_COOKIE_HTTPONLY should always be True for security."""
        cfg = AuthConfig()
        assert cfg.SESSION_COOKIE_HTTPONLY is True


class TestAuthConfigValidation:
    """Verifies config validation rules."""

    def test_invalid_auth_backend_raises(self, monkeypatch):
        """An invalid AUTH_BACKEND should raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_BACKEND", "invalid_backend")
        with pytest.raises(ValueError, match="Invalid AUTH_BACKEND"):
            AuthConfig()

    @pytest.mark.parametrize("backend", ["dummy", "ldap", "sqlite", "sql", "proxy"])
    def test_valid_auth_backends(self, monkeypatch, backend):
        """All valid backend names should be accepted."""
        monkeypatch.setenv("DAGSTER_AUTH_BACKEND", backend)
        if backend == "proxy":
            monkeypatch.setenv("DAGSTER_AUTH_PROXY_TRUSTED_IPS", "10.0.0.1")
        cfg = AuthConfig()
        assert cfg.AUTH_BACKEND == backend

    def test_session_max_age_too_low_raises(self, monkeypatch):
        """SESSION_MAX_AGE below 60 should raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_SESSION_MAX_AGE", "30")
        with pytest.raises(ValueError, match="SESSION_MAX_AGE"):
            AuthConfig()

    def test_secret_key_too_short_raises(self, monkeypatch):
        """SECRET_KEY shorter than 16 chars should raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_SECRET_KEY", "short")
        with pytest.raises(ValueError, match="SECRET_KEY"):
            AuthConfig()

    def test_invalid_redis_url_raises(self, monkeypatch):
        """An invalid REDIS_URL format should raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_REDIS_URL", "invalid://redis")
        with pytest.raises(ValueError, match="REDIS_URL"):
            AuthConfig()

    def test_valid_redis_url_accepted(self, monkeypatch):
        """A valid redis:// URL should be accepted."""
        monkeypatch.setenv("DAGSTER_AUTH_REDIS_URL", "redis://localhost:6379")
        cfg = AuthConfig()
        assert cfg.REDIS_URL == "redis://localhost:6379"

    def test_valid_rediss_url_accepted(self, monkeypatch):
        """A valid rediss:// (TLS) URL should be accepted."""
        monkeypatch.setenv("DAGSTER_AUTH_REDIS_URL", "rediss://localhost:6380")
        cfg = AuthConfig()
        assert cfg.REDIS_URL == "rediss://localhost:6380"


class TestAuthConfigSecretKey:
    """Verifies SECRET_KEY auto-generation and logging."""

    def test_warning_logged_when_secret_key_missing(self, monkeypatch, caplog):
        """Without SECRET_KEY in dev, a warning must be logged (not printed)."""
        monkeypatch.setenv("DAGSTER_AUTH_ENV", "development")
        monkeypatch.delenv("DAGSTER_AUTH_SECRET_KEY", raising=False)
        with caplog.at_level("WARNING"):
            cfg = AuthConfig()
        assert any(
            "auto-generated SECRET_KEY" in msg for msg in caplog.messages
        ), "Warning about auto-generated key must be logged"

    def test_secret_key_not_in_log(self, monkeypatch, caplog):
        """The generated key must not appear in log output."""
        monkeypatch.setenv("DAGSTER_AUTH_ENV", "development")
        monkeypatch.delenv("DAGSTER_AUTH_SECRET_KEY", raising=False)
        with caplog.at_level("WARNING"):
            cfg = AuthConfig()
        for msg in caplog.messages:
            assert cfg.SECRET_KEY not in msg, (
                "SECRET_KEY value must not appear in log"
            )

    def test_production_raises_without_secret_key(self, monkeypatch):
        """In production, missing SECRET_KEY must raise ValueError."""
        monkeypatch.setenv("DAGSTER_AUTH_ENV", "production")
        monkeypatch.delenv("DAGSTER_AUTH_SECRET_KEY", raising=False)
        with pytest.raises(ValueError, match="SECRET_KEY"):
            AuthConfig()


class TestAuthConfigFromEnv:
    """Verifies environment variable overrides."""

    def test_auth_backend_from_env(self, monkeypatch):
        """AUTH_BACKEND should be read from DAGSTER_AUTH_BACKEND env var."""
        monkeypatch.setenv("DAGSTER_AUTH_BACKEND", "dummy")
        cfg = AuthConfig()
        assert cfg.AUTH_BACKEND == "dummy"

    def test_session_max_age_from_env(self, monkeypatch):
        """SESSION_MAX_AGE should be read from env and converted to int."""
        monkeypatch.setenv("DAGSTER_AUTH_SESSION_MAX_AGE", "7200")
        cfg = AuthConfig()
        assert cfg.SESSION_MAX_AGE == 7200

    def test_rate_limit_disabled_from_env(self, monkeypatch):
        """Setting RATE_LIMIT to 'false' should disable it."""
        monkeypatch.setenv("DAGSTER_AUTH_RATE_LIMIT", "false")
        cfg = AuthConfig()
        assert cfg.RATE_LIMIT_ENABLED is False

    def test_env_setting(self, monkeypatch):
        """ENV should be read from DAGSTER_AUTH_ENV."""
        monkeypatch.setenv("DAGSTER_AUTH_ENV", "staging")
        cfg = AuthConfig()
        assert cfg.ENV == "staging"

    def test_admin_password_from_env(self, monkeypatch):
        """ADMIN_PASSWORD should be read from DAGSTER_AUTH_ADMIN_PASSWORD."""
        monkeypatch.setenv("DAGSTER_AUTH_ADMIN_PASSWORD", "secret123")
        cfg = AuthConfig()
        assert cfg.ADMIN_PASSWORD == "secret123"

    def test_admin_user_default(self):
        """ADMIN_USER should default to 'admin'."""
        cfg = AuthConfig()
        assert cfg.ADMIN_USER == "admin"

    def test_admin_user_from_env(self, monkeypatch):
        """ADMIN_USER should be read from DAGSTER_AUTH_ADMIN_USER."""
        monkeypatch.setenv("DAGSTER_AUTH_ADMIN_USER", "root")
        cfg = AuthConfig()
        assert cfg.ADMIN_USER == "root"


class TestAuthConfigRepr:
    """Verifies safe string representation."""

    def test_repr_masks_secrets(self):
        """__repr__ should not expose sensitive information."""
        cfg = AuthConfig()
        rep = repr(cfg)
        assert "SECRET_KEY" not in rep
        assert "PASSWORD" not in rep


class TestGlobalConfig:
    """Verifies the global config singleton."""

    def test_config_is_auth_config_instance(self):
        """The global 'config' should be an AuthConfig instance."""
        assert isinstance(config, AuthConfig)

    def test_config_has_expected_attributes(self):
        """Config should have all expected attributes."""
        expected = [
            "AUTH_BACKEND",
            "SECRET_KEY",
            "SESSION_COOKIE_NAME",
            "SESSION_MAX_AGE",
            "RATE_LIMIT_ENABLED",
            "ENV",
            "LOG_LEVEL",
        ]
        for attr in expected:
            assert hasattr(config, attr), f"Missing config attribute: {attr}"
