"""
Configuration management for authentication system.
Maintains placeholders for LDAP/OAuth while enabling Peewee SQL and Redis Sessions.
"""

import os
import secrets


class AuthConfig:
    """Centralized configuration for the authentication system."""

    def __init__(self):
        # Environment metadata for Audit Logging
        self.ENV = os.getenv("DAGSTER_AUTH_ENV", "production")

        # Session settings
        self.SECRET_KEY = os.getenv("DAGSTER_AUTH_SECRET_KEY", self._generate_secret_key())
        self.SESSION_COOKIE_NAME = os.getenv("DAGSTER_AUTH_COOKIE_NAME", "dagster_session")
        self.SESSION_MAX_AGE = int(os.getenv("DAGSTER_AUTH_SESSION_MAX_AGE", "86400"))  # 24h
        self.SESSION_COOKIE_SECURE = (
            os.getenv("DAGSTER_AUTH_COOKIE_SECURE", "false").lower() == "true"
        )
        self.SESSION_COOKIE_HTTPONLY = True  # Always True for security
        self.SESSION_COOKIE_SAMESITE = os.getenv("DAGSTER_AUTH_COOKIE_SAMESITE", "lax")

        # --- Redis Configuration (Stateful Sessions) ---
        self.REDIS_URL = os.getenv("DAGSTER_AUTH_REDIS_URL")

        # Authentication backend
        self.AUTH_BACKEND = os.getenv("DAGSTER_AUTH_BACKEND", "sql").lower()

        # --- Database Configuration (Peewee SQL) ---
        # We keep DAGSTER_AUTH_DB for compatibility, but prefer the URL DSN
        self.DAGSTER_AUTH_DB = os.getenv("DAGSTER_AUTH_DB", "./dagster_auth.db")
        self.DAGSTER_AUTH_DATABASE_URL = os.getenv(
            "DAGSTER_AUTH_DATABASE_URL", f"sqlite:///{self.DAGSTER_AUTH_DB}"
        )

        # UI Injection Settings
        self.UI_DEBUG = os.getenv("DAGSTER_AUTH_DEBUG", "false").lower() == "true"
        self.UI_SAFE_MODE = os.getenv("DAGSTER_AUTH_UI_SAFE_MODE", "true").lower() == "true"

        # Rate limiting
        self.RATE_LIMIT_ENABLED = os.getenv("DAGSTER_AUTH_RATE_LIMIT", "true").lower() == "true"
        self.RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("DAGSTER_AUTH_RATE_LIMIT_ATTEMPTS", "5"))
        self.RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DAGSTER_AUTH_RATE_LIMIT_WINDOW", "300"))

        # LDAP settings
        self.DAGSTER_AUTH_LDAP_SERVER = os.getenv("DAGSTER_AUTH_LDAP_SERVER")
        self.DAGSTER_AUTH_LDAP_BASE_DN = os.getenv("DAGSTER_AUTH_LDAP_BASE_DN")
        self.DAGSTER_AUTH_LDAP_BIND_DN = os.getenv("DAGSTER_AUTH_LDAP_BIND_DN")
        self.DAGSTER_AUTH_LDAP_BIND_PASSWORD = os.getenv("DAGSTER_AUTH_LDAP_BIND_PASSWORD")
        self.DAGSTER_AUTH_LDAP_USER_FILTER = os.getenv(
            "DAGSTER_AUTH_LDAP_USER_FILTER", "(uid={username})"
        )
        self.DAGSTER_AUTH_LDAP_USE_TLS = (
            str(os.getenv("DAGSTER_AUTH_LDAP_USE_TLS", "false")).lower() == "true"
        )
        self.DAGSTER_AUTH_LDAP_CA_CERT = os.getenv("DAGSTER_AUTH_LDAP_CA_CERT")
        self.DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE = os.getenv("DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE")
        self.DAGSTER_AUTH_LDAP_GROUP_PATTERN = os.getenv("DAGSTER_AUTH_LDAP_GROUP_PATTERN")

        # OAuth settings (Maintained)
        self.OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
        self.OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
        self.OAUTH_AUTHORIZATION_URL = os.getenv("OAUTH_AUTHORIZATION_URL")
        self.OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL")
        self.OAUTH_USERINFO_URL = os.getenv("OAUTH_USERINFO_URL")

        # Admin Bootstrap (Used by SQL Backend)
        self.ADMIN_PASSWORD = os.getenv("DAGSTER_AUTH_ADMIN_PASSWORD", "")

        # Logging and Audit
        self.LOG_LEVEL = os.getenv("DAGSTER_AUTH_LOG_LEVEL", "INFO")
        self.AUDIT_LOG_ENABLED = os.getenv("DAGSTER_AUTH_AUDIT_LOG", "true").lower() == "true"

        # Validate critical settings
        self._validate()

    @staticmethod
    def _generate_secret_key() -> str:
        """Generate a secure random secret key if not provided."""
        key = secrets.token_urlsafe(32)
        print(f"⚠️  WARNING: Using auto-generated secret key. Set DAGSTER_AUTH_SECRET_KEY!")
        print(f"    Suggested value: {key}")
        return key

    def _validate(self):
        """Validate configuration settings with support for the new SQL backend."""
        valid_backends = ["dummy", "ldap", "oauth", "sqlite", "sql"]
        if self.AUTH_BACKEND not in valid_backends:
            raise ValueError(
                f"Invalid AUTH_BACKEND: {self.AUTH_BACKEND}. "
                f"Must be one of: {', '.join(valid_backends)}"
            )

        if self.SESSION_MAX_AGE < 60:
            raise ValueError("SESSION_MAX_AGE must be at least 60 seconds")

        if len(self.SECRET_KEY) < 16:
            raise ValueError("SECRET_KEY must be at least 16 characters")

    def __repr__(self):
        """Safe representation hiding sensitive data."""
        return (
            f"<AuthConfig backend={self.AUTH_BACKEND} "
            f"env={self.ENV} "
            f"redis={'enabled' if self.REDIS_URL else 'disabled'} "
            f"rate_limit={self.RATE_LIMIT_ENABLED}>"
        )


# Global config instance
config = AuthConfig()
