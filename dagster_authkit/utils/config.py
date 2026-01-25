"""Configuration management for authentication system."""

import os
import secrets


class AuthConfig:
    """Centralized configuration for the authentication system."""

    def __init__(self):
        # Session settings
        self.SECRET_KEY = os.getenv("DAGSTER_AUTH_SECRET_KEY", self._generate_secret_key())
        self.SESSION_COOKIE_NAME = os.getenv("DAGSTER_AUTH_COOKIE_NAME", "dagster_session")
        self.SESSION_MAX_AGE = int(os.getenv("DAGSTER_AUTH_SESSION_MAX_AGE", "86400"))  # 24h
        self.SESSION_COOKIE_SECURE = (
            os.getenv("DAGSTER_AUTH_COOKIE_SECURE", "false").lower() == "true"
        )
        self.SESSION_COOKIE_HTTPONLY = True  # Always True for security
        self.SESSION_COOKIE_SAMESITE = os.getenv("DAGSTER_AUTH_COOKIE_SAMESITE", "lax")

        # Authentication backend
        self.AUTH_BACKEND = os.getenv("DAGSTER_AUTH_BACKEND", "dummy").lower()

        # Rate limiting
        self.RATE_LIMIT_ENABLED = os.getenv("DAGSTER_AUTH_RATE_LIMIT", "true").lower() == "true"
        self.RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("DAGSTER_AUTH_RATE_LIMIT_ATTEMPTS", "5"))
        self.RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DAGSTER_AUTH_RATE_LIMIT_WINDOW", "300"))

        # LDAP settings (for future implementation)
        self.LDAP_SERVER_URI = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
        self.LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")
        self.LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
        self.LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
        self.LDAP_USER_SEARCH_FILTER = os.getenv(
            "LDAP_USER_SEARCH_FILTER", "(sAMAccountName={username})"
        )
        self.LDAP_USE_TLS = os.getenv("LDAP_USE_TLS", "true").lower() == "true"

        # OAuth settings (for future implementation)
        self.OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
        self.OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
        self.OAUTH_AUTHORIZATION_URL = os.getenv("OAUTH_AUTHORIZATION_URL")
        self.OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL")
        self.OAUTH_USERINFO_URL = os.getenv("OAUTH_USERINFO_URL")

        # Admin Bootstrap (for Docker/K8s Infrastructure as Code)
        self.ADMIN_USER = os.getenv("DAGSTER_AUTH_ADMIN_USER", "")
        self.ADMIN_PASSWORD = os.getenv("DAGSTER_AUTH_ADMIN_PASSWORD", "")
        self.ADMIN_EMAIL = os.getenv("DAGSTER_AUTH_ADMIN_EMAIL", "")

        # Logging
        self.LOG_LEVEL = os.getenv("DAGSTER_AUTH_LOG_LEVEL", "INFO")
        self.AUDIT_LOG_ENABLED = os.getenv("DAGSTER_AUTH_AUDIT_LOG", "true").lower() == "true"

        self.DB_URL = os.getenv("DAGSTER_AUTH_DB_URL", "sqlite:///./dagster_auth.db")

        # Validate critical settings
        self._validate()

    def _generate_secret_key(self) -> str:
        """Generate a secure random secret key if not provided."""
        key = secrets.token_urlsafe(32)
        print(
            f"⚠️  WARNING: Using auto-generated secret key. Set DAGSTER_AUTH_SECRET_KEY in production!"
        )
        print(f"    Suggested value: {key}")
        return key

    def _validate(self):
        """Validate configuration settings."""
        if self.AUTH_BACKEND not in ["dummy", "ldap", "oauth", "saml", "sqlite"]:
            raise ValueError(
                f"Invalid AUTH_BACKEND: {self.AUTH_BACKEND}. "
                f"Must be one of: dummy, ldap, oauth, saml, sqlite"
            )

        if self.SESSION_MAX_AGE < 60:
            raise ValueError("SESSION_MAX_AGE must be at least 60 seconds")

        if len(self.SECRET_KEY) < 16:
            raise ValueError("SECRET_KEY must be at least 16 characters")

    def __repr__(self):
        """Safe representation hiding sensitive data."""
        return (
            f"<AuthConfig backend={self.AUTH_BACKEND} "
            f"session_max_age={self.SESSION_MAX_AGE}s "
            f"rate_limit={self.RATE_LIMIT_ENABLED}>"
        )


# Global config instance
config = AuthConfig()
