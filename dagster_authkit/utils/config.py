"""
Configuration management for authentication system.
Maintains placeholders for LDAP/OAuth while enabling Peewee SQL and Redis Sessions.
"""

import logging
import os
import secrets

logger = logging.getLogger(__name__)


class AuthConfig:
    """Centralized configuration for the authentication system."""

    def __init__(self):
        """
        Initialise authentication configuration from environment variables.

        **Session settings:**
            ``DAGSTER_AUTH_SECRET_KEY``            Required in production. Signing secret.
            ``DAGSTER_AUTH_COOKIE_NAME``           Default: ``dagster_session``
            ``DAGSTER_AUTH_SESSION_MAX_AGE``       Default: ``86400`` (24h, seconds)
            ``DAGSTER_AUTH_COOKIE_SECURE``         Default: ``true``
            ``DAGSTER_AUTH_COOKIE_SAMESITE``       Default: ``lax``

        **Backend selection:**
            ``DAGSTER_AUTH_BACKEND``               Default: ``sql``
                                                   One of: dummy, ldap, oauth, sqlite, sql, proxy

        **Redis (distributed sessions & rate limiting):**
            ``DAGSTER_AUTH_REDIS_URL``             Optional. Enables Redis backend.

        **Database (Peewee SQL):**
            ``DAGSTER_AUTH_DB``                    Default: ``./dagster_auth.db``
            ``DAGSTER_AUTH_DATABASE_URL``          DSN, auto-derived from above

        **Rate limiting:**
            ``DAGSTER_AUTH_RATE_LIMIT``            Default: ``true``
            ``DAGSTER_AUTH_RATE_LIMIT_ATTEMPTS``   Default: ``5``
            ``DAGSTER_AUTH_RATE_LIMIT_WINDOW``     Default: ``300`` (seconds)

        **LDAP (when backend=ldap):**
            ``DAGSTER_AUTH_LDAP_SERVER``, ``DAGSTER_AUTH_LDAP_BASE_DN``,
            ``DAGSTER_AUTH_LDAP_BIND_DN``, ``DAGSTER_AUTH_LDAP_BIND_PASSWORD``,
            ``DAGSTER_AUTH_LDAP_USER_FILTER``      Default: ``(uid={username})``
            ``DAGSTER_AUTH_LDAP_USE_TLS``          Default: ``false``
            ``DAGSTER_AUTH_LDAP_CA_CERT``, ``DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE``,
            ``DAGSTER_AUTH_LDAP_GROUP_PATTERN``,
            ``DAGSTER_AUTH_LDAP_TIMEOUT``          Default: ``10`` (seconds)

        **Proxy auth (when backend=proxy):**
            ``DAGSTER_AUTH_PROXY_USER_HEADER``     Default: ``Remote-User``
            ``DAGSTER_AUTH_PROXY_GROUPS_HEADER``   Default: ``Remote-Groups``
            ``DAGSTER_AUTH_PROXY_EMAIL_HEADER``    Default: ``Remote-Email``
            ``DAGSTER_AUTH_PROXY_NAME_HEADER``     Default: ``Remote-Name``
            ``DAGSTER_AUTH_PROXY_GROUP_PATTERN``   LDAP DN pattern for role mapping
            ``DAGSTER_AUTH_PROXY_LOGOUT_URL``      Default: ``https://auth.company.com/logout``
            ``DAGSTER_AUTH_PROXY_TRUSTED_IPS``     Required (space/comma-separated)
            ``DAGSTER_AUTH_PROXY_TRUST_ALL``       Default: ``false`` — opt-in insecure

        **RBAC:**
            ``DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE`` Default: ``ADMIN`` — deny-by-default
            ``DAGSTER_AUTH_REST_WRITE_ROLE``       Default: ``EDITOR``

        **Bootstrap:**
            ``DAGSTER_AUTH_ADMIN_USER``            Default: ``admin``. Admin username
            ``DAGSTER_AUTH_ADMIN_PASSWORD``        Auto-creates admin on first run

        **Logging:**
            ``DAGSTER_AUTH_ENV``                   Default: ``production``
            ``DAGSTER_AUTH_LOG_LEVEL``             Default: ``INFO``
            ``DAGSTER_AUTH_AUDIT_LOG``             Default: ``true``

        Raises:
            ValueError: If any setting is invalid or a required value is missing.
        """
        # Environment metadata for Audit Logging
        self.ENV = os.getenv("DAGSTER_AUTH_ENV", "production")

        # Session settings
        self.SECRET_KEY = os.getenv("DAGSTER_AUTH_SECRET_KEY")
        if not self.SECRET_KEY:
            if self.ENV == "production":
                raise ValueError(
                    "DAGSTER_AUTH_SECRET_KEY is required in production.\n"
                    "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'\n"
                    "Auto-generated keys cause session invalidation across pod restarts and "
                    "in multi-pod deployments."
                )
            self.SECRET_KEY = secrets.token_urlsafe(32)
            logger.warning(
                "Using auto-generated SECRET_KEY in non-production mode. "
                "Set DAGSTER_AUTH_SECRET_KEY to a persistent value."
            )
        self.SESSION_COOKIE_NAME = os.getenv("DAGSTER_AUTH_COOKIE_NAME", "dagster_session")
        self.SESSION_MAX_AGE = int(os.getenv("DAGSTER_AUTH_SESSION_MAX_AGE", "86400"))  # 24h
        self.SESSION_COOKIE_SECURE = (
            os.getenv("DAGSTER_AUTH_COOKIE_SECURE", "true").lower() == "true"
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

        # PROXY AUTH SETTINGS (Authelia Forward Auth)
        self.DAGSTER_AUTH_PROXY_USER_HEADER = os.getenv(
            "DAGSTER_AUTH_PROXY_USER_HEADER", "Remote-User"
        )
        self.DAGSTER_AUTH_PROXY_GROUPS_HEADER = os.getenv(
            "DAGSTER_AUTH_PROXY_GROUPS_HEADER", "Remote-Groups"
        )
        self.DAGSTER_AUTH_PROXY_EMAIL_HEADER = os.getenv(
            "DAGSTER_AUTH_PROXY_EMAIL_HEADER", "Remote-Email"
        )
        self.DAGSTER_AUTH_PROXY_NAME_HEADER = os.getenv(
            "DAGSTER_AUTH_PROXY_NAME_HEADER", "Remote-Name"
        )
        self.DAGSTER_AUTH_PROXY_GROUP_PATTERN = os.getenv("DAGSTER_AUTH_PROXY_GROUP_PATTERN")

        self.DAGSTER_AUTH_PROXY_LOGOUT_URL = os.getenv(
            "DAGSTER_AUTH_PROXY_LOGOUT_URL", "https://auth.company.com/logout"
        )

        # Trusted proxy IPs (space/comma-separated). If empty and proxy mode
        # is active, the boot fails unless DAGSTER_AUTH_PROXY_TRUST_ALL=true
        # is explicitly set (opt-in to the insecure default).
        raw_ips = os.getenv("DAGSTER_AUTH_PROXY_TRUSTED_IPS", "")
        self.DAGSTER_AUTH_PROXY_TRUSTED_IPS = frozenset(
            ip.strip() for ip in raw_ips.replace(",", " ").split() if ip.strip()
        )
        self.DAGSTER_AUTH_PROXY_TRUST_ALL = (
            os.getenv("DAGSTER_AUTH_PROXY_TRUST_ALL", "false").lower() == "true"
        )

        # RBAC: role required for GraphQL mutations not in any explicit list.
        # Default: ADMIN (deny-by-default). Set to "VIEWER" for open-by-default.
        raw_unknown_role = os.getenv("DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE", "ADMIN").upper()
        valid_roles = {"VIEWER", "LAUNCHER", "EDITOR", "ADMIN"}
        if raw_unknown_role not in valid_roles:
            raise ValueError(
                f"Invalid DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE: {raw_unknown_role}. "
                f"Must be one of: {', '.join(sorted(valid_roles))}"
            )
        self.DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE = raw_unknown_role

        # RBAC: minimum role for non-GraphQL REST write requests (POST/PUT/DELETE/PATCH).
        # Default: EDITOR. REST writes are typically administrative operations
        # (user management, config changes). GraphQL mutations have per-operation RBAC.
        raw_rest_role = os.getenv("DAGSTER_AUTH_REST_WRITE_ROLE", "EDITOR").upper()
        if raw_rest_role not in valid_roles:
            raise ValueError(
                f"Invalid DAGSTER_AUTH_REST_WRITE_ROLE: {raw_rest_role}. "
                f"Must be one of: {', '.join(sorted(valid_roles))}"
            )
        self.DAGSTER_AUTH_REST_WRITE_ROLE = raw_rest_role

        # Admin Bootstrap (Used by SQL Backend)
        self.ADMIN_USER = os.getenv("DAGSTER_AUTH_ADMIN_USER", "admin")
        self.ADMIN_PASSWORD = os.getenv("DAGSTER_AUTH_ADMIN_PASSWORD", "")

        # Logging and Audit
        self.LOG_LEVEL = os.getenv("DAGSTER_AUTH_LOG_LEVEL", "INFO")
        self.AUDIT_LOG_ENABLED = os.getenv("DAGSTER_AUTH_AUDIT_LOG", "true").lower() == "true"

        # Validate critical settings
        self._validate()

    def _validate(self):
        """Validate configuration settings with support for the new SQL backend."""
        valid_backends = ["dummy", "ldap", "oauth", "sqlite", "sql", "proxy"]
        if self.AUTH_BACKEND not in valid_backends:
            raise ValueError(
                f"Invalid AUTH_BACKEND: {self.AUTH_BACKEND}. "
                f"Must be one of: {', '.join(valid_backends)}"
            )

        if self.AUTH_BACKEND == "proxy":
            if not self.DAGSTER_AUTH_PROXY_TRUSTED_IPS and not self.DAGSTER_AUTH_PROXY_TRUST_ALL:
                raise ValueError(
                    "DAGSTER_AUTH_BACKEND=proxy requires DAGSTER_AUTH_PROXY_TRUSTED_IPS "
                    "to be set. Any caller that can reach this pod can spoof proxy auth "
                    "headers and gain admin access. Set DAGSTER_AUTH_PROXY_TRUST_ALL=true "
                    "only if you fully understand the risk (e.g. NetworkPolicy restricts "
                    "access to the proxy only)."
                )

        if self.SESSION_MAX_AGE < 60:
            raise ValueError("SESSION_MAX_AGE must be at least 60 seconds")

        if len(self.SECRET_KEY) < 16:
            raise ValueError("SECRET_KEY must be at least 16 characters")

        if self.REDIS_URL:
            if not self.REDIS_URL.startswith(("redis://", "rediss://")):
                raise ValueError(
                    f"Invalid REDIS_URL format: {self.REDIS_URL}\n"
                    "Must start with redis:// or rediss://"
                )

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
