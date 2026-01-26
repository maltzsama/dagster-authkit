"""Authentication backends for dagster-authkit."""

from .base import AuthBackend
from .dummy import DummyAuthBackend

# Optional backends (may require extras)
try:
    from .sql import SQLiteAuthBackend
except ImportError:
    SQLiteAuthBackend = None

try:
    from .ldap import LDAPAuthBackend
except ImportError:
    LDAPAuthBackend = None

try:
    from .oauth import OAuthBackend
except ImportError:
    OAuthBackend = None

__all__ = [
    "AuthBackend",
    "DummyAuthBackend",
    "SQLiteAuthBackend",
    "LDAPAuthBackend",
    "OAuthBackend",
]
