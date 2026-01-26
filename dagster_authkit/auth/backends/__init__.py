"""
Authentication backends for dagster-authkit.

This module exposes the available authentication providers.
The unified Peewee backend handles all SQL-based providers.
"""

from .base import AuthBackend
from .dummy import DummyAuthBackend

# Unified SQL Backend (requires Peewee)
try:
    from .sql import PeeweeAuthBackend
except ImportError:
    # This happens if 'peewee' is not installed in the environment
    PeeweeAuthBackend = None

# Placeholder for future LDAP implementation
try:
    from .ldap import LDAPAuthBackend
except ImportError:
    LDAPAuthBackend = None

# Placeholder for future OAuth implementation
try:
    from .oauth import OAuthBackend
except ImportError:
    OAuthBackend = None

__all__ = [
    "AuthBackend",
    "DummyAuthBackend",
    "PeeweeAuthBackend",
    "LDAPAuthBackend",
    "OAuthBackend",
]