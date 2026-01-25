"""
Session Management System

Cryptographically signed cookies using itsdangerous.
Tamper-proof sessions without session backend.
"""

import logging
from typing import Any, Dict, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages sessions using cryptographically signed cookies.

    Uses itsdangerous.URLSafeTimedSerializer for:
    - Signing cookies (prevents tampering)
    - Timestamp cookies (auto-expiration)
    - URL-safe encoding
    """

    def __init__(
        self,
        secret_key: str,
        cookie_name: str = "dagster_session",
        max_age: int = 86400,  # 24 hours
        salt: str = "dagster-auth-session",
    ):
        """
        Args:
            secret_key: Secret key for signing (CRITICAL - must persist!)
            cookie_name: Cookie name
            max_age: Lifetime in seconds
            salt: Salt for key derivation
        """
        if not secret_key:
            raise ValueError("SECRET_KEY is required for session management")

        self.secret_key = secret_key
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.salt = salt

        # Serializer for signing/verifying cookies
        self.serializer = URLSafeTimedSerializer(secret_key=secret_key, salt=salt)

    def create_session(self, user_data: Dict[str, Any]) -> str:
        """
        Creates signed session for a user.

        Args:
            user_data: Dict with user data (username, roles, etc.)

        Returns:
            str: Session token (signed, URL-safe)

        Example:
            >>> manager = SessionManager('secret-key-123')
            >>> token = manager.create_session({
            ...     'username': 'admin',
            ...     'roles': ['admin', 'editor']
            ... })
            >>> print(token)
            'eyJhbGc...'  # URL-safe signed token
        """
        token = self.serializer.dumps(user_data)
        logger.debug(f"Created session for user: {user_data.get('username')}")
        return token

    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validates and decodes session token.

        Args:
            token: Session token (from cookie)

        Returns:
            Dict with user data if valid, None if invalid/expired

        Example:
            >>> user_data = manager.validate_session(token)
            >>> if user_data:
            ...     print(f"Authenticated as: {user_data['username']}")
            ... else:
            ...     print("Invalid or expired session")
        """
        if not token:
            return None

        try:
            # Loads with max_age = auto-expiration
            user_data = self.serializer.loads(token, max_age=self.max_age)

            logger.debug(f"Valid session for user: {user_data.get('username')}")
            return user_data

        except SignatureExpired:
            logger.info("Session expired")
            return None

        except BadSignature:
            logger.warning("Invalid session signature (tampering detected)")
            return None

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None

    def invalidate_session(self) -> None:
        """
        Invalidates session (in practice, just removes cookie in response).

        Note: Since sessions are stateless (signed), there's no backend
        to invalidate. Invalidation happens by removing cookie from client.
        """
        # No-op here, actual invalidation happens in middleware
        # by setting cookie with max_age=0
        pass


# ========================================
# Global Singleton Instance
# ========================================

_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """
    Returns session manager singleton.

    Returns:
        Global SessionManager instance

    Raises:
        RuntimeError: If SECRET_KEY not configured
    """
    global _session_manager

    if _session_manager is None:
        from dagster_authkit.utils.config import config

        if not config.SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY not configured! " "Set DAGSTER_AUTH_SECRET_KEY environment variable."
            )

        _session_manager = SessionManager(
            secret_key=config.SECRET_KEY,
            cookie_name=config.SESSION_COOKIE_NAME,
            max_age=config.SESSION_MAX_AGE,
            salt="dagster-auth-session-v1",
        )

        logger.info("SessionManager initialized")

    return _session_manager


# ========================================
# Convenience Functions
# ========================================


def create_session(user_data: Dict[str, Any]) -> str:
    """
    Convenience function to create session.

    Args:
        user_data: Dict with user info

    Returns:
        Session token
    """
    return get_session_manager().create_session(user_data)


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to validate session.

    Args:
        token: Session token

    Returns:
        User data or None
    """
    return get_session_manager().validate_session(token)
