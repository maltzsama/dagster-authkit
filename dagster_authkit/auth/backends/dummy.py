"""
Dummy Authentication Backend

Hardcoded backend for development and testing.
⚠️ NEVER use in production!
"""

import logging
from typing import List, Optional

from .base import AuthBackend, AuthUser, Role

logger = logging.getLogger(__name__)


class DummyAuthBackend(AuthBackend):
    """
    Dummy backend with hardcoded users.

    Available users:
    - admin/admin   → Role.ADMIN (full access)
    - editor/editor → Role.EDITOR (manage schedules/sensors)
    - launcher/launcher → Role.LAUNCHER (execute runs)
    - viewer/viewer → Role.VIEWER (read-only)

    ⚠️ FOR DEVELOPMENT/TESTING ONLY!

    Usage:
        export DAGSTER_AUTH_BACKEND=dummy
        dagster-authkit dev
    """

    # Hardcoded users
    USERS = {
        "admin": {
            "password": "admin",  # INSECURE: Plaintext!
            "role": Role.ADMIN,
            "email": "admin@localhost",
            "full_name": "Administrator",
        },
        "editor": {
            "password": "editor",
            "role": Role.EDITOR,
            "email": "editor@localhost",
            "full_name": "Editor User",
        },
        "launcher": {
            "password": "launcher",
            "role": Role.LAUNCHER,
            "email": "launcher@localhost",
            "full_name": "Launcher User",
        },
        "viewer": {
            "password": "viewer",
            "role": Role.VIEWER,
            "email": "viewer@localhost",
            "full_name": "Viewer User",
        },
    }

    def __init__(self, config: dict):
        super().__init__(config)
        logger.warning(
            "⚠️  DummyAuthBackend initialized - DO NOT USE IN PRODUCTION!\n"
            "    Available users: admin/admin, editor/editor, launcher/launcher, viewer/viewer"
        )

    # ========================================
    # CORE METHODS (Abstract Implementation)
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """
        Authenticates against hardcoded users.

        Args:
            username: Username
            password: Password (plaintext comparison!)

        Returns:
            AuthUser if authenticated, None if failed
        """
        user = self.USERS.get(username)

        if not user:
            logger.debug(f"Dummy auth: user '{username}' not found")
            return None

        # ⚠️ INSECURE: Plaintext comparison!
        if user["password"] == password:
            logger.info(f"Dummy auth: user '{username}' authenticated successfully")
            return AuthUser(
                username=username,
                role=user["role"],
                email=user["email"],
                full_name=user["full_name"],
            )
        else:
            logger.warning(f"Dummy auth: invalid password for user '{username}'")
            return None

    def get_user(self, username: str) -> Optional[AuthUser]:
        """
        Fetches user info (without authenticating).

        Args:
            username: Username

        Returns:
            AuthUser or None
        """
        user = self.USERS.get(username)

        if not user:
            return None

        return AuthUser(
            username=username, role=user["role"], email=user["email"], full_name=user["full_name"]
        )

    def get_name(self) -> str:
        """Returns backend name."""
        return "dummy"

    # ========================================
    # USER MANAGEMENT (Read-Only)
    # ========================================

    def list_users(self) -> List[AuthUser]:
        """
        Lists all hardcoded users.

        Returns:
            List of AuthUser instances
        """
        return [
            AuthUser(
                username=username,
                role=user["role"],
                email=user["email"],
                full_name=user["full_name"],
            )
            for username, user in self.USERS.items()
        ]

    # ========================================
    # UNSUPPORTED OPERATIONS
    # ========================================

    def add_user(self, *args, **kwargs) -> bool:
        """Dummy backend doesn't support user creation."""
        logger.error("DummyAuthBackend does not support add_user()")
        return False

    def delete_user(self, *args, **kwargs) -> bool:
        """Dummy backend doesn't support user deletion."""
        logger.error("DummyAuthBackend does not support delete_user()")
        return False

    def change_password(self, *args, **kwargs) -> bool:
        """Dummy backend doesn't support password changes."""
        logger.error("DummyAuthBackend does not support change_password()")
        return False

    def change_role(self, *args, **kwargs) -> bool:
        """Dummy backend doesn't support role changes."""
        logger.error("DummyAuthBackend does not support change_role()")
        return False
