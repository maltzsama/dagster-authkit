"""
Dummy Authentication Backend

Hardcoded backend for development and testing.
NEVER use in production!
"""

import logging
from typing import Any, Dict, List, Optional

from .base import AuthBackend

logger = logging.getLogger(__name__)


class DummyAuthBackend(AuthBackend):
    """
    Dummy backend with hardcoded users.

    Available users:
    - admin/admin → roles: [admin, editor, viewer]
    - editor/editor → roles: [editor, viewer]
    - viewer/viewer → roles: [viewer]

    ⚠️ FOR DEVELOPMENT/TESTING ONLY!
    """

    # Hardcoded users
    USERS = {
        "admin": {
            "username": "admin",
            "password": "admin",  # Plaintext! Never do this in production
            "email": "admin@localhost",
            "display_name": "Administrator",
            "roles": ["admin", "editor", "viewer"],
        },
        "editor": {
            "username": "editor",
            "password": "editor",
            "email": "editor@localhost",
            "display_name": "Editor",
            "roles": ["editor", "viewer"],
        },
        "viewer": {
            "username": "viewer",
            "password": "viewer",
            "email": "viewer@localhost",
            "display_name": "Viewer",
            "roles": ["viewer"],
        },
    }

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        logger.warning(
            "⚠️  DummyAuthBackend initialized - DO NOT USE IN PRODUCTION! "
            "Hardcoded users: admin/admin, editor/editor, viewer/viewer"
        )

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticates against hardcoded users.

        Args:
            username: Username
            password: Password (plaintext comparison!)

        Returns:
            User info dict or None
        """
        user = self.USERS.get(username)

        if not user:
            logger.debug(f"Dummy auth: user '{username}' not found")
            return None

        # INSECURE: Plaintext comparison!
        if user["password"] == password:
            logger.info(f"Dummy auth: user '{username}' authenticated successfully")
            return {
                "username": user["username"],
                "email": user["email"],
                "display_name": user["display_name"],
                "roles": user["roles"],
            }
        else:
            logger.warning(f"Dummy auth: invalid password for user '{username}'")
            return None

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Fetches user info (without authenticating).

        Args:
            username: Username

        Returns:
            User info dict (without password) or None
        """
        user = self.USERS.get(username)

        if not user:
            return None

        return {
            "username": user["username"],
            "email": user["email"],
            "display_name": user["display_name"],
            "roles": user["roles"],
        }

    def get_name(self) -> str:
        """Returns backend name."""
        return "dummy"

    def list_users(self) -> List[Dict[str, Any]]:
        """
        Lists all hardcoded users.

        Returns:
            List of user info dicts
        """
        return [
            {
                "username": user["username"],
                "email": user["email"],
                "display_name": user["display_name"],
                "roles": user["roles"],
            }
            for user in self.USERS.values()
        ]
