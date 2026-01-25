"""
Base Authentication Backend

Abstract base class that all backends must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class AuthBackend(ABC):
    """
    Abstract base class for authentication backends.

    All backends (SQLite, LDAP, OAuth, etc.) must inherit from this class
    and implement the abstract methods.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initializes backend with configuration.

        Args:
            config: Dict with settings (usually config.__dict__)
        """
        self.config = config

    @abstractmethod
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticates user with username and password.

        Args:
            username: Username
            password: Password in plain text

        Returns:
            Dict with user info if authenticated, None if failed

            Expected format:
            {
                'username': str,
                'email': str,
                'display_name': str,
                'roles': List[str]  # ['admin', 'editor', 'viewer']
            }
        """
        pass

    @abstractmethod
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Fetches information for a user (without authenticating).

        Args:
            username: Username

        Returns:
            Dict with user info or None if user doesn't exist
            Same format as authenticate()
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        Returns the identifying name of the backend.

        Returns:
            str: Backend name (e.g., 'sqlite', 'ldap', 'oauth', 'dummy')
        """
        pass

    # ========================================
    # OPTIONAL METHODS
    # Backends can implement if they support user management
    # ========================================

    def add_user(
        self,
        username: str,
        password: str,
        email: str = "",
        display_name: str = "",
        roles: List[str] = None,
        performed_by: str = "system",
        **kwargs,
    ) -> bool:
        """
        Adds a new user (OPTIONAL - only for local backends).

        Args:
            username: Username
            password: Password in plain text
            email: User's email
            display_name: Display name
            roles: List of roles ['admin', 'editor', 'viewer']
            performed_by: Who created the user (for auditing)

        Returns:
            bool: True if created, False if failed

        Raises:
            NotImplementedError: If backend doesn't support it (LDAP, OAuth)
        """
        raise NotImplementedError(f"{self.get_name()} backend does not support user creation")

    def delete_user(self, username: str, performed_by: str = "system") -> bool:
        """
        Removes a user (OPTIONAL - only for local backends).

        Args:
            username: Username
            performed_by: Who deleted the user (for auditing)

        Returns:
            bool: True if deleted, False if user doesn't exist

        Raises:
            NotImplementedError: If backend doesn't support it
        """
        raise NotImplementedError(f"{self.get_name()} backend does not support user deletion")

    def change_password(
        self, username: str, new_password: str, performed_by: str = "system"
    ) -> bool:
        """
        Changes a user's password (OPTIONAL - only for local backends).

        Args:
            username: Username
            new_password: New password in plain text
            performed_by: Who changed it (for auditing)

        Returns:
            bool: True if changed, False if user doesn't exist

        Raises:
            NotImplementedError: If backend doesn't support it
        """
        raise NotImplementedError(f"{self.get_name()} backend does not support password changes")

    def list_users(self) -> List[Dict[str, Any]]:
        """
        Lists all users (OPTIONAL - only for local backends).

        Returns:
            List of dicts with user info

        Raises:
            NotImplementedError: If backend doesn't support it
        """
        raise NotImplementedError(f"{self.get_name()} backend does not support user listing")

    def update_roles(self, username: str, roles: List[str], performed_by: str = "system") -> bool:
        """
        Updates a user's roles (OPTIONAL).

        Args:
            username: Username
            roles: New list of roles
            performed_by: Who changed it (for auditing)

        Returns:
            bool: True if updated

        Raises:
            NotImplementedError: If backend doesn't support it
        """
        raise NotImplementedError(f"{self.get_name()} backend does not support role updates")

    def validate_roles(self, roles: list) -> list:
        """
        Validate and normalize role names.

        Args:
            roles: List of role names

        Returns:
            List of valid, normalized roles
        """
        valid_roles = {"admin", "editor", "viewer"}
        normalized = []

        for role in roles:
            role_lower = role.lower().strip()
            if role_lower in valid_roles:
                normalized.append(role_lower)

        return normalized
