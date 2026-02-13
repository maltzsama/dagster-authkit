"""
Proxy Authentication Backend (Authelia Forward Auth)

Reads authentication headers set by upstream reverse proxy (Authelia).
Does NOT handle sessions, passwords, or rate limiting - that's Authelia's job.

Expected Headers (Authelia defaults):
- Remote-User: username
- Remote-Groups: comma-separated groups (e.g., "cn=admins,ou=groups,dc=company,dc=com")
- Remote-Email: user email
- Remote-Name: full name

Group → Role Mapping:
Configure via DAGSTER_AUTH_PROXY_GROUP_PATTERN:
  cn={role},ou=groups,dc=company,dc=com

Examples:
  - cn=admins,ou=groups,dc=company,dc=com → Role.ADMIN
  - cn=editors,ou=groups,dc=company,dc=com → Role.EDITOR
  - cn=launchers,ou=groups,dc=company,dc=com → Role.LAUNCHER
  - cn=viewers,ou=groups,dc=company,dc=com → Role.VIEWER

If DAGSTER_AUTH_PROXY_GROUP_PATTERN is not set, falls back to simple matching:
  - "admins" → Role.ADMIN
  - "editors" → Role.EDITOR
  - etc.
"""

import logging
from typing import Any, Dict, List, Optional

from dagster_authkit.auth.backends.base import AuthBackend, AuthUser, Role

logger = logging.getLogger(__name__)


class ProxyAuthBackend(AuthBackend):
    """
    Proxy-based authentication for Authelia/Traefik forward auth.

    ALL configuration comes from dagster_authkit.utils.config.
    No config parsing here - just uses what's already loaded.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # Header names (from centralized config)
        self.user_header = config["DAGSTER_AUTH_PROXY_USER_HEADER"]
        self.groups_header = config["DAGSTER_AUTH_PROXY_GROUPS_HEADER"]
        self.email_header = config["DAGSTER_AUTH_PROXY_EMAIL_HEADER"]
        self.name_header = config["DAGSTER_AUTH_PROXY_NAME_HEADER"]

        # Group → Role mapping pattern
        group_pattern = config.get("DAGSTER_AUTH_PROXY_GROUP_PATTERN")
        if group_pattern:
            # Pattern-based mapping (LDAP DNs)
            # Example: "cn={role},ou=groups,dc=company,dc=com"
            self.group_mappings = {
                Role.ADMIN: group_pattern.replace("{role}", "admins"),
                Role.EDITOR: group_pattern.replace("{role}", "editors"),
                Role.LAUNCHER: group_pattern.replace("{role}", "launchers"),
                Role.VIEWER: group_pattern.replace("{role}", "viewers"),
            }
            logger.info(f"✅ Using LDAP DN pattern: {group_pattern}")
        else:
            # Simple group name matching (case-insensitive)
            # Works with simple Authelia group names
            self.group_mappings = {
                Role.ADMIN: "admins",
                Role.EDITOR: "editors",
                Role.LAUNCHER: "launchers",
                Role.VIEWER: "viewers",
            }
            logger.info("✅ Using simple group matching (admins, editors, launchers, viewers)")

        logger.info(
            f"ProxyAuthBackend initialized\n"
            f"  User header: {self.user_header}\n"
            f"  Groups header: {self.groups_header}\n"
            f"  Email header: {self.email_header}\n"
            f"  Name header: {self.name_header}\n"
            f"  Group mappings: {self.group_mappings}"
        )

    def get_name(self) -> str:
        return "proxy"

    # ========================================
    # Password Auth NOT Supported
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """
        NOT USED in proxy mode.
        Authentication happens at Authelia, not here.

        Raises:
            NotImplementedError: Always (passwords handled by Authelia)
        """
        raise NotImplementedError(
            "ProxyAuthBackend does not support password authentication.\n"
            "Authentication is handled by upstream proxy (Authelia).\n"
            "If you're seeing this error, check your AUTH_BACKEND setting."
        )

    def get_user(self, username: str) -> Optional[AuthUser]:
        """
        NOT USED in proxy mode.
        User data comes from HTTP headers, not database lookups.

        Raises:
            NotImplementedError: Always (user data from headers)
        """
        raise NotImplementedError(
            "ProxyAuthBackend does not support get_user().\n"
            "User data is extracted from HTTP headers by middleware.\n"
            "If you're seeing this error, check your middleware implementation."
        )

    # ========================================
    # PROXY-SPECIFIC: Header Parsing
    # ========================================

    def get_user_from_headers(self, headers: Dict[str, str]) -> Optional[AuthUser]:
        """
        Extracts user from HTTP headers set by Authelia.

        This is the MAIN method used by the middleware in proxy mode.

        Args:
            headers: HTTP headers dict (case-insensitive)

        Returns:
            AuthUser if headers valid, None if missing required headers

        Example:
            headers = {
                "Remote-User": "john",
                "Remote-Groups": "cn=admins,ou=groups,dc=company,dc=com",
                "Remote-Email": "john@company.com",
                "Remote-Name": "John Doe"
            }
            user = backend.get_user_from_headers(headers)
            # Returns: AuthUser(username="john", role=Role.ADMIN, ...)
        """
        # Normalize headers to lowercase for case-insensitive lookup
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Extract username (REQUIRED)
        username = headers_lower.get(self.user_header.lower())
        if not username:
            logger.warning(
                f"❌ Proxy auth: Missing required header '{self.user_header}'\n"
                f"   Available headers: {list(headers.keys())}"
            )
            return None

        # Extract groups (for role mapping)
        groups_raw = headers_lower.get(self.groups_header.lower(), "")
        groups = [g.strip().lower() for g in groups_raw.split(",") if g.strip()]

        # Determine role from groups
        role = self._determine_role_from_groups(groups)

        # Extract optional metadata
        email = headers_lower.get(self.email_header.lower(), "")
        full_name = headers_lower.get(self.name_header.lower(), "") or username.capitalize()

        logger.info(
            f"✅ Proxy auth: User '{username}' authenticated\n"
            f"   Groups: {groups}\n"
            f"   Role: {role.name}\n"
            f"   Email: {email or 'N/A'}\n"
            f"   Full name: {full_name}"
        )

        return AuthUser(
            username=username,
            role=role,
            email=email,
            full_name=full_name,
        )

    def _determine_role_from_groups(self, groups: List[str]) -> Role:
        """
        Maps LDAP groups to AuthKit roles.

        Priority: ADMIN > EDITOR > LAUNCHER > VIEWER

        Args:
            groups: List of group DNs or names (already lowercased)

        Returns:
            Highest matching role, defaults to VIEWER if no match

        Example:
            groups = ["cn=admins,ou=groups,dc=company,dc=com", "cn=developers,ou=groups"]
            # Returns: Role.ADMIN (highest priority match)
        """
        # Check in priority order
        for role in [Role.ADMIN, Role.EDITOR, Role.LAUNCHER, Role.VIEWER]:
            target_group = self.group_mappings.get(role, "").lower()
            if target_group and target_group in groups:
                logger.debug(f"   Matched '{target_group}' → {role.name}")
                return role

        logger.warning(
            f"⚠️  No group match found for: {groups}\n"
            f"   Expected one of: {list(self.group_mappings.values())}\n"
            f"   Defaulting to VIEWER role"
        )
        return Role.VIEWER

    # ========================================
    # User Management NOT Supported
    # (Users managed in Authelia/LDAP)
    # ========================================

    def add_user(self, *args, **kwargs) -> bool:
        """Not supported - users managed in Authelia/LDAP."""
        raise NotImplementedError(
            "ProxyAuthBackend does not support user management.\n"
            "Users are managed in your Authelia configuration or LDAP server."
        )

    def delete_user(self, *args, **kwargs) -> bool:
        """Not supported - users managed in Authelia/LDAP."""
        raise NotImplementedError(
            "ProxyAuthBackend does not support user management.\n"
            "Users are managed in your Authelia configuration or LDAP server."
        )

    def change_password(self, *args, **kwargs) -> bool:
        """Not supported - passwords managed in Authelia/LDAP."""
        raise NotImplementedError(
            "ProxyAuthBackend does not support password changes.\n"
            "Passwords are managed in your Authelia configuration or LDAP server."
        )

    def list_users(self) -> List[AuthUser]:
        """Not supported - query LDAP directly."""
        raise NotImplementedError(
            "ProxyAuthBackend does not support user listing.\n"
            "Query your LDAP server or Authelia user database directly."
        )

    def change_role(self, *args, **kwargs) -> bool:
        """Not supported - roles managed via LDAP groups."""
        raise NotImplementedError(
            "ProxyAuthBackend does not support role changes.\n"
            "Roles are determined by LDAP group membership. "
            "Manage group assignments in your LDAP server."
        )
