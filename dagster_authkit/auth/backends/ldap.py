"""
LDAP Authentication Backend

Supports:
- Microsoft Active Directory
- OpenLDAP
- Any RFC 4511 compliant LDAP server

Uses ldap3 (pure Python, thread-safe, cross-platform).

Configuration via environment variables:
    DAGSTER_AUTH_LDAP_SERVER=ldap://ldap.company.com:389
    DAGSTER_AUTH_LDAP_BIND_DN=cn=readonly,dc=company,dc=com
    DAGSTER_AUTH_LDAP_BIND_PASSWORD=secret
    DAGSTER_AUTH_LDAP_BASE_DN=ou=users,dc=company,dc=com
    DAGSTER_AUTH_LDAP_USER_FILTER=(uid={username})  # OpenLDAP
    DAGSTER_AUTH_LDAP_USER_FILTER=(sAMAccountName={username})  # Active Directory

    # Role mapping (choose one method):

    # Method 1: Group pattern (RECOMMENDED)
    DAGSTER_AUTH_LDAP_GROUP_PATTERN=cn=dagster-{role},ou=groups,dc=company,dc=com
    # {role} will be replaced with: admins, editors, launchers, viewers

    # Method 2: LDAP attribute
    DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE=dagsterRole

    # Optional TLS
    DAGSTER_AUTH_LDAP_USE_TLS=true
    DAGSTER_AUTH_LDAP_CA_CERT=/path/to/ca.crt
"""

import logging
from typing import Any, Dict, List, Optional

from dagster_authkit.auth.backends.base import AuthBackend, AuthUser, Role

logger = logging.getLogger(__name__)


class LDAPAuthBackend(AuthBackend):
    """
    LDAP/Active Directory authentication backend.

    Features:
    - Thread-safe (uses ldap3 SAFE_SYNC strategy)
    - Pure Python (no C dependencies)
    - Connection pooling
    - TLS support
    - Smart group pattern matching
    - Flexible role mapping (groups or attributes)
    - Cross-platform (Windows, Linux, macOS)
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # Validate required config
        required = ["DAGSTER_AUTH_LDAP_SERVER", "DAGSTER_AUTH_LDAP_BASE_DN"]
        missing = [k for k in required if not config.get(k)]
        if missing:
            raise ValueError(f"Missing LDAP config: {missing}")

        self.server_uri = config["DAGSTER_AUTH_LDAP_SERVER"]
        self.bind_dn = config.get("DAGSTER_AUTH_LDAP_BIND_DN")
        self.bind_password = config.get("DAGSTER_AUTH_LDAP_BIND_PASSWORD")
        self.base_dn = config["DAGSTER_AUTH_LDAP_BASE_DN"]

        # User search filter (default: uid for OpenLDAP)
        self.user_filter = config.get(
            "DAGSTER_AUTH_LDAP_USER_FILTER",
            "(uid={username})"
        )

        # TLS settings
        self.use_tls = config.get("DAGSTER_AUTH_LDAP_USE_TLS", "false").lower() == "true"
        self.ca_cert = config.get("DAGSTER_AUTH_LDAP_CA_CERT")

        # Role mapping strategy
        self.role_attribute = config.get("DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE")

        # Smart group pattern mapping
        group_pattern = config.get("DAGSTER_AUTH_LDAP_GROUP_PATTERN")
        if group_pattern:
            self.group_mappings = {
                Role.ADMIN: group_pattern.replace("{role}", "admins"),
                Role.EDITOR: group_pattern.replace("{role}", "editors"),
                Role.LAUNCHER: group_pattern.replace("{role}", "launchers"),
                Role.VIEWER: group_pattern.replace("{role}", "viewers"),
            }
        else:
            self.group_mappings = {}

        # Initialize server and connection pool
        self.server = None
        self._init_server()

        logger.info(
            f"LDAPAuthBackend initialized:\n"
            f"  Server: {self.server_uri}\n"
            f"  Base DN: {self.base_dn}\n"
            f"  User filter: {self.user_filter}\n"
            f"  TLS: {self.use_tls}\n"
            f"  Role mapping: {'groups' if self.group_mappings else 'attribute' if self.role_attribute else 'default (VIEWER)'}"
        )

    def _init_server(self):
        """Initialize LDAP server object."""
        try:
            from ldap3 import Server, Tls
            import ssl

            # TLS setup
            tls_config = None
            if self.use_tls:
                tls_config = Tls(
                    validate=ssl.CERT_REQUIRED if self.ca_cert else ssl.CERT_NONE,
                    ca_certs_file=self.ca_cert,
                )

            self.server = Server(
                self.server_uri,
                use_ssl=self.use_tls,
                tls=tls_config,
            )

            logger.info("LDAP: Server initialized")

        except ImportError:
            raise RuntimeError(
                "LDAP backend requires 'ldap3' package.\n"
                "Install with: pip install ldap3"
            )
        except Exception as e:
            logger.error(f"Failed to initialize LDAP server: {e}")
            raise

    def get_name(self) -> str:
        return "ldap"

    # ========================================
    # Core Authentication
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """
        Authenticates user against LDAP.

        Process:
        1. Search for user DN
        2. Bind with user credentials
        3. Fetch user attributes
        4. Determine role (groups or attribute)
        5. Return AuthUser
        """
        try:
            from ldap3 import Connection, SAFE_SYNC

            # Step 1: Find user DN using service account
            user_dn = self._find_user_dn(username)
            if not user_dn:
                logger.warning(f"LDAP: User '{username}' not found")
                return None

            # Step 2: Authenticate by binding with user credentials
            conn = Connection(
                self.server,
                user=user_dn,
                password=password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                raise_exceptions=False,
            )

            if not conn.bind():
                logger.warning(f"LDAP: Invalid password for '{username}'")
                return None

            logger.info(f"LDAP: User '{username}' authenticated successfully")

            # Step 3: Fetch user attributes
            attrs = self._get_user_attributes(user_dn)

            # Step 4: Determine role
            role = self._determine_role(user_dn, attrs)

            conn.unbind()

            # Step 5: Build AuthUser
            return AuthUser(
                username=username,
                role=role,
                email=attrs.get("mail", [""])[0] if attrs.get("mail") else "",
                full_name=attrs.get("displayName", [attrs.get("cn", [""])[0]])[0] if attrs.get("displayName") or attrs.get("cn") else "",
            )

        except Exception as e:
            logger.error(f"LDAP authentication error for '{username}': {e}")
            return None

    def get_user(self, username: str) -> Optional[AuthUser]:
        """
        Fetches user info from LDAP (without password check).

        ⚠️ WARNING: This queries LDAP on every call!

        Usage:
        - CLI tools (dagster-authkit list-users)
        - Admin operations

        NOT for:
        - Session validation (middleware has cached data)
        - Per-request auth checks (use session)

        For active sessions, user data is already in session cache.
        This method is ONLY for cases where you need fresh LDAP data.
        """
        try:
            user_dn = self._find_user_dn(username)
            if not user_dn:
                return None

            attrs = self._get_user_attributes(user_dn)
            role = self._determine_role(user_dn, attrs)

            return AuthUser(
                username=username,
                role=role,
                email=attrs.get("mail", [""])[0] if attrs.get("mail") else "",
                full_name=attrs.get("displayName", [attrs.get("cn", [""])[0]])[0] if attrs.get("displayName") or attrs.get("cn") else "",
            )
        except Exception as e:
            logger.error(f"LDAP get_user error for '{username}': {e}")
            return None

    # ========================================
    # LDAP Helpers
    # ========================================

    def _find_user_dn(self, username: str) -> Optional[str]:
        """Search for user DN by username."""
        try:
            from ldap3 import Connection, SAFE_SYNC
            from ldap3.utils.conv import escape_filter_chars

            # Use service account for search (or anonymous if not configured)
            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
            )

            search_filter = self.user_filter.format(username=escape_filter_chars(username))

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=["dn"]
            )

            if conn.entries:
                user_dn = str(conn.entries[0].entry_dn)
                conn.unbind()
                return user_dn

            conn.unbind()
            return None

        except Exception as e:
            logger.error(f"LDAP search error: {e}")
            return None

    def _get_user_attributes(self, user_dn: str) -> Dict[str, List[str]]:
        """Fetch user attributes from LDAP."""
        try:
            from ldap3 import Connection, SAFE_SYNC

            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
            )

            # Attributes to fetch
            attrs_to_fetch = [
                "cn", "displayName", "mail", "memberOf",
            ]
            if self.role_attribute:
                attrs_to_fetch.append(self.role_attribute)

            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=attrs_to_fetch
            )

            if conn.entries:
                entry = conn.entries[0]
                attrs = {}

                # Convert ldap3 Entry to dict
                for attr_name in attrs_to_fetch:
                    if hasattr(entry, attr_name):
                        value = getattr(entry, attr_name).values
                        attrs[attr_name] = value if isinstance(value, list) else [value]

                conn.unbind()
                return attrs

            conn.unbind()
            return {}

        except Exception as e:
            logger.error(f"LDAP attribute fetch error: {e}")
            return {}

    def _determine_role(self, user_dn: str, attrs: Dict[str, List[str]]) -> Role:
        """
        Determine user role from LDAP.

        Priority:
        1. Group membership (if configured)
        2. LDAP attribute (if configured)
        3. Default to VIEWER
        """
        # Method 1: Group membership
        member_of = attrs.get("memberOf", [])
        if member_of and self.group_mappings:
            # Check groups in priority order (ADMIN > EDITOR > LAUNCHER > VIEWER)
            for role in [Role.ADMIN, Role.EDITOR, Role.LAUNCHER, Role.VIEWER]:
                group_dn = self.group_mappings.get(role)
                if group_dn and group_dn in member_of:
                    logger.debug(f"Role determined by group: {role.name}")
                    return role

        # Method 2: LDAP attribute
        if self.role_attribute:
            role_values = attrs.get(self.role_attribute, [])
            if role_values:
                role_value = str(role_values[0]).upper()
                try:
                    role = Role[role_value]
                    logger.debug(f"Role determined by attribute: {role.name}")
                    return role
                except KeyError:
                    logger.warning(f"Invalid role value in LDAP: {role_value}")

        # Default: VIEWER
        logger.debug("Role defaulted to VIEWER")
        return Role.VIEWER

    # ========================================
    # User Management (NOT SUPPORTED)
    # ========================================

    def add_user(self, *args, **kwargs) -> bool:
        """LDAP doesn't support user creation via Dagster."""
        logger.error("LDAP backend does not support add_user(). Create users in LDAP/AD.")
        return False

    def delete_user(self, *args, **kwargs) -> bool:
        """LDAP doesn't support user deletion via Dagster."""
        logger.error("LDAP backend does not support delete_user(). Disable users in LDAP/AD.")
        return False

    def change_password(self, *args, **kwargs) -> bool:
        """LDAP doesn't support password changes via Dagster."""
        logger.error("LDAP backend does not support change_password(). Use LDAP/AD password reset.")
        return False

    def list_users(self) -> List[AuthUser]:
        """
        Lists all users in LDAP (filtered by user_filter).

        ⚠️ WARNING: This can be expensive on large directories!
        """
        try:
            from ldap3 import Connection, SAFE_SYNC

            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
            )

            # Search all users
            search_filter = self.user_filter.replace("{username}", "*")

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=["cn", "displayName", "mail", "memberOf"]
            )

            users = []
            for entry in conn.entries:
                username = str(entry.cn.value) if hasattr(entry, 'cn') else "unknown"

                attrs = {}
                for attr in ["cn", "displayName", "mail", "memberOf"]:
                    if hasattr(entry, attr):
                        value = getattr(entry, attr).values
                        attrs[attr] = value if isinstance(value, list) else [value]

                role = self._determine_role(str(entry.entry_dn), attrs)

                users.append(AuthUser(
                    username=username,
                    role=role,
                    email=attrs.get("mail", [""])[0] if attrs.get("mail") else "",
                    full_name=attrs.get("displayName", [""])[0] if attrs.get("displayName") else "",
                ))

            conn.unbind()
            return users

        except Exception as e:
            logger.error(f"LDAP list_users error: {e}")
            return []

    def change_role(self, *args, **kwargs) -> bool:
        """LDAP doesn't support role changes via Dagster."""
        logger.error("LDAP backend does not support change_role(). Manage roles in LDAP groups.")
        return False
