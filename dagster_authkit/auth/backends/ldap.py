"""
LDAP Authentication Backend

Supports:
- Microsoft Active Directory
- OpenLDAP
- Any RFC 4511 compliant LDAP server

Uses ldap3 (pure Python, thread-safe, cross-platform).
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
    - TLS support
    - Smart group pattern matching
    - Flexible role mapping (groups or attributes)
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialise LDAP connection and validation.

        Args:
            config: Dict with LDAP settings (see ``AuthConfig`` documentation
                    for the full list of ``DAGSTER_AUTH_LDAP_*`` variables).

        Raises:
            ValueError: If required LDAP settings (SERVER, BASE_DN) are missing.
        """
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
        self.user_filter = config.get("DAGSTER_AUTH_LDAP_USER_FILTER", "(uid={username})")

        # TLS settings - string cast to prevent bool-proxy issues
        self.use_tls = str(config.get("DAGSTER_AUTH_LDAP_USE_TLS", "false")).lower() == "true"
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

        self.server = None
        self._init_server()

    def _init_server(self):
        """Initialize LDAP server object."""
        try:
            from ldap3 import Server, Tls
            import ssl

            tls_config = None
            if self.use_tls:
                if self.ca_cert:
                    tls_config = Tls(
                        validate=ssl.CERT_REQUIRED,
                        ca_certs_file=self.ca_cert,
                    )
                else:
                    tls_config = Tls(validate=ssl.CERT_NONE)
                    logger.warning(
                        "LDAP TLS enabled without CA cert — connection is vulnerable to MITM. "
                        "Set DAGSTER_AUTH_LDAP_CA_CERT in production."
                    )

            self.server = Server(
                self.server_uri,
                use_ssl=self.use_tls,
                tls=tls_config,
            )
            logger.info(f"LDAP: Server initialized for {self.server_uri}")
        except Exception as e:
            logger.error(f"LDAP: Failed to initialize server object: {e}")
            raise

    def get_name(self) -> str:
        return "ldap"

    def _get_timeout(self) -> int:
        """Get the LDAP connection timeout from config, defaulting to 10 seconds."""
        try:
            return int(self.config.get("DAGSTER_AUTH_LDAP_TIMEOUT", 10))
        except (ValueError, TypeError):
            return 10

    def _build_auth_user(self, username: str, role: Role, attrs: Dict[str, List[str]]) -> AuthUser:
        """Build an AuthUser from LDAP attributes (shared between authenticate and get_user)."""

        def _first(attr_name: str) -> str:
            val = attrs.get(attr_name, "")
            if isinstance(val, list):
                return val[0] if val else ""
            return str(val) if val else ""

        display_name = _first("displayName")
        cn_value = _first("cn")
        full_name = display_name or cn_value or username

        return AuthUser(
            username=username,
            role=role,
            email=_first("mail"),
            full_name=full_name,
        )

    # ========================================
    # Core Authentication
    # ========================================

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        """
        Authenticates user against LDAP.
        """
        if not password:
            logger.warning(f"LDAP: Empty password rejected for '{username}'")
            return None

        try:
            from ldap3 import Connection, SAFE_SYNC

            # Step 1: Find user DN
            user_dn = self._find_user_dn(username)
            if not user_dn:
                return None

            # Step 2: Bind with user credentials
            conn = Connection(
                self.server,
                user=user_dn,
                password=password,
                client_strategy=SAFE_SYNC,
                auto_bind=False,
                raise_exceptions=False,
                receive_timeout=self._get_timeout(),
            )

            try:
                status, result, _, _ = conn.bind()

                if not status:
                    logger.warning(
                        f"LDAP: Authentication failed for '{username}': {result.get('description')}"
                    )
                    return None

                logger.info(f"LDAP: User '{username}' bound successfully")

                # Step 3 & 4: Attributes and Role
                attrs = self._get_user_attributes(user_dn, conn)
                role = self._determine_role(user_dn, attrs, conn=conn)

                return self._build_auth_user(username, role, attrs)
            finally:
                conn.unbind()

        except Exception as e:
            logger.error(f"LDAP: Auth error for '{username}': {e}")
            return None

    def get_user(self, username: str) -> Optional[AuthUser]:
        """Fetch user info from LDAP without password check."""
        try:
            from ldap3 import Connection, SAFE_SYNC

            user_dn = self._find_user_dn(username)
            if not user_dn:
                return None

            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                receive_timeout=self._get_timeout(),
            )

            try:
                attrs = self._get_user_attributes(user_dn, conn)
                role = self._determine_role(user_dn, attrs, conn=conn)

                return self._build_auth_user(username, role, attrs)
            finally:
                conn.unbind()

        except Exception as e:
            logger.error(f"LDAP: get_user error for '{username}': {e}")
            return None

    # ========================================
    # LDAP Helpers (SAFE_SYNC Architecture)
    # ========================================

    def _find_user_dn(self, username: str) -> Optional[str]:
        """Search for user DN using service account and tuple unpacking."""
        from ldap3 import Connection, SAFE_SYNC, SUBTREE
        from ldap3.utils.conv import escape_filter_chars

        conn = None
        try:
            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
                receive_timeout=self._get_timeout(),
            )

            status, _, response, _ = conn.search(
                search_base=self.base_dn,
                search_filter=self.user_filter.format(username=escape_filter_chars(username)),
                search_scope=SUBTREE,
                attributes=[],
                size_limit=1,
            )

            if status and response:
                return response[0]["dn"]

            logger.warning(f"LDAP: User '{username}' not found under base DN.")
            return None
        except Exception as e:
            logger.error(f"LDAP: Error searching DN for '{username}': {e}")
            return None
        finally:
            if conn is not None:
                conn.unbind()

    def _get_user_attributes(self, user_dn: str, existing_conn=None) -> Dict[str, List[str]]:
        """Fetch attributes using raw response from SAFE_SYNC tuple.
        If existing_conn is provided, the caller is responsible for cleanup.
        Otherwise, a new connection is created and properly cleaned up."""
        from ldap3 import Connection, SAFE_SYNC

        owns_connection = existing_conn is None
        conn = existing_conn
        try:
            if conn is None:
                conn = Connection(
                    self.server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    client_strategy=SAFE_SYNC,
                    auto_bind=True,
                    receive_timeout=self._get_timeout(),
                )

            attrs_to_fetch = ["cn", "displayName", "mail", "memberOf"]
            if self.role_attribute:
                attrs_to_fetch.append(self.role_attribute)

            status, _, response, _ = conn.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=attrs_to_fetch,
            )

            if status and response:
                attrs = response[0].get("attributes", {})

                # DEBUG: Show LDAP attributes
                logger.debug(
                    f"LDAP attributes fetched for {user_dn}: "
                    f"displayName={attrs.get('displayName')}, "
                    f"cn={attrs.get('cn')}, "
                    f"mail={attrs.get('mail')}"
                )

                return attrs

            return {}
        except Exception as e:
            logger.error(f"LDAP: Error fetching attributes for {user_dn}: {e}")
            return {}
        finally:
            if owns_connection and conn is not None:
                conn.unbind()

    def _determine_role(self, user_dn: str, attrs: Dict[str, List[str]], conn=None) -> Role:
        """
        Determine role with fallback to manual group search.
        """
        # 1. Try to get groups from user attributes (standard memberOf)
        member_of = [m.lower() for m in attrs.get("memberOf", [])]

        # 2. If member_of is empty, perform a Reverse Group Search (The OpenLDAP fix)
        if not member_of and conn:
            logger.debug(f"LDAP: memberOf empty for {user_dn}. Performing manual group search.")
            member_of = self._get_user_groups_manually(user_dn)

        # 3. Check group mappings (Case-insensitive)
        if member_of and self.group_mappings:
            # Priority order: ADMIN > EDITOR > LAUNCHER > VIEWER
            for role in [Role.ADMIN, Role.EDITOR, Role.LAUNCHER, Role.VIEWER]:
                target_group = self.group_mappings.get(role)
                if target_group and target_group.lower() in member_of:
                    logger.info(f"LDAP: Role {role.name} assigned to {user_dn}")
                    return role

        # 4. Fallback to Role Attribute if configured
        if self.role_attribute:
            role_values = attrs.get(self.role_attribute, [])
            if role_values:
                try:
                    return Role[str(role_values[0]).upper()]
                except KeyError:
                    pass

        logger.warning(f"LDAP: No group match found for {user_dn}. Defaulting to VIEWER.")
        return Role.VIEWER

    def _get_domain_base_dn(self) -> str:
        """Extract domain base DN from user base DN (remove OU)."""
        parts = self.base_dn.split(",")
        # Remove OUs, keep only DCs
        domain_parts = [p.strip() for p in parts if p.strip().lower().startswith("dc=")]
        return ",".join(domain_parts)

    def _get_user_groups_manually(self, user_dn: str) -> List[str]:
        """
        Reverse search: Find groups that have this user DN as a member.
        Works for OpenLDAP which doesn't auto-populate memberOf.

        Creates its own admin connection for search (users can't search groups).
        """
        try:
            from ldap3 import Connection, SAFE_SYNC, SUBTREE

            admin_conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
            )

            try:
                domain_base = self._get_domain_base_dn()
                search_filter = f"(|(member={user_dn})(uniqueMember={user_dn}))"

                logger.info(f"LDAP: Manual group search:")
                logger.info(f"  base_dn: {domain_base}")
                logger.info(f"  filter: {search_filter}")
                logger.info(f"  user_dn: {user_dn}")

                status, _, response, _ = admin_conn.search(
                    search_base=domain_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=["cn"],
                )

                logger.info(f"LDAP: Search status: {status}")
                logger.info(f"LDAP: Search response: {response}")

                if status and response:
                    groups = [entry["dn"].lower() for entry in response]
                    logger.info(f"LDAP: Found {len(groups)} groups for {user_dn}: {groups}")
                    return groups

                logger.warning(f"LDAP: No groups found for {user_dn}")
                return []
            finally:
                admin_conn.unbind()
        except Exception as e:
            logger.error(f"LDAP: Manual group search failed: {e}", exc_info=True)
            return []

    @staticmethod
    def _first_value(attrs: Dict[str, list], key: str, default: str = "") -> str:
        """Safely extract the first value from an LDAP attribute list."""
        values = attrs.get(key, [])
        return str(values[0]) if values else default

    def list_users(self) -> List[AuthUser]:
        """Iterate through raw response to list users."""
        try:
            from ldap3 import Connection, SAFE_SYNC

            conn = Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                client_strategy=SAFE_SYNC,
                auto_bind=True,
            )

            status, _, response, _ = conn.search(
                search_base=self.base_dn,
                search_filter=self.user_filter.replace("{username}", "*"),
                attributes=["cn", "displayName", "mail", "memberOf"],
            )

            users = []
            if status and response:
                for entry in response:
                    raw_attrs = entry.get("attributes", {})
                    username = self._first_value(raw_attrs, "cn", "unknown")
                    role = self._determine_role(entry["dn"], raw_attrs)

                    users.append(
                        AuthUser(
                            username=username,
                            role=role,
                            email=self._first_value(raw_attrs, "mail"),
                            full_name=self._first_value(raw_attrs, "displayName", username),
                        )
                    )

            conn.unbind()
            return users
        except Exception as e:
            logger.error(f"LDAP: Error listing users: {e}")
            return []

    # ========================================
    # Write Operations (Unsupported - Fail Loud)
    # ========================================

    def add_user(self, *args, **kwargs) -> bool:
        logger.error(
            "LDAP: Backend does not support add_user(). Manage users in your LDAP/AD server."
        )
        return False

    def delete_user(self, *args, **kwargs) -> bool:
        logger.error(
            "LDAP: Backend does not support delete_user(). Disable users in your LDAP/AD server."
        )
        return False

    def change_password(self, *args, **kwargs) -> bool:
        logger.error(
            "LDAP: Backend does not support change_password(). Use your domain's native password tools."
        )
        return False

    def change_role(self, *args, **kwargs) -> bool:
        logger.error(
            "LDAP: Backend does not support change_role() via API. Manage permissions via LDAP groups."
        )
        return False
